"""
Module: classification.ml_classifier
Purpose: Isolation Forest-based behavioral anomaly detection.
         Trains on normal system behavior to establish a baseline,
         then flags processes that deviate significantly.
         Provides feature-level explanations via manual importance scoring.
Owner: classification
Dependencies: scikit-learn, numpy, joblib, psutil
Performance: Feature collection runs in background at 5s intervals.
             Prediction is O(T×D) per sample where T=n_estimators, D=features.
             Typical latency: <5ms per process prediction.
             Model size: ~2MB (100 estimators, 256 max_samples).

Feature Vector (28 features per process snapshot):
    Resource:   cpu_pct, memory_pct, io_read_mbs, io_write_mbs
    Behavioral: n_threads, n_handles, n_open_files, n_connections, n_children
    Temporal:   lifetime_secs, cpu_time_user, cpu_time_kernel
    Parent:     parent_is_system, parent_is_shell, parent_is_browser, parent_is_office
    Path:       path_is_temp, path_is_system32, path_is_program_files, path_is_appdata
    Name:       name_entropy, name_length, has_numeric_suffix
    Network:    has_listening_port, has_external_conn, unique_remote_ips
    Signing:    is_signed, is_microsoft_signed
"""

from __future__ import annotations

import asyncio
import math
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import (
    IS_WINDOWS,
    ML_ANOMALY_THRESHOLD,
    ML_BASELINE_DURATION_SECONDS,
    ML_CONTAMINATION,
    ML_MAX_SAMPLES,
    ML_MIN_PROCESS_LIFETIME_SECONDS,
    ML_N_ESTIMATORS,
    ML_RANDOM_STATE,
    ML_RETRAIN_INTERVAL_DAYS,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.exceptions import (
    BaselineTrainingError,
    FeatureExtractionError,
    ModelLoadError,
    ModelNotTrainedError,
    ModelSaveError,
)


# =============================================================================
# FEATURE VECTOR
# =============================================================================

@dataclass
class ProcessFeatures:
    """
    28-dimensional feature vector for ML process anomaly detection.

    All continuous features are normalized to [0, 1] or log-scaled
    before being passed to the Isolation Forest.
    """

    # --- Resource utilization ---
    cpu_pct: float = 0.0           # 0-100% of one core
    memory_pct: float = 0.0        # % of system RAM
    io_read_mbs: float = 0.0       # MB/s read rate
    io_write_mbs: float = 0.0      # MB/s write rate

    # --- Behavioral counters ---
    n_threads: int = 1
    n_handles: int = 0             # Windows only; 0 on Linux
    n_open_files: int = 0
    n_connections: int = 0
    n_children: int = 0

    # --- Temporal features ---
    lifetime_secs: float = 0.0
    cpu_time_user: float = 0.0
    cpu_time_kernel: float = 0.0

    # --- Parent process flags (one-hot) ---
    parent_is_system: bool = False
    parent_is_shell: bool = False
    parent_is_browser: bool = False
    parent_is_office: bool = False

    # --- Path-based flags (one-hot) ---
    path_is_temp: bool = False
    path_is_system32: bool = False
    path_is_program_files: bool = False
    path_is_appdata: bool = False

    # --- Name analysis ---
    name_entropy: float = 0.0      # Shannon entropy of process name
    name_length: int = 0
    has_numeric_suffix: bool = False  # e.g., "svchost32.exe"

    # --- Network behavior ---
    has_listening_port: bool = False
    has_external_conn: bool = False
    unique_remote_ips: int = 0

    # --- Code signing ---
    is_signed: bool = False
    is_microsoft_signed: bool = False

    def to_numpy(self) -> "np.ndarray":
        """Convert to numpy array for sklearn. Import numpy lazily."""
        import numpy as np
        return np.array([
            self.cpu_pct / 100.0,
            self.memory_pct / 100.0,
            min(self.io_read_mbs / 100.0, 1.0),
            min(self.io_write_mbs / 100.0, 1.0),
            min(self.n_threads / 50.0, 1.0),
            min(self.n_handles / 1000.0, 1.0),
            min(self.n_open_files / 100.0, 1.0),
            min(self.n_connections / 20.0, 1.0),
            min(self.n_children / 10.0, 1.0),
            min(math.log1p(self.lifetime_secs) / 12.0, 1.0),  # log(e^12)≈12
            min(self.cpu_time_user / 3600.0, 1.0),
            min(self.cpu_time_kernel / 3600.0, 1.0),
            float(self.parent_is_system),
            float(self.parent_is_shell),
            float(self.parent_is_browser),
            float(self.parent_is_office),
            float(self.path_is_temp),
            float(self.path_is_system32),
            float(self.path_is_program_files),
            float(self.path_is_appdata),
            min(self.name_entropy / 4.0, 1.0),   # Max entropy ≈4 bits for 16-char name
            min(self.name_length / 30.0, 1.0),
            float(self.has_numeric_suffix),
            float(self.has_listening_port),
            float(self.has_external_conn),
            min(self.unique_remote_ips / 10.0, 1.0),
            float(self.is_signed),
            float(self.is_microsoft_signed),
        ], dtype=float)

    @property
    def feature_names(self) -> list[str]:
        return [
            "cpu_pct", "memory_pct", "io_read_mbs", "io_write_mbs",
            "n_threads", "n_handles", "n_open_files", "n_connections", "n_children",
            "lifetime_secs", "cpu_time_user", "cpu_time_kernel",
            "parent_is_system", "parent_is_shell", "parent_is_browser", "parent_is_office",
            "path_is_temp", "path_is_system32", "path_is_program_files", "path_is_appdata",
            "name_entropy", "name_length", "has_numeric_suffix",
            "has_listening_port", "has_external_conn", "unique_remote_ips",
            "is_signed", "is_microsoft_signed",
        ]


# =============================================================================
# FEATURE EXTRACTOR
# =============================================================================

class FeatureExtractor:
    """Extracts a ProcessFeatures vector from a live psutil Process object."""

    _SYSTEM_PARENTS = frozenset({
        "system", "init", "systemd", "launchd",
        "services.exe", "wininit.exe", "kernel_task",
    })
    _SHELL_PARENTS = frozenset({
        "cmd.exe", "powershell.exe", "bash", "sh", "zsh", "fish",
        "wscript.exe", "cscript.exe",
    })
    _BROWSER_PARENTS = frozenset({
        "chrome.exe", "firefox.exe", "msedge.exe",
        "safari", "opera.exe", "brave.exe",
    })
    _OFFICE_PARENTS = frozenset({
        "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "onenote.exe",
    })

    def extract(self, pid: int) -> Optional[ProcessFeatures]:
        """
        Extract features for the given PID using psutil.

        Returns None if the process has exited or access is denied.

        Raises:
            FeatureExtractionError: On unexpected extraction failures.
        """
        try:
            import psutil
            proc = psutil.Process(pid)
            return self._extract_from_proc(proc)
        except (ImportError, Exception) as exc:
            return None

    def _extract_from_proc(self, proc: Any) -> Optional[ProcessFeatures]:
        import psutil

        try:
            with proc.oneshot():
                name = proc.name()
                create_time = proc.create_time()
                lifetime = time.time() - create_time

                if lifetime < ML_MIN_PROCESS_LIFETIME_SECONDS:
                    return None  # Too young — skip to reduce FPs

                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = ""

                try:
                    cpu_pct = proc.cpu_percent(interval=None)
                except Exception:
                    cpu_pct = 0.0

                try:
                    mem = proc.memory_percent()
                except Exception:
                    mem = 0.0

                try:
                    n_threads = proc.num_threads()
                except Exception:
                    n_threads = 1

                try:
                    open_files = len(proc.open_files())
                except Exception:
                    open_files = 0

                try:
                    conns = proc.connections()
                    n_conns = len(conns)
                    has_listen = any(
                        c.status == "LISTEN" for c in conns
                        if hasattr(c, "status")
                    )
                    external_ips = {
                        c.raddr.ip for c in conns
                        if c.raddr and not self._is_private(c.raddr.ip)
                    }
                    has_external = len(external_ips) > 0
                    unique_remote = len(external_ips)
                except Exception:
                    n_conns = 0
                    has_listen = False
                    has_external = False
                    unique_remote = 0

                try:
                    cpu_times = proc.cpu_times()
                    cpu_user = cpu_times.user
                    cpu_kernel = getattr(cpu_times, "system", 0.0)
                except Exception:
                    cpu_user = cpu_kernel = 0.0

                try:
                    ppid = proc.ppid()
                    parent = psutil.Process(ppid)
                    parent_name = parent.name().lower()
                except Exception:
                    parent_name = ""

                try:
                    children = proc.children()
                    n_children = len(children)
                except Exception:
                    n_children = 0

                # Windows: handles count
                n_handles = 0
                if IS_WINDOWS:
                    try:
                        n_handles = proc.num_handles()
                    except Exception:
                        pass

                # I/O rates (need two samples for delta — approximate here)
                io_read_mbs = io_write_mbs = 0.0
                try:
                    io = proc.io_counters()
                    # Use cumulative / lifetime as a rate approximation
                    if lifetime > 0:
                        io_read_mbs = (io.read_bytes / (1024 * 1024)) / lifetime
                        io_write_mbs = (io.write_bytes / (1024 * 1024)) / lifetime
                except Exception:
                    pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        exe_lower = exe.lower().replace("\\", "/")
        return ProcessFeatures(
            cpu_pct=min(cpu_pct, 100.0),
            memory_pct=min(mem, 100.0),
            io_read_mbs=min(io_read_mbs, 1000.0),
            io_write_mbs=min(io_write_mbs, 1000.0),
            n_threads=n_threads,
            n_handles=n_handles,
            n_open_files=open_files,
            n_connections=n_conns,
            n_children=n_children,
            lifetime_secs=lifetime,
            cpu_time_user=cpu_user,
            cpu_time_kernel=cpu_kernel,
            parent_is_system=parent_name in self._SYSTEM_PARENTS,
            parent_is_shell=parent_name in self._SHELL_PARENTS,
            parent_is_browser=parent_name in self._BROWSER_PARENTS,
            parent_is_office=parent_name in self._OFFICE_PARENTS,
            path_is_temp="temp" in exe_lower or "/tmp" in exe_lower,
            path_is_system32="system32" in exe_lower or "syswow64" in exe_lower,
            path_is_program_files="program files" in exe_lower,
            path_is_appdata="appdata" in exe_lower,
            name_entropy=self._shannon_entropy(name),
            name_length=len(name),
            has_numeric_suffix=self._has_numeric_suffix(name),
            has_listening_port=has_listen,
            has_external_conn=has_external,
            unique_remote_ips=unique_remote,
            is_signed=False,         # Populated separately on Windows
            is_microsoft_signed=False,
        )

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s.lower():
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        n = len(s)
        for count in freq.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _has_numeric_suffix(name: str) -> bool:
        """Return True if process name has an unexpected numeric suffix (e.g., svchost32)."""
        import re
        base = name.lower().replace(".exe", "").replace(".dll", "")
        return bool(re.search(r"\d{2,}$", base))

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Return True if IP is private/loopback."""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except ValueError:
            return True


# =============================================================================
# ML CLASSIFIER
# =============================================================================

class MLClassifier:
    """
    Isolation Forest behavioral anomaly classifier.

    Two-phase lifecycle:
    1. Training: observe normal system behavior for baseline_duration_seconds
    2. Inference: score new process snapshots against the trained model

    The model is retrained weekly on accumulated normal behavior samples
    to adapt to software installations and configuration changes.
    """

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config
        self._model: Optional[Any] = None          # IsolationForest
        self._scaler: Optional[Any] = None         # StandardScaler
        self._feature_extractor = FeatureExtractor()
        self._is_trained = False
        self._training_samples: int = 0
        self._model_path = Path(config.ml.model_path)
        self._anomaly_threshold = config.ml.anomaly_threshold
        self._log = logger.bind(component="MLClassifier")

        # Try loading an existing model on init
        if self._model_path.exists():
            try:
                self._load_model()
            except ModelLoadError as exc:
                self._log.warning("Could not load existing model: {exc}", exc=exc)

    # =========================================================================
    # Training
    # =========================================================================

    async def train_baseline(
        self,
        duration_seconds: int = ML_BASELINE_DURATION_SECONDS,
        output_path: Optional[Path] = None,
        progress_callback: Optional[Any] = None,
    ) -> None:
        """
        Observe system behavior for duration_seconds and train the model.

        Collects process snapshots every 5 seconds, accumulating a training
        dataset that represents normal system behavior. Then trains an
        Isolation Forest model on the collected samples.

        Args:
            duration_seconds:  Observation window in seconds.
            output_path:       Where to save the trained model (default: config path).
            progress_callback: Optional callable(pct: float) for progress updates.

        Raises:
            BaselineTrainingError: If insufficient samples collected.
        """
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self._log.info(
            "Starting ML baseline training. Duration: {d}s", d=duration_seconds
        )

        import psutil
        collection_interval = 5.0
        samples: list["np.ndarray"] = []
        start_time = time.time()
        elapsed = 0.0

        while elapsed < duration_seconds:
            # Collect features for all running processes
            for pid in psutil.pids():
                features = self._feature_extractor.extract(pid)
                if features is not None:
                    samples.append(features.to_numpy())

            elapsed = time.time() - start_time
            pct = min(elapsed / duration_seconds, 1.0)

            if progress_callback:
                try:
                    progress_callback(pct)
                except Exception:
                    pass

            self._log.debug(
                "Training: {pct:.0%} ({n} samples collected)",
                pct=pct, n=len(samples),
            )

            remaining = duration_seconds - elapsed
            if remaining > 0:
                await asyncio.sleep(min(collection_interval, remaining))

        if len(samples) < 100:
            raise BaselineTrainingError(
                reason="Insufficient samples collected",
                samples_collected=len(samples),
                samples_needed=100,
            )

        self._log.info(
            "Training Isolation Forest on {n} samples...", n=len(samples)
        )

        X = np.array(samples)

        # Fit scaler and model
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(
            n_estimators=self._config.ml.n_estimators,
            contamination=self._config.ml.contamination,
            max_samples=min(self._config.ml.max_samples, len(samples)),
            random_state=self._config.ml.random_state,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        self._model = model
        self._scaler = scaler
        self._is_trained = True
        self._training_samples = len(samples)

        # Save to disk
        save_path = output_path or self._model_path
        self._save_model(save_path)

        self._log.info(
            "ML baseline training complete. Model saved to {path}",
            path=save_path,
        )

    # =========================================================================
    # Inference
    # =========================================================================

    def predict_anomaly(
        self, features: ProcessFeatures
    ) -> tuple[bool, float]:
        """
        Score a process against the trained baseline.

        Args:
            features: ProcessFeatures vector for the process to score.

        Returns:
            (is_anomaly, anomaly_score)
            anomaly_score: typically in [-1.0, 0.0] for Isolation Forest
                           (more negative = more anomalous)

        Raises:
            ModelNotTrainedError: If no model has been trained yet.
        """
        if not self._is_trained or self._model is None:
            raise ModelNotTrainedError()

        import numpy as np

        X = features.to_numpy().reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        prediction = self._model.predict(X_scaled)[0]   # 1=normal, -1=anomaly
        score = float(self._model.score_samples(X_scaled)[0])

        is_anomaly = prediction == -1 and score < self._anomaly_threshold
        return is_anomaly, score

    def predict_pid(self, pid: int) -> Optional[tuple[bool, float, ProcessFeatures]]:
        """
        Extract features for a PID and predict anomaly.

        Returns:
            (is_anomaly, score, features) or None if process inaccessible.
        """
        if not self._is_trained:
            return None

        features = self._feature_extractor.extract(pid)
        if features is None:
            return None

        try:
            is_anomaly, score = self.predict_anomaly(features)
            return is_anomaly, score, features
        except ModelNotTrainedError:
            return None

    def explain_prediction(
        self, features: ProcessFeatures, score: float
    ) -> list[dict[str, Any]]:
        """
        Return top contributing features to an anomaly prediction.

        Uses a simple sensitivity analysis: for each feature, compute
        how much the score changes when that feature is zeroed out.
        Returns top 5 most impactful features.

        Args:
            features: The ProcessFeatures that triggered anomaly.
            score:    The anomaly score from predict_anomaly().

        Returns:
            List of dicts: [{feature, value, impact, direction}, ...]
            Sorted by absolute impact (descending).
        """
        if not self._is_trained or self._model is None:
            return []

        import numpy as np

        base_vec = features.to_numpy()
        feature_names = features.feature_names
        contributions: list[dict[str, Any]] = []

        for i, fname in enumerate(feature_names):
            if base_vec[i] == 0.0:
                continue  # Skip zero features

            # Zero out this feature and re-score
            perturbed = base_vec.copy()
            perturbed[i] = 0.0

            X_base = base_vec.reshape(1, -1)
            X_pert = perturbed.reshape(1, -1)

            try:
                X_base_s = self._scaler.transform(X_base)
                X_pert_s = self._scaler.transform(X_pert)
                score_pert = float(self._model.score_samples(X_pert_s)[0])
                impact = score - score_pert  # Positive = this feature increases anomaly
            except Exception:
                continue

            contributions.append({
                "feature": fname,
                "value": round(float(base_vec[i]), 4),
                "impact": round(float(impact), 4),
                "direction": "increases_anomaly" if impact > 0 else "decreases_anomaly",
            })

        # Sort by absolute impact
        contributions.sort(key=lambda x: abs(x["impact"]), reverse=True)
        return contributions[:5]

    # =========================================================================
    # Model Persistence
    # =========================================================================

    def _save_model(self, path: Path) -> None:
        """Save model and scaler to disk using joblib."""
        try:
            import joblib
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(
                {"model": self._model, "scaler": self._scaler,
                 "samples": self._training_samples},
                str(path),
            )
            self._log.debug("Model saved: {path}", path=path)
        except Exception as exc:
            raise ModelSaveError(str(path), str(exc)) from exc

    def _load_model(self) -> None:
        """Load model and scaler from disk using joblib."""
        try:
            import joblib
            data = joblib.load(str(self._model_path))
            self._model = data["model"]
            self._scaler = data["scaler"]
            self._training_samples = data.get("samples", 0)
            self._is_trained = True
            self._log.info(
                "ML model loaded from {path} ({n} training samples)",
                path=self._model_path,
                n=self._training_samples,
            )
        except Exception as exc:
            raise ModelLoadError(str(self._model_path), str(exc)) from exc

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def training_samples(self) -> int:
        return self._training_samples

    def get_stats(self) -> dict[str, Any]:
        return {
            "is_trained": self._is_trained,
            "training_samples": self._training_samples,
            "model_path": str(self._model_path),
            "model_exists": self._model_path.exists(),
            "anomaly_threshold": self._anomaly_threshold,
            "n_estimators": getattr(self._model, "n_estimators", 0) if self._model else 0,
        }