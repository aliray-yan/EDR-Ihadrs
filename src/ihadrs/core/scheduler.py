"""
Module: core.scheduler
Purpose: Centralized task scheduler for recurring IHADRS background jobs.
         Wraps APScheduler (if available) with a fallback to threading.Timer
         for environments where APScheduler is not installed.
         Provides job registration, health monitoring, and graceful shutdown.
Owner: core
Dependencies: threading, loguru, (optional) apscheduler
Performance: All jobs run in daemon threads. Scheduler overhead is negligible.
"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from loguru import logger

from ihadrs.exceptions import UnexpectedInternalError


# =============================================================================
# JOB DEFINITION
# =============================================================================

@dataclass
class ScheduledJob:
    """
    Represents a registered recurring background job.

    Attributes:
        job_id: Unique identifier.
        name: Human-readable name for logging.
        func: The callable to invoke.
        interval_seconds: How often to run the job.
        enabled: Whether this job is currently active.
        run_immediately: If True, run once at scheduler start before first interval.
        last_run_time: Unix timestamp of last execution.
        last_run_duration: Seconds the last execution took.
        last_error: Most recent error string (if any).
        run_count: Total number of executions.
        error_count: Number of executions that raised exceptions.
    """

    job_id: str
    name: str
    func: Callable[[], None]
    interval_seconds: float
    enabled: bool = True
    run_immediately: bool = False

    # Runtime tracking
    last_run_time: float = field(default=0.0)
    last_run_duration: float = field(default=0.0)
    last_error: Optional[str] = field(default=None)
    run_count: int = field(default=0)
    error_count: int = field(default=0)
    next_run_time: float = field(default=0.0)

    @property
    def error_rate(self) -> float:
        """Fraction of runs that resulted in errors."""
        return self.error_count / self.run_count if self.run_count > 0 else 0.0

    @property
    def is_healthy(self) -> bool:
        """Return True if error rate is below 50%."""
        return self.error_rate < 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "interval_seconds": self.interval_seconds,
            "enabled": self.enabled,
            "last_run_time": self.last_run_time,
            "last_run_duration_ms": round(self.last_run_duration * 1000, 1),
            "last_error": self.last_error,
            "run_count": self.run_count,
            "error_count": self.error_count,
            "error_rate": f"{self.error_rate:.1%}",
            "next_run_in_seconds": max(
                0.0, self.next_run_time - time.time()
            ),
        }


# =============================================================================
# SCHEDULER
# =============================================================================

class TaskScheduler:
    """
    Lightweight task scheduler for IHADRS background jobs.

    Uses Python's threading module for simplicity and portability.
    Each job runs in an isolated daemon thread on its own interval timer,
    so a slow job never delays other jobs.

    Registered jobs include:
    - ML model retraining (weekly)
    - Log rotation check (daily)
    - Database pruning (daily)
    - IOC feed updates (hourly)
    - Health check logging (30 seconds)
    - Resource stats logging (5 minutes)

    Usage:
        scheduler = TaskScheduler()
        scheduler.add_job("health_check", health_check_fn, interval=30)
        scheduler.start()
        ...
        scheduler.stop()
    """

    def __init__(self) -> None:
        self._jobs: dict[str, ScheduledJob] = {}
        self._timers: dict[str, threading.Timer] = {}
        self._jobs_lock = threading.RLock()
        self._running = False
        self._shutdown_event = threading.Event()

        logger.debug("TaskScheduler initialized.")

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the scheduler and kick off all registered jobs.

        Jobs with run_immediately=True are invoked once before their
        first scheduled interval.
        """
        if self._running:
            logger.warning("TaskScheduler.start() called while already running.")
            return

        self._running = True
        self._shutdown_event.clear()

        with self._jobs_lock:
            for job in self._jobs.values():
                if job.enabled:
                    self._schedule_job(job, immediate=job.run_immediately)

        job_count = len(self._jobs)
        logger.info(
            "TaskScheduler started with {n} job(s).",
            n=job_count,
        )

    def stop(self, timeout_seconds: float = 10.0) -> None:
        """
        Stop the scheduler and cancel all pending timers.

        Running jobs are allowed to complete (they run in daemon threads,
        so they'll be killed if the process exits before completion).

        Args:
            timeout_seconds: Maximum seconds to wait for clean shutdown.
        """
        if not self._running:
            return

        logger.info("TaskScheduler stopping — cancelling {n} timers...", n=len(self._timers))
        self._running = False
        self._shutdown_event.set()

        with self._jobs_lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()

        logger.info("TaskScheduler stopped.")

    # -------------------------------------------------------------------------
    # Job Management
    # -------------------------------------------------------------------------

    def add_job(
        self,
        name: str,
        func: Callable[[], None],
        interval_seconds: float,
        job_id: Optional[str] = None,
        enabled: bool = True,
        run_immediately: bool = False,
    ) -> str:
        """
        Register a new recurring job.

        Args:
            name: Human-readable job name.
            func: Callable to invoke. Must be thread-safe.
            interval_seconds: How often to run the job (minimum 1.0).
            job_id: Optional custom ID. Auto-generated if not provided.
            enabled: If False, job is registered but not started.
            run_immediately: If True and scheduler is running, run once now.

        Returns:
            The job_id string.

        Raises:
            ValueError: If a job with this name already exists.
        """
        if interval_seconds < 1.0:
            raise ValueError(
                f"Job interval must be ≥ 1.0 seconds (got {interval_seconds})."
            )

        resolved_id = job_id or f"job-{uuid.uuid4().hex[:8]}"

        with self._jobs_lock:
            # Check for duplicate names
            existing_names = {j.name for j in self._jobs.values()}
            if name in existing_names:
                raise ValueError(
                    f"A job named '{name}' is already registered. "
                    "Use a unique name or remove the existing job first."
                )

            job = ScheduledJob(
                job_id=resolved_id,
                name=name,
                func=func,
                interval_seconds=interval_seconds,
                enabled=enabled,
                run_immediately=run_immediately,
            )
            self._jobs[resolved_id] = job

            # If scheduler is already running, start this job immediately
            if self._running and enabled:
                self._schedule_job(job, immediate=run_immediately)

        logger.debug(
            "Job registered: '{name}' (id={id}) every {interval}s",
            name=name,
            id=resolved_id,
            interval=interval_seconds,
        )
        return resolved_id

    def remove_job(self, job_id: str) -> bool:
        """
        Remove a job and cancel its timer.

        Args:
            job_id: The ID returned by add_job().

        Returns:
            True if found and removed, False otherwise.
        """
        with self._jobs_lock:
            if job_id not in self._jobs:
                return False

            # Cancel timer if running
            timer = self._timers.pop(job_id, None)
            if timer:
                timer.cancel()

            job = self._jobs.pop(job_id)
            logger.debug("Job removed: '{name}' (id={id})", name=job.name, id=job_id)
            return True

    def enable_job(self, job_id: str) -> bool:
        """Enable a disabled job. Starts its timer if the scheduler is running."""
        with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            job.enabled = True
            if self._running:
                self._schedule_job(job, immediate=False)
            logger.debug("Job enabled: '{name}'", name=job.name)
            return True

    def disable_job(self, job_id: str) -> bool:
        """Disable a job and cancel its timer."""
        with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            job.enabled = False
            timer = self._timers.pop(job_id, None)
            if timer:
                timer.cancel()
            logger.debug("Job disabled: '{name}'", name=job.name)
            return True

    def trigger_now(self, job_id: str) -> bool:
        """
        Trigger a job to run immediately (outside its normal schedule).

        The regular schedule continues unaffected.

        Args:
            job_id: ID of the job to run.

        Returns:
            True if the job was found and triggered.
        """
        with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                logger.warning(
                    "trigger_now: job '{id}' not found.", id=job_id
                )
                return False

        # Run in a new thread to avoid blocking the caller
        thread = threading.Thread(
            target=self._run_job,
            args=(job,),
            name=f"ihadrs-job-{job.name}-oneshot",
            daemon=True,
        )
        thread.start()
        logger.debug(
            "Job '{name}' triggered manually (one-shot).", name=job.name
        )
        return True

    # -------------------------------------------------------------------------
    # Internal Scheduling
    # -------------------------------------------------------------------------

    def _schedule_job(self, job: ScheduledJob, immediate: bool = False) -> None:
        """
        Schedule (or reschedule) a job's next execution.

        If ``immediate`` is True, runs the job in a thread RIGHT NOW and
        then reschedules normally for the next interval.

        Args:
            job: The job to schedule.
            immediate: If True, execute once now before scheduling.
        """
        if not self._running:
            return

        # Cancel any existing timer for this job
        old_timer = self._timers.pop(job.job_id, None)
        if old_timer:
            old_timer.cancel()

        if immediate:
            # Spawn a thread to run immediately, then reschedule
            thread = threading.Thread(
                target=self._run_and_reschedule,
                args=(job,),
                name=f"ihadrs-job-{job.name}",
                daemon=True,
            )
            thread.start()
        else:
            # Normal: schedule via timer
            job.next_run_time = time.time() + job.interval_seconds
            timer = threading.Timer(
                interval=job.interval_seconds,
                function=self._run_and_reschedule,
                args=(job,),
            )
            timer.name = f"ihadrs-timer-{job.name}"
            timer.daemon = True
            timer.start()
            self._timers[job.job_id] = timer

    def _run_and_reschedule(self, job: ScheduledJob) -> None:
        """Run a job and then reschedule it for its next interval."""
        self._run_job(job)
        # Reschedule if still running and job is still enabled
        if self._running and job.enabled:
            self._schedule_job(job, immediate=False)

    def _run_job(self, job: ScheduledJob) -> None:
        """
        Execute a job's function with full error isolation and timing.

        Errors are caught, logged, and tracked but never propagate —
        a failing job does not affect other jobs.
        """
        start_time = time.monotonic()
        job.last_run_time = time.time()
        job.run_count += 1

        logger.debug(
            "Running scheduled job: '{name}' (run #{count})",
            name=job.name,
            count=job.run_count,
        )

        try:
            job.func()
            elapsed = time.monotonic() - start_time
            job.last_run_duration = elapsed
            job.last_error = None

            # Warn if job is taking too long
            if elapsed > job.interval_seconds * 0.5:
                logger.warning(
                    "Job '{name}' took {ms:.0f}ms ({pct:.0f}% of interval).",
                    name=job.name,
                    ms=elapsed * 1000,
                    pct=(elapsed / job.interval_seconds) * 100,
                )

        except Exception as exc:
            elapsed = time.monotonic() - start_time
            job.last_run_duration = elapsed
            job.error_count += 1

            error_msg = f"{type(exc).__name__}: {exc}"
            job.last_error = error_msg

            logger.error(
                "Scheduled job '{name}' failed (error #{count}): {error}\n{tb}",
                name=job.name,
                count=job.error_count,
                error=error_msg,
                tb=traceback.format_exc(),
            )

            # If job has been failing consistently, emit a health warning
            if job.error_rate > 0.5 and job.run_count >= 5:
                logger.critical(
                    "Job '{name}' has >50% error rate ({rate:.0%}) over {n} runs. "
                    "Check configuration and system state.",
                    name=job.name,
                    rate=job.error_rate,
                    n=job.run_count,
                )

    # -------------------------------------------------------------------------
    # Health & Introspection
    # -------------------------------------------------------------------------

    def get_jobs(self) -> list[dict[str, Any]]:
        """Return status of all registered jobs."""
        with self._jobs_lock:
            return [job.to_dict() for job in self._jobs.values()]

    def health_check(self) -> dict[str, Any]:
        """Return scheduler health for the API /health endpoint."""
        with self._jobs_lock:
            total = len(self._jobs)
            enabled = sum(1 for j in self._jobs.values() if j.enabled)
            failing = [
                j.name
                for j in self._jobs.values()
                if not j.is_healthy and j.run_count >= 3
            ]

        status = "healthy"
        issues: list[str] = []

        if not self._running:
            status = "stopped"
            issues.append("Scheduler is not running")
        elif failing:
            status = "degraded"
            issues.extend(f"Job '{name}' has high error rate" for name in failing)

        return {
            "status": status,
            "running": self._running,
            "issues": issues,
            "total_jobs": total,
            "enabled_jobs": enabled,
            "failing_jobs": failing,
        }