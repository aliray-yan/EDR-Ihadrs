"""
Simulation: Brute Force / Credential Stuffing Attack
Tests: R016 (Authentication Failure Spike), BRUTE_FORCE_AUTH behavioral,
       CREDENTIAL_STUFFING_SUCCESS correlation pattern.

Usage:
    python tests/simulations/simulate_bruteforce.py
    python -m pytest tests/simulations/simulate_bruteforce.py -v
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest

from ihadrs.constants import AttackCategory, EventType, MonitorType, Severity
from ihadrs.core.event_bus import BusEvent, EventBus, EventPriority
from ihadrs.detection.engine import DetectionEngine
from ihadrs.models.events import AuthenticationEvent
from ihadrs.models.threats import ThreatEvent


def _make_config(tmp_path: Path):
    from ihadrs.core.config import IHADRSConfig
    return IHADRSConfig.model_validate({
        "app": {"require_admin": False},
        "logging": {"console_output": False, "level": "WARNING"},
        "detection": {
            "rules_file": "config/rules.yaml",
            "ransomware_rename_threshold": 20,
            "ransomware_time_window_seconds": 10.0,
            "brute_force_failure_threshold": 5,
            "brute_force_time_window_seconds": 60.0,
            "bulk_file_read_threshold": 100,
            "bulk_file_read_window_seconds": 5.0,
            "c2_beacon_min_interval_seconds": 30,
            "c2_beacon_max_jitter_pct": 0.15,
            "correlation_window_seconds": 300,
        },
        "monitors": {"file_watch_paths": [str(tmp_path)], "ip_whitelist": []},
        "api": {"enabled": False, "token": "test"},
        "response": {"mode": "manual"},
    })


def _make_auth_failure(
    source_ip: str = "192.168.100.50",
    target_user: str = "Administrator",
) -> AuthenticationEvent:
    return AuthenticationEvent(
        event_type=EventType.AUTH_LOGON_FAILURE,
        source_monitor=MonitorType.AUTHENTICATION,
        hostname="TARGET-PC",
        success=False,
        logon_type=3,
        logon_type_name="Network",
        target_username=target_user,
        source_ip=source_ip,
        auth_package="NTLM",
        windows_event_id=4625,
    )


def _make_auth_success(
    source_ip: str = "192.168.100.50",
    target_user: str = "Administrator",
) -> AuthenticationEvent:
    return AuthenticationEvent(
        event_type=EventType.AUTH_LOGON_SUCCESS,
        source_monitor=MonitorType.AUTHENTICATION,
        hostname="TARGET-PC",
        success=True,
        logon_type=3,
        logon_type_name="Network",
        target_username=target_user,
        source_ip=source_ip,
        auth_package="NTLM",
        windows_event_id=4624,
    )


class TestBruteForceSimulation:

    @pytest.mark.asyncio
    @pytest.mark.simulation
    async def test_brute_force_detected_at_threshold(self, tmp_path):
        """
        5 authentication failures from same IP within 60s → brute force alert.
        """
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()

        detected: list[BusEvent] = []
        bus.subscribe("sink", detected.append, {EventType.IHADRS_DETECTION_TRIGGERED})

        config = _make_config(tmp_path)
        engine = DetectionEngine(config, bus)
        await engine.initialize()

        attacker_ip = "10.20.30.40"

        # Simulate 6 rapid failures (above threshold of 5)
        start = time.monotonic()
        for i in range(6):
            event = _make_auth_failure(source_ip=attacker_ip, target_user="admin")
            engine.process_event(BusEvent(
                event_type=EventType.AUTH_LOGON_FAILURE,
                source="AuthMonitor",
                payload=event,
            ))
            await asyncio.sleep(0.02)

        # Wait for detection
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not detected:
            await asyncio.sleep(0.1)

        latency = time.monotonic() - start
        bus.stop(drain_timeout_seconds=2.0)

        assert len(detected) >= 1, "Brute force attack NOT detected"
        threat: ThreatEvent = detected[0].payload
        assert isinstance(threat, ThreatEvent)
        assert threat.attack_category in (
            AttackCategory.BRUTE_FORCE,
            AttackCategory.CREDENTIAL_THEFT,
        ), f"Expected BRUTE_FORCE, got {threat.attack_category.value}"
        assert threat.severity in (Severity.HIGH, Severity.CRITICAL)
        assert latency <= 5.0

        print(
            f"\n✅ BRUTE FORCE SIMULATION PASSED\n"
            f"   Category: {threat.attack_category.value}\n"
            f"   Severity: {threat.severity.value}\n"
            f"   Confidence: {threat.confidence:.0%}\n"
            f"   Latency: {latency:.2f}s"
        )

    @pytest.mark.asyncio
    @pytest.mark.simulation
    async def test_credential_stuffing_chain_detected(self, tmp_path):
        """
        Multiple failures from same IP followed by success → credential stuffing.
        """
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()

        detected: list[BusEvent] = []
        bus.subscribe("sink", detected.append, {EventType.IHADRS_DETECTION_TRIGGERED})

        config = _make_config(tmp_path)
        engine = DetectionEngine(config, bus)
        await engine.initialize()

        attacker_ip = "5.6.7.8"

        # Stage 1: 5 failures (credential stuffing attempts)
        for i in range(5):
            engine.process_event(BusEvent(
                event_type=EventType.AUTH_LOGON_FAILURE,
                source="AuthMonitor",
                payload=_make_auth_failure(attacker_ip, f"user{i}"),
            ))
            await asyncio.sleep(0.02)

        # Stage 2: SUCCESS — attacker found valid credentials
        engine.process_event(BusEvent(
            event_type=EventType.AUTH_LOGON_SUCCESS,
            source="AuthMonitor",
            payload=_make_auth_success(attacker_ip, "administrator"),
        ))

        await asyncio.sleep(0.5)
        bus.stop(drain_timeout_seconds=2.0)

        # Should detect either brute force or credential stuffing
        brute_force = [
            b for b in detected
            if isinstance(b.payload, ThreatEvent)
            and b.payload.attack_category in (
                AttackCategory.BRUTE_FORCE,
                AttackCategory.CREDENTIAL_THEFT,
            )
        ]
        assert len(brute_force) >= 1, (
            "Credential stuffing chain NOT detected. "
            f"Got {len(detected)} total detections."
        )
        print(
            f"\n✅ CREDENTIAL STUFFING SIMULATION PASSED\n"
            f"   Detections: {len(detected)}"
        )

    @pytest.mark.asyncio
    @pytest.mark.simulation
    async def test_few_failures_no_alert(self, tmp_path):
        """
        Fewer than threshold failures must NOT trigger brute force alert (FP test).
        """
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()

        detected: list[BusEvent] = []
        bus.subscribe("sink", detected.append, {EventType.IHADRS_DETECTION_TRIGGERED})

        config = _make_config(tmp_path)
        engine = DetectionEngine(config, bus)
        await engine.initialize()

        # Only 2 failures — well below threshold of 5
        for i in range(2):
            engine.process_event(BusEvent(
                event_type=EventType.AUTH_LOGON_FAILURE,
                source="AuthMonitor",
                payload=_make_auth_failure("9.9.9.9", "user"),
            ))
            await asyncio.sleep(0.05)

        await asyncio.sleep(0.3)
        bus.stop(drain_timeout_seconds=2.0)

        bf_alerts = [
            b for b in detected
            if isinstance(b.payload, ThreatEvent)
            and b.payload.attack_category == AttackCategory.BRUTE_FORCE
        ]
        assert len(bf_alerts) == 0, (
            f"FALSE POSITIVE: {len(bf_alerts)} brute force alerts from only 2 failures"
        )
        print("\n✅ BRUTE FORCE FALSE POSITIVE TEST PASSED")


if __name__ == "__main__":
    async def main():
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sim = TestBruteForceSimulation()
            await sim.test_brute_force_detected_at_threshold(tmp_path)
            await sim.test_credential_stuffing_chain_detected(tmp_path)
            await sim.test_few_failures_no_alert(tmp_path)
            print("\n✅ All brute force simulations passed.")

    asyncio.run(main())