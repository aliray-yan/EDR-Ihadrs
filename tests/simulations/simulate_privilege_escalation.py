"""
Simulation: Privilege Escalation / Credential Dump
Tests: R005 (Credential Dumping), R018 (Security Tool Tampering),
       elevated process detection

Safe simulation — no actual credentials accessed.
"""

from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
import pytest
from ihadrs.constants import AttackCategory, EventType, MonitorType, Severity
from ihadrs.core.event_bus import BusEvent, EventBus
from ihadrs.detection.engine import DetectionEngine
from ihadrs.models.events import make_process_created_event, RegistryEvent
from ihadrs.models.threats import ThreatEvent


def _make_config(tmp_path):
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


class TestPrivilegeEscalationSimulation:

    @pytest.mark.asyncio
    @pytest.mark.simulation
    async def test_mimikatz_detected(self, tmp_path):
        """Mimikatz execution triggers credential dumping alert (R005)."""
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})

        config = _make_config(tmp_path)
        engine = DetectionEngine(config, bus)
        await engine.initialize()

        event = make_process_created_event(
            pid=7777,
            name="mimikatz.exe",
            image_path="C:/Users/alice/AppData/Local/Temp/mimikatz.exe",
            command_line="mimikatz.exe sekurlsa::logonpasswords exit",
            parent_pid=1234,
            parent_name="cmd.exe",
            is_elevated=True,
        )
        event.is_elevated = True
        engine.process_event(BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        ))
        await asyncio.sleep(0.5)
        bus.stop(drain_timeout_seconds=2.0)

        assert len(threats) >= 1, "Mimikatz NOT detected"
        threat = threats[0].payload
        assert "R005" in threat.evidence.triggered_rule_ids, (
            f"Expected R005, got {threat.evidence.triggered_rule_ids}"
        )
        assert threat.severity in (Severity.CRITICAL, Severity.HIGH)
        print(
            f"\n✅ MIMIKATZ SIMULATION PASSED\n"
            f"   Severity: {threat.severity.value}\n"
            f"   Category: {threat.attack_category.value}"
        )

    @pytest.mark.asyncio
    @pytest.mark.simulation
    async def test_defender_disable_detected(self, tmp_path):
        """Disabling Windows Defender triggers defense evasion alert (R018)."""
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})

        config = _make_config(tmp_path)
        engine = DetectionEngine(config, bus)
        await engine.initialize()

        event = make_process_created_event(
            pid=8888,
            name="powershell.exe",
            image_path="C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            command_line="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
            parent_pid=1234,
            parent_name="cmd.exe",
        )
        engine.process_event(BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        ))
        await asyncio.sleep(0.5)
        bus.stop(drain_timeout_seconds=2.0)

        rule_ids = set()
        for b in threats:
            if isinstance(b.payload, ThreatEvent):
                rule_ids.update(b.payload.evidence.triggered_rule_ids)

        assert "R018" in rule_ids, f"Expected R018, got {rule_ids}"
        print(f"\n✅ DEFENDER DISABLE SIMULATION PASSED — rules: {rule_ids}")

    @pytest.mark.asyncio
    @pytest.mark.simulation
    async def test_shadow_copy_deletion_detected(self, tmp_path):
        """Shadow copy deletion triggers inhibit-recovery alert (R004)."""
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})

        config = _make_config(tmp_path)
        engine = DetectionEngine(config, bus)
        await engine.initialize()

        event = make_process_created_event(
            pid=9999,
            name="vssadmin.exe",
            image_path="C:/Windows/System32/vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            parent_pid=1234,
            parent_name="cmd.exe",
        )
        engine.process_event(BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        ))
        await asyncio.sleep(0.5)
        bus.stop(drain_timeout_seconds=2.0)

        rule_ids = set()
        for b in threats:
            if isinstance(b.payload, ThreatEvent):
                rule_ids.update(b.payload.evidence.triggered_rule_ids)

        assert "R004" in rule_ids, f"Expected R004, got {rule_ids}"
        print(f"\n✅ SHADOW COPY DELETION SIMULATION PASSED — rules: {rule_ids}")


if __name__ == "__main__":
    async def main():
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            sim = TestPrivilegeEscalationSimulation()
            await sim.test_mimikatz_detected(p)
            await sim.test_defender_disable_detected(p)
            await sim.test_shadow_copy_deletion_detected(p)
            print("\n✅ All privilege escalation simulations passed.")
    asyncio.run(main())