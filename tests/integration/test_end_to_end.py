"""
Integration tests: End-to-end detection pipeline.
Tests the full chain: monitor event -> bus -> detection engine -> ThreatEvent -> alert.
No mocking -- real components wired together.
"""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
import pytest
from ihadrs.constants import AttackCategory, EventType, MonitorType, Severity
from ihadrs.core.event_bus import BusEvent, EventBus
from ihadrs.detection.engine import DetectionEngine
from ihadrs.models.events import make_process_created_event
from ihadrs.models.threats import ThreatEvent


def _cfg(tmp_path):
    from ihadrs.core.config import IHADRSConfig
    return IHADRSConfig.model_validate({
        "app": {"require_admin": False},
        "logging": {"console_output": False, "level": "WARNING"},
        "detection": {
            "rules_file": str(Path(__file__).parent.parent.parent / "config" / "rules.yaml"),
            "ransomware_rename_threshold": 5,
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


class TestEndToEndPipeline:

    @pytest.mark.asyncio
    async def test_malicious_event_produces_threat(self, tmp_path):
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})
        engine = DetectionEngine(_cfg(tmp_path), bus)
        await engine.initialize()
        event = make_process_created_event(
            pid=1234, name="powershell.exe",
            image_path="C:/Windows/System32/powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=4, parent_name="cmd.exe",
        )
        engine.process_event(BusEvent(event_type=EventType.PROCESS_CREATED, source="ProcessMonitor", payload=event))
        await asyncio.sleep(0.3)
        bus.stop(drain_timeout_seconds=2.0)
        assert len(threats) >= 1
        t = threats[0].payload
        assert isinstance(t, ThreatEvent)
        assert "R001" in t.evidence.triggered_rule_ids

    @pytest.mark.asyncio
    async def test_clean_event_no_threat(self, tmp_path):
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})
        engine = DetectionEngine(_cfg(tmp_path), bus)
        await engine.initialize()
        event = make_process_created_event(
            pid=100, name="notepad.exe",
            image_path="C:/Windows/System32/notepad.exe",
            command_line="notepad.exe C:/Users/alice/doc.txt",
            parent_pid=4, parent_name="explorer.exe",
        )
        engine.process_event(BusEvent(event_type=EventType.PROCESS_CREATED, source="ProcessMonitor", payload=event))
        await asyncio.sleep(0.3)
        bus.stop(drain_timeout_seconds=2.0)
        assert len(threats) == 0

    @pytest.mark.asyncio
    async def test_metrics_increment(self, tmp_path):
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        engine = DetectionEngine(_cfg(tmp_path), bus)
        await engine.initialize()
        for _ in range(5):
            event = make_process_created_event(
                pid=100, name="notepad.exe",
                image_path="C:/Windows/notepad.exe",
                command_line="notepad.exe",
                parent_pid=4, parent_name="explorer.exe",
            )
            engine.process_event(BusEvent(event_type=EventType.PROCESS_CREATED, source="ProcessMonitor", payload=event))
        bus.stop(drain_timeout_seconds=2.0)
        assert engine.get_metrics()["events_processed"] >= 5

    @pytest.mark.asyncio
    async def test_threat_event_all_fields(self, tmp_path):
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})
        engine = DetectionEngine(_cfg(tmp_path), bus)
        await engine.initialize()
        event = make_process_created_event(
            pid=7777, name="powershell.exe",
            image_path="C:/Windows/System32/powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=4, parent_name="cmd.exe",
        )
        engine.process_event(BusEvent(event_type=EventType.PROCESS_CREATED, source="ProcessMonitor", payload=event))
        await asyncio.sleep(0.3)
        bus.stop(drain_timeout_seconds=2.0)
        assert threats
        t = threats[0].payload
        assert t.threat_id and t.severity in Severity and t.attack_category in AttackCategory
        assert 0.0 < t.confidence <= 1.0
        assert t.mitre_techniques and t.affected_resource and t.summary
        assert t.evidence.triggered_rule_ids

    @pytest.mark.asyncio
    async def test_high_severity_for_office_chain(self, tmp_path):
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        threats = []
        bus.subscribe("sink", threats.append, {EventType.IHADRS_DETECTION_TRIGGERED})
        engine = DetectionEngine(_cfg(tmp_path), bus)
        await engine.initialize()
        event = make_process_created_event(
            pid=5555, name="powershell.exe",
            image_path="C:/Windows/System32/powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=2222, parent_name="winword.exe",
        )
        engine.process_event(BusEvent(event_type=EventType.PROCESS_CREATED, source="ProcessMonitor", payload=event))
        await asyncio.sleep(0.3)
        bus.stop(drain_timeout_seconds=2.0)
        assert threats
        severities = {b.payload.severity for b in threats if isinstance(b.payload, ThreatEvent)}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities