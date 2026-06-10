"""
Unit tests for models.events and models.threats.

Tests verify:
- Event dataclass field defaults and types
- Event factory functions produce correct objects
- ThreatEvent serialization (to_dict, to_log_dict, to_alert_dict)
- ThreatEvent derived properties (is_critical, requires_immediate_action)
- Evidence and context serialization
- RemediationStep ordering
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ihadrs.constants import (
    AttackCategory,
    EventType,
    MonitorType,
    ResponseStatus,
    Severity,
)
from ihadrs.models.events import (
    AuthenticationEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RegistryEvent,
    ServiceEvent,
    SystemEvent,
    make_file_event,
    make_network_connection_event,
    make_process_created_event,
    make_process_terminated_event,
    make_registry_event,
)
from ihadrs.models.threats import (
    AutomatedActionRecord,
    FileContext,
    NetworkContext,
    ProcessContext,
    RemediationStep,
    ThreatEvent,
    ThreatEvidence,
)


# =============================================================================
# PROCESS EVENT TESTS
# =============================================================================

class TestProcessEvent:
    """ProcessEvent dataclass and factory."""

    def test_factory_sets_correct_event_type(self) -> None:
        event = make_process_created_event(1234, "cmd.exe", "C:\\cmd.exe", "cmd /c", 0, "system")
        assert event.event_type == EventType.PROCESS_CREATED
        assert event.source_monitor == MonitorType.PROCESS

    def test_factory_preserves_all_fields(self) -> None:
        event = make_process_created_event(
            pid=9999,
            name="powershell.exe",
            image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc dGVzdA==",
            parent_pid=1234,
            parent_name="cmd.exe",
            username="alice",
            hostname="WORKSTATION-01",
            is_elevated=True,
        )
        assert event.pid == 9999
        assert event.process_name == "powershell.exe"
        assert event.command_line == "powershell.exe -enc dGVzdA=="
        assert event.parent_pid == 1234
        assert event.parent_name == "cmd.exe"
        assert event.username == "alice"
        assert event.hostname == "WORKSTATION-01"
        assert event.is_elevated is True

    def test_terminated_event_factory(self) -> None:
        event = make_process_terminated_event(
            pid=5555, name="malware.exe", lifetime_seconds=120.5
        )
        assert event.event_type == EventType.PROCESS_TERMINATED
        assert event.pid == 5555
        assert event.lifetime_seconds == pytest.approx(120.5)

    def test_event_has_unique_id(self) -> None:
        e1 = make_process_created_event(1, "a.exe", "", "", 0, "")
        e2 = make_process_created_event(2, "b.exe", "", "", 0, "")
        assert e1.event_id != e2.event_id

    def test_event_timestamp_is_utc(self) -> None:
        event = make_process_created_event(1, "a.exe", "", "", 0, "")
        assert event.timestamp.tzinfo == timezone.utc

    def test_to_dict_contains_required_keys(self) -> None:
        event = make_process_created_event(1234, "cmd.exe", "C:\\cmd.exe", "cmd /c", 0, "system")
        d = event.to_dict()
        required = {"event_id", "event_type", "pid", "process_name", "source_monitor"}
        assert required.issubset(d.keys())

    def test_to_dict_event_type_is_string(self) -> None:
        event = make_process_created_event(1, "a.exe", "", "", 0, "")
        d = event.to_dict()
        assert isinstance(d["event_type"], str)
        assert d["event_type"] == "process.created"


# =============================================================================
# NETWORK EVENT TESTS
# =============================================================================

class TestNetworkEvent:
    """NetworkEvent dataclass and factory."""

    def test_factory_sets_correct_fields(self) -> None:
        event = make_network_connection_event(
            pid=1234,
            process_name="chrome.exe",
            local_ip="192.168.1.100",
            local_port=54321,
            remote_ip="8.8.8.8",
            remote_port=443,
            protocol="tcp",
            direction="outbound",
            state="ESTABLISHED",
            remote_hostname="dns.google.com",
        )
        assert event.pid == 1234
        assert event.process_name == "chrome.exe"
        assert event.remote_ip == "8.8.8.8"
        assert event.remote_port == 443
        assert event.remote_hostname == "dns.google.com"
        assert event.event_type == EventType.NETWORK_CONNECTION_OPENED

    def test_to_dict_contains_network_fields(self) -> None:
        event = make_network_connection_event(
            1, "p.exe", "127.0.0.1", 8080, "1.2.3.4", 443
        )
        d = event.to_dict()
        assert "remote_ip" in d
        assert "remote_port" in d
        assert "local_ip" in d
        assert "local_port" in d


# =============================================================================
# FILE EVENT TESTS
# =============================================================================

class TestFileEvent:
    """FileEvent dataclass and factory."""

    def test_renamed_event_captures_extensions(self) -> None:
        event = make_file_event(
            file_path="C:\\Users\\alice\\doc.docx.encrypted",
            change_type="renamed",
            old_path="C:\\Users\\alice\\doc.docx",
            new_path="C:\\Users\\alice\\doc.docx.encrypted",
        )
        assert event.event_type == EventType.FILE_RENAMED
        assert event.new_extension == ".encrypted"
        assert event.file_extension == ".encrypted"

    def test_executable_flag_set_for_exe(self) -> None:
        event = make_file_event(
            file_path="C:\\temp\\payload.exe",
            change_type="created",
        )
        assert event.is_executable is True

    def test_non_executable_flag_for_text_file(self) -> None:
        event = make_file_event(
            file_path="C:\\temp\\readme.txt",
            change_type="created",
        )
        assert event.is_executable is False

    def test_directory_extracted_from_path(self) -> None:
        event = make_file_event(
            file_path="C:\\Users\\alice\\Documents\\report.docx",
            change_type="modified",
        )
        assert "Documents" in event.directory

    def test_file_name_extracted(self) -> None:
        event = make_file_event("C:\\temp\\evil.exe", "created")
        assert event.file_name == "evil.exe"


# =============================================================================
# REGISTRY EVENT TESTS
# =============================================================================

class TestRegistryEvent:
    """RegistryEvent dataclass and factory."""

    def test_persistence_path_detection(self) -> None:
        event = make_registry_event(
            hive="HKCU",
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            change_type="value_set",
            value_name="Malware",
            value_data="C:\\temp\\malware.exe",
        )
        assert event.is_persistence_path is True

    def test_non_persistence_path_not_flagged(self) -> None:
        event = make_registry_event(
            hive="HKCU",
            key_path="SOFTWARE\\SomeApp\\Settings",
            change_type="value_set",
            value_name="Theme",
            value_data="Dark",
        )
        assert event.is_persistence_path is False

    def test_full_path_constructed(self) -> None:
        event = make_registry_event(
            hive="HKLM",
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            change_type="value_set",
        )
        assert event.full_path == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"


# =============================================================================
# THREAT EVENT TESTS
# =============================================================================

class TestThreatEvent:
    """ThreatEvent model, properties, and serialization."""

    def _make_threat(self, **overrides: object) -> ThreatEvent:
        defaults: dict = {
            "source_monitor": "process_monitor",
            "attack_category": AttackCategory.MALWARE_EXECUTION,
            "severity": Severity.HIGH,
            "confidence": 0.85,
            "mitre_tactics": ["TA0002"],
            "mitre_techniques": ["T1059.001"],
            "mitre_tactic_names": ["Execution"],
            "mitre_technique_names": ["PowerShell"],
            "affected_resource": "process:powershell.exe:4444",
            "summary": "Encoded PowerShell execution",
            "user_explanation": "PowerShell ran encoded commands.",
            "technical_details": "Process PID 4444 used -enc flag.",
            "evidence": ThreatEvidence(triggered_rule_ids=["R001"]),
        }
        defaults.update(overrides)
        return ThreatEvent(**defaults)

    def test_is_critical_for_critical_severity(self) -> None:
        t = self._make_threat(severity=Severity.CRITICAL)
        assert t.is_critical is True

    def test_is_not_critical_for_high_severity(self) -> None:
        t = self._make_threat(severity=Severity.HIGH)
        assert t.is_critical is False

    def test_is_high_confidence(self) -> None:
        t = self._make_threat(confidence=0.9)
        assert t.is_high_confidence is True

    def test_is_not_high_confidence_below_threshold(self) -> None:
        t = self._make_threat(confidence=0.7)
        assert t.is_high_confidence is False

    def test_requires_immediate_action_critical_high_confidence(self) -> None:
        t = self._make_threat(severity=Severity.CRITICAL, confidence=0.9)
        assert t.requires_immediate_action is True

    def test_not_requires_action_if_false_positive(self) -> None:
        t = self._make_threat(
            severity=Severity.CRITICAL,
            confidence=0.9,
            marked_as_false_positive=True,
        )
        assert t.requires_immediate_action is False

    def test_not_requires_action_low_confidence(self) -> None:
        t = self._make_threat(severity=Severity.CRITICAL, confidence=0.5)
        assert t.requires_immediate_action is False

    def test_alert_icon_matches_severity(self) -> None:
        for sev, expected_icon in [
            (Severity.LOW, "🟢"),
            (Severity.MEDIUM, "🟡"),
            (Severity.HIGH, "🟠"),
            (Severity.CRITICAL, "🔴"),
        ]:
            t = self._make_threat(severity=sev)
            assert t.alert_icon == expected_icon

    def test_primary_technique_returns_first(self) -> None:
        t = self._make_threat(
            mitre_techniques=["T1059.001", "T1218"],
            mitre_technique_names=["PowerShell", "LOLBin"],
        )
        assert t.primary_technique == "T1059.001"
        assert t.primary_technique_name == "PowerShell"

    def test_primary_technique_empty_when_no_techniques(self) -> None:
        t = self._make_threat(
            mitre_techniques=[],
            mitre_technique_names=[],
        )
        assert t.primary_technique == ""
        assert t.primary_technique_name == ""

    def test_unique_threat_ids(self) -> None:
        t1 = self._make_threat()
        t2 = self._make_threat()
        assert t1.threat_id != t2.threat_id

    def test_to_dict_has_all_top_level_keys(self) -> None:
        t = self._make_threat()
        d = t.to_dict()
        required_keys = {
            "threat_id", "timestamp", "severity", "attack_category",
            "confidence", "mitre", "affected_resource", "summary",
            "explanation", "evidence", "remediation", "automated_actions",
            "response_status", "false_positive", "tags", "references",
        }
        assert required_keys.issubset(d.keys())

    def test_to_dict_severity_is_string(self) -> None:
        t = self._make_threat(severity=Severity.CRITICAL)
        d = t.to_dict()
        assert d["severity"] == "CRITICAL"
        assert isinstance(d["severity"], str)

    def test_to_dict_confidence_rounded(self) -> None:
        t = self._make_threat(confidence=0.853721)
        d = t.to_dict()
        assert d["confidence"] == pytest.approx(0.854, rel=1e-2)

    def test_to_log_dict_is_compact(self) -> None:
        t = self._make_threat()
        d = t.to_log_dict()
        # Log dict should have fewer keys than full dict
        assert len(d) < len(t.to_dict())
        # But still have essentials
        assert "threat_id" in d
        assert "severity" in d
        assert "attack_category" in d

    def test_to_alert_dict_has_icon_and_color(self) -> None:
        t = self._make_threat(severity=Severity.CRITICAL)
        d = t.to_alert_dict()
        assert "icon" in d
        assert "color" in d
        assert d["icon"] == "🔴"
        assert d["color"] == "#dc3545"

    def test_repr_is_informative(self) -> None:
        t = self._make_threat()
        r = repr(t)
        assert "ThreatEvent" in r
        assert "HIGH" in r

    def test_remediation_steps_ordered_by_step_number(self) -> None:
        steps = [
            RemediationStep(3, "recovery", "Step 3"),
            RemediationStep(1, "immediate", "Step 1"),
            RemediationStep(2, "investigation", "Step 2"),
        ]
        t = self._make_threat(remediation_steps=steps)
        sorted_steps = sorted(t.remediation_steps, key=lambda s: s.step_number)
        assert sorted_steps[0].description == "Step 1"
        assert sorted_steps[2].description == "Step 3"


# =============================================================================
# THREAT EVIDENCE TESTS
# =============================================================================

class TestThreatEvidence:
    """ThreatEvidence serialization."""

    def test_to_dict_with_ml_score(self) -> None:
        ev = ThreatEvidence(
            triggered_rule_ids=["R001", "R002"],
            triggered_rule_names=["Encoded PS", "Office Shell"],
            iocs=["4444", "mimikatz"],
            ml_anomaly_score=-0.8,
            ml_contributing_features=[
                {"feature": "path_is_temp", "weight": 1.5}
            ],
        )
        d = ev.to_dict()
        assert d["ml_anomaly_score"] == pytest.approx(-0.8)
        assert len(d["ml_features"]) == 1
        assert "4444" in d["iocs"]


# =============================================================================
# AUTOMATED ACTION RECORD TESTS
# =============================================================================

class TestAutomatedActionRecord:
    """AutomatedActionRecord serialization."""

    def test_to_dict_contains_all_fields(self) -> None:
        record = AutomatedActionRecord(
            action_type="kill_process",
            target="malware.exe:4444",
            success=True,
            result_message="Process terminated",
            rollback_available=True,
            rollback_data={"pid": 4444, "name": "malware.exe"},
        )
        d = record.to_dict()
        assert d["action_type"] == "kill_process"
        assert d["success"] is True
        assert d["rollback_available"] is True
        assert "timestamp" in d


# =============================================================================
# SEVERITY ORDERING TESTS
# =============================================================================

class TestSeverityOrdering:
    """Severity enum comparison operators."""

    def test_low_less_than_critical(self) -> None:
        assert Severity.LOW < Severity.CRITICAL

    def test_high_greater_than_medium(self) -> None:
        assert Severity.HIGH > Severity.MEDIUM

    def test_same_severity_equal(self) -> None:
        assert Severity.HIGH == Severity.HIGH

    def test_ordering_all_levels(self) -> None:
        levels = [Severity.CRITICAL, Severity.LOW, Severity.HIGH, Severity.MEDIUM]
        sorted_levels = sorted(levels)
        assert sorted_levels == [
            Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
        ]

    def test_numeric_values_correct(self) -> None:
        assert Severity.LOW.numeric == 1
        assert Severity.MEDIUM.numeric == 2
        assert Severity.HIGH.numeric == 3
        assert Severity.CRITICAL.numeric == 4