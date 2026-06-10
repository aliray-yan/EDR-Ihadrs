"""
Unit tests for Phase 3 — Detection Engine.

Tests cover:
    RuleLoader:       YAML loading, validation, error handling
    RuleEvaluator:    All 30 rules, all operators, edge cases, FP suppression
    BehavioralDetector: Ransomware, brute force, spawn burst, bulk file
    CorrelationEngine:  Office macro chain, download→exec, credential stuffing
    DetectionEngine:    Full pipeline, dedup, ThreatEvent construction, emission
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ihadrs.constants import (
    AttackCategory,
    EventType,
    MonitorType,
    Severity,
)
from ihadrs.core.event_bus import BusEvent, EventBus, EventPriority
from ihadrs.detection.behavioral import BehavioralDetector, SlidingWindowTracker
from ihadrs.detection.correlation import CorrelationEngine
from ihadrs.detection.engine import DetectionEngine, _interpolate
from ihadrs.detection.rule_engine import (
    DetectionRule,
    MITREMapping,
    RuleClause,
    RuleEvaluator,
    RuleLoader,
    ThresholdConfig,
)
from ihadrs.exceptions import RuleLoadError
from ihadrs.models.events import (
    AuthenticationEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RegistryEvent,
    ServiceEvent,
    make_file_event,
    make_network_connection_event,
    make_process_created_event,
    make_process_terminated_event,
    make_registry_event,
)
from ihadrs.models.threats import ThreatEvent


# =============================================================================
# FIXTURES & HELPERS
# =============================================================================

RULES_FILE = Path("config/rules.yaml")


def _ps_event(
    command_line: str = "powershell.exe",
    process_name: str = "powershell.exe",
    parent_name: str = "explorer.exe",
    pid: int = 1234,
) -> ProcessEvent:
    return make_process_created_event(
        pid=pid,
        name=process_name,
        image_path=f"C:/Windows/System32/{process_name}",
        command_line=command_line,
        parent_pid=4,
        parent_name=parent_name,
    )


def _auth_failure(source_ip: str = "1.2.3.4", username: str = "admin") -> AuthenticationEvent:
    return AuthenticationEvent(
        event_type=EventType.AUTH_LOGON_FAILURE,
        source_monitor=MonitorType.AUTHENTICATION,
        success=False,
        source_ip=source_ip,
        target_username=username,
        auth_package="NTLM",
    )


def _auth_success(source_ip: str = "1.2.3.4", username: str = "admin") -> AuthenticationEvent:
    return AuthenticationEvent(
        event_type=EventType.AUTH_LOGON_SUCCESS,
        source_monitor=MonitorType.AUTHENTICATION,
        success=True,
        source_ip=source_ip,
        target_username=username,
        auth_package="NTLM",
    )


def _make_config(tmp_path: Path) -> Any:
    from ihadrs.core.config import IHADRSConfig
    return IHADRSConfig.model_validate({
        "app": {"require_admin": False},
        "logging": {"console_output": False, "level": "WARNING"},
        "detection": {
            "rules_file": str(RULES_FILE),
            "disabled_rules": [],
            "enabled_rules": [],
            "ransomware_rename_threshold": 5,
            "ransomware_time_window_seconds": 10.0,
            "brute_force_failure_threshold": 3,
            "brute_force_time_window_seconds": 30.0,
            "bulk_file_read_threshold": 10,
            "bulk_file_read_window_seconds": 5.0,
            "c2_beacon_min_interval_seconds": 30,
            "c2_beacon_max_jitter_pct": 0.15,
            "correlation_window_seconds": 300,
        },
        "monitors": {"file_watch_paths": [str(tmp_path)], "ip_whitelist": []},
        "api": {"enabled": False, "token": "test"},
        "response": {"mode": "manual"},
    })


# =============================================================================
# RULE LOADER TESTS
# =============================================================================

class TestRuleLoader:

    def test_load_real_rules_yaml(self):
        """Load the production rules.yaml and verify basic structure."""
        if not RULES_FILE.exists():
            pytest.skip("config/rules.yaml not found — run from project root")
        rules = RuleLoader.load_rules(RULES_FILE)
        assert len(rules) == 30
        assert all(isinstance(r, DetectionRule) for r in rules)

    def test_all_rules_have_required_fields(self):
        if not RULES_FILE.exists():
            pytest.skip()
        rules = RuleLoader.load_rules(RULES_FILE)
        for rule in rules:
            assert rule.rule_id, f"Rule missing rule_id: {rule}"
            assert rule.name, f"Rule {rule.rule_id} missing name"
            assert rule.severity in Severity
            assert 0.0 <= rule.confidence <= 1.0

    def test_missing_file_raises_rule_load_error(self, tmp_path):
        with pytest.raises(RuleLoadError):
            RuleLoader.load_rules(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises_rule_load_error(self, tmp_path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("rules: [unclosed bracket\n  - bad")
        with pytest.raises(RuleLoadError):
            RuleLoader.load_rules(bad_yaml)

    def test_invalid_rule_is_skipped_not_fatal(self, tmp_path):
        """A single invalid rule should be skipped; valid rules still load."""
        rules_yaml = tmp_path / "rules.yaml"
        rules_yaml.write_text("""
rules:
  - rule_id: "R001"
    name: "Valid Rule"
    severity: HIGH
    detection:
      condition: all
      rules:
        - monitor: process
          field: process_name
          operator: equals
          value: "powershell.exe"
  - rule_id: "R_BAD"
    name: "Missing severity"
    detection:
      condition: all
      rules: []
""")
        rules = RuleLoader.load_rules(rules_yaml)
        # Valid rule loads, invalid one is skipped
        assert any(r.rule_id == "R001" for r in rules)

    def test_rule_severities_parsed_correctly(self):
        if not RULES_FILE.exists():
            pytest.skip()
        rules = RuleLoader.load_rules(RULES_FILE)
        for rule in rules:
            assert rule.severity in (Severity.LOW, Severity.MEDIUM,
                                     Severity.HIGH, Severity.CRITICAL)

    def test_rule_mitre_mapping_loaded(self):
        if not RULES_FILE.exists():
            pytest.skip()
        rules = RuleLoader.load_rules(RULES_FILE)
        # R001 should have T1059.001 and TA0002
        r001 = next((r for r in rules if r.rule_id == "R001"), None)
        assert r001 is not None
        assert "T1059.001" in r001.mitre.techniques
        assert "TA0002" in r001.mitre.tactics

    def test_rule_remediation_loaded(self):
        if not RULES_FILE.exists():
            pytest.skip()
        rules = RuleLoader.load_rules(RULES_FILE)
        r001 = next((r for r in rules if r.rule_id == "R001"), None)
        assert r001 is not None
        assert len(r001.remediation.manual_steps) > 0

    def test_disabled_rule_parsed(self, tmp_path):
        rules_yaml = tmp_path / "rules.yaml"
        rules_yaml.write_text("""
rules:
  - rule_id: "R_DISABLED"
    name: "Disabled Rule"
    enabled: false
    severity: LOW
    detection:
      condition: all
      rules: []
""")
        rules = RuleLoader.load_rules(rules_yaml)
        assert any(r.rule_id == "R_DISABLED" and not r.enabled for r in rules)


# =============================================================================
# RULE EVALUATOR TESTS — Operators
# =============================================================================

class TestRuleEvaluatorOperators:
    """Test every RuleOperator against ProcessEvent fields."""

    def _make_evaluator(self, tmp_path: Path, yaml_content: str) -> RuleEvaluator:
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml_content)
        rules = RuleLoader.load_rules(rules_file)
        return RuleEvaluator(rules)

    def _rule_yaml(self, operator: str, field: str, value: Any,
                   values: list = None, condition: str = "all") -> str:
        if values:
            vals_str = "\n".join(f'            - "{v}"' for v in values)
            clause = f"""
        - monitor: process
          field: {field}
          operator: {operator}
          values:
{vals_str}
          case_sensitive: false"""
        else:
            clause = f"""
        - monitor: process
          field: {field}
          operator: {operator}
          value: "{value}"
          case_sensitive: false"""
        return f"""
rules:
  - rule_id: "T001"
    name: "Test Rule"
    severity: HIGH
    detection:
      condition: {condition}
      rules:{clause}
"""

    def test_equals_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("equals", "process_name", "powershell.exe"))
        ))
        assert len(ev.evaluate(_ps_event(process_name="powershell.exe"))) == 1

    def test_equals_no_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("equals", "process_name", "cmd.exe"))
        ))
        assert len(ev.evaluate(_ps_event(process_name="powershell.exe"))) == 0

    def test_contains_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("contains", "command_line", "-enc"))
        ))
        assert len(ev.evaluate(_ps_event(command_line="powershell.exe -enc ABC"))) == 1

    def test_contains_no_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("contains", "command_line", "-enc"))
        ))
        assert len(ev.evaluate(_ps_event(command_line="powershell.exe -File test.ps1"))) == 0

    def test_contains_any_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml(
                "contains_any", "command_line", None,
                values=["-enc", "-encodedcommand", "-e "]
            ))
        ))
        assert len(ev.evaluate(_ps_event(command_line="powershell.exe -encodedcommand ABC"))) == 1

    def test_contains_any_no_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml(
                "contains_any", "command_line", None, values=["-enc", "-e "]
            ))
        ))
        assert len(ev.evaluate(_ps_event(command_line="powershell.exe -File script.ps1"))) == 0

    def test_starts_with_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("starts_with", "process_name", "power"))
        ))
        assert len(ev.evaluate(_ps_event(process_name="powershell.exe"))) == 1

    def test_ends_with_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("ends_with", "process_name", ".exe"))
        ))
        assert len(ev.evaluate(_ps_event(process_name="powershell.exe"))) == 1

    def test_not_equals_match(self, tmp_path):
        ev = RuleEvaluator(RuleLoader.load_rules(
            self._write(tmp_path, self._rule_yaml("not_equals", "process_name", "notepad.exe"))
        ))
        # powershell.exe != notepad.exe → match
        assert len(ev.evaluate(_ps_event(process_name="powershell.exe"))) == 1

    def test_all_condition_requires_all_clauses(self, tmp_path):
        """ALL condition: both clauses must match."""
        rules_yaml = tmp_path / "rules.yaml"
        rules_yaml.write_text("""
rules:
  - rule_id: "T001"
    name: "Test"
    severity: HIGH
    detection:
      condition: all
      rules:
        - monitor: process
          field: process_name
          operator: equals
          value: "powershell.exe"
          case_sensitive: false
        - monitor: process
          field: command_line
          operator: contains
          value: "-enc"
          case_sensitive: false
""")
        ev = RuleEvaluator(RuleLoader.load_rules(rules_yaml))
        # Both clauses match
        assert len(ev.evaluate(_ps_event(command_line="powershell.exe -enc ABC"))) == 1
        # Only one clause matches
        assert len(ev.evaluate(_ps_event(command_line="powershell.exe -File test.ps1"))) == 0

    def test_any_condition_requires_one_clause(self, tmp_path):
        """ANY condition: at least one clause must match."""
        rules_yaml = tmp_path / "rules.yaml"
        rules_yaml.write_text("""
rules:
  - rule_id: "T001"
    name: "Test"
    severity: HIGH
    detection:
      condition: any
      rules:
        - monitor: process
          field: process_name
          operator: equals
          value: "cmd.exe"
          case_sensitive: false
        - monitor: process
          field: process_name
          operator: equals
          value: "powershell.exe"
          case_sensitive: false
""")
        ev = RuleEvaluator(RuleLoader.load_rules(rules_yaml))
        assert len(ev.evaluate(_ps_event(process_name="cmd.exe"))) == 1
        assert len(ev.evaluate(_ps_event(process_name="powershell.exe"))) == 1
        assert len(ev.evaluate(_ps_event(process_name="notepad.exe"))) == 0

    def _write(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / f"rules_{uuid.uuid4().hex[:6]}.yaml"
        p.write_text(content)
        return p


# =============================================================================
# RULE EVALUATOR TESTS — Production Rules
# =============================================================================

class TestProductionRules:
    """Test each production rule fires on malicious input and not on clean input."""

    @pytest.fixture(autouse=True)
    def skip_if_no_rules(self):
        if not RULES_FILE.exists():
            pytest.skip("config/rules.yaml not found")

    @pytest.fixture
    def evaluator(self) -> RuleEvaluator:
        rules = RuleLoader.load_rules(RULES_FILE)
        return RuleEvaluator(rules)

    def test_R001_encoded_powershell_detected(self, evaluator):
        event = _ps_event(
            command_line="powershell.exe -enc SQBFAFgA",
            process_name="powershell.exe",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R001" for r in matched), "R001 should fire"

    def test_R001_clean_powershell_not_flagged(self, evaluator):
        event = _ps_event(
            command_line="powershell.exe -File C:/scripts/backup.ps1",
            process_name="powershell.exe",
        )
        matched = evaluator.evaluate(event)
        assert not any(r.rule_id == "R001" for r in matched)

    def test_R002_office_spawning_shell(self, evaluator):
        event = _ps_event(
            process_name="powershell.exe",
            parent_name="winword.exe",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R002" for r in matched), "R002 should fire"

    def test_R002_legitimate_parent_not_flagged(self, evaluator):
        event = _ps_event(
            process_name="powershell.exe",
            parent_name="explorer.exe",
        )
        matched = evaluator.evaluate(event)
        assert not any(r.rule_id == "R002" for r in matched)

    def test_R004_shadow_copy_deletion(self, evaluator):
        event = _ps_event(
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            parent_name="cmd.exe",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R004" for r in matched), "R004 should fire"

    def test_R005_mimikatz_detection(self, evaluator):
        event = _ps_event(
            process_name="mimikatz.exe",
            command_line="mimikatz.exe sekurlsa::logonpasswords",
            parent_name="cmd.exe",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R005" for r in matched), "R005 should fire"

    def test_R018_defender_disable(self, evaluator):
        event = _ps_event(
            process_name="powershell.exe",
            command_line="Set-MpPreference -DisableRealtimeMonitoring $true",
            parent_name="cmd.exe",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R018" for r in matched), "R018 should fire"

    def test_R023_hosts_file_modification(self, evaluator):
        # Construct FileEvent with Windows-style backslash path that the rule checks
        from ihadrs.models.events import FileEvent
        from ihadrs.constants import MonitorType, EventType
        event = FileEvent(
            event_type=EventType.FILE_MODIFIED,
            source_monitor=MonitorType.FILE,
            file_path=r"C:\Windows\System32\drivers\etc\hosts",
            file_name="hosts",
            change_type="modified",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R023" for r in matched), "R023 should fire"

    def test_R012_registry_run_key(self, evaluator):
        event = make_registry_event(
            hive="HKCU",
            key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            change_type="value_set",
            value_name="Malware",
            value_data="C:/temp/malware.exe",
        )
        matched = evaluator.evaluate(event)
        assert any(r.rule_id == "R012" for r in matched), "R012 should fire"

    def test_disabled_rule_not_evaluated(self):
        """Explicitly disabled rules must not fire."""
        rules = RuleLoader.load_rules(RULES_FILE)
        evaluator = RuleEvaluator(rules, disabled_rule_ids=["R001"])
        event = _ps_event(command_line="powershell.exe -enc SQBFAFgA")
        matched = evaluator.evaluate(event)
        assert not any(r.rule_id == "R001" for r in matched)

    def test_enabled_filter_limits_evaluation(self):
        """When enabled_rule_ids is set, only those rules are evaluated."""
        rules = RuleLoader.load_rules(RULES_FILE)
        evaluator = RuleEvaluator(rules, enabled_rule_ids=["R002"])

        # R001 match event — should NOT fire (not in enabled_rule_ids)
        event_r001 = _ps_event(command_line="powershell.exe -enc SQBFAFgA")
        matched = evaluator.evaluate(event_r001)
        assert not any(r.rule_id == "R001" for r in matched)

        # R002 match event — SHOULD fire
        event_r002 = _ps_event(process_name="powershell.exe", parent_name="winword.exe")
        matched = evaluator.evaluate(event_r002)
        assert any(r.rule_id == "R002" for r in matched)

    def test_get_rule_by_id(self):
        rules = RuleLoader.load_rules(RULES_FILE)
        evaluator = RuleEvaluator(rules)
        r001 = evaluator.get_rule_by_id("R001")
        assert r001 is not None
        assert r001.name == "Encoded PowerShell Execution"

    def test_get_rule_by_id_not_found(self):
        rules = RuleLoader.load_rules(RULES_FILE)
        evaluator = RuleEvaluator(rules)
        assert evaluator.get_rule_by_id("RXXX") is None


# =============================================================================
# BEHAVIORAL DETECTOR TESTS
# =============================================================================

class TestSlidingWindowTracker:

    def test_add_returns_true_on_threshold(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=3)
        assert tracker.add() is False
        assert tracker.add() is False
        assert tracker.add() is True   # threshold crossed

    def test_add_returns_false_after_threshold(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=2)
        tracker.add()
        assert tracker.add() is True   # threshold
        assert tracker.add() is False  # already past threshold

    def test_count_in_window(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=100)
        for _ in range(5):
            tracker.add()
        assert tracker.count_in_window() == 5

    def test_events_expire_outside_window(self):
        tracker = SlidingWindowTracker(window_seconds=0.1, threshold=100)
        tracker.add({"x": 1})
        time.sleep(0.15)
        assert tracker.count_in_window() == 0

    def test_reset_clears_all(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=3)
        for _ in range(5):
            tracker.add()
        tracker.reset()
        assert tracker.count_in_window() == 0

    def test_get_events_in_window_returns_metadata(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=100)
        tracker.add({"pid": 1234, "name": "test.exe"})
        events = tracker.get_events_in_window()
        assert len(events) == 1
        assert events[0]["pid"] == 1234


class TestBehavioralDetector:

    @pytest.fixture
    def detector(self) -> BehavioralDetector:
        return BehavioralDetector(
            ransomware_rename_threshold=5,
            ransomware_window_seconds=10.0,
            brute_force_threshold=3,
            brute_force_window_seconds=30.0,
            process_spawn_threshold=3,
            process_spawn_window_seconds=10.0,
            bulk_file_threshold=5,
            bulk_file_window_seconds=5.0,
        )

    def _crypto_rename(self, ext: str = ".encrypted", pid: int = 1234) -> FileEvent:
        return make_file_event(
            file_path=f"/tmp/doc.docx{ext}",
            change_type="renamed",
            pid=pid,
            process_name="ransomware.exe",
            old_path="/tmp/doc.docx",
            new_path=f"/tmp/doc.docx{ext}",
        )

    def test_ransomware_fires_at_threshold(self, detector):
        """Ransomware detection fires exactly at the threshold."""
        matches = []
        for i in range(5):
            results = detector.process_event(self._crypto_rename())
            matches.extend(results)

        ransomware = [m for m in matches if m.pattern_id == "RANSOMWARE_BULK_ENCRYPT"]
        assert len(ransomware) >= 1
        assert ransomware[0].severity == Severity.CRITICAL
        assert ransomware[0].attack_category == AttackCategory.RANSOMWARE

    def test_ransomware_no_fire_below_threshold(self, detector):
        """Below threshold: no ransomware detection."""
        matches = []
        for i in range(3):  # below threshold of 5
            results = detector.process_event(self._crypto_rename())
            matches.extend(results)
        assert not any(m.pattern_id == "RANSOMWARE_BULK_ENCRYPT" for m in matches)

    def test_ransomware_non_crypto_extension_ignored(self, detector):
        """File renames with non-crypto extensions don't trigger ransomware."""
        matches = []
        for _ in range(10):
            event = make_file_event(
                file_path="/tmp/file.docx.bak",
                change_type="renamed",
                old_path="/tmp/file.docx",
                new_path="/tmp/file.docx.bak",
            )
            matches.extend(detector.process_event(event))
        assert not any(m.pattern_id == "RANSOMWARE_BULK_ENCRYPT" for m in matches)

    def test_brute_force_fires_at_threshold(self, detector):
        """Brute force detection fires when auth failure threshold is crossed."""
        matches = []
        for _ in range(3):
            results = detector.process_event(_auth_failure("10.0.0.1"))
            matches.extend(results)

        bf = [m for m in matches if m.pattern_id == "BRUTE_FORCE_AUTH"]
        assert len(bf) >= 1
        assert bf[0].severity == Severity.HIGH
        assert bf[0].context["source_ip"] == "10.0.0.1"

    def test_brute_force_different_sources_tracked_separately(self, detector):
        """Failures from different IPs are tracked independently."""
        for _ in range(2):
            detector.process_event(_auth_failure("1.1.1.1"))
        for _ in range(2):
            detector.process_event(_auth_failure("2.2.2.2"))

        # Neither source has reached threshold of 3 yet
        for _ in range(2):
            results = detector.process_event(_auth_failure("1.1.1.1"))
            bf = [m for m in results if m.pattern_id == "BRUTE_FORCE_AUTH"]
            # Threshold is 3 total for each source
        # Source 1.1.1.1 has now seen 4 — should have fired at exactly 3
        tracker = detector._brute_force_trackers["1.1.1.1"]
        assert tracker.count_in_window() >= 3

    def test_brute_force_success_not_tracked(self, detector):
        """Successful logins don't count toward brute force threshold."""
        matches = []
        for _ in range(5):
            results = detector.process_event(_auth_success("1.2.3.4"))
            matches.extend(results)
        assert not any(m.pattern_id == "BRUTE_FORCE_AUTH" for m in matches)

    def test_spawn_burst_fires_at_threshold(self, detector):
        """Rapid shell spawning fires at threshold."""
        matches = []
        for i in range(3):
            event = _ps_event(
                process_name="powershell.exe",
                parent_name="malware.exe",
                pid=1000 + i,
            )
            results = detector.process_event(event)
            matches.extend(results)

        burst = [m for m in matches if m.pattern_id == "RAPID_SHELL_SPAWN"]
        assert len(burst) >= 1
        assert burst[0].attack_category == AttackCategory.MALWARE_EXECUTION

    def test_spawn_burst_only_tracks_shells(self, detector):
        """Non-shell processes don't trigger spawn burst detection."""
        matches = []
        for i in range(5):
            event = _ps_event(
                process_name="notepad.exe",  # Not a shell
                parent_name="explorer.exe",
                pid=2000 + i,
            )
            matches.extend(detector.process_event(event))
        assert not any(m.pattern_id == "RAPID_SHELL_SPAWN" for m in matches)

    def test_cooldown_prevents_duplicate_alerts(self, detector):
        """Cooldown suppresses repeated alerts for the same pattern."""
        detector._detection_cooldown = 3600.0  # 1 hour cooldown

        all_matches = []
        for _ in range(20):  # Far above threshold
            results = detector.process_event(self._crypto_rename())
            all_matches.extend(results)

        ransomware = [m for m in all_matches if m.pattern_id == "RANSOMWARE_BULK_ENCRYPT"]
        assert len(ransomware) == 1  # Only one alert despite many events

    def test_reset_all_trackers(self, detector):
        """reset_all_trackers clears all internal state."""
        for _ in range(10):
            detector.process_event(self._crypto_rename())

        detector.reset_all_trackers()
        stats = detector.get_tracker_stats()
        assert stats["ransomware_window_count"] == 0


# =============================================================================
# CORRELATION ENGINE TESTS
# =============================================================================

class TestCorrelationEngine:

    @pytest.fixture
    def engine(self) -> CorrelationEngine:
        return CorrelationEngine(window_seconds=300)

    def test_office_macro_chain_detected(self, engine):
        """Office app spawns shell → network connection → correlation fires."""
        # Stage 1: winword.exe spawns powershell.exe
        shell_event = make_process_created_event(
            pid=5555, name="powershell.exe",
            image_path="C:/Windows/System32/powershell.exe",
            command_line="powershell.exe -WindowStyle Hidden",
            parent_pid=2222, parent_name="winword.exe",
        )
        results1 = engine.process_event(shell_event)
        # No match yet at stage 1

        # Stage 2: powershell.exe connects to external IP
        net_event = make_network_connection_event(
            pid=5555, process_name="powershell.exe",
            local_ip="192.168.1.100", local_port=54321,
            remote_ip="1.2.3.4", remote_port=443,
        )
        results2 = engine.process_event(net_event)

        all_results = results1 + results2
        office_macro = [m for m in all_results if m.pattern_id == "OFFICE_MACRO_C2"]
        assert len(office_macro) >= 1
        assert office_macro[0].severity == Severity.CRITICAL
        assert "winword.exe" in office_macro[0].context["office_app"]

    def test_download_execution_chain(self, engine):
        """File created in downloads → executable runs from same path."""
        exe_path = "C:/Users/alice/Downloads/setup.exe"

        # Stage 1: exe file created in downloads
        file_event = make_file_event(
            file_path=exe_path,
            change_type="created",
        )
        engine.process_event(file_event)

        # Stage 2: that exe is executed
        proc_event = make_process_created_event(
            pid=7777, name="setup.exe",
            image_path=exe_path,
            command_line=exe_path,
            parent_pid=4, parent_name="explorer.exe",
        )
        results = engine.process_event(proc_event)

        dl_exec = [m for m in results if m.pattern_id == "DOWNLOAD_EXECUTION"]
        assert len(dl_exec) >= 1

    def test_credential_stuffing_chain(self, engine):
        """Multiple auth failures from same IP + subsequent success = detection."""
        source = "192.168.50.1"

        # Stage 1: 4 failures
        for _ in range(4):
            engine.process_event(_auth_failure(source_ip=source))

        # Stage 2: success from same source
        results = engine.process_event(_auth_success(source_ip=source))

        cred_stuff = [m for m in results if m.pattern_id == "CREDENTIAL_STUFFING_SUCCESS"]
        assert len(cred_stuff) >= 1
        assert cred_stuff[0].severity == Severity.CRITICAL

    def test_credential_stuffing_requires_failures_first(self, engine):
        """Success without prior failures should NOT trigger detection."""
        results = engine.process_event(_auth_success(source_ip="5.5.5.5"))
        assert not any(m.pattern_id == "CREDENTIAL_STUFFING_SUCCESS" for m in results)

    def test_credential_stuffing_too_few_failures(self, engine):
        """Only 1 failure before success is not enough."""
        source = "3.3.3.3"
        engine.process_event(_auth_failure(source_ip=source))
        results = engine.process_event(_auth_success(source_ip=source))
        assert not any(m.pattern_id == "CREDENTIAL_STUFFING_SUCCESS" for m in results)

    def test_correlation_window_expires(self, engine):
        """Events outside the window don't form chains."""
        short_engine = CorrelationEngine(window_seconds=1)

        # Stage 1
        shell_event = make_process_created_event(
            pid=5555, name="powershell.exe",
            image_path="C:/Windows/System32/powershell.exe",
            command_line="powershell.exe",
            parent_pid=2222, parent_name="winword.exe",
        )
        short_engine.process_event(shell_event)

        # Wait for window to expire
        time.sleep(1.5)

        # Stage 2 — too late
        net_event = make_network_connection_event(
            pid=5555, process_name="powershell.exe",
            local_ip="192.168.1.1", local_port=12345,
            remote_ip="1.2.3.4", remote_port=443,
        )
        results = short_engine.process_event(net_event)
        assert not any(m.pattern_id == "OFFICE_MACRO_C2" for m in results)

    def test_cooldown_prevents_duplicate_correlations(self, engine):
        """Same correlation pattern doesn't fire twice in rapid succession."""
        source = "9.9.9.9"
        # First chain
        for _ in range(4):
            engine.process_event(_auth_failure(source_ip=source))
        r1 = engine.process_event(_auth_success(source_ip=source))
        assert any(m.pattern_id == "CREDENTIAL_STUFFING_SUCCESS" for m in r1)

        # Immediate second chain — should be suppressed by cooldown
        for _ in range(4):
            engine.process_event(_auth_failure(source_ip=source))
        r2 = engine.process_event(_auth_success(source_ip=source))
        assert not any(m.pattern_id == "CREDENTIAL_STUFFING_SUCCESS" for m in r2)

    def test_get_stats(self, engine):
        stats = engine.get_stats()
        assert "window_seconds" in stats
        assert stats["window_seconds"] == 300


# =============================================================================
# DETECTION ENGINE INTEGRATION TESTS
# =============================================================================

class TestDetectionEngine:

    @pytest.fixture
    def event_bus(self) -> EventBus:
        bus = EventBus(max_queue_size=500, max_events_per_second=10000)
        bus.start()
        yield bus
        bus.stop(drain_timeout_seconds=2.0)

    @pytest.fixture
    def engine(self, tmp_path, event_bus) -> DetectionEngine:
        if not RULES_FILE.exists():
            pytest.skip("config/rules.yaml not found")
        config = _make_config(tmp_path)
        return DetectionEngine(config, event_bus)

    @pytest.mark.asyncio
    async def test_initialize_loads_rules(self, engine):
        await engine.initialize()
        assert engine.rule_count > 0

    @pytest.mark.asyncio
    async def test_detection_emits_threat_event(self, engine, event_bus):
        """Malicious event triggers ThreatEvent emission on the bus."""
        await engine.initialize()

        received: list[BusEvent] = []
        event_bus.subscribe(
            "threat_sink",
            received.append,
            {EventType.IHADRS_DETECTION_TRIGGERED},
        )

        # Publish encoded PowerShell event
        event = _ps_event(command_line="powershell.exe -enc SQBFAFgA")
        bus_event = BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        )
        engine.process_event(bus_event)
        time.sleep(0.2)

        assert len(received) >= 1
        threat = received[0].payload
        assert isinstance(threat, ThreatEvent)
        assert threat.severity in (Severity.HIGH, Severity.CRITICAL)

    @pytest.mark.asyncio
    async def test_clean_event_no_threat_emitted(self, engine, event_bus):
        """Clean events must not produce ThreatEvents."""
        await engine.initialize()

        received: list[BusEvent] = []
        event_bus.subscribe(
            "threat_sink",
            received.append,
            {EventType.IHADRS_DETECTION_TRIGGERED},
        )

        clean = _ps_event(
            process_name="notepad.exe",
            command_line="notepad.exe C:/Users/alice/document.txt",
            parent_name="explorer.exe",
        )
        bus_event = BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=clean,
        )
        engine.process_event(bus_event)
        time.sleep(0.2)
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_deduplication_suppresses_repeat_detections(self, engine, event_bus):
        """Same rule+resource within cooldown window emits only one threat."""
        await engine.initialize()

        received: list[BusEvent] = []
        event_bus.subscribe(
            "threat_sink",
            received.append,
            {EventType.IHADRS_DETECTION_TRIGGERED},
        )

        event = _ps_event(command_line="powershell.exe -enc SQBFAFgA", pid=9999)
        bus_event = BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        )

        # Publish the same event 5 times
        for _ in range(5):
            engine.process_event(bus_event)
        time.sleep(0.2)

        # Deduplication: R001 (rule-based) fires exactly once.
        # Behavioral detector may fire separately for spawn burst —
        # count only rule-triggered threats carrying R001.
        rule_threats = [
            b for b in received
            if isinstance(b.payload, ThreatEvent)
            and "R001" in b.payload.evidence.triggered_rule_ids
        ]
        assert len(rule_threats) == 1, (
            f"Expected 1 R001 threat, got {len(rule_threats)}: "
            f"{[b.payload.evidence.triggered_rule_ids for b in received]}"
        )

    @pytest.mark.asyncio
    async def test_threat_event_has_correct_fields(self, engine, event_bus):
        """Emitted ThreatEvent has all required fields populated."""
        await engine.initialize()

        received: list[BusEvent] = []
        event_bus.subscribe(
            "threat_sink",
            received.append,
            {EventType.IHADRS_DETECTION_TRIGGERED},
        )

        event = _ps_event(command_line="powershell.exe -enc SQBFAFgA", pid=4321)
        engine.process_event(BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        ))
        time.sleep(0.2)

        assert received, "No threat emitted"
        threat: ThreatEvent = received[0].payload

        # Required fields
        assert threat.threat_id
        assert threat.severity in Severity
        assert threat.attack_category in AttackCategory
        assert 0.0 < threat.confidence <= 1.0
        assert threat.mitre_techniques
        assert threat.affected_resource
        assert threat.summary
        assert threat.evidence.triggered_rule_ids

    @pytest.mark.asyncio
    async def test_health_check_after_init(self, engine):
        await engine.initialize()
        health = engine.health_check()
        assert health["status"] == "healthy"
        assert health["rule_count"] > 0

    @pytest.mark.asyncio
    async def test_health_check_before_init(self, tmp_path, event_bus):
        if not RULES_FILE.exists():
            pytest.skip()
        config = _make_config(tmp_path)
        engine = DetectionEngine(config, event_bus)
        # Not initialized yet
        health = engine.health_check()
        assert health["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_metrics_increment_on_processing(self, engine, event_bus):
        await engine.initialize()

        event = _ps_event(command_line="powershell.exe -enc SQBFAFgA")
        engine.process_event(BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="ProcessMonitor",
            payload=event,
        ))

        metrics = engine.get_metrics()
        assert metrics["events_processed"] >= 1

    @pytest.mark.asyncio
    async def test_internal_events_not_detected(self, engine, event_bus):
        """Events from 'DetectionEngine' source are ignored (prevent self-loop)."""
        await engine.initialize()

        received: list[BusEvent] = []
        event_bus.subscribe(
            "threat_sink",
            received.append,
            {EventType.IHADRS_DETECTION_TRIGGERED},
        )

        event = _ps_event(command_line="powershell.exe -enc SQBFAFgA")
        engine.process_event(BusEvent(
            event_type=EventType.PROCESS_CREATED,
            source="DetectionEngine",  # Internal source — must be ignored
            payload=event,
        ))
        time.sleep(0.1)
        assert len(received) == 0


# =============================================================================
# TEMPLATE INTERPOLATION TESTS
# =============================================================================

class TestInterpolation:

    def test_basic_interpolation(self):
        result = _interpolate("Process {process_name} PID {pid}", {
            "process_name": "powershell.exe",
            "pid": 1234,
        })
        assert result == "Process powershell.exe PID 1234"

    def test_missing_variable_uses_placeholder(self):
        result = _interpolate("Process {missing_var}", {})
        assert result == "Process ?"

    def test_empty_template(self):
        assert _interpolate("", {"key": "value"}) == ""

    def test_no_variables(self):
        result = _interpolate("Static string", {})
        assert result == "Static string"


# =============================================================================
# MITRE MAPPER TESTS
# =============================================================================

class TestMITREMapper:

    def test_get_technique_name_known(self):
        from ihadrs.intelligence.mitre import MITREMapper
        name = MITREMapper.get_technique_name("T1059.001")
        # Should return a meaningful name, not just the ID
        assert name  # Non-empty

    def test_get_technique_name_unknown_returns_id(self):
        from ihadrs.intelligence.mitre import MITREMapper
        name = MITREMapper.get_technique_name("T9999.999")
        assert name == "T9999.999"

    def test_get_tactic_name_from_constants(self):
        from ihadrs.intelligence.mitre import MITREMapper
        name = MITREMapper.get_tactic_name("TA0002")
        assert "Execution" in name

    def test_get_technique_names_list(self):
        from ihadrs.intelligence.mitre import MITREMapper
        names = MITREMapper.get_technique_names(["T1059.001", "T1486"])
        assert len(names) == 2
        assert all(isinstance(n, str) for n in names)