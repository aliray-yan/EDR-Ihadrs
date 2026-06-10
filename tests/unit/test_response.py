"""
Unit tests for Phase 5 — Response System and Alerting.

Tests cover:
    RemediationRecommender: playbook loading, step generation, interpolation
    AutoResponder:          action dispatch, dry-run, rollback, mode filtering
    Notifier:               rate limiting, severity filtering, cooldown, dispatch
    ActionResult:           serialization, to_record conversion
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ihadrs.alerting.notifier import Notifier
from ihadrs.constants import AttackCategory, ActionType, ResponseMode, ResponseStatus, Severity
from ihadrs.core.event_bus import BusEvent, EventType
from ihadrs.models.threats import AutomatedActionRecord, ThreatEvent, ThreatEvidence, ProcessContext
from ihadrs.response.auto_responder import ActionResult, AutoResponder
from ihadrs.response.recommender import RemediationRecommender


# =============================================================================
# HELPERS
# =============================================================================

def _make_config(tmp_path: Path, mode: str = "semi_auto") -> Any:
    from ihadrs.core.config import IHADRSConfig
    return IHADRSConfig.model_validate({
        "app": {"require_admin": False},
        "logging": {"console_output": False, "level": "WARNING"},
        "response": {
            "mode": mode,
            "confirmation_timeout_seconds": 3,
            "auto_respond_severities": ["CRITICAL"],
            "playbooks_file": "config/playbooks.yaml",
            "max_concurrent_responses": 3,
            "rollback_on_false_positive": True,
        },
        "alerting": {
            "desktop_notifications": False,
            "console_output": False,
            "min_severity_console": "LOW",
            "min_severity_desktop": "MEDIUM",
            "max_alerts_per_minute": 10,
            "alert_cooldown_seconds": 0,
        },
        "detection": {"rules_file": "config/rules.yaml"},
        "monitors": {"file_watch_paths": [str(tmp_path)], "ip_whitelist": []},
        "api": {"enabled": False, "token": "test"},
    })


def _make_threat(
    severity: Severity = Severity.CRITICAL,
    category: AttackCategory = AttackCategory.RANSOMWARE,
    pid: int = 9999,
) -> ThreatEvent:
    threat = ThreatEvent(
        source_monitor="process_monitor",
        severity=severity,
        confidence=0.92,
        attack_category=category,
        mitre_techniques=["T1486"],
        mitre_tactics=["TA0040"],
        mitre_technique_names=["Data Encrypted for Impact"],
        mitre_tactic_names=["Impact"],
        affected_resource=f"process:ransomware.exe:{pid}",
        summary="Ransomware detected: mass file encryption",
        user_explanation="Files are being encrypted by ransomware.",
        evidence=ThreatEvidence(triggered_rule_ids=["R003"]),
        process_context=ProcessContext(
            pid=pid,
            name="ransomware.exe",
            image_path="C:/temp/ransomware.exe",
            command_line="ransomware.exe --encrypt",
            parent_pid=1234,
            parent_name="cmd.exe",
        ),
    )
    return threat


# =============================================================================
# REMEDIATION RECOMMENDER TESTS
# =============================================================================

class TestRemediationRecommender:

    @pytest.fixture
    def recommender(self) -> RemediationRecommender:
        return RemediationRecommender()

    def test_generate_returns_steps(self, recommender):
        threat = _make_threat(category=AttackCategory.RANSOMWARE)
        steps = recommender.generate(threat)
        assert isinstance(steps, list)
        assert len(steps) > 0

    def test_steps_are_ordered_by_category(self, recommender):
        """immediate steps come before investigation, which come before remediation."""
        threat = _make_threat(category=AttackCategory.RANSOMWARE)
        steps = recommender.generate(threat)
        categories = [s.category for s in steps]
        # No "remediation" or "prevention" step should appear before "immediate"
        seen_non_immediate = False
        for cat in categories:
            if cat != "immediate":
                seen_non_immediate = True
            if seen_non_immediate and cat == "immediate":
                pytest.fail("Immediate step appeared after non-immediate step")

    def test_steps_have_ascending_numbers(self, recommender):
        threat = _make_threat()
        steps = recommender.generate(threat)
        for i, step in enumerate(steps):
            assert step.step_number == i + 1

    def test_step_description_not_empty(self, recommender):
        threat = _make_threat()
        steps = recommender.generate(threat)
        for step in steps:
            assert step.description, f"Step {step.step_number} has empty description"

    def test_template_interpolation_works(self, recommender):
        """Template variables {process_name}, {pid} etc. are substituted."""
        threat = _make_threat(pid=4444)
        steps = recommender.generate(threat)
        descriptions = " ".join(s.description for s in steps)
        # Should NOT contain raw template placeholders
        assert "{pid}" not in descriptions
        assert "{process_name}" not in descriptions

    def test_generate_for_all_categories_no_error(self, recommender):
        """generate() must not raise for any attack category."""
        for category in AttackCategory:
            threat = _make_threat(category=category)
            steps = recommender.generate(threat)
            assert isinstance(steps, list)

    def test_fallback_steps_when_no_playbook(self):
        """If no playbook file, default steps are returned."""
        rec = RemediationRecommender(playbooks_file=Path("/nonexistent/playbooks.yaml"))
        threat = _make_threat(category=AttackCategory.RECONNAISSANCE)
        steps = rec.generate(threat)
        assert len(steps) > 0

    def test_interpolate_missing_variable(self, recommender):
        result = recommender._interpolate("Hello {missing_var}", {})
        assert result == "Hello ?"

    def test_interpolate_present_variable(self, recommender):
        result = recommender._interpolate("PID is {pid}", {"pid": 1234})
        assert result == "PID is 1234"


# =============================================================================
# ACTION RESULT TESTS
# =============================================================================

class TestActionResult:

    def test_to_record_converts_correctly(self):
        result = ActionResult(
            action_type=ActionType.KILL_PROCESS.value,
            target="malware.exe:4444",
            success=True,
            result_message="Process terminated",
            rollback_data={"pid": 4444},
        )
        record = result.to_record()
        assert isinstance(record, AutomatedActionRecord)
        assert record.action_type == ActionType.KILL_PROCESS.value
        assert record.success is True
        assert record.rollback_available is True

    def test_failed_result_to_record(self):
        result = ActionResult(
            action_type=ActionType.BLOCK_IP.value,
            target="1.2.3.4",
            success=False,
            error_message="Access denied",
        )
        record = result.to_record()
        assert record.success is False
        assert record.rollback_available is False

    def test_default_action_id_is_unique(self):
        r1 = ActionResult()
        r2 = ActionResult()
        assert r1.action_id != r2.action_id


# =============================================================================
# AUTO RESPONDER TESTS
# =============================================================================

class TestAutoResponder:

    @pytest.fixture
    def responder_manual(self, tmp_path) -> AutoResponder:
        return AutoResponder(_make_config(tmp_path, mode="manual"))

    @pytest.fixture
    def responder_auto(self, tmp_path) -> AutoResponder:
        return AutoResponder(_make_config(tmp_path, mode="full_auto"))

    @pytest.fixture
    def responder_semi(self, tmp_path) -> AutoResponder:
        config = _make_config(tmp_path, mode="semi_auto")
        return AutoResponder(config)

    @pytest.mark.asyncio
    async def test_manual_mode_returns_no_actions(self, responder_manual):
        """MANUAL mode: no automated actions executed."""
        threat = _make_threat(severity=Severity.CRITICAL)
        results = await responder_manual.respond(threat)
        assert results == []

    @pytest.mark.asyncio
    async def test_severity_below_threshold_no_response(self, responder_auto):
        """Threat below auto-respond severity threshold: no actions."""
        threat = _make_threat(severity=Severity.MEDIUM)  # Only CRITICAL auto-responds
        results = await responder_auto.respond(threat)
        assert results == []

    @pytest.mark.asyncio
    async def test_dry_run_returns_success_without_executing(self, tmp_path):
        """Dry run mode: actions logged but not actually executed."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)
        responder._dry_run = True

        threat = _make_threat(severity=Severity.CRITICAL)
        results = await responder.respond(threat)

        assert all(r.result_message.startswith("[DRY RUN]") for r in results if r.success)
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_respond_updates_threat_status(self, tmp_path):
        """ThreatEvent.response_status is updated after response."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)
        responder._dry_run = True

        threat = _make_threat(severity=Severity.CRITICAL)
        assert threat.response_status == ResponseStatus.NONE

        await responder.respond(threat)
        assert threat.response_status in (
            ResponseStatus.EXECUTED,
            ResponseStatus.FAILED,
            ResponseStatus.CANCELLED,
        )

    @pytest.mark.asyncio
    async def test_respond_appends_action_records(self, tmp_path):
        """Executed actions are appended to ThreatEvent.automated_actions."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)
        responder._dry_run = True

        threat = _make_threat(severity=Severity.CRITICAL)
        assert len(threat.automated_actions) == 0

        await responder.respond(threat)
        assert len(threat.automated_actions) > 0

    @pytest.mark.asyncio
    async def test_kill_process_nonexistent_pid_succeeds(self, tmp_path):
        """Killing a non-existent PID is treated as success (already gone)."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)

        result = await responder._kill_process("99999999", {})
        # Should succeed (process doesn't exist = already gone)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_suspend_process_nonexistent_pid_succeeds(self, tmp_path):
        """Suspending a non-existent PID is treated as success."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)

        result = await responder._suspend_process("99999999", {})
        assert result.success is True

    @pytest.mark.asyncio
    async def test_quarantine_file_nonexistent_succeeds(self, tmp_path):
        """Quarantining a non-existent file is treated as success."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)

        result = await responder._quarantine_file(
            "/nonexistent/path/file.exe", {}
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_quarantine_and_restore_file(self, tmp_path):
        """File can be quarantined and then restored via rollback."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)

        # Create a real temp file
        test_file = tmp_path / "test_malware.exe"
        test_file.write_text("fake malware content")

        # Quarantine it
        result = await responder._quarantine_file(str(test_file), {})
        assert result.success is True
        assert not test_file.exists(), "File should be moved to quarantine"
        assert result.rollback_data

        # Restore via rollback
        record = result.to_record()
        restored = await responder.rollback_action(record)
        assert restored is True
        assert test_file.exists(), "File should be restored"

    @pytest.mark.asyncio
    async def test_collect_forensics_creates_file(self, tmp_path):
        """Forensics collection creates a JSON snapshot file."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)
        threat = _make_threat()

        result = await responder._collect_forensics("1234", {}, threat)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_semi_auto_timeout_auto_approves(self, tmp_path):
        """Semi-auto mode auto-approves after timeout (1 second in test config)."""
        config = _make_config(tmp_path, mode="semi_auto")
        responder = AutoResponder(config)
        responder._confirmation_timeout = 0.1
        responder._dry_run = True

        threat = _make_threat(severity=Severity.CRITICAL)
        results = await responder.respond(threat)

        # Should have executed after 0.1s timeout
        assert threat.response_status != ResponseStatus.CANCELLED

    def test_extract_pid_from_string(self, tmp_path):
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)
        assert responder._extract_pid("1234") == 1234
        assert responder._extract_pid("abc") is None
        assert responder._extract_pid("") is None
        assert responder._extract_pid(None) is None

    @pytest.mark.asyncio
    async def test_rollback_no_data_returns_false(self, tmp_path: Path):
        """Rollback without rollback_data returns False."""
        config = _make_config(tmp_path, mode="full_auto")
        responder = AutoResponder(config)
        record = AutomatedActionRecord(
            action_type="kill_process",
            target="test:1234",
            rollback_data={},  # No rollback data
        )
        result = await responder.rollback_action(record)
        assert result is False


# =============================================================================
# NOTIFIER TESTS
# =============================================================================

class TestNotifier:

    @pytest.fixture
    def notifier(self, tmp_path) -> Notifier:
        config = _make_config(tmp_path)
        return Notifier(config)

    def _make_bus_event(self, threat: ThreatEvent) -> BusEvent:
        return BusEvent(
            event_type=EventType.IHADRS_DETECTION_TRIGGERED,
            source="DetectionEngine",
            payload=threat,
        )

    def test_handle_non_threat_payload_is_no_op(self, notifier):
        """Non-ThreatEvent payloads are silently ignored."""
        bus_event = BusEvent(
            event_type=EventType.IHADRS_DETECTION_TRIGGERED,
            source="test",
            payload={"not": "a threat"},
        )
        # Should not raise
        notifier.handle_event(bus_event)

    def test_rate_limit_passes_initially(self, notifier):
        """Fresh notifier is under rate limit."""
        assert notifier._passes_rate_limit() is True

    def test_rate_limit_blocks_after_max_alerts(self, notifier):
        """Rate limit blocks after max_alerts_per_minute."""
        notifier._max_per_minute = 3
        now = time.time()
        for _ in range(3):
            notifier._alert_times.append(now)
        assert notifier._passes_rate_limit() is False

    def test_rate_limit_resets_after_minute(self, notifier):
        """Old alerts expire from the rate limit window."""
        notifier._max_per_minute = 3
        old_time = time.time() - 65  # > 60 seconds ago
        for _ in range(5):
            notifier._alert_times.append(old_time)
        assert notifier._passes_rate_limit() is True

    def test_cooldown_suppresses_duplicate(self, notifier):
        """Same severity+category is suppressed within cooldown window."""
        notifier._cooldown_seconds = 60.0
        threat = _make_threat()

        # First alert — record it
        notifier._record_alert(threat)

        # Second alert of same type — should be on cooldown
        assert notifier._is_on_cooldown(threat) is True

    def test_no_cooldown_when_zero(self, notifier):
        """cooldown_seconds=0 means no suppression."""
        notifier._cooldown_seconds = 0
        threat = _make_threat()
        notifier._record_alert(threat)
        assert notifier._is_on_cooldown(threat) is False

    def test_different_categories_not_on_cooldown(self, notifier):
        """Different attack categories use different cooldown keys."""
        notifier._cooldown_seconds = 60.0
        threat1 = _make_threat(category=AttackCategory.RANSOMWARE)
        threat2 = _make_threat(category=AttackCategory.BRUTE_FORCE)
        notifier._record_alert(threat1)
        assert not notifier._is_on_cooldown(threat2)

    def test_dispatch_calls_console_when_enabled(self, notifier):
        """Console channel is called when console_output=True."""
        notifier._config.console_output = True
        notifier._config.min_severity_console = "LOW"

        with patch.object(notifier._console_channel, "send") as mock_send:
            threat = _make_threat(severity=Severity.HIGH)
            notifier._dispatch(threat)
            mock_send.assert_called_once_with(threat)

    def test_dispatch_skips_console_when_disabled(self, notifier):
        """Console channel not called when console_output=False."""
        notifier._config.console_output = False

        with patch.object(notifier._console_channel, "send") as mock_send:
            threat = _make_threat(severity=Severity.CRITICAL)
            notifier._dispatch(threat)
            mock_send.assert_not_called()

    def test_dispatch_skips_low_severity_for_desktop(self, notifier):
        """LOW severity threat doesn't trigger desktop if min is MEDIUM."""
        notifier._config.desktop_notifications = True
        notifier._config.min_severity_desktop = "MEDIUM"

        with patch.object(notifier._desktop_channel, "send") as mock_send:
            threat = _make_threat(severity=Severity.LOW)
            notifier._dispatch(threat)
            mock_send.assert_not_called()

    def test_handle_event_full_flow(self, notifier):
        """handle_event triggers dispatch for valid ThreatEvent."""
        notifier._config.console_output = True
        notifier._config.min_severity_console = "LOW"

        threat = _make_threat(severity=Severity.CRITICAL)
        bus_event = self._make_bus_event(threat)

        with patch.object(notifier._console_channel, "send") as mock_send:
            notifier.handle_event(bus_event)
            mock_send.assert_called_once_with(threat)

    def test_handle_event_respects_rate_limit(self, notifier):
        """Rate-limited alerts are not dispatched."""
        notifier._max_per_minute = 0  # Block all
        notifier._config.console_output = True

        threat = _make_threat()
        bus_event = self._make_bus_event(threat)

        with patch.object(notifier._console_channel, "send") as mock_send:
            notifier.handle_event(bus_event)
            mock_send.assert_not_called()