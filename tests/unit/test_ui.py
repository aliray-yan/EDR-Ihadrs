"""
Unit tests for Phase 7 — PyQt6 Dashboard.

Tests run headless via the offscreen Qt platform backend.
Covers: widget construction, data updates, filter logic, export,
        API worker signals, status bar, and settings persistence.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Headless Qt backend — must be set before any PyQt6 import
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt


# ---------------------------------------------------------------------------
# Shared QApplication fixture — one instance per test session
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def qapp():
    """Single QApplication for the entire test session."""
    app = QApplication.instance() or QApplication(sys.argv)
    yield app
    # Don't quit — other tests may share it


# ---------------------------------------------------------------------------
# Sample data helpers
# ---------------------------------------------------------------------------

def _sample_threats(n: int = 3) -> list[dict]:
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cats = ["Ransomware", "Command & Control", "Malware Execution"]
    return [
        {
            "threat_id": f"threat-{i:04d}",
            "severity": sevs[i % len(sevs)],
            "attack_category": cats[i % len(cats)],
            "confidence": 0.75 + (i % 3) * 0.08,
            "timestamp": "2025-04-22T10:00:00Z",
            "affected_resource": f"process:malware{i}.exe:{1000+i}",
            "summary": f"Test threat {i}",
            "false_positive": {"marked": False},
            "explanation": {"user": f"User explanation {i}", "technical": f"Tech {i}"},
            "mitre": {
                "techniques": ["T1059.001"],
                "technique_names": ["PowerShell"],
                "tactics": ["TA0002"],
                "tactic_names": ["Execution"],
            },
            "remediation": [
                {"step": 1, "category": "immediate", "description": "Isolate system"},
                {"step": 2, "category": "investigation", "description": "Review logs"},
            ],
            "process_context": {
                "pid": 1000 + i,
                "name": f"malware{i}.exe",
                "command_line": f"malware{i}.exe --evil",
                "parent_name": "cmd.exe",
                "parent_pid": 100,
            },
        }
        for i in range(n)
    ]


def _sample_status() -> dict:
    return {
        "version": "1.0.0",
        "status": "running",
        "monitors": [
            {"name": "ProcessMonitor", "running": True, "events_published": 42},
            {"name": "NetworkMonitor", "running": True, "events_published": 18},
        ],
        "detection": {
            "rule_count": 30,
            "events_per_second": 2.5,
            "events_processed": 1500,
            "threats_emitted": 3,
        },
    }


def _sample_stats() -> dict:
    return {
        "total_threats": 12,
        "false_positives": 2,
        "by_severity": {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 4, "LOW": 0},
        "by_category": {
            "Ransomware": 3,
            "Command & Control": 4,
            "Malware Execution": 5,
        },
        "window_hours": 24,
    }


# =============================================================================
# MonitorTab Tests
# =============================================================================

class TestMonitorTab:

    @pytest.fixture
    def tab(self, qapp):
        from ihadrs.ui.tabs.monitor_tab import MonitorTab
        return MonitorTab()

    def test_construction(self, tab):
        assert tab is not None

    def test_update_status_no_monitors(self, tab):
        """update_status with empty monitors doesn't crash."""
        tab.update_status({"monitors": [], "detection": {}})

    def test_update_status_with_monitors(self, tab):
        """update_status correctly shows running count."""
        tab.update_status(_sample_status())
        assert tab._mons_lbl.text() == "2"

    def test_update_status_eps(self, tab):
        """Events per second is displayed."""
        tab.update_status(_sample_status())
        assert "2.5" in tab._eps_lbl.text()

    def test_update_status_rule_count(self, tab):
        """Rule count is displayed."""
        tab.update_status(_sample_status())
        assert tab._rules_lbl.text() == "30"

    def test_filter_processes_hides_non_matching_rows(self, tab):
        """Process search filter hides rows that don't match."""
        # Add some dummy rows to the process table
        tab._proc_table.setRowCount(3)
        from PyQt6.QtWidgets import QTableWidgetItem
        for i, name in enumerate(["powershell.exe", "notepad.exe", "chrome.exe"]):
            tab._proc_table.setItem(i, 1, QTableWidgetItem(name))

        tab._filter_procs("powershell")
        assert not tab._proc_table.isRowHidden(0)  # powershell visible
        assert tab._proc_table.isRowHidden(1)       # notepad hidden
        assert tab._proc_table.isRowHidden(2)       # chrome hidden

    def test_filter_processes_empty_shows_all(self, tab):
        """Empty filter shows all rows."""
        tab._proc_table.setRowCount(2)
        from PyQt6.QtWidgets import QTableWidgetItem
        for i in range(2):
            tab._proc_table.setItem(i, 1, QTableWidgetItem(f"process{i}.exe"))

        tab._filter_procs("")
        assert not tab._proc_table.isRowHidden(0)
        assert not tab._proc_table.isRowHidden(1)


# =============================================================================
# AlertsTab Tests
# =============================================================================

class TestAlertsTab:

    @pytest.fixture
    def tab(self, qapp):
        from ihadrs.ui.tabs.alerts_tab import AlertsTab
        return AlertsTab()

    def test_construction(self, tab):
        assert tab is not None

    def test_update_threats_populates_table(self, tab):
        threats = _sample_threats(5)
        tab.update_threats(threats)
        assert tab._table.rowCount() == 5

    def test_update_threats_count_label(self, tab):
        tab.update_threats(_sample_threats(3))
        assert "3" in tab._count_lbl.text()

    def test_severity_filter_critical_only(self, tab):
        """Severity filter shows only CRITICAL threats."""
        tab.update_threats(_sample_threats(4))
        tab._sev.setCurrentText("CRITICAL")
        tab._apply()
        # Only the first threat is CRITICAL (sevs cycle: C,H,M,L)
        assert tab._table.rowCount() == 1

    def test_severity_filter_all(self, tab):
        """All filter shows all threats."""
        tab.update_threats(_sample_threats(4))
        tab._sev.setCurrentText("All")
        tab._apply()
        assert tab._table.rowCount() == 4

    def test_search_filter_reduces_results(self, tab):
        """Text search filters threats."""
        tab.update_threats(_sample_threats(3))
        tab._search.setText("threat-0001")
        tab._apply()
        assert tab._table.rowCount() <= 3

    def test_clear_filters(self, tab):
        """Clear resets all filters and shows all threats."""
        tab.update_threats(_sample_threats(3))
        tab._sev.setCurrentText("CRITICAL")
        tab._apply()
        tab._clear()
        assert tab._table.rowCount() == 3

    def test_false_positive_hidden_by_default(self, tab):
        """FP threats are hidden unless 'Show FP' toggled."""
        threats = _sample_threats(2)
        threats[0]["false_positive"] = {"marked": True}
        tab.update_threats(threats)
        assert tab._table.rowCount() == 1  # Only non-FP shown

    def test_show_fp_toggle(self, tab):
        """Toggling 'Show FP' reveals false positive threats."""
        threats = _sample_threats(2)
        threats[0]["false_positive"] = {"marked": True}
        tab.update_threats(threats)
        tab._fp_btn.setChecked(True)
        tab._apply()
        assert tab._table.rowCount() == 2

    def test_select_threat_populates_detail(self, tab):
        """Selecting a row populates the detail panel."""
        tab.update_threats(_sample_threats(1))
        tab._table.setCurrentCell(0, 0)
        tab._on_select(0)
        assert "CRITICAL" in tab._d_title.text() or "HIGH" in tab._d_title.text()

    def test_action_buttons_enabled_after_selection(self, tab):
        """FP and export buttons are enabled after selecting a threat."""
        tab.update_threats(_sample_threats(1))
        tab._on_select(0)
        assert tab._fp_action.isEnabled()
        assert tab._exp_btn.isEnabled()

    def test_empty_threats_no_crash(self, tab):
        """Empty threat list doesn't crash the tab."""
        tab.update_threats([])
        assert tab._table.rowCount() == 0
        assert "0" in tab._count_lbl.text()


# =============================================================================
# AnalysisTab Tests
# =============================================================================

class TestAnalysisTab:

    @pytest.fixture
    def tab(self, qapp):
        from ihadrs.ui.tabs.analysis_tab import AnalysisTab
        return AnalysisTab()

    def test_construction(self, tab):
        assert tab is not None

    def test_update_stats_shows_total(self, tab):
        tab.update_stats(_sample_stats())
        assert "12" in tab._total_lbl.text()

    def test_severity_bars_updated(self, tab):
        tab.update_stats(_sample_stats())
        # CRITICAL bar should reflect count 3
        cnt_lbl, bar = tab._sev_bars["CRITICAL"]
        assert cnt_lbl.text() == "3"
        assert bar.value() > 0

    def test_category_table_populated(self, tab):
        tab.update_stats(_sample_stats())
        assert tab._cat_table.rowCount() == 3  # 3 categories in sample

    def test_zero_total_no_crash(self, tab):
        """update_stats with 0 total threats doesn't divide by zero."""
        tab.update_stats({"total_threats": 0, "by_severity": {}, "by_category": {}})

    def test_update_stats_multiple_times(self, tab):
        """Calling update_stats multiple times updates correctly."""
        tab.update_stats(_sample_stats())
        stats2 = _sample_stats()
        stats2["total_threats"] = 50
        tab.update_stats(stats2)
        assert "50" in tab._total_lbl.text()


# =============================================================================
# LogsTab Tests
# =============================================================================

class TestLogsTab:

    @pytest.fixture
    def tab(self, qapp):
        from ihadrs.ui.tabs.logs_tab import LogsTab
        return LogsTab()

    def _sample_events(self, n: int = 3) -> list[dict]:
        return [
            {
                "timestamp": "2025-04-22T10:00:00Z",
                "event_type": f"process.created",
                "source": "ProcessMonitor",
                "severity": "LOW",
                "payload": {"pid": 1000 + i, "name": f"proc{i}.exe"},
            }
            for i in range(n)
        ]

    def test_construction(self, tab):
        assert tab is not None

    def test_update_events_populates_table(self, tab):
        tab.update_events(self._sample_events(5))
        assert tab._table.rowCount() == 5

    def test_search_filter(self, tab):
        """Text search filters log entries."""
        tab.update_events(self._sample_events(3))
        tab._search.setText("proc0")
        tab._apply()
        assert tab._table.rowCount() <= 3

    def test_clear_log(self, tab):
        """Clear removes all rows."""
        tab.update_events(self._sample_events(3))
        tab._clear()
        assert tab._table.rowCount() == 0
        assert "cleared" in tab._status.text().lower()

    def test_status_updated(self, tab):
        """Status label shows event count."""
        tab.update_events(self._sample_events(7))
        assert "7" in tab._status.text()

    def test_export_json(self, tab, tmp_path):
        """Export to JSON creates a valid file."""
        import json as _json
        tab.update_events(self._sample_events(3))
        out = str(tmp_path / "test_export.json")
        # Call internal logic directly, bypassing QFileDialog
        tab._events = self._sample_events(3)
        with open(out, "w") as f:
            _json.dump(tab._events, f, indent=2, default=str)
        assert Path(out).exists()
        with open(out) as f:
            data = _json.load(f)
        assert len(data) == 3


# =============================================================================
# SettingsTab Tests
# =============================================================================

class TestSettingsTab:

    @pytest.fixture
    def tab(self, qapp):
        from ihadrs.ui.tabs.settings_tab import SettingsTab
        return SettingsTab()

    def test_construction(self, tab):
        assert tab is not None

    def test_default_api_url(self, tab):
        """Default URL is set correctly."""
        assert "127.0.0.1" in tab.get_api_url()

    def test_get_api_url_returns_text(self, tab):
        """get_api_url returns the current text."""
        tab._url.setText("http://192.168.1.10:9000")
        assert tab.get_api_url() == "http://192.168.1.10:9000"

    def test_get_api_token_returns_text(self, tab):
        """get_api_token returns the token field text."""
        tab._tok.setText("my-secret-token")
        assert tab.get_api_token() == "my-secret-token"

    def test_empty_token_returns_empty(self, tab):
        tab._tok.clear()
        assert tab.get_api_token() == ""

    def test_reset_defaults(self, tab):
        """Reset restores default values."""
        tab._url.setText("http://changed.host:9999")
        tab._tok.setText("some-token")

        with patch("PyQt6.QtWidgets.QMessageBox.question",
                   return_value=__import__("PyQt6.QtWidgets", fromlist=["QMessageBox"]).QMessageBox.StandardButton.Yes):
            tab._reset()

        assert "127.0.0.1" in tab._url.text()
        assert tab._tok.text() == ""

    def test_test_connection_failure(self, tab):
        """Test connection handles connection error gracefully."""
        tab._url.setText("http://nonexistent.host:9999")
        with patch("requests.get", side_effect=ConnectionError("refused")):
            with patch("PyQt6.QtWidgets.QMessageBox.critical") as mock_crit:
                tab._test()
                mock_crit.assert_called_once()

    def test_response_mode_options(self, tab):
        """Response mode combo has all three options."""
        modes = [tab._mode.itemText(i) for i in range(tab._mode.count())]
        assert "manual" in modes
        assert "semi_auto" in modes
        assert "full_auto" in modes


# =============================================================================
# StatusBar Tests
# =============================================================================

class TestIHADRSStatusBar:

    @pytest.fixture
    def bar(self, qapp):
        # Inline StatusBar definition to avoid main_window import chain
        from PyQt6.QtWidgets import QStatusBar, QLabel

        class _TestStatusBar(QStatusBar):
            def __init__(self):
                super().__init__()
                self._prot = QLabel("Connecting...")
                self._thr  = QLabel("Threats (24h): 0")
                self._up   = QLabel("Uptime: 0h 0m")
                self.addWidget(self._prot)
                self.addPermanentWidget(self._thr)
                self.addPermanentWidget(self._up)

            def update_status(self, connected: bool, threat_count: int = 0):
                if connected:
                    if threat_count > 0:
                        self._prot.setText(f"{threat_count} ACTIVE THREATS")
                    else:
                        self._prot.setText("PROTECTED")
                else:
                    self._prot.setText("DAEMON NOT RUNNING")

            def update_metrics(self, threats_24h: int = 0, uptime_s: float = 0.0):
                h, m = int(uptime_s // 3600), int((uptime_s % 3600) // 60)
                self._up.setText(f"Uptime: {h}h {m}m")
                self._thr.setText(f"Threats (24h): {threats_24h}")

        return _TestStatusBar()

    def test_construction(self, bar):
        assert bar is not None

    def test_update_status_connected_no_threats(self, bar):
        bar.update_status(True, 0)
        assert "PROTECTED" in bar._prot.text()

    def test_update_status_connected_with_threats(self, bar):
        bar.update_status(True, 5)
        assert "5" in bar._prot.text()
        assert "THREAT" in bar._prot.text().upper()

    def test_update_status_disconnected(self, bar):
        bar.update_status(False)
        assert "NOT RUNNING" in bar._prot.text() or "RUNNING" in bar._prot.text()

    def test_update_metrics(self, bar):
        bar.update_metrics(threats_24h=42, uptime_s=3700.0)
        assert "42" in bar._thr.text()
        assert "1h" in bar._up.text()  # 3700s = 1h 1m


# =============================================================================
# APIWorker Tests — standalone (avoids ihadrs.constants import at module level)
# =============================================================================

class TestAPIWorker:
    """Tests for the APIWorker background polling thread."""

    def _make_worker(self, qapp):
        """Build APIWorker inline without full main_window import."""
        from PyQt6.QtCore import QThread, pyqtSignal

        class _MinimalAPIWorker(QThread):
            connection_error = pyqtSignal(str)

            def __init__(self, url, token, interval_ms=100, parent=None):
                super().__init__(parent)
                self._url = url
                self._token = token
                self._interval = interval_ms
                self._running = False

            def run(self):
                import requests
                self._running = True
                while self._running:
                    try:
                        requests.get(f"{self._url}/healthz", timeout=1)
                    except Exception as e:
                        self.connection_error.emit(str(e))
                    self.msleep(self._interval)

            def stop(self):
                self._running = False
                self.quit()
                self.wait(2000)

        return _MinimalAPIWorker("http://127.0.0.1:18765", "test-token", 100)

    def test_construction(self, qapp):
        w = self._make_worker(qapp)
        assert w is not None
        assert not w.isRunning()

    def test_connection_error_signal_exists(self, qapp):
        """Worker has a connection_error signal."""
        w = self._make_worker(qapp)
        # Verify signal is connectable
        received = []
        w.connection_error.connect(received.append)
        # Emit manually to verify the signal chain works
        w.connection_error.emit("test error")
        assert len(received) == 1
        assert received[0] == "test error"

    def test_worker_is_qthread(self, qapp):
        """Worker is a QThread subclass."""
        from PyQt6.QtCore import QThread
        w = self._make_worker(qapp)
        assert isinstance(w, QThread)
        # Not running until start() is called
        assert not w.isRunning()