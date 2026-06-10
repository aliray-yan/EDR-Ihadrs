"""
Module: ui.main_window
Main application window: tab container, status bar, API polling worker.
"""
from __future__ import annotations
import time
from typing import Any, Optional

from PyQt6.QtCore import QSize, Qt, QThread, QTimer, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QAction, QCloseEvent, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QStatusBar,
    QSystemTrayIcon, QTabWidget, QVBoxLayout, QWidget,
)
from ihadrs.constants import APP_FULL_NAME, APP_NAME, APP_VERSION


class APIWorker(QThread):
    status_received  = pyqtSignal(dict)
    threats_received = pyqtSignal(list)
    stats_received   = pyqtSignal(dict)
    connection_error = pyqtSignal(str)

    def __init__(self, api_url: str, api_token: str,
                 poll_interval_ms: int = 2000, parent=None):
        super().__init__(parent)
        self._url   = api_url.rstrip("/")
        self._token = api_token
        self._interval = poll_interval_ms
        self._running  = False
        self._headers  = {"X-IHADRS-Token": api_token, "Content-Type": "application/json"}

    def run(self):
        import requests
        self._running = True
        while self._running:
            try:
                r = requests.get(f"{self._url}/api/v1/status", headers=self._headers, timeout=3)
                if r.ok: self.status_received.emit(r.json())
                r = requests.get(f"{self._url}/api/v1/threats?limit=50", headers=self._headers, timeout=3)
                if r.ok: self.threats_received.emit(r.json().get("threats", []))
                r = requests.get(f"{self._url}/api/v1/stats?hours=24", headers=self._headers, timeout=3)
                if r.ok: self.stats_received.emit(r.json())
            except requests.exceptions.ConnectionError:
                self.connection_error.emit(f"Cannot connect to {self._url}")
            except Exception as e:
                self.connection_error.emit(str(e))
            self.msleep(self._interval)

    def stop(self):
        self._running = False
        self.quit()
        self.wait(2000)


class IHADRSStatusBar(QStatusBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._prot = QLabel("⏳  Connecting...")
        self._prot.setObjectName("status_degraded")
        self._cpu  = QLabel("CPU: --")
        self._ram  = QLabel("RAM: --")
        self._up   = QLabel("Uptime: --")
        self._thr  = QLabel("Threats (24h): --")
        for lbl in [self._cpu, self._ram, self._up, self._thr]:
            lbl.setStyleSheet("color: #a0a0c0; padding: 0 8px;")
        self.addWidget(self._prot)
        self.addWidget(QLabel("  "))
        self.addPermanentWidget(self._cpu)
        self.addPermanentWidget(self._ram)
        self.addPermanentWidget(self._thr)
        self.addPermanentWidget(self._up)

    def update_status(self, connected: bool, threat_count: int = 0):
        if connected:
            if threat_count > 0:
                self._prot.setText(f"🔴  {threat_count} ACTIVE THREATS")
                self._prot.setObjectName("status_critical")
            else:
                self._prot.setText("🟢  PROTECTED")
                self._prot.setObjectName("status_healthy")
        else:
            self._prot.setText("⚪  DAEMON NOT RUNNING")
            self._prot.setObjectName("status_degraded")
        self._prot.style().unpolish(self._prot)
        self._prot.style().polish(self._prot)

    def update_metrics(self, threats_24h: int = 0, uptime_s: float = 0.0):
        h, m = int(uptime_s // 3600), int((uptime_s % 3600) // 60)
        self._up.setText(f"Uptime: {h}h {m}m")
        self._thr.setText(f"Threats (24h): {threats_24h}")


class MainWindow(QMainWindow):
    _DEFAULT_API_URL   = "http://127.0.0.1:8765"
    _DEFAULT_API_TOKEN = ""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._api_worker: Optional[APIWorker] = None
        self._connected  = False
        self._last_threats = 0
        self._setup_window()
        self._build_menu()
        self._build_central_widget()
        self._build_status_bar()
        self._setup_tray()
        self._start_api_worker()

    def _setup_window(self):
        self.setWindowTitle(f"{APP_NAME} — Security Dashboard v{APP_VERSION}")
        self.setMinimumSize(QSize(1024, 720))
        self.resize(QSize(1280, 800))

    def _build_menu(self):
        mb = self.menuBar()
        fm = mb.addMenu("&File")
        ea = QAction("&Export Events...", self)
        ea.setShortcut(QKeySequence("Ctrl+E"))
        ea.triggered.connect(self._on_export)
        fm.addAction(ea)
        fm.addSeparator()
        qa = QAction("&Quit", self)
        qa.setShortcut(QKeySequence("Ctrl+Q"))
        qa.triggered.connect(self.close)
        fm.addAction(qa)
        vm = mb.addMenu("&View")
        ra = QAction("&Refresh Now", self)
        ra.setShortcut(QKeySequence("F5"))
        ra.triggered.connect(self._on_refresh)
        vm.addAction(ra)
        hm = mb.addMenu("&Help")
        aa = QAction("&About", self)
        aa.triggered.connect(self._on_about)
        hm.addAction(aa)

    def _build_central_widget(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        from ihadrs.ui.tabs.monitor_tab  import MonitorTab
        from ihadrs.ui.tabs.alerts_tab   import AlertsTab
        from ihadrs.ui.tabs.analysis_tab import AnalysisTab
        from ihadrs.ui.tabs.logs_tab     import LogsTab
        from ihadrs.ui.tabs.settings_tab import SettingsTab

        self._monitor_tab  = MonitorTab(self)
        self._alerts_tab   = AlertsTab(self)
        self._analysis_tab = AnalysisTab(self)
        self._logs_tab     = LogsTab(self)
        self._settings_tab = SettingsTab(self)

        self._tabs.addTab(self._monitor_tab,  "📊  Monitor")
        self._tabs.addTab(self._alerts_tab,   "🚨  Alerts")
        self._tabs.addTab(self._analysis_tab, "🔍  Analysis")
        self._tabs.addTab(self._logs_tab,     "📋  Logs")
        self._tabs.addTab(self._settings_tab, "⚙️   Settings")
        layout.addWidget(self._tabs)

    def _build_status_bar(self):
        self._status_bar = IHADRSStatusBar(self)
        self.setStatusBar(self._status_bar)

    def _setup_tray(self):
        self._tray = None
        try:
            tray = QSystemTrayIcon(self)
            tray.setToolTip(f"{APP_NAME} — Click to open dashboard")
            tray.activated.connect(self._on_tray_activated)
            from PyQt6.QtWidgets import QMenu
            menu = QMenu()
            show = QAction("Show Dashboard", self); show.triggered.connect(self.show)
            quit = QAction("Quit", self); quit.triggered.connect(QApplication.quit)
            menu.addAction(show); menu.addSeparator(); menu.addAction(quit)
            tray.setContextMenu(menu)
            tray.show()
            self._tray = tray
        except Exception:
            pass

    def _start_api_worker(self):
        url   = self._settings_tab.get_api_url()
        token = self._settings_tab.get_api_token()
        if not token:
            self._status_bar.update_status(False)
            return
        self._api_worker = APIWorker(url, token, parent=self)
        self._api_worker.status_received.connect(self._on_status)
        self._api_worker.threats_received.connect(self._on_threats)
        self._api_worker.stats_received.connect(self._on_stats)
        self._api_worker.connection_error.connect(self._on_error)
        self._api_worker.start()

    def restart_api_worker(self):
        if self._api_worker: self._api_worker.stop()
        self._connected = False
        self._start_api_worker()

    @pyqtSlot(dict)
    def _on_status(self, data: dict):
        self._connected = True
        self._status_bar.update_status(True, self._last_threats)
        self._monitor_tab.update_status(data)

    @pyqtSlot(list)
    def _on_threats(self, threats: list):
        active = [t for t in threats if not t.get("false_positive", {}).get("marked", False)]
        self._last_threats = len(active)
        self._alerts_tab.update_threats(threats)

    @pyqtSlot(dict)
    def _on_stats(self, stats: dict):
        self._analysis_tab.update_stats(stats)
        self._status_bar.update_metrics(threats_24h=stats.get("total_threats", 0))

    @pyqtSlot(str)
    def _on_error(self, err: str):
        self._connected = False
        self._status_bar.update_status(False)

    def _on_export(self):
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "Export Events", "ihadrs_events.json", "JSON (*.json)")
        if path: self._logs_tab.export_to_file(path)

    def _on_refresh(self):
        pass  # Worker polls continuously

    def _on_about(self):
        QMessageBox.about(self, f"About {APP_NAME}",
            f"<h2>{APP_NAME}</h2><p><b>{APP_FULL_NAME}</b></p><p>Version {APP_VERSION}</p>"
            "<p>Lightweight endpoint detection and response for individuals and small teams.</p>")

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.hide() if self.isVisible() else self.show()

    def closeEvent(self, event: QCloseEvent):
        if self._tray and self._tray.isVisible():
            self.hide()
            event.ignore()
            return
        if self._api_worker: self._api_worker.stop()
        event.accept()