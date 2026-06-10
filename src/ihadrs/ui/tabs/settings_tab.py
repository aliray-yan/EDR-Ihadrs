"""Module: ui.tabs.settings_tab — Configuration panel."""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)


class SettingsTab(QWidget):
    _DEFAULTS = {
        "api_url": "http://127.0.0.1:8765",
        "api_token": "",
        "response_mode": "manual",
        "min_severity": "MEDIUM",
        "poll_interval_ms": 2000,
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._load()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Connection group
        cg = QGroupBox("IHADRS Daemon Connection")
        cf = QFormLayout(cg)
        cf.setSpacing(10)
        self._url = QLineEdit()
        self._url.setPlaceholderText("http://127.0.0.1:8765")
        cf.addRow("API URL:", self._url)

        tok_row = QHBoxLayout()
        self._tok = QLineEdit()
        self._tok.setEchoMode(QLineEdit.EchoMode.Password)
        self._tok.setPlaceholderText("API token")
        show_btn = QPushButton("Show")
        show_btn.setFixedWidth(50)
        show_btn.setCheckable(True)
        show_btn.toggled.connect(
            lambda on: self._tok.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
            )
        )
        tok_row.addWidget(self._tok)
        tok_row.addWidget(show_btn)
        cf.addRow("API Token:", tok_row)

        self._poll = QSpinBox()
        self._poll.setRange(500, 30000)
        self._poll.setSingleStep(500)
        self._poll.setSuffix(" ms")
        self._poll.setValue(2000)
        cf.addRow("Poll Interval:", self._poll)
        layout.addWidget(cg)

        # Response group
        rg = QGroupBox("Response Mode")
        rf = QFormLayout(rg)
        rf.setSpacing(10)
        self._mode = QComboBox()
        self._mode.addItems(["manual", "semi_auto", "full_auto"])
        rf.addRow("Mode:", self._mode)
        layout.addWidget(rg)

        # Notifications group
        ng = QGroupBox("Notifications")
        nf = QFormLayout(ng)
        nf.setSpacing(10)
        self._desktop = QCheckBox("Enable desktop notifications")
        self._desktop.setChecked(True)
        nf.addRow("", self._desktop)
        self._console = QCheckBox("Console output")
        self._console.setChecked(True)
        nf.addRow("", self._console)
        self._minsev = QComboBox()
        self._minsev.addItems(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self._minsev.setCurrentText("MEDIUM")
        nf.addRow("Min severity:", self._minsev)
        layout.addWidget(ng)

        # Buttons
        br = QHBoxLayout()
        sv = QPushButton("Save Settings")
        sv.clicked.connect(self._save)
        br.addWidget(sv)
        ts = QPushButton("Test Connection")
        ts.clicked.connect(self._test)
        br.addWidget(ts)
        rs = QPushButton("Reset Defaults")
        rs.clicked.connect(self._reset)
        br.addWidget(rs)
        br.addStretch()
        layout.addLayout(br)
        layout.addStretch()

    def _load(self):
        try:
            from PyQt6.QtCore import QSettings
            s = QSettings("IHADRS", "Dashboard")
            self._url.setText(s.value("api_url", self._DEFAULTS["api_url"]))
            self._tok.setText(s.value("api_token", ""))
            self._poll.setValue(int(s.value("poll_interval_ms", 2000)))
            idx = self._mode.findText(s.value("response_mode", "manual"))
            if idx >= 0:
                self._mode.setCurrentIndex(idx)
            self._desktop.setChecked(s.value("desktop_notifications", True, type=bool))
            self._console.setChecked(s.value("console_output", True, type=bool))
            si = self._minsev.findText(s.value("min_severity", "MEDIUM"))
            if si >= 0:
                self._minsev.setCurrentIndex(si)
        except Exception:
            pass

    def _save(self):
        try:
            from PyQt6.QtCore import QSettings
            s = QSettings("IHADRS", "Dashboard")
            s.setValue("api_url", self._url.text())
            s.setValue("api_token", self._tok.text())
            s.setValue("poll_interval_ms", self._poll.value())
            s.setValue("response_mode", self._mode.currentText())
            s.setValue("desktop_notifications", self._desktop.isChecked())
            s.setValue("console_output", self._console.isChecked())
            s.setValue("min_severity", self._minsev.currentText())
            s.sync()
        except Exception as e:
            QMessageBox.warning(self, "Save Failed", str(e))
            return

        mw = self.parent().parent() if self.parent() and self.parent().parent() else None
        if mw and hasattr(mw, "restart_api_worker"):
            mw.restart_api_worker()
        QMessageBox.information(self, "Saved", "Settings saved successfully.")

    def _test(self):
        url = self._url.text().rstrip("/")
        try:
            import requests
            r = requests.get(url + "/healthz", timeout=3)
            if r.ok:
                d = r.json()
                msg = "Connected successfully. Version: " + str(d.get("version", "unknown"))
                QMessageBox.information(self, "Connection OK", msg)
            else:
                QMessageBox.warning(self, "Failed", "HTTP " + str(r.status_code))
        except Exception as e:
            QMessageBox.critical(self, "Failed", "Could not connect: " + str(e))

    def _reset(self):
        reply = QMessageBox.question(self, "Reset", "Reset all settings to defaults?")
        if reply == QMessageBox.StandardButton.Yes:
            self._url.setText(self._DEFAULTS["api_url"])
            self._tok.clear()
            self._poll.setValue(2000)
            self._mode.setCurrentText("manual")
            self._desktop.setChecked(True)
            self._console.setChecked(True)
            self._minsev.setCurrentText("MEDIUM")

    def get_api_url(self):
        return self._url.text().strip() or self._DEFAULTS["api_url"]

    def get_api_token(self):
        return self._tok.text().strip()