"""
Module: ui.tabs.monitor_tab
Live process list, system status, and event feed.
"""
from __future__ import annotations
from typing import Optional
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QProgressBar, QPushButton, QSplitter,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)


class MonitorTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        top = QSplitter(Qt.Orientation.Horizontal)
        top.addWidget(self._build_status_panel())
        top.addWidget(self._build_process_panel())
        top.setSizes([260, 720])
        layout.addWidget(top, stretch=2)
        layout.addWidget(self._build_event_panel(), stretch=1)

    def _build_status_panel(self):
        group = QGroupBox("System Status")
        layout = QVBoxLayout(group)
        self._prot_lbl = QLabel("⏳  Connecting...")
        self._prot_lbl.setStyleSheet("font-size:14px; font-weight:bold;")
        layout.addWidget(self._prot_lbl)

        for label, attr, max_val, suffix in [
            ("CPU:", "_cpu_bar", 100, "%v%"),
            ("RAM:", "_ram_bar", 500, "%vMB"),
        ]:
            row = QHBoxLayout()
            row.addWidget(QLabel(label))
            bar = QProgressBar()
            bar.setRange(0, max_val); bar.setValue(0)
            bar.setFormat(suffix); bar.setFixedHeight(18)
            row.addWidget(bar)
            layout.addLayout(row)
            setattr(self, attr, bar)

        layout.addWidget(QLabel(""))
        for text, default, attr in [
            ("Threats (24h):", "0",    "_threats_lbl"),
            ("Rules active:",  "--",   "_rules_lbl"),
            ("Monitors up:",   "--",   "_mons_lbl"),
            ("Events/sec:",    "0.00", "_eps_lbl"),
        ]:
            row = QHBoxLayout()
            row.addWidget(QLabel(text))
            lbl = QLabel(default)
            lbl.setStyleSheet("color:#e0e0e0; font-weight:bold;")
            row.addWidget(lbl); row.addStretch()
            layout.addLayout(row)
            setattr(self, attr, lbl)

        layout.addStretch()
        btn = QPushButton("🔍 Scan Now")
        btn.clicked.connect(lambda: None)
        layout.addWidget(btn)
        return group

    def _build_process_panel(self):
        group = QGroupBox("Active Processes")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(4, 4, 4, 4)
        self._proc_search = QLineEdit()
        self._proc_search.setPlaceholderText("Filter processes...")
        self._proc_search.textChanged.connect(self._filter_procs)
        layout.addWidget(self._proc_search)

        self._proc_table = QTableWidget(0, 6)
        self._proc_table.setHorizontalHeaderLabels(["PID","Name","CPU%","RAM(MB)","Parent","Risk"])
        self._proc_table.setAlternatingRowColors(True)
        self._proc_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._proc_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._proc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._proc_table.verticalHeader().setVisible(False)
        self._proc_table.setShowGrid(False)
        layout.addWidget(self._proc_table)
        self._proc_count = QLabel("Processes: --")
        self._proc_count.setStyleSheet("color:#a0a0c0; font-size:11px;")
        layout.addWidget(self._proc_count)
        return group

    def _build_event_panel(self):
        group = QGroupBox("Recent Events (Last 100)")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(4, 4, 4, 4)
        self._evt_table = QTableWidget(0, 5)
        self._evt_table.setHorizontalHeaderLabels(["Time","Event Type","Source","Details","Severity"])
        self._evt_table.setAlternatingRowColors(True)
        self._evt_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._evt_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._evt_table.verticalHeader().setVisible(False)
        self._evt_table.setShowGrid(False)
        self._evt_table.setMaximumHeight(180)
        layout.addWidget(self._evt_table)
        return group

    def update_status(self, status: dict):
        monitors = status.get("monitors", [])
        running  = sum(1 for m in monitors if m.get("running", False))
        self._prot_lbl.setText(
            f"🟢  PROTECTED — {running} monitors" if running
            else "🔴  NO MONITORS RUNNING"
        )
        det = status.get("detection", {})
        self._eps_lbl.setText(f"{det.get('events_per_second', 0):.2f}")
        self._rules_lbl.setText(str(det.get("rule_count", "--")))
        self._mons_lbl.setText(str(running))

    def _filter_procs(self, text: str):
        for row in range(self._proc_table.rowCount()):
            item = self._proc_table.item(row, 1)
            match = text.lower() in (item.text().lower() if item else "")
            self._proc_table.setRowHidden(row, not match)