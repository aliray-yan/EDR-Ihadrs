"""Module: ui.tabs.logs_tab — Raw event log explorer."""
from __future__ import annotations
import json
from typing import Optional
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QFileDialog, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

_SEV_COLORS = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}


class LogsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: list[dict] = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(8,8,8,8); layout.setSpacing(6)
        tb = QHBoxLayout()
        tb.addWidget(QLabel("Search:"))
        self._search = QLineEdit(); self._search.setPlaceholderText("Filter log entries...")
        self._search.textChanged.connect(self._apply)
        tb.addWidget(self._search, stretch=2)
        exp = QPushButton("📄 Export JSON"); exp.clicked.connect(lambda: self.export_to_file("events.json")); tb.addWidget(exp)
        clr = QPushButton("🗑 Clear"); clr.clicked.connect(self._clear); tb.addWidget(clr)
        layout.addLayout(tb)

        g = QGroupBox("Security Event Log"); gl = QVBoxLayout(g); gl.setContentsMargins(4,4,4,4)
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Timestamp","Event Type","Source Monitor","Details","Severity"])
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False); self._table.setShowGrid(False)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setSortingEnabled(True)
        gl.addWidget(self._table)
        self._status = QLabel("No events. Start the IHADRS daemon first.")
        self._status.setStyleSheet("color:#a0a0c0; font-size:11px;")
        gl.addWidget(self._status)
        layout.addWidget(g)

    def update_events(self, events: list[dict]):
        self._events = events; self._apply()

    def _apply(self):
        s = self._search.text().lower()
        filtered = [e for e in self._events if not s or s in json.dumps(e, default=str).lower()]
        self._populate(filtered)

    def _populate(self, events):
        self._table.setSortingEnabled(False); self._table.setRowCount(len(events))
        for row, evt in enumerate(events):
            ts = evt.get("timestamp","")
            try:
                from datetime import datetime; ts = datetime.fromisoformat(ts.replace("Z","+00:00")).strftime("%Y-%m-%d %H:%M:%S")
            except: pass
            pl = evt.get("payload",{})
            det = " | ".join(f"{k}={v}" for k,v in list(pl.items())[:4] if not isinstance(v,(dict,list))) if isinstance(pl,dict) else str(pl)[:80]
            sev = evt.get("severity","")
            for col, txt in enumerate([ts, evt.get("event_type",""), evt.get("source",""), det, sev]):
                item = QTableWidgetItem(str(txt))
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                if col == 4 and sev in _SEV_COLORS: item.setForeground(QColor(_SEV_COLORS[sev]))
                self._table.setItem(row, col, item)
        self._table.setSortingEnabled(True)
        self._status.setText(f"{len(events)} event(s)")

    def export_to_file(self, default: str):
        path, _ = QFileDialog.getSaveFileName(self, "Export Events", default, "JSON (*.json);;CSV (*.csv)")
        if not path: return
        try:
            if path.endswith(".csv"):
                import csv
                with open(path,"w",newline="",encoding="utf-8") as f:
                    if self._events:
                        w = csv.DictWriter(f, fieldnames=list(self._events[0].keys()))
                        w.writeheader(); w.writerows(self._events)
            else:
                with open(path,"w",encoding="utf-8") as f: json.dump(self._events, f, indent=2, default=str)
            QMessageBox.information(self,"Exported",f"Saved to {path}")
        except Exception as e:
            QMessageBox.critical(self,"Export Failed",str(e))

    def _clear(self):
        self._events = []; self._table.setRowCount(0); self._status.setText("Log cleared.")