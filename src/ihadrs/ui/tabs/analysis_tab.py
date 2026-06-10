"""Module: ui.tabs.analysis_tab — Threat statistics panel."""
from __future__ import annotations
from typing import Optional
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QProgressBar,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)


class AnalysisTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8,8,8,8); layout.setSpacing(8)
        top = QHBoxLayout()
        top.addWidget(self._build_sev_panel())
        top.addWidget(self._build_cat_panel(), stretch=2)
        layout.addLayout(top)
        layout.addWidget(self._build_mitre_panel(), stretch=1)

    def _build_sev_panel(self):
        g = QGroupBox("By Severity (24h)"); lo = QVBoxLayout(g); g.setFixedWidth(220)
        self._sev_bars: dict = {}
        for sev, col in [("CRITICAL","#dc3545"),("HIGH","#fd7e14"),("MEDIUM","#ffc107"),("LOW","#28a745")]:
            row = QHBoxLayout()
            lbl = QLabel(sev); lbl.setFixedWidth(70); lbl.setStyleSheet(f"color:{col};")
            bar = QProgressBar(); bar.setRange(0,100); bar.setValue(0); bar.setFixedHeight(16); bar.setTextVisible(False)
            bar.setStyleSheet(f"QProgressBar::chunk{{background:{col};border-radius:2px;}}QProgressBar{{background:#1a1a2e;border:1px solid #2d2d44;border-radius:2px;}}")
            cnt = QLabel("0"); cnt.setFixedWidth(28); cnt.setStyleSheet(f"color:{col};font-weight:bold;")
            row.addWidget(lbl); row.addWidget(bar); row.addWidget(cnt)
            lo.addLayout(row)
            self._sev_bars[sev] = (cnt, bar)
        lo.addStretch()
        self._total_lbl = QLabel("Total: 0")
        self._total_lbl.setStyleSheet("color:#e0e0e0;font-weight:bold;font-size:13px;")
        lo.addWidget(self._total_lbl)
        return g

    def _build_cat_panel(self):
        g = QGroupBox("By Attack Category (24h)"); lo = QVBoxLayout(g)
        self._cat_table = QTableWidget(0, 3)
        self._cat_table.setHorizontalHeaderLabels(["Category","Count","% Total"])
        self._cat_table.verticalHeader().setVisible(False)
        self._cat_table.setShowGrid(False)
        self._cat_table.setEditTriggers(self._cat_table.EditTrigger.NoEditTriggers)
        self._cat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._cat_table.setAlternatingRowColors(True)
        lo.addWidget(self._cat_table)
        return g

    def _build_mitre_panel(self):
        g = QGroupBox("Top MITRE ATT&CK Techniques"); lo = QVBoxLayout(g)
        self._mitre_table = QTableWidget(0, 4)
        self._mitre_table.setHorizontalHeaderLabels(["Technique ID","Name","Tactic","Detections"])
        self._mitre_table.verticalHeader().setVisible(False); self._mitre_table.setShowGrid(False)
        self._mitre_table.setEditTriggers(self._mitre_table.EditTrigger.NoEditTriggers)
        self._mitre_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._mitre_table.setAlternatingRowColors(True); self._mitre_table.setMaximumHeight(220)
        lo.addWidget(self._mitre_table)
        return g

    def update_stats(self, stats: dict):
        total = stats.get("total_threats", 0)
        by_sev = stats.get("by_severity", {})
        by_cat = stats.get("by_category", {})
        self._total_lbl.setText(f"Total: {total}")
        mx = max(by_sev.values(), default=1) or 1
        for sev, (cnt, bar) in self._sev_bars.items():
            c = by_sev.get(sev, 0); cnt.setText(str(c)); bar.setValue(int(c/mx*100))
        items = sorted(by_cat.items(), key=lambda x: x[1], reverse=True)
        self._cat_table.setRowCount(len(items))
        for row, (cat, cnt) in enumerate(items):
            pct = f"{cnt/total*100:.1f}%" if total else "0%"
            for col, txt in enumerate([cat, str(cnt), pct]):
                item = QTableWidgetItem(txt)
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                self._cat_table.setItem(row, col, item)