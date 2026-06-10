"""
Module: ui.tabs.alerts_tab
Threat alert feed with detail view and response controls.
"""
from __future__ import annotations
import json
from typing import Optional
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea,
    QSplitter, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

_SEV_COLORS = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}
_SEV_ICONS  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}


class AlertsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._threats: list[dict] = []
        self._selected: Optional[dict] = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        layout.addWidget(self._build_filter_bar())
        sp = QSplitter(Qt.Orientation.Horizontal)
        sp.addWidget(self._build_list_panel())
        sp.addWidget(self._build_detail_panel())
        sp.setSizes([480, 560])
        layout.addWidget(sp)

    def _build_filter_bar(self):
        w = QWidget(); lo = QHBoxLayout(w)
        lo.setContentsMargins(0,0,0,0)
        lo.addWidget(QLabel("Filter:"))
        self._search = QLineEdit(); self._search.setPlaceholderText("Search...")
        self._search.textChanged.connect(self._apply)
        lo.addWidget(self._search, stretch=2)
        lo.addWidget(QLabel("Severity:"))
        self._sev = QComboBox()
        self._sev.addItems(["All","CRITICAL","HIGH","MEDIUM","LOW"])
        self._sev.currentTextChanged.connect(self._apply)
        lo.addWidget(self._sev)
        self._fp_btn = QPushButton("Show FP"); self._fp_btn.setCheckable(True)
        self._fp_btn.setFixedWidth(70); self._fp_btn.clicked.connect(self._apply)
        lo.addWidget(self._fp_btn)
        clr = QPushButton("Clear"); clr.setFixedWidth(50)
        clr.clicked.connect(self._clear); lo.addWidget(clr)
        return w

    def _build_list_panel(self):
        g = QGroupBox("Detected Threats"); lo = QVBoxLayout(g)
        lo.setContentsMargins(4,4,4,4)
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Time","Severity","Category","Resource","Conf."])
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setSortingEnabled(True)
        self._table.itemSelectionChanged.connect(self._on_row_changed)
        lo.addWidget(self._table)
        self._count_lbl = QLabel("0 threats")
        self._count_lbl.setStyleSheet("color:#a0a0c0; font-size:11px;")
        lo.addWidget(self._count_lbl)
        return g

    def _build_detail_panel(self):
        g = QGroupBox("Threat Details"); lo = QVBoxLayout(g)
        lo.setContentsMargins(6,6,6,6); lo.setSpacing(6)
        self._d_title = QLabel("Select a threat to view details")
        self._d_title.setStyleSheet("font-size:15px; font-weight:bold; color:#e0e0e0;")
        self._d_title.setWordWrap(True)
        lo.addWidget(self._d_title)
        self._d_meta = QLabel(""); self._d_meta.setStyleSheet("color:#a0a0c0; font-size:11px;")
        lo.addWidget(self._d_meta)

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(scroll.Shape.NoFrame)
        content = QWidget(); clo = QVBoxLayout(content); clo.setSpacing(8)

        for title, attr, max_h, style in [
            ("What Happened",    "_d_expl",  80,  "color:#e0e0e0;"),
            ("Technical Details","_d_tech",  110, "background:#0d0d1a; color:#a0f0a0; font-family:monospace;"),
            ("MITRE ATT&CK",     "_d_mitre", 60,  "color:#e0e0e0;"),
            ("Recommended Actions","_d_rem", 160, "color:#e0e0e0;"),
        ]:
            grp = QGroupBox(title); glo = QVBoxLayout(grp)
            te = QTextEdit(); te.setReadOnly(True)
            if max_h: te.setMaximumHeight(max_h)
            if style: te.setStyleSheet(style)
            glo.addWidget(te); clo.addWidget(grp)
            setattr(self, attr, te)

        clo.addStretch(); scroll.setWidget(content); lo.addWidget(scroll, stretch=1)

        btn_row = QHBoxLayout()
        self._fp_action = QPushButton("✓ Mark FP"); self._fp_action.setEnabled(False)
        self._fp_action.clicked.connect(self._on_fp)
        btn_row.addWidget(self._fp_action)
        self._exp_btn = QPushButton("📄 Export"); self._exp_btn.setEnabled(False)
        self._exp_btn.clicked.connect(self._on_export)
        btn_row.addWidget(self._exp_btn)
        lo.addLayout(btn_row)
        return g

    def update_threats(self, threats: list[dict]):
        self._threats = threats
        self._apply()

    def _apply(self):
        search = self._search.text().lower()
        sev_f  = self._sev.currentText()
        show_fp = self._fp_btn.isChecked()
        filtered = []
        for t in self._threats:
            if t.get("false_positive", {}).get("marked") and not show_fp: continue
            if sev_f != "All" and t.get("severity") != sev_f: continue
            if search and search not in json.dumps(t, default=str).lower(): continue
            filtered.append(t)
        self._populate(filtered)
        self._count_lbl.setText(f"{len(filtered)} threat(s)")

    def _populate(self, threats):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(threats))
        for row, t in enumerate(threats):
            ts = t.get("timestamp","")
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts.replace("Z","+00:00")).strftime("%m/%d %H:%M")
            except: pass
            sev = t.get("severity","")
            self._cell(row, 0, ts).setData(Qt.ItemDataRole.UserRole, t)
            si = self._cell(row, 1, f"{_SEV_ICONS.get(sev,'')} {sev}")
            si.setForeground(QColor(_SEV_COLORS.get(sev,"#e0e0e0")))
            self._cell(row, 2, t.get("attack_category",""))
            res = t.get("affected_resource","")
            self._cell(row, 3, res[:40]+"..." if len(res)>40 else res)
            self._cell(row, 4, f"{t.get('confidence',0):.0%}")
        self._table.setSortingEnabled(True)

    def _cell(self, row, col, text):
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self._table.setItem(row, col, item)
        return item

    def _on_row_changed(self):
        rows = self._table.selectionModel().selectedRows()
        self._on_select(rows[0].row() if rows else -1)

    def _on_select(self, row: int):
        if row < 0: return
        item = self._table.item(row, 0)
        if not item: return
        t = item.data(Qt.ItemDataRole.UserRole)
        if not t: return
        self._selected = t
        sev = t.get("severity","")
        self._d_title.setText(f"{_SEV_ICONS.get(sev,'')} {sev}: {t.get('attack_category','')}")
        self._d_meta.setText(f"ID: {t.get('threat_id','')[:16]}...  Confidence: {t.get('confidence',0):.0%}")
        expl = t.get("explanation",{})
        self._d_expl.setPlainText(expl.get("user","") or t.get("summary",""))
        self._d_tech.setPlainText(expl.get("technical",""))
        mitre = t.get("mitre",{})
        tecs  = ", ".join(f"{i}({n})" for i,n in zip(mitre.get("techniques",[])[:3], mitre.get("technique_names",[""])))
        self._d_mitre.setPlainText(f"Techniques: {tecs or 'N/A'}")
        steps = t.get("remediation",[])
        rem = chr(10).join(str(s.get("step","")) + ". " + str(s.get("description","")) for s in steps)
        self._d_rem.setPlainText(rem or "No steps available.")
        self._fp_action.setEnabled(True)
        self._exp_btn.setEnabled(True)

    def _on_fp(self):
        if not self._selected: return
        QMessageBox.information(self, "Marked", "Threat marked as false positive.")

    def _on_export(self):
        if not self._selected: return
        from PyQt6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "Export", "threat.json", "JSON (*.json)")
        if path:
            with open(path,"w") as f: json.dump(self._selected, f, indent=2, default=str)

    def _clear(self):
        self._search.clear(); self._sev.setCurrentIndex(0)
        self._fp_btn.setChecked(False); self._apply()