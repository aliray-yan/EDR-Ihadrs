"""
Module: ui.app
Entry point for the IHADRS PyQt6 dashboard.
"""
from __future__ import annotations
import sys
from pathlib import Path
from ihadrs.constants import APP_FULL_NAME, APP_NAME, APP_VERSION


def main() -> None:
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
    except ImportError:
        print("PyQt6 not installed. Run: pip install ihadrs[ui]")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_FULL_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("IHADRS")
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    app.setStyleSheet(_DARK_THEME)

    from ihadrs.ui.main_window import MainWindow
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


_DARK_THEME = """
QMainWindow, QDialog, QWidget { background-color: #1a1a2e; color: #e0e0e0;
    font-family: "Segoe UI", Arial, sans-serif; font-size: 13px; }
QTabWidget::pane { border: 1px solid #2d2d44; background-color: #16213e; }
QTabBar::tab { background: #0f3460; color: #a0a0c0; padding: 8px 20px;
    border: none; border-right: 1px solid #1a1a2e; }
QTabBar::tab:selected { background: #e94560; color: white; font-weight: bold; }
QTableWidget { background-color: #16213e; alternate-background-color: #1a2040;
    gridline-color: #2d2d44; color: #e0e0e0; selection-background-color: #0f3460; }
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section { background-color: #0f3460; color: #a0a0c0; font-weight: bold;
    padding: 6px; border: none; border-right: 1px solid #2d2d44; }
QPushButton { background-color: #0f3460; color: #e0e0e0; border: 1px solid #2d2d44;
    border-radius: 4px; padding: 6px 14px; font-weight: bold; }
QPushButton:hover { background-color: #1a4a80; }
QPushButton:pressed { background-color: #e94560; }
QLabel#status_healthy { color: #28a745; font-weight: bold; }
QLabel#status_degraded { color: #ffc107; font-weight: bold; }
QLabel#status_critical { color: #dc3545; font-weight: bold; }
QScrollBar:vertical { background: #16213e; width: 10px; border: none; }
QScrollBar::handle:vertical { background: #0f3460; border-radius: 5px; min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #e94560; }
QLineEdit, QTextEdit { background-color: #16213e; border: 1px solid #2d2d44;
    border-radius: 4px; color: #e0e0e0; padding: 4px 8px; }
QGroupBox { border: 1px solid #2d2d44; border-radius: 4px; margin-top: 8px;
    color: #a0a0c0; font-weight: bold; padding-top: 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
QProgressBar { border: 1px solid #2d2d44; border-radius: 4px;
    background-color: #16213e; text-align: center; color: #e0e0e0; }
QProgressBar::chunk { background-color: #0f3460; border-radius: 3px; }
QComboBox { background-color: #16213e; border: 1px solid #2d2d44;
    border-radius: 4px; padding: 4px 8px; color: #e0e0e0; }
QSplitter::handle { background: #2d2d44; }
"""

if __name__ == "__main__":
    main()