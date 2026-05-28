"""
PyInstaller entry point — uses only absolute imports.
Do NOT rename this file; build.spec references it.
Run from source with:  python loghawk.py
"""

import sys
import os
from pathlib import Path

# Ensure the repo root is on sys.path so `src.*` absolute imports resolve.
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from src.ui.main_window import MainWindow


def main() -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("LogHawk")
    app.setOrganizationName("LogHawk")

    window = MainWindow()
    window.show()

    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        if path.exists():
            ft = "evtx" if path.suffix.lower() == ".evtx" else "csv"
            window._load_file(str(path), ft)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
