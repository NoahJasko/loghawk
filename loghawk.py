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

# ── Windows: register as a standalone app BEFORE QApplication ────────────────
# Without this, Windows treats the process as "python.exe" and shows the
# Python icon in the taskbar regardless of setWindowIcon().
if sys.platform == "win32":
    import ctypes
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "NoahJasko.LogHawk.1"
        )
    except Exception:
        pass

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon

from src.ui.main_window import MainWindow


def _app_icon() -> QIcon | None:
    """Return the best available icon (ICO preferred, PNG fallback)."""
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS) / "resources"   # type: ignore[attr-defined]
    else:
        base = _HERE / "src" / "resources"
    for name in ("logo.ico", "logo.png"):
        p = base / name
        if p.exists():
            icon = QIcon(str(p))
            if not icon.isNull():
                return icon
    return None


def main() -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("LogHawk")
    app.setOrganizationName("LogHawk")

    icon = _app_icon()
    if icon:
        app.setWindowIcon(icon)   # sets default for every window in the process

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
