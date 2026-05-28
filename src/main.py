"""LogHawk entry point."""

import sys
from pathlib import Path

# When frozen by PyInstaller _MEIPASS provides the bundle root.
# We patch the data path so event_db.py can find security_events.json.
if getattr(sys, "frozen", False):
    import os
    _bundle = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    os.environ["LOGHAWK_DATA"] = str(_bundle / "data")

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from .ui.main_window import MainWindow


def main() -> int:
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("LogHawk")
    app.setOrganizationName("LogHawk")

    window = MainWindow()
    window.show()

    # If a file was passed on the command line, open it
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        if path.exists():
            ft = "evtx" if path.suffix.lower() == ".evtx" else "csv"
            window._load_file(str(path), ft)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
