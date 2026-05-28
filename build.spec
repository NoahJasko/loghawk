# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for LogHawk — produces a single Windows .exe"""

from pathlib import Path
import sys

HERE = Path(SPECPATH)
SRC  = HERE / "src"

a = Analysis(
    [str(SRC / "main.py")],
    pathex=[str(HERE)],
    binaries=[],
    datas=[
        (str(SRC / "data" / "security_events.json"), "data"),
        (str(SRC / "resources" / "style.qss"),       "resources"),
    ],
    hiddenimports=[
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "win32evtlog",
        "win32con",
        "pywintypes",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="LogHawk",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,            # add icon path here if you have one
    version=None,
)
