# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for LogHawk — produces a single Windows .exe"""

from pathlib import Path

HERE = Path(SPECPATH)
SRC  = HERE / "src"

# Logo files — included when present; build works without them too
_logo_png = SRC / "resources" / "logo.png"
_logo_ico = SRC / "resources" / "logo.ico"

_datas = [
    (str(SRC / "data" / "security_events.json"), "data"),
    (str(SRC / "resources" / "style.qss"),       "resources"),
]
if _logo_png.exists():
    _datas.append((str(_logo_png), "resources"))
if _logo_ico.exists():
    _datas.append((str(_logo_ico), "resources"))

_icon = str(_logo_ico) if _logo_ico.exists() else None

a = Analysis(
    [str(HERE / "loghawk.py")],
    pathex=[str(HERE)],
    binaries=[],
    datas=_datas,
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
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_icon,   # .ico used when logo.ico is present, otherwise default
    version=None,
)
