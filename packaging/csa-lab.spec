# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-folder build for CSA Lab."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parents[0]
if ROOT.name == "packaging":
    ROOT = ROOT.parent

datas = [
    (str(ROOT / "assets" / "logo.png"), "assets"),
    (str(ROOT / "collector" / "windows"), "collector/windows"),
    (str(ROOT / "collector_schema"), "collector_schema"),
    (str(ROOT / "frameworks"), "frameworks"),
    (str(ROOT / "knowledge"), "knowledge"),
    (str(ROOT / "schemas"), "schemas"),
    (str(ROOT / "software"), "software"),
    (str(ROOT / "templates"), "templates"),
    (str(ROOT / "csa_console" / "templates"), "csa_console/templates"),
    (str(ROOT / "csa_lab" / "templates"), "csa_lab/templates"),
    (
        str(ROOT / "csa_lab" / "powershell"),
        "csa_lab/powershell",
    ),
    (
        str(ROOT / "build" / "collector" / "CSA-Collector.exe"),
        "collector-bootstrapper",
    ),
]

hiddenimports = sorted(
    set(
        collect_submodules("rules")
        + collect_submodules("compliance")
        + collect_submodules("frameworks")
        + collect_submodules("cve")
        + collect_submodules("software")
    )
)

a = Analysis(
    [str(ROOT / "csa_lab" / "app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CSA-Lab",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CSA-Lab",
)
