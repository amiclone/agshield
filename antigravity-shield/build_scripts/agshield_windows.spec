# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for AGShield (Windows)
Builds a standalone .exe for the AntiGravity Shield.
"""

import os
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Resolve paths relative to project root (one level up from build_scripts)
PROJECT_ROOT = Path(SPECPATH).parent.resolve() if 'SPECPATH' in globals() else Path(os.path.dirname(os.path.abspath(SPEC))).parent.resolve()

# Collect all agshield data files
datas = []
datas += collect_data_files('agshield', includes=['*.yaml'])
datas += collect_data_files('watchdog', includes=['*.txt'])

# Collect all submodules
hiddenimports = []
hiddenimports += collect_submodules('agshield')
hiddenimports += [
    'click',
    'rich',
    'yaml',
    'psutil',
    'watchdog',
    'watchdog.observers',
    'watchdog.events',
    'watchdog.observers.read_directory_changes',
    'socket',
    'json',
    'sqlite3',
    'threading',
    'signal',
    'logging',
    'win32api',
    'win32con',
    'scipy.stats',
    'matplotlib',
]

a = Analysis(
    [str(PROJECT_ROOT / 'src' / 'agshield' / 'cli.py')],
    pathex=[str(PROJECT_ROOT / 'src')],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'pandas'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='agshield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(PROJECT_ROOT / 'build_scripts' / 'icon.ico') if (PROJECT_ROOT / 'build_scripts' / 'icon.ico').exists() else None,
)
