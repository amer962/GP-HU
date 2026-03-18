# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\gui.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\models', 'models'), ('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\step2_feature_extractor.py', '.'), ('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\step3_monitor.py', '.'), ('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\step4_kill_chain.py', '.'), ('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\step5_main.py', '.'), ('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\step6_file_guard.py', '.'), ('C:\\Users\\MSI-PC\\Desktop\\RansomwareProject\\ransomware_detector\\step7_decompiler.py', '.')],
    hiddenimports=['sklearn', 'sklearn.linear_model', 'sklearn.utils._cython_blas', 'sklearn.neighbors._partition_nodes', 'sklearn.tree._utils', 'joblib', 'psutil', 'numpy', 'pandas', 'tkinter', 'tkinter.ttk', 'tkinter.font', 'watchdog', 'watchdog.observers', 'watchdog.events'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='RansomShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='RansomShield',
)
