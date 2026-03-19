"""
build_exe.py — يحوّل البرنامج لـ .exe حقيقي
==============================================
شغّله على Windows:
    python build_exe.py

المتطلبات:
    pip install pyinstaller

النتيجة:
    dist/RansomShield/RansomShield.exe   ← البرنامج الكامل
    dist/RansomShield.exe                ← نسخة single file (أبطأ بالفتح)
"""

import os
import sys
import subprocess
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def check_pyinstaller():
    try:
        import PyInstaller
        print(f"[OK] PyInstaller موجود: v{PyInstaller.__version__}")
        return True
    except ImportError:
        print("[!] PyInstaller غير مثبّت — جاري التثبيت...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
        return True

def build():
    print("=" * 60)
    print("  بناء RansomShield.exe")
    print("=" * 60)

    check_pyinstaller()

    # مسار الملفات
    main_script  = os.path.join(BASE_DIR, "gui.py")
    models_dir   = os.path.join(BASE_DIR, "models")
    icon_path    = os.path.join(BASE_DIR, "icon.ico")   # اختياري

    # تأكد من وجود ملف النموذج
    if not os.path.exists(os.path.join(models_dir, "mlran_model.pkl")):
        print("[ERROR] النموذج غير موجود!")
        print("        شغّل أولاً: python step1_train_model.py")
        sys.exit(1)

    # ─── بناء أمر PyInstaller ─────────────────────────────
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=RansomShield",
        "--onedir",                    # مجلد واحد (أسرع بالفتح من --onefile)
        "--windowed",                  # بدون CMD window خلفية
        "--clean",                     # مسح build القديم
        "--noconfirm",                 # بدون أسئلة

        # ضمّ مجلد models كاملاً
        f"--add-data={models_dir};models",

        # ضمّ ملفات Python الأخرى
        f"--add-data={os.path.join(BASE_DIR, 'step2_feature_extractor.py')};.",
        f"--add-data={os.path.join(BASE_DIR, 'step3_monitor.py')};.",
        f"--add-data={os.path.join(BASE_DIR, 'step4_kill_chain.py')};.",
        f"--add-data={os.path.join(BASE_DIR, 'step5_main.py')};.",
        f"--add-data={os.path.join(BASE_DIR, 'step6_file_guard.py')};.",
        f"--add-data={os.path.join(BASE_DIR, 'step7_decompiler.py')};.",

        # المكتبات المخفية (PyInstaller ما يكتشفها تلقائياً)
        "--hidden-import=sklearn",
        "--hidden-import=sklearn.linear_model",
        "--hidden-import=sklearn.utils._cython_blas",
        "--hidden-import=sklearn.neighbors._partition_nodes",
        "--hidden-import=sklearn.tree._utils",
        "--hidden-import=joblib",
        "--hidden-import=psutil",
        "--hidden-import=numpy",
        "--hidden-import=pandas",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.font",
        "--hidden-import=watchdog",
        "--hidden-import=watchdog.observers",
        "--hidden-import=watchdog.events",

        # الأيقونة (اختياري — لو ما عندك icon.ico احذف السطرين)
        # f"--icon={icon_path}",

        # الملف الرئيسي
        main_script,
    ]

    print("\n[*] جاري البناء... (قد يأخذ 2-5 دقائق)")
    print("[*] الأمر:")
    print("    " + " ".join(cmd[2:5]) + " ...")

    result = subprocess.run(cmd, cwd=BASE_DIR)

    if result.returncode == 0:
        exe_path = os.path.join(BASE_DIR, "dist", "RansomShield", "RansomShield.exe")
        print("\n" + "=" * 60)
        print("  تم البناء بنجاح!")
        print(f"  الملف: dist\\RansomShield\\RansomShield.exe")
        if os.path.exists(exe_path):
            size = os.path.getsize(exe_path) / (1024*1024)
            print(f"  الحجم: {size:.1f} MB")
        print("=" * 60)
        print("\n  لتشغيل البرنامج:")
        print("  dist\\RansomShield\\RansomShield.exe")
        print("\n  لمشاركته: انسخ مجلد dist\\RansomShield كاملاً")
    else:
        print("\n[ERROR] فشل البناء")
        print("  جرّب: pip install --upgrade pyinstaller")

if __name__ == "__main__":
    build()
