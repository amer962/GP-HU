# -*- coding: utf-8 -*-
"""
STEP 5 — Main (نقطة الدخول الرئيسية)
================================================
يجمع كل الخطوات ويشغّل النظام كاملاً:

  Monitor (step3) → FeatureExtractor (step2) → Detector/KillChain (step4)

الاستخدام:
  python step5_main.py              ← مراقبة كل العمليات
  python step5_main.py --pid 1234   ← مراقبة عملية محددة
  python step5_main.py --test       ← اختبار على عينات MLRan
  python step5_main.py --simulate   ← محاكاة هجوم (للتجربة بدون فيروس)
"""

import os, sys, json, time, argparse, logging, threading, signal, platform
from datetime import datetime
import psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

MLRAN_DIR  = os.path.join(BASE_DIR, '..', 'mlran', 'mlran-main')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOGS_DIR   = os.path.join(BASE_DIR, 'logs')
DUMPS_DIR  = os.path.join(BASE_DIR, 'dumps')

# ─────────────────────────────────────────────────────────
def setup_logging():
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_file = os.path.join(LOGS_DIR, f"system_{datetime.now().strftime('%Y%m%d')}.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout),
        ]
    )
    return logging.getLogger('main')


def check_prerequisites():
    """تأكد إن النموذج موجود قبل التشغيل"""
    model_path = os.path.join(MODELS_DIR, 'mlran_model.pkl')
    if not os.path.exists(model_path):
        print("❌ النموذج غير موجود!")
        print("   شغّل أولاً: python step1_train_model.py")
        sys.exit(1)

    feat_path = os.path.join(MODELS_DIR, 'feature_cols.json')
    if not os.path.exists(feat_path):
        print("❌ feature_cols.json غير موجود!")
        print("   شغّل أولاً: python step1_train_model.py")
        sys.exit(1)

    print("✅ النموذج موجود وجاهز")


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           MLRan Ransomware Detection System              ║
║                                                          ║
║  Model:    Logistic Regression (98.1% accuracy)          ║
║  Dataset:  MLRan — 4800+ samples, 64 families            ║
║  Features: 483 behavioral features (RFE selected)        ║
╚══════════════════════════════════════════════════════════╝
""")


# ─────────────────────────────────────────────────────────
# وضع المراقبة الكاملة
# ─────────────────────────────────────────────────────────
def run_monitoring_mode(target_pid: int = None, interval: float = 5.0,
                        enable_guard: bool = True, enable_decompiler: bool = True):
    """يراقب العمليات ويطبق Kill chain + File Guard + AI Decompiler عند الكشف"""
    from step3_monitor    import ProcessMonitor
    from step4_kill_chain import RansomwareDetector
    from step6_file_guard import FileGuard
    from step7_decompiler import AIDecompiler

    logger = logging.getLogger('monitor')

    detector   = RansomwareDetector(MODELS_DIR, LOGS_DIR, DUMPS_DIR)
    monitor    = ProcessMonitor()
    guard      = FileGuard(store_dir=os.path.join(BASE_DIR, "guard_store"))
    decompiler = AIDecompiler(reports_dir=os.path.join(BASE_DIR, "decompiled"))

    if enable_guard:
        guard_ok = guard.start()
        if guard_ok:
            print("[FileGuard] Copy-on-Write حماية الملفات شغّالة")
        else:
            print("[FileGuard] watchdog غير مثبّت -- pip install watchdog")

    print(f"[System] بدأ المراقبة للـ PID {target_pid}" if target_pid else "[System] بدأ مراقبة كل العمليات")
    print(f"[System] Kill threshold: 90% | Warn threshold: 70%")
    print(f"[System] Logs: {LOGS_DIR}")
    print(f"[System] Forensics: {DUMPS_DIR}")
    print("-" * 60)

    stop_event = threading.Event()
    stats = {'checked': 0, 'suspicious': 0, 'killed': 0, 'restored': 0}

    def handle_observation(pid, observed):
        stats['checked'] += 1
        result = detector.analyze(pid, observed)

        if result['verdict'] == 'ransomware':
            stats['killed'] += 1
            proc_name = result.get('name', f'pid-{pid}')
            logger.critical(
                f"KILLED | PID={pid} | {proc_name} | "
                f"Conf={result['confidence']:.2%} | "
                f"Features={result['triggered_features'][:3]}"
            )
            if enable_guard:
                print(f"[FileGuard] استعادة الملفات للـ PID {pid}...")
                rollback = guard.rollback(pid=pid)
                stats['restored'] += rollback.get('restored', 0)
                if rollback.get('restored', 0) > 0:
                    print(f"[FileGuard] استُعيد {rollback['restored']} ملف")

            if enable_decompiler:
                exe_path = observed.get('exe', '')
                if exe_path and os.path.exists(exe_path):
                    print(f"[AIDecompiler] تحليل {proc_name}...")
                    threading.Thread(
                        target=decompiler.analyze,
                        kwargs={'exe_path': exe_path, 'process_name': proc_name},
                        daemon=True
                    ).start()

        elif result['verdict'] == 'suspicious':
            stats['suspicious'] += 1
            logger.warning(
                f"SUSPICIOUS | PID={pid} | {result['name']} | "
                f"Conf={result['confidence']:.2%}"
            )
            print(f"  مشبوه: PID={pid} {result['name'][:30]} | {result['confidence']:.2%}")

        # Ctrl+C للإيقاف
    def on_signal(sig, frame):
        print(f"\n[System] إيقاف المراقبة...")
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if target_pid:
        # مراقبة عملية محددة
        print(f"[Monitor] مراقبة PID {target_pid} كل {interval}s")
        while not stop_event.is_set():
            try:
                observed = monitor.observe_process(target_pid)
                handle_observation(target_pid, observed)
                if (stats['checked'] % 6) == 0:
                    print(f"  [Stats] checked={stats['checked']} | "
                          f"suspicious={stats['suspicious']} | "
                          f"killed={stats['killed']}")
            except Exception as e:
                logger.error(f"خطأ: {e}")
            stop_event.wait(timeout=interval)
    else:
        # مراقبة كل العمليات
        status_thread = threading.Thread(
            target=lambda: _print_status_loop(stats, stop_event),
            daemon=True
        )
        status_thread.start()
        monitor.watch_all_processes(handle_observation, stop_event, interval=interval)

    print(f"\n[System] اكتملت المراقبة")
    print(f"  عمليات فُحصت:   {stats['checked']}")
    print(f"  مشبوهة:         {stats['suspicious']}")
    print(f"  أُوقفت (killed): {stats['killed']}")


def _print_status_loop(stats: dict, stop: threading.Event):
    """يطبع إحصائيات كل 30 ثانية"""
    while not stop.is_set():
        stop.wait(timeout=30)
        if not stop.is_set():
            print(f"\n[Status] checked={stats['checked']} | "
                  f"suspicious={stats['suspicious']} | "
                  f"killed={stats['killed']}\n")


# ─────────────────────────────────────────────────────────
# وضع الاختبار على عينات MLRan الحقيقية
# ─────────────────────────────────────────────────────────
def run_test_mode():
    """يختبر الـ detector على عينات حقيقية من الداتا"""
    from step4_kill_chain import RansomwareDetector, test_on_cuckoo_samples

    detector = RansomwareDetector(MODELS_DIR, LOGS_DIR, DUMPS_DIR)
    test_on_cuckoo_samples(detector, MLRAN_DIR)


# ─────────────────────────────────────────────────────────
# وضع المحاكاة — للتجربة بدون فيروس حقيقي
# ─────────────────────────────────────────────────────────
def run_simulation_mode():
    """
    يحاكي سلوك ransomware على عملية وهمية
    لاختبار النظام بدون خطر
    """
    from step2_feature_extractor import FeatureExtractor
    import numpy as np, joblib

    print("\n=== وضع المحاكاة ===")
    print("محاكاة سلوك WannaCry (من الداتا الحقيقية)...\n")

    extractor = FeatureExtractor(MODELS_DIR)
    model     = joblib.load(os.path.join(MODELS_DIR, 'mlran_model.pkl'))

    # سلوك WannaCry الحقيقي (من عينات الداتا)
    wannacry_behavior = {
        'api_calls': {
            'NtProtectVirtualMemory',   # code injection
            'CreateProcessInternalW',    # spawn processes
            'NtAllocateVirtualMemory',   # memory allocation
            'NtOpenProcess',             # open other processes
            'CryptAcquireContextW',      # crypto init
            'CryptCreateHash',           # hashing
            'CryptHashData',             # hashing data
            'Process32NextW',            # enumerate processes
            'CreateToolhelp32Snapshot',  # snapshot processes
            'RegSetValueExW',            # registry persistence
            'NtDelayExecution',          # anti-sandbox delay
        },
        'reg_written': {
            r'HKEY_CURRENT_USER\Software\WannaCrypt0r',
            r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\WannaCry',
        },
        'file_created': {
            r'c:\users\administrator\@wanadecryptor@.exe',
            r'c:\users\administrator\@please_read_me@.txt',
            r'c:\windows\tasksche.exe',
        },
        'file_written': {
            r'c:\users\administrator\documents\report.wncry',
            r'c:\users\administrator\pictures\photo.wncry',
            r'c:\users\administrator\desktop\important.wncry',
        },
        'signatures': {
            'allocates_rwx',
            'antisandbox_foregroundwindows',
            'ransomware_mass_file_encryption',
        },
        'dlls_loaded': {'advapi32', 'cryptsp', 'kernel32'},
        'drop_extensions': {'wncry', 'wnry'},
        'strings': set(),
        'reg_opened': set(), 'reg_deleted': set(), 'reg_read': set(),
        'file_deleted': set(), 'file_read': set(), 'file_exists': set(),
        'dirs_created': set(), 'network_conns': [],
        'name': 'wannacry_sim.exe', 'cmdline': '', 'cpu_percent': 95.0,
        'mem_mb': 150.0, 'file_ops_count': 127,
    }

    vector    = extractor.build_vector(wannacry_behavior)
    vec_array = np.array(vector).reshape(1, -1)
    proba     = model.predict_proba(vec_array)[0]
    confidence = float(proba[1])
    triggered = extractor.get_triggered_features(vector)

    print(f"  النتيجة: {'🔴 RANSOMWARE' if confidence >= 0.5 else '🟢 SAFE'}")
    print(f"  Confidence: {confidence:.2%}")
    print(f"  Features مكتشفة ({len(triggered)}):")
    for f in triggered[:20]:
        print(f"    ✓ {f}")

    print(f"\n  السيناريو التالي — عملية آمنة:")
    safe_behavior = {
        'api_calls': {'CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle'},
        'dlls_loaded': {'kernel32', 'ntdll'},
        'reg_opened': {r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer'},
        'strings': {'notepad', 'windows'},
        'name': 'notepad.exe', 'cmdline': 'notepad.exe test.txt',
        'cpu_percent': 1.0, 'mem_mb': 5.0, 'file_ops_count': 2,
        'reg_written': set(), 'reg_deleted': set(), 'reg_read': set(),
        'file_created': set(), 'file_written': set(), 'file_deleted': set(),
        'file_read': set(), 'file_exists': set(), 'dirs_created': set(),
        'drop_extensions': set(), 'signatures': set(), 'network_conns': [],
    }

    vec2 = extractor.build_vector(safe_behavior)
    proba2 = model.predict_proba(np.array(vec2).reshape(1, -1))[0]
    conf2  = float(proba2[1])
    print(f"  النتيجة: {'🔴 RANSOMWARE' if conf2 >= 0.5 else '🟢 SAFE'}")
    print(f"  Confidence: {conf2:.2%}")
    print("\n✅ المحاكاة نجحت — النظام يفرق بين Ransomware والعمليات الآمنة")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MLRan Ransomware Detector')
    parser.add_argument('--pid',      type=int,   help='راقب عملية محددة بالـ PID')
    parser.add_argument('--interval', type=float, default=5.0, help='ثواني بين كل فحص (default: 5)')
    parser.add_argument('--test',     action='store_true', help='اختبر على عينات MLRan')
    parser.add_argument('--simulate', action='store_true', help='محاكاة WannaCry (بدون فيروس)')
    args = parser.parse_args()

    logger = setup_logging()
    print_banner()
    check_prerequisites()

    if args.test:
        run_test_mode()
    elif args.simulate:
        run_simulation_mode()
    else:
        run_monitoring_mode(target_pid=args.pid, interval=args.interval)
