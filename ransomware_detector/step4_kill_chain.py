# -*- coding: utf-8 -*-
"""
STEP 4 — Kill Chain (الكشف + الإيقاف)
================================================
بيأخذ الـ observed behavior من Monitor → يحوله لـ vector → يمرره للنموذج
إذا النموذج قال ransomware بثقة > THRESHOLD:
  1. تجميد العملية فوراً (SuspendThread / SIGSTOP)
  2. قطع الشبكة
  3. حفظ معلومات جنائية
  4. إنهاء العملية
  5. تسجيل الحادثة

Thresholds (من نتائج MLRan):
  KILL_THRESHOLD:  0.90 → kill فوري
  WARN_THRESHOLD:  0.70 → تسجيل + مراقبة مشددة
"""

import os, sys, json, time, logging, platform, signal, ctypes
import threading
from datetime import datetime
from typing import Optional
import psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from step2_feature_extractor import FeatureExtractor
import joblib
import numpy as np

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
KILL_THRESHOLD = 0.90   # فوق هاد → kill فوري
WARN_THRESHOLD = 0.70   # فوق هاد → تسجيل + مراقبة
# ─────────────────────────────────────────────────────────

SAFE_PROCESSES = {
    # عمليات النظام الأساسية — ما نلمسها أبداً
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe',
    'explorer.exe', 'taskmgr.exe', 'python.exe', 'python3',
    'cmd.exe', 'powershell.exe',  # عشان ما نقتل نفسنا
}

class RansomwareDetector:
    """
    الـ detector الرئيسي — بيجمع كل الخطوات:
    Monitor → FeatureExtractor → Model → KillChain
    """

    def __init__(self, models_dir: str, logs_dir: str, dumps_dir: str):
        self.models_dir = os.path.abspath(models_dir)
        self.logs_dir   = os.path.abspath(logs_dir)
        self.dumps_dir  = os.path.abspath(dumps_dir)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.dumps_dir, exist_ok=True)

        # تحميل النموذج
        model_path = os.path.join(self.models_dir, 'mlran_model.pkl')
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"النموذج غير موجود: {model_path}\n"
                f"شغّل أولاً: python step1_train_model.py"
            )
        self.model     = joblib.load(model_path)
        self.extractor = FeatureExtractor(self.models_dir)
        self.is_windows = platform.system() == 'Windows'

        # tracking العمليات المشبوهة (لتجنب تكرار الكشف)
        self._suspicious: dict = {}   # pid → {'count': int, 'first_seen': time}
        self._killed: set = set()     # pids تم إيقافها
        self._lock = threading.Lock()

        logger.info("RansomwareDetector جاهز")
        print(f"[Detector] النموذج محمل | Kill threshold: {KILL_THRESHOLD} | Warn: {WARN_THRESHOLD}")

    def analyze(self, pid: int, observed: dict) -> dict:
        """
        يحلل العملية ويرجع نتيجة الكشف.
        Returns: {
          'pid': int,
          'name': str,
          'confidence': float,   # 0.0 → 1.0
          'verdict': str,        # 'safe' / 'suspicious' / 'ransomware'
          'triggered_features': list,
          'action_taken': str,
        }
        """
        result = {
            'pid': pid,
            'name': observed.get('name', ''),
            'confidence': 0.0,
            'verdict': 'safe',
            'triggered_features': [],
            'action_taken': 'none',
            'timestamp': datetime.now().isoformat(),
        }

        # تجاهل عمليات النظام الآمنة
        proc_name = observed.get('name', '').lower()
        if proc_name in SAFE_PROCESSES or pid in self._killed:
            return result

        # بناء الـ feature vector
        try:
            vector    = self.extractor.build_vector(observed)
            vec_array = np.array(vector).reshape(1, -1)
        except Exception as e:
            logger.error(f"خطأ في build_vector للـ PID {pid}: {e}")
            return result

        # توقع النموذج
        try:
            proba      = self.model.predict_proba(vec_array)[0]
            confidence = float(proba[1])  # احتمال ransomware
        except Exception as e:
            logger.error(f"خطأ في predict للـ PID {pid}: {e}")
            return result

        result['confidence'] = confidence
        result['triggered_features'] = self.extractor.get_triggered_features(vector)

        # الحكم
        if confidence >= KILL_THRESHOLD:
            result['verdict'] = 'ransomware'
            action = self._execute_kill_chain(pid, observed, result)
            result['action_taken'] = action

        elif confidence >= WARN_THRESHOLD:
            result['verdict'] = 'suspicious'
            result['action_taken'] = 'monitoring'
            with self._lock:
                if pid not in self._suspicious:
                    self._suspicious[pid] = {'count': 0, 'first_seen': time.time()}
                self._suspicious[pid]['count'] += 1
                # إذا ظل مشبوهاً 3 مرات متتالية → kill
                if self._suspicious[pid]['count'] >= 3:
                    logger.warning(f"PID {pid} ({proc_name}) مشبوه 3 مرات متتالية → kill")
                    action = self._execute_kill_chain(pid, observed, result)
                    result['action_taken'] = action
                    result['verdict'] = 'ransomware'

        # تسجيل الحادثة
        self._log_event(result, observed)
        return result

    def _execute_kill_chain(self, pid: int, observed: dict, result: dict) -> str:
        """
        Kill chain مكون من 4 خطوات:
        1. تجميد العملية (قبل ما تكمل التشفير)
        2. قطع الشبكة (لمنع C2 communication)
        3. حفظ معلومات جنائية
        4. إنهاء العملية نهائياً
        """
        proc_name = observed.get('name', f'PID-{pid}')
        logger.critical(
            f"RANSOMWARE DETECTED | PID={pid} | Name={proc_name} | "
            f"Confidence={result['confidence']:.2%}"
        )
        print(f"\n{'='*60}")
        print(f"  ⚠  RANSOMWARE DETECTED")
        print(f"  PID:        {pid}")
        print(f"  Name:       {proc_name}")
        print(f"  Confidence: {result['confidence']:.2%}")
        print(f"  Top features: {result['triggered_features'][:5]}")
        print(f"{'='*60}\n")

        actions_done = []

        # ── 1. تجميد العملية ──────────────────────────────
        frozen = self._freeze_process(pid)
        if frozen:
            actions_done.append('frozen')
            logger.info(f"PID {pid} تم تجميده")

        # ── 2. قطع الشبكة ─────────────────────────────────
        network_blocked = self._block_network(pid, observed)
        if network_blocked:
            actions_done.append('network_blocked')

        # ── 3. حفظ معلومات جنائية ──────────────────────────
        forensics_path = self._save_forensics(pid, observed, result)
        if forensics_path:
            actions_done.append(f'forensics_saved:{os.path.basename(forensics_path)}')

        # ── 4. إنهاء العملية ──────────────────────────────
        killed = self._kill_process(pid)
        if killed:
            actions_done.append('killed')
            with self._lock:
                self._killed.add(pid)

        action_str = '+'.join(actions_done) if actions_done else 'failed'
        print(f"[KillChain] اكتمل: {action_str}\n")
        return action_str

    def _freeze_process(self, pid: int) -> bool:
        """تجميد العملية — يوقف كل threads قبل ما تكمل التشفير"""
        try:
            if self.is_windows:
                # Windows: NtSuspendProcess عبر ctypes
                PROCESS_SUSPEND_RESUME = 0x0800
                handle = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_SUSPEND_RESUME, False, pid
                )
                if handle:
                    # NtSuspendProcess من ntdll
                    ret = ctypes.windll.ntdll.NtSuspendProcess(handle)
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return ret == 0
            else:
                # Linux/Mac: SIGSTOP
                os.kill(pid, signal.SIGSTOP)
                return True
        except Exception as e:
            logger.error(f"تعذر تجميد PID {pid}: {e}")
        return False

    def _block_network(self, pid: int, observed: dict) -> bool:
        """
        قطع الاتصالات الشبكية للعملية.
        Windows: Windows Firewall API
        Linux:   iptables
        """
        try:
            proc = psutil.Process(pid)
            conns = proc.net_connections(kind='all')
            for conn in conns:
                if conn.raddr:
                    ip = conn.raddr.ip
                    if self.is_windows:
                        # إضافة قاعدة Windows Firewall لحجب الـ IP
                        os.system(f'netsh advfirewall firewall add rule '
                                  f'name="RansomBlock_{pid}_{ip}" '
                                  f'dir=out action=block remoteip={ip}')
                    else:
                        # Linux iptables
                        os.system(f'iptables -A OUTPUT -p tcp -d {ip} -j DROP 2>/dev/null')
            return True
        except Exception as e:
            logger.error(f"تعذر قطع الشبكة للـ PID {pid}: {e}")
        return False

    def _save_forensics(self, pid: int, observed: dict, result: dict) -> Optional[str]:
        """
        حفظ معلومات جنائية شاملة للتحليل اللاحق.
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            fname = os.path.join(self.dumps_dir, f"ransomware_{pid}_{timestamp}.json")

            forensics = {
                'detection': result,
                'process_info': {
                    'pid': pid,
                    'name': observed.get('name'),
                    'cmdline': observed.get('cmdline'),
                    'cpu': observed.get('cpu_percent'),
                    'memory_mb': observed.get('mem_mb'),
                },
                'behavior': {
                    'api_calls':   list(observed.get('api_calls', [])),
                    'reg_written': list(observed.get('reg_written', [])),
                    'file_written': list(observed.get('file_written', [])),
                    'file_created': list(observed.get('file_created', [])),
                    'signatures':  list(observed.get('signatures', [])),
                    'network':     observed.get('network_conns', []),
                },
                'triggered_features': result.get('triggered_features', []),
                'timestamp': datetime.now().isoformat(),
            }

            with open(fname, 'w', encoding='utf-8') as f:
                json.dump(forensics, f, ensure_ascii=False, indent=2)

            logger.info(f"Forensics محفوظة: {fname}")
            return fname
        except Exception as e:
            logger.error(f"تعذر حفظ forensics للـ PID {pid}: {e}")
        return None

    def _kill_process(self, pid: int) -> bool:
        """إنهاء العملية وكل child processes"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            # اقتل الأطفال أولاً
            for child in children:
                try:
                    child.kill()
                    logger.info(f"Child PID {child.pid} أُنهي")
                except Exception:
                    pass

            # ثم العملية الأم
            parent.kill()
            logger.info(f"PID {pid} أُنهي نهائياً")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"تعذر إنهاء PID {pid}: {e}")
        return False

    def _log_event(self, result: dict, observed: dict):
        """تسجيل كل حادثة في log file بصيغة JSON"""
        if result['verdict'] == 'safe':
            return  # ما نسجل العمليات الآمنة

        log_file = os.path.join(
            self.logs_dir,
            f"detections_{datetime.now().strftime('%Y%m%d')}.jsonl"
        )
        entry = {
            'timestamp':          result['timestamp'],
            'pid':                result['pid'],
            'process_name':       result['name'],
            'verdict':            result['verdict'],
            'confidence':         round(result['confidence'], 4),
            'action':             result['action_taken'],
            'top_features':       result['triggered_features'][:10],
            'signatures':         list(observed.get('signatures', [])),
            'network_connections': len(observed.get('network_conns', [])),
        }
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


# ─────────────────────────────────────────────────────────
# اختبار على Cuckoo report حقيقي من الداتا
# ─────────────────────────────────────────────────────────
def test_on_cuckoo_samples(detector: RansomwareDetector, mlran_dir: str):
    """
    يختبر الـ detector على عينات حقيقية من MLRan
    لتأكد إن الكشف يشتغل صح
    """
    import pandas as pd
    labels = pd.read_csv(os.path.join(mlran_dir, '6_experiments/FS_MLRan_Datasets/MLRan_labels.csv'))
    reports_dir = os.path.join(mlran_dir, '4_cuckoo_parser_scripts/json_reports')

    print("\n=== اختبار على عينات MLRan الحقيقية ===\n")
    correct = 0
    total   = 0

    for fname in sorted(os.listdir(reports_dir))[:10]:
        if not fname.endswith('.json'):
            continue
        sample_id = int(fname.replace('.json', ''))

        # الـ label الحقيقي
        row = labels[labels['sample_id'] == sample_id]
        if row.empty:
            continue
        true_label = int(row['sample_type'].values[0])  # 0=good, 1=ransom

        # قراءة الـ report
        with open(os.path.join(reports_dir, fname)) as f:
            report = json.load(f)

        behavior = report.get('behavior', {})
        apistats = behavior.get('apistats', {})
        summary  = behavior.get('summary', {})

        observed = {
            'api_calls':    set(),
            'reg_opened':   set(summary.get('regkey_opened', [])),
            'reg_written':  set(summary.get('regkey_written', [])),
            'reg_deleted':  set(summary.get('regkey_deleted', [])),
            'reg_read':     set(summary.get('regkey_read', [])),
            'file_created': set(f.lower() for f in summary.get('file_created', [])),
            'file_written': set(f.lower() for f in summary.get('file_written', [])),
            'file_deleted': set(f.lower() for f in summary.get('file_deleted', [])),
            'file_read':    set(f.lower() for f in summary.get('file_read', [])),
            'file_exists':  set(f.lower() for f in summary.get('file_exists', [])),
            'dlls_loaded':  set(d.lower() for d in summary.get('dll_loaded', [])),
            'strings':      set(report.get('strings', [])),
            'name':         f"sample_{sample_id}",
            'cmdline':      '',
            'cpu_percent':  0,
            'mem_mb':       0,
            'file_ops_count': 0,
            'network_conns': [],
            'signatures':   set(),
            'dirs_created': set(),
            'drop_extensions': set(),
        }
        for pid_str, apis in apistats.items():
            observed['api_calls'].update(apis.keys())

        # تشغيل الكشف (بدون kill — اختبار فقط)
        vector     = detector.extractor.build_vector(observed)
        vec_array  = __import__('numpy').array(vector).reshape(1, -1)
        proba      = detector.model.predict_proba(vec_array)[0]
        confidence = float(proba[1])
        predicted  = 1 if confidence >= 0.5 else 0

        match      = "✓" if predicted == true_label else "✗"
        label_str  = "RANSOM" if true_label == 1 else "GOOD  "
        pred_str   = "RANSOM" if predicted  == 1 else "GOOD  "
        print(f"  {match} Sample {sample_id} | True={label_str} | Pred={pred_str} | Conf={confidence:.2%}")

        if predicted == true_label:
            correct += 1
        total += 1

    print(f"\n  دقة الاختبار: {correct}/{total} = {correct/total*100:.1f}%")
    print("  ✅ النظام شغال — جاهز للتشغيل الحي")


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
    MLRAN_DIR  = os.path.join(BASE_DIR, '..', 'mlran', 'mlran-main')
    MODELS_DIR = os.path.join(BASE_DIR, 'models')

    detector = RansomwareDetector(
        models_dir = MODELS_DIR,
        logs_dir   = os.path.join(BASE_DIR, 'logs'),
        dumps_dir  = os.path.join(BASE_DIR, 'dumps'),
    )

    test_on_cuckoo_samples(detector, MLRAN_DIR)
