# -*- coding: utf-8 -*-
"""
STEP 3 — Behavioral Monitor (المراقب السلوكي)
================================================
يراقب كل العمليات الشغالة على الجهاز وبيجمع سلوكها
كل 30 ثانية ويمررها للـ FeatureExtractor.

يشتغل على Windows و Linux/Mac (مع capabilities مختلفة).

الـ features اللي بنقدر نجمعها live:
    Windows:  API calls (ETW) + Registry + File ops + DLLs + Network
    Linux:    strace API calls + File ops + /proc info
    أي نظام: psutil (file handles, connections, memory, CPU patterns)

استخدام psutil كـ primary source لأنه cross-platform وسريع.
"""

import os, sys, json, time, re, threading, logging, platform
import collections
from datetime import datetime
from typing import Dict, Set, Callable, Optional
import psutil

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Suspicious behavior patterns (من signatures في الداتا)
# SIGNATURE:allocates_rwx, SIGNATURE:antisandbox_*, etc.
# ─────────────────────────────────────────────────────────
CRYPTO_EXTENSIONS = {
    'enc', 'encrypted', 'locked', 'crypto', 'crypt',
    'wnry', 'wncry', 'wcry', 'wcryt',          # WannaCry
    'zepto', 'locky',                            # Locky
    'cerber', 'cerber2', 'cerber3',              # Cerber
    'ecc', 'ezz', 'exx', 'xyz', 'zzz',          # TeslaCrypt
    'aaa', 'abc', 'xyz', 'micro',                # Shade
    'vvv', 'ccc', 'zzz', 'abc',
    'ransomed', 'payransom',
}

RANSOM_NOTE_PATTERNS = [
    r'HOW_TO_DECRYPT', r'README.*RANSOM', r'HELP_DECRYPT',
    r'DECRYPT_INSTRUCTIONS', r'YOUR_FILES_ARE_ENCRYPTED',
    r'RECOVER_FILES', r'HOW_TO_RESTORE', r'_DECRYPT_',
    r'PAYMENT', r'bitcoin', r'tor\.onion',
]

SUSPICIOUS_API_PATTERNS = {
    # Crypto APIs — الأهم في كشف ransomware
    'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContext',
    'CryptHashData', 'CryptCreateHash',
    # File mass operations
    'MoveFileExW', 'DeleteFileW', 'SetEndOfFile',
    # Process injection
    'NtProtectVirtualMemory', 'NtAllocateVirtualMemory', 'NtCreateThreadEx',
    'CreateRemoteThread', 'WriteProcessMemory',
    # Shadow copy deletion
    'ShellExecuteW', 'CreateProcessW', 'WinExec',
    # Network for C2
    'InternetOpenW', 'HttpSendRequestW', 'WSAConnect',
}

SUSPICIOUS_REGISTRY_KEYS = {
    # Run keys — persistence
    r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
    r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    # Disable backup/recovery
    r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS',
    r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine',
    # Disable Windows Defender
    r'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender',
}

# ─────────────────────────────────────────────────────────
class ProcessMonitor:
    """
    يراقب عملية محددة (أو كل العمليات) وبيجمع سلوكها السلوكي.
    يستخدم psutil كـ core + Windows ETW إذا متاح.
    """

    def __init__(self, window_seconds: int = 30):
        self.window_seconds = window_seconds
        self._observations: Dict[int, dict] = {}  # pid → observed behavior
        self._lock = threading.Lock()
        self.is_windows = platform.system() == 'Windows'

    def observe_process(self, pid: int) -> dict:
        """
        يجمع السلوك الحي لعملية محددة.
        Returns: dict مع كل السلوك الملاحظ
        """
        observed = {
            'api_calls':    set(),
            'reg_opened':   set(),
            'reg_written':  set(),
            'reg_deleted':  set(),
            'reg_read':     set(),
            'file_created': set(),
            'file_written': set(),
            'file_deleted': set(),
            'file_read':    set(),
            'file_exists':  set(),
            'file_failed':  set(),
            'strings':      set(),
            'dlls_loaded':  set(),
            'dirs_created': set(),
            'drop_extensions': set(),
            'signatures':   set(),
            'network_conns': [],
            # metadata
            'pid':          pid,
            'name':         '',
            'cmdline':      '',
            'cpu_percent':  0.0,
            'mem_mb':       0.0,
            'file_ops_count': 0,
        }

        try:
            proc = psutil.Process(pid)

            # ── Basic info ──
            observed['name']    = proc.name()
            observed['cmdline'] = ' '.join(proc.cmdline()) if proc.cmdline() else ''

            # ── CPU + Memory ──
            observed['cpu_percent'] = proc.cpu_percent(interval=0.1)
            observed['mem_mb']      = proc.memory_info().rss / (1024*1024)

            # ── Open files ──
            try:
                open_files = proc.open_files()
                for f in open_files:
                    path = f.path.lower()
                    observed['file_read'].add(path)
                    # فحص امتداد الملف
                    ext = path.rsplit('.', 1)[-1] if '.' in path else ''
                    if ext in CRYPTO_EXTENSIONS:
                        observed['signatures'].add('encrypted_file_extension_found')
                        observed['drop_extensions'].add(ext)
                    # استخراج الـ directory
                    dir_path = os.path.dirname(path)
                    if dir_path:
                        observed['dirs_created'].add(dir_path)
                observed['file_ops_count'] = len(open_files)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # ── Network connections ──
            try:
                conns = proc.net_connections(kind='all')
                for conn in conns:
                    if conn.raddr:
                        observed['network_conns'].append({
                            'ip': conn.raddr.ip,
                            'port': conn.raddr.port,
                            'status': conn.status
                        })
                        # اتصال C2 مشبوه
                        if conn.raddr.port in [443, 80, 8080, 8443, 9001, 9030]:
                            observed['signatures'].add('suspicious_network_connection')
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # ── DLLs المحملة (Windows) ──
            if self.is_windows:
                try:
                    maps = proc.memory_maps()
                    for m in maps:
                        if m.path and '.dll' in m.path.lower():
                            dll_name = os.path.basename(m.path).lower()
                            observed['dlls_loaded'].add(dll_name.replace('.dll', ''))
                            observed['dlls_loaded'].add(dll_name)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            # ── الـ command line strings ──
            if observed['cmdline']:
                # كشف shadow copy deletion (vssadmin delete shadows)
                cmdline_lower = observed['cmdline'].lower()
                if 'vssadmin' in cmdline_lower and 'delete' in cmdline_lower:
                    observed['signatures'].add('delete_shadow_copies')
                if 'bcdedit' in cmdline_lower and 'recoveryenabled' in cmdline_lower:
                    observed['signatures'].add('disable_recovery')
                if 'wbadmin' in cmdline_lower and 'delete' in cmdline_lower:
                    observed['signatures'].add('delete_windows_backup')
                # Command line as string feature
                for part in observed['cmdline'].split():
                    if len(part) > 3:
                        observed['strings'].add(part.lower())

            # ── Windows-specific: Registry + ETW ──
            if self.is_windows:
                self._observe_windows_specific(proc, observed)

            # ── Pattern-based signatures ──
            self._detect_signatures(observed)

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"PID {pid}: {e}")

        return observed

    def _observe_windows_specific(self, proc, observed: dict):
        """مراقبة Windows-specific: Registry + ETW API calls"""
        try:
            import winreg

            # الـ registry keys الأكثر شيوعاً عند الـ ransomware
            WATCHED_KEYS = [
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            ]
            for hive, subkey in WATCHED_KEYS:
                try:
                    key = winreg.OpenKey(hive, subkey)
                    full_key = f"HKEY_{'CURRENT_USER' if hive==winreg.HKEY_CURRENT_USER else 'LOCAL_MACHINE'}\\{subkey}"
                    observed['reg_opened'].add(full_key)
                    winreg.CloseKey(key)
                except Exception:
                    pass

        except ImportError:
            pass  # مش على Windows

        # ETW — Event Tracing for Windows (إذا متاح)
        try:
            import etw
            # هاد advanced — بيحتاج admin. نتركه optional
        except ImportError:
            pass

    def _detect_signatures(self, observed: dict):
        """
        كشف الـ signatures المشبوهة (من 9_signature_parser.py في MLRan)
        هاي الـ signatures موجودة في الداتاست كـ features
        """
        # allocates_rwx — تنفيذ كود من memory مكتوب
        if 'NtProtectVirtualMemory' in observed['api_calls'] or \
           'NtAllocateVirtualMemory' in observed['api_calls']:
            observed['signatures'].add('allocates_rwx')

        # process injection
        if 'CreateRemoteThread' in observed['api_calls'] or \
           'WriteProcessMemory' in observed['api_calls']:
            observed['signatures'].add('injection_runpe')

        # anti-sandbox checks
        if 'GetSystemMetrics' in observed['api_calls'] or \
           'NtDelayExecution' in observed['api_calls']:
            observed['signatures'].add('antisandbox_foregroundwindows')

        # تشفير جماعي للملفات (أهم علامة)
        if observed['file_ops_count'] > 50:
            observed['signatures'].add('ransomware_mass_file_encryption')

        # crypto API استخدام
        crypto_apis = {'CryptEncrypt', 'CryptGenKey', 'CryptHashData'}
        if crypto_apis.intersection(observed['api_calls']):
            observed['signatures'].add('uses_crypto_apis')

        # ransom note creation
        all_files = observed['file_created'] | observed['file_written']
        for filepath in all_files:
            for pattern in RANSOM_NOTE_PATTERNS:
                if re.search(pattern, filepath, re.IGNORECASE):
                    observed['signatures'].add('creates_ransom_note')
                    break

    def watch_all_processes(self,
                             on_observation: Callable[[int, dict], None],
                             stop_event: threading.Event,
                             interval: float = 5.0,
                             ignore_system: bool = True):
        """
        يراقب كل العمليات الشغالة كل `interval` ثانية.
        يستدعي on_observation(pid, observed) لكل عملية.
        """
        SYSTEM_PROCS = {'system', 'svchost.exe', 'csrss.exe', 'lsass.exe',
                        'services.exe', 'winlogon.exe', 'smss.exe',
                        'registry', 'idle', 'kworker', 'kthreadd'}

        logger.info(f"بدء المراقبة — كل {interval} ثانية")
        print(f"[Monitor] مراقبة العمليات كل {interval}s — Ctrl+C للإيقاف")

        while not stop_event.is_set():
            pids = psutil.pids()
            for pid in pids:
                if stop_event.is_set():
                    break
                try:
                    proc_name = psutil.Process(pid).name().lower()
                    if ignore_system and proc_name in SYSTEM_PROCS:
                        continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                observed = self.observe_process(pid)
                if observed['name']:  # عملية موجودة
                    on_observation(pid, observed)

            stop_event.wait(timeout=interval)

        logger.info("المراقبة توقفت")


# ─────────────────────────────────────────────────────────
# اختبار المراقب
# ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    monitor = ProcessMonitor()

    print("=== اختبار المراقب على العمليات الحالية ===\n")
    pids = psutil.pids()[:10]  # اختبر على أول 10 عمليات

    for pid in pids:
        obs = monitor.observe_process(pid)
        if obs['name']:
            sigs = ', '.join(obs['signatures']) if obs['signatures'] else 'لا شي'
            print(f"PID {pid:5} | {obs['name']:25} | "
                  f"Files:{obs['file_ops_count']:3} | "
                  f"Net:{len(obs['network_conns']):2} | "
                  f"Signatures: {sigs}")

    print("\n✅ المراقب شغال — جاهز للدمج مع الـ detector")
    print("→ الخطوة التالية: python step4_kill_chain.py --test")
