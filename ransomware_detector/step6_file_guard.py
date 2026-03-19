# -*- coding: utf-8 -*-
"""
STEP 6 — File Guard (Copy-on-Write + Rollback)
================================================
الفكرة:
  قبل ما أي عملية مشبوهة تكتب على ملف:
    1. احفظ نسخة أصلية في مجلد مخفي
    2. خزّن pointer في RAM { path -> backup_path }
    3. انتظر قرار النموذج (5-30 ثانية)
    4a. إذا آمن  → احذف النسخة الاحتياطية
    4b. إذا رانسوم وير → استعد كل الملفات الأصلية (Rollback)

النتيجة: حتى لو شفّر الرانسوم وير ملفات قبل ما نكشفه،
         نقدر نرجع كل شي للحالة الأصلية بثانية واحدة.
"""

import os
import sys
import shutil
import hashlib
import logging
import threading
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Set, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# المجلدات اللي نراقبها
# ─────────────────────────────────────────────────────────
DEFAULT_WATCHED_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Pictures"),
    os.path.expanduser("~/Downloads"),
    "C:\\Users",
]

# الامتدادات المهمة اللي نحميها
PROTECTED_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.txt', '.jpg', '.jpeg', '.png', '.bmp',
    '.mp4', '.avi', '.mov', '.zip', '.rar', '.7z',
    '.py',  '.js',  '.html', '.css', '.json', '.xml',
    '.db',  '.sql', '.csv',  '.psd', '.ai',  '.svg',
}

# ─────────────────────────────────────────────────────────
class FileBackupStore:
    """
    يخزّن النسخ الاحتياطية في RAM وعلى الديسك.

    البنية في RAM:
        _backups = {
            "C:\\Users\\user\\doc.docx": {
                "backup_path": "C:\\...\\guard\\abc123.bak",
                "original_path": "C:\\Users\\user\\doc.docx",
                "size": 4096,
                "timestamp": 1710000000.0,
                "pid": 1234,        # العملية اللي استدعت الحفظ
                "confirmed": False  # هل تأكد إنها ransomware؟
            }
        }
    """

    def __init__(self, store_dir: str):
        self.store_dir = os.path.abspath(store_dir)
        os.makedirs(self.store_dir, exist_ok=True)
        # إخفاء المجلد على Windows
        try:
            import subprocess
            subprocess.run(
                ['attrib', '+H', '+S', self.store_dir],
                capture_output=True
            )
        except Exception:
            pass

        self._backups: Dict[str, dict] = {}   # path → backup info
        self._lock    = threading.RLock()
        self._stats   = {'saved': 0, 'restored': 0, 'discarded': 0}

        logger.info(f"FileBackupStore جاهز: {self.store_dir}")

    def save(self, original_path: str, pid: int = 0) -> Optional[str]:
        """
        احفظ نسخة من الملف قبل أي تعديل.
        يُستدعى عند أول write على ملف من عملية مشبوهة.
        """
        original_path = os.path.abspath(original_path)

        with self._lock:
            # إذا محفوظ مسبقاً ما نحفظه مرة ثانية (نحمي النسخة الأصلية الأولى)
            if original_path in self._backups:
                return self._backups[original_path]['backup_path']

            if not os.path.isfile(original_path):
                return None

            # إنشاء اسم فريد للنسخة الاحتياطية
            h = hashlib.md5(original_path.encode()).hexdigest()[:12]
            ext = Path(original_path).suffix
            backup_name = f"{h}_{int(time.time())}{ext}.bak"
            backup_path = os.path.join(self.store_dir, backup_name)

            try:
                shutil.copy2(original_path, backup_path)
                size = os.path.getsize(original_path)

                self._backups[original_path] = {
                    'backup_path':   backup_path,
                    'original_path': original_path,
                    'size':          size,
                    'timestamp':     time.time(),
                    'pid':           pid,
                    'confirmed':     False,
                }
                self._stats['saved'] += 1
                logger.debug(f"Backed up: {os.path.basename(original_path)} ({size} bytes)")
                return backup_path

            except Exception as e:
                logger.error(f"فشل حفظ {original_path}: {e}")
                return None

    def rollback_all(self, pid: int = None) -> dict:
        """
        استعد كل الملفات المحفوظة.
        إذا pid محدد → فقط الملفات اللي لمستها هاي العملية.
        """
        with self._lock:
            targets = {
                path: info for path, info in self._backups.items()
                if pid is None or info.get('pid') == pid
            }

        restored = []
        failed   = []

        for original_path, info in targets.items():
            backup_path = info['backup_path']
            try:
                if os.path.exists(backup_path):
                    # استعادة الملف الأصلي
                    shutil.copy2(backup_path, original_path)
                    restored.append(original_path)
                    self._stats['restored'] += 1
                    logger.info(f"Restored: {os.path.basename(original_path)}")
            except Exception as e:
                failed.append(original_path)
                logger.error(f"فشل استعادة {original_path}: {e}")

        # احذف من الـ RAM بعد الاستعادة
        with self._lock:
            for path in list(targets.keys()):
                del self._backups[path]

        return {
            'restored': len(restored),
            'failed':   len(failed),
            'files':    restored,
        }

    def discard(self, pid: int = None):
        """
        العملية آمنة — احذف النسخ الاحتياطية اللي ما نحتاجها.
        """
        with self._lock:
            targets = [
                path for path, info in self._backups.items()
                if pid is None or info.get('pid') == pid
            ]

        deleted = 0
        for path in targets:
            info = self._backups.get(path)
            if info:
                try:
                    if os.path.exists(info['backup_path']):
                        os.remove(info['backup_path'])
                    del self._backups[path]
                    deleted += 1
                    self._stats['discarded'] += 1
                except Exception:
                    pass

        logger.debug(f"Discarded {deleted} backups for pid={pid}")

    def get_stats(self) -> dict:
        with self._lock:
            return {
                **self._stats,
                'active_backups': len(self._backups),
                'store_dir': self.store_dir,
            }

    def get_backed_up_files(self, pid: int = None) -> list:
        with self._lock:
            return [
                info for info in self._backups.values()
                if pid is None or info.get('pid') == pid
            ]


# ─────────────────────────────────────────────────────────
class SuspiciousWriteHandler(FileSystemEventHandler):
    """
    Watchdog event handler — يراقب كتابات الملفات.
    عند أي write على ملف محمي → يحفظ نسخة فوراً.
    """

    def __init__(self, store: FileBackupStore,
                 suspicious_pids: Set[int],
                 on_suspicious_write=None):
        super().__init__()
        self.store              = store
        self.suspicious_pids    = suspicious_pids   # set مشترك مع الـ detector
        self.on_suspicious_write = on_suspicious_write
        self._seen_events: Set[str] = set()

    def _should_protect(self, path: str) -> bool:
        ext = Path(path).suffix.lower()
        return ext in PROTECTED_EXTENSIONS

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_write(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_write(event.src_path)

    def _handle_write(self, path: str):
        if not self._should_protect(path):
            return

        # تجنب معالجة نفس الحدث مرتين
        key = f"{path}_{int(time.time())}"
        if key in self._seen_events:
            return
        self._seen_events.add(key)
        # نظّف الـ cache القديم
        if len(self._seen_events) > 1000:
            self._seen_events.clear()

        # احفظ نسخة احتياطية — نحتاجها بغض النظر عن مصدر الكتابة
        # (أي عملية قد تكون مشبوهة في المستقبل)
        self.store.save(path, pid=0)

        if self.on_suspicious_write:
            self.on_suspicious_write(path)


# ─────────────────────────────────────────────────────────
class FileGuard:
    """
    الواجهة الرئيسية — يجمع Store + Watchdog.

    الاستخدام:
        guard = FileGuard("guard_store")
        guard.start()

        # عند كشف رانسوم وير:
        result = guard.rollback(pid=1234)
        print(f"استُعيد {result['restored']} ملف")

        # عند التأكد إنه آمن:
        guard.confirm_safe(pid=1234)
    """

    def __init__(self, store_dir: str = "guard_store",
                 watched_dirs: list = None):
        self.store       = FileBackupStore(store_dir)
        self.watched_dirs = watched_dirs or DEFAULT_WATCHED_DIRS
        self._observer   = None
        self._running    = False

    def start(self):
        if not WATCHDOG_AVAILABLE:
            logger.warning("watchdog غير مثبّت — pip install watchdog")
            logger.warning("الـ File Guard لن يعمل")
            return False

        handler = SuspiciousWriteHandler(
            store=self.store,
            suspicious_pids=set(),
            on_suspicious_write=self._on_write
        )

        self._observer = Observer()
        mounted = 0
        for d in self.watched_dirs:
            if os.path.isdir(d):
                try:
                    self._observer.schedule(handler, d, recursive=True)
                    mounted += 1
                    logger.info(f"File Guard يراقب: {d}")
                except Exception as e:
                    logger.warning(f"ما قدر يراقب {d}: {e}")

        if mounted == 0:
            logger.warning("File Guard: لا يوجد مجلد للمراقبة")
            return False

        self._observer.start()
        self._running = True
        logger.info(f"File Guard شغّال — يراقب {mounted} مجلد")
        print(f"[FileGuard] يراقب {mounted} مجلد | Store: {self.store.store_dir}")
        return True

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self._running = False

    def rollback(self, pid: int = None) -> dict:
        """
        رانسوم وير اكتُشف → استعد كل الملفات اللي لمسها.
        """
        backed = self.store.get_backed_up_files(pid)
        print(f"\n[FileGuard] بدء الاستعادة — {len(backed)} ملف محفوظ...")

        result = self.store.rollback_all(pid)

        print(f"[FileGuard] ✅ استُعيد {result['restored']} ملف")
        if result['failed']:
            print(f"[FileGuard] ⚠  فشل استعادة {result['failed']} ملف")
        return result

    def confirm_safe(self, pid: int):
        """
        العملية آمنة → احذف النسخ الاحتياطية غير المطلوبة.
        """
        self.store.discard(pid)

    def get_status(self) -> dict:
        stats = self.store.get_stats()
        stats['running'] = self._running
        return stats

    def _on_write(self, path: str):
        logger.debug(f"File write intercepted: {os.path.basename(path)}")
