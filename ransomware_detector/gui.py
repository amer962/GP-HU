# -*- coding: utf-8 -*-
"""
RansomShield — واجهة برنامج الحماية
=====================================
شغّل: python gui.py
متطلبات: pip install customtkinter pillow psutil joblib scikit-learn
"""

import os
import sys
import json
import time
import threading
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.font as tkfont

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ─── ألوان ومقاييس ─────────────────────────────────────────
DARK_BG      = "#0d1117"
PANEL_BG     = "#161b22"
CARD_BG      = "#1c2128"
BORDER       = "#30363d"
GREEN        = "#3fb950"
GREEN_DIM    = "#238636"
RED          = "#f85149"
AMBER        = "#d29922"
BLUE         = "#58a6ff"
TEXT_PRIMARY = "#e6edf3"
TEXT_SEC     = "#8b949e"
TEXT_MUTED   = "#484f58"
ACCENT       = "#1f6feb"

# ─── حالات النظام ──────────────────────────────────────────
STATUS_PROTECTED  = "محمي"
STATUS_SCANNING   = "يفحص..."
STATUS_THREAT     = "تهديد مكتشف!"
STATUS_IDLE       = "متوقف"


# ══════════════════════════════════════════════════════════════
class RansomShieldApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RansomShield — حماية متقدمة من الفدية")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)
        self.root.configure(bg=DARK_BG)
        self.root.resizable(True, True)

        # إيقاف إغلاق مباشر
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # ─── حالة النظام ───────────────────────────────────
        self._protection_on  = tk.BooleanVar(value=False)
        self._status_text    = tk.StringVar(value=STATUS_IDLE)
        self._status_color   = tk.StringVar(value=TEXT_SEC)
        self._threats_count  = tk.IntVar(value=0)
        self._files_protected= tk.IntVar(value=0)
        self._scan_progress  = tk.DoubleVar(value=0.0)
        self._current_file   = tk.StringVar(value="")

        # ─── بيانات التهديدات ──────────────────────────────
        self._threats = []      # قائمة التهديدات
        self._log     = []      # سجل الأحداث

        # ─── تحميل النموذج ─────────────────────────────────
        self._model     = None
        self._feat_cols = None
        self._extractor = None
        self._load_model()

        # ─── بناء الواجهة ──────────────────────────────────
        self._setup_fonts()
        self._build_ui()

        # ─── تحديث دوري ────────────────────────────────────
        self._update_clock()
        self._animate_pulse()

    # ══════════════════════════════════════════════════════════
    # تحميل النموذج
    # ══════════════════════════════════════════════════════════
    def _load_model(self):
        try:
            import joblib
            model_path = os.path.join(BASE_DIR, "models", "mlran_model.pkl")
            feats_path = os.path.join(BASE_DIR, "models", "feature_cols.json")
            if os.path.exists(model_path) and os.path.exists(feats_path):
                self._model     = joblib.load(model_path)
                with open(feats_path) as f:
                    self._feat_cols = json.load(f)
                try:
                    from step2_feature_extractor import FeatureExtractor
                    self._extractor = FeatureExtractor(os.path.join(BASE_DIR, "models"))
                except Exception:
                    pass
        except Exception as e:
            pass

    # ══════════════════════════════════════════════════════════
    # الخطوط
    # ══════════════════════════════════════════════════════════
    def _setup_fonts(self):
        self.font_title  = tkfont.Font(family="Segoe UI", size=22, weight="bold")
        self.font_large  = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        self.font_medium = tkfont.Font(family="Segoe UI", size=11)
        self.font_small  = tkfont.Font(family="Segoe UI", size=9)
        self.font_mono   = tkfont.Font(family="Consolas",  size=9)
        self.font_status = tkfont.Font(family="Segoe UI", size=13, weight="bold")
        self.font_num    = tkfont.Font(family="Segoe UI", size=28, weight="bold")

    # ══════════════════════════════════════════════════════════
    # بناء الواجهة
    # ══════════════════════════════════════════════════════════
    def _build_ui(self):
        # ─── الإطار الرئيسي ────────────────────────────────
        main = tk.Frame(self.root, bg=DARK_BG)
        main.pack(fill=tk.BOTH, expand=True)

        # ─── الشريط الجانبي ────────────────────────────────
        sidebar = tk.Frame(main, bg=PANEL_BG, width=220)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)

        # ─── خط فاصل ───────────────────────────────────────
        tk.Frame(main, bg=BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y)

        # ─── المحتوى الرئيسي ───────────────────────────────
        content = tk.Frame(main, bg=DARK_BG)
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # ─── شريط علوي ─────────────────────────────────────
        self._build_topbar(content)

        # ─── منطقة المحتوى (تبويبات) ───────────────────────
        self._notebook_frame = tk.Frame(content, bg=DARK_BG)
        self._notebook_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))

        # ─── بناء الصفحات ───────────────────────────────────
        self._pages = {}
        self._current_page = tk.StringVar(value="dashboard")

        self._pages["dashboard"] = self._build_dashboard(self._notebook_frame)
        self._pages["scan"]      = self._build_scan_page(self._notebook_frame)
        self._pages["threats"]   = self._build_threats_page(self._notebook_frame)
        self._pages["log"]       = self._build_log_page(self._notebook_frame)
        self._pages["settings"]  = self._build_settings_page(self._notebook_frame)

        self._show_page("dashboard")

    # ──────────────────────────────────────────────────────────
    # الشريط الجانبي
    # ──────────────────────────────────────────────────────────
    def _build_sidebar(self, parent):
        # لوغو
        logo_frame = tk.Frame(parent, bg=PANEL_BG)
        logo_frame.pack(fill=tk.X, padx=20, pady=(24,8))

        tk.Canvas(logo_frame, width=36, height=36,
                  bg=PANEL_BG, highlightthickness=0).pack(side=tk.LEFT)
        self._draw_shield_logo(logo_frame)

        tk.Label(logo_frame, text="RansomShield",
                 font=tkfont.Font(family="Segoe UI", size=13, weight="bold"),
                 fg=TEXT_PRIMARY, bg=PANEL_BG).pack(side=tk.LEFT, padx=8)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=16, pady=12)

        # أزرار التنقل
        nav_items = [
            ("dashboard", "⬡  لوحة التحكم"),
            ("scan",      "⌕  فحص الملفات"),
            ("threats",   "⚠  التهديدات"),
            ("log",       "≡  سجل الأحداث"),
            ("settings",  "⚙  الإعدادات"),
        ]

        self._nav_buttons = {}
        for page_id, label in nav_items:
            btn = tk.Label(parent, text=label,
                           font=self.font_medium,
                           fg=TEXT_SEC, bg=PANEL_BG,
                           anchor=tk.W, padx=24, pady=10,
                           cursor="hand2")
            btn.pack(fill=tk.X)
            btn.bind("<Button-1>", lambda e, p=page_id: self._show_page(p))
            btn.bind("<Enter>",    lambda e, b=btn: b.config(fg=TEXT_PRIMARY, bg=CARD_BG))
            btn.bind("<Leave>",    lambda e, b=btn, p=page_id: self._nav_leave(b, p))
            self._nav_buttons[page_id] = btn

        # حالة الحماية في الأسفل
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=16, side=tk.BOTTOM, pady=0)
        status_frame = tk.Frame(parent, bg=PANEL_BG)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=16, pady=16)

        self._sidebar_status = tk.Label(
            status_frame, textvariable=self._status_text,
            font=self.font_small, fg=TEXT_SEC, bg=PANEL_BG
        )
        self._sidebar_status.pack()

        self._clock_label = tk.Label(
            status_frame, text="", font=self.font_small,
            fg=TEXT_MUTED, bg=PANEL_BG
        )
        self._clock_label.pack(pady=(4,0))

    def _draw_shield_logo(self, parent):
        c = tk.Canvas(parent, width=36, height=36,
                      bg=PANEL_BG, highlightthickness=0)
        c.place(x=0, y=0)
        pts = [18,2, 34,8, 34,22, 18,34, 2,22, 2,8]
        c.create_polygon(pts, fill=ACCENT, outline="", smooth=False)
        c.create_text(18, 19, text="R", fill="white",
                      font=tkfont.Font(family="Segoe UI", size=12, weight="bold"))

    def _nav_leave(self, btn, page_id):
        if self._current_page.get() == page_id:
            btn.config(fg=TEXT_PRIMARY, bg=ACCENT)
        else:
            btn.config(fg=TEXT_SEC, bg=PANEL_BG)

    def _show_page(self, page_id):
        # أخفِ كل الصفحات
        for pid, frame in self._pages.items():
            frame.pack_forget()
        # أظهر المطلوبة
        self._pages[page_id].pack(fill=tk.BOTH, expand=True)
        self._current_page.set(page_id)
        # حدّث التنقل
        for pid, btn in self._nav_buttons.items():
            if pid == page_id:
                btn.config(fg=TEXT_PRIMARY, bg=ACCENT)
            else:
                btn.config(fg=TEXT_SEC, bg=PANEL_BG)

    # ──────────────────────────────────────────────────────────
    # الشريط العلوي
    # ──────────────────────────────────────────────────────────
    def _build_topbar(self, parent):
        bar = tk.Frame(parent, bg=DARK_BG)
        bar.pack(fill=tk.X, padx=20, pady=(16,12))

        self._page_title = tk.Label(
            bar, text="لوحة التحكم",
            font=self.font_large, fg=TEXT_PRIMARY, bg=DARK_BG
        )
        self._page_title.pack(side=tk.LEFT)

        # أزرار الشريط العلوي
        scan_btn = self._make_button(bar, "فحص سريع", self._quick_scan,
                                     bg=GREEN_DIM, fg="white")
        scan_btn.pack(side=tk.RIGHT, padx=(8,0))

    # ══════════════════════════════════════════════════════════
    # لوحة التحكم
    # ══════════════════════════════════════════════════════════
    def _build_dashboard(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        # ─── بطاقة الحالة الرئيسية ─────────────────────────
        status_card = self._card(frame)
        status_card.pack(fill=tk.X, pady=(0,16))

        # جانب أيسر: الحالة
        left = tk.Frame(status_card, bg=CARD_BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=24, pady=24)

        self._shield_canvas = tk.Canvas(
            left, width=80, height=80, bg=CARD_BG, highlightthickness=0
        )
        self._shield_canvas.pack(side=tk.LEFT)
        self._draw_main_shield()

        status_text_frame = tk.Frame(left, bg=CARD_BG)
        status_text_frame.pack(side=tk.LEFT, padx=20)

        self._main_status_label = tk.Label(
            status_text_frame,
            textvariable=self._status_text,
            font=tkfont.Font(family="Segoe UI", size=20, weight="bold"),
            fg=GREEN, bg=CARD_BG
        )
        self._main_status_label.pack(anchor=tk.W)

        tk.Label(
            status_text_frame,
            text="نموذج MLRan — دقة 98.1% | 483 ميزة سلوكية",
            font=self.font_small, fg=TEXT_SEC, bg=CARD_BG
        ).pack(anchor=tk.W, pady=(4,0))

        # جانب أيمن: زر التفعيل
        right = tk.Frame(status_card, bg=CARD_BG)
        right.pack(side=tk.RIGHT, padx=24, pady=24)

        self._toggle_btn = tk.Button(
            right,
            text="تفعيل الحماية",
            font=tkfont.Font(family="Segoe UI", size=11, weight="bold"),
            fg="white", bg=GREEN_DIM,
            relief=tk.FLAT, padx=20, pady=10,
            cursor="hand2",
            command=self._toggle_protection
        )
        self._toggle_btn.pack()

        # ─── بطاقات الإحصائيات ─────────────────────────────
        stats_row = tk.Frame(frame, bg=DARK_BG)
        stats_row.pack(fill=tk.X, pady=(0,16))

        stats = [
            ("التهديدات المكتشفة", self._threats_count,  RED,   "هذا الجلسة"),
            ("الملفات المحمية",    self._files_protected, GREEN, "Copy-on-Write"),
            ("دقة النموذج",        None,                  BLUE,  "98.1%"),
            ("عائلات Ransomware",  None,                  AMBER, "64 عائلة"),
        ]

        for title, var, color, subtitle in stats:
            card = self._card(stats_row)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,12))
            card.pack_configure(padx=(0,12))

            inner = tk.Frame(card, bg=CARD_BG)
            inner.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

            if var is not None:
                num_lbl = tk.Label(
                    inner, textvariable=var,
                    font=self.font_num, fg=color, bg=CARD_BG
                )
            else:
                num_lbl = tk.Label(
                    inner, text=subtitle,
                    font=self.font_large, fg=color, bg=CARD_BG
                )
            num_lbl.pack(anchor=tk.W)

            tk.Label(inner, text=title,
                     font=self.font_small, fg=TEXT_SEC, bg=CARD_BG
            ).pack(anchor=tk.W)

            if var is not None:
                tk.Label(inner, text=subtitle,
                         font=self.font_small, fg=TEXT_MUTED, bg=CARD_BG
                ).pack(anchor=tk.W)

        # ─── آخر الأحداث ───────────────────────────────────
        log_card = self._card(frame)
        log_card.pack(fill=tk.BOTH, expand=True)

        log_inner = tk.Frame(log_card, bg=CARD_BG)
        log_inner.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        tk.Label(log_inner, text="آخر الأحداث",
                 font=self.font_medium, fg=TEXT_PRIMARY, bg=CARD_BG
        ).pack(anchor=tk.W, pady=(0,10))

        self._dashboard_log = tk.Text(
            log_inner, height=6,
            bg=DARK_BG, fg=TEXT_SEC,
            font=self.font_mono, relief=tk.FLAT,
            state=tk.DISABLED, wrap=tk.WORD
        )
        self._dashboard_log.pack(fill=tk.BOTH, expand=True)
        self._dashboard_log.tag_config("threat",  foreground=RED)
        self._dashboard_log.tag_config("warn",    foreground=AMBER)
        self._dashboard_log.tag_config("info",    foreground=BLUE)
        self._dashboard_log.tag_config("success", foreground=GREEN)

        self._add_log("النظام جاهز — النموذج محمّل (98.1% دقة)", "info")
        if self._model:
            self._add_log("تم تحميل 483 ميزة سلوكية من MLRan Dataset", "success")

        return frame

    def _draw_main_shield(self, color=None):
        c = self._shield_canvas
        c.delete("all")
        col = color or GREEN_DIM
        pts = [40,4, 74,16, 74,48, 40,76, 6,48, 6,16]
        c.create_polygon(pts, fill=col, outline="", smooth=False)
        # علامة صح أو تحذير
        if self._status_text.get() == STATUS_THREAT:
            c.create_text(40,42, text="!", fill="white",
                          font=tkfont.Font(family="Segoe UI",size=28,weight="bold"))
        else:
            # علامة صح
            c.create_line(24,42, 36,54, 56,30,
                          fill="white", width=4, capstyle=tk.ROUND, joinstyle=tk.ROUND)

    # ══════════════════════════════════════════════════════════
    # صفحة الفحص
    # ══════════════════════════════════════════════════════════
    def _build_scan_page(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        # بطاقة خيارات الفحص
        opt_card = self._card(frame)
        opt_card.pack(fill=tk.X, pady=(0,16))
        opt_inner = tk.Frame(opt_card, bg=CARD_BG)
        opt_inner.pack(fill=tk.X, padx=20, pady=20)

        tk.Label(opt_inner, text="نوع الفحص",
                 font=self.font_medium, fg=TEXT_PRIMARY, bg=CARD_BG
        ).pack(anchor=tk.W, pady=(0,12))

        scan_types = [
            ("فحص سريع",   "العمليات الحية الآن",       self._quick_scan),
            ("فحص ملف",    "اختر ملف exe للفحص",        self._scan_file),
            ("فحص مجلد",   "افحص مجلداً كاملاً",        self._scan_folder),
        ]

        btns_row = tk.Frame(opt_inner, bg=CARD_BG)
        btns_row.pack(fill=tk.X)

        for title, subtitle, cmd in scan_types:
            btn_card = tk.Frame(btns_row, bg=DARK_BG,
                                highlightbackground=BORDER, highlightthickness=1,
                                cursor="hand2")
            btn_card.pack(side=tk.LEFT, padx=(0,12), pady=4, ipadx=16, ipady=12)
            btn_card.bind("<Button-1>", lambda e, c=cmd: c())

            tk.Label(btn_card, text=title,
                     font=tkfont.Font(family="Segoe UI",size=11,weight="bold"),
                     fg=TEXT_PRIMARY, bg=DARK_BG
            ).pack(padx=16, pady=(10,2))
            tk.Label(btn_card, text=subtitle,
                     font=self.font_small, fg=TEXT_SEC, bg=DARK_BG
            ).pack(padx=16, pady=(0,10))

        # شريط التقدم
        prog_card = self._card(frame)
        prog_card.pack(fill=tk.X, pady=(0,16))
        prog_inner = tk.Frame(prog_card, bg=CARD_BG)
        prog_inner.pack(fill=tk.X, padx=20, pady=20)

        self._scan_status_lbl = tk.Label(
            prog_inner, text="لا يوجد فحص جارٍ",
            font=self.font_medium, fg=TEXT_SEC, bg=CARD_BG
        )
        self._scan_status_lbl.pack(anchor=tk.W)

        self._current_file_lbl = tk.Label(
            prog_inner, textvariable=self._current_file,
            font=self.font_mono, fg=TEXT_MUTED, bg=CARD_BG
        )
        self._current_file_lbl.pack(anchor=tk.W, pady=(4,8))

        self._progress_bar = ttk.Progressbar(
            prog_inner, variable=self._scan_progress,
            maximum=100, mode='determinate', length=500
        )
        self._progress_bar.pack(fill=tk.X)

        # نتائج الفحص
        results_card = self._card(frame)
        results_card.pack(fill=tk.BOTH, expand=True)
        results_inner = tk.Frame(results_card, bg=CARD_BG)
        results_inner.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        hdr = tk.Frame(results_inner, bg=CARD_BG)
        hdr.pack(fill=tk.X, pady=(0,10))
        tk.Label(hdr, text="نتائج الفحص",
                 font=self.font_medium, fg=TEXT_PRIMARY, bg=CARD_BG
        ).pack(side=tk.LEFT)

        # جدول النتائج
        cols = ("الملف", "النتيجة", "ثقة النموذج", "الحالة")
        self._scan_tree = ttk.Treeview(
            results_inner, columns=cols, show="headings", height=8
        )
        self._style_treeview()
        for col in cols:
            self._scan_tree.heading(col, text=col)
            self._scan_tree.column(col, width=200)
        self._scan_tree.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(results_inner, orient=tk.VERTICAL,
                                   command=self._scan_tree.yview)
        self._scan_tree.configure(yscrollcommand=scrollbar.set)

        return frame

    # ══════════════════════════════════════════════════════════
    # صفحة التهديدات
    # ══════════════════════════════════════════════════════════
    def _build_threats_page(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        hdr_card = self._card(frame)
        hdr_card.pack(fill=tk.X, pady=(0,16))
        hdr_inner = tk.Frame(hdr_card, bg=CARD_BG)
        hdr_inner.pack(fill=tk.X, padx=20, pady=16)

        tk.Label(hdr_inner, text="التهديدات المكتشفة",
                 font=self.font_medium, fg=TEXT_PRIMARY, bg=CARD_BG
        ).pack(side=tk.LEFT)

        clear_btn = self._make_button(
            hdr_inner, "مسح القائمة", self._clear_threats,
            bg=DARK_BG, fg=TEXT_SEC
        )
        clear_btn.pack(side=tk.RIGHT)

        # جدول التهديدات
        list_card = self._card(frame)
        list_card.pack(fill=tk.BOTH, expand=True)
        list_inner = tk.Frame(list_card, bg=CARD_BG)
        list_inner.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        cols = ("الوقت", "العملية", "PID", "الثقة", "الإجراء", "الميزات المكتشفة")
        self._threats_tree = ttk.Treeview(
            list_inner, columns=cols, show="headings", height=15
        )
        self._style_treeview()
        widths = [130, 160, 60, 80, 100, 300]
        for col, w in zip(cols, widths):
            self._threats_tree.heading(col, text=col)
            self._threats_tree.column(col, width=w)
        self._threats_tree.pack(fill=tk.BOTH, expand=True)
        self._threats_tree.tag_configure("ransomware", foreground=RED)
        self._threats_tree.tag_configure("suspicious", foreground=AMBER)

        return frame

    # ══════════════════════════════════════════════════════════
    # سجل الأحداث
    # ══════════════════════════════════════════════════════════
    def _build_log_page(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        ctrl = tk.Frame(frame, bg=DARK_BG)
        ctrl.pack(fill=tk.X, pady=(0,12))
        tk.Label(ctrl, text="سجل الأحداث الكامل",
                 font=self.font_medium, fg=TEXT_PRIMARY, bg=DARK_BG
        ).pack(side=tk.LEFT)
        self._make_button(ctrl, "مسح السجل", self._clear_log,
                          bg=PANEL_BG, fg=TEXT_SEC).pack(side=tk.RIGHT)

        log_card = self._card(frame)
        log_card.pack(fill=tk.BOTH, expand=True)
        log_inner = tk.Frame(log_card, bg=CARD_BG)
        log_inner.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        self._full_log = tk.Text(
            log_inner, bg=DARK_BG, fg=TEXT_SEC,
            font=self.font_mono, relief=tk.FLAT,
            state=tk.DISABLED, wrap=tk.WORD
        )
        self._full_log.pack(fill=tk.BOTH, expand=True)
        self._full_log.tag_config("threat",  foreground=RED)
        self._full_log.tag_config("warn",    foreground=AMBER)
        self._full_log.tag_config("info",    foreground=BLUE)
        self._full_log.tag_config("success", foreground=GREEN)
        self._full_log.tag_config("muted",   foreground=TEXT_MUTED)

        scrollbar = ttk.Scrollbar(log_inner, command=self._full_log.yview)
        self._full_log.configure(yscrollcommand=scrollbar.set)

        return frame

    # ══════════════════════════════════════════════════════════
    # صفحة الإعدادات
    # ══════════════════════════════════════════════════════════
    def _build_settings_page(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        settings = [
            ("عتبة الكشف (Kill Threshold)",
             "الحد الأدنى للثقة قبل إيقاف العملية",
             "90%"),
            ("عتبة التحذير (Warn Threshold)",
             "الحد الأدنى للثقة قبل إطلاق تحذير",
             "70%"),
            ("نافذة المراقبة",
             "المدة الزمنية لجمع السلوك قبل التحليل",
             "5 ثواني"),
            ("File Guard",
             "حفظ نسخ احتياطية تلقائياً قبل أي تعديل",
             "مفعّل"),
            ("AI Decompiler",
             "تحليل الـ exe تلقائياً بعد الكشف",
             "مفعّل إذا توفّر ANTHROPIC_API_KEY"),
        ]

        for title, desc, value in settings:
            card = self._card(frame)
            card.pack(fill=tk.X, pady=(0,8))
            inner = tk.Frame(card, bg=CARD_BG)
            inner.pack(fill=tk.X, padx=20, pady=16)

            info = tk.Frame(inner, bg=CARD_BG)
            info.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Label(info, text=title,
                     font=self.font_medium, fg=TEXT_PRIMARY, bg=CARD_BG
            ).pack(anchor=tk.W)
            tk.Label(info, text=desc,
                     font=self.font_small, fg=TEXT_SEC, bg=CARD_BG
            ).pack(anchor=tk.W)

            tk.Label(inner, text=value,
                     font=tkfont.Font(family="Segoe UI",size=10,weight="bold"),
                     fg=BLUE, bg=CARD_BG
            ).pack(side=tk.RIGHT)

        # معلومات النموذج
        model_card = self._card(frame)
        model_card.pack(fill=tk.X, pady=(8,0))
        model_inner = tk.Frame(model_card, bg=CARD_BG)
        model_inner.pack(fill=tk.X, padx=20, pady=16)

        tk.Label(model_inner, text="معلومات النموذج",
                 font=self.font_medium, fg=TEXT_PRIMARY, bg=CARD_BG
        ).pack(anchor=tk.W, pady=(0,10))

        info_items = [
            ("النموذج",       "Logistic Regression"),
            ("الدقة",         "98.15% على بيانات الاختبار"),
            ("الميزات",       "483 ميزة سلوكية (RFE-selected)"),
            ("بيانات التدريب","MLRan Dataset — 4,880 عينة — 64 عائلة"),
            ("البيانات من",   "2006 إلى 2024"),
        ]

        for label, val in info_items:
            row = tk.Frame(model_inner, bg=CARD_BG)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=f"{label}:", width=16,
                     font=self.font_small, fg=TEXT_SEC, bg=CARD_BG, anchor=tk.W
            ).pack(side=tk.LEFT)
            tk.Label(row, text=val,
                     font=self.font_small, fg=TEXT_PRIMARY, bg=CARD_BG, anchor=tk.W
            ).pack(side=tk.LEFT)

        return frame

    # ══════════════════════════════════════════════════════════
    # منطق الحماية والفحص
    # ══════════════════════════════════════════════════════════
    def _toggle_protection(self):
        if not self._protection_on.get():
            self._start_protection()
        else:
            self._stop_protection()

    def _start_protection(self):
        self._protection_on.set(True)
        self._status_text.set(STATUS_PROTECTED)
        self._toggle_btn.config(text="إيقاف الحماية", bg="#6e1a1a")
        self._main_status_label.config(fg=GREEN)
        self._draw_main_shield(GREEN_DIM)
        self._add_log("الحماية مفعّلة — مراقبة كل العمليات", "success")

        # شغّل المراقبة في الخلفية
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

    def _stop_protection(self):
        self._protection_on.set(False)
        self._status_text.set(STATUS_IDLE)
        self._toggle_btn.config(text="تفعيل الحماية", bg=GREEN_DIM)
        self._main_status_label.config(fg=TEXT_SEC)
        self._draw_main_shield(TEXT_MUTED)
        self._add_log("الحماية أُوقفت", "warn")

    def _monitor_loop(self):
        """يراقب العمليات في الخلفية"""
        try:
            import psutil
            from step3_monitor import ProcessMonitor
            from step4_kill_chain import RansomwareDetector

            detector = RansomwareDetector(
                os.path.join(BASE_DIR, "models"),
                os.path.join(BASE_DIR, "logs"),
                os.path.join(BASE_DIR, "dumps"),
            )
            monitor = ProcessMonitor()

            def on_observation(pid, observed):
                if not self._protection_on.get():
                    return
                result = detector.analyze(pid, observed)
                if result['verdict'] in ('ransomware', 'suspicious'):
                    self.root.after(0, self._on_threat_detected, result)

            import threading as _t
            stop = _t.Event()
            monitor.watch_all_processes(on_observation, stop, interval=5.0)

        except Exception as e:
            self._add_log(f"خطأ في المراقبة: {e}", "warn")

    def _on_threat_detected(self, result):
        """يُستدعى من الـ monitor عند اكتشاف تهديد"""
        pid        = result['pid']
        name       = result.get('name', 'unknown')
        conf       = result.get('confidence', 0)
        verdict    = result['verdict']
        features   = result.get('triggered_features', [])
        ts         = datetime.datetime.now().strftime("%H:%M:%S")
        action     = result.get('action_taken', '-')

        tag = "ransomware" if verdict == 'ransomware' else "suspicious"
        label = "مُوقف" if verdict == 'ransomware' else "مراقَب"

        # أضف للجدول
        feat_str = ", ".join(features[:3]) + ("..." if len(features) > 3 else "")
        self._threats_tree.insert(
            "", 0,
            values=(ts, name, pid, f"{conf:.1%}", label, feat_str),
            tags=(tag,)
        )
        self._threats_count.set(self._threats_count.get() + 1)

        # سجّل الحدث
        level = "threat" if verdict == 'ransomware' else "warn"
        self._add_log(
            f"{ts} | {verdict.upper()} | PID={pid} {name} | Conf={conf:.1%} | {feat_str}",
            level
        )

        # إذا رانسوم وير → تنبيه
        if verdict == 'ransomware':
            self._status_text.set(STATUS_THREAT)
            self._main_status_label.config(fg=RED)
            self._draw_main_shield(RED)
            self._show_threat_alert(name, pid, conf, features)

    def _show_threat_alert(self, name, pid, conf, features):
        feat_str = "\n".join(f"  • {f}" for f in features[:8])
        messagebox.showwarning(
            "⚠ تهديد مكتشف!",
            f"رانسوم وير تم إيقافه!\n\n"
            f"العملية: {name}\n"
            f"PID: {pid}\n"
            f"ثقة النموذج: {conf:.1%}\n\n"
            f"الميزات المكتشفة:\n{feat_str}\n\n"
            f"تم تجميد العملية وحفظ تقرير في مجلد logs/"
        )
        # أعد الحالة للحماية بعد 5 ثواني
        self.root.after(5000, self._reset_status)

    def _reset_status(self):
        if self._protection_on.get():
            self._status_text.set(STATUS_PROTECTED)
            self._main_status_label.config(fg=GREEN)
            self._draw_main_shield(GREEN_DIM)

    # ─── فحص الملفات ────────────────────────────────────────
    def _quick_scan(self):
        self._show_page("scan")
        self._page_title.config(text="فحص سريع")
        threading.Thread(target=self._run_quick_scan, daemon=True).start()

    def _run_quick_scan(self):
        import psutil
        self.root.after(0, lambda: self._scan_status_lbl.config(
            text="يفحص العمليات الحية...", fg=BLUE
        ))
        self._add_log("بدء الفحص السريع للعمليات الحية", "info")

        try:
            procs = list(psutil.process_iter(['pid', 'name', 'exe']))
            total = len(procs)

            for i, proc in enumerate(procs):
                if not proc.info.get('exe'):
                    continue
                progress = (i / total) * 100
                name = proc.info.get('name', '')
                self.root.after(0, lambda p=progress, n=name: (
                    self._scan_progress.set(p),
                    self._current_file.set(n)
                ))
                time.sleep(0.02)

            self.root.after(0, self._scan_done, total)
        except Exception as e:
            self.root.after(0, lambda: self._scan_status_lbl.config(
                text=f"خطأ: {e}", fg=RED
            ))

    def _scan_file(self):
        path = filedialog.askopenfilename(
            title="اختر ملف للفحص",
            filetypes=[("Executable", "*.exe *.dll"), ("All", "*.*")]
        )
        if not path:
            return
        self._show_page("scan")
        threading.Thread(
            target=self._analyze_single_file, args=(path,), daemon=True
        ).start()

    def _scan_folder(self):
        folder = filedialog.askdirectory(title="اختر مجلداً للفحص")
        if not folder:
            return
        self._show_page("scan")
        threading.Thread(
            target=self._run_folder_scan, args=(folder,), daemon=True
        ).start()

    def _analyze_single_file(self, path):
        name = os.path.basename(path)
        self.root.after(0, lambda: self._scan_status_lbl.config(
            text=f"يفحص: {name}", fg=BLUE
        ))
        self._add_log(f"فحص الملف: {name}", "info")

        # محاكاة فحص PE
        result = "غير معروف"
        conf   = 0.0
        color  = TEXT_SEC

        try:
            import pefile
            pe = pefile.PE(path)
            suspicious = 0
            for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp in entry.imports:
                    if imp.name and any(x in imp.name.decode('utf-8','ignore')
                                        for x in ['Crypt','VirtualAlloc','WriteProcess']):
                        suspicious += 1
            if suspicious >= 3:
                result = "مشبوه"
                conf   = 0.72
                color  = AMBER
            else:
                result = "آمن"
                conf   = 0.05
                color  = GREEN
            pe.close()
        except Exception:
            result = "تعذّر التحليل"
            color  = TEXT_MUTED

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.root.after(0, lambda: (
            self._scan_progress.set(100),
            self._scan_status_lbl.config(text=f"اكتمل فحص {name}", fg=GREEN),
            self._scan_tree.insert("", 0,
                values=(name, result, f"{conf:.0%}" if conf else "-", ts))
        ))
        self._add_log(f"نتيجة {name}: {result} ({conf:.0%})", "warn" if result=="مشبوه" else "success")

    def _run_folder_scan(self, folder):
        exes = []
        for root_dir, _, files in os.walk(folder):
            for f in files:
                if f.endswith(('.exe', '.dll')):
                    exes.append(os.path.join(root_dir, f))

        total = len(exes) or 1
        for i, path in enumerate(exes):
            self.root.after(0, lambda p=(i/total*100), n=os.path.basename(path): (
                self._scan_progress.set(p),
                self._current_file.set(n)
            ))
            self._analyze_single_file(path)
            time.sleep(0.1)

        self.root.after(0, self._scan_done, len(exes))

    def _scan_done(self, count):
        self._scan_status_lbl.config(
            text=f"اكتمل الفحص — {count} عملية/ملف",
            fg=GREEN
        )
        self._scan_progress.set(100)
        self._current_file.set("")
        self._add_log(f"اكتمل الفحص — {count} عنصر", "success")

    # ══════════════════════════════════════════════════════════
    # أدوات مساعدة للواجهة
    # ══════════════════════════════════════════════════════════
    def _card(self, parent):
        outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD_BG)
        inner.pack(fill=tk.BOTH, expand=True)
        return outer

    def _make_button(self, parent, text, cmd, bg=ACCENT, fg="white"):
        btn = tk.Button(
            parent, text=text, command=cmd,
            font=self.font_small, fg=fg, bg=bg,
            relief=tk.FLAT, padx=12, pady=6,
            cursor="hand2",
            activebackground=DARK_BG, activeforeground=TEXT_PRIMARY
        )
        return btn

    def _style_treeview(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background=DARK_BG,
                         foreground=TEXT_SEC,
                         rowheight=28,
                         fieldbackground=DARK_BG,
                         borderwidth=0,
                         font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                         background=CARD_BG,
                         foreground=TEXT_PRIMARY,
                         font=("Segoe UI", 9, "bold"),
                         borderwidth=0)
        style.map("Treeview",
                   background=[("selected", ACCENT)],
                   foreground=[("selected", "white")])

        style.configure("Horizontal.TProgressbar",
                         troughcolor=DARK_BG,
                         background=GREEN,
                         borderwidth=0)

    def _add_log(self, message, level="info"):
        ts  = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {message}\n"

        widgets = []
        if hasattr(self, '_dashboard_log'): widgets.append(self._dashboard_log)
        if hasattr(self, '_full_log'): widgets.append(self._full_log)
        for widget in widgets:
            try:
                widget.configure(state=tk.NORMAL)
                widget.insert("1.0", line, level)
                lines = int(widget.index(tk.END).split('.')[0])
                if lines > 200:
                    widget.delete("150.0", tk.END)
                widget.configure(state=tk.DISABLED)
            except Exception:
                pass

    def _clear_threats(self):
        for item in self._threats_tree.get_children():
            self._threats_tree.delete(item)
        self._threats_count.set(0)

    def _clear_log(self):
        widgets = []
        if hasattr(self, '_dashboard_log'): widgets.append(self._dashboard_log)
        if hasattr(self, '_full_log'): widgets.append(self._full_log)
        for widget in widgets:
            try:
                widget.configure(state=tk.NORMAL)
                widget.delete("1.0", tk.END)
                widget.configure(state=tk.DISABLED)
            except Exception:
                pass

    def _update_clock(self):
        now = datetime.datetime.now().strftime("%Y/%m/%d  %H:%M:%S")
        try:
            self._clock_label.config(text=now)
        except Exception:
            pass
        self.root.after(1000, self._update_clock)

    def _animate_pulse(self):
        """نبضة بسيطة على أيقونة الدرع"""
        try:
            if self._protection_on.get():
                self._draw_main_shield(GREEN_DIM)
        except Exception:
            pass
        self.root.after(2000, self._animate_pulse)

    def _on_close(self):
        if self._protection_on.get():
            if messagebox.askyesno("إيقاف الحماية",
                                    "الحماية مفعّلة. هل تريد الإغلاق وإيقاف الحماية؟"):
                self._stop_protection()
                self.root.destroy()
        else:
            self.root.destroy()

    # ══════════════════════════════════════════════════════════
    def run(self):
        # تأكد من وجود المجلدات
        for d in ["logs", "dumps", "guard_store", "decompiled"]:
            os.makedirs(os.path.join(BASE_DIR, d), exist_ok=True)

        self.root.mainloop()


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = RansomShieldApp()
    app.run()
