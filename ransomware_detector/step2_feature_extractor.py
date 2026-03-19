# -*- coding: utf-8 -*-
"""
STEP 2 — Feature Extractor (الجسر الأهم في النظام)
================================================
هاد الملف يحول السلوك الحي لـ process إلى vector من 483 feature
بنفس الطريقة اللي استخدمها MLRan في:
  - 4_cuckoo_parser_scripts/1_api_parser.py          → API calls
  - 4_cuckoo_parser_scripts/2_registry_keys_parser.py → REG keys
  - 4_cuckoo_parser_scripts/3_file_operations_parser.py → FILE ops
  - 4_cuckoo_parser_scripts/7_system_resources_parser.py → DLLs, system info

الفرق: بدل ما نقرأ من Cuckoo JSON report، نقرأ من العملية الحية مباشرة.

يشتغل على: Windows (الـ APIs موجودة) + Linux/Mac (مع features محدودة)
"""

import os, sys, json, time, re
import collections
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """
    يحول بيانات السلوك الحي لـ process إلى feature vector من 483 قيمة.
    كل قيمة إما 0 (ما صارت) أو 1 (صارت).

    الـ feature categories (من RFE_selected_feature_names_dic.json):
        API:       63  مثل API:NtProtectVirtualMemory
        REG:       90  مثل REG:WRITTEN:HKCU/Software/...
        FILE:      16  مثل FILE:WRITTEN:c:/users/...
        STRING:   223  مثل STRING:cmd.exe
        SYSTEM:    38  مثل SYSTEM:DLL_LOADED:advapi32
        DROP:      23  مثل DROP:EXTENSION:exe
        SIGNATURE: 20  مثل SIGNATURE:allocates_rwx
        DIRECTORY: 10  مثل DIRECTORY:CREATED:c:/users
    """

    def __init__(self, models_dir: str):
        models_dir = os.path.abspath(models_dir)

        with open(os.path.join(models_dir, 'feature_cols.json')) as f:
            self.feature_cols = json.load(f)   # ['5', '8', '18', ...] — الترتيب مهم

        with open(os.path.join(models_dir, 'feature_names.json')) as f:
            self.feat_map = json.load(f)        # {'5': 'API:NtProtectVirtualMemory', ...}

        # عكس الـ map: اسم → ID (للبحث السريع)
        self.name_to_id = {v: k for k, v in self.feat_map.items()}

        # تصنيف الـ features حسب النوع
        self.api_features  = {v: k for k, v in self.feat_map.items() if v.startswith('API:')}
        self.reg_features  = {v: k for k, v in self.feat_map.items() if v.startswith('REG:')}
        self.file_features = {v: k for k, v in self.feat_map.items() if v.startswith('FILE:')}
        self.str_features  = {v: k for k, v in self.feat_map.items() if v.startswith('STRING:')}
        self.sys_features  = {v: k for k, v in self.feat_map.items() if v.startswith('SYSTEM:')}
        self.sig_features  = {v: k for k, v in self.feat_map.items() if v.startswith('SIGNATURE:')}
        self.dir_features  = {v: k for k, v in self.feat_map.items() if v.startswith('DIRECTORY:')}
        self.drop_features = {v: k for k, v in self.feat_map.items() if v.startswith('DROP:')}

        logger.info(f"FeatureExtractor جاهز: {len(self.feature_cols)} features")

    def build_vector(self, observed: dict) -> list:
        """
        observed: dict يحتوي على السلوك الملاحظ
        {
          'api_calls':    set of strings  e.g. {'NtProtectVirtualMemory', 'CreateFile'}
          'reg_opened':   set of strings  e.g. {'HKEY_CURRENT_USER\\Software\\...'}
          'reg_written':  set of strings
          'reg_deleted':  set of strings
          'reg_read':     set of strings
          'file_created': set of strings  e.g. {'c:\\users\\admin\\doc.exe'}
          'file_written': set of strings
          'file_deleted': set of strings
          'file_read':    set of strings
          'file_exists':  set of strings
          'file_failed':  set of strings
          'strings':      set of strings  (من memory أو command line)
          'dlls_loaded':  set of strings  e.g. {'advapi32', 'kernel32'}
          'dirs_created': set of strings
          'drop_extensions': set of strings  e.g. {'exe', 'dll'}
          'signatures':   set of strings  (سلوك مشبوه مكتشف)
        }

        Returns: list من 483 قيمة (0 أو 1) بنفس ترتيب feature_cols
        """
        # بناء dict من feature_id → قيمة (كلها 0 بالبداية)
        vec = {col: 0 for col in self.feature_cols}

        # ── API calls (1_api_parser.py نفس المنطق) ──
        for api in observed.get('api_calls', set()):
            key = f"API:{api}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        # ── Registry (2_registry_keys_parser.py) ──
        for regkey in observed.get('reg_opened', set()):
            # normalize: lowercase + استبدال HKEY_CURRENT_USER -> HKCU إلخ
            normalized = self._normalize_regkey(regkey)
            for fmt in [regkey, normalized]:
                key = f"REG:OPENED:{fmt}"
                if key in self.name_to_id:
                    vec[self.name_to_id[key]] = 1

        for regkey in observed.get('reg_written', set()):
            normalized = self._normalize_regkey(regkey)
            for fmt in [regkey, normalized]:
                key = f"REG:WRITTEN:{fmt}"
                if key in self.name_to_id:
                    vec[self.name_to_id[key]] = 1

        for regkey in observed.get('reg_deleted', set()):
            key = f"REG:DELETED:{self._normalize_regkey(regkey)}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        for regkey in observed.get('reg_read', set()):
            key = f"REG:READ:{self._normalize_regkey(regkey)}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        # ── File operations (3_file_operations_parser.py) ──
        file_op_map = {
            'file_created':    'CREATED',
            'file_written':    'WRITTEN',
            'file_deleted':    'DELETED',
            'file_read':       'READ',
            'file_exists':     'EXISTS',
            'file_failed':     'FAILED',
        }
        for obs_key, feat_type in file_op_map.items():
            for filepath in observed.get(obs_key, set()):
                key = f"FILE:{feat_type}:{filepath.lower()}"
                if key in self.name_to_id:
                    vec[self.name_to_id[key]] = 1

        # ── Strings (5_strings_parser.py) ──
        for s in observed.get('strings', set()):
            key = f"STRING:{s}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        # ── System resources / DLLs (7_system_resources_parser.py) ──
        for dll in observed.get('dlls_loaded', set()):
            for fmt in [dll, dll.lower(), f"c:\\windows\\system32\\{dll.lower()}.dll"]:
                key = f"SYSTEM:DLL_LOADED:{fmt}"
                if key in self.name_to_id:
                    vec[self.name_to_id[key]] = 1

        # ── Directory operations ──
        for d in observed.get('dirs_created', set()):
            key = f"DIRECTORY:CREATED:{d.lower()}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        # ── Dropped file extensions (8_dropped_file_parser.py) ──
        for ext in observed.get('drop_extensions', set()):
            key = f"DROP:EXTENSION:{ext.lower()}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        # ── Signatures (9_signature_parser.py) ──
        for sig in observed.get('signatures', set()):
            key = f"SIGNATURE:{sig}"
            if key in self.name_to_id:
                vec[self.name_to_id[key]] = 1

        # إرجاع القيم بنفس الترتيب المطلوب
        return [vec[col] for col in self.feature_cols]

    def get_triggered_features(self, vector: list) -> list:
        """يرجع أسماء الـ features اللي قيمتها 1 (الـ features المكتشفة)"""
        triggered = []
        for i, val in enumerate(vector):
            if val == 1:
                col_id = self.feature_cols[i]
                name   = self.feat_map.get(str(col_id), col_id)
                triggered.append(name)
        return triggered

    def _normalize_regkey(self, key: str) -> str:
        """تطبيع مفاتيح الريجستري لتتطابق مع الداتا"""
        key = key.strip().lower()
        replacements = [
            ('hkey_current_user', 'HKEY_CURRENT_USER'),
            ('hkey_local_machine', 'HKEY_LOCAL_MACHINE'),
            ('hkey_classes_root', 'HKEY_CLASSES_ROOT'),
            ('hklm\\', 'HKEY_LOCAL_MACHINE\\'),
            ('hkcu\\', 'HKEY_CURRENT_USER\\'),
        ]
        for old, new in replacements:
            if key.startswith(old):
                key = new + key[len(old):]
                break
        return key


# ─────────────────────────────────────────────────────────
# اختبار الـ extractor على عينة حقيقية من Cuckoo report
# ─────────────────────────────────────────────────────────
def test_on_real_cuckoo_report(models_dir: str, report_path: str):
    """
    يختبر الـ extractor على JSON report حقيقي من MLRan
    للتأكد إن الـ features تتطابق مع الداتاست
    """
    extractor = FeatureExtractor(models_dir)

    with open(report_path) as f:
        report = json.load(f)

    behavior   = report.get('behavior', {})
    apistats   = behavior.get('apistats', {})
    summary    = behavior.get('summary', {})

    # استخراج السلوك بنفس طريقة parsers المجلد 4
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
    }

    # API calls من apistats
    for pid, apis in apistats.items():
        observed['api_calls'].update(apis.keys())

    vector   = extractor.build_vector(observed)
    active   = sum(vector)
    triggered = extractor.get_triggered_features(vector)

    print(f"\nاختبار على: {os.path.basename(report_path)}")
    print(f"Features مكتشفة: {active}/{len(vector)}")
    print("أبرز الـ features:")
    for f in triggered[:15]:
        print(f"  ✓ {f}")

    return vector


if __name__ == '__main__':
    BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
    MODELS_DIR = os.path.join(BASE_DIR, 'models')
    MLRAN_DIR  = os.path.join(BASE_DIR, '..', 'mlran', 'mlran-main')

    logging.basicConfig(level=logging.INFO)

    # اختبار على أول report حقيقي من الداتا
    test_report = os.path.join(MLRAN_DIR, '4_cuckoo_parser_scripts/json_reports/10002.json')

    if os.path.exists(test_report):
        vec = test_on_real_cuckoo_report(MODELS_DIR, test_report)
        print(f"\nVector sample (first 20): {vec[:20]}")
        print("✅ Feature extractor شغال بشكل صحيح")
    else:
        print("ملف الاختبار ما موجود، جرب: python step2_feature_extractor.py")
