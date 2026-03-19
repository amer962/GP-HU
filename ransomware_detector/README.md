# دليل تشغيل نظام كشف الرانسوم وير
## مبني على MLRan Dataset — الخطوات الكاملة

---

## البنية الكاملة للمشروع

```
ransomware_detector/
│
├── step1_train_model.py      ← تدريب النموذج من الداتا
├── step2_feature_extractor.py ← تحويل السلوك لـ vector
├── step3_monitor.py          ← مراقبة العمليات الحية
├── step4_kill_chain.py       ← كشف + إيقاف
├── step5_main.py             ← تشغيل النظام كله
├── requirements.txt
│
├── models/                   ← يُنشأ بعد الخطوة ١
│   ├── ransomware_model.pkl   → النموذج المدرّب
│   ├── feature_map.json       → ربط الاسم بـ index
│   ├── feature_names.json     → أسماء الـ 483 ميزة
│   └── feature_order.json     → ترتيب الأعمدة
│
├── logs/                     ← يُنشأ تلقائياً
│   ├── detections.jsonl       → سجل الكشف
│   ├── kill_report_*.json     → تقارير الإيقاف
│   └── system.log             → لوغ النظام
│
└── dumps/                    ← memory dumps للتحليل
```

---

## المتطلبات

- **نظام التشغيل:** Windows 10/11 أو Windows Server
- **Python:** 3.9 أو أحدث
- **صلاحيات:** Administrator (لازم للـ Kill Chain)
- **ملفات MLRan:** مجلد `mlran-main` من الـ repo

---

## خطوة صفر: التثبيت

افتح CMD أو PowerShell كـ Administrator وشغّل:

```cmd
pip install scikit-learn pandas numpy joblib psutil pywin32 watchdog
```

---

## الخطوة ١: تدريب النموذج
**الملفات المستخدمة من MLRan:**
- `mlran-main/6_experiments/FS_MLRan_Datasets/MLRan_X_train_RFE.csv`
  → 3,905 عينة × 483 ميزة (بيانات التدريب)
- `mlran-main/6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv`
  → 975 عينة للتقييم
- `mlran-main/6_experiments/FS_MLRan_Datasets/RFE_selected_feature_names_dic.json`
  → خريطة ربط كل رقم ميزة باسمها الحقيقي

**شغّل:**
```cmd
set MLRAN_PATH=C:\path\to\mlran-main
python step1_train_model.py
```

**النتيجة المتوقعة:**
```
[*] تحميل البيانات...
    Train: (3905, 483)  |  Test: (975, 483)
[*] تدريب النموذج...
    الدقة (Accuracy):  98.15%
    True Positive  (رانسوم وير اكتُشف صح):  459
    False Positive (goodware اتهم غلط):       12
    False Negative (رانسوم وير فات علينا):     6
[✓] الخطوة ١ اكتملت
```

**الملفات اللي تنشأ:**
- `models/ransomware_model.pkl` — النموذج (4.7 KB)
- `models/feature_map.json` — 483 ميزة مع أرقامها
- `models/feature_names.json` — أسماء مرتبة

---

## الخطوة ٢ + ٣ + ٤ + ٥: تشغيل النظام
**لا تحتاج تشغّلها منفصلة — step5_main.py يجمعها كلها**

```cmd
python step5_main.py
```

**الخيارات:**
```
--window 30        النافذة الزمنية لجمع السلوك (ثانية)
--threshold 0.85   عتبة الكشف (85% = اكتُشف كرانسوم وير)
--no-kill          كشف فقط بدون إيقاف (للاختبار)
--min-feat 5       حد أدنى من الميزات قبل الكشف
```

**مثال بدون Kill Chain (للاختبار أولاً):**
```cmd
python step5_main.py --no-kill
```

**مثال بـ Kill Chain مفعّل:**
```cmd
python step5_main.py --window 30 --threshold 0.85
```

---

## ماذا يحدث عند الكشف؟

```
[!!!] رانسوم وير مؤكد! pid=4823 name=malware.exe confidence=97.3%
[Kill 1/4] تجميد العملية...       ← NtSuspendProcess
[Kill 2/4] قطع الاتصال الشبكي...  ← Windows Firewall + socket close
[Kill 3/4] أخذ memory dump...     ← MiniDumpWriteDump → dumps/
[Kill 4/4] إنهاء العملية...       ← psutil.kill() + children
[Report]   محفوظ: logs/kill_report_malware.exe_4823_20250317_142533.json
```

---

## فهم الـ 483 ميزة (من الداتا)

| الفئة      | عدد الميزات | أمثلة                                          |
|------------|-------------|------------------------------------------------|
| STRING     | 223         | strings من ذاكرة البرنامج                       |
| REG        | 90          | `REG:WRITTEN:HKCU\Software\Microsoft\...`      |
| API        | 63          | `API:NtProtectVirtualMemory`, `API:CryptEncrypt` |
| SYSTEM     | 38          | `SYSTEM:DLL_LOADED:advapi32`                   |
| DROP       | 23          | `DROP:EXTENSION:exe`, `DROP:TYPE:pe32_exec`   |
| SIGNATURE  | 20          | `SIGNATURE:allocates_rwx`, `SIGNATURE:injection_runpe` |
| FILE       | 16          | `FILE:WRITTEN:c:\users\...\document.docx`     |
| DIRECTORY  | 10          | `DIRECTORY:CREATED:c:\users\...`              |

---

## تقرير الكشف — مثال

```json
{
  "timestamp": "2025-03-17T14:25:33",
  "pid": 4823,
  "process_name": "malware.exe",
  "confidence": 0.9731,
  "status": "KILLED",
  "triggered_features_count": 47,
  "triggered_features": [
    "API:NtProtectVirtualMemory",
    "API:CryptEncrypt",
    "SIGNATURE:allocates_rwx",
    "SIGNATURE:injection_write_memory",
    "REG:WRITTEN:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "FILE:WRITTEN:c:\\users\\admin\\documents\\report.docx.encrypted"
  ]
}
```

---

## ملاحظات مهمة

1. **الخطوة ١ فقط** تشتغل على أي نظام (Windows/Linux/Mac)
2. **الخطوة ٥** تحتاج Windows فقط — لأن الـ 483 ميزة مبنية على Windows APIs
3. **Kill Chain** تحتاج Admin privileges — بدونها فقط الكشف يعمل
4. **لو ما عندك صلاحيات**: شغّل `--no-kill` وراجع لوغات `logs/detections.jsonl`
5. **اختبر دائماً في VM** قبل الـ production

---

## استكشاف الأخطاء

| المشكلة | الحل |
|---------|------|
| `FileNotFoundError: models/ransomware_model.pkl` | شغّل `step1_train_model.py` أولاً |
| `Access Denied` في Kill Chain | شغّل كـ Administrator |
| `Import winreg failed` | أنت على Linux — الـ monitor لن يراقب Registry |
| `NtSuspendProcess failed` | النموذج مكتشف لكن تجميد فشل — psutil يكمّل |
