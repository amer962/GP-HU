# 🛡️ RansomShield — نظام كشف برامج الفدية السلوكي

> نظام حماية متقدم مبني على الذكاء الاصطناعي يكشف برامج الفدية (Ransomware) بناءً على سلوكها — لا بناءً على توقيعها.

---

## 📋 نظرة عامة

RansomShield نظام كشف ودفاع ضد برامج الفدية مبني على مجموعة بيانات **MLRan** — أكبر مجموعة بيانات سلوكية مفتوحة المصدر لبرامج الفدية.

- **دقة الكشف:** 98.15%
- **عدد العينات:** 4,880+ عينة (64 عائلة رانسوم وير)
- **الميزات:** 483 ميزة سلوكية مختارة بـ Mutual Information + RFE
- **النموذج:** Logistic Regression
- **الفترة الزمنية للبيانات:** 2006 — 2024

---

## 🏗️ بنية المشروع

```
RansomShield/
│
├── ransomware_detector/          # النظام الرئيسي
│   ├── gui.py                    # واجهة المستخدم الرسومية
│   ├── step1_train_model.py      # تدريب النموذج من MLRan
│   ├── step2_feature_extractor.py # تحويل السلوك لـ feature vector
│   ├── step3_monitor.py          # مراقبة العمليات الحية
│   ├── step4_kill_chain.py       # الكشف + الإيقاف التلقائي
│   ├── step5_main.py             # تشغيل النظام من CMD
│   ├── step6_file_guard.py       # Copy-on-Write + Rollback
│   ├── step7_decompiler.py       # AI Decompiler للتحليل الجنائي
│   ├── build_exe.py              # بناء ملف .exe
│   └── models/                  # النموذج المدرّب (جاهز)
│       ├── mlran_model.pkl
│       ├── feature_cols.json
│       └── feature_names.json
│
└── mlran-main/                   # مجموعة بيانات MLRan الأصلية
    ├── 1_sample_collection_scripts/
    ├── 2_collected_samples_metadata/
    ├── 3_cuckoo_submission_automation/
    ├── 4_cuckoo_parser_scripts/
    ├── 5_mlran_dataset/
    └── 6_experiments/
        └── FS_MLRan_Datasets/
            ├── MLRan_X_train_RFE.csv
            ├── MLRan_X_test_RFE.csv
            └── RFE_selected_feature_names_dic.json
```

---

## ⚙️ كيف يعمل النظام

```
العملية الحية
     ↓
مراقبة السلوك (API calls, Registry, Files, Network)
     ↓
استخراج 483 ميزة سلوكية
     ↓
نموذج ML يعطي confidence score
     ↓
< 70%  → آمن
70-90% → مشبوه (مراقبة مكثفة)
> 90%  → رانسوم وير ← Kill Chain
              ↓
    ١. تجميد العملية فوراً
    ٢. قطع الشبكة
    ٣. Memory dump للتحليل
    ٤. إنهاء العملية
    ٥. استعادة الملفات (Rollback)
```

---

## 🚀 التثبيت والتشغيل

### المتطلبات
- Python 3.9+
- Windows 10/11
- صلاحيات Administrator

### ١. تثبيت المكتبات
```cmd
pip install scikit-learn pandas numpy joblib psutil pywin32 watchdog
```

### ٢. تدريب النموذج
```cmd
cd ransomware_detector
set MLRAN_PATH=..\mlran-main
py step1_train_model.py
```

### ٣. تشغيل الواجهة الرسومية
```cmd
py gui.py
```

### ٤. أو تشغيل من CMD
```cmd
py step5_main.py           # مراقبة كاملة مع Kill Chain
py step5_main.py --simulate # اختبار بدون فيروس حقيقي
```

### ٥. بناء ملف .exe
```cmd
pip install pyinstaller
py build_exe.py
```
النتيجة: `dist\RansomShield\RansomShield.exe`

---

## 🧪 الاختبار

### بدون فيروس حقيقي (آمن 100%)
```cmd
py step5_main.py --simulate
```
يحاكي سلوك WannaCry الحقيقي ويختبر الكشف.

### باستخدام RanSim
```
github.com/lawndoc/RanSim
```
يحاكي 22 نوع رانسوم وير داخل بيئة آمنة.

### داخل VM (موصى به)
١. شغّل VirtualBox أو Windows Sandbox
٢. خذ Snapshot قبل الاختبار
٣. شغّل RansomShield
٤. شغّل RanSim
٥. راقب النتائج

---

## 📊 نتائج النموذج

| المقياس | القيمة |
|---------|--------|
| Accuracy | 98.15% |
| Precision (Ransomware) | 97% |
| Recall (Ransomware) | 99% |
| F1-Score | 98% |
| False Positives | 12 / 975 |
| False Negatives | 6 / 975 |

---

## 🔬 الميزات السلوكية (483 ميزة)

| الفئة | العدد | أمثلة |
|-------|-------|-------|
| STRING | 223 | strings من ذاكرة البرنامج |
| REG | 90 | تعديلات الـ Registry |
| API | 63 | NtProtectVirtualMemory, CryptEncrypt |
| SYSTEM | 38 | DLLs محملة |
| DROP | 23 | امتدادات الملفات المُنشأة |
| SIGNATURE | 20 | allocates_rwx, injection_runpe |
| FILE | 16 | عمليات الملفات |
| DIRECTORY | 10 | عمليات المجلدات |

---

## 🛡️ مميزات إضافية

**File Guard (Copy-on-Write)**
يحفظ نسخة من كل ملف قبل أي تعديل — لو اكتُشف رانسوم وير يُستعاد كل شي تلقائياً.

**AI Decompiler**
بعد الكشف يحلل الـ exe تلقائياً ويولّد تقرير يشرح خوارزمية التشفير المستخدمة.
يحتاج `ANTHROPIC_API_KEY` للتحليل الكامل:
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
```

---

## 📁 البيانات

مجموعة بيانات MLRan مأخوذة من:
```
Onwuegbuche, F. C., et al. (2025).
MLRan: A Behavioural Dataset for Ransomware Analysis and Detection.
arXiv:2505.18613
```
الرابط: [github.com/faithfulco/mlran](https://github.com/faithfulco/mlran)

---

## ⚠️ تحذير

هاد النظام مخصص للبحث والتعليم فقط.
لا تشغّله خارج بيئة اختبار معزولة (VM) عند تجربة عينات رانسوم وير حقيقية.
