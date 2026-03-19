"""
STEP 1 — تدريب النموذج وحفظه
================================================
الملفات المستخدمة من MLRan:
  - 6_experiments/FS_MLRan_Datasets/MLRan_X_train_RFE.csv        (3905 عينة, 483 ميزة)
  - 6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv         (975 عينة)
  - 6_experiments/FS_MLRan_Datasets/RFE_selected_feature_names_dic.json

الناتج (في مجلد models/):
  - mlran_model.pkl      النموذج المدرب جاهز للاستخدام
  - feature_cols.json    قائمة الـ 483 عمود بالترتيب الصحيح
  - feature_names.json   mapping من ID الى اسم مقروء (API:NtProtectVirtualMemory...)
"""

import os, json
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import joblib

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MLRAN_DIR  = os.environ.get('MLRAN_PATH', os.path.join(BASE_DIR, '..', 'mlran-main'))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

print(f"[Config] MLRAN_PATH = {MLRAN_DIR}")
# تحقق أن المجلد موجود
if not os.path.exists(MLRAN_DIR):
    print(f"\n[ERROR] المجلد غير موجود: {MLRAN_DIR}")
    print("الحل: شغّل الأمر التالي أولاً:")
    print(f"  set MLRAN_PATH=<المسار الصحيح لمجلد mlran-main>")
    exit(1)

# ── 1. تحميل الداتا ───────────────────────────────────────
print("[1/4] تحميل الداتا من MLRan...")

tr = pd.read_csv(os.path.join(MLRAN_DIR, '6_experiments/FS_MLRan_Datasets/MLRan_X_train_RFE.csv'))
te = pd.read_csv(os.path.join(MLRAN_DIR, '6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv'))

# الأعمدة metadata — مش features فعلية
META_COLS = ['sample_id', 'sample_type', 'family_label', 'type_label']
FEAT_COLS = [c for c in tr.columns if c not in META_COLS]

X_train = tr[FEAT_COLS].values
y_train = tr['sample_type'].values  # 0=goodware, 1=ransomware
X_test  = te[FEAT_COLS].values
y_test  = te['sample_type'].values

print(f"    Train: {X_train.shape} — goodware={sum(y_train==0)}, ransomware={sum(y_train==1)}")
print(f"    Test:  {X_test.shape}  — goodware={sum(y_test==0)},  ransomware={sum(y_test==1)}")
print(f"    Features: {len(FEAT_COLS)} (بعد Mutual Information + RFE selection)")

# ── 2. تدريب النموذج ──────────────────────────────────────
print("\n[2/4] تدريب Logistic Regression...")
# لماذا LR وليس Random Forest؟
#   - 98.15% دقة (أعلى من RF 96.6% في هاد الداتاست)
#   - inference بالميلي-ثانية — مهم جداً للكشف real-time
#   - predict_proba() يعطي confidence score مباشرة

model = LogisticRegression(C=1, solver='liblinear', max_iter=1000)
model.fit(X_train, y_train)

pred = model.predict(X_test)
acc  = accuracy_score(y_test, pred)
print(f"    Accuracy: {acc:.4f} ({acc*100:.1f}%)")
print()
print(classification_report(y_test, pred, target_names=['goodware', 'ransomware']))

# ── 3. حفظ كل شي ──────────────────────────────────────────
print("[3/4] حفظ النموذج والـ metadata...")

joblib.dump(model, os.path.join(MODELS_DIR, 'mlran_model.pkl'))
with open(os.path.join(MODELS_DIR, 'feature_cols.json'), 'w') as f:
    json.dump(FEAT_COLS, f)

src = os.path.join(MLRAN_DIR, '6_experiments/FS_MLRan_Datasets/RFE_selected_feature_names_dic.json')
with open(src) as f:
    feat_map = json.load(f)
with open(os.path.join(MODELS_DIR, 'feature_names.json'), 'w') as f:
    json.dump(feat_map, f, ensure_ascii=False, indent=2)

# ── 4. أهم الـ features (للفهم) ───────────────────────────
print("[4/4] أهم 15 feature في النموذج:")
coefs   = model.coef_[0]
top_idx = np.argsort(np.abs(coefs))[-15:][::-1]
for i in top_idx:
    col_id    = FEAT_COLS[i]
    feat_name = feat_map.get(str(col_id), col_id)
    direction = "RANSOM ▲" if coefs[i] > 0 else "SAFE   ▼"
    print(f"    [{direction}]  {feat_name}  (coef={coefs[i]:+.3f})")

model_size = os.path.getsize(os.path.join(MODELS_DIR, 'mlran_model.pkl'))
print(f"\n✅ حُفظ في {MODELS_DIR}/")
print(f"   mlran_model.pkl    ({model_size//1024} KB)")
print(f"   feature_cols.json  ({len(FEAT_COLS)} features)")
print(f"   feature_names.json (483 ID → name mappings)")
print("\n→ الخطوة التالية: python step2_feature_extractor.py --test")
