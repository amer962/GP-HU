# api.py — REST API for RansomShield model
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict
import joblib, json, numpy as np, os

BASE  = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(f"{BASE}/models/mlran_model.pkl")

with open(f"{BASE}/models/feature_cols.json")  as f: FEAT_COLS  = json.load(f)
with open(f"{BASE}/models/feature_names.json") as f: FEAT_NAMES = json.load(f)

# feature_name → index
FEAT_MAP = {name: i for i, name in enumerate(FEAT_NAMES)}

app = FastAPI(title="RansomShield API", version="1.0")

class BehaviorRequest(BaseModel):
    pid:          int
    process_name: str
    api_calls:    List[str] = []
    reg_written:  List[str] = []
    reg_opened:   List[str] = []
    file_written: List[str] = []
    file_created: List[str] = []
    dlls_loaded:  List[str] = []
    signatures:   List[str] = []
    strings:      List[str] = []

class PredictResponse(BaseModel):
    pid:               int
    process_name:      str
    confidence:        float
    verdict:           str
    triggered_features: List[str]

@app.get("/health")
def health():
    return {"status": "ok", "model": "LogisticRegression", "features": 483}

@app.post("/predict", response_model=PredictResponse)
def predict(req: BehaviorRequest):
    vec = np.zeros(len(FEAT_COLS), dtype=np.int8)

    def set_feat(key):
        idx = FEAT_MAP.get(key)
        if idx is not None:
            vec[idx] = 1

    for api  in req.api_calls:    set_feat(f"API:{api}")
    for reg  in req.reg_written:  set_feat(f"REG:WRITTEN:{reg}")
    for reg  in req.reg_opened:   set_feat(f"REG:OPENED:{reg}")
    for f    in req.file_written:  set_feat(f"FILE:WRITTEN:{f.lower()}")
    for f    in req.file_created:  set_feat(f"FILE:CREATED:{f.lower()}")
    for dll  in req.dlls_loaded:  set_feat(f"SYSTEM:DLL_LOADED:{dll.lower()}")
    for sig  in req.signatures:   set_feat(f"SIGNATURE:{sig.lower()}")
    for s    in req.strings:      set_feat(f"STRING:{s.lower()}")

    proba      = model.predict_proba(vec.reshape(1, -1))[0]
    confidence = float(proba[1])

    if confidence >= 0.90:   verdict = "ransomware"
    elif confidence >= 0.70: verdict = "suspicious"
    else:                    verdict = "safe"

    triggered = [FEAT_NAMES[i] for i, v in enumerate(vec) if v == 1]

    return PredictResponse(
        pid=req.pid,
        process_name=req.process_name,
        confidence=round(confidence, 4),
        verdict=verdict,
        triggered_features=triggered
    )
