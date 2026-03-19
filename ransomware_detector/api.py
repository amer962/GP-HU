#!/usr/bin/env python3
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List
import joblib, json, numpy as np, os, datetime, collections

BASE  = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(f"{BASE}/models/mlran_model.pkl")

# feature_map: {"API:NtProtectVirtualMemory": 0, ...}
with open(f"{BASE}/models/feature_map.json") as f:
    FEAT_MAP = json.load(f)

# feature_cols: ['5','8','18',...] — 483 عمود
with open(f"{BASE}/models/feature_cols.json") as f:
    FEAT_COLS = json.load(f)

# inv map: index -> feature name (للتقرير)
INV_MAP = {v: k for k, v in FEAT_MAP.items()}

app = FastAPI(title="RansomShield")
events = collections.deque(maxlen=200)
stats  = {"checked": 0, "suspicious": 0, "killed": 0, "safe": 0}

class BehaviorRequest(BaseModel):
    pid:          int       = 0
    process_name: str       = "unknown"
    api_calls:    List[str] = []
    reg_written:  List[str] = []
    reg_opened:   List[str] = []
    file_written: List[str] = []
    file_created: List[str] = []
    dlls_loaded:  List[str] = []
    signatures:   List[str] = []
    strings:      List[str] = []

@app.get("/health")
def health():
    return {"status": "ok", "model": "LogisticRegression", "features": len(FEAT_COLS)}

@app.get("/stats")
def get_stats():
    return {**stats, "recent_events": list(events)[:20]}

@app.post("/predict")
def predict(req: BehaviorRequest):
    vec = np.zeros(len(FEAT_COLS), dtype=np.int8)

    def s(key):
        idx = FEAT_MAP.get(key)
        if idx is not None:
            vec[idx] = 1

    for x in req.api_calls:    s(f"API:{x}")
    for x in req.reg_written:  s(f"REG:WRITTEN:{x}")
    for x in req.reg_opened:   s(f"REG:OPENED:{x}")
    for x in req.file_written: s(f"FILE:WRITTEN:{x.lower()}")
    for x in req.file_created: s(f"FILE:CREATED:{x.lower()}")
    for x in req.dlls_loaded:  s(f"SYSTEM:DLL_LOADED:{x.lower()}")
    for x in req.signatures:   s(f"SIGNATURE:{x.lower()}")
    for x in req.strings:      s(f"STRING:{x.lower()}")

    proba      = model.predict_proba(vec.reshape(1, -1))[0]
    confidence = float(proba[1])

    if confidence >= 0.90:    verdict = "ransomware"
    elif confidence >= 0.70:  verdict = "suspicious"
    else:                     verdict = "safe"

    triggered = [INV_MAP[i] for i, v in enumerate(vec) if v == 1]

    event = {
        "time":       datetime.datetime.now().strftime("%H:%M:%S"),
        "pid":        req.pid,
        "name":       req.process_name,
        "confidence": round(confidence * 100, 1),
        "verdict":    verdict,
        "features":   triggered[:5],
    }
    events.appendleft(event)
    stats["checked"] += 1
    if verdict == "ransomware":   stats["killed"]     += 1
    elif verdict == "suspicious": stats["suspicious"] += 1
    else:                         stats["safe"]       += 1

    return {
        "pid": req.pid,
        "process_name": req.process_name,
        "confidence": round(confidence, 4),
        "verdict": verdict,
        "triggered_features": triggered,
    }

@app.post("/simulate")
def simulate():
    req = BehaviorRequest(
        pid=9999, process_name="wannacry_sim.exe",
        api_calls=["NtProtectVirtualMemory","CreateProcessInternalW",
                   "NtAllocateVirtualMemory","NtOpenProcess",
                   "CryptAcquireContextW","CryptCreateHash",
                   "Process32NextW","CreateToolhelp32Snapshot",
                   "RegSetValueExW","NtDelayExecution"],
        reg_written=[r"HKEY_CURRENT_USER\Software\WannaCrypt0r",
                     r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\WannaCry"],
        file_written=[r"c:\users\admin\documents\report.wncry"],
        dlls_loaded=["advapi32","cryptsp","kernel32"],
        signatures=["allocates_rwx","antisandbox_foregroundwindows"],
    )
    return predict(req)

@app.get("/", response_class=HTMLResponse)
def dashboard():
    html_path = os.path.join(BASE, "dashboard.html")
    if os.path.exists(html_path):
        return open(html_path, encoding="utf-8").read()
    return "<h1>dashboard.html not found</h1>"
