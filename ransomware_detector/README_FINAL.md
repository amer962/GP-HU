# 🛡️ RansomShield

**AI-powered ransomware detection that stops threats based on behavior — not signatures.**

Built on the [MLRan dataset](https://github.com/faithfulco/mlran) — 4,880+ real ransomware samples across 64 families, spanning 2006–2024.

> 98.15% detection accuracy | 483 behavioral features | Catches zero-day attacks

---

## How It Works

Instead of matching file signatures like traditional antivirus, RansomShield watches *what a process actually does* — API calls, registry modifications, file operations, network activity. If the behavior matches ransomware patterns, it kills the process before it can finish encrypting your files.

```
Process Running
      ↓
Collect behavior (API calls, registry, files, network)
      ↓
Extract 483 features → ML Model
      ↓
< 70%  →  Safe, ignore
70–90% →  Suspicious, monitor closely
> 90%  →  Ransomware → Kill immediately
                ↓
        1. Freeze process
        2. Cut network access
        3. Save memory dump
        4. Terminate process
        5. Restore any encrypted files
```

---

## Quick Start

### Option A — Docker (Recommended)

No Python setup needed. Just Docker.

```bash
git clone https://github.com/YOUR_USERNAME/RansomShield.git
cd RansomShield/ransomware_detector
docker-compose up -d
```

API is now running at `http://localhost:8000`

Check it's working:
```bash
curl http://localhost:8000/health
# {"status": "ok", "model": "LogisticRegression", "features": 483}
```

Browse the interactive API docs:
```
http://localhost:8000/docs
```

---

### Option B — Run Locally (Windows)

**Requirements:** Python 3.9+, Windows 10/11, Administrator privileges

**1. Install dependencies**
```cmd
pip install scikit-learn pandas numpy joblib psutil pywin32 watchdog fastapi uvicorn
```

**2. Train the model**
```cmd
cd ransomware_detector
set MLRAN_PATH=..\mlran-main
py step1_train_model.py
```

Expected output:
```
Train: (3905, 483) — goodware=2040, ransomware=1865
Accuracy: 98.15%
✅ Model saved to models/
```

**3. Run the GUI**
```cmd
py gui.py
```

**4. Or run from terminal**
```cmd
py step5_main.py            # Full monitoring with kill chain
py step5_main.py --simulate # Safe test — no real malware needed
```

---

### Option C — Build a standalone .exe

```cmd
pip install pyinstaller
py build_exe.py
```

Output: `dist\RansomShield\RansomShield.exe` — copy the whole folder, double-click to run.

---

## Testing Without Real Malware

Run the built-in simulation — it replays real WannaCry behavior from the dataset:

```cmd
py step5_main.py --simulate
```

```
Result: 🔴 RANSOMWARE
Confidence: 88.26%
Triggered features:
  ✓ API:NtProtectVirtualMemory
  ✓ API:NtAllocateVirtualMemory
  ✓ SIGNATURE:allocates_rwx
  ✓ API:RegSetValueExW
  ...

Safe process (notepad): 🟢 SAFE — Confidence: 10.70%
```

For more realistic testing, use [RanSim](https://github.com/lawndoc/RanSim) inside a VM.

---

## VM + Docker Setup (Best for Lab Testing)

This is the recommended setup for safely testing against real ransomware samples:

```
Your Machine                      VM (isolated)
┌──────────────────┐              ┌─────────────────┐
│  Docker          │              │                 │
│  ┌────────────┐  │  HTTP :8000  │  vm_client.py   │
│  │ RansomShield│◄──────────────│  monitors procs │
│  │    API     │  │              │  sends behavior │
│  └────────────┘  │              │                 │
└──────────────────┘              └─────────────────┘
```

**On your machine — start the API:**
```cmd
docker-compose up -d
```

**Inside the VM — install and run the client:**
```cmd
pip install psutil requests
set RANSOMSHIELD_API=http://YOUR_HOST_IP:8000
py vm_client.py
```

Find your host IP with `ipconfig` — look for IPv4 Address.

---

## Project Structure

```
ransomware_detector/
├── api.py                      # REST API (FastAPI)
├── gui.py                      # Desktop GUI
├── vm_client.py                # Client to run inside VM
├── step1_train_model.py        # Train model from MLRan data
├── step2_feature_extractor.py  # Behavior → 483 feature vector
├── step3_monitor.py            # Live process monitor
├── step4_kill_chain.py         # Detection + kill logic
├── step5_main.py               # CLI entry point
├── step6_file_guard.py         # File backup + rollback
├── step7_decompiler.py         # Post-detection EXE analysis
├── build_exe.py                # Build standalone .exe
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements_api.txt
└── models/
    ├── mlran_model.pkl         # Pre-trained model (ready to use)
    ├── feature_cols.json       # Feature column order
    └── feature_names.json      # Feature ID → name mapping
```

---

## API Reference

**POST** `/predict` — Analyze a process

```json
{
  "pid": 1234,
  "process_name": "suspicious.exe",
  "api_calls": ["NtProtectVirtualMemory", "CryptEncrypt"],
  "reg_written": ["HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"],
  "file_written": ["c:\\users\\user\\documents\\report.docx"],
  "dlls_loaded": ["advapi32", "cryptsp"],
  "signatures": ["allocates_rwx"],
  "strings": ["kernel32.dll", "delete"]
}
```

Response:
```json
{
  "pid": 1234,
  "process_name": "suspicious.exe",
  "confidence": 0.9423,
  "verdict": "ransomware",
  "triggered_features": [
    "API:NtProtectVirtualMemory",
    "API:CryptEncrypt",
    "SIGNATURE:allocates_rwx"
  ]
}
```

**GET** `/health` — Check API status

**GET** `/docs` — Interactive Swagger UI

---

## Model Performance

| Metric | Value |
|--------|-------|
| Accuracy | 98.15% |
| Precision | 97% |
| Recall | 99% |
| F1-Score | 98% |
| False Positives | 12 / 975 test samples |
| False Negatives | 6 / 975 test samples |

Top features driving detection:
```
[+2.60]  STRING: "this program cannot be run in dos mode"
[+1.71]  API: LdrGetProcedureAddress
[+1.34]  API: NtAllocateVirtualMemory
[+1.28]  SIGNATURE: packer_entropy
[+0.98]  SIGNATURE: allocates_rwx
```

---

## Extra Features

**File Guard** — Before any suspicious process writes to a protected file (`.docx`, `.pdf`, `.jpg`, etc.), a backup is saved automatically. If ransomware is confirmed, all affected files are restored instantly.

**AI Decompiler** — After killing a process, the executable is analyzed automatically. Add your Anthropic API key for a full natural language report explaining what the malware does:
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
```

---

## Dataset

This project is built on the MLRan dataset:

```
Onwuegbuche, F. C., Olaoluwa, A., Jurcut, A. D., & Pasquale, L. (2025).
MLRan: A Behavioural Dataset for Ransomware Analysis and Detection.
arXiv:2505.18613
```

→ [github.com/faithfulco/mlran](https://github.com/faithfulco/mlran)

---

## ⚠️ Disclaimer

This project is for **research and educational purposes only**.
Never run real ransomware samples outside an isolated VM environment.
Always take a snapshot before testing.
