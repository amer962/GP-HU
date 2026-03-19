# 🛡️ RansomShield — Behavioral Ransomware Detection System

> An AI-powered ransomware detection and response system that identifies threats based on **behavior**, not signatures — capable of catching zero-day attacks.

---

## Overview

RansomShield is a behavioral ransomware detection system built on the **MLRan dataset** — the largest open-source behavioral dataset for ransomware research.

- **Detection Accuracy:** 98.15%
- **Training Samples:** 4,880+ samples across 64 ransomware families
- **Features:** 483 behavioral features selected via Mutual Information + RFE
- **Model:** Logistic Regression
- **Dataset Coverage:** 2006 — 2024

---

## How It Works

```
Running Process
      ↓
Behavioral Monitoring (API calls, Registry, Files, Network)
      ↓
Extract 483 Behavioral Features
      ↓
ML Model → Confidence Score
      ↓
< 70%  → Safe
70-90% → Suspicious (enhanced monitoring)
> 90%  → Ransomware → Kill Chain activated
                ↓
    1. Freeze process immediately
    2. Block network access
    3. Memory dump for forensics
    4. Terminate process + children
    5. Restore affected files (Rollback)
```

---

## Project Structure

```
RansomShield/
│
├── ransomware_detector/
│   ├── gui.py                     # Graphical user interface
│   ├── step1_train_model.py       # Train model from MLRan data
│   ├── step2_feature_extractor.py # Convert behavior to feature vector
│   ├── step3_monitor.py           # Live process monitor
│   ├── step4_kill_chain.py        # Detection + automatic termination
│   ├── step5_main.py              # CLI entry point
│   ├── step6_file_guard.py        # Copy-on-Write + Rollback
│   ├── step7_decompiler.py        # AI-powered forensic decompiler
│   ├── build_exe.py               # Build standalone .exe
│   └── models/                    # Pre-trained model (ready to use)
│       ├── mlran_model.pkl
│       ├── feature_cols.json
│       └── feature_names.json
│
└── mlran-main/                    # MLRan dataset
    └── 6_experiments/
        └── FS_MLRan_Datasets/
            ├── MLRan_X_train_RFE.csv
            ├── MLRan_X_test_RFE.csv
            └── RFE_selected_feature_names_dic.json
```

---

## Installation & Usage

### Requirements
- Python 3.9+
- Windows 10/11
- Administrator privileges

### 1. Install dependencies
```cmd
pip install scikit-learn pandas numpy joblib psutil pywin32 watchdog
```

### 2. Train the model
```cmd
cd ransomware_detector
set MLRAN_PATH=..\mlran-main
py step1_train_model.py
```

### 3. Launch GUI
```cmd
py gui.py
```

### 4. Or run from CLI
```cmd
py step5_main.py             # Full monitoring with Kill Chain
py step5_main.py --simulate  # Safe simulation (no real malware needed)
```

### 5. Build standalone .exe
```cmd
pip install pyinstaller
py build_exe.py
```
Output: `dist\RansomShield\RansomShield.exe`

---

## Testing

### Safe simulation (no malware required)
```cmd
py step5_main.py --simulate
```
Simulates real WannaCry behavior using actual dataset samples.

Expected output:
```
Result: 🔴 RANSOMWARE
Confidence: 88.26%
Triggered features:
  ✓ API:NtProtectVirtualMemory
  ✓ API:NtAllocateVirtualMemory
  ✓ SIGNATURE:allocates_rwx
  ...

Safe process result: 🟢 SAFE — Confidence: 10.70%
```

### Using RanSim (simulates 22 ransomware types)
```
github.com/lawndoc/RanSim
```

### Inside a VM (recommended for real samples)
1. Launch VirtualBox or Windows Sandbox
2. Take a Snapshot before testing
3. Start RansomShield and enable protection
4. Run RanSim or a real sample
5. Observe detection results
6. Restore Snapshot when done

---

## Model Performance

| Metric | Value |
|--------|-------|
| Accuracy | 98.15% |
| Precision (Ransomware) | 97% |
| Recall (Ransomware) | 99% |
| F1-Score | 98% |
| False Positives | 12 / 975 |
| False Negatives | 6 / 975 |

---

## Behavioral Features (483 total)

| Category | Count | Examples |
|----------|-------|---------|
| STRING | 223 | Strings extracted from process memory |
| REG | 90 | Registry key modifications |
| API | 63 | NtProtectVirtualMemory, CryptEncrypt |
| SYSTEM | 38 | Loaded DLLs |
| DROP | 23 | Dropped file extensions |
| SIGNATURE | 20 | allocates_rwx, injection_runpe |
| FILE | 16 | File system operations |
| DIRECTORY | 10 | Directory operations |

---

## Key Features

### File Guard — Copy-on-Write + Rollback
Before any suspicious process modifies a file, a backup copy is saved automatically. If ransomware is confirmed, all affected files are instantly restored to their original state.

### AI Decompiler
After detection, the malicious executable is automatically analyzed. The system extracts suspicious API imports, disassembles the entry point, and generates a forensic report explaining the encryption algorithm used.

Requires `ANTHROPIC_API_KEY` for full AI analysis:
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
py step5_main.py
```

### Zero-Day Detection
Since detection is behavior-based rather than signature-based, RansomShield can detect unknown ransomware variants as long as they exhibit typical ransomware behavior patterns (mass file encryption, registry persistence, crypto API usage).

---

## Top Detection Features (from trained model)

```
[RANSOM ▲]  STRING: "this program cannot be run in dos mode"  (+2.599)
[RANSOM ▲]  API: LdrGetProcedureAddress                       (+1.707)
[RANSOM ▲]  API: NtAllocateVirtualMemory                      (+1.338)
[RANSOM ▲]  SIGNATURE: packer_entropy                         (+1.277)
[RANSOM ▲]  SIGNATURE: allocates_rwx                          (+0.979)
[SAFE   ▼]  API: CoUninitialize                               (-0.812)
[SAFE   ▼]  SYSTEM: DLL_LOADED: uxtheme.dll                   (-0.744)
```

---

## Dataset

MLRan dataset sourced from:

```
Onwuegbuche, F. C., Olaoluwa, A., Jurcut, A. D., & Pasquale, L. (2025).
MLRan: A Behavioural Dataset for Ransomware Analysis and Detection.
arXiv preprint arXiv:2505.18613
```

[github.com/faithfulco/mlran](https://github.com/faithfulco/mlran)

---

## ⚠️ Disclaimer

This project is intended for **research and educational purposes only**.  
Do not run real ransomware samples outside of an isolated VM environment.  
Always take a snapshot before testing.
