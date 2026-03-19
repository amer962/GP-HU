# vm_client.py — يشتغل جوا الـ VM ويتصل بالـ API
# شغّله: py vm_client.py
# المتطلبات: pip install psutil requests

import os, time, requests, psutil, threading, logging

API_URL  = os.environ.get("RANSOMSHIELD_API", "http://localhost:8000")
INTERVAL = 5   # ثواني بين كل فحص

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("client")

SAFE_PROCS = {
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe',
    'explorer.exe', 'python.exe', 'py.exe', 'cmd.exe', 'powershell.exe'
}

def collect_behavior(proc: psutil.Process) -> dict:
    """يجمع سلوك العملية"""
    behavior = {
        "pid":          proc.pid,
        "process_name": proc.name(),
        "api_calls":    [],
        "reg_written":  [],
        "reg_opened":   [],
        "file_written": [],
        "file_created": [],
        "dlls_loaded":  [],
        "signatures":   [],
        "strings":      [],
    }

    try:
        # DLLs محملة
        for m in proc.memory_maps():
            if m.path.lower().endswith('.dll'):
                dll = os.path.basename(m.path).replace('.dll','').lower()
                behavior["dlls_loaded"].append(dll)
    except Exception: pass

    try:
        # ملفات مفتوحة
        for f in proc.open_files():
            behavior["file_created"].append(f.path.lower())
    except Exception: pass

    try:
        # اتصالات شبكية → signature
        conns = proc.connections(kind='inet')
        if conns:
            behavior["signatures"].append("network_http")
    except Exception: pass

    try:
        # CPU عالي → signature مشبوهة
        cpu = proc.cpu_percent(interval=0.1)
        if cpu > 80:
            behavior["signatures"].append("packer_entropy")
    except Exception: pass

    return behavior

def check_process(proc: psutil.Process):
    """يرسل سلوك العملية للـ API ويتصرف حسب النتيجة"""
    try:
        if proc.name().lower() in SAFE_PROCS:
            return

        behavior = collect_behavior(proc)

        # أرسل للـ API
        resp = requests.post(
            f"{API_URL}/predict",
            json=behavior,
            timeout=5
        )
        if resp.status_code != 200:
            return

        result = resp.json()
        verdict    = result["verdict"]
        confidence = result["confidence"]
        features   = result["triggered_features"]

        if verdict == "ransomware":
            log.critical(
                f"RANSOMWARE | PID={proc.pid} | {proc.name()} | "
                f"Conf={confidence:.1%} | Features={features[:3]}"
            )
            print(f"\n{'='*60}")
            print(f"  ⚠  RANSOMWARE DETECTED")
            print(f"  PID:        {proc.pid}")
            print(f"  Process:    {proc.name()}")
            print(f"  Confidence: {confidence:.1%}")
            print(f"  Features:   {', '.join(features[:5])}")
            print(f"{'='*60}\n")

            # إيقاف العملية
            try:
                proc.kill()
                log.critical(f"KILLED: {proc.name()} (PID={proc.pid})")
            except Exception as e:
                log.error(f"Kill failed: {e}")

        elif verdict == "suspicious":
            log.warning(
                f"SUSPICIOUS | PID={proc.pid} | {proc.name()} | "
                f"Conf={confidence:.1%}"
            )

    except requests.ConnectionError:
        log.error(f"Cannot connect to API at {API_URL} — is Docker running?")
    except Exception as e:
        log.debug(f"Error checking PID={proc.pid}: {e}")

def monitor_loop():
    log.info(f"RansomShield Client — API: {API_URL}")
    log.info("Monitoring all processes — Ctrl+C to stop")
    log.info("-" * 50)

    # تحقق من الـ API
    try:
        r = requests.get(f"{API_URL}/health", timeout=3)
        info = r.json()
        log.info(f"API connected — Model: {info['model']} | Features: {info['features']}")
    except Exception:
        log.error(f"API not reachable at {API_URL}")
        log.error("Make sure Docker container is running:")
        log.error("  docker-compose up -d")
        return

    stats = {"checked": 0, "suspicious": 0, "killed": 0}

    while True:
        try:
            procs = list(psutil.process_iter(['pid', 'name']))
            threads = []
            for proc in procs:
                t = threading.Thread(
                    target=check_process, args=(proc,), daemon=True
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=2)

            stats["checked"] += len(procs)
            log.info(f"Checked {len(procs)} processes | Total: {stats['checked']}")

        except KeyboardInterrupt:
            log.info("Stopped.")
            break
        except Exception as e:
            log.error(f"Loop error: {e}")

        time.sleep(INTERVAL)

if __name__ == "__main__":
    monitor_loop()
