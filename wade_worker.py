#!/usr/bin/env python3
# WADE Queue Worker (with Hayabusa sub-worker)
# - Drains shared _queue work-orders created by stage_daemon.py
# - Dispatches tools by classification (e01 | mem | disk_raw | network_config)
# - Respects "full" vs "light" profile
# - Hayabusa runs against WinEvtLogs extracted by Dissect to: /home/<owner>/DataSources/Hosts/<hostname>/WinEvtLogs
# - Idempotent claiming via atomic rename into _inflight
# - Writes per-task JSON logs under /var/wade/logs/worker

import os, json, time, shutil, uuid, subprocess, signal, shlex
from pathlib import Path
from datetime import datetime

# ----------------------- Config -----------------------
WADE_ENV = Path("/etc/wade/wade.env")
WORKER_ENV = Path("/etc/wade/wade-worker.env")

DEFAULT_OWNER = "autopsy"
DEFAULT_DATADIR = "DataSources"
DEFAULT_QUEUE_DIR = "_queue"
LOG_ROOT = Path("/var/wade/logs/worker")
LOG_ROOT.mkdir(parents=True, exist_ok=True)

SCAN_INTERVAL = int(os.environ.get("WADE_WORKER_SCAN_INTERVAL", "10"))
MAX_PARALLEL = int(os.environ.get("WADE_WORKER_MAX_PARALLEL", "1"))
DEFAULT_TIMEOUT_SEC = int(os.environ.get("WADE_WORKER_TOOL_TIMEOUT_SEC", "1800"))  # 30 min
HOSTNAME = os.uname().nodename

def load_env_file(path: Path) -> dict:
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k,v = line.split("=",1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# ----------------------- Queue paths -----------------------
def resolve_paths():
    base = load_env_file(WADE_ENV)
    worker = load_env_file(WORKER_ENV)
    owner = base.get("WADE_OWNER_USER", DEFAULT_OWNER)
    datas = base.get("WADE_DATADIR", DEFAULT_DATADIR)
    qdir = base.get("WADE_QUEUE_DIR", DEFAULT_QUEUE_DIR)
    if qdir.startswith("/"):
        queue_root = Path(qdir)
    else:
        queue_root = Path(f"/home/{owner}/{datas}") / qdir
    inflight = queue_root / "_inflight" / HOSTNAME
    done = queue_root / "_done" / HOSTNAME
    failed = queue_root / "_failed" / HOSTNAME
    for d in (queue_root, inflight, done, failed):
        d.mkdir(parents=True, exist_ok=True)
    return queue_root, inflight, done, failed, owner, datas, worker

QUEUE_ROOT, INFLIGHT_ROOT, DONE_ROOT, FAILED_ROOT, OWNER, DATADIR_NAME, WORKER_KV = resolve_paths()

# ----------------------- Logging -----------------------
def log_event(event: dict):
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    wid = event.get("work_id", "noid")
    out = LOG_ROOT / f"worker_{ts}_{wid}.json"
    out.write_text(json.dumps(event, indent=2) + "\n")

def run_cmd(cmd, cwd=None, timeout=DEFAULT_TIMEOUT_SEC):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", repr(e)

# ----------------------- Claim / ack -----------------------
def claim_work(path: Path):
    """
    Atomically move a queue json into _inflight/<hostname>/ to claim.
    If move fails because file vanished, someone else claimed it.
    """
    try:
        dest = INFLIGHT_ROOT / path.name
        path.replace(dest)
        return dest
    except FileNotFoundError:
        return None
    except PermissionError:
        return None

def ack_done(path: Path):
    dest = DONE_ROOT / path.name
    try:
        path.replace(dest)
    except Exception:
        shutil.copy2(path, dest)
        path.unlink(missing_ok=True)

def ack_failed(path: Path):
    dest = FAILED_ROOT / path.name
    try:
        path.replace(dest)
    except Exception:
        shutil.copy2(path, dest)
        path.unlink(missing_ok=True)

# ----------------------- Tool Registry -----------------------
# Toggle tools via /etc/wade/wade-worker.env:
#   ENABLE_VOL3=1
#   ENABLE_BULK_EXTRACTOR=1
#   ENABLE_DISSECT=0
#   ENABLE_HAYABUSA=1
ENABLE_VOL3 = WORKER_KV.get("ENABLE_VOL3","1") == "1"
ENABLE_BULK = WORKER_KV.get("ENABLE_BULK_EXTRACTOR","1") == "1"
ENABLE_DISSECT = WORKER_KV.get("ENABLE_DISSECT","0") == "1"
ENABLE_HAYABUSA = WORKER_KV.get("ENABLE_HAYABUSA","1") == "1"

VOL_BIN = shutil.which("vol") or "/usr/local/bin/vol"
BULK_BIN = shutil.which("bulk_extractor") or "/usr/bin/bulk_extractor"
DISSECT_BIN = shutil.which("dissect") or "/usr/bin/dissect"  # placeholder

# Hayabusa location and command template
HAYA_BIN = shutil.which("hayabusa") or "/usr/local/bin/hayabusa"
HAYA_RULES_DIR = WORKER_KV.get("HAYA_RULES_DIR", "")  # e.g., /opt/hayabusa-rules
# Default template uses csv-timeline; override via HAYA_CMD_TEMPLATE if needed
HAYA_CMD_TEMPLATE = WORKER_KV.get(
    "HAYA_CMD_TEMPLATE",
    '{bin} csv-timeline -d "{evtx_dir}" -o "{out_dir}/timeline.csv"' + ('' if not HAYA_RULES_DIR else ' -r "{rules_dir}"')
)

def ensure_outdir(hostname: str, tool: str, work_id: str) -> Path:
    out = Path(f"/home/{OWNER}/{DATADIR_NAME}/Hosts/{hostname}/wade/{tool}/{work_id}")
    out.mkdir(parents=True, exist_ok=True)
    return out

# ----------------------- Specific tasks -----------------------
def task_vol3_basic(dest_path: str, hostname: str, work_id: str, profile: str) -> dict:
    if not ENABLE_VOL3 or not Path(VOL_BIN).exists():
        return {"tool":"vol3","status":"skipped","reason":"disabled_or_missing"}
    outdir = ensure_outdir(hostname, "vol3", work_id)
    results = {}
    cmds = [
        [VOL_BIN, "-f", dest_path, "windows.info"],
        [VOL_BIN, "-f", dest_path, "windows.pslist"],
    ]
    for cmd in cmds:
        name = "_".join(cmd[-1:])
        rc, out, err = run_cmd(cmd, timeout=900)
        (outdir / f"{name}.txt").write_text(out + ("\nERR:\n"+err if err else ""))
        results[name] = {"rc":rc}
    return {"tool":"vol3","status":"ok","outputs":list(results.keys())}

def task_bulk_extractor(dest_path: str, hostname: str, work_id: str, profile: str) -> dict:
    if not ENABLE_BULK or not Path(BULK_BIN).exists():
        return {"tool":"bulk_extractor","status":"skipped","reason":"disabled_or_missing"}
    outdir = ensure_outdir(hostname, "bulk_extractor", work_id)
    cmd = [BULK_BIN, "-o", str(outdir), dest_path]
    rc, out, err = run_cmd(cmd, timeout=DEFAULT_TIMEOUT_SEC)
    (outdir / "stdout.txt").write_text(out)
    (outdir / "stderr.txt").write_text(err)
    return {"tool":"bulk_extractor","status":"ok" if rc==0 else "error","rc":rc}

def task_dissect_quick(dest_path: str, hostname: str, work_id: str, profile: str) -> dict:
    # Placeholder task — customize to your Dissect module set for EVTX extraction
    if not ENABLE_DISSECT or not Path(DISSECT_BIN).exists():
        return {"tool":"dissect","status":"skipped","reason":"disabled_or_missing"}
    outdir = ensure_outdir(hostname, "dissect", work_id)
    cmd = [DISSECT_BIN, "--help"]
    rc, out, err = run_cmd(cmd, timeout=120)
    (outdir / "help.txt").write_text(out + ("\nERR:\n"+err if err else ""))
    return {"tool":"dissect","status":"ok" if rc==0 else "error","rc":rc}

def find_evtx_dir(hostname: str, dest_path: str):
    """
    Look for extracted Windows Event Logs folder for this host.
    Preferred: /home/<owner>/<DataSources>/Hosts/<hostname>/WinEvtLogs
    Fallbacks: winevt/Logs, EVTX, evtx
    """
    host_root = Path(dest_path).parent
    candidates = [
        host_root / "WinEvtLogs",
        host_root / "winevt" / "Logs",
        host_root / "EVTX",
        host_root / "evtx",
    ]
    for c in candidates:
        try:
            if c.exists() and any(p.suffix.lower() == ".evtx" for p in c.glob("*.evtx")):
                return c
        except Exception:
            pass
    return None

def task_hayabusa(evtx_dir: Path, hostname: str, work_id: str, profile: str) -> dict:
    if not ENABLE_HAYABUSA:
        return {"tool":"hayabusa","status":"skipped","reason":"disabled"}
    if not Path(HAYA_BIN).exists():
        return {"tool":"hayabusa","status":"skipped","reason":"binary_not_found","bin":HAYA_BIN}

    outdir = ensure_outdir(hostname, "hayabusa", work_id)
    cmd_str = HAYA_CMD_TEMPLATE.format(
        bin=HAYA_BIN,
        evtx_dir=str(evtx_dir),
        out_dir=str(outdir),
        rules_dir=HAYA_RULES_DIR
    )
    cmd = shlex.split(cmd_str)

    rc, out, err = run_cmd(cmd, timeout=DEFAULT_TIMEOUT_SEC)
    (outdir / "stdout.txt").write_text(out or "")
    (outdir / "stderr.txt").write_text(err or "")

    # small metadata marker
    try:
        (outdir / "meta.json").write_text(json.dumps({
            "hostname": hostname,
            "work_id": work_id,
            "evtx_dir": str(evtx_dir),
            "ran_at_utc": datetime.utcnow().isoformat() + "Z",
            "profile": profile
        }, indent=2))
    except Exception:
        pass

    return {
        "tool":"hayabusa",
        "status":"ok" if rc == 0 else "error",
        "rc": rc,
        "evtx_dir": str(evtx_dir),
        "out_dir": str(outdir),
        "cmd": cmd
    }

# ----------------------- Plans per classification -----------------------
def plan_for(work: dict) -> list:
    """
    Returns a list of task dicts {"name":..., "fn":callable}
    Plans differ for full vs light.
    """
    profile = work.get("profile","light")
    cls = work.get("classification","unknown")
    dest = work.get("dest_path")
    hostname = work.get("hostname") or Path(dest).stem
    wid = work.get("id") or uuid.uuid4().hex

    tasks = []

    if cls == "mem":
        # Memory: Volatility basic triage (if enabled)
        tasks.append({"name":"vol3_basic", "fn": lambda: task_vol3_basic(dest, hostname, wid, profile)})

    elif cls in ("disk_raw", "e01"):
        # Disk/E01: bulk_extractor is safe baseline
        tasks.append({"name":"bulk_extractor", "fn": lambda: task_bulk_extractor(dest, hostname, wid, profile)})

        # In full profile, run Dissect placeholder (replace with real EVTX extraction)
        if profile == "full":
            tasks.append({"name":"dissect_quick", "fn": lambda: task_dissect_quick(dest, hostname, wid, profile)})

        # Hayabusa: run if WinEvtLogs is present (either freshly extracted or pre-existing)
        def _hayabusa_wrapper():
            evtx = find_evtx_dir(hostname, dest)
            if not evtx:
                return {"tool":"hayabusa","status":"skipped","reason":"no_evtx_found"}
            return task_hayabusa(evtx, hostname, wid, profile)
        tasks.append({"name":"hayabusa", "fn": _hayabusa_wrapper})

    elif cls == "network_config":
        # Placeholder: later add lint/normalize/ship to Splunk
        tasks.append({"name":"network_config_ack", "fn": lambda: {"tool":"netcfg","status":"ok"}})

    else:
        tasks.append({"name":"noop", "fn": lambda: {"tool":"noop","status":"skipped","reason":"unknown_class"}})

    return tasks

# ----------------------- Main loop -----------------------
def find_candidates(queue_root: Path, limit=MAX_PARALLEL) -> list:
    # Walk known class/profile dirs; prefer oldest first
    candidates = []
    if not queue_root.exists():
        return []
    for cls_dir in queue_root.iterdir():
        if not cls_dir.is_dir() or cls_dir.name.startswith("_"):
            continue
        for prof_dir in cls_dir.iterdir():
            if not prof_dir.is_dir():
                continue
            for j in prof_dir.glob("*.json"):
                candidates.append(j)
                if len(candidates) >= limit:
                    break
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break
    candidates.sort(key=lambda p: p.stat().st_mtime)  # oldest first
    return candidates[:limit]

def process_one(json_path: Path):
    claimed = claim_work(json_path)
    if not claimed:
        return False  # someone else got it

    try:
        work = json.loads(claimed.read_text())
    except Exception as e:
        log_event({"event":"bad_workorder","path":str(json_path),"error":repr(e),"when":now_iso()})
        ack_failed(claimed)
        return True

    work_id = work.get("id") or uuid.uuid4().hex
    started = time.time()

    plan = plan_for(work)
    results = []
    status = "ok"

    for step in plan:
        try:
            res = step["fn"]()
        except Exception as e:
            res = {"tool":step.get("name","?"), "status":"error", "error":repr(e)}
        results.append(res)
        if res.get("status") == "error":
            status = "error"

    event = {
        "event":"work_complete",
        "work_id": work_id,
        "classification": work.get("classification"),
        "profile": work.get("profile"),
        "dest_path": work.get("dest_path"),
        "hostname": work.get("hostname"),
        "source_host": work.get("source_host"),
        "results": results,
        "status": status,
        "started_at_utc": datetime.utcfromtimestamp(started).isoformat() + "Z",
        "finished_at_utc": now_iso(),
        "duration_seconds": round(time.time()-started, 3),
        "worker_host": HOSTNAME,
    }
    log_event(event)

    if status == "ok":
        ack_done(claimed)
    else:
        ack_failed(claimed)
    return True

def main():
    stop=False
    def _sig(a,b):
        nonlocal stop; stop=True
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    print(f"[*] WADE worker on {HOSTNAME} watching: {QUEUE_ROOT}")
    while not stop:
        picked = find_candidates(QUEUE_ROOT, limit=MAX_PARALLEL)
        if not picked:
            time.sleep(SCAN_INTERVAL)
            continue
        for p in picked:
            process_one(p)

if __name__ == "__main__":
    main()
