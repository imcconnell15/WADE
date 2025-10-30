#!/usr/bin/env python3
# WADE Staging Daemon (Python, heuristic edition)
# - Watches Staging/full and Staging/light
# - Classifies E01 / mem / raw-dd / network_config via signatures (no heavy tools by default)
# - Per-file JSON event logs to /var/wade/logs/stage
# - Text log (rotating) to /var/wade/logs/stage/stage_daemon.log
# - Sorts host images to DataSources/Hosts/<hostname>/ and network configs to DataSources/Network/<hostname>/

import json, os, re, shutil, signal, sqlite3, subprocess, sys, time, string, uuid, logging, logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

# ---------- Config ----------
WADE_ENV = Path("/etc/wade/wade.env")
DEFAULT_OWNER = "autopsy"
DEFAULT_DATADIR = "DataSources"
DEFAULT_STAGINGDIR = "Staging"

SCAN_INTERVAL_SEC = int(os.environ.get("WADE_STAGE_SCAN_INTERVAL", "30"))

# COPY-FINISH guard
STABLE_SECONDS    = int(os.environ.get("WADE_STAGE_STABLE_SECONDS", "10"))
MIN_AGE_SECONDS   = int(os.environ.get("WADE_STAGE_MIN_AGE_SECONDS", "2"))
POLL_SECONDS      = float(os.environ.get("WADE_STAGE_POLL_SECONDS", "1.0"))
REQUIRE_CLOSED_FD = os.environ.get("WADE_STAGE_REQUIRE_CLOSED_FD", "0").lower() in ("1","true","yes")

# Heuristic scanning caps
HEAD_SCAN_BYTES   = int(os.environ.get("WADE_STAGE_HEAD_SCAN_BYTES", str(1024*1024)))       # 1 MiB
KDBG_SCAN_BYTES   = int(os.environ.get("WADE_STAGE_KDBG_SCAN_BYTES", str(32*1024*1024)))    # 32 MiB default
TEXT_SNIFF_BYTES  = int(os.environ.get("WADE_STAGE_TEXT_SNIFF_BYTES", str(128*1024)))       # 128 KiB
TEXT_MIN_PRINTABLE_RATIO = float(os.environ.get("WADE_STAGE_TEXT_MIN_PRINTABLE_RATIO", "0.92"))

# Optional tool probe for extension-less memory files
MEM_VOL_PROBE = os.environ.get("WADE_STAGE_MEM_VOL_PROBE", "0").lower() in ("1","true","yes")

STATE_DIR = Path("/var/wade/state")
LOG_ROOT  = Path("/var/wade/logs/stage")
TEXT_LOG  = LOG_ROOT / "stage_daemon.log"
STATE_DIR.mkdir(parents=True, exist_ok=True)
LOG_ROOT.mkdir(parents=True, exist_ok=True)
SQLITE_DB = STATE_DIR / "staging_index.sqlite3"

FRAGMENT_LOG: Optional[str] = None
STAGING_ROOT: Optional[Path] = None

INCOMPLETE_SUFFIXES = (".part", ".partial", ".tmp", ".crdownload", ".copying")

# ---- Logging ----
def init_logging() -> logging.Logger:
    level_name = os.environ.get("WADE_STAGE_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handlers = []
    try:
        TEXT_LOG.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(str(TEXT_LOG), maxBytes=5*1024*1024, backupCount=3))
    except Exception:
        pass
    handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(level=level, format="%(asctime)sZ %(levelname)s %(message)s", handlers=handlers)
    logging.Formatter.converter = time.gmtime  # force UTC in text log
    return logging.getLogger("wade.staging")

log = init_logging()

# ---- UTC helpers ----
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def utc_from_ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def ymd_from_path_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")

# Light helpers -------------------------------------------------------------
def load_wade_env():
    env = {}
    for k, v in os.environ.items():
        if k.startswith("WADE_"):
            env[k] = v
    try:
        if WADE_ENV.exists():
            for line in WADE_ENV.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line: 
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except PermissionError:
        pass
    return env

def run_cmd(cmd, timeout=10):
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(p) / cmd
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    # a few common extras we care about
    extras = [
        "/usr/local/bin/vol", "/usr/bin/vol", "/opt/pipx/venvs/volatility3/bin/vol",
        "/usr/local/bin/target-info", "/usr/bin/target-info",
        "/usr/local/bin/ewfinfo", "/usr/bin/ewfinfo",
        "/usr/sbin/lsof", "/usr/bin/lsof",
    ]
    base = Path(cmd).name
    for e in extras:
        if Path(e).name == base and Path(e).is_file() and os.access(e, os.X_OK):
            return e
    return None

def ensure_dirs(*paths):
    for p in paths: Path(p).mkdir(parents=True, exist_ok=True)

# ---- Strong “wait until finished” guard ----------------------------------
def wait_to_finish(path: Path,
                   stable_seconds: int = STABLE_SECONDS,
                   min_age_seconds: int = MIN_AGE_SECONDS,
                   poll_seconds: float = POLL_SECONDS,
                   require_closed_fd: bool = REQUIRE_CLOSED_FD) -> bool:
    if not path.exists():
        return False

    last_size = -1
    last_mtime_ns = -1
    remaining = stable_seconds
    lsof_path = which("lsof") if require_closed_fd else None

    while True:
        try:
            st = path.stat()
        except FileNotFoundError:
            return False

        if st.st_size == last_size and st.st_mtime_ns == last_mtime_ns:
            remaining -= poll_seconds
        else:
            last_size = st.st_size
            last_mtime_ns = st.st_mtime_ns
            remaining = stable_seconds

        if remaining <= 0:
            age = time.time() - st.st_mtime
            if age < min_age_seconds:
                time.sleep(max(poll_seconds, min_age_seconds - age))
                remaining = stable_seconds
                continue

            if lsof_path:
                rc, out, _ = run_cmd([lsof_path, "-t", "--", str(path)], timeout=5)
                if rc == 0 and out.strip():
                    time.sleep(poll_seconds)
                    remaining = stable_seconds
                    continue

            return True

        time.sleep(poll_seconds)

def fast_signature(path: Path) -> str:
    st = path.stat()
    return f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}"

def init_db():
    conn = sqlite3.connect(str(SQLITE_DB))
    conn.execute("""
    CREATE TABLE IF NOT EXISTS processed (
      sig TEXT PRIMARY KEY, path TEXT, size INTEGER, mtime_ns INTEGER,
      first_seen TEXT, last_seen TEXT, dest_path TEXT, classification TEXT, profile TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_path ON processed(path)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_last ON processed(last_seen)")
    conn.commit()
    return conn

def already_processed(conn, sig: str) -> bool:
    return conn.execute("SELECT 1 FROM processed WHERE sig=?", (sig,)).fetchone() is not None

def record_processed(conn, sig: str, path: Path, dest: Path, cls: str, profile: str):
    st = path.stat()
    now = utc_now_iso()
    conn.execute("""
    INSERT OR REPLACE INTO processed
    (sig, path, size, mtime_ns, first_seen, last_seen, dest_path, classification, profile)
    VALUES (?, ?, ?, ?, COALESCE((SELECT first_seen FROM processed WHERE sig=?), ?), ?, ?, ?, ?)
    """, (sig, str(path), st.st_size, st.st_mtime_ns, sig, now, now, str(dest), cls, profile))
    conn.commit()

def json_log(payload: dict, base_dir: Path = LOG_ROOT):
    # always include ts_utc
    payload.setdefault("ts_utc", utc_now_iso())
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = payload.get("original_name","item")
    safe = re.sub(r"[^A-Za-z0-9_.-]+","_", name)[:80]
    out = base_dir / f"stage_{ts}_{safe}.json"
    out.write_text(json.dumps(payload, indent=2)+"\n")
    return out

def read_head(path: Path, n: int) -> bytes:
    with path.open("rb") as f:
        return f.read(n)

def is_probably_text(path: Path) -> Tuple[bool, str]:
    try:
        data = read_head(path, min(TEXT_SNIFF_BYTES, path.stat().st_size))
        printable = set(bytes(string.printable, "ascii"))
        printable_ratio = sum(b in printable for b in data) / max(1, len(data))
        if printable_ratio >= TEXT_MIN_PRINTABLE_RATIO:
            try:
                return True, data.decode("utf-8", errors="ignore")
            except Exception:
                return True, data.decode("latin-1", errors="ignore")
        return False, ""
    except Exception:
        return False, ""

def resolve_queue_root(owner: str, datasources: Path, env: dict) -> Path:
    q = env.get("WADE_QUEUE_DIR", "_queue")
    qpath = Path(q)
    if qpath.is_absolute():
        return qpath
    return datasources / qpath

def write_json_atomic(path: Path, obj: dict):
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(obj, indent=2) + "\n")
    os.replace(tmp, path)

def enqueue_work(queue_root: Path, work: dict) -> Path:
    cls = work.get("classification", "unknown")
    prof = work.get("profile", "light")
    qdir = queue_root / cls / prof
    qdir.mkdir(parents=True, exist_ok=True)
    wid = work.get("id") or str(uuid.uuid4())
    wpath = qdir / f"{wid}.json"
    write_json_atomic(wpath, work)
    return wpath

# Heuristic detectors -------------------------------------------------------
def is_e01(path: Path) -> bool:
    if path.suffix.lower() == ".e01":
        return True
    rc, out, _ = run_cmd(["file","-b",str(path)], timeout=5)
    return ("EnCase" in out) or ("EWF" in out)

def detect_disk_image(path: Path) -> Optional[dict]:
    try:
        head = read_head(path, min(HEAD_SCAN_BYTES, path.stat().st_size))
        size = len(head)
        if size >= 520 and b"EFI PART" in head[512:520]:
            return {"kind":"gpt", "evidence":"EFI PART header"}
        if size >= 512 and head[510:512] == b"\x55\xaa":
            pt = head[446:446+64]
            if any(pt[i] != 0 for i in range(64)):
                return {"kind":"mbr", "evidence":"MBR 0x55AA + non-empty PT"}
            return {"kind":"mbr", "evidence":"MBR 0x55AA"}
        if size >= 512:
            if head[3:11] == b"NTFS    ":
                return {"kind":"fs", "evidence":"NTFS boot sig"}
            if b"FAT32" in head[0x40:0x90]:
                return {"kind":"fs", "evidence":"FAT32 label"}
    except Exception:
        pass
    return None

def name_looks_memory(path: Path) -> bool:
    n = path.name.lower()
    # cover names without dot extensions (e.g., "immamemoryfile")
    return any(s in n for s in (".mem", ".vmem", ".lime", "hiberfil", "winpmem", "rawmem", "ramdump", "memory", "memdump", "physmem"))

def detect_memory_dump(path: Path) -> Optional[dict]:
    try:
        head = read_head(path, min(max(HEAD_SCAN_BYTES, 4096), path.stat().st_size))
        if head[:4] in (b"HIBR", b"Hibr", b"hibr"):
            return {"kind":"hibernation", "evidence":"HIBR magic"}
        if head[:4] == b"LiME":
            return {"kind":"lime", "evidence":"LiME magic"}
        # KDBG scan window (configurable)
        if KDBG_SCAN_BYTES > 0:
            scan = read_head(path, min(KDBG_SCAN_BYTES, path.stat().st_size))
            if b"KDBG" in scan:
                return {"kind":"raw", "evidence":"KDBG observed"}
        # Name hint if not a disk
        if name_looks_memory(path) and not detect_disk_image(path):
            return {"kind":"raw", "evidence":"name hint (mem) and not disk"}
    except Exception:
        pass
    # Optional volatility probe (off by default)
    if MEM_VOL_PROBE:
        vol = os.environ.get("WADE_VOL_PATH") or which("vol")
        if vol:
            rc, out, _ = run_cmd([vol, "-f", str(path), "windows.info.Info"], timeout=45)
            if rc == 0 and re.search(r"\bSystemTime\b", out):
                return {"kind":"raw", "evidence":"volatility info probe"}
    return None

# Network configuration detection ------------------------------------------
NET_VENDOR = ("cisco_ios","juniper_junos","vyos_edgeos","arista_eos","mikrotik_ros")

def detect_cisco_ios(text: str) -> Optional[dict]:
    anchors = 0
    if re.search(r"(?im)^Building configuration\.\.\.", text): anchors += 1
    if re.search(r"(?im)^Current configuration\s*:", text): anchors += 1
    if re.search(r"(?im)^service (timestamps|password-encryption|call-home)", text): anchors += 1
    if re.search(r"(?im)^line vty\s+\d+", text): anchors += 1
    if anchors < 2: return None
    hostname = None
    m = re.search(r"(?im)^hostname\s+([A-Za-z0-9._-]+)", text)
    if m: hostname = m.group(1)
    os_version = None
    m = re.search(r"(?im)^(?:Cisco IOS.*Version|version)\s+([0-9A-Za-z.\(\)_-]+)", text)
    if m: os_version = m.group(1)
    return {"vendor":"cisco_ios","hostname":hostname,"os_version":os_version,"platform":None}

def detect_juniper_junos(text: str) -> Optional[dict]:
    if re.search(r"(?im)^\s*set\s+system\s+host-name\s+\S+", text) or "system {" in text:
        hostname = None
        m = re.search(r"(?im)^\s*set\s+system\s+host-name\s+(\S+)", text)
        if not m:
            m = re.search(r"(?s)system\s*{\s*[^}]*host-name\s+([A-Za-z0-9._-]+);", text)
        if m: hostname = m.group(1)
        return {"vendor":"juniper_junos","hostname":hostname,"os_version":None,"platform":None}
    return None

def detect_vyos_edgeos(text: str) -> Optional[dict]:
    if re.search(r"(?im)^\s*set\s+system\s+host-name\s+\S+", text) and "interfaces " in text:
        m = re.search(r"(?im)^\s*set\s+system\s+host-name\s+(\S+)", text)
        hostname = m.group(1) if m else None
        return {"vendor":"vyos_edgeos","hostname":hostname,"os_version":None,"platform":None}
    return None

def detect_arista_eos(text: str) -> Optional[dict]:
    if ("daemon TerminAttr" in text) or ("management api http-commands" in text):
        m = re.search(r"(?im)^hostname\s+([A-Za-z0-9._-]+)", text)
        hostname = m.group(1) if m else None
        return {"vendor":"arista_eos","hostname":hostname,"os_version":None,"platform":None}
    return None

def detect_mikrotik_ros(text: str) -> Optional[dict]:
    if "/interface" in text and "/ip " in text:
        m = re.search(r"(?im)^/system identity set name=(\S+)", text)
        hostname = m.group(1) if m else None
        return {"vendor":"mikrotik_ros","hostname":hostname,"os_version":None,"platform":None}
    return None

def detect_network_config(path: Path) -> Optional[dict]:
    ok, txt = is_probably_text(path)
    if not ok: return None
    for det in (detect_cisco_ios, detect_juniper_junos, detect_vyos_edgeos, detect_arista_eos, detect_mikrotik_ros):
        info = det(txt)
        if info:
            info["bytes_previewed"] = min(TEXT_SNIFF_BYTES, path.stat().st_size)
            info["line_count_preview"] = txt.count("\n")+1
            return info
    return None

# Optional best-effort metadata via tools ----------------------------------
def _json_deep_get_first_str(d):
    # walk nested dicts/lists to find first 'hostname'-ish key (case-insensitive)
    stack = [d]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(k, str) and k.lower() in ("hostname", "host_name", "computername", "computer_name"):
                    if isinstance(v, str) and v.strip():
                        return v.strip()
                stack.append(v)
        elif isinstance(x, list):
            stack.extend(x)
    return None

def best_effort_e01_meta(path: Path) -> Tuple[Optional[str], Optional[str]]:
    host = None
    datecol = None

    # Prefer Dissect's target-info JSON
    tgt = which("target-info")
    if tgt:
        rc, out, _ = run_cmd([tgt, str(path), "-j"], timeout=30)
        if rc == 0:
            try:
                j = json.loads(out)
                # try shallow then deep
                host = j.get("hostname") or _json_deep_get_first_str(j) or host
            except Exception:
                pass
        if host is None:
            # Plain-text fallback (your example format)
            rc, out, _ = run_cmd([tgt, str(path)], timeout=30)
            if rc == 0 and out:
                m = re.search(r"(?m)^Hostname\s*:\s*(\S+)", out)
                if m: host = m.group(1).strip()
                # install date is not "acquisition date" but gives a useful y-m-d
                m = re.search(r"(?m)^Install date\s*:\s*([^\n]+)", out)
                if m:
                    s = m.group(1)
                    m2 = re.search(r"(\d{4}-\d{2}-\d{2})", s)
                    if m2: datecol = m2.group(1)

    # ewfinfo for acquisition date (better “date collected”)
    ewf = which("ewfinfo")
    if ewf:
        rc, out, _ = run_cmd([ewf, str(path)], timeout=30)
        if rc == 0:
            m = re.search(r"(?i)Acquisition date\s*:\s*([^\n]+)", out)
            if m:
                s = m.group(1)
                m2 = re.search(r"(\d{4}-\d{2}-\d{2})", s)
                if m2:
                    datecol = m2.group(1)

    return host, datecol

def best_effort_mem_meta(path: Path) -> Tuple[Optional[str], Optional[str]]:
    vol = os.environ.get("WADE_VOL_PATH") or which("vol")
    if not vol:
        return None, None
    host = None
    rc, out, _ = run_cmd([vol, "-f", str(path), "windows.registry.hivelist"], timeout=45)
    if rc == 0:
        for line in out.splitlines():
            if "SYSTEM" in line:
                off = line.split()[0]
                rc2, out2, _ = run_cmd([vol, "-f", str(path), "windows.registry.printkey",
                                        "--offset", off, "--key",
                                        r"ControlSet001\\Control\\ComputerName\\ComputerName"], timeout=45)
                if rc2 == 0:
                    mm = re.search(r'ComputerName.*?"([^"]+)"', out2)
                    if mm: host = mm.group(1).strip()
                break
    datecol = None
    rc3, out3, _ = run_cmd([vol, "-f", str(path), "windows.info.Info"], timeout=45)
    if rc3 == 0:
        mm = re.search(r'(\d{4}-\d{2}-\d{2})', out3)
        if mm: datecol = mm.group(1)
    return host, datecol

# Classification orchestrator ----------------------------------------------
def fallback_date_from_fs(path: Path) -> str:
    return ymd_from_path_mtime(path)

def e01_fragmentation(path: Path) -> dict:
    base = path.with_suffix("")
    parts = sorted(p.name for p in path.parent.glob(f"{base.name}.E0[2-9]*"))
    return {"fragmented": len(parts)>0, "parts": parts}

def match_host_from_filename(datasources: Path, path: Path) -> Optional[str]:
    try:
        hosts_dir = datasources / "Hosts"
        if not hosts_dir.exists(): return None
        fn = path.stem.lower()
        candidates = [d.name for d in hosts_dir.iterdir() if d.is_dir()]
        for h in candidates:
            hl = h.lower()
            if fn == hl or fn.startswith(hl) or hl in fn:
                return h
    except Exception:
        pass
    return None

def classify(path: Path, datasources: Path) -> Tuple[str, dict]:
    ext = path.suffix.lower()

    # 0) extension-first
    if ext == ".e01":
        details = {"date_collected": fallback_date_from_fs(path),
                   "hostname": path.stem,
                   "fragmentation": e01_fragmentation(path)}
        h2, d2 = best_effort_e01_meta(path)
        if h2: details["hostname"] = h2
        if d2: details["date_collected"] = d2
        return "e01", details

    if ext in {".mem", ".vmem", ".lime"} or "hiberfil" in path.name.lower():
        details = {"date_collected": fallback_date_from_fs(path),
                   "hostname": path.stem,
                   "mem_signature": detect_memory_dump(path) or {"kind":"raw","evidence":"extension-based"}}
        h2, d2 = best_effort_mem_meta(path)
        if h2: details["hostname"] = h2
        if d2: details["date_collected"] = d2
        return "mem", details

    # 1) network configs (textual)
    net = detect_network_config(path)
    if net:
        return "network_config", net

    # 2) raw/dd: prefer disk then mem
    if ext in {".raw", ".dd"}:
        dsk = detect_disk_image(path)
        if dsk:
            return "disk_raw", {"disk_signature": dsk, "date_collected": fallback_date_from_fs(path)}
        mem = detect_memory_dump(path)
        if mem:
            h2, d2 = best_effort_mem_meta(path)
            return "mem", {"mem_signature": mem,
                           "date_collected": d2 or fallback_date_from_fs(path),
                           "hostname": h2 or path.stem}

    # 3) disk by magic
    dsk2 = detect_disk_image(path)
    if dsk2:
        return "disk_raw", {"disk_signature": dsk2, "date_collected": fallback_date_from_fs(path)}

    # 4) mem by magic (incl. optional vol-probe)
    mem2 = detect_memory_dump(path)
    if mem2:
        h2, d2 = best_effort_mem_meta(path)
        return "mem", {"mem_signature": mem2,
                       "date_collected": d2 or fallback_date_from_fs(path),
                       "hostname": h2 or path.stem}

    # 5) misc fallback into existing host “misc” if filename matches a known host
    mh = match_host_from_filename(datasources, path)
    if mh:
        return "misc", {"hostname": mh, "date_collected": fallback_date_from_fs(path)}

    return "unknown", {}

# Placement ----------------------------------------------------------------
def move_and_rename(path: Path, out_root: Path, classification: str, hostname: Optional[str], date_str: str) -> Path:
    if classification == "network_config":
        host = hostname or path.stem
        dest_dir = out_root / "Network" / host
        ensure_dirs(dest_dir)
        ext = path.suffix or ".cfg"
        dest = dest_dir / f"cfg_{host}_{date_str}{ext}"
    elif classification == "misc":
        host = hostname or "_unsorted"
        dest_dir = out_root / "Hosts" / host / "misc"
        ensure_dirs(dest_dir)
        dest = dest_dir / path.name
    else:
        host = hostname or path.stem
        dest_dir = out_root / "Hosts" / host
        ensure_dirs(dest_dir)
        ext = path.suffix
        if classification == "e01": ext = ".E01"
        elif classification == "mem": ext = ext if ext else ".mem"
        dest = dest_dir / f"{host}_{date_str}{ext}"

    i = 1
    while dest.exists():
        stem, ext = os.path.splitext(dest.name)
        dest = dest.with_name(f"{stem}__{i}{ext}"); i += 1
    try:
        path.rename(dest)
    except Exception:
        shutil.move(str(path), str(dest))
    return dest

def append_fragment_note(fragment_details: dict, dest: Path):
    global FRAGMENT_LOG
    if not fragment_details or not fragment_details.get("fragmented") or not FRAGMENT_LOG: return
    lines = [
        f"{dest}",
        "### Fragmentation Detected ###",
        "1) A fragmented .E01 image has been detected.",
        "2) Files found:",
        *[f"   - {p}" for p in fragment_details.get("parts", [])],
        "--------------------------------------------------",
        "### Handling Instructions ###",
        "1) On a Windows VM, open FTKImager.",
        "2) Mount the fragmented E01 (File -> Mount Image).",
        "3) Create a new E01 of the logical drive with fragmentation interval '0'.",
        "4) Place the defragmented file back into the staging share.",
        "--------------------------------------------------",
        ""
    ]
    with open(FRAGMENT_LOG, "a") as f: f.write("\n".join(lines))

# Main processing -----------------------------------------------------------
def process_one(conn, path: Path, out_root: Path, profile: str, owner_user: str, queue_root: Path):
    original_name = path.name

    # Skip obviously incomplete suffixes
    low = str(path).lower()
    if low.endswith(INCOMPLETE_SUFFIXES) or path.suffix.lower() in INCOMPLETE_SUFFIXES:
        log.debug(f"skip incomplete-suffix: {path}")
        return

    # Strong copy-finish guard
    if not wait_to_finish(path):
        return

    started = time.time()
    sig = fast_signature(path)

    # Duplicate guard → Staging/ignored
    if already_processed(conn, sig):
        if STAGING_ROOT:
            ignored = STAGING_ROOT / "ignored"
            ensure_dirs(ignored)
            dest_ignored = ignored / path.name
            try:
                path.rename(dest_ignored)
            except Exception:
                shutil.move(str(path), str(dest_ignored))
            json_log({
                "event":"staging_duplicate_ignored",
                "original_name":original_name,
                "full_path":str(dest_ignored),
                "profile":profile,
                "sig":sig,
                "size_bytes":dest_ignored.stat().st_size
            })
            log.info(f"duplicate → ignored: {dest_ignored}")
        return

    # Classify
    classification, details = classify(path, out_root)
    log.info(f"classified {path} → {classification}")

    if classification == "unknown":
        # one-time log + record to stop repeat spam
        json_log({
            "event":"staging_skipped_unknown","original_name":original_name,"full_path":str(path),
            "profile":profile,"sig":sig,"size_bytes":path.stat().st_size,"reason":"unrecognized file type"
        })
        record_processed(conn, sig, path, path, "unknown", profile)
        log.warning(f"unknown file type, recorded to prevent repeat logs: {path}")
        return

    # Derive common fields
    hostname = details.get("hostname") or None
    date_collected = details.get("date_collected") or fallback_date_from_fs(path)

    # Move/rename
    dest = move_and_rename(path, out_root, classification, hostname, date_collected)
    try:
        shutil.chown(dest, user=owner_user, group=owner_user)
        shutil.chown(dest.parent, user=owner_user, group=owner_user)
    except Exception:
        pass

    duration = time.time() - started

    if classification == "e01":
        append_fragment_note(details.get("fragmentation"), dest)

    payload = {
        "event":"staged",
        "profile":profile,
        "classification":classification,
        "original_name":original_name,
        "source_path":str(path),
        "dest_path":str(dest),
        "sig":sig,
        "size_bytes":dest.stat().st_size,
        "started_at_utc": utc_from_ts_iso(started),
        "finished_at_utc": utc_now_iso(),
        "duration_seconds":round(duration,3),
    }

    # Build work order
    work = {
        "schema": "wade.queue.workorder",
        "version": 1,
        "id": str(uuid.uuid4()),
        "created_utc": utc_now_iso(),
        "profile": profile,
        "classification": classification,
        "original_name": original_name,
        "source_host": os.uname().nodename,
        "dest_path": str(dest),
        "size_bytes": dest.stat().st_size,
        "sig": sig,
    }
    if classification in ("e01","mem"):
        work["hostname"] = hostname or Path(dest).stem
        work["date_collected"] = date_collected
    if classification == "network_config":
        work["vendor"] = details.get("vendor")
        work["os_version"] = details.get("os_version")
        work["hostname"] = details.get("hostname") or Path(dest).stem
    if classification == "misc":
        work["hostname"] = hostname or "_unsorted"

    queue_path = enqueue_work(queue_root, work)
    payload["queue_path"] = str(queue_path)

    if classification == "disk_raw":
        payload["evidence"] = details.get("disk_signature")
    elif classification == "mem":
        payload["evidence"] = details.get("mem_signature")

    json_log(payload)
    record_processed(conn, sig, dest, dest, classification, profile)
    log.info(f"staged → {classification} {dest} (queued {queue_path.name}) in {duration:.2f}s")

def build_paths():
    env = load_wade_env()
    owner = env.get("WADE_OWNER_USER", DEFAULT_OWNER)
    datadir_name = env.get("WADE_DATADIR", DEFAULT_DATADIR)
    staging_name = env.get("WADE_STAGINGDIR", DEFAULT_STAGINGDIR)

    home = Path(f"/home/{owner}")
    staging_root = home / staging_name
    staging_full = staging_root / "full"
    staging_light = staging_root / "light"
    datasources = home / datadir_name

    queue_root = resolve_queue_root(owner, datasources, env)
    ensure_dirs(queue_root)

    global FRAGMENT_LOG, STAGING_ROOT
    FRAGMENT_LOG = str(datasources / "images_to_be_defragmented.log")
    STAGING_ROOT = staging_root

    ensure_dirs(staging_full, staging_light, datasources / "Hosts", datasources / "Network", staging_root / "ignored")
    return owner, staging_full, staging_light, datasources, queue_root

def iter_files(d: Path):
    for p in d.glob("*"):
        if p.is_file() and not p.name.lower().endswith(INCOMPLETE_SUFFIXES):
            yield p

def main():
    owner, stage_full, stage_light, datasources, queue_root = build_paths()
    conn = init_db()
    stop = False
    def _sig(_a,_b): 
        nonlocal stop; stop = True
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    log.info("[*] WADE staging daemon (heuristic) running…")
    while not stop:
        try:
            for p in iter_files(stage_full):
                process_one(conn, p, datasources, profile="full", owner_user=owner, queue_root=queue_root)
            for p in iter_files(stage_light):
                process_one(conn, p, datasources, profile="light", owner_user=owner, queue_root=queue_root)
        except Exception as e:
            json_log({"event":"staging_error","error":repr(e),"ts_utc": utc_now_iso()})
            log.exception("staging_error")
        # sleep with early exit
        steps = max(1, int(SCAN_INTERVAL_SEC / POLL_SECONDS))
        for _ in range(steps):
            if stop: break
            time.sleep(POLL_SECONDS)
    log.info("[*] WADE staging daemon exiting.")

if __name__ == "__main__":
    main()
