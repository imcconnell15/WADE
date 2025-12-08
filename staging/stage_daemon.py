#!/usr/bin/env python3
"""
WADE Staging Daemon – v2.3 (stability + dedupe race + env precedence + ops logging)

v2.4 (Current):
- Adjsuted memory image detection

Kept (v2.3):
- Optional requests import (Whiff no longer crashes daemon if not installed)
- Env precedence: environment variables override /etc/wade/wade.env
- enqueue_work() stray brace removed
- Content-dedupe race: catch UNIQUE(content_sig) IntegrityError post-move and treat as dup
- Defrag temp dir: try /var/wade/tmp, fall back to system tmp
- Unknowns quarantined to DataSources/Unknown to avoid infinite reprocessing
- quick_content_sig() accepts size_hint to reduce extra stats
- ETL hostname colocation retained from v2.2
- Pre-move stat retained to avoid FileNotFoundError on moved src
- NEW: Human-readable text logging to journald/stdout (toggle via WADE_TEXT_LOGS / WADE_TEXT_LOG_LEVEL)

Kept (v2.2/v2.1):
- Classifier registry and network-config detectors
- VM disk & package detection (qcow2, vhdx, vmdk, vdi, vhd; ova/ovf)
- Mountless OS hints (Linux/Windows/macOS)
- E01 magic (EVF...) + ewfinfo acquisition date + target-info hostname
- ETL guard so .etl is never considered memory
- Inotify CLOSE_WRITE gating + size-stable + optional lsof writer check
- Optional auto-defrag of fragmented E01 via ewfexport
- Troubleshooting-friendly logs (file(1) one-liner + hex head)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import string
import subprocess
import sys
import time
import uuid
import plistlib
import logging
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Any

# -----------------------------
# Optional inotify
# -----------------------------
try:
    from inotify_simple import INotify, flags
    INOTIFY_AVAILABLE = True
except Exception:
    INOTIFY_AVAILABLE = False

# -----------------------------
# Optional Whiff (requests is optional)
# -----------------------------
try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore

WHIFF_ENABLE = os.getenv("WHIFF_ENABLE", "1").lower() in ("1", "true", "yes")
WHIFF_URL = os.getenv("WHIFF_URL", "http://127.0.0.1:8088/annotate")

def whiff_annotate(ev: dict) -> dict:
    if not WHIFF_ENABLE or requests is None:
        return {}
    try:
        r = requests.post(WHIFF_URL, json={"event": ev}, timeout=3)
        j = r.json() if r is not None else {}
        return (j or {}).get("help", {}) or {}
    except Exception:
        return {"summary": "Whiff unavailable", "next_steps": [], "mitre": [], "refs": [], "confidence": 0.0}

# -----------------------------
# Configuration
# -----------------------------
WADE_ENV = Path("/etc/wade/wade.env")
DEFAULT_OWNER = "autopsy"
DEFAULT_DATADIR = "DataSources"
DEFAULT_STAGINGDIR = "Staging"

SCAN_INTERVAL_SEC = int(os.getenv("WADE_STAGE_SCAN_INTERVAL", "30"))
STABLE_SECONDS = int(os.getenv("WADE_STAGE_STABLE_SECONDS", "60"))  # safer default
REQUIRE_CLOSE_WRITE = os.getenv("WADE_STAGE_REQUIRE_CLOSE_WRITE", "1") == "1"
VERIFY_NO_WRITERS = os.getenv("WADE_STAGE_VERIFY_NO_WRITERS", "1") == "1"

HEAD_SCAN_BYTES = int(os.getenv("WADE_STAGE_HEAD_SCAN_BYTES", str(1024 * 1024)))
TEXT_SNIFF_BYTES = int(os.getenv("WADE_STAGE_TEXT_SNIFF_BYTES", str(128 * 1024)))
TEXT_MIN_PRINTABLE_RATIO = float(os.getenv("WADE_STAGE_TEXT_MIN_PRINTABLE_RATIO", "0.92"))

HEX_PREVIEW_BYTES = int(os.getenv("WADE_STAGE_HEX_PREVIEW_BYTES", "32"))

WADE_STAGE_RECURSIVE = os.getenv("WADE_STAGE_RECURSIVE", "0") == "1"

SMALL_FILE_BYTES = int(os.getenv("WADE_STAGE_SMALL_FILE_BYTES", str(2 * 1024 * 1024)))  # 2MiB
SMALL_FILE_STABLE = int(os.getenv("WADE_STAGE_SMALL_FILE_STABLE", "5"))

SIG_SAMPLE_BYTES = int(os.getenv("WADE_SIG_SAMPLE_BYTES", str(4 * 1024 * 1024)))  # 4MiB head+tail

MEM_MIN_BYTES = int(os.getenv("WADE_MEM_MIN_BYTES", str(100 * 1024 * 1024)))  # ~100MiB default

# Text logging toggles
WADE_TEXT_LOGS = os.getenv("WADE_TEXT_LOGS", "1").lower() in ("1", "true", "yes")
WADE_TEXT_LOG_LEVEL = os.getenv("WADE_TEXT_LOG_LEVEL", "INFO").upper()

# -----------------------------
# Globals
# -----------------------------
STATE_DIR: Path
LOG_ROOT: Path
SQLITE_DB: Path
STAGING_ROOT: Optional[Path] = None
FRAGMENT_LOG: Optional[Path] = None

# Module logger (configured in setup_logging() called from main())
log = logging.getLogger("wade.stage")

# -----------------------------
# Magic DB
# -----------------------------
def _sig(offset: int, blob: bytes) -> Tuple[int, bytes]:
    return (offset, blob)

MAGIC_DB: Dict[str, Tuple[Tuple[int, bytes], ...]] = {
    # EWF/E01: begins with EVF 09 0D 0A FF 00 ...
    "ewf": (_sig(0, b"EVF"),),
    # Disks
    "ntfs": (_sig(3, b"NTFS    "),),
    "fat32": (_sig(0x52, b"FAT32   "),),
    "gpt": (_sig(512, b"EFI PART"),),
    "mbr": (_sig(510, b"\x55\xaa"),),
    # VM disk formats
    "qcow": (_sig(0, b"QFI\xfb"),),
    "vhdx": (_sig(0x200, b"vhdxfile"),),
    "vmdk": (_sig(0, b"KDMV"),),           # streamOptimized/sparse header
    "vdi":  (_sig(0, b"\x7fVDI"),),
    # Tar/OVA (ustar)
    "tar_ustar": (_sig(257, b"ustar"),),
}

# -----------------------------
# Compiled regexes
# -----------------------------
_RE_HOSTNAME = re.compile(r"(?im)^hostname\s+([A-Za-z0-9._-]+)")

# -----------------------------
# Helpers
# -----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def utc_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ymd_from_mtime(p: Path) -> str:
    return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")

def load_env() -> Dict[str, str]:
    """Load /etc/wade/wade.env as defaults, then apply environment overrides (ENV wins)."""
    file_env: Dict[str, str] = {}
    if WADE_ENV.is_file():
        try:
            for line in WADE_ENV.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                file_env[k.strip()] = v.strip().strip('"\'')
        except Exception:
            pass
    env_overrides = {k: v for k, v in os.environ.items() if k.startswith("WADE_")}
    merged = {**file_env, **env_overrides}
    return merged

def which(cmd: str) -> Optional[str]:
    # Try PATH
    for p in os.getenv("PATH", "").split(os.pathsep):
        cand = Path(p) / cmd
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    # Common absolute fallbacks
    extras = (
        "/usr/local/bin/vol", "/usr/bin/vol", "/opt/pipx/venvs/volatility3/bin/vol",
        "/usr/local/bin/target-info", "/usr/bin/target-info",
        "/usr/local/bin/ewfinfo", "/usr/bin/ewfinfo",
        "/usr/local/bin/ewfexport", "/usr/bin/ewfexport",
        "/usr/bin/file", "/usr/local/bin/file",
        "/usr/bin/lsof", "/usr/sbin/lsof", "/bin/lsof",
    )
    name = Path(cmd).name
    for e in extras:
        if Path(e).name == name and Path(e).is_file() and os.access(e, os.X_OK):
            return e
    return None

VOL_PATH = os.getenv("WADE_VOL_PATH") or which("vol")
TARGET_INFO_PATH = which("target-info")
EWFINFO_PATH = which("ewfinfo")
EWFEXPORT_PATH = which("ewfexport")
FILE_CMD = which("file")
LSOF_CMD = which("lsof")

def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True, check=False
        )
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def ensure_dirs(*paths: Path) -> None:
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)

def fast_signature(p: Path) -> str:
    st = p.stat()
    return f"{st.st_dev}:{st.st_ino}:{st.st_size}:{int(st.st_mtime_ns)}"

def quick_content_sig(p: Path, sample_bytes: int = SIG_SAMPLE_BYTES, size_hint: Optional[int] = None) -> str:
    """Fast content fingerprint: sha256(head+tail)+size."""
    size = size_hint if size_hint is not None else p.stat().st_size
    if size == 0:
        return "0:0"
    if size <= 2 * sample_bytes:
        blob = p.read_bytes()
    else:
        with p.open("rb") as f:
            head = f.read(sample_bytes)
            f.seek(max(0, size - sample_bytes))
            tail = f.read(sample_bytes)
        blob = head + tail
    h = hashlib.sha256(blob).hexdigest()
    return f"{size}:{h}"

def safe_chown(path: Path, user: str, group: str) -> None:
    try:
        shutil.chown(path, user=user, group=group)
    except Exception:
        pass

def extract_text_snippet(p: Path, max_bytes: int = 512*1024) -> str:
    try:
        data = p.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

# -----------------------------
# I/O
# -----------------------------
def read_head_once(p: Path, max_bytes: int = HEAD_SCAN_BYTES) -> bytes:
    size = p.stat().st_size
    if size <= max_bytes:
        return p.read_bytes()
    chunk = 512 * 1024
    with p.open("rb") as f:
        head = f.read(min(chunk, max_bytes // 2))
        f.seek(max(0, size - chunk))
        tail = f.read(min(chunk, max_bytes // 2))
    return head + tail

def is_probably_text(p: Path) -> Tuple[bool, str]:
    try:
        data = p.read_bytes()[:TEXT_SNIFF_BYTES]
        printable = set(string.printable.encode("ascii"))
        ratio = sum(b in printable for b in data) / max(1, len(data))
        if ratio >= TEXT_MIN_PRINTABLE_RATIO:
            return True, data.decode("utf-8", errors="ignore")
        return False, ""
    except Exception:
        return False, ""

# -----------------------------
# SQLite
# -----------------------------
def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(SQLITE_DB), timeout=30.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS processed (
            sig TEXT PRIMARY KEY,
            src_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            dest_path TEXT NOT NULL,
            classification TEXT NOT NULL,
            profile TEXT NOT NULL,
            content_sig TEXT
        );
    """)
    # Migrate to add content_sig if missing
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(processed)").fetchall()}
        if "content_sig" not in cols:
            conn.execute("ALTER TABLE processed ADD COLUMN content_sig TEXT;")
    except sqlite3.OperationalError:
        pass
    # Unique by content (allows many NULLs)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_processed_content_sig ON processed(content_sig);")
    conn.commit()
    return conn

def already_processed(conn: sqlite3.Connection, sig: str) -> bool:
    return conn.execute("SELECT 1 FROM processed WHERE sig = ?", (sig,)).fetchone() is not None

def already_processed_by_content(conn: sqlite3.Connection, content_sig: Optional[str]) -> bool:
    if not content_sig:
        return False
    return conn.execute("SELECT 1 FROM processed WHERE content_sig = ?", (content_sig,)).fetchone() is not None

def record_processed_snapshot(conn: sqlite3.Connection, sig: str, src_path: str,
                              size: int, mtime_ns: int, dest: Path,
                              classification: str, profile: str,
                              content_sig: Optional[str] = None) -> None:
    now = utc_now_iso()
    conn.execute("""
        INSERT INTO processed (sig, src_path, size, mtime_ns, first_seen, last_seen, dest_path, classification, profile, content_sig)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sig) DO UPDATE SET
            src_path = excluded.src_path,
            size = excluded.size,
            mtime_ns = excluded.mtime_ns,
            last_seen = excluded.last_seen,
            dest_path = excluded.dest_path,
            classification = excluded.classification,
            profile = excluded.profile,
            content_sig = COALESCE(excluded.content_sig, processed.content_sig);
    """, (sig, src_path, size, mtime_ns, now, now, str(dest), classification, profile, content_sig))
    conn.commit()

# -----------------------------
# JSON Logging (machine)
# -----------------------------
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    import math
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def _daily_log_path() -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return LOG_ROOT / f"stage_{today}.log"

def json_log(event: str, **fields: Any) -> None:
    payload = {"timestamp_utc": utc_now_iso(), "event": event, **fields}
    line = json.dumps(payload, ensure_ascii=False)
    path = _daily_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

def debug_probe_file(p: Path) -> Dict[str, Any]:
    """Return 1-line file(1) string and hex head to help triage unknowns."""
    info = {}
    if FILE_CMD:
        rc, out, _ = run_cmd([FILE_CMD, "-b", str(p)], timeout=5)
        if rc == 0:
            info["file_one_liner"] = out.strip()
    try:
        with p.open("rb") as f:
            head = f.read(HEX_PREVIEW_BYTES)
        info["hex_head"] = " ".join(f"{b:02x}" for b in head)
    except Exception:
        pass
    return info

# -----------------------------
# Ops logging setup (human)
# -----------------------------
def setup_logging(source_host: str) -> logging.Logger:
    """
    Text logs -> journald (stdout). Keep JSON in /var/wade/logs/stage via json_log().
    UTC timestamps with trailing 'Z'. Toggle with WADE_TEXT_LOGS / WADE_TEXT_LOG_LEVEL.
    """
    logger = logging.getLogger("wade.stage")
    if logger.handlers:
        return logger

    if not WADE_TEXT_LOGS:
        # Attach a NullHandler so library importers don't see "No handler" warnings
        logger.addHandler(logging.NullHandler())
        return logger

    # Level
    level = getattr(logging, WADE_TEXT_LOG_LEVEL, logging.INFO)
    logger.setLevel(level)

    # Host filter to stamp host once
    class HostFilter(logging.Filter):
        def __init__(self, host: str): self.host = host
        def filter(self, record: logging.LogRecord) -> bool:
            record.host = self.host
            return True

    # UTC formatter
    import time as _time
    logging.Formatter.converter = _time.gmtime
    fmt = logging.Formatter("%(asctime)sZ %(levelname)s %(host)s %(message)s",
                            "%Y-%m-%dT%H:%M:%S")

    sh = logging.StreamHandler()  # journald picks this up from stdout
    sh.setFormatter(fmt)

    logger.addFilter(HostFilter(source_host))
    logger.addHandler(sh)
    return logger

# -----------------------------
# Classifier registry
# -----------------------------
Classifier = Callable[[Path, Path], Tuple[str, Dict[str, Any]]]
CLASSIFIERS: List[Classifier] = []

def register_classifier(fn: Classifier) -> Classifier:
    CLASSIFIERS.append(fn)
    return fn

# -----------------------------
# Network Config Detectors
# -----------------------------
def _cisco_ios(text: str) -> Optional[Dict[str, Any]]:
    anchors = 0
    if re.search(r"(?im)^Building configuration\.\.\.", text): anchors += 1
    if re.search(r"(?im)^Current configuration\s*:", text): anchors += 1
    if re.search(r"(?im)^service (timestamps|password-encryption|call-home)", text): anchors += 1
    if re.search(r"(?im)^line vty\s+\d+", text): anchors += 1
    if anchors < 2: return None
    m_host = _RE_HOSTNAME.search(text)
    m_ver = re.search(r"(?im)^(?:Cisco IOS.*Version|version)\s+([0-9A-Za-z.\(\)_-]+)", text)
    return {"vendor": "cisco_ios", "hostname": m_host.group(1) if m_host else None,
            "os_version": m_ver.group(1) if m_ver else None, "platform": "IOS"}

def _cisco_asa(text: str) -> Optional[Dict[str, Any]]:
    if "ASA Version" not in text and "Cisco Adaptive Security Appliance" not in text:
        return None
    m_ver = re.search(r"ASA Version\s+([0-9.]+)", text)
    m_host = _RE_HOSTNAME.search(text)
    m_serial = re.search(r"Hardware:\s+.*,\s+([A-Z0-9]{11})", text)
    return {"vendor": "cisco_asa", "hostname": m_host.group(1) if m_host else None,
            "os_version": m_ver.group(1) if m_ver else None, "platform": "ASA",
            "serial": m_serial.group(1) if m_serial else None}

def _fortigate(text: str) -> Optional[Dict[str, Any]]:
    tl = text.lower()
    if not (re.search(r'(?im)^\s*#?\s*config[-_ ]version\s*[:=]\s*', text) or "fortigate" in tl):
        return None
    m_ver = re.search(r'(?im)config[-_ ]version\s*[:=]\s*([0-9A-Za-z.\-_]+)', text)
    m_host = re.search(r'(?im)^\s*set\s+hostname\s+"?([A-Za-z0-9._-]+)"?', text)
    return {
        "vendor": "fortinet_fortigate",
        "hostname": m_host.group(1) if m_host else None,
        "os_version": m_ver.group(1) if m_ver else None,
        "platform": "FortiGate",
    }

def _paloalto(text: str) -> Optional[Dict[str, Any]]:
    if "set deviceconfig system hostname" not in text and "<panos>" not in text:
        return None
    m_host = re.search(r"set deviceconfig system hostname\s+([A-Za-z0-9._-]+)", text)
    m_ver = re.search(r"sw-version\s+([0-9.]+)", text)
    return {"vendor": "paloalto_panos", "hostname": m_host.group(1) if m_host else None,
            "os_version": m_ver.group(1) if m_ver else None, "platform": "PAN-OS"}

def _juniper_screenos(text: str) -> Optional[Dict[str, Any]]:
    if "ScreenOS" not in text or "set hostname" not in text:
        return None
    m_host = re.search(r"set hostname\s+\"?([A-Za-z0-9._-]+)\"?", text)
    m_ver = re.search(r"ScreenOS\s+([0-9.]+)", text)
    return {"vendor": "juniper_screenos", "hostname": m_host.group(1) if m_host else None,
            "os_version": m_ver.group(1) if m_ver else None, "platform": "ScreenOS"}

def _checkpoint_gaia(text: str) -> Optional[Dict[str, Any]]:
    if "set hostname" not in text or "Gaia" not in text:
        return None
    m_host = re.search(r"set hostname\s+([A-Za-z0-9._-]+)", text)
    m_ver = re.search(r"Gaia\s+R([0-9.]+)", text)
    return {"vendor": "checkpoint_gaia", "hostname": m_host.group(1) if m_host else None,
            "os_version": m_ver.group(1) if m_ver else None, "platform": "Gaia"}

def _juniper_junos(text: str) -> Optional[Dict[str, Any]]:
    if "set system host-name" not in text:
        return None
    m_host = re.search(r"set\s+system\s+host-name\s+(\S+)", text)
    return {"vendor": "juniper_junos", "hostname": m_host.group(1) if m_host else None,
            "platform": "Junos"}

def _vyos_edgeos(text: str) -> Optional[Dict[str, Any]]:
    if "set system host-name" not in text or "interfaces" not in text:
        return None
    m_host = re.search(r"set\s+system\s+host-name\s+(\S+)", text)
    return {"vendor": "vyos_edgeos", "hostname": m_host.group(1) if m_host else None,
            "platform": "VyOS/EdgeOS"}

def _arista_eos(text: str) -> Optional[Dict[str, Any]]:
    if "daemon TerminAttr" not in text and "management api http-commands" not in text:
        return None
    m_host = _RE_HOSTNAME.search(text)
    return {"vendor": "arista_eos", "hostname": m_host.group(1) if m_host else None,
            "platform": "EOS"}

def _mikrotik_ros(text: str) -> Optional[Dict[str, Any]]:
    if "/interface" not in text or "/ip " not in text:
        return None
    m_host = re.search(r"/system identity set name=(\S+)", text)
    return {"vendor": "mikrotik_ros", "hostname": m_host.group(1) if m_host else None,
            "platform": "RouterOS"}

_NETWORK_DETECTORS = (
    _cisco_asa, _fortigate, _paloalto, _juniper_screenos, _checkpoint_gaia,
    _cisco_ios, _juniper_junos, _vyos_edgeos, _arista_eos, _mikrotik_ros,
)

# -----------------------------
# Core Heuristics: E01
# -----------------------------
def _has_magic_at(buf: bytes, off: int, sig: bytes) -> bool:
    if off < 0 or off + len(sig) > len(buf):
        return False
    return buf[off:off+len(sig)] == sig

def is_e01(p: Path) -> bool:
    if p.suffix.lower() == ".e01":
        return True
    head = read_head_once(p, 1024)
    return any(_has_magic_at(head, off, sig) for off, sig in MAGIC_DB["ewf"])

def e01_fragmentation(p: Path) -> Dict[str, Any]:
    base = p.with_suffix("")
    parts = sorted(f.name for f in p.parent.glob(f"{base.name}.E0[2-9]*") if f.is_file())
    return {"fragmented": bool(parts), "parts": parts}

def _parse_ewfinfo_acq_date(txt: str) -> Optional[str]:
    # Acquisition date: Thu May 15 07:28:46 2025
    m = re.search(r"Acquisition date\s*:\s*([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})", txt)
    if not m:
        return None
    raw = m.group(1)
    try:
        dt = datetime.strptime(raw, "%a %b %d %H:%M:%S %Y")
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return None

@register_classifier
def classify_e01(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    if not is_e01(p):
        return "", {}
    hostname = p.stem
    date_col = ymd_from_mtime(p)

    # Prefer ewfinfo acquisition date
    if EWFINFO_PATH:
        rc, out, _ = run_cmd([EWFINFO_PATH, str(p)], timeout=30)
        if rc == 0:
            maybe = _parse_ewfinfo_acq_date(out)
            if maybe:
                date_col = maybe

    # Prefer target-info hostname
    if TARGET_INFO_PATH:
        rc, out, _ = run_cmd([TARGET_INFO_PATH, "-j", str(p)], timeout=30)
        if rc == 0:
            try:
                j = json.loads(out)
                if j.get("hostname"):
                    hostname = j["hostname"]
            except Exception:
                pass

    return "e01", {
        "hostname": hostname,
        "date_collected": date_col,
        "fragmentation": e01_fragmentation(p),
    }

# -----------------------------
# Memory
# -----------------------------

def name_looks_memory(p: Path) -> bool:
    n = p.name.lower()
    return any(k in n for k in (".mem", ".vmem", "hiberfil", "hibernat", "winpmem", "rawmem", ".lime"))

def detect_memory_dump(p: Path) -> Optional[Dict[str, str]]:
    """
    Decide whether this file is a memory dump.

    Order of operations:
      1) Header magic (hibernation / LiME) – strongest signal.
      2) Size gate for "raw" dumps (MEM_MIN_BYTES).
      3) Volatility probe (preferred when available).
      4) Filename hints (name_looks_memory) as a fallback for big files.

    NOTE: This is intentionally *content-first*. We do not rely on the filename,
    and we treat a successful Volatility probe as authoritative even when the
    extension or file(1) string is misleading (e.g. ETL-based captures).
    """
    # 1) Header magic
    head = read_head_once(p, 4096)
    size = p.stat().st_size

    # Windows hibernation file
    if head.startswith(b"HIBR"):
        return {"kind": "hiber", "evidence": "HIBR magic"}

    # LiME header (Linux Memory Extractor)
    if b"Lime" in head[:4096]:
        return {"kind": "lime", "evidence": "LiME header"}

    # 2) Size gate: very small files are almost never full dumps
    if size < MEM_MIN_BYTES and not name_looks_memory(p):
        return None

    # 3) Volatility probes
    if VOL_PATH:
        # Windows
        rc, out, err = run_cmd([VOL_PATH, "-f", str(p), "windows.info.Info"], timeout=120)
        if rc == 0:
            # Look for core fields that only show up on a valid Windows memory layer
            if ("NtSystemRoot" in out) or ("Kernel Base" in out) or re.search(r"\bwindows\b", out, re.IGNORECASE):
                return {"kind": "raw", "evidence": "volatility windows.info"}

        # Linux
        rc, out, err = run_cmd([VOL_PATH, "-f", str(p), "linux.banner.Banner"], timeout=120)
        if rc == 0 and ("Linux version" in out or "Linux" in out):
            return {"kind": "raw", "evidence": "volatility linux.banner"}

    # 4) Fallback: big file + name smells like memory
    if name_looks_memory(p):
        return {"kind": "raw", "evidence": "filename_hint"}

    return None

def best_effort_mem_meta(p: Path) -> Tuple[Optional[str], Optional[str]]:
    if not VOL_PATH:
        return None, None
    # Try to extract ComputerName
    rc, out, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.registry.hivelist"], timeout=60)
    host = None
    if rc == 0:
        for line in out.splitlines():
            if "SYSTEM" in line:
                offset = line.split()[0]
                rc2, out2, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.registry.printkey",
                                        "--offset", offset, "--key",
                                        r"ControlSet001\Control\ComputerName\ComputerName"], timeout=60)
                if rc2 == 0:
                    m = re.search(r'ComputerName.*?"([^"]+)"', out2)
                    if m:
                        host = m.group(1)
                break
    # Date (very rough)
    rc3, out3, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.info.Info"], timeout=60)
    date = None
    if rc3 == 0:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", out3)
        if m:
            date = m.group(1)
    return host, date

@register_classifier
def classify_memory(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    sig = detect_memory_dump(p)
    if not sig:
        return "", {}

    hostname = p.stem
    date_col = ymd_from_mtime(p)
    meta = {
        "hostname": hostname,
        "date_collected": date_col,
        "mem_signature": sig,
    }

    if not VOL_PATH:
        return "mem", meta

    # Try Windows first
    rc, out, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.info.Info"], timeout=90)
    score = 0
    if rc == 0:
        m_ver = re.search(r"Image\s+version:\s+([\d.]+)", out)
        m_build = re.search(r"Build\s+number:\s+(\d+)", out)
        m_ed = re.search(r"Edition:\s+(.+)", out)
        m_arch = re.search(r"Architecture:\s+(\w+)", out)

        if m_ver:
            meta["os"] = "Windows"; meta["version"] = m_ver.group(1); score += 30
        if m_build:
            meta["build"] = m_build.group(1); score += 25
        if m_ed:
            edition = m_ed.group(1).lower()
            meta["edition"] = "Server" if "server" in edition else "Workstation"; score += 20
        if m_arch:
            meta["arch"] = m_arch.group(1); score += 15

        h, d = best_effort_mem_meta(p)
        if h: meta["hostname"] = h; score += 10
        if d: meta["date_collected"] = d
    else:
        # Try Linux
        rc2, out2, _ = run_cmd([VOL_PATH, "-f", str(p), "linux.uname.Uname"], timeout=60)
        if rc2 == 0 and "Linux version" in out2:
            meta["os"] = "Linux"; score += 30
            m_kern = re.search(r"Linux version ([^\s]+)", out2)
            if m_kern:
                meta["kernel"] = m_kern.group(1); score += 25

    meta["confidence"] = min(100, score)
    return "mem", meta

# -----------------------------
# VM & Disk Detection
# -----------------------------
def _mountless_os_detect_from_text(text: str) -> Tuple[Dict[str, Any], int]:
    meta: Dict[str, Any] = {}
    score = 0

    m_osrel = re.search(r"PRETTY_NAME=\"?([^\"]+)\"?", text)
    if m_osrel:
        pretty = m_osrel.group(1)
        meta["os"] = "Linux"; meta["distro"] = pretty; score += 30
        m_ver = re.search(r"VERSION_ID=\"?([^\"]+)\"?", text)
        if m_ver:
            meta["version"] = m_ver.group(1); score += 25
        meta["arch"] = "x86_64" if "64" in text else "x86"; score += 15
        return meta, min(100, score)

    if re.search(r"Microsoft\\Windows NT\\CurrentVersion", text, re.I):
        meta["os"] = "Windows"; score += 30
        m_ver = re.search(r"CurrentVersion[\s=]+([0-9.]+)", text)
        if m_ver:
            meta["version"] = m_ver.group(1); score += 25
        m_build = re.search(r"CurrentBuild[\s=]+(\d+)", text)
        if m_build:
            meta["build"] = m_build.group(1); score += 20
        meta["edition"] = "Server" if "Server" in text else "Workstation"; score += 15
        return meta, min(100, score)

    if "com.apple.SystemVersion" in text:
        # Parsing deferred to plist bytes
        return {}, 0

    return {}, 0

def _mountless_os_enrich_from_plist_bytes(p: Path, meta: Dict[str, Any], score: int) -> Tuple[Dict[str, Any], int]:
    try:
        win = read_head_once(p, 2 * 1024 * 1024)
        m = re.search(b"<plist.*?</plist>", win, re.DOTALL)
        if not m and len(win) < 2 * 1024 * 1024:
            blob = p.read_bytes()[:4 * 1024 * 1024]
            m = re.search(b"<plist.*?</plist>", blob, re.DOTALL)
        if m:
            pl = plistlib.loads(m.group(0))
            meta["os"] = "macOS"
            meta["version"] = pl.get("ProductVersion", "")
            meta["build"] = pl.get("ProductBuildVersion", "")
            score += 55
    except Exception:
        pass
    return meta, min(100, score)

def detect_disk_image(p: Path) -> Optional[Dict[str, str]]:
    head = read_head_once(p)
    if any(_has_magic_at(head, off, sig) for off, sig in MAGIC_DB["gpt"]):
        return {"kind": "gpt", "evidence": "EFI PART header"}
    if any(_has_magic_at(head, off, sig) for off, sig in MAGIC_DB["mbr"]):
        pt = head[446:510]
        if any(pt):
            return {"kind": "mbr", "evidence": "MBR 0x55AA + PT"}
        return {"kind": "mbr", "evidence": "MBR 0x55AA"}
    if any(_has_magic_at(head, off, sig) for off, sig in MAGIC_DB["ntfs"]):
        return {"kind": "ntfs", "evidence": "NTFS boot"}
    if any(_has_magic_at(head, off, sig) for off, sig in MAGIC_DB["fat32"]):
        return {"kind": "fat32", "evidence": "FAT32 label"}
    return None

def detect_vm_image(p: Path) -> Optional[Dict[str, str]]:
    buf = read_head_once(p, max(HEAD_SCAN_BYTES, 1024 * 1024))
    if any(_has_magic_at(buf, off, sig) for off, sig in MAGIC_DB["qcow"]):
        return {"format": "qcow2", "evidence": "QFI\\xfb magic at 0"}
    if any(_has_magic_at(buf, off, sig) for off, sig in MAGIC_DB["vhdx"]):
        return {"format": "vhdx", "evidence": "vhdxfile at 0x200"}
    if any(_has_magic_at(buf, off, sig) for off, sig in MAGIC_DB["vmdk"]):
        return {"format": "vmdk", "evidence": "KDMV header"}
    if any(_has_magic_at(buf, off, sig) for off, sig in MAGIC_DB["vdi"]):
        return {"format": "vdi", "evidence": "Oracle VDI header"}
    tail = buf[-1024:]
    if b"conectix" in tail:
        return {"format": "vhd", "evidence": "conectix footer"}
    return None

def detect_vm_package(p: Path) -> Optional[Dict[str, str]]:
    head = read_head_once(p, 512 * 1024)
    if any(_has_magic_at(head, off, sig) for off, sig in MAGIC_DB["tar_ustar"]):
        return {"pkg": "ova", "evidence": "ustar tar header"}
    ok, txt = is_probably_text(p)
    if ok and "<Envelope" in txt and "schemas.dmtf.org/ovf/envelope/1" in txt:
        return {"pkg": "ovf", "evidence": "OVF XML envelope"}
    return None

@register_classifier
def classify_disk_raw(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    sig = detect_disk_image(p)
    if not sig:
        return "", {}
    meta = {"disk_signature": sig, "date_collected": ymd_from_mtime(p)}
    text = extract_text_snippet(p, 1024*1024)
    os_meta, score = _mountless_os_detect_from_text(text)
    if "os" not in os_meta and "com.apple.SystemVersion" in text:
        os_meta, score = _mountless_os_enrich_from_plist_bytes(p, os_meta, score)
    meta.update(os_meta); meta["confidence"] = score
    return "disk_raw", meta

WADE_STAGE_ACCEPT_DOCS = os.getenv("WADE_STAGE_ACCEPT_DOCS", "0") == "1"

@register_classifier
def classify_net_docs(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    # optional doc classifier
    if not WADE_STAGE_ACCEPT_DOCS:
        return "", {}
    if p.suffix.lower() not in (".md", ".rst", ".adoc", ".txt"):
        return "", {}
    ok, txt = is_probably_text(p)
    if not ok:
        return "", {}
    if any(k in txt.lower() for k in ("site-to-site", "azure vnet", "paloalto", "fortigate", "ipsec")) \
       and not any(k in txt for k in ("set hostname", "Building configuration")):
        return "network_doc", {"date_collected": ymd_from_mtime(p)}
    return "", {}

@register_classifier
def classify_vm_disk(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    sig = detect_vm_image(p)
    if not sig:
        return "", {}
    meta = {"format": sig["format"], "date_collected": ymd_from_mtime(p)}
    text = extract_text_snippet(p, 1024*1024)
    os_meta, score = _mountless_os_detect_from_text(text)
    if "os" not in os_meta and "com.apple.SystemVersion" in text:
        os_meta, score = _mountless_os_enrich_from_plist_bytes(p, os_meta, score)
    meta.update(os_meta); meta["confidence"] = score
    return "vm_disk", meta

@register_classifier
def classify_vm_package(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    sig = detect_vm_package(p)
    if not sig:
        return "", {}
    return "vm_package", {"package": sig.get("pkg"), "date_collected": ymd_from_mtime(p)}

# -----------------------------
# Network config classifier
# -----------------------------
@register_classifier
def classify_network_cfg(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    ok, txt = is_probably_text(p)
    if not ok:
        return "", {}

    preview = "\n".join(txt.splitlines()[:3])
    stats = {"size_bytes": p.stat().st_size,
             "line_count": txt.count("\n") + 1,
             "entropy": calculate_entropy(p.read_bytes()[:TEXT_SNIFF_BYTES])}

    best_score = 0; best_info = None
    for det in _NETWORK_DETECTORS:
        info = det(txt)
        if not info:
            continue
        score = 0
        if info.get("hostname"): score += 30
        if info.get("os_version"): score += 25
        if info.get("platform"): score += 15
        if info.get("serial"): score += 20
        if score > best_score:
            best_score = score; best_info = info

    if best_info:
        best_info.update({"confidence": min(100, best_score),
                          "preview_lines": preview, **stats})
        return "network_config", best_info
    return "", {}

# -----------------------------
# Misc fallback 
# -----------------------------
def match_host_from_filename(datasources: Path, p: Path) -> Optional[str]:
    hosts_dir = datasources / "Hosts"
    if not hosts_dir.is_dir():
        return None
    stem = p.stem.lower()
    for d in hosts_dir.iterdir():
        if d.is_dir() and (stem == d.name.lower() or stem.startswith(d.name.lower())):
            return d.name
    return None

@register_classifier
def classify_misc(p: Path, datasources: Path) -> Tuple[str, Dict[str, Any]]:
    host = match_host_from_filename(datasources, p)
    if host:
        return "misc", {"hostname": host, "date_collected": ymd_from_mtime(p)}
    return "", {}

# -----------------------------
# Orchestrator
# -----------------------------
def classify_file(p: Path, datasources: Path) -> Tuple[str, Dict[str, Any]]:
    for clf in CLASSIFIERS:
        cls, details = clf(p, datasources)
        if cls:
            return cls, details
    return "unknown", {}

# -----------------------------
# Destination & Move
# -----------------------------
def build_destination(src: Path, root: Path, classification: str, details: Dict[str, Any]) -> Path:
    date_str = details.get("date_collected", ymd_from_mtime(src))
    hostname = details.get("hostname") or src.stem

    if classification == "network_config":
        dir_ = root / "Network" / hostname
        ext = src.suffix or ".cfg"
        name = f"cfg_{hostname}_{date_str}{ext}"

    elif classification == "misc":
        dir_ = root / "Hosts" / hostname / "misc"
        name = src.name

    elif classification == "vm_disk":
        fmt = details.get("format") or "disk"
        dir_ = root / "VM" / fmt
        ext = src.suffix or f".{fmt}"
        name = f"{hostname}_{date_str}{ext}"

    elif classification == "vm_package":
        pkg = details.get("package") or "pkg"
        dir_ = root / "VM" / "packages"
        ext = src.suffix or f".{pkg}"
        name = f"{hostname}_{date_str}{ext}"

    elif classification == "network_doc":
        dir_ = root / "Network" / "docs"
        ext = src.suffix or ".txt"
        name = f"{src.stem}_{date_str}{ext}"

    else:
        # e01, mem, disk_raw, etc. → Hosts/<hostname>
        dir_ = root / "Hosts" / hostname
        ext = ".E01" if classification == "e01" else (src.suffix or (".mem" if classification == "mem" else ""))
        name = f"{hostname}_{date_str}{ext}"

    ensure_dirs(dir_)
    dest = dir_ / name
    i = 1
    while dest.exists():
        stem, suf = os.path.splitext(name)
        dest = dest.with_name(f"{stem}__{i}{suf}"); i += 1
    return dest

def move_atomic(src: Path, dest: Path) -> None:
    try:
        src.rename(dest)
    except OSError:
        shutil.copy2(src, dest)
        src.unlink(missing_ok=True)

# -----------------------------
# Fragment note
# -----------------------------
def append_fragment_note(details: Dict[str, Any], dest: Path) -> None:
    if not FRAGMENT_LOG or not details.get("fragmented"):
        return
    lines = [str(dest), "### FRAGMENTED E01 ###", "Parts:",
             *[f"  - {p}" for p in details.get("parts", [])], "",
             "INSTRUCTIONS:",
             "1) Use FTK Imager → Mount → Export defragmented E01",
             "2) Drop back into Staging", "-"*50, ""]
    FRAGMENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with FRAGMENT_LOG.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))

# -----------------------------
# Auto-defrag (optional)
# -----------------------------
def defragment_e01_fragments(src: Path, dest_dir: Path, owner: str) -> Optional[Path]:
    if not EWFEXPORT_PATH or not EWFINFO_PATH:
        json_log("defrag_skip", reason="ewfexport/ewfinfo missing", src=str(src))
        log.info("defrag skip (tools missing): %s", src)
        return None
    frag_info = e01_fragmentation(src)
    if not frag_info.get("fragmented"):
        return None

    parts = [src.parent / p for p in frag_info["parts"]]
    all_parts = [src] + parts
    if not all(p.exists() for p in all_parts):
        json_log("defrag_skip", reason="missing_parts", src=str(src))
        log.warning("defrag skip (missing parts): %s", src)
        return None

    def seg_num(p: Path) -> int:
        try:
            return int(p.suffix[2:])  # .E02 -> 2
        except Exception:
            return 999
    all_parts.sort(key=seg_num)

    import tempfile
    tmp_parent = Path("/var/wade/tmp")
    try:
        ensure_dirs(tmp_parent)
        base_tmpdir = str(tmp_parent)
    except Exception:
        base_tmpdir = None  # fall back to system tmp

    with tempfile.TemporaryDirectory(dir=base_tmpdir) as tmpdir:
        tmp = Path(tmpdir)
        merged_base = tmp / f"{src.stem}_merged"
        cmd = [EWFEXPORT_PATH, "-t", str(merged_base), "-f", "ewf"] + [str(x) for x in all_parts]
        start = time.time()
        rc, out, err = run_cmd(cmd, timeout=3600)
        merged_e01 = merged_base.with_suffix(".E01")
        if rc != 0 or not merged_e01.exists():
            json_log("defrag_failed", src=str(src), rc=rc, error=err, duration=round(time.time()-start, 2))
            log.error("defrag failed rc=%s src=%s err=%s", rc, src, err.strip() if err else "")
            return None
        rc2, _, _ = run_cmd([EWFINFO_PATH, str(merged_e01)], timeout=30)
        if rc2 != 0:
            json_log("defrag_verify_failed", src=str(src))
            log.error("defrag verify failed: %s", src)
            return None

        final_dest = dest_dir / f"{src.stem}_defragmented.E01"
        try:
            shutil.move(str(merged_e01), str(final_dest))
            safe_chown(final_dest, owner, owner)
            safe_chown(final_dest.parent, owner, owner)
        except Exception as e:
            json_log("defrag_move_failed", src=str(src), error=str(e))
            log.error("defrag move failed: %s -> %s (%s)", merged_e01, final_dest, e)
            return None

        json_log("defrag_success", src=str(src), dest=str(final_dest),
                 parts=len(all_parts), size_bytes=final_dest.stat().st_size,
                 duration_seconds=round(time.time()-start, 2))
        log.info("defrag success: %s -> %s", src, final_dest)
        return final_dest

# -----------------------------
# Queue
# -----------------------------
def enqueue_work(root: Path, work: Dict[str, Any]) -> Path:
    cls = work.get("classification", "unknown")
    prof = work.get("profile", "light")
    qdir = root / cls / prof
    qdir.mkdir(parents=True, exist_ok=True)
    wid = work.get("id") or str(uuid.uuid4())
    tmp = qdir / f"{wid}.json.tmp"
    final = qdir / f"{wid}.json"
    tmp.write_text(json.dumps(work, indent=2) + "\n")
    os.replace(str(tmp), str(final))
    return final

# -----------------------------
# Lock
# -----------------------------
@contextmanager
def acquire_lock(p: Path):
    lock = p.with_suffix(".lock")
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        try:
            yield lock
        finally:
            lock.unlink(missing_ok=True)
    except FileExistsError:
        raise RuntimeError("already locked") from None

# -----------------------------
# Copy-safety helpers
# -----------------------------
def no_open_writers(p: Path) -> bool:
    if not LSOF_CMD or not VERIFY_NO_WRITERS:
        return True
    rc, out, _ = run_cmd([LSOF_CMD, "-t", "--", str(p)], timeout=5)
    # lsof returns 0 with PIDs if open; 1 if none; treat empty stdout as "no writers"
    if rc == 0 and out.strip():
        return False
    return True

def wait_stable(p: Path, seconds: int) -> bool:
    if not p.exists():
        return False
    last = p.stat().st_size
    remaining = seconds
    while remaining > 0:
        time.sleep(1)
        if not p.exists():
            return False
        cur = p.stat().st_size
        if cur == last:
            remaining -= 1
        else:
            last = cur
            remaining = seconds
    return True

# -----------------------------
# Processing
# -----------------------------
def process_one(
    conn: sqlite3.Connection,
    src: Path,
    datasources: Path,
    profile: str,
    owner: str,
    queue_root: Path,
) -> None:
    try:
        with acquire_lock(src):
            start_ts = time.time()

            # Size-aware stability wait
            st0 = src.stat()
            stable_secs = SMALL_FILE_STABLE if st0.st_size <= SMALL_FILE_BYTES else STABLE_SECONDS
            if not wait_stable(src, stable_secs):
                json_log("not_stable", src_path=str(src), waited_seconds=stable_secs)
                log.debug("not stable yet (waited=%ss): %s", stable_secs, src)
                return
            if not no_open_writers(src):
                json_log("writers_present", src_path=str(src))
                log.debug("writers present: %s", src)
                return

            # --- PRE-MOVE SNAPSHOT ---
            pre_st = st0  # reuse the stat we already did
            pre_sig = f"{pre_st.st_dev}:{pre_st.st_ino}:{pre_st.st_size}:{int(pre_st.st_mtime_ns)}"
            pre_content_sig = quick_content_sig(src, size_hint=pre_st.st_size)

            # Positive-path breadcrumbs
            json_log("waited_for_stable",
                     src_path=str(src),
                     stable_seconds=stable_secs,
                     size_bytes=pre_st.st_size)

                        # New: log what we’re about to use for dedupe
            json_log("dedupe_probe",
                     src_path=str(src),
                     sig=pre_sig,
                     content_sig=pre_content_sig)

            if LSOF_CMD and VERIFY_NO_WRITERS:
                rc, out, _ = run_cmd([LSOF_CMD, "-t", "--", str(src)], timeout=5)
                json_log("writer_check",
                         src_path=str(src),
                         writers_found=(rc == 0 and out.strip() != ""))

            # Duplicate guard (by content first, then inode sig)
            if already_processed_by_content(conn, pre_content_sig):
                ignored = STAGING_ROOT / "ignored"
                ensure_dirs(ignored)
                dest_ignored = ignored / src.name
                move_atomic(src, dest_ignored)
                json_log("duplicate_ignored_content",
                         original_name=src.name, dest_path=str(dest_ignored),
                         profile=profile, content_sig=pre_content_sig)
                log.warning("duplicate by content -> ignored: %s -> %s", src.name, dest_ignored)
                return

            if already_processed(conn, pre_sig):
                ignored = STAGING_ROOT / "ignored"
                ensure_dirs(ignored)
                dest_ignored = ignored / src.name
                move_atomic(src, dest_ignored)
                json_log("duplicate_ignored",
                         original_name=src.name, dest_path=str(dest_ignored),
                         profile=profile, sig=pre_sig)
                log.warning("duplicate by sig -> ignored: %s -> %s", src.name, dest_ignored)
                return

            # Classification
            classification, details = classify_file(src, datasources)
            if classification == "unknown":
                triage = debug_probe_file(src)
                # Move unknown into quarantine to avoid repeated churn
                unk_dir = datasources / "Unknown"
                ensure_dirs(unk_dir)
                unk_dest = unk_dir / src.name
                move_atomic(src, unk_dest)
                safe_chown(unk_dest, owner, owner)
                json_log("quarantined_unknown", original_name=src.name, dest_path=str(unk_dest),
                         profile=profile, sig=pre_sig, **triage)
                log.warning("quarantined unknown -> %s", unk_dest)
                return

            hostname = details.get("hostname") or src.stem
            dest = build_destination(src, datasources, classification, details)

            # If a same-named file already exists and bytes match, ignore (no "__1")
            if dest.exists():
                try:
                    if quick_content_sig(dest) == pre_content_sig:
                        ignored = STAGING_ROOT / "ignored"
                        ensure_dirs(ignored)
                        dest_ignored = ignored / src.name
                        move_atomic(src, dest_ignored)
                        json_log("duplicate_ignored_existing",
                                 original_name=src.name, existing=str(dest),
                                 dest_path=str(dest_ignored), profile=profile,
                                 content_sig=pre_content_sig)
                        log.warning("duplicate existing (same content) -> ignored: %s -> %s", src.name, dest_ignored)
                        return
                except Exception:
                    pass

            # Move / E01 handling
            final_path = dest
            fragged = None
            if classification == "e01":
                fragged = details.get("fragmentation")
                merged_path = defragment_e01_fragments(src, dest.parent, owner) if (fragged and fragged.get("fragmented")) else None
                if merged_path:
                    final_path = merged_path
                    # Re-enrich hostname/date from merged
                    if TARGET_INFO_PATH:
                        rc, out, _ = run_cmd([TARGET_INFO_PATH, "-j", str(final_path)], timeout=30)
                        if rc == 0:
                            try:
                                j = json.loads(out)
                                if j.get("hostname"):
                                    details["hostname"] = j["hostname"]; hostname = j["hostname"]
                                if j.get("acquired_date"):
                                    details["date_collected"] = j["acquired_date"]
                            except Exception:
                                pass
                else:
                    # Fall back to moving original
                    move_atomic(src, dest)
                    final_path = dest
                    if fragged and fragged.get("fragmented"):
                        append_fragment_note(fragged, final_path)
            else:
                # Non-E01: move final
                move_atomic(src, dest)
                final_path = dest

            # Ownership
            safe_chown(final_path, owner, owner)
            safe_chown(final_path.parent, owner, owner)

            # Work order & DB (use size hints to reduce extra stats)
            final_st = final_path.stat()
            final_content_sig = quick_content_sig(final_path, size_hint=final_st.st_size)
            final_sig = f"{final_st.st_dev}:{final_st.st_ino}:{final_st.st_size}:{int(final_st.st_mtime_ns)}"

            work = {
                "schema": "wade.queue.workorder",
                "version": 1,
                "id": str(uuid.uuid4()),
                "created_utc": utc_now_iso(),
                "profile": profile,
                "classification": classification,
                "original_name": src.name,
                "source_host": os.uname().nodename,
                "dest_path": str(final_path),
                "size_bytes": final_st.st_size,
                "sig": final_sig,
                "content_sig": final_content_sig,
            }
            if classification in ("e01", "mem"):
                work.update(hostname=hostname, date_collected=details.get("date_collected"))
            if classification == "network_config":
                work.update(vendor=details.get("vendor"),
                            os_version=details.get("os_version"),
                            hostname=hostname)
            if classification == "vm_disk":
                work.update(vm_format=details.get("format"))

            queue_path = enqueue_work(queue_root, work)

            # Rich log payload
            log_payload: Dict[str, Any] = {
                "event": "staged",
                "profile": profile,
                "classification": classification,
                "original_name": src.name,
                "src_path": str(src),
                "dest_path": str(final_path),
                "sig": final_sig,
                "content_sig": final_content_sig,
                "size_bytes": final_st.st_size,
                "started_utc": utc_from_ts(start_ts),
                "finished_utc": utc_now_iso(),
                "duration_seconds": round(time.time() - start_ts, 3),
                "queue_path": str(queue_path),
            }

            if classification in ("disk_raw", "vm_disk"):
                md = {
                    "os": details.get("os"),
                    "version": details.get("version"),
                    "edition": details.get("edition"),
                    "arch": details.get("arch"),
                    "build": details.get("build"),
                    "kernel": details.get("kernel"),
                    "distro": details.get("distro"),
                    "confidence": details.get("confidence"),
                }
                if classification == "vm_disk":
                    md["vm_format"] = details.get("format")
                log_payload["metadata"] = {k: v for k, v in md.items() if v is not None}

            elif classification in ("e01", "mem", "vm_package"):
                md = {
                    "hostname": details.get("hostname"),
                    "date_collected": details.get("date_collected"),
                }
                if classification == "e01":
                    md["fragmented"] = bool(fragged and fragged.get("fragmented"))
                if classification == "mem":
                    md["mem_kind"] = (details.get("mem_signature") or {}).get("kind")
                if classification == "vm_package":
                    md["package"] = details.get("package")
                log_payload["metadata"] = {k: v for k, v in md.items() if v is not None}

            # Optional Whiff assist (non-blocking)
            assist = whiff_annotate(log_payload)
            if assist:
                log_payload["assist"] = assist

            json_log(**log_payload)
            log.info("staged %s -> %s (%s/%s) bytes=%d",
                     src.name, final_path, classification, profile, final_st.st_size)

            # Record pre-move snapshot (no stat on src after move)
            try:
                record_processed_snapshot(
                    conn, pre_sig, str(src), pre_st.st_size, int(pre_st.st_mtime_ns),
                    final_path, classification, profile, content_sig=final_content_sig
                )
            except sqlite3.IntegrityError:
                # Another record with same content_sig already exists -> treat as dup
                row = conn.execute("SELECT dest_path FROM processed WHERE content_sig = ?", (final_content_sig,)).fetchone()
                existing = row[0] if row else None
                ignored = STAGING_ROOT / "ignored"
                ensure_dirs(ignored)
                dup_dest = ignored / final_path.name
                move_atomic(final_path, dup_dest)
                json_log("postmove_duplicate_by_content", existing=existing, moved_to=str(dup_dest),
                         original_name=src.name, profile=profile, content_sig=final_content_sig)
                log.warning("post-move duplicate by content: %s (existing=%s) -> %s",
                            final_path, existing, dup_dest)
                return

    except Exception as exc:
        failed = src.with_suffix(".failed")
        try:
            src.rename(failed)
        except Exception:
            pass
        json_log("processing_failed", original_name=src.name, src_path=str(src),
                 error=str(exc), profile=profile)
        log.error("processing failed for %s: %s", src, exc)
        raise

# -----------------------------
# Paths & housekeeping
# -----------------------------
def build_paths() -> Tuple[str, Path, Path, Path, Path]:
    env = load_env()
    owner = env.get("WADE_OWNER_USER", DEFAULT_OWNER)

    datadir_cfg = env.get("WADE_DATADIR", DEFAULT_DATADIR)
    staging_cfg = env.get("WADE_STAGINGDIR", DEFAULT_STAGINGDIR)
    home = Path(f"/home/{owner}")

    datadir = Path(datadir_cfg)
    staging = Path(staging_cfg)

    # Allow absolute overrides; otherwise treat as under /home/<owner>
    if datadir.is_absolute():
        datasources = datadir
    else:
        datasources = home / datadir

    if staging.is_absolute():
        staging_root = staging
    else:
        staging_root = home / staging

    full = staging_root / "full"
    light = staging_root / "light"

    queue_root_cfg = env.get("WADE_QUEUE_DIR", "_queue")
    queue_root = Path(queue_root_cfg)
    if not queue_root.is_absolute():
        queue_root = datasources / queue_root

    global STATE_DIR, LOG_ROOT, SQLITE_DB, STAGING_ROOT, FRAGMENT_LOG
    STATE_DIR = Path("/var/wade/state")
    LOG_ROOT = Path("/var/wade/logs/stage")
    SQLITE_DB = STATE_DIR / "staging_index.sqlite3"
    STAGING_ROOT = staging_root
    FRAGMENT_LOG = datasources / "images_to_be_defragmented.log"

    ensure_dirs(full, light, datasources / "Hosts", datasources / "Network",
                staging_root / "ignored", queue_root, STATE_DIR, LOG_ROOT, datasources / "Unknown")

    # Queue hygiene: delete >7 day old files
    now = time.time()
    for cls in ("e01", "mem", "disk_raw", "vm_disk", "vm_package", "network_config", "network_doc", "misc", "unknown"):
        for prof in ("full", "light"):
            qdir = queue_root / cls / prof
            if qdir.exists():
                for f in qdir.iterdir():
                    if f.is_file() and f.stat().st_mtime < now - 7*86400:
                        f.unlink(missing_ok=True)

    return owner, full, light, datasources, queue_root

# -----------------------------
# Main Loop
# -----------------------------
def iter_files(dir_: Path) -> Iterable[Path]:
    """Yield candidate files (skip temp-ish) from dir_. Recursive when enabled."""
    skip_suffixes = (".part", ".tmp", ".crdownload")
    if not WADE_STAGE_RECURSIVE:
        for p in dir_.iterdir():
            if p.is_file() and not p.name.lower().endswith(skip_suffixes):
                yield p
        return

    # Recursive walk
    for root, dirs, files in os.walk(dir_):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if name.lower().endswith(skip_suffixes):
                continue
            p = Path(root) / name
            if p.is_file():
                yield p

def polling_loop(conn, full, light, datasources, queue_root, owner):
    log.info("polling mode – scanning every %ss", SCAN_INTERVAL_SEC)
    while True:
        for directory, prof in ((full, "full"), (light, "light")):
            for p in iter_files(directory):
                process_one(conn, p, datasources, prof, owner, queue_root)
        time.sleep(SCAN_INTERVAL_SEC)

def inotify_loop(conn, full, light, datasources, queue_root, owner):
    inotify = INotify()
    base_flags = flags.CLOSE_WRITE if REQUIRE_CLOSE_WRITE else (flags.CLOSE_WRITE | flags.MOVED_TO | flags.CREATE)
    dir_flags = base_flags | flags.MOVED_TO | flags.CREATE  # for new files/dirs
    watch_map: Dict[int, Path] = {}

    def add_watch_dir(d: Path):
        if not d.exists() or not d.is_dir():
            return None
        wd = inotify.add_watch(str(d), dir_flags)
        watch_map[wd] = d
        return wd

    def add_tree(root: Path):
        add_watch_dir(root)
        if WADE_STAGE_RECURSIVE:
            for r, dirs, _ in os.walk(root):
                for d in dirs:
                    add_watch_dir(Path(r) / d)

    add_tree(full)
    add_tree(light)

    log.info("inotify mode – recursive=%s", "on" if WADE_STAGE_RECURSIVE else "off")

    while True:
        for ev in inotify.read(timeout=1000):
            parent = watch_map.get(ev.wd)
            if parent is None:
                continue
            name = ev.name
            if not name:
                continue
            path = parent / name

            # If a directory appears and recursion is enabled, start watching it
            if WADE_STAGE_RECURSIVE and (ev.mask & flags.ISDIR):
                if path.is_dir():
                    add_watch_dir(path)
                continue

            # Skip temp-ish partials
            nl = name.lower()
            if nl.endswith((".part", ".tmp", ".crdownload")):
                continue

            # Only proceed on files
            if path.is_file():
                # extra debounce: ensure stable + no writers
                if not wait_stable(path, STABLE_SECONDS):
                    continue
                if not no_open_writers(path):
                    continue

                prof = "full" if parent == full else "light"
                process_one(conn, path, datasources, prof, owner, queue_root)

def main() -> None:
    owner, stage_full, stage_light, datasources, queue_root = build_paths()
    # Init ops logging (text)
    setup_logging(os.uname().nodename)
    conn = init_db()
    def _sig(*_): sys.exit(0)
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    log.info("WADE staging daemon starting…")
    try:
        if INOTIFY_AVAILABLE:
            inotify_loop(conn, stage_full, stage_light, datasources, queue_root, owner)
        else:
            polling_loop(conn, stage_full, stage_light, datasources, queue_root, owner)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
