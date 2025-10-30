#!/opt/wade/.venv/bin/python
"""
WADE Staging Daemon – Heuristic Edition (VM + E01 Auto-Defrag)
https://github.com/imcconnell15/WADE

- VM disk formats: VMDK, VHD, VHDX, QCOW/QCOW2, VDI
- VM packages: OVA (tar/ustar), OVF (XML)
- E01 auto-defrag (ewfexport) with unattended mode; optional RAW output
- Patched DB write post-move; E01 magic offsets; graceful shutdown; macOS plist bounds
- Secondary EWF segments skipped; queue hygiene; symlink-safe chown
"""

from __future__ import annotations

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
import stat as _stat
import tempfile
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Any

# ----------------------------------------------------------------------
# Optional: inotify_simple
# ----------------------------------------------------------------------
try:
    from inotify_simple import INotify, flags
    INOTIFY_AVAILABLE = True
except Exception:  # pragma: no cover
    INOTIFY_AVAILABLE = False

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
WADE_ENV = Path("/etc/wade/wade.env")
DEFAULT_OWNER = "autopsy"
DEFAULT_DATADIR = "DataSources"
DEFAULT_STAGINGDIR = "Staging"

SCAN_INTERVAL_SEC = int(os.getenv("WADE_STAGE_SCAN_INTERVAL", "30"))
STABLE_SECONDS = int(os.getenv("WADE_STAGE_STABLE_SECONDS", "10"))

HEAD_SCAN_BYTES = int(os.getenv("WADE_STAGE_HEAD_SCAN_BYTES", str(1024 * 1024)))
TEXT_SNIFF_BYTES = int(os.getenv("WADE_STAGE_TEXT_SNIFF_BYTES", str(128 * 1024)))
TEXT_MIN_PRINTABLE_RATIO = float(os.getenv("WADE_STAGE_TEXT_MIN_PRINTABLE_RATIO", "0.92"))

# ----------------------------------------------------------------------
# Global paths
# ----------------------------------------------------------------------
STATE_DIR: Path
LOG_ROOT: Path
SQLITE_DB: Path
STAGING_ROOT: Optional[Path] = None
FRAGMENT_LOG: Optional[Path] = None

# ----------------------------------------------------------------------
# Magic DB (offset -> bytes)
# ----------------------------------------------------------------------
MAGIC_DB: Dict[str, Tuple[Tuple[int, bytes], ...]] = {
    # EWF / E01
    "ewf": ((0, b"LV1"), (8, b"EWF")),
    # Memory
    "hiberfil": ((0, b"hibr"), (0, b"HIBR"), (0, b"Hibr")),
    "lime": ((0, b"LiME"),),
    # Filesystems / boot signatures
    "ntfs": ((3, b"NTFS    "),),
    "fat32": ((82, b"FAT32   "),),
    "gpt": ((512, b"EFI PART"),),
    "mbr": ((510, b"\x55\xaa"),),
    # Virtualization formats
    "qcow": ((0, b"QFI\xfb"),),             # QCOW2
    "vhdx": ((0x200, b"vhdxfile"),),        # VHDX at 0x200
    "vmdk": ((0, b"KDMV"),),                # VMDK stream/sparse
    "vdi":  ((0, b"<<< Oracle VM VirtualBox Disk Image >>>"),),
    # Packaging (not disks)
    "tar_ustar": ((257, b"ustar"),),        # OVA = tar (ustar)
}

# ----------------------------------------------------------------------
# Compiled regexes
# ----------------------------------------------------------------------
_RE_HOSTNAME = re.compile(r"(?im)^hostname\s+([A-Za-z0-9._-]+)")
_EWF_SEGMENT_RE = re.compile(r"\.E(\d{2,})$", re.I)

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def utc_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ymd_from_mtime(p: Path) -> str:
    return datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")

def load_env() -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.startswith("WADE_")}
    if WADE_ENV.is_file():
        try:
            for line in WADE_ENV.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"\'')
        except Exception:
            pass
    return env

def which(cmd: str) -> Optional[str]:
    for p in os.getenv("PATH", "").split(os.pathsep):
        cand = Path(p) / cmd
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    extras = (
        "/usr/local/bin/vol", "/usr/bin/vol", "/opt/pipx/venvs/volatility3/bin/vol",
        "/usr/local/bin/target-info", "/usr/bin/target-info",
        "/usr/local/bin/ewfinfo", "/usr/bin/ewfinfo",
        "/usr/bin/ewfexport", "/usr/local/bin/ewfexport",
    )
    name = Path(cmd).name
    for e in extras:
        if Path(e).name == name and Path(e).is_file() and os.access(e, os.X_OK):
            return e
    return None

VOL_PATH = os.getenv("WADE_VOL_PATH") or which("vol")
TARGET_INFO_PATH = which("target-info")
EWFINFO_PATH = which("ewfinfo")

def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True, check=False)
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

def extract_text_snippet(p: Path, max_bytes: int = 512*1024) -> str:
    try:
        data = p.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

# ----------------------------------------------------------------------
# I/O
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# SQLite
# ----------------------------------------------------------------------
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
            profile TEXT NOT NULL
        );
    """)
    conn.commit()
    return conn

def already_processed(conn: sqlite3.Connection, sig: str) -> bool:
    return conn.execute("SELECT 1 FROM processed WHERE sig = ?", (sig,)).fetchone() is not None

def record_processed(conn: sqlite3.Connection, sig: str, src: Path, dest: Path, classification: str, profile: str) -> None:
    # Patch A: record using dest.stat() so move/rename doesn't break stat()
    now = utc_now_iso()
    st = dest.stat()
    conn.execute("""
        INSERT INTO processed VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sig) DO UPDATE SET
            src_path = excluded.src_path,
            size = excluded.size,
            mtime_ns = excluded.mtime_ns,
            last_seen = excluded.last_seen,
            dest_path = excluded.dest_path,
            classification = excluded.classification,
            profile = excluded.profile;
    """, (sig, str(src), st.st_size, int(st.st_mtime_ns), now, now, str(dest), classification, profile))
    conn.commit()

# ----------------------------------------------------------------------
# Enhanced Logging
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# Metrics + chown helpers
# ----------------------------------------------------------------------
def update_metrics(category: str, profile: str, key: str, delta: int = 1) -> None:
    """Write /var/wade/state/metrics.json; never block staging."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        metrics_path = STATE_DIR / "metrics.json"
        data = {}
        if metrics_path.exists():
            with metrics_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        data.setdefault(category, {}).setdefault(profile, {}).setdefault(key, 0)
        data[category][profile][key] += delta
        tmp = metrics_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(str(tmp), str(metrics_path))
    except Exception:
        pass

def safe_chown(p: Path, user: str, group: str) -> None:
    """Symlink-safe chown."""
    try:
        st = os.lstat(p)
        if _stat.S_ISLNK(st.st_mode):
            return
        shutil.chown(p, user=user, group=group)
    except Exception:
        pass

# ----------------------------------------------------------------------
# Classification Registry
# ----------------------------------------------------------------------
Classifier = Callable[[Path, Path], Tuple[str, Dict[str, Any]]]
CLASSIFIERS: List[Classifier] = []

def register_classifier(fn: Classifier) -> Classifier:
    CLASSIFIERS.append(fn)
    return fn

# ----------------------------------------------------------------------
# Network Config Detectors
# ----------------------------------------------------------------------
def _cisco_ios(text: str) -> Optional[Dict[str, Any]]:
    anchors = 0
    if re.search(r"(?im)^Building configuration\.\.\.", text): anchors += 1
    if re.search(r"(?im)^Current configuration\s*:", text): anchors += 1
    if re.search(r"(?im)^service (timestamps|password-encryption|call-home)", text): anchors += 1
    if re.search(r"(?im)^line vty\s+\d+", text): anchors += 1
    if anchors < 2: return None
    m_host = _RE_HOSTNAME.search(text)
    m_ver = re.search(r"(?im)^(?:Cisco IOS.*Version|version)\s+([0-9A-Za-z.\(\)_-]+)", text)
    return {
        "vendor": "cisco_ios",
        "hostname": m_host.group(1) if m_host else None,
        "os_version": m_ver.group(1) if m_ver else None,
        "platform": "IOS",
    }

def _cisco_asa(text: str) -> Optional[Dict[str, Any]]:
    if "ASA Version" not in text and "Cisco Adaptive Security Appliance" not in text:
        return None
    m_ver = re.search(r"ASA Version\s+([0-9.]+)", text)
    m_host = _RE_HOSTNAME.search(text)
    m_serial = re.search(r"Hardware:\s+.*,\s+([A-Z0-9]{11})", text)
    return {
        "vendor": "cisco_asa",
        "hostname": m_host.group(1) if m_host else None,
        "os_version": m_ver.group(1) if m_ver else None,
        "platform": "ASA",
        "serial": m_serial.group(1) if m_serial else None,
    }

def _fortigate(text: str) -> Optional[Dict[str, Any]]:
    if "config version" not in text.lower() or "FortiGate" not in text:
        return None
    m_ver = re.search(r"config version\s+[0-9-]+-([0-9.]+)", text, re.I)
    m_host = re.search(r"set hostname\s+\"?([A-Za-z0-9._-]+)\"?", text)
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
    return {
        "vendor": "paloalto_panos",
        "hostname": m_host.group(1) if m_host else None,
        "os_version": m_ver.group(1) if m_ver else None,
        "platform": "PAN-OS",
    }

def _juniper_screenos(text: str) -> Optional[Dict[str, Any]]:
    if "ScreenOS" not in text or "set hostname" not in text:
        return None
    m_host = re.search(r"set hostname\s+\"?([A-Za-z0-9._-]+)\"?", text)
    m_ver = re.search(r"ScreenOS\s+([0-9.]+)", text)
    return {
        "vendor": "juniper_screenos",
        "hostname": m_host.group(1) if m_host else None,
        "os_version": m_ver.group(1) if m_ver else None,
        "platform": "ScreenOS",
    }

def _checkpoint_gaia(text: str) -> Optional[Dict[str, Any]]:
    if "set hostname" not in text or "Gaia" not in text:
        return None
    m_host = re.search(r"set hostname\s+([A-Za-z0-9._-]+)", text)
    m_ver = re.search(r"Gaia\s+R([0-9.]+)", text)
    return {
        "vendor": "checkpoint_gaia",
        "hostname": m_host.group(1) if m_host else None,
        "os_version": m_ver.group(1) if m_ver else None,
        "platform": "Gaia",
    }

def _juniper_junos(text: str) -> Optional[Dict[str, Any]]:
    if "set system host-name" not in text:
        return None
    m_host = re.search(r"set\s+system\s+host-name\s+(\S+)", text)
    return {
        "vendor": "juniper_junos",
        "hostname": m_host.group(1) if m_host else None,
        "platform": "Junos",
    }

def _vyos_edgeos(text: str) -> Optional[Dict[str, Any]]:
    if "set system host-name" not in text or "interfaces" not in text:
        return None
    m_host = re.search(r"set\s+system\s+host-name\s+(\S+)", text)
    return {
        "vendor": "vyos_edgeos",
        "hostname": m_host.group(1) if m_host else None,
        "platform": "VyOS/EdgeOS",
    }

def _arista_eos(text: str) -> Optional[Dict[str, Any]]:
    if "daemon TerminAttr" not in text and "management api http-commands" not in text:
        return None
    m_host = _RE_HOSTNAME.search(text)
    return {
        "vendor": "arista_eos",
        "hostname": m_host.group(1) if m_host else None,
        "platform": "EOS",
    }

def _mikrotik_ros(text: str) -> Optional[Dict[str, Any]]:
    if "/interface" not in text or "/ip " not in text:
        return None
    m_host = re.search(r"/system identity set name=(\S+)", text)
    return {
        "vendor": "mikrotik_ros",
        "hostname": m_host.group(1) if m_host else None,
        "platform": "RouterOS",
    }

_NETWORK_DETECTORS = (
    _cisco_asa,
    _fortigate,
    _paloalto,
    _juniper_screenos,
    _checkpoint_gaia,
    _cisco_ios,
    _juniper_junos,
    _vyos_edgeos,
    _arista_eos,
    _mikrotik_ros,
)

# ----------------------------------------------------------------------
# Core Heuristics
# ----------------------------------------------------------------------
def _has_magic_at(buf: bytes, offset: int, sig: bytes) -> bool:
    end = offset + len(sig)
    return len(buf) >= end and buf[offset:end] == sig

def is_e01(p: Path) -> bool:
    if p.suffix.lower() == ".e01":
        return True
    head = read_head_once(p, max(HEAD_SCAN_BYTES, 16))
    for off, sig in MAGIC_DB["ewf"]:
        if _has_magic_at(head, off, sig):
            return True
    return False

def is_ewf_secondary_segment(p: Path) -> bool:
    """True if this looks like E02, E03, E10+ (case-insensitive)."""
    m = _EWF_SEGMENT_RE.search(p.name)
    return bool(m and m.group(1) != "01")

def e01_fragmentation(p: Path) -> Dict[str, Any]:
    """
    Detect sibling segments for an E01 set. Handles E02..E09 and E10+ (case-insensitive).
    """
    base = p.with_suffix("")
    parts: List[str] = []
    for f in p.parent.glob(f"{base.name}.E*"):
        n = f.name
        if n.lower().endswith(".e01"):
            continue
        if _EWF_SEGMENT_RE.search(n):
            parts.append(n)
    def seg_num(name: str) -> int:
        m = _EWF_SEGMENT_RE.search(name)
        return int(m.group(1)) if m else 999999
    parts.sort(key=seg_num)
    return {"fragmented": bool(parts), "parts": parts}

# ----------------------------------------------------------------------
# AUTO DEFRAGMENT E01
# ----------------------------------------------------------------------
def _ensure_tmp_root() -> Path:
    tmp_root = Path("/var/wade/tmp")
    tmp_root.mkdir(parents=True, exist_ok=True)
    return tmp_root

def _ewf_target_path(base: Path, fmt: str) -> Path:
    if fmt == "raw":
        return base.with_suffix(".raw")
    return base.with_suffix(".E01")

def defragment_e01_fragments(src: Path, final_dest: Path, owner: str) -> Optional[Path]:
    """
    Merge segmented E01 (starting at E01) into single output (EWF by default; RAW if configured).
    Returns final_dest path on success, or None on failure/skip.
    """
    if is_ewf_secondary_segment(src):
        json_log("defrag_skip", reason="not_primary_segment", src=str(src))
        return None

    if not EWFINFO_PATH or not which("ewfexport"):
        json_log("defrag_skip", reason="missing_ewf_tools", src=str(src))
        return None

    frag_info = e01_fragmentation(src)
    if not frag_info.get("fragmented"):
        return None

    parts = [src.parent / p for p in frag_info["parts"]]
    all_parts = [src] + parts
    if not all(p.exists() for p in all_parts):
        json_log("defrag_skip", reason="missing_parts", src=str(src))
        return None

    def seg_num(p: Path) -> int:
        m = _EWF_SEGMENT_RE.search(p.name)
        return int(m.group(1)) if m else 999999
    all_parts.sort(key=seg_num)

    fmt = os.getenv("WADE_E01_DEFRAG_FORMAT", "ewf").strip().lower()
    if fmt not in {"ewf", "encase6", "encase7", "ewfx", "raw"}:
        fmt = "ewf"

    with tempfile.TemporaryDirectory(dir=str(_ensure_tmp_root())) as tdir:
        base = Path(tdir) / "merged"
        target_path = _ewf_target_path(base, fmt)

        cmd = [
            "ewfexport",
            "-u",                # unattended
            "-f", fmt,           # output format
            "-t", str(base),     # base (extension decided by format)
        ]
        if fmt in {"ewf", "encase6", "encase7", "ewfx"}:
            seg_size = int(os.getenv("WADE_E01_SEGMENT_SIZE_BYTES", str(8 * 1024**4)))
            cmd += ["-S", str(seg_size)]

        cmd += [str(all_parts[0])] + [str(p) for p in all_parts[1:]]

        start = time.time()
        rc, out, err = run_cmd(cmd, timeout=3600)

        produced = target_path
        if not produced.exists():
            candidates = list(base.parent.glob(base.name + ".*"))
            produced = candidates[0] if candidates else None

        if rc != 0 or not produced or not produced.exists():
            json_log("defrag_failed", src=str(src), rc=rc, stderr=err, duration=round(time.time() - start, 2))
            update_metrics("e01", "full", "defrag_failed")
            return None

        if fmt != "raw" and EWFINFO_PATH:
            rc2, _, _ = run_cmd([EWFINFO_PATH, str(produced)], timeout=30)
            if rc2 != 0:
                json_log("defrag_verify_failed", src=str(src), produced=str(produced))
                return None

        final = final_dest.with_suffix(produced.suffix)
        final.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(produced), str(final))
        safe_chown(final, owner, owner)
        safe_chown(final.parent, owner, owner)

        json_log(
            "defrag_success",
            src=str(src),
            dest=str(final),
            format=fmt,
            parts=len(all_parts),
            size_bytes=final.stat().st_size,
            duration_seconds=round(time.time() - start, 2),
            derived_from=[str(p) for p in all_parts],
        )
        update_metrics("e01", "full", "defrag_success")
        return final

# ----------------------------------------------------------------------
# VM & Disk Detection
# ----------------------------------------------------------------------
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
        # plist parsing happens against bounded bytes by caller
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

# ----------------------------------------------------------------------
# Classifiers (order = precedence)
# ----------------------------------------------------------------------
@register_classifier
def classify_e01(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    if not is_e01(p):
        return "", {}
    hostname = p.stem
    date_col = ymd_from_mtime(p)
    if TARGET_INFO_PATH:
        rc, out, _ = run_cmd([TARGET_INFO_PATH, str(p), "-j"], timeout=20)
        if rc == 0:
            try:
                j = json.loads(out)
                if j.get("hostname"):
                    hostname = j["hostname"]
            except Exception:
                pass
    if EWFINFO_PATH:
        rc, out, _ = run_cmd([EWFINFO_PATH, str(p)], timeout=20)
        if rc == 0:
            m = re.search(r"Acquisition date\s*:\s*(.+)", out)
            if m:
                iso = re.search(r"\d{4}-\d{2}-\d{2}", m.group(1))
                if iso:
                    date_col = iso.group(0)
    return "e01", {
        "hostname": hostname,
        "date_collected": date_col,
        "fragmentation": e01_fragmentation(p),
    }

@register_classifier
def classify_memory(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    head = read_head_once(p, max(HEAD_SCAN_BYTES, 4096))
    sig = None
    if head[:4] in (b"HIBR", b"Hibr", b"hibr"):
        sig = {"kind": "hibernation", "evidence": "HIBR magic"}
    elif head[:4] == b"LiME":
        sig = {"kind": "lime", "evidence": "LiME magic"}
    elif any(k in p.name.lower() for k in (".mem", ".vmem", "hiberfil", "hibernat", "winpmem", "rawmem", ".lime")):
        sig = {"kind": "raw", "evidence": "filename hint"}
    if not sig:
        return "", {}

    hostname = p.stem
    date_col = ymd_from_mtime(p)
    meta: Dict[str, Any] = {
        "hostname": hostname,
        "date_collected": date_col,
        "mem_signature": sig,
    }

    if not VOL_PATH:
        meta["confidence"] = 10
        return "mem", meta

    rc, out, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.info.Info"], timeout=45)
    score = 0
    if rc == 0:
        m_ver = re.search(r"Image\s+version:\s+([\d.]+)", out)
        m_build = re.search(r"Build\s+number:\s+(\d+)", out)
        m_ed = re.search(r"Edition:\s+(.+)", out)
        m_arch = re.search(r"Architecture:\s+(\w+)", out)

        if m_ver: meta["os"] = "Windows"; meta["version"] = m_ver.group(1); score += 30
        if m_build: meta["build"] = m_build.group(1); score += 25
        if m_ed:
            edition = m_ed.group(1).lower()
            meta["edition"] = "Server" if "server" in edition else "Workstation"; score += 20
        if m_arch: meta["arch"] = m_arch.group(1); score += 15

        h, d = best_effort_mem_meta(p)
        if h: meta["hostname"] = h; score += 10
        if d: meta["date_collected"] = d
    else:
        rc2, out2, _ = run_cmd([VOL_PATH, "-f", str(p), "linux.bash.Bash"], timeout=30)
        if rc2 == 0 and "Linux" in out2:
            meta["os"] = "Linux"; score += 30
            rc3, out3, _ = run_cmd([VOL_PATH, "-f", str(p), "linux.uname.Uname"], timeout=30)
            if rc3 == 0:
                m_kern = re.search(r"Linux version ([^\s]+)", out3)
                if m_kern:
                    meta["kernel"] = m_kern.group(1); score += 25

    meta["confidence"] = min(100, score if score else 15)
    return "mem", meta

@register_classifier
def classify_vm_image(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    info = detect_vm_image(p)
    if not info:
        return "", {}
    meta: Dict[str, Any] = {"format": info["format"], "evidence": info["evidence"]}
    score = 20
    txt = extract_text_snippet(p, 1024 * 1024)
    os_meta, os_score = _mountless_os_detect_from_text(txt)
    if os_meta:
        meta.update(os_meta); score += os_score
    if meta.get("os") == "macOS":
        meta, score = _mountless_os_enrich_from_plist_bytes(p, meta, score)
    meta["date_collected"] = ymd_from_mtime(p)
    meta["confidence"] = min(100, score)
    return "vm_disk", meta

@register_classifier
def classify_disk_raw(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    sig = detect_disk_image(p)
    if not sig:
        return "", {}
    meta: Dict[str, Any] = {"disk_signature": sig, "date_collected": ymd_from_mtime(p)}
    txt = extract_text_snippet(p, 1024 * 1024)
    os_meta, score = _mountless_os_detect_from_text(txt)
    if os_meta:
        meta.update(os_meta)
        meta["confidence"] = min(100, score)
        if meta.get("os") == "macOS":
            meta, score = _mountless_os_enrich_from_plist_bytes(p, meta, score)
            meta["confidence"] = min(100, score)
    else:
        meta["confidence"] = 10
    return "disk_raw", meta

@register_classifier
def classify_network_cfg(p: Path, _: Path) -> Tuple[str, Dict[str, Any]]:
    ok, txt = is_probably_text(p)
    if not ok:
        return "", {}
    preview = "\n".join(txt.splitlines()[:3])
    stats = {
        "size_bytes": p.stat().st_size,
        "line_count": txt.count("\n") + 1,
        "entropy": calculate_entropy(p.read_bytes()[:TEXT_SNIFF_BYTES]),
    }
    best_score = 0
    best_info: Optional[Dict[str, Any]] = None
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
            best_score = score
            best_info = info
    if best_info:
        best_info.update({
            "confidence": min(100, best_score),
            "preview_lines": preview,
            **stats,
        })
        return "network_config", best_info
    return "", {}

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
def classify_vm_package(p: Path, datasources: Path) -> Tuple[str, Dict[str, Any]]:
    info = detect_vm_package(p)
    if not info:
        return "", {}
    host = match_host_from_filename(datasources, p)
    meta = {
        "package": info["pkg"],
        "evidence": info["evidence"],
        "date_collected": ymd_from_mtime(p),
        "hostname": host,
        "confidence": 50,
    }
    return "vm_package", meta

@register_classifier
def classify_misc(p: Path, datasources: Path) -> Tuple[str, Dict[str, Any]]:
    host = match_host_from_filename(datasources, p)
    if host:
        return "misc", {"hostname": host, "date_collected": ymd_from_mtime(p)}
    return "", {}

# ----------------------------------------------------------------------
# Best-effort memory metadata
# ----------------------------------------------------------------------
def best_effort_mem_meta(p: Path) -> Tuple[Optional[str], Optional[str]]:
    if not VOL_PATH:
        return None, None
    rc, out, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.registry.hivelist"], timeout=45)
    host = None
    if rc == 0:
        for line in out.splitlines():
            if "SYSTEM" in line:
                offset = line.split()[0]
                rc2, out2, _ = run_cmd([
                    VOL_PATH, "-f", str(p), "windows.registry.printkey",
                    "--offset", offset, "--key",
                    r"ControlSet001\Control\ComputerName\ComputerName"
                ], timeout=45)
                if rc2 == 0:
                    m = re.search(r'ComputerName.*?"([^"]+)"', out2)
                    if m:
                        host = m.group(1)
                break
    rc3, out3, _ = run_cmd([VOL_PATH, "-f", str(p), "windows.info.Info"], timeout=45)
    date = None
    if rc3 == 0:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", out3)
        if m:
            date = m.group(1)
    return host, date

# ----------------------------------------------------------------------
# Destination & Move
# ----------------------------------------------------------------------
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

    elif classification == "vm_package":
        dir_ = root / "Hosts" / hostname / "vm"
        ext = src.suffix or (".ova" if details.get("package") == "ova" else ".ovf")
        name = f"vm_pkg_{hostname}_{date_str}{ext}"

    elif classification == "vm_disk":
        dir_ = root / "Hosts" / hostname / "vm"
        ext = src.suffix or f".{details.get('format','img')}"
        name = f"vm_{hostname}_{date_str}{ext}"

    else:
        dir_ = root / "Hosts" / hostname
        if classification == "e01":
            ext = ".E01"
        elif classification == "mem":
            ext = src.suffix or ".mem"
        elif classification == "disk_raw":
            ext = src.suffix or ".img"
        else:
            ext = src.suffix or ""
        name = f"{hostname}_{date_str}{ext}"

    ensure_dirs(dir_)
    dest = dir_ / name
    i = 1
    while dest.exists():
        stem, suf = os.path.splitext(name)
        dest = dest.with_name(f"{stem}__{i}{suf}")
        i += 1
    return dest

def move_atomic(src: Path, dest: Path) -> None:
    try:
        src.rename(dest)
    except OSError:
        shutil.copy2(src, dest)
        src.unlink()

# ----------------------------------------------------------------------
# Fragment note
# ----------------------------------------------------------------------
def append_fragment_note(details: Dict[str, Any], dest: Path) -> None:
    if not FRAGMENT_LOG or not details.get("fragmented"):
        return
    lines = [
        str(dest), "### FRAGMENTED E01 ###", "Parts:",
        *[f"  - {p}" for p in details.get("parts", [])], "",
        "INSTRUCTIONS:",
        "1) Use FTK Imager → Mount → Export defragmented E01",
        "2) Drop back into Staging", "-"*50, ""
    ]
    FRAGMENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with FRAGMENT_LOG.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ----------------------------------------------------------------------
# Queue
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# Lock
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# Processing
# ----------------------------------------------------------------------
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
            if not wait_stable(src, STABLE_SECONDS):
                return

            # Skip secondary EWF segments; primaries will consume them
            if is_ewf_secondary_segment(src):
                ignored = STAGING_ROOT / "ignored"
                ensure_dirs(ignored)
                dst = ignored / src.name
                move_atomic(src, dst)
                json_log("ewf_segment_skipped", src_path=str(src), dest_path=str(dst), note="secondary_segment")
                return

            # Pre-sig (source) to avoid duplicate churn on same upload
            src_sig = fast_signature(src)
            if already_processed(conn, src_sig):
                ignored = STAGING_ROOT / "ignored"
                ensure_dirs(ignored)
                dest_ignored = ignored / src.name
                move_atomic(src, dest_ignored)
                json_log("duplicate_ignored", original_name=src.name, dest_path=str(dest_ignored), profile=profile, sig=src_sig)
                return

            classification, details = classify_file(src, datasources)
            if classification == "unknown":
                json_log("skipped_unknown", original_name=src.name, src_path=str(src), profile=profile, sig=src_sig)
                return

            hostname = details.get("hostname") or src.stem
            dest = build_destination(src, datasources, classification, details)
            final_path = None  # will be set to the file we enqueue/log/DB

            if classification == "e01":
                # Attempt auto-defrag before moving original
                date_str = details.get("date_collected", ymd_from_mtime(src))
                defrag_dest = dest.parent / f"{hostname}_{date_str}_defragmented.E01"
                merged_path = defragment_e01_fragments(src, defrag_dest, owner)

                if merged_path:
                    # Archive the original primary to ignored to prevent reprocessing
                    ignored = STAGING_ROOT / "ignored"
                    ensure_dirs(ignored)
                    ignored_dest = ignored / src.name
                    move_atomic(src, ignored_dest)
                    final_path = merged_path
                    fragged = True
                else:
                    # Fall back to normal move + fragment note
                    move_atomic(src, dest)
                    safe_chown(dest, owner, owner)
                    safe_chown(dest.parent, owner, owner)
                    append_fragment_note(details.get("fragmentation", {}), dest)
                    final_path = dest
                    fragged = details.get("fragmentation", {}).get("fragmented")

            else:
                # Non-E01 classifications
                move_atomic(src, dest)
                safe_chown(dest, owner, owner)
                safe_chown(dest.parent, owner, owner)
                final_path = dest
                fragged = None

            # Duplicate check against the final artifact
            final_sig = fast_signature(final_path)
            if already_processed(conn, final_sig):
                ignored2 = STAGING_ROOT / "ignored"
                ensure_dirs(ignored2)
                dup = ignored2 / final_path.name
                move_atomic(final_path, dup)
                json_log("duplicate_ignored", dest_path=str(dup), sig=final_sig)
                return

            # Build work order
            work: Dict[str, Any] = {
                "schema": "wade.queue.workorder",
                "version": 1,
                "id": str(uuid.uuid4()),
                "created_utc": utc_now_iso(),
                "profile": profile,
                "classification": classification,
                "original_name": src.name,
                "source_host": os.uname().nodename,
                "dest_path": str(final_path),
                "size_bytes": final_path.stat().st_size,
                "sig": final_sig,
            }
            if classification in ("e01", "mem", "vm_disk"):
                work.update(hostname=hostname, date_collected=details.get("date_collected", ymd_from_mtime(final_path)))
            if classification == "network_config":
                work.update(vendor=details.get("vendor"), os_version=details.get("os_version"), hostname=hostname)
            if classification == "vm_disk":
                work.update(vm_format=details.get("format"))
            if classification == "vm_package":
                work.update(vm_package=details.get("package"))
            if classification == "misc":
                work["hostname"] = hostname

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
                "size_bytes": final_path.stat().st_size,
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
                    md["fragmented"] = bool(fragged)
                if classification == "mem":
                    md["mem_kind"] = details.get("mem_signature", {}).get("kind")
                if classification == "vm_package":
                    md["package"] = details.get("package")
                log_payload["metadata"] = {k: v for k, v in md.items() if v is not None}

            json_log(**log_payload)
            record_processed(conn, final_sig, src, final_path, classification, profile)

    except Exception as exc:
        failed = src.with_suffix(".failed")
        try:
            src.rename(failed)
        except Exception:
            pass
        json_log("processing_failed", original_name=src.name, src_path=str(src), error=str(exc), profile=profile)
        raise

# ----------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------
def build_paths() -> Tuple[str, Path, Path, Path, Path]:
    env = load_env()
    owner = env.get("WADE_OWNER_USER", DEFAULT_OWNER)
    datadir = Path(env.get("WADE_DATADIR", DEFAULT_DATADIR))
    staging = Path(env.get("WADE_STAGINGDIR", DEFAULT_STAGINGDIR))
    home = Path(f"/home/{owner}")
    staging_root = home / staging
    full = staging_root / "full"
    light = staging_root / "light"
    datasources = home / datadir
    queue_root = Path(env.get("WADE_QUEUE_DIR", "_queue"))
    if not queue_root.is_absolute():
        queue_root = datasources / queue_root

    global STATE_DIR, LOG_ROOT, SQLITE_DB, STAGING_ROOT, FRAGMENT_LOG
    STATE_DIR = Path("/var/wade/state")
    LOG_ROOT = Path("/var/wade/logs/stage")
    SQLITE_DB = STATE_DIR / "staging_index.sqlite3"
    STAGING_ROOT = staging_root
    FRAGMENT_LOG = datasources / "images_to_be_defragmented.log"

    ensure_dirs(full, light, datasources / "Hosts", datasources / "Network",
                staging_root / "ignored", queue_root, STATE_DIR, LOG_ROOT)

    # Queue hygiene: remove >7d old work orders
    cutoff = time.time() - 7 * 86400
    for class_dir in queue_root.glob("*"):
        for prof_dir in class_dir.glob("*"):
            for f in prof_dir.glob("*.json"):
                try:
                    if f.stat().st_mtime < cutoff:
                        f.unlink(missing_ok=True)
                except Exception:
                    pass

    return owner, full, light, datasources, queue_root

# ----------------------------------------------------------------------
# Main Loop
# ----------------------------------------------------------------------
def iter_files(dir_: Path) -> Iterable[Path]:
    for p in dir_.iterdir():
        if p.is_file() and not p.name.lower().endswith((".part", ".tmp", ".crdownload")):
            yield p

def polling_loop(conn, full, light, datasources, queue_root, owner, should_stop):
    print(f"[+] Polling mode – scanning every {SCAN_INTERVAL_SEC}s")
    while not should_stop():
        for directory, prof in ((full, "full"), (light, "light")):
            for p in iter_files(directory):
                process_one(conn, p, datasources, prof, owner, queue_root)
        for _ in range(SCAN_INTERVAL_SEC):
            if should_stop():
                return
            time.sleep(1)

def inotify_loop(conn, full, light, datasources, queue_root, owner, should_stop):
    inotify = INotify()
    watch_flags = flags.CLOSE_WRITE | flags.MOVED_TO | flags.CREATE
    wd_full = inotify.add_watch(str(full), watch_flags)
    wd_light = inotify.add_watch(str(light), watch_flags)
    print("[+] inotify mode – waiting for events")
    while not should_stop():
        for ev in inotify.read(timeout=1000):
            if should_stop():
                return
            if ev.name.lower().endswith((".part", ".tmp", ".crdownload")):
                continue
            dir_ = full if ev.wd == wd_full else light
            path = dir_ / ev.name
            if path.is_file():
                process_one(conn, path, datasources, "full" if ev.wd == wd_full else "light", owner, queue_root)

def classify_file(p: Path, datasources: Path) -> Tuple[str, Dict[str, Any]]:
    # Registration order determines precedence (E01 → mem → vm_disk → disk_raw → network → vm_package → misc)
    for clf in CLASSIFIERS:
        cls, details = clf(p, datasources)
        if cls:
            return cls, details
    return "unknown", {}

def main() -> None:
    owner, stage_full, stage_light, datasources, queue_root = build_paths()
    conn = init_db()
    stop = False
    def _sig(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    print("[*] WADE staging daemon starting…")
    try:
        if INOTIFY_AVAILABLE:
            inotify_loop(conn, stage_full, stage_light, datasources, queue_root, owner, should_stop=lambda: stop)
        else:
            polling_loop(conn, stage_full, stage_light, datasources, queue_root, owner, should_stop=lambda: stop)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
