"""
Staging daemon configuration and constants.

All environment variables and magic byte signatures centralized here.
"""
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ============================================================================
# Paths
# ============================================================================
OWNER_USER = os.getenv("WADE_OWNER_USER", "autopsy")
DATADIR = Path(os.getenv("WADE_DATADIR", f"/home/{OWNER_USER}/DataSources"))
STAGING_ROOT = Path(os.getenv("WADE_STAGING", f"/home/{OWNER_USER}/Staging"))
QUEUE_DIR = DATADIR / os.getenv("WADE_QUEUE_DIR", "_queue")

STAGE_FULL = STAGING_ROOT / "full"
STAGE_LIGHT = STAGING_ROOT / "light"

# ============================================================================
# Logging
# ============================================================================
LOG_DIR = Path(os.getenv("WADE_LOG_DIR", "/var/log/wade"))
FRAGMENT_LOG = LOG_DIR / "fragmented_e01.log" if os.getenv("WADE_FRAGMENT_LOG") else None

# ============================================================================
# Processing Options
# ============================================================================
REQUIRE_CLOSE_WRITE = os.getenv("WADE_STAGE_REQUIRE_CLOSE_WRITE", "1") == "1"
VERIFY_NO_WRITERS = os.getenv("WADE_STAGE_VERIFY_NO_WRITERS", "1") == "1"
WADE_STAGE_RECURSIVE = os.getenv("WADE_STAGE_RECURSIVE", "0") == "1"
WADE_STAGE_ACCEPT_DOCS = os.getenv("WADE_STAGE_ACCEPT_DOCS", "0") == "1"
AUTO_DEFRAG_E01 = os.getenv("WADE_AUTODEFRAG_E01", "0") == "1"

# Wait times
WAIT_STABLE_SEC = int(os.getenv("WADE_STAGE_WAIT_STABLE", "5"))
POLL_INTERVAL_SEC = int(os.getenv("WADE_STAGE_POLL_INTERVAL", "30"))

# ============================================================================
# Tool Paths
# ============================================================================
LSOF_CMD = os.getenv("WADE_LSOF_PATH", "lsof")
EWFINFO_PATH = os.getenv("WADE_EWFINFO_PATH")  # Auto-detected if None
EWFEXPORT_PATH = os.getenv("WADE_EWFEXPORT_PATH")
VOLATILITY_PATH = os.getenv("WADE_VOLATILITY3_PATH", "vol.py")

# ============================================================================
# Detection Constants
# ============================================================================
HEAD_SCAN_BYTES = 512 * 1024  # 512KB head/tail for magic detection
TEXT_SNIFF_BYTES = 4 * 1024    # 4KB for text detection
MEM_MIN_BYTES = 64 * 1024 * 1024  # 64MB minimum for raw memory dumps

# Magic byte signatures (offset, bytes) pairs
MAGIC_DB: Dict[str, List[Tuple[int, bytes]]] = {
    # EWF/E01
    "ewf": [
        (0, b"EVF\x09\r\n\x81\x00"),  # EVF2
        (0, b"EVF2\r\n\x81\x00"),     # EVF2 alt
        (0, b"EVF\x01"),               # EVF1
    ],
    
    # Memory dumps
    "hibr": [(0, b"hibr"), (0, b"HIBR")],
    "lime": [(0, b"EMiL")],
    
    # Disk partition tables
    "gpt": [(0, b"EFI PART")],
    "mbr": [(510, b"\x55\xAA")],
    
    # Filesystems
    "ntfs": [(3, b"NTFS    ")],
    "fat32": [(82, b"FAT32   ")],
    
    # VM formats
    "qcow": [(0, b"QFI\xfb")],
    "vhdx": [(0x200, b"vhdxfile")],
    "vmdk": [(0, b"KDMV")],
    "vdi": [(64, b"<<< Oracle VM VirtualBox")],
    
    # Archive formats
    "tar_ustar": [(257, b"ustar")],
}

# ============================================================================
# Database
# ============================================================================
DB_PATH = Path(os.getenv("WADE_STAGE_DB", "/var/wade/staging_state.db"))

# ============================================================================
# Whiff Integration (optional AI assist)
# ============================================================================
WHIFF_ENABLED = os.getenv("WADE_WHIFF_ENABLED", "0") == "1"
WHIFF_URL = os.getenv("WADE_WHIFF_URL", "http://localhost:8000")
