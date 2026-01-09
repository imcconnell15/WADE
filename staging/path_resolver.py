"""
Path resolution and destination building for staging daemon.

Implements the directory routing system that determines where files
are staged and which tools will process them.

Directory structure:
  DataSources/
    Hosts/{hostname}/                # Classified host artifacts
    Network/{hostname}/              # Network configs
    VM/{hostname}/                   # VM images
    Malware/{filename}/              # Malware samples
    Misc/                            # Uncategorized
"""
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from .config import DATADIR


def ymd_from_mtime(p: Path) -> str:
    """Extract YYYY-MM-DD from file mtime.
    
    Args:
        p: File path
    
    Returns:
        Date string (YYYY-MM-DD)
    """
    try:
        mtime = p.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _sanitize(s: str) -> str:
    s = re.sub(r'[<>:"|?*]', "_", s)
    return s.strip().strip(". ")

CLASSIFICATION_TO_SOURCETYPE = {
    "memory": "memory",
    "e01": "disk",
    "disk_raw": "disk",
    "vm_disk": "vm",
    "vm_package": "vm",
    "network_config": "network",
    "network_doc": "network-docs",
    "malware": "malware",
    "misc": "misc",
    "unknown": "misc",
}

def sourcetype_for(classification: str) -> str:
    return CLASSIFICATION_TO_SOURCETYPE.get(str(classification).lower(), "misc")

def build_destination(
    src: Path,
    root: Path,
    classification: str,
    details: Dict[str, Any],
) -> Path:
    """
    New routing:
      Raw evidence -> DataSources/$sourcetype/$hostname/<original_filename>
    """
    hostname = details.get("hostname") or details.get("host_id") or src.stem
    hostname = _sanitize(hostname)
    sourcetype = sourcetype_for(classification)

    dir_ = root / sourcetype / hostname
    dir_.mkdir(parents=True, exist_ok=True)

    dest = dir_ / src.name
    counter = 1
    while dest.exists():
        stem, suf = src.stem, src.suffix
        dest = dir_ / f"{stem}__{counter}{suf}"
        counter += 1
    return dest

def detect_profile(path: Path, staging_root: Path) -> Tuple[str, Optional[str]]:
    """Detect staging profile from path structure.
    
    Supported layouts:
      - <Staging>/full/<file>          → ("full", None)
      - <Staging>/light/<file>         → ("light", None)
      - <Staging>/<location>/full/<file> → ("full", location)
      - <Staging>/<location>/light/<file> → ("light", location)
    
    Args:
        path: File path
        staging_root: Staging root directory
    
    Returns:
        Tuple of (profile, location)
    """
    try:
        rel = path.relative_to(staging_root)
    except ValueError:
        # Not under staging root; default to full
        return "full", None
    
    parts = rel.parts
    if not parts:
        return "full", None
    
    # Check if first part is profile
    if parts[0] in ("full", "light"):
        return parts[0], None
    
    # Check if second part is profile (location/profile pattern)
    if len(parts) > 1 and parts[1] in ("full", "light"):
        return parts[1], parts[0]
    
    # Default
    return "full", None


def match_host_from_filename(datasources: Path, p: Path) -> Optional[str]:
    """Extract host ID if filename matches existing host directory.
    
    Useful for misc files dropped with host-identifying names.
    
    Args:
        datasources: DataSources root
        p: File path
    
    Returns:
        Hostname if matched, None otherwise
    """
    hosts_dir = datasources / "Hosts"
    if not hosts_dir.exists():
        return None
    
    # Get existing hostnames
    try:
        hostnames = {d.name for d in hosts_dir.iterdir() if d.is_dir()}
    except OSError:
        return None
    
    # Check if filename contains a known hostname
    filename_lower = p.stem.lower()
    for hostname in hostnames:
        pattern = re.compile(r'\b' + re.escape(hostname.lower()) + r'\b')
        if pattern.search(filename_lower):
            return hostname
    
    return None
