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
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple

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
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d")


def build_destination(
    src: Path,
    root: Path,
    classification: str,
    details: Dict[str, Any],
) -> Path:
    """Build destination path based on classification and metadata.
    
    Routing logic:
      - network_config → Network/{hostname}/{filename}
      - memory → Hosts/{hostname}{filename}
      - e01 → Hosts/{hostname}/{filename}
      - disk_raw, vm_disk → Hosts/{hostname}/{filename}
      - vm_package → VM/{hostname}/{filename}
      - malware → Malware/{filename}/
      - misc → Hosts/{host_id}/{filename}
      - unknown → Misc/{filename}
    
    Args:
        src: Source file path
        root: DataSources root directory
        classification: File classification
        details: Metadata dict from classifier
    
    Returns:
        Destination path (may not exist yet)
    """
    date_str = details.get("date_collected", ymd_from_mtime(src))
    
    # Primary identity is hostname; fall back to host_id or filename
    hostname = details.get("hostname") or details.get("host_id") or src.stem
    
    # Sanitize hostname for filesystem
    hostname = re.sub(r'[<>:"|?*]', "_", hostname)
    hostname = hostname.strip(". ")
    
    # Choose directory structure based on classification
    if classification == "network_config":
        # Network configs grouped under DataSources/Network/<hostname>/
        dir_ = root / "Network" / hostname
        name = src.name
    
    elif classification == "memory":
        # Memory dumps under Hosts/<hostname>
        dir_ = root / "Hosts" / hostname 
        name = src.name
    
    elif classification in ("e01", "disk_raw", "vm_disk"):
        # Disk images under Hosts/<hostname>/<date>/
        dir_ = root / "Hosts" / hostname 
        name = src.name
    
    elif classification == "vm_package":
        # VM packages (OVA/OVF) under VM/<hostname>/
        dir_ = root / "VM" / hostname
        name = src.name
    
    elif classification == "malware":
        # Malware samples get own directory
        dir_ = root / "Malware" / src.stem
        name = src.name
    
    elif classification == "misc":
        # Misc files under identified host
        host_id = details.get("host_id", hostname)
        dir_ = root / "Misc" / host_id
        name = src.name
    
    elif classification == "network_doc":
        # Network documentation
        dir_ = root / "Network" / host_id
        name = src.name
    
    else:
        # Unknown classification → Misc/<date>/
        dir_ = root / "Misc" / date_str
        name = src.name
    
    # Ensure directory exists
    dir_.mkdir(parents=True, exist_ok=True)
    
    # Handle filename collisions
    dest = dir_ / name
    counter = 1
    while dest.exists():
        stem = src.stem
        suffix = src.suffix
        dest = dir_ / f"{stem}__{counter}{suffix}"
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
        if hostname.lower() in filename_lower:
            return hostname
    
    return None
