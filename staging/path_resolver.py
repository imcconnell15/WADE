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
    """
    Return the file's modification date as a YYYY-MM-DD string.
    
    Parameters:
        p (Path): Path to the file whose modification time will be used. If the file's mtime cannot be read, the current date is used.
    
    Returns:
        date_str (str): Date formatted as `YYYY-MM-DD` derived from the file's modification time or the current date on error.
    """
    try:
        mtime = p.stat().st_mtime
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d")


def _sanitize(s: str) -> str:
    """
    Produce a filesystem-safe component from an arbitrary string.
    
    Replaces any of the characters < > : " | ? * with underscores and trims leading/trailing whitespace as well as trailing dots and spaces.
    
    Parameters:
        s (str): Input string to sanitize.
    
    Returns:
        str: A sanitized string suitable for use as a filesystem path component.
    """
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
    """
    Map a classification label to the sourcetype used for destination paths.
    
    Parameters:
        classification (str): Classification label (e.g., "e01", "memory", "vm_disk").
    
    Returns:
        str: The corresponding sourcetype (e.g., "disk", "memory", "vm"); returns "misc" if the classification is unknown.
    """
    return CLASSIFICATION_TO_SOURCETYPE.get(str(classification).lower(), "misc")

def build_destination(
    src: Path,
    root: Path,
    classification: str,
    details: Dict[str, Any],
) -> Path:
    """
    Build the destination path for a source file within the DataSources hierarchy.
    
    Parameters:
        src (Path): Source file path whose name will be preserved (or suffixed if a conflict occurs).
        root (Path): Root DataSources directory under which the file will be placed.
        classification (str): Classification label used to determine the sourcetype subdirectory.
        details (Dict[str, Any]): Metadata used to determine the hostname; `details["hostname"]` or `details["host_id"]` are preferred and fall back to the source stem.
    
    Returns:
        Path: A filesystem path of the form <root>/<sourcetype>/<hostname>/<filename>. If a file with the same name already exists, a numeric suffix (`__N`) is appended to the stem to avoid collisions.
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
    """
    Detect the staging profile and optional location from a path within a staging root.
    
    Recognizes these layouts:
    - <Staging>/full/<file>                   → profile "full", no location
    - <Staging>/light/<file>                  → profile "light", no location
    - <Staging>/<location>/full/<file>        → profile "full", location is <location>
    - <Staging>/<location>/light/<file>       → profile "light", location is <location>
    
    Parameters:
        path (Path): Path to the file to analyze.
        staging_root (Path): Root staging directory to interpret the relative layout.
    
    Returns:
        Tuple[str, Optional[str]]: `profile` is "full" or "light"; `location` is the location directory name when present, otherwise `None`.
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
    """
    Determine the host ID by checking whether the file's stem contains the name of an existing host directory.
    
    Parameters:
        datasources (Path): Path to the DataSources root containing a "Hosts" directory.
        p (Path): Path to the file whose stem should be matched against host names.
    
    Returns:
        hostname (str) or None: The matching host directory name if found, `None` otherwise.
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