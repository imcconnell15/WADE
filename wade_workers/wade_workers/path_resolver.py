from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from .ticket_schema import WorkerTicket

# Map staging classifications to $sourcetype directory names
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
    "e01_fragment": "disk",  # normally skipped; here for completeness
}

def _sanitize(s: str) -> str:
    # Windows-invalid and reserved characters stripping for cross-platform safety
    s = re.sub(r'[<>:"|?*\r\n\t]', "_", s)
    return s.strip().strip(". ")

def sourcetype_for(classification: str) -> str:
    return CLASSIFICATION_TO_SOURCETYPE.get(str(classification).lower(), "misc")

def now_utc_compact() -> str:
    # YYYYmmddTHHMMSSZ (UTC)
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def datasources_root_from_env(env: dict | None) -> Path:
    owner = (env or {}).get("WADE_OWNER_USER") or os.environ.get("WADE_OWNER_USER", "autopsy")
    default_root = f"/home/{owner}/DataSources"
    return Path((env or {}).get("WADE_DATADIR") or os.environ.get("WADE_DATADIR", default_root))

def compute_worker_output_paths(
    ticket: WorkerTicket,
    tool: str,
    module: str,
    env: dict | None = None,
) -> Tuple[Path, Path]:
    """
    Returns (output_dir, output_file) per the required layout:
    DataSources/$sourcetype/$hostname/$tool/$module/$hostname_$datetime.jsonl
    """
    root = datasources_root_from_env(env)
    m = ticket.metadata
    hostname = _sanitize(m.hostname or "unknown_host")
    sourcetype = sourcetype_for(m.classification)

    tool_dir = _sanitize(tool)
    module_dir = _sanitize(module.replace(".", "_"))

    output_dir = root / sourcetype / hostname / tool_dir / module_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = now_utc_compact()
    outfile = output_dir / f"{hostname}_{ts}.jsonl"
    return output_dir, outfile
