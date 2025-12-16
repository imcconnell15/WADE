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
    """
    Sanitize a string for safe use in filesystem paths.
    
    Replaces characters that are invalid or problematic on Windows ( < > : " | ? * and carriage return, newline, tab ) with underscores, then trims leading and trailing whitespace as well as leading/trailing dots and spaces.
    
    Parameters:
        s (str): Input string to sanitize.
    
    Returns:
        str: The sanitized string suitable for use in file or directory names.
    """
    s = re.sub(r'[<>:"|?*\r\n\t]', "_", s)
    return s.strip().strip(". ")

def sourcetype_for(classification: str) -> str:
    """
    Map a staging classification string to a sourcetype directory name.
    
    Parameters:
        classification (str): Staging classification value (case-insensitive).
    
    Returns:
        str: The mapped sourcetype name, or "misc" if the classification is not recognized.
    """
    return CLASSIFICATION_TO_SOURCETYPE.get(str(classification).lower(), "misc")

def now_utc_compact() -> str:
    # YYYYmmddTHHMMSSZ (UTC)
    """
    Return the current UTC time as a compact timestamp.
    
    Returns:
        A string with the current UTC time in the format YYYYmmddTHHMMSSZ (for example, "20251216T123456Z").
    """
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def datasources_root_from_env(env: dict | None) -> Path:
    """
    Determine the DataSources root path using environment variables with sensible defaults.
    
    Parameters:
        env (dict | None): Optional mapping to use in place of os.environ for lookups. If provided, keys
            "WADE_OWNER_USER" and "WADE_DATADIR" are read from this mapping before falling back to os.environ.
    
    Returns:
        pathlib.Path: Resolved path for the DataSources root. Resolution order:
            - Use "WADE_DATADIR" from `env` if present,
            - else use "WADE_DATADIR" from os.environ if present,
            - else construct "/home/{owner}/DataSources" where `owner` is taken from "WADE_OWNER_USER"
              in `env`, then os.environ, and defaults to "autopsy".
    """
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
    Compute and ensure the filesystem output directory and a timestamped JSONL file path for a worker's results.
    
    Parameters:
        ticket (WorkerTicket): Ticket whose metadata provides `hostname` (falls back to "unknown_host") and `classification` (mapped to a sourcetype) used to build the path.
        tool (str): Tool name to use as a subdirectory (sanitized).
        module (str): Module name to use as a subdirectory (dots are replaced with underscores and the result is sanitized).
        env (dict | None): Optional environment mapping used to determine the DataSources root (overrides os.environ when provided).
    
    Returns:
        Tuple[Path, Path]: A pair (output_dir, output_file) where `output_dir` is the created directory
        DataSources/<sourcetype>/<hostname>/<tool>/<module> and `output_file` is a Path to
        "<hostname>_YYYYmmddTHHMMSSZ.jsonl" inside that directory.
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