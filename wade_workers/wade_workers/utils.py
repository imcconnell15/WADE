#!/usr/bin/env python3
import os, io, json, shutil, subprocess, tempfile, time, socket
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

WADE_ENV_FILE = Path("/etc/wade/wade.env")
DEFAULTS = {
    "WADE_OWNER_USER": "autopsy",
    "WADE_DATADIR": "DataSources",
    "WADE_STAGINGDIR": "Staging",
    "WADE_QUEUE_DIR": "_queue",
    "WADE_LOG_DIR": "/var/wade/logs",
}

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _parse_env_file(p: Path) -> Dict[str,str]:
    env: Dict[str,str] = {}
    if p.is_file():
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k,v = line.split("=",1)
            env[k.strip()] = v.strip()
    return env

def load_env() -> Dict[str,str]:
    env = dict(DEFAULTS)
    env.update(_parse_env_file(WADE_ENV_FILE))
    env.update({k:v for k,v in os.environ.items() if k.startswith("WADE_") or k.startswith("WHIFF_")})
    return env

def wade_paths(env: Dict[str,str], host: str, tool: str, module: str) -> Tuple[Path, Path]:
    owner   = env.get("WADE_OWNER_USER","autopsy")
    datadir = env.get("WADE_DATADIR","DataSources")
    base = Path(f"/home/{owner}")/datadir / "Hosts" / host / f"wade_{tool}" / module
    base.mkdir(parents=True, exist_ok=True)
    log_dir = Path(env.get("WADE_LOG_DIR","/var/wade/logs"))/ "workers"
    log_dir.mkdir(parents=True, exist_ok=True)
    return base, log_dir

def finalize_records_to_json(env: Dict[str,str], host: str, tool: str, module: str,
                             records: List[dict], help_text: str = "",
                             image_path: Optional[str] = None,
                             prefer_jsonl: bool = True) -> Tuple[Path,int]:
    out_dir, _ = wade_paths(env, host, tool, module)
    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    out = out_dir / f"{tool}_{module}_{ts}.jsonl"
    cnt = 0
    with open(out, "w", encoding="utf-8") as f:
        for rec in records:
            rec = dict(rec)
            rec.setdefault("host", host)
            rec.setdefault("tool", tool)
            rec.setdefault("module", module)
            if help_text:  rec.setdefault("help_text", help_text)
            if image_path: rec.setdefault("image_path", image_path)
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            cnt += 1
    return out, cnt

def read_ticket(p: Path) -> Optional[dict]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
