from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any
import os, time
from .utils import ensure_dir, write_placeholder

@dataclass
class Job:
    hostname: str
    os_family: str          # 'windows' | 'linux' | 'mac'
    image_path: Path        # mem or disk image path
    tool_hint: str          # 'memory' | 'disk'
    dt_format: str

class BaseWorker:
    def __init__(self, cfg: Dict[str, Any], env: Dict[str, str]):
        self.cfg = cfg
        self.env = env
        self.datasources = Path(os.environ.get("WADE_DATASOURCES", "/home/autopsy/DataSources/Hosts"))
        self.logdir = Path(os.environ.get("WADE_LOG_DIR", "/var/wade/logs"))
        self.status_dir = Path(os.environ.get("WADE_STATUS_DIR", "/var/wade/status"))
        ensure_dir(self.logdir); ensure_dir(self.status_dir)

    def out_dir(self, hostname: str, tool: str, module: str) -> Path:
        return self.datasources / hostname / tool / module

    def json_name(self, hostname: str, module: str, dt: str, ext: str) -> str:
        return f"{hostname}_{module}_{dt}.{ext}"

    def placeholder_no_output(self, outfile_json: Path, meta: Dict[str, Any]) -> None:
        if self.cfg.get("global", {}).get("write_placeholders", True):
            placeholder = outfile_json.with_suffix(".placeholder.json")
            write_placeholder(placeholder, meta)
