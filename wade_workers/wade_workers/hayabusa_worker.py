#!/usr/bin/env python3
import shutil, subprocess
from pathlib import Path
from typing import List, Dict, Tuple

from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

def _cmd(env: Dict[str,str]) -> str:
    return env.get("HAYABUSA_CMD") or (shutil.which("hayabusa") and "hayabusa") or "hayabusa"

def _rules_dir(env: Dict[str,str], cfg: dict) -> Path | None:
    p = None
    if "hayabusa" in cfg and isinstance(cfg["hayabusa"], dict) and cfg["hayabusa"].get("rules_dir"):
        p = Path(cfg["hayabusa"]["rules_dir"])
    if not p:
        v = env.get("HAYABUSA_RULES_DIR")
        if v:
            p = Path(v)
    return p if p and p.exists() else None

class HayabusaWorker(BaseWorker):
    tool = "hayabusa"
    module = "csv"
    help_text = "Run Hayabusa against Windows event logs. Emits a summary record and path to CSV."

    def _host_and_src(self, ticket) -> Tuple[str, Path]:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        p = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not p.exists():
            raise FileNotFoundError(f"input not found: {p}")
        return host, p

    def run(self, ticket: dict) -> WorkerResult:
        host, src = self._host_and_src(ticket)
        hay = _cmd(self.env)
        if not shutil.which(hay):
            return WorkerResult(None, 0, [f"hayabusa not found (HAYABUSA_CMD={hay})"])

        out_dir, _ = wade_paths(self.env, host, self.tool, self.module)
        out_csv = out_dir / f"hayabusa_{now_iso().replace(':','').replace('-','').replace('T','_').replace('Z','')}.csv"

        rules = _rules_dir(self.env, self.config)
        # Try the common invocation pattern. If src is a dir, use -d; if file, -f.
        args = [hay, "csv"]
        if rules:
            args += ["-r", str(rules)]
        if src.is_dir():
            args += ["-d", str(src)]
        else:
            args += ["-f", str(src)]
        args += ["-o", str(out_csv)]

        try:
            cp = subprocess.run(args, capture_output=True, text=True, check=False)
        except Exception as e:
            return WorkerResult(None, 0, [f"spawn: {e!r}"])

        errors: List[str] = []
        if cp.returncode != 0:
            errors.append(f"rc={cp.returncode} stderr={cp.stderr.strip()[:4000]}")

        rec = {
            "ts": now_iso(),
            "csv": str(out_csv),
            "rc": cp.returncode,
            "stderr": cp.stderr.strip() if cp.stderr else "",
            "stdout": cp.stdout.strip() if cp.stdout else "",
            "rules_dir": str(rules) if rules else None,
        }
        out, cnt = self.run_records(host, [rec], str(src))
        return WorkerResult(out, cnt, errors)
