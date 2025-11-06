#!/usr/bin/env python3
import shutil, subprocess
from pathlib import Path
from typing import List, Dict, Tuple

from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

def _cmd(env: Dict[str,str]) -> str:
    # Allow override with DISSECT_CMD; otherwise prefer target-info in PATH
    return env.get("DISSECT_CMD") or (shutil.which("target-info") and "target-info") or "target-info"

class DissectWorker(BaseWorker):
    tool = "dissect"
    module = "target-info"
    help_text = "Run Dissect target-info to capture disk layout & metadata."

    def _host_and_img(self, ticket) -> Tuple[str, Path]:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        p = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not p.exists():
            raise FileNotFoundError(f"target not found: {p}")
        return host, p

    def _append_log(self, host: str, text: str):
        _, log_dir = wade_paths(self.env, host, self.tool, self.module)
        (log_dir / f"{self.tool}_{self.module}.log").write_text(
            ((log_dir / f"{self.tool}_{self.module}.log").read_text(encoding="utf-8", errors="ignore") if (log_dir / f"{self.tool}_{self.module}.log").exists() else "")
            + text.rstrip() + "\n",
            encoding="utf-8"
        )

    def run(self, ticket: dict) -> WorkerResult:
        host, img = self._host_and_img(ticket)
        cmd = _cmd(self.env)
        args = [cmd, str(img)]
        self._append_log(host, f"{now_iso()} running: {' '.join(args)}")
        errors: List[str] = []

        try:
            cp = subprocess.run(args, capture_output=True, text=True, check=False)
        except Exception as e:
            return WorkerResult(None, 0, [f"spawn: {e!r}"])

        if cp.returncode != 0:
            errors.append(f"rc={cp.returncode} stderr={cp.stderr.strip()[:4000]}")
            rec = {"ts": now_iso(), "rc": cp.returncode, "stderr": cp.stderr}
            out, cnt = self.run_records(host, [rec], str(img))
            return WorkerResult(out, cnt, errors)

        # Store textual output as a single record; downstream can parse
        rec = {"ts": now_iso(), "stdout": cp.stdout}
        out, cnt = self.run_records(host, [rec], str(img))
        return WorkerResult(out, cnt, errors)
