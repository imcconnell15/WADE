#!/usr/bin/env python3
import os, shutil, subprocess
from pathlib import Path
from typing import List, Dict, Tuple

from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

def _be_cmd(env: Dict[str,str]) -> str:
    return env.get("BULK_EXTRACTOR_CMD") or (shutil.which("bulk_extractor") and "bulk_extractor") or "bulk_extractor"

class BulkExtractorWorker(BaseWorker):
    tool = "bulkextractor"
    module = "features"
    help_text = "Run bulk_extractor to carve feature files; we emit a summary JSON."

    def _host_and_img(self, ticket) -> Tuple[str, Path]:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        p = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not p.exists():
            raise FileNotFoundError(f"artifact not found: {p}")
        return host, p

    def _append_log(self, host: str, text: str):
        _, log_dir = wade_paths(self.env, host, self.tool, self.module)
        with open(log_dir / f"{self.tool}_{self.module}.log", "a", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n")

    def run(self, ticket: dict) -> WorkerResult:
        host, f = self._host_and_img(ticket)
        be = _be_cmd(self.env)
        if not shutil.which(be):
            return WorkerResult(None, 0, [f"bulk_extractor not found (BULK_EXTRACTOR_CMD={be})"])

        # Put BE output in the same wade_ tree for traceability
        out_dir, _ = wade_paths(self.env, host, self.tool, self.module)
        be_out = out_dir / f"be_{int(os.stat(f).st_mtime)}"
        be_out.mkdir(parents=True, exist_ok=True)

        args = [be, "-o", str(be_out), str(f)]
        self._append_log(host, f"{now_iso()} running: {' '.join(args)}")
        try:
            cp = subprocess.run(args, capture_output=True, text=True, check=False)
        except Exception as e:
            return WorkerResult(None, 0, [f"spawn: {e!r}"])

        errors: List[str] = []
        if cp.returncode != 0:
            errors.append(f"rc={cp.returncode} stderr={cp.stderr.strip()[:4000]}")

        # Summarize feature files present
        feats = []
        for ff in sorted(be_out.glob("*.txt")):
            try:
                size = ff.stat().st_size
            except Exception:
                size = 0
            feats.append({"file": ff.name, "bytes": size})

        rec = {
            "ts": now_iso(),
            "be_out_dir": str(be_out),
            "feature_files": feats,
            "stderr": cp.stderr.strip() if cp.stderr else "",
            "rc": cp.returncode,
        }
        out, cnt = self.run_records(host, [rec], str(f))
        return WorkerResult(out, cnt, errors)
