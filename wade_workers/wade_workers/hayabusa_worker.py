#!/usr/bin/env python3
import os, subprocess, shutil, json
from pathlib import Path
from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

class HayabusaWorker(BaseWorker):
    tool = "hayabusa"
    help_text = "Hayabusa analysis over exported Windows EVTX logs."
    prefer_jsonl = True

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.hay = self.env.get("HAYABUSA_DEST") or shutil.which("hayabusa")

    def run(self, ticket: dict) -> WorkerResult:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        paths = wade_paths(self.env, host)
        evtx_dir = paths["host_root"]/ "winevtlog"
        if not evtx_dir.exists():
            return WorkerResult(None, 0, [f"evtx_dir_missing:{evtx_dir}"])
        if not self.hay:
            return WorkerResult(None, 0, ["hayabusa_not_found"])
        if self.should_skip_by_splunk(host, "hayabusa", str(evtx_dir)):
            return WorkerResult(None, 0, ["dedupe_splunk"])

        # Generate line-delimited JSON (hayabusa supports JSON output via -o json)
        p = subprocess.run(
            [self.hay, "scan", "-d", str(evtx_dir), "-o", "json"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if p.returncode != 0 or not p.stdout.strip():
            self.module = "scan"
            return self.run_records(host, [{"ts": now_iso(), "stderr": p.stderr, "error":"hayabusa_failed"}], str(evtx_dir))

        # Parse lines to dicts
        self.module = "scan"
        dicts = []
        for line in p.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                dicts.append(json.loads(line))
            except Exception:
                pass
        return self.run_records(host, dicts, str(evtx_dir))
