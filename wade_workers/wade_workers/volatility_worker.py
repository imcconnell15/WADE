#!/usr/bin/env python3
import os, json, subprocess, shutil
from pathlib import Path
from typing import List, Iterable
from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

DEFAULT_MODULES = [
    # safe, broadly useful windows modules
    "windows.info", "windows.pslist", "windows.pstree", "windows.cmdline",
    "windows.netscan", "windows.handles", "windows.dlllist", "windows.services",
    "windows.malfind",
]

class VolatilityWorker(BaseWorker):
    tool = "volatility3"
    help_text = "Volatility3 memory analysis; modules vary by OS profile."
    prefer_jsonl = True

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.vol = shutil.which("vol3") or shutil.which("vol") or shutil.which("volatility3")

    def _run_module(self, image: Path, module: str) -> Iterable[dict]:
        if not self.vol:
            yield {"ts": now_iso(), "error": "volatility3_not_found", "module": module}
            return
        # Use JSON output if supported; some plugins print tables only.
        out = subprocess.run(
            [self.vol, "-f", str(image), module, "--output", "json"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if out.returncode != 0 or not out.stdout.strip():
            yield {"ts": now_iso(), "module": module, "stderr": out.stderr.strip()[:4000], "error": "module_failed"}
            return
        try:
            data = json.loads(out.stdout)
            if isinstance(data, list):
                for row in data:
                    row["module"] = module
                    yield row
            else:
                yield {"module": module, "data": data}
        except Exception:
            # Fallback: one blob per run
            yield {"module": module, "data_raw": out.stdout}

    def run(self, ticket: dict) -> WorkerResult:
        kind = ticket.get("kind")
        path = Path(ticket.get("dest_path",""))
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        if kind != "memory" or not path.exists():
            return WorkerResult(None, 0, [f"skip kind={kind} path_exists={path.exists()}"])
        if self.should_skip_by_splunk(host, "multi", str(path)):
            return WorkerResult(None, 0, ["dedupe_splunk"])

        modules = self.config.get("volatility", {}).get("modules", DEFAULT_MODULES)
        all_records = []
        for m in modules:
            for rec in self._run_module(path, m):
                all_records.append(rec)

        # Write one file per tool/module-group
        self.module = "memory-suite"
        return self.run_records(host, all_records, str(path))
