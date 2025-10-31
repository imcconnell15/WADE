#!/usr/bin/env python3
import os, shutil, yara, tempfile
from pathlib import Path
from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

class YaraWorker(BaseWorker):
    tool = "yara"
    help_text = "YARA scanning (memory image or selected mounted paths)."
    prefer_jsonl = True

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.ruleset = self.config.get("yara", {}).get("ruleset", "/opt/wade/yara/packed_rules.yar")

    def _compile_rules(self):
        try:
            return yara.compile(filepath=self.ruleset)
        except Exception as e:
            return None

    def run(self, ticket: dict) -> WorkerResult:
        kind = ticket.get("kind")
        path = Path(ticket.get("dest_path",""))
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        if not path.exists():
            return WorkerResult(None, 0, ["target_missing"])
        if self.should_skip_by_splunk(host, "yara", str(path)):
            return WorkerResult(None, 0, ["dedupe_splunk"])

        rules = self._compile_rules()
        if not rules:
            return WorkerResult(None, 0, ["yara_compile_failed"])

        hits = []
        try:
            # Simple strategy: scan the file itself (memory image, archive, etc.)
            for m in rules.match(data=path.read_bytes(), timeout=30):
                hits.append({"rule": m.rule, "tags": m.tags, "meta": m.meta})
        except Exception as e:
            hits.append({"error":"yara_scan_error","detail":str(e)})

        self.module = "scan"
        return self.run_records(host, hits, str(path))
