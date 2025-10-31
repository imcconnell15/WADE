#!/usr/bin/env python3
from __future__ import annotations
import os, subprocess, shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from .utils import load_env, wade_paths, finalize_records_to_json, now_iso
from .splunk_dedupe import SplunkDedupe

@dataclass
class WorkerResult:
    path: Optional[Path]
    count: int
    errors: List[str]

class BaseWorker:
    tool: str = "base"
    module: str = "base"
    help_text: str = "Base worker"
    prefer_jsonl: bool = True

    def __init__(self, env: Optional[Dict[str,str]] = None, config: Optional[dict] = None):
        self.env = env or load_env()
        self.config = config or {}
        self.dedupe = SplunkDedupe(self.env, self.config.get("splunk", {}))

    def should_skip_by_splunk(self, host: str, module: str, image_path: Optional[str]) -> bool:
        # opt-in dedupe: disabled unless configured
        return self.dedupe.already_ingested(host, self.tool, module, image_path)

    def run_records(self, host: str, records: Iterable[dict], image_path: Optional[str]) -> WorkerResult:
        final, cnt = finalize_records_to_json(
            self.env, host, self.tool, self.module, records, self.help_text, image_path, self.prefer_jsonl
        )
        return WorkerResult(final, cnt, [])

    # Abstract-ish
    def run(self, ticket: dict) -> WorkerResult:  # pragma: no cover
        raise NotImplementedError

    # Helpers
    def which(self, name: str) -> Optional[str]:
        return shutil.which(name)  # type: ignore

    def popen(self, args: List[str], **kw):
        return subprocess.Popen(args, **kw)
