#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from .utils import load_env, finalize_records_to_json

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

    def run_records(self, host: str, records: List[dict], image_path: Optional[str] = None) -> WorkerResult:
        final, cnt = finalize_records_to_json(
            self.env, host, self.tool, self.module, records, self.help_text, image_path, self.prefer_jsonl
        )
        return WorkerResult(final, cnt, [])

    def run(self, ticket: dict) -> WorkerResult:
        raise NotImplementedError
