#!/usr/bin/env python3
import os, shutil, subprocess
from pathlib import Path
from typing import List, Dict, Tuple

from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

def _yara_cmd(env: Dict[str,str]) -> str:
    return env.get("YARA_CMD") or (shutil.which("yara") and "yara") or "yara"

def _rules_dir(env: Dict[str,str], cfg: dict) -> Path | None:
    # YAML: yara.rules_dir: /opt/wade/yara-rules
    p = None
    if "yara" in cfg and isinstance(cfg["yara"], dict) and cfg["yara"].get("rules_dir"):
        p = Path(cfg["yara"]["rules_dir"])
    if not p:
        v = env.get("YARA_RULES_DIR")
        if v:
            p = Path(v)
    return p if p and p.exists() else None

class YaraWorker(BaseWorker):
    tool = "yara"
    module = "scan"
    help_text = "Scan the artifact with YARA rules; emit one record per match."

    def _host_and_img(self, ticket) -> Tuple[str, Path]:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        p = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not p.exists():
            raise FileNotFoundError(f"file not found: {p}")
        return host, p

    def _append_log(self, host: str, text: str):
        _, log_dir = wade_paths(self.env, host, self.tool, self.module)
        with open(log_dir / f"{self.tool}_{self.module}.log", "a", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n")

    def run(self, ticket: dict) -> WorkerResult:
        host, f = self._host_and_img(ticket)
        yara = _yara_cmd(self.env)
        rules = _rules_dir(self.env, self.config)
        errors: List[str] = []

        if not shutil.which(yara):
            return WorkerResult(None, 0, [f"yara not found (YARA_CMD={yara})"])

        if not rules:
            # No rules? Return gracefully with a single “skipped” record
            rec = {"ts": now_iso(), "skipped": True, "reason": "no rules dir configured"}
            out, cnt = self.run_records(host, [rec], str(f))
            return WorkerResult(out, cnt, [])

        # Recursive scan; output is lines like: RULE FILE:OFFSET STRING...
        # We'll parse minimally into JSON.
        args = [yara, "-r", str(rules), str(f)]
        self._append_log(host, f"{now_iso()} running: {' '.join(args)}")
        try:
            cp = subprocess.run(args, capture_output=True, text=True, check=False)
        except Exception as e:
            return WorkerResult(None, 0, [f"spawn: {e!r}"])

        if cp.returncode not in (0, 1):  # 1 means "no match" in some yara builds
            errors.append(f"rc={cp.returncode} stderr={cp.stderr.strip()[:4000]}")

        records: List[dict] = []
        for line in cp.stdout.splitlines():
            # naive parse: first token is rule, last token(s) include filename/offset
            parts = line.strip().split(None, 1)
            if not parts:
                continue
            rule = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            records.append({"ts": now_iso(), "rule": rule, "detail": rest})

        if not records:
            # emit a “no matches” marker so Splunk can count
            records = [{"ts": now_iso(), "rule_matches": 0}]

        out, cnt = self.run_records(host, records, str(f))
        return WorkerResult(out, cnt, errors)
