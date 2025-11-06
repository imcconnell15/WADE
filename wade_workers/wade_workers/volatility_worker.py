#!/usr/bin/env python3
import os, json, shutil, subprocess
from pathlib import Path
from typing import List, Dict, Tuple

from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

def _vol_cmd(env: Dict[str,str]) -> str:
    # Prefer explicit path; else vol.py; else python3 -m volatility3
    for c in (env.get("VOL_CMD"), "vol.py"):
        if c and shutil.which(c):
            return c
    return "python3 -m volatility3"

def _modules(env: Dict[str,str], cfg: dict) -> List[str]:
    # YAML: volatility.modules: [windows.pslist, windows.netscan]
    if "volatility" in cfg and isinstance(cfg["volatility"], dict) and cfg["volatility"].get("modules"):
        m = cfg["volatility"]["modules"]
        if isinstance(m, list) and m:
            return [str(x) for x in m]
    # ENV fallback
    mods = env.get("VOL_MODULES", "windows.pslist,windows.psscan")
    return [m.strip() for m in mods.split(",") if m.strip()]

class VolatilityWorker(BaseWorker):
    tool = "volatility"
    module = "multi"
    help_text = "Run Volatility3 modules against a memory image. Outputs JSONL per module."

    def _host_and_img(self, ticket) -> Tuple[str, Path]:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        p = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not p.exists():
            raise FileNotFoundError(f"memory image not found: {p}")
        return host, p

    def _append_log(self, host: str, text: str):
        _, log_dir = wade_paths(self.env, host, self.tool, self.module)
        with open(log_dir / f"{self.tool}_{self.module}.log", "a", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n")

    def run(self, ticket: dict) -> WorkerResult:
        host, img = self._host_and_img(ticket)
        cmd = _vol_cmd(self.env)
        mods = _modules(self.env, self.config)
        out_count = 0
        errors: List[str] = []
        last_out = None

        for mod in mods:
            args = [cmd, "-f", str(img), mod, "-r", "json"]
            self._append_log(host, f"{now_iso()} running: {' '.join(args)}")
            try:
                cp = subprocess.run(args, capture_output=True, text=True, check=False)
            except Exception as e:
                errors.append(f"{mod}: spawn error: {e!r}")
                continue

            if cp.returncode != 0:
                errors.append(f"{mod}: rc={cp.returncode} stderr={cp.stderr.strip()[:4000]}")
                # still record a small error artifact for Splunk visibility
                rec = {"ts": now_iso(), "module": mod, "rc": cp.returncode, "stderr": cp.stderr}
                last_out, _ = self.run_records(host, [rec], str(img))
                continue

            # try to parse Vol3 JSON; if unknown, store raw
            records = []
            try:
                data = json.loads(cp.stdout)
                if isinstance(data, dict) and "columns" in data and "rows" in data:
                    cols = data.get("columns") or []
                    for row in data.get("rows") or []:
                        try:
                            records.append({"module": mod, **{cols[i]: row[i] for i in range(min(len(cols), len(row)))}})
                        except Exception:
                            records.append({"module": mod, "row": row})
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            item = {"module": mod, **item}
                        else:
                            item = {"module": mod, "row": item}
                        records.append(item)
                else:
                    records.append({"module": mod, "raw": cp.stdout})
            except Exception:
                records.append({"module": mod, "raw": cp.stdout})

            last_out, cnt = self.run_records(host, records, str(img))
            out_count += cnt
            self._append_log(host, f"{now_iso()} {mod} -> {cnt} records")

        return WorkerResult(last_out, out_count, errors)
