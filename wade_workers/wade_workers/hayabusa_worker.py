from __future__ import annotations
import json
from pathlib import Path

from .base import BaseWorker, WorkerResult
from .module_config import get_global_config
from .subprocess_utils import run_tool
from .logging import EventLogger
from .ticket_schema import WorkerTicket
from .path_resolver import compute_worker_output_paths

class HayabusaWorker(BaseWorker):
    tool = "hayabusa"
    module = "detections"
    help_text = "Run Hayabusa against Windows event logs (JSONL detections)."

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("hayabusa_worker")
        self.cfg = get_global_config()

    def run(self, ticket_dict: dict) -> WorkerResult:
        ticket = WorkerTicket.from_dict(ticket_dict)
        host = ticket.metadata.hostname or "unknown_host"
        target = Path(ticket.metadata.dest_path)
        if not target.exists():
            return WorkerResult(path=None, count=0, errors=[f"Input not found: {target}"])

        self.logger.log_worker_start(self.tool, host=host, image_path=str(target))
        outdir, outfile = compute_worker_output_paths(ticket, self.tool, self.module, self.env)

        # Optional: custom rules dir and min level via YAML config (hayabusa.*)
        rules_dir = self.cfg.get_tool_config("hayabusa").get("rules_dir")
        min_level = self.cfg.get_tool_config("hayabusa").get("min_level", "low")

        args = ["detect", "--input", str(target), "--format", "jsonl", "--min-level", str(min_level)]
        if rules_dir:
            args += ["--rules", str(rules_dir)]

        total = 0
        try:
            # Run hayabusa and capture stdout to tmp file
            tmp_out = outdir / f"hayabusa_tmp_{target.stem}.jsonl"
            res = run_tool("hayabusa", args + ["--output", str(tmp_out)], timeout=1200, check=False)
            if res.rc != 0:
                # Some versions write to stdout only; fallback to reading stdout
                if res.stdout.strip():
                    with open(tmp_out, "w", encoding="utf-8") as f:
                        f.write(res.stdout)

            # Wrap JSONL with envelope
            envelope = ticket.get_artifact_envelope(self.tool, self.module)
            with open(tmp_out, "r", encoding="utf-8") as src, open(outfile, "w", encoding="utf-8") as dst:
                for line in src:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        rec = {"raw": line}
                    obj = {**envelope, **rec}
                    dst.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    total += 1
            tmp_out.unlink(missing_ok=True)
            self.logger.log_worker_complete(self.tool, host=host, module=self.module, record_count=total, output_path=outfile)
        except Exception as e:
            return WorkerResult(path=None, count=0, errors=[f"hayabusa failed: {e}"])

        return WorkerResult(path=outdir, count=total)
