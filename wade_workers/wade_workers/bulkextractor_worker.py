from __future__ import annotations
import json
from pathlib import Path

from .base import BaseWorker, WorkerResult
from .module_config import get_global_config
from .subprocess_utils import run_tool
from .logging import EventLogger
from .ticket_schema import WorkerTicket
from .path_resolver import compute_worker_output_paths

DEFAULT_SCANNERS = ["email","url","ccn","telephone","base64"]

class BulkExtractorWorker(BaseWorker):
    tool = "bulk_extractor"
    module = "scan"

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("bulk_extractor_worker")
        self.cfg = get_global_config()

    def run(self, ticket_dict: dict) -> WorkerResult:
        ticket = WorkerTicket.from_dict(ticket_dict)
        host = ticket.metadata.hostname or "unknown_host"
        target = Path(ticket.metadata.dest_path)
        if not target.exists():
            return WorkerResult(path=None, count=0, errors=[f"Input not found: {target}"])

        scanners = self.cfg.get_modules("bulk_extractor", key="scanners", default=DEFAULT_SCANNERS)
        disabled = set(self.cfg.get_modules("bulk_extractor", key="disabled_scanners", default=[]))
        scanners = [s for s in scanners if s not in disabled]

        self.logger.log_worker_start(self.tool, host=host, image_path=str(target))
        outdir, outfile = compute_worker_output_paths(ticket, self.tool, self.module, self.env)

        tmp_dir = outdir / "be_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        args = ["-o", str(tmp_dir)]
        for s in scanners:
            args += ["-S", s]
        args += [str(target)]

        try:
            run_tool("bulk_extractor", args, timeout=3600, check=True)
            # Convert be output (feature files) to JSONL envelope quickly
            count = 0
            with open(outfile, "w", encoding="utf-8") as dst:
                env = ticket.get_artifact_envelope(self.tool, self.module)
                for f in tmp_dir.glob("*.txt"):
                    for line in f.read_text(errors="ignore").splitlines():
                        if not line.strip():
                            continue
                        rec = {"source": f.name, "data": line}
                        dst.write(json.dumps({**env, **rec}, ensure_ascii=False) + "\n")
                        count += 1
            self.logger.log_worker_complete(self.tool, host=host, module=self.module, record_count=count, output_path=outfile)
            return WorkerResult(path=outdir, count=count)
        except Exception as e:
            return WorkerResult(path=None, count=0, errors=[f"bulk_extractor failed: {e}"])
