from __future__ import annotations
import json
from pathlib import Path

from .base import BaseWorker, WorkerResult
from .module_config import get_global_config
from .subprocess_utils import run_tool
from .logging import EventLogger
from .ticket_schema import WorkerTicket
from .path_resolver import compute_worker_output_paths

class YaraWorker(BaseWorker):
    tool = "yara"
    module = "scan"

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("yara_worker")
        self.cfg = get_global_config()

    def run(self, ticket_dict: dict) -> WorkerResult:
        ticket = WorkerTicket.from_dict(ticket_dict)
        host = ticket.metadata.hostname or "unknown_host"
        target = Path(ticket.metadata.dest_path)
        if not target.exists():
            return WorkerResult(path=None, count=0, errors=[f"Input not found: {target}"])

        ruleset = self.cfg.get_tool_config("yara").get("ruleset")
        if not ruleset:
            return WorkerResult(path=None, count=0, errors=["yara.ruleset not configured in config.yaml"])
        timeout = int(self.cfg.get_tool_config("yara").get("timeout_sec", 300))

        outdir, outfile = compute_worker_output_paths(ticket, self.tool, self.module, self.env)
        envl = ticket.get_artifact_envelope(self.tool, self.module)

        try:
            res = run_tool("yara", ["-r", str(ruleset), str(target)], timeout=timeout, check=False)
            count = 0
            with open(outfile, "w", encoding="utf-8") as f:
                for line in res.stdout.splitlines():
                    if not line.strip():
                        continue
                    rec = {"match": line}
                    f.write(json.dumps({**envl, **rec}, ensure_ascii=False) + "\n")
                    count += 1
            self.logger.log_worker_complete(self.tool, host=host, module=self.module, record_count=count, output_path=outfile)
            return WorkerResult(path=outdir, count=count)
        except Exception as e:
            return WorkerResult(path=None, count=0, errors=[f"yara failed: {e}"])
