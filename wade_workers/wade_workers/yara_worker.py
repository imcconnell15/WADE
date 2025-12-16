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
        """
        Initialize the YaraWorker, configure its per-worker logger, and load global configuration.
        
        Parameters:
            env (optional): Execution environment identifier or context used by the worker.
            config (optional): Worker-specific configuration overrides.
        """
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("yara_worker")
        self.cfg = get_global_config()

    def run(self, ticket_dict: dict) -> WorkerResult:
        """
        Run YARA on the ticket's destination path and write one JSON-line artifact per match.
        
        Processes the provided ticket dictionary to locate the target file or directory, reads YARA configuration (ruleset and optional timeout), executes the YARA tool against the target, and writes each non-empty match line as a JSON object (merged with the ticket's artifact envelope) to the worker output file. On success returns the output directory and the number of match records written; on failure returns a WorkerResult with no path, a count of 0, and an error message.
        
        Parameters:
            ticket_dict (dict): Serialized WorkerTicket dictionary containing metadata (including `dest_path` and `hostname`) and artifact envelope data.
        
        Returns:
            WorkerResult: On success, `path` is the worker output directory and `count` is the number of match records written. On failure, `path` is None, `count` is 0, and `errors` contains one descriptive error message.
        """
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