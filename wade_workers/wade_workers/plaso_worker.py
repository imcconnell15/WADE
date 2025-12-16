from __future__ import annotations
import json
from pathlib import Path
from typing import List, Tuple

from .base import BaseWorker, WorkerResult
from .module_config import get_global_config
from .subprocess_utils import run_tool
from .logging import EventLogger
from .ticket_schema import WorkerTicket
from .path_resolver import compute_worker_output_paths

DEFAULT_OUTPUT_MODULES = ["json_line"]  # use psort JSONL

class PlasoWorker(BaseWorker):
    tool = "plaso"
    module = "timeline"
    help_text = "Run log2timeline + psort; export JSONL wrapped with ticket envelope."

    def __init__(self, env=None, config=None):
        """
        Initialize the PlasoWorker by invoking the base initializer, setting up the worker logger, and loading global configuration.
        
        Parameters:
            env: Optional environment overrides for the worker.
            config: Optional configuration fragment for the worker.
        """
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("plaso_worker")
        self.cfg = get_global_config()

    def _get_psort_modules(self) -> List[str]:
        """
        Retrieve the configured psort output modules for the "plaso" tool.
        
        Returns:
            List[str]: A list of psort output module names; if none are configured, returns DEFAULT_OUTPUT_MODULES.
        """
        return self.cfg.get_modules("plaso", key="output_modules", default=DEFAULT_OUTPUT_MODULES)

    def run(self, ticket_dict: dict) -> WorkerResult:
        """
        Process an input image with log2timeline and psort modules, wrap each psort record with the ticket's artifact envelope, and write per-module JSONL outputs.
        
        Parameters:
            ticket_dict (dict): Dictionary representation of a WorkerTicket containing metadata (including `dest_path` and optional `hostname`) and artifact envelope information.
        
        Returns:
            WorkerResult: Result containing:
                - path: parent directory of the processed image, or None if processing failed before output creation.
                - count: total number of records written across all processed psort modules.
                - errors: list of error messages encountered (e.g., "Input not found: <path>", "log2timeline failed: <msg>", or "psort <module> failed: <msg>").
        """
        ticket = WorkerTicket.from_dict(ticket_dict)
        host = ticket.metadata.hostname or "unknown_host"
        img_path = Path(ticket.metadata.dest_path)
        if not img_path.exists():
            return WorkerResult(path=None, count=0, errors=[f"Input not found: {img_path}"])

        self.logger.log_worker_start(self.tool, host=host, image_path=str(img_path))

        # Create plaso storage
        storage_file = img_path.parent / f"{img_path.stem}.plaso"
        try:
            run_tool("log2timeline.py", ["-z", "UTC", str(storage_file), str(img_path)], timeout=1800, check=True)
        except Exception as e:
            return WorkerResult(path=None, count=0, errors=[f"log2timeline failed: {e}"])

        total = 0
        errors: List[str] = []
        for outmod in self._get_psort_modules():
            # Compute per-module output path
            module_name = f"psort_{outmod}"
            outdir, outfile = compute_worker_output_paths(ticket, self.tool, module_name, self.env)

            # Run psort to produce JSONL; stream-wrap with envelope
            try:
                # Produce a temp psort output file
                tmp_psort = outdir / f"psort_tmp_{img_path.stem}.jsonl"
                run_tool("psort.py", ["-o", outmod, "-w", str(tmp_psort), str(storage_file)], timeout=1200, check=True)

                # Stream wrap each line with ticket envelope
                envelope = ticket.get_artifact_envelope(self.tool, module_name)
                with open(tmp_psort, "r", encoding="utf-8") as src, open(outfile, "w", encoding="utf-8") as dst:
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
                tmp_psort.unlink(missing_ok=True)
                self.logger.log_worker_complete(self.tool, host=host, module=module_name, record_count=total, output_path=outfile)
            except Exception as e:
                errors.append(f"psort {outmod} failed: {e}")

        return WorkerResult(path=img_path.parent, count=total, errors=errors)