"""
WADE Plaso/log2timeline Worker

Example of adding a new tool with configurable output modules.

Configuration:
  YAML:
    plaso:
      output_modules:
        - dynamic
        - l2tcsv
      filters:
        - "date > '2024-01-01'"
  
  Environment:
    WADE_PLASO_OUTPUT_MODULES="dynamic,l2tcsv,json_line"
"""
from pathlib import Path
from typing import List, Tuple

from .base import BaseWorker, WorkerResult
from .subprocess_utils import run_tool
from .logging import EventLogger
from .module_config import get_global_config


DEFAULT_OUTPUT_MODULES = ["dynamic"]


class PlasoWorker(BaseWorker):
    """Worker for Plaso/log2timeline analysis."""
    
    tool = "plaso"
    module = "log2timeline"
    help_text = "Extract timeline from disk images using Plaso/log2timeline."

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("plaso_worker")
        self.module_config = get_global_config()

    def _get_output_modules(self) -> List[str]:
        """Get list of plaso output modules to generate."""
        return self.module_config.get_modules(
            tool="plaso",
            key="output_modules",
            default=DEFAULT_OUTPUT_MODULES,
        )

    def run(self, ticket: dict) -> WorkerResult:
        """Run plaso extraction and output generation."""
        errors: List[str] = []
        
        # Extract path
        img_path = Path(ticket.get("dest_path") or ticket.get("path"))
        host = ticket.get("host", "unknown")
        
        # Run log2timeline to create plaso storage
        storage_file = img_path.parent / f"{img_path.stem}.plaso"
        
        self.logger.log_worker_start("plaso", host=host, image_path=str(img_path))
        
        try:
            result = run_tool(
                "log2timeline.py",
                ["-z", "UTC", str(storage_file), str(img_path)],
                timeout=1800,  # 30 minutes
                check=True,
            )
        except Exception as e:
            errors.append(f"log2timeline failed: {e}")
            return WorkerResult(path=None, count=0, errors=errors)
        
        # Generate output formats
        output_modules = self._get_output_modules()
        output_dir, _ = self._get_output_paths(host)
        
        for module in output_modules:
            try:
                output_file = output_dir / f"timeline.{module}.txt"
                run_tool(
                    "psort.py",
                    [
                        "-o", module,
                        "-w", str(output_file),
                        str(storage_file),
                    ],
                    timeout=600,
                    check=True,
                )
            except Exception as e:
                errors.append(f"psort {module} failed: {e}")
        
        self.logger.log_worker_complete("plaso", host=host, output_path=output_dir)
        
        return WorkerResult(path=output_dir, count=len(output_modules), errors=errors)
    
    def _get_output_paths(self, host: str) -> Tuple[Path, Path]:
        from .utils import wade_paths
        return wade_paths(self.env, host, self.tool, self.module)
