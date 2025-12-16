"""
WADE Volatility3 Worker

Runs Volatility3 memory analysis modules against memory images.
Supports configurable module lists via YAML config and environment overrides.

Configuration:
  YAML (wade_config.yaml):
    volatility:
      modules:
        - windows.pslist
        - windows.netscan
      disabled_modules:
        - windows.malfind
  
  Environment:
    WADE_VOLATILITY_MODULES="windows.pslist,windows.netscan,windows.cmdline"
    WADE_VOLATILITY_MODULES="+windows.registry.hivelist,-windows.malfind"
"""
import json
from pathlib import Path
from typing import List, Tuple

from .base import BaseWorker, WorkerResult
from .subprocess_utils import run_tool, get_default_registry, ToolNotFoundError
from .logging import EventLogger, finalize_worker_records
from .module_config import get_global_config


# Default modules if not configured
DEFAULT_MODULES = [
    "windows.info",
    "windows.pslist",
    "windows.pstree", 
    "windows.cmdline",
    "windows.netscan",
    "windows.handles",
    "windows.dlllist",
    "windows.services",
]


class VolatilityWorker(BaseWorker):
    """Worker for running Volatility3 memory analysis."""
    
    tool = "volatility"
    module = "multi"
    help_text = "Run Volatility3 modules against a memory image. Outputs JSONL per module."

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("volatility_worker")
        self.module_config = get_global_config()
        
        # Verify volatility3 is available
        try:
            get_default_registry().require_tool("volatility3")
        except ToolNotFoundError:
            # Also try vol.py as fallback
            try:
                get_default_registry().require_tool("vol.py")
            except ToolNotFoundError:
                self.logger.log_event(
                    "worker.volatility.tool_missing",
                    status="error",
                    error="Neither 'volatility3' nor 'vol.py' found in PATH or WADE_VOLATILITY3_PATH"
                )

    def _resolve_host_and_image(self, ticket: dict) -> Tuple[str, Path]:
        """Extract host and image path from ticket.
        
        Args:
            ticket: Worker ticket dict
        
        Returns:
            Tuple of (hostname, image_path)
        
        Raises:
            FileNotFoundError: If image doesn't exist
        """
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME", "unknown_host")
        
        # Try various path keys
        path_str = ticket.get("dest_path") or ticket.get("path") or ticket.get("image_path")
        if not path_str:
            raise ValueError("No image path specified in ticket (need 'dest_path', 'path', or 'image_path')")
        
        img_path = Path(path_str)
        if not img_path.exists():
            raise FileNotFoundError(f"Memory image not found: {img_path}")
        
        return host, img_path

    def _get_modules(self) -> List[str]:
        """Get list of Volatility modules to run.
        
        Priority:
          1. WADE_VOLATILITY_MODULES env var
          2. YAML config volatility.modules
          3. DEFAULT_MODULES constant
        
        Returns:
            List of module names to execute
        """
        return self.module_config.get_modules(
            tool="volatility",
            key="modules",
            default=DEFAULT_MODULES,
        )

    def _run_module(
        self,
        module_name: str,
        image_path: Path,
        host: str,
    ) -> Tuple[List[dict], str]:
        """Run a single Volatility module.
        
        Args:
            module_name: Module to run (e.g., "windows.pslist")
            image_path: Path to memory image
            host: Hostname for logging
        
        Returns:
            Tuple of (parsed_records, error_message)
            error_message is empty string on success
        """
        self.logger.log_event(
            "worker.volatility.module_start",
            module=module_name,
            host=host,
            image_path=str(image_path),
        )
        
        # Try volatility3 first, fallback to vol.py
        tool_name = "volatility3"
        try:
            get_default_registry().require_tool(tool_name)
        except ToolNotFoundError:
            tool_name = "vol.py"
        
        args = ["-f", str(image_path), module_name, "-r", "json"]
        
        try:
            result = run_tool(
                tool_name,
                args,
                timeout=300,  # 5 minutes per module
                check=False,
            )
        except Exception as e:
            error = f"Failed to spawn {tool_name}: {e}"
            self.logger.log_worker_error("volatility", error, module=module_name, host=host)
            return [], error
        
        if not result.success:
            error = f"rc={result.rc}, stderr={result.truncated_stderr()}"
            self.logger.log_worker_error(
                "volatility",
                error,
                module=module_name,
                host=host,
                returncode=result.rc,
            )
            # Return minimal error record for visibility
            return [{
                "module": module_name,
                "error": error,
                "rc": result.rc,
            }], error
        
        # Parse Volatility3 JSON output
        records = self._parse_volatility_json(module_name, result.stdout)
        
        self.logger.log_event(
            "worker.volatility.module_complete",
            status="success",
            module=module_name,
            host=host,
            record_count=len(records),
            duration_sec=result.duration_sec,
        )
        
        return records, ""

    def _parse_volatility_json(self, module_name: str, stdout: str) -> List[dict]:
        """Parse Volatility3 JSON output format.
        
        Volatility3 outputs JSON with "columns" and "rows" arrays.
        Convert to list of dicts for easier downstream processing.
        
        Args:
            module_name: Module that generated output
            stdout: Raw stdout from volatility
        
        Returns:
            List of record dicts
        """
        if not stdout.strip():
            return []
        
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # Malformed JSON - store as raw
            return [{"module": module_name, "raw_output": stdout}]
        
        # Handle columns/rows format
        if isinstance(data, dict) and "columns" in data and "rows" in data:
            columns = data.get("columns") or []
            rows = data.get("rows") or []
            
            records = []
            for row in rows:
                try:
                    # Zip columns and row values
                    record = {
                        "module": module_name,
                        **{columns[i]: row[i] for i in range(min(len(columns), len(row)))}
                    }
                    records.append(record)
                except Exception:
                    # Malformed row - include as-is
                    records.append({"module": module_name, "row": row})
            
            return records
        
        # Handle list format
        if isinstance(data, list):
            return [
                {"module": module_name, **item} if isinstance(item, dict)
                else {"module": module_name, "data": item}
                for item in data
            ]
        
        # Unknown format
        return [{"module": module_name, "data": data}]

    def run(self, ticket: dict) -> WorkerResult:
        """Execute Volatility worker.
        
        Args:
            ticket: Worker ticket with image path and host info
        
        Returns:
            WorkerResult with execution summary
        """
        errors: List[str] = []
        
        try:
            host, img_path = self._resolve_host_and_image(ticket)
        except (ValueError, FileNotFoundError) as e:
            errors.append(str(e))
            return WorkerResult(path=None, count=0, errors=errors)
        
        self.logger.log_worker_start("volatility", host=host, image_path=str(img_path))
        
        modules = self._get_modules()
        if not modules:
            errors.append("No modules configured - check YAML config or WADE_VOLATILITY_MODULES")
            return WorkerResult(path=None, count=0, errors=errors)
        
        total_records = 0
        output_dir, _ = self._get_output_paths(host)
        
        for module_name in modules:
            records, error = self._run_module(module_name, img_path, host)
            
            if error:
                errors.append(f"{module_name}: {error}")
            
            if records:
                # Write records to JSONL
                output_file = output_dir / f"{module_name.replace('.', '_')}.jsonl"
                count = finalize_worker_records(
                    records,
                    output_path=output_file,
                    tool="volatility",
                    module=module_name,
                    host=host,
                    metadata={"image_path": str(img_path)},
                )
                total_records += count
        
        self.logger.log_worker_complete(
            "volatility",
            host=host,
            record_count=total_records,
            output_path=output_dir,
        )
        
        return WorkerResult(path=output_dir, count=total_records, errors=errors)
    
    def _get_output_paths(self, host: str) -> Tuple[Path, Path]:
        """Get output and log directories for this host.
        
        Args:
            host: Hostname
        
        Returns:
            Tuple of (output_dir, log_dir)
        """
        from .utils import wade_paths
        return wade_paths(self.env, host, self.tool, self.module)
