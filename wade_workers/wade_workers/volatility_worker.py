"""
WADE Volatility3 Worker (Updated with error handling)

Demonstrates proper exception handling, retry logic, and exit codes.
"""
import json
import subprocess
from pathlib import Path
from typing import List, Tuple

from .base import BaseWorker, WorkerResult
from .subprocess_utils import run_tool, get_default_registry
from .logging import EventLogger, finalize_worker_records_with_ticket
from .module_config import get_global_config
from .ticket_schema import WorkerTicket

# New imports for error handling
from .exceptions import (
    ToolNotFoundError,
    ToolExecutionError,
    ToolTimeoutError,
    ParseError,
    TicketValidationError,
    FileAccessError,
)
from .retry import RetryConfig
from .exit_codes import ExitCode


DEFAULT_MODULES = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
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
        
        # Verify tool availability at init (fail fast)
        try:
            self.vol_path = get_default_registry().require_tool("volatility3")
        except ToolNotFoundError:
            # Try fallback
            try:
                self.vol_path = get_default_registry().require_tool("vol.py")
            except ToolNotFoundError as e:
                self.logger.log_worker_error(
                    "volatility",
                    "Tool not found - install volatility3 or set WADE_VOLATILITY3_PATH",
                )
                raise  # Re-raise for proper handling

    def _validate_ticket(self, ticket_dict: dict) -> WorkerTicket:
        """Validate and parse ticket.
        
        Args:
            ticket_dict: Raw ticket dictionary
        
        Returns:
            Validated WorkerTicket
        
        Raises:
            TicketValidationError: If ticket is invalid
        """
        try:
            ticket = WorkerTicket.from_dict(ticket_dict)
        except Exception as e:
            raise TicketValidationError(
                "Failed to parse ticket",
                details={"error": str(e)},
                suggestion="Check ticket schema version and format"
            )  from e
        
        # Validate required fields
        if not ticket.metadata.dest_path:
            raise TicketValidationError(
                "Missing dest_path in ticket",
                suggestion="Ensure staging daemon populates dest_path"
            )
        
        # Validate file exists
        img_path = Path(ticket.metadata.dest_path)
        if not img_path.exists():
            raise FileAccessError(
                f"Memory image not found: {img_path}",
                details={"path": str(img_path)},
                suggestion="Check if file was moved or deleted"
            )
        
        if not img_path.is_file():
            raise FileAccessError(
                f"Path is not a file: {img_path}",
                details={"path": str(img_path)}
            )
        
        return ticket

    def _get_modules(self) -> List[str]:
        """Get list of Volatility modules to run."""
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
        retry_decorator,
    ) -> Tuple[List[dict], str]:
        """Run a single Volatility module with retry logic.
        
        Args:
            module_name: Module to run
            image_path: Path to memory image
            host: Hostname for logging
            retry_decorator: Retry decorator for this tool
        
        Returns:
            Tuple of (parsed_records, error_message)
        
        Raises:
            ToolExecutionError: If tool fails after retries
            ToolTimeoutError: If tool times out
            ParseError: If output parsing fails
        """
        self.logger.log_event(
            "worker.volatility.module_start",
            module=module_name,
            host=host,
            image_path=str(image_path),
        )
        
        # Apply retry decorator to execution
        @retry_decorator
        def execute_module():
            args = ["-f", str(image_path), module_name, "-r", "json"]
            
            result = run_tool(
                "volatility3",
                args,
                timeout=300,  # 5 minutes per module
                check=False,
            )
            
            # Check for timeout
            if result.timed_out:
                raise ToolTimeoutError(
                    f"Volatility module {module_name} timed out",
                    tool="volatility3",
                    timeout_sec=300,
                )
            
            # Check for execution failure
            if not result.success:
                stderr = result.truncated_stderr()
                
                # Classify error
                if "not found" in stderr.lower() or "no module named" in stderr.lower():
                    raise ToolExecutionError(
                        f"Module {module_name} not found or unsupported",
                        tool="volatility3",
                        returncode=result.rc,
                        stderr=stderr,
                        suggestion="Check module name or volatility version"
                    )
                else:
                    raise ToolExecutionError(
                        f"Volatility module {module_name} failed",
                        tool="volatility3",
                        returncode=result.rc,
                        stderr=stderr,
                    )
            
            return result
        
        # Execute with retry
        try:
            result = execute_module()
        except (ToolExecutionError, ToolTimeoutError) as e:
            # Log error
            self.logger.log_worker_error(
                "volatility",
                str(e),
                module=module_name,
                host=host,
            )
            # Return error record for visibility
            return [{
                "module": module_name,
                "error": e.message,
                "error_type": e.__class__.__name__,
            }], str(e)
        
        # Parse output
        try:
            records = self._parse_volatility_json(module_name, result.stdout)
        except Exception as e:
            raise ParseError(
                f"Failed to parse {module_name} output",
                details={"module": module_name, "error": str(e)},
                suggestion="Check volatility3 output format"
            )
        
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
        """Parse Volatility3 JSON output format."""
        if not stdout.strip():
            return []
        
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            # Not valid JSON - wrap as raw
            return [{
                "module": module_name,
                "raw_output": stdout,
                "parse_error": str(e)
            }]
        
        # Handle columns/rows format
        if isinstance(data, dict) and "columns" in data and "rows" in data:
            columns = data.get("columns") or []
            rows = data.get("rows") or []
            
            records = []
            for row in rows:
                try:
                    record = {
                        "module": module_name,
                        **{columns[i]: row[i] for i in range(min(len(columns), len(row)))}
                    }
                    records.append(record)
                except Exception:
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

    def run(self, ticket_dict: dict) -> WorkerResult:
        """Execute Volatility worker with proper error handling.
        
        Args:
            ticket_dict: Worker ticket
        
        Returns:
            WorkerResult with execution summary
        
        Raises:
            TicketValidationError: If ticket is invalid
            ToolNotFoundError: If volatility not found
            FileAccessError: If memory image inaccessible
        """
        # Validate ticket (raises on error)
        ticket = self._validate_ticket(ticket_dict)
        
        host = ticket.metadata.hostname
        img_path = Path(ticket.metadata.dest_path)
        
        self.logger.log_worker_start("volatility", host=host, image_path=str(img_path))
        
        # Get modules
        modules = self._get_modules()
        if not modules:
            raise TicketValidationError(
                "No modules configured",
                suggestion="Set WADE_VOLATILITY_MODULES or check config.yaml"
            )
        
        # Get retry decorator for this tool
        retry_decorator = RetryConfig.get_retry_decorator("volatility")
        
        # Run modules
        total_records = 0
        errors = []
        output_dir, _ = self._get_output_paths(host)
        
        for module_name in modules:
            try:
                records, error = self._run_module(
                    module_name,
                    img_path,
                    host,
                    retry_decorator,
                )
                
                if error:
                    errors.append(f"{module_name}: {error}")
                
                if records:
                    output_file = output_dir / f"{module_name.replace('.', '_')}.jsonl"
                    count = finalize_worker_records_with_ticket(
                        records,
                        output_path=output_file,
                        ticket=ticket,
                        tool="volatility",
                        module=module_name,
                    )
                    total_records += count
            
            except ParseError as e:
                # Parse errors are non-fatal; log and continue
                errors.append(f"{module_name}: {e.message}")
                self.logger.log_worker_error(
                    "volatility",
                    e.message,
                    module=module_name,
                    host=host,
                )
        
        self.logger.log_worker_complete(
            "volatility",
            host=host,
            record_count=total_records,
            output_path=output_dir,
        )
        
        return WorkerResult(path=output_dir, count=total_records, errors=errors)
    
    def _get_output_paths(self, host: str) -> Tuple[Path, Path]:
        """Get output and log directories."""
        from .utils import wade_paths
        return wade_paths(self.env, host, self.tool, self.module)
