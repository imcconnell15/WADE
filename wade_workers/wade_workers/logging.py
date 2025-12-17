"""
Unified JSONL event logging for WADE workers and processes.

Provides a consistent schema for all events across the pipeline:
- Worker execution events
- Staging/classification events
- Tool output events
- Error events

Adding a new event type:
    logger = EventLogger.get_logger("my_new_tool")
    logger.log_event(
        "tool.my_new_tool.complete",
        host="DESKTOP-ABC",
        records_found=42,
        custom_field="value",
    )
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from .ticket_schema import WorkerTicket

class EventLogger:
    """Structured JSONL logger for WADE events.
    
    All events follow a consistent schema with core fields plus extensible metadata.
    Log files are organized by date for easier rotation and analysis.
    
    Example:
        logger = EventLogger(Path("/data/logs"), source="volatility_worker")
        logger.log_event(
            "worker.volatility.start",
            host="DESKTOP-ABC",
            image_path="/data/mem.raw",
            profile="Win10x64",
        )
    """
    
    # Core schema fields present in every event
    CORE_FIELDS = {
        "timestamp_utc",
        "event_type",
        "source",
        "status",
    }
    
    def __init__(
        self,
        log_dir: Path,
        source: str,
        rotate_daily: bool = True,
    ):
        """Initialize event logger.
        
        Args:
            log_dir: Directory for log files
            source: Source identifier (e.g., "volatility_worker", "stage_daemon")
            rotate_daily: Create new file each day (YYYY-MM-DD.jsonl)
        """
        self.log_dir = Path(log_dir)
        self.source = source
        self.rotate_daily = rotate_daily
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Python logger for errors
        self._logger = logging.getLogger(f"wade.{source}")
    
    def _get_log_path(self) -> Path:
        """Get current log file path."""
        if self.rotate_daily:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return self.log_dir / f"{self.source}_{date_str}.jsonl"
        else:
            return self.log_dir / f"{self.source}.jsonl"
    
    def log_event(
        self,
        event_type: str,
        status: str = "info",
        **fields: Any,
    ) -> Path:
        """Log an event with arbitrary fields.
        
        Args:
            event_type: Event type (e.g., "worker.volatility.complete")
            status: Event status (info, success, warning, error)
            **fields: Additional event-specific fields
        
        Returns:
            Path to log file where event was written
        
        Example:
            logger.log_event(
                "worker.volatility.complete",
                status="success",
                host="DESKTOP-ABC",
                module="windows.pslist",
                records=42,
                duration_sec=3.14,
            )
        """
        event = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "source": self.source,
            "status": status,
            **fields,
        }
        
        log_path = self._get_log_path()
        
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                json.dump(event, f, ensure_ascii=False, default=str)
                f.write("\n")
        except Exception as e:
            self._logger.error(f"Failed to write event to {log_path}: {e}")
            # Don't raise - logging errors shouldn't crash the application
        
        return log_path
    
    def log_worker_start(
        self,
        tool: str,
        module: Optional[str] = None,
        host: Optional[str] = None,
        **extra_fields: Any,
    ) -> Path:
        """Log worker start event with standard fields.
        
        Args:
            tool: Tool name (e.g., "volatility3")
            module: Module/plugin name (e.g., "windows.pslist")
            host: Host/system name
            **extra_fields: Additional fields
        """
        return self.log_event(
            f"worker.{tool}.start",
            status="info",
            tool=tool,
            module=module,
            host=host,
            **extra_fields,
        )
    
    def log_worker_complete(
        self,
        tool: str,
        module: Optional[str] = None,
        host: Optional[str] = None,
        record_count: Optional[int] = None,
        duration_sec: Optional[float] = None,
        output_path: Optional[Path] = None,
        **extra_fields: Any,
    ) -> Path:
        """Log worker completion with results.
        
        Args:
            tool: Tool name
            module: Module/plugin name
            host: Host/system name
            record_count: Number of records/artifacts found
            duration_sec: Execution time
            output_path: Path to output file
            **extra_fields: Additional fields
        """
        return self.log_event(
            f"worker.{tool}.complete",
            status="success",
            tool=tool,
            module=module,
            host=host,
            record_count=record_count,
            duration_sec=duration_sec,
            output_path=str(output_path) if output_path else None,
            **extra_fields,
        )
    
    def log_worker_error(
        self,
        tool: str,
        error_msg: str,
        module: Optional[str] = None,
        host: Optional[str] = None,
        **extra_fields: Any,
    ) -> Path:
        """Log worker error.
        
        Args:
            tool: Tool name
            error_msg: Error description
            module: Module/plugin name
            host: Host/system name
            **extra_fields: Additional fields
        """
        return self.log_event(
            f"worker.{tool}.error",
            status="error",
            tool=tool,
            module=module,
            host=host,
            error_msg=error_msg,
            **extra_fields,
        )
    
    def log_classification(
        self,
        file_path: Path,
        classification: str,
        confidence: Optional[float] = None,
        **extra_fields: Any,
    ) -> Path:
        """Log file classification event.
        
        Args:
            file_path: File that was classified
            classification: Classification result (e.g., "e01", "memory_dump")
            confidence: Classification confidence (0.0-1.0)
            **extra_fields: Additional fields
        """
        return self.log_event(
            "staging.classification",
            status="info",
            file_path=str(file_path),
            classification=classification,
            confidence=confidence,
            **extra_fields,
        )
    
    @classmethod
    def get_logger(
        cls,
        source: str,
        log_dir: Optional[Path] = None,
    ) -> EventLogger:
        """Get or create logger for a source.
        
        Args:
            source: Source identifier
            log_dir: Log directory (default: /data/logs or $WADE_LOG_DIR)
        
        Returns:
            EventLogger instance
        """
        if log_dir is None:
            import os
            log_dir = Path(os.environ.get("WADE_LOG_DIR", "/data/logs"))
        
        return cls(log_dir, source)


def finalize_worker_records_with_ticket(
    records: List[Dict[str, Any]],
    output_path: Path,
    ticket: WorkerTicket,
    tool: str,
    module: str,
) -> int:
    """Write worker output with ticket metadata envelope.
    
    This replaces finalize_worker_records() for v2.0 tickets.
    Each record gets the full ticket metadata for Splunk searchability.
    
    Args:
        records: List of record dicts
        output_path: Output JSONL file
        ticket: WorkerTicket with metadata
        tool: Tool name
        module: Module name
    
    Returns:
        Number of records written
    
    Example:
        records = parse_tool_output(result.stdout)
        count = finalize_worker_records_with_ticket(
            records,
            output_path=Path("/data/output/pslist.jsonl"),
            ticket=ticket,
            tool="volatility",
            module="windows.pslist",
        )
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get envelope from ticket
    envelope = ticket.get_artifact_envelope(tool, module)
    
    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            # Merge envelope with record (envelope fields don't override record fields)
            artifact = {**envelope, **record}
            json.dump(artifact, f, ensure_ascii=False, default=str)
            f.write("\n")
    
    return len(records)
