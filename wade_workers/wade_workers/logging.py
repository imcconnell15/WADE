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
        """
        Create an EventLogger configured to write JSONL events for a given source.
        
        Parameters:
            log_dir (Path): Directory where log files will be stored; the directory is created if it does not exist.
            source (str): Identifier for the event source (used in filenames and the event `source` field).
            rotate_daily (bool): If True, use daily-rotated files named "{source}_{YYYY-MM-DD}.jsonl"; if False, use a single "{source}.jsonl" file.
        """
        self.log_dir = Path(log_dir)
        self.source = source
        self.rotate_daily = rotate_daily
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Python logger for errors
        self._logger = logging.getLogger(f"wade.{source}")
    
    def _get_log_path(self) -> Path:
        """
        Compute the file path used for writing the current log.
        
        Returns:
            Path: Path to the JSONL log file. If `rotate_daily` is True the filename is "{source}_{YYYY-MM-DD}.jsonl" using the current UTC date; otherwise the filename is "{source}.jsonl".
        """
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
        """
        Emit a "worker.<tool>.start" event containing standard identifying fields.
        
        Parameters:
            tool (str): Tool name (e.g., "volatility3").
            module (Optional[str]): Module or plugin name (e.g., "windows.pslist").
            host (Optional[str]): Host or system name where the worker runs.
            **extra_fields: Additional event fields to include.
        
        Returns:
            Path: Path to the log file the event was written to.
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
        """
        Record a successful worker completion event with optional metadata.
        
        Parameters:
            tool: Name of the tool or worker that completed.
            module: Optional module or plugin name associated with the run.
            host: Optional host or system identifier where the work ran.
            record_count: Optional number of records or artifacts produced.
            duration_sec: Optional execution duration in seconds.
            output_path: Optional path to the worker's output; included in the event as a string if provided.
            **extra_fields: Additional event fields to include.
        
        Returns:
            Path to the log file that the event was written to.
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
        """
        Record an error event for a worker tool.
        
        Parameters:
            tool (str): The tool name associated with the worker.
            error_msg (str): Human-readable error description.
            module (Optional[str]): Optional module or plugin name that ran the tool.
            host (Optional[str]): Optional host or system identifier where the worker ran.
            **extra_fields: Any additional event fields to include in the logged record.
        
        Returns:
            Path: Path to the JSONL log file that the event was appended to.
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
        """
        Log a staging classification event for a file.
        
        Parameters:
            file_path (Path): Path of the file that was classified.
            classification (str): Classification label (e.g., "e01", "memory_dump").
            confidence (Optional[float]): Confidence score from 0.0 to 1.0.
            **extra_fields: Any additional event fields to include.
        
        Returns:
            log_path (Path): Path to the JSONL log file the event was written to.
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
        """
        Obtain an EventLogger configured for the given source and log directory.
        
        Parameters:
            source (str): Identifier for the event source (e.g., worker name).
            log_dir (Optional[Path]): Directory to store logs. If omitted, resolved from the WADE_LOG_DIR environment variable or defaults to /data/logs.
        
        Returns:
            EventLogger: An EventLogger instance configured with the resolved log directory and provided source.
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
    """
    Write records to a JSONL file, merging each record with an artifact envelope obtained from the provided ticket.
    
    Parameters:
        records (List[Dict[str, Any]]): Records to write; each becomes one JSON object line after merging with the envelope.
        output_path (Path): Destination JSONL file path; parent directories will be created if missing.
        ticket (WorkerTicket): Ticket used to obtain the artifact envelope via ticket.get_artifact_envelope(tool, module).
        tool (str): Tool name used to request the envelope.
        module (str): Module name used to request the envelope.
    
    Returns:
        int: Number of records written.
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