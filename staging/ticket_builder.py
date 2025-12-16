"""
Ticket builder for staging daemon.

Creates v2.0 tickets with full metadata for workers.
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from wade_workers.ticket_schema import WorkerTicket, TicketMetadata
from wade_workers.hashing import quick_hash


def build_staging_ticket(
    dest_path: Path,
    classification: str,
    hostname: Optional[str] = None,
    os_family: Optional[str] = None,
    source_file: Optional[str] = None,
    case_id: Optional[str] = None,
    case_name: Optional[str] = None,
    analyst: Optional[str] = None,
    priority: int = 5,
    tags: Optional[list] = None,
    **custom_fields,
) -> WorkerTicket:
    """Build worker ticket from staging daemon.
    
    Args:
        dest_path: Path where file was staged
        classification: File classification (e01, memory, disk, etc.)
        hostname: Target system hostname (if known)
        os_family: OS family (windows, linux, macos)
        source_file: Original filename
        case_id: Case identifier
        case_name: Case name
        analyst: Analyst username
        priority: Priority 1-10 (default: 5)
        tags: List of tags
        **custom_fields: Additional metadata
    
    Returns:
        WorkerTicket ready to queue
    """
    # Compute file hash
    file_hash = None
    file_size = None
    try:
        file_size = dest_path.stat().st_size
        file_hash = quick_hash(dest_path, sample_mb=4)
    except Exception:
        pass
    
    # Build metadata
    metadata = TicketMetadata(
        hostname=hostname or dest_path.parent.name or "unknown_host",
        classification=classification,
        os_family=os_family,
        source_file=source_file or dest_path.name,
        dest_path=str(dest_path),
        file_size_bytes=file_size,
        file_hash_sha256=file_hash,
        case_id=case_id,
        case_name=case_name,
        analyst=analyst,
        staged_utc=datetime.now(timezone.utc).isoformat(),
        priority=priority,
        tags=tags or [],
        custom=custom_fields,
    )
    
    return WorkerTicket(metadata=metadata)


def queue_ticket(
    ticket: WorkerTicket,
    queue_root: Path,
    profile: str = "default",
) -> Path:
    """Queue a ticket for processing.
    
    Args:
        ticket: WorkerTicket to queue
        queue_root: Queue root directory
        profile: Worker profile (e.g., "default", "memory", "malware")
    
    Returns:
        Path to queued ticket file
    """
    # Queue structure: {classification}/{profile}/{ticket_id}.json
    classification = ticket.metadata.classification
    ticket_id = ticket.metadata.ticket_id
    
    queue_dir = queue_root / classification / profile
    queue_dir.mkdir(parents=True, exist_ok=True)
    
    ticket_path = queue_dir / f"{ticket_id}.json"
    ticket.save(ticket_path)
    
    return ticket_path
