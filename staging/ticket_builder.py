# staging/ticket_builder.py (additions/changes)
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, List
from wade_workers.ticket_schema import WorkerTicket, TicketMetadata
from wade_workers.hashing import quick_hash
from .tool_routing import ToolRouting

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
    tags: Optional[List[str]] = None,
    profile: str = "full",
    location: Optional[str] = None,
    details: Optional[Dict] = None,
    **custom_fields,
) -> WorkerTicket:
    # Compute file hash and size for deduplication
    file_size = dest_path.stat().st_size if dest_path.exists() else None
    file_hash = quick_hash(dest_path) if dest_path.exists() else None
    details = details or {}
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
        custom={**custom_fields, **details, **({"location": location} if location else {})},
    )

    # NEW: compute requested tools based on classification, profile, and details
    router = ToolRouting()
    requested = router.select_tools(classification=classification, profile=profile, details={"os_family": os_family, **details}, location=location)

    ticket = WorkerTicket(metadata=metadata)
    ticket.worker_config = {
        **(ticket.worker_config or {}),
        "profile": profile,
        "location": location,
        "requested_tools": requested,
    }
    return ticket
