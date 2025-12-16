# staging/ticket_builder.py (additions/changes)
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
    # ... existing hash/size logic ...
    """
    Builds a WorkerTicket for staging a file, populating metadata and worker_config including requested tools.
    
    Parameters:
        dest_path (Path): Destination filesystem path for the staged file.
        classification (str): Classification label used to route tools and tag the ticket.
        hostname (Optional[str]): Hostname to record; if omitted, derived from dest_path.parent.name or "unknown_host".
        os_family (Optional[str]): Operating system family used when selecting tools.
        source_file (Optional[str]): Original source filename; defaults to dest_path.name.
        case_id (Optional[str]): Case identifier associated with the ticket.
        case_name (Optional[str]): Case name associated with the ticket.
        analyst (Optional[str]): Analyst name to record on the ticket.
        priority (int): Priority level for the ticket.
        tags (Optional[List[str]]): List of tags to attach to the ticket.
        profile (str): Tooling/profile name used for tool selection and added to worker_config.
        location (Optional[str]): Location string included in metadata and worker_config.
        details (Optional[Dict]): Additional metadata details merged into the ticket's custom fields and used for tool selection.
        **custom_fields: Arbitrary additional custom fields to include in the ticket's custom metadata.
    
    Returns:
        WorkerTicket: A ticket whose metadata is populated (including file hash/size, staged UTC timestamp, and custom fields) and whose worker_config includes "profile", "location", and "requested_tools" as determined by ToolRouting.select_tools.
    """
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