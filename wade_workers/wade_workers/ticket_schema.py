"""
WADE Ticket Schema and Validation

Defines the canonical ticket format with metadata for Splunk ingestion.
All tickets follow this schema to ensure consistent artifact tagging.

Schema Design Principles:
  1. Core metadata always present (host, classification, timestamps)
  2. Backward compatible (old field names mapped to new)
  3. Extensible (arbitrary metadata preserved)
  4. Splunk-optimized (fields designed for search/filtering)
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TicketMetadata:
    """Core metadata for Splunk ingestion and traceability.
    
    These fields are injected into every JSON artifact line for searchability.
    """
    # === Identity ===
    ticket_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = "unknown_host"  # Target system hostname
    
    # === Classification ===
    classification: str = "unknown"  # e01, memory, disk, network, malware
    os_family: Optional[str] = None  # windows, linux, macos
    os_version: Optional[str] = None  # Win10x64, Ubuntu22.04
    
    # === Source File ===
    source_file: str = ""  # Original filename (e.g., evidence.E01)
    dest_path: str = ""    # Full path in DataSources
    file_size_bytes: Optional[int] = None
    file_hash_sha256: Optional[str] = None
    
    # === Case Information ===
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    analyst: Optional[str] = None
    
    # === Timestamps ===
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    staged_utc: Optional[str] = None  # When file was staged
    acquired_utc: Optional[str] = None  # When evidence was acquired
    
    # === Processing ===
    priority: int = 5  # 1-10, lower = higher priority
    retry_count: int = 0
    tags: List[str] = field(default_factory=list)  # e.g., ["encrypted", "cloud"]
    
    # === Custom Metadata ===
    # Store arbitrary key-value pairs for case-specific fields
    custom: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkerTicket:
    """Complete worker ticket with metadata and configuration.
    
    This is the canonical format passed to workers and stored in the queue.
    """
    # Core metadata (always present)
    metadata: TicketMetadata
    
    # Worker configuration (optional overrides)
    worker_config: Dict[str, Any] = field(default_factory=dict)
    
    # Schema version for forward compatibility
    schema_version: str = "2.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Produce a serializable dictionary representation of the worker ticket.
        
        Returns:
            ticket_dict (Dict[str, Any]): Dictionary with keys:
                - "schema_version": schema version string.
                - "metadata": dict representation of the ticket's metadata.
                - "worker_config": worker configuration dictionary.
        """
        return {
            "schema_version": self.schema_version,
            "metadata": asdict(self.metadata),
            "worker_config": self.worker_config,
        }
    
    def to_json(self) -> str:
        """
        Serialize the worker ticket to a JSON-formatted string.
        
        Returns:
            json_str (str): JSON representation of the ticket containing `schema_version`, `metadata`, and `worker_config`, formatted with indentation.
        """
        return json.dumps(self.to_dict(), indent=2)
    
    def save(self, path: Path) -> None:
        """
        Write the ticket's JSON representation to the given filesystem path, creating any missing parent directories.
        
        Parameters:
            path (Path): Filesystem path to the output JSON file; parent directories will be created if they do not exist.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkerTicket:
        """
        Construct a WorkerTicket from a serialized mapping, handling legacy v1 tickets by migrating them to the v2 schema.
        
        Parameters:
            data (Dict[str, Any]): Dictionary representing a serialized ticket (v2 schema produced by to_dict/to_json, or a legacy v1 ticket). If "schema_version" is absent it is treated as "1.0".
        
        Returns:
            WorkerTicket: A WorkerTicket instance populated from the provided dictionary.
        """
        schema_version = data.get("schema_version", "1.0")
        
        # Handle old format (schema v1.0)
        if schema_version == "1.0" or "metadata" not in data:
            return cls._from_v1(data)
        
        # Schema v2.0+
        metadata_dict = data.get("metadata", {})
        metadata = TicketMetadata(**metadata_dict)
        
        return cls(
            metadata=metadata,
            worker_config=data.get("worker_config", {}),
            schema_version=schema_version,
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> WorkerTicket:
        """
        Construct a WorkerTicket from a JSON-formatted string.
        
        Parameters:
            json_str (str): JSON representation of a ticket payload.
        
        Returns:
            WorkerTicket: Parsed WorkerTicket instance built from the provided JSON.
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    @classmethod
    def load(cls, path: Path) -> WorkerTicket:
        """
        Constructs a WorkerTicket from a JSON file at the given filesystem path.
        
        Parameters:
            path (Path): Path to the JSON file containing the ticket.
        
        Returns:
            WorkerTicket: Ticket reconstructed from the file's JSON content.
        """
        return cls.from_json(path.read_text())
    
    @classmethod
    def _from_v1(cls, data: Dict[str, Any]) -> WorkerTicket:
        """
        Convert a legacy v1 ticket dictionary into a v2 WorkerTicket instance.
        
        Builds a TicketMetadata from mapped v1 fields, preserves any unmapped keys in metadata.custom,
        and moves v1 `plugins` into the returned ticket's worker_config.
        
        Parameters:
            data (Dict[str, Any]): A dictionary containing a v1 ticket representation.
        
        Returns:
            WorkerTicket: A WorkerTicket populated from the provided v1 data with schema_version "2.0".
        """
        # Extract core fields with backward compat
        hostname = data.get("host") or data.get("hostname", "unknown_host")
        dest_path = data.get("dest_path") or data.get("path") or data.get("image_path", "")
        classification = data.get("classification", "unknown")
        os_family = data.get("os_family") or data.get("os")
        
        # Extract source filename
        source_file = data.get("source_file") or Path(dest_path).name if dest_path else ""
        
        # Build metadata
        metadata = TicketMetadata(
            ticket_id=data.get("ticket_id", str(uuid.uuid4())),
            hostname=hostname,
            classification=classification,
            os_family=os_family,
            source_file=source_file,
            dest_path=dest_path,
            case_id=data.get("case_id"),
            case_name=data.get("case_name"),
            analyst=data.get("analyst"),
            created_utc=data.get("created_utc", datetime.now(timezone.utc).isoformat()),
            staged_utc=data.get("staged_utc"),
            priority=data.get("priority", 5),
            tags=data.get("tags", []),
        )
        
        # Preserve any extra fields in custom dict
        preserved_fields = {
            k: v for k, v in data.items()
            if k not in {
                "host", "hostname", "dest_path", "path", "image_path",
                "classification", "os_family", "os", "source_file",
                "ticket_id", "case_id", "case_name", "analyst",
                "created_utc", "staged_utc", "priority", "tags",
                "schema_version", "metadata", "worker_config",
                "plugins",  # Move to worker_config
            }
        }
        metadata.custom = preserved_fields
        
        # Move plugin overrides to worker_config
        worker_config = data.get("worker_config", {})
        if "plugins" in data:
            worker_config["plugins"] = data["plugins"]
        
        return cls(
            metadata=metadata,
            worker_config=worker_config,
            schema_version="2.0",
        )
    
    def get_artifact_envelope(self, tool: str, module: str) -> Dict[str, Any]:
        """
        Produce a metadata envelope to merge into each artifact record.
        
        The envelope contains ticket identity, source file and path, classification, the provided tool and module names, case and analyst info, OS fields when present, current UTC artifact_created_utc timestamp, tags, and any custom metadata from the ticket.
        
        Parameters:
            tool (str): Name of the producing tool (e.g., "volatility").
            module (str): Name of the tool module or plugin (e.g., "windows.pslist").
        
        Returns:
            Dict[str, Any]: Mapping of envelope fields suitable for merging into an artifact JSON object.
        """
        m = self.metadata
        return {
            # Identity
            "ticket_id": m.ticket_id,
            "hostname": m.hostname,
            
            # Source
            "source_file": m.source_file,
            "dest_path": m.dest_path,
            "classification": m.classification,
            
            # Tool
            "tool": tool,
            "module": module,
            
            # Case
            "case_id": m.case_id,
            "case_name": m.case_name,
            "analyst": m.analyst,
            
            # OS (if known)
            "os_family": m.os_family,
            "os_version": m.os_version,
            
            # Timestamp
            "artifact_created_utc": datetime.now(timezone.utc).isoformat(),
            
            # Tags
            "tags": m.tags,
            
            # Custom fields
            **m.custom,
        }


def validate_ticket(ticket: WorkerTicket) -> List[str]:
    """
    Check a WorkerTicket for missing or invalid required fields.
    
    Performs these validations: hostname presence and not "unknown_host", dest_path presence and filesystem existence, classification not "unknown", created_utc is a valid ISO-8601 timestamp, and priority is between 1 and 10.
    
    Parameters:
        ticket (WorkerTicket): The ticket to validate.
    
    Returns:
        List[str]: A list of validation messages; an empty list indicates the ticket is valid.
    """
    issues = []
    m = ticket.metadata
    
    # Required fields
    if not m.hostname or m.hostname == "unknown_host":
        issues.append("Missing or invalid hostname")
    
    if not m.dest_path:
        issues.append("Missing dest_path")
    elif not Path(m.dest_path).exists():
        issues.append(f"dest_path does not exist: {m.dest_path}")
    
    if m.classification == "unknown":
        issues.append("Classification is 'unknown'")
    
    # Timestamps
    try:
        datetime.fromisoformat(m.created_utc.replace("Z", "+00:00"))
    except ValueError:
        issues.append(f"Invalid created_utc timestamp: {m.created_utc}")
    
    # Priority range
    if not 1 <= m.priority <= 10:
        issues.append(f"Priority out of range (1-10): {m.priority}")
    
    return issues