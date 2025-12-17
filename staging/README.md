# WADE Staging Daemon

The **Staging Daemon** is the entry point for all evidence files entering the WADE pipeline. It provides intelligent classification, metadata extraction, deduplication, and ticket generation for downstream worker processing.

---

## 🎯 Overview

The staging daemon monitors designated directories for incoming forensic artifacts, automatically:
1. **Detects** new files via inotify or polling
2. **Waits** for file stability (no size changes, no open writers)
3. **Classifies** files using a priority-based registry of classifiers
4. **Extracts** metadata (hostname, OS, filesystem, Volatility profile, etc.)
5. **Deduplicates** using path and content signatures
6. **Routes** to appropriate tools based on classification and profile
7. **Generates** tickets with comprehensive metadata
8. **Moves** files to organized destination structure
9. **Enqueues** tickets for worker processing

---

## 🏗️ Architecture

```mermaid
graph TB
    A[File Arrives in Staging] --> B[Stability Check]
    B --> C[Deduplication Check]
    C --> D{Already Processed?}
    D -->|Yes| Z[Skip]
    D -->|No| E[Read File Head]
    E --> F[Classifier Registry]
    F --> G{Can Classify?}
    G -->|No Classifier| H[MiscClassifier]
    G -->|Yes| I[Run Classifier]
    I --> J{Classification Result}
    J -->|Unknown/Error| Z
    J -->|Success| K[Path Resolver]
    K --> L[Build Destination Path]
    L --> M[Tool Routing]
    M --> N[Build Ticket]
    N --> O[Move File]
    O --> P[Record in DB]
    P --> Q[Enqueue Ticket]
📂 Module Structure
staging/
├── classifiers/              # Classification engine
│   ├── __init__.py          # Registry and orchestration
│   ├── base.py              # ClassificationResult, Classifier protocol
│   ├── e01.py               # EnCase EWF images (priority 10)
│   ├── disk.py              # Raw disk images (priority 15)
│   ├── memory.py            # Memory dumps (priority 20)
│   ├── vm.py                # VM disk formats (priority 25)
│   ├── network.py           # Network configs & docs (priority 40/50)
│   └── misc.py              # Malware & fallback (priority 45/100)
├── config.py                # Environment-driven configuration
├── db.py                    # SQLite deduplication tracking
├── file_ops.py              # File I/O utilities
├── path_resolver.py         # Destination path construction
├── stage_daemon.py          # Main orchestrator (StagingDaemon class)
├── ticket_builder.py        # Ticket generation
├── tool_routing.py          # Tool selection engine
└── wade-staging.service     # systemd unit file
🔍 Classification System
Priority-Based Registry
Classifiers are executed in priority order (lowest number = highest priority). The first classifier that returns a successful result wins.

Priority	Classifier	Detects	Magic Bytes / Indicators
10	E01Classifier	EnCase EWF images	EVF\x09\r\n\x81 or .E01/.Ex01
15	DiskClassifier	Raw disk images	GPT signature, MBR boot sig, NTFS/FAT32 headers
20	MemoryClassifier	Memory dumps	Hibernation, LiME, entropy checks
25	VMClassifier	VM disk formats	QCOW2, VMDK, VHD, VHDX, VDI, OVA, OVF
40	NetworkConfigClassifier	Device configs	Text files with Cisco/Juniper/PAN syntax
45	MalwareClassifier	Malware samples	PE header + suspicious filenames
50	NetworkDocumentClassifier	Network diagrams	.vsdx, .drawio, topology keywords
100	MiscClassifier	Everything else	Fallback for text/binary/documents
Classifier Interface
from pathlib import Path
from typing import Protocol

@dataclass
class ClassificationResult:
    classification: str        # e.g., "e01", "memory", "disk_raw"
    confidence: float          # 0.0 to 1.0
    details: Dict[str, Any]    # hostname, os_family, profile, etc.
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.classification != "unknown" and self.error is None

class Classifier(Protocol):
    priority: int

    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Fast pre-check (magic bytes, extension, size)."""
        ...

    def classify(self, path: Path) -> ClassificationResult:
        """Full classification with metadata extraction."""
        ...
Example: E01Classifier
class E01Classifier:
    priority = 10  # Highest priority

    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check for EWF magic bytes or .E01/.Ex01 extension."""
        if head_bytes[:8] == b'EVF\x09\r\n\x81':
            return True
        suffix = path.suffix.lower()
        return suffix in {'.e01', '.ex01'}

    def classify(self, path: Path) -> ClassificationResult:
        """Extract metadata via ewfinfo."""
        # Check if part of a fragment set
        if self._is_fragment(path):
            return self._handle_fragment(path)
        
        # Run ewfinfo to extract metadata
        ewfinfo_path = self._find_ewfinfo()
        if not ewfinfo_path:
            return ClassificationResult(
                classification="e01",
                confidence=0.8,
                details={"note": "ewfinfo not available"},
                error=None
            )
        
        result = subprocess.run(
            [ewfinfo_path, str(path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        metadata = self._parse_ewfinfo(result.stdout)
        
        return ClassificationResult(
            classification="e01",
            confidence=0.95,
            details={
                "hostname": metadata.get("computer_name", "unknown"),
                "os_family": self._infer_os(metadata),
                "date_collected": metadata.get("acquisition_date"),
                "sectors": metadata.get("sectors"),
                "bytes_per_sector": metadata.get("bytes_per_sector"),
            }
        )
Metadata Extraction Examples
E01Classifier extracts via ewfinfo:

Computer name / hostname
OS information
Acquisition date/time
Drive geometry (sectors, bytes per sector)
Examiner notes
MemoryClassifier extracts via Volatility:

Suggested profile (e.g., Win10x64_19041)
OS family (Windows/Linux)
Hibernation file detection
LiME dump detection
DiskClassifier extracts via heuristics + target-info:

Partition type (GPT/MBR)
Filesystem (NTFS, FAT32, ext2/3/4)
Hostname (from filesystem metadata)
VMClassifier extracts from descriptors:

Hypervisor type (VMware, VirtualBox, Hyper-V, QEMU/KVM)
VM format (VMDK, VDI, VHDX, QCOW2)
Hostname from VMDK descriptor or OVF manifest
🎫 Ticket Generation
Ticket Builder Flow
from staging.ticket_builder import build_staging_ticket

ticket = build_staging_ticket(
    dest_path=dest_path,
    classification="e01",
    hostname="DESKTOP-ABC123",
    os_family="Windows",
    source_file=str(src_path),
    case_id="2025-001",
    case_name="Ransomware Investigation",
    analyst="autopsy",
    priority=5,
    tags=["ransomware", "critical"],
    profile="full",
    location="datacenterA",
    details=classification_result.details
)
Ticket Schema (v2.0)
{
  "schema_version": "2.0",
  "metadata": {
    "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
    "hostname": "DESKTOP-ABC123",
    "classification": "e01",
    "os_family": "Windows",
    "os_version": "10.0.19041",
    "source_file": "/home/autopsy/Staging/full/evidence.E01",
    "dest_path": "/home/autopsy/DataSources/e01/DESKTOP-ABC123/evidence.E01",
    "file_size_bytes": 52428800,
    "file_hash_sha256": "abc123...",
    "case_id": "2025-001",
    "case_name": "Ransomware Investigation",
    "analyst": "autopsy",
    "created_utc": "2025-12-16T20:00:00Z",
    "staged_utc": "2025-12-16T20:00:30Z",
    "acquired_utc": "2025-12-15T18:30:00Z",
    "priority": 5,
    "retry_count": 0,
    "tags": ["ransomware", "critical"],
    "custom": {
      "date_collected": "2025-12-15",
      "examiner": "J. Smith"
    }
  },
  "worker_config": {
    "profile": "full",
    "location": "datacenterA",
    "requested_tools": [
      "dissect",
      "hayabusa",
      "plaso",
      "bulk_extractor",
      "yara"
    ]
  }
}
🛤️ Tool Routing
Routing Engine
The ToolRouting class selects which tools to run based on:

Classification (e.g., e01, memory, disk_raw)
Profile (full vs light)
OS family (Windows, Linux, macOS)
Location (site-specific overrides)
Environment variables
Priority (highest to lowest):

1. DEFAULT_MATRIX (code defaults)
2. config.yaml routing.defaults
3. config.yaml os_overrides
4. config.yaml location_overrides
5. Environment variable (WADE_ROUTE_<CLASS>_<PROFILE>)
6. Global disable/enable (WADE_DISABLE_TOOLS / WADE_ENABLE_TOOLS)
7. Platform sanitization (remove hayabusa on non-Windows)
Example Routing
from staging.tool_routing import ToolRouting

router = ToolRouting()

# E01 image, full profile, Windows OS, datacenterA location
tools = router.select_tools(
    classification="e01",
    profile="full",
    details={"os_family": "Windows"},
    location="datacenterA"
)
# Returns: ["dissect", "hayabusa", "plaso", "bulk_extractor", "yara"]

# Memory dump, light profile, Linux
tools = router.select_tools(
    classification="memory",
    profile="light",
    details={"os_family": "Linux"}
)
# Returns: ["volatility"]  (hayabusa removed for Linux)
Configuration Examples
YAML (etc/config.yaml):

routing:
  defaults:
    e01:
      full: [dissect, hayabusa, plaso, bulk_extractor]
      light: [dissect, hayabusa]
    memory:
      full: [volatility, yara_mem]
      light: [volatility]

  os_overrides:
    windows:
      add:
        memory.full: [hayabusa]  # Add Hayabusa for Windows memory
    linux:
      remove:
        memory.full: [hayabusa]  # Remove Hayabusa for Linux

  location_overrides:
    datacenterA:
      add:
        e01.full: [yara]  # Add YARA at primary datacenter
    remote_site_B:
      remove:
        e01.full: [plaso]  # Skip heavy processing at remote site
Environment Variable:

# Override E01 full routing
WADE_ROUTE_E01_FULL=dissect,hayabusa,+yara,-plaso

# Global disable
WADE_DISABLE_TOOLS=autopsy,bulk_extractor

# Global enable (overrides disabled)
WADE_ENABLE_TOOLS=yara_mem
💾 Deduplication System
Two-Tier Strategy
1. Path Signature:

Combines: {resolved_path}_{file_size}_{mtime}
Purpose: Skip unchanged files at original location
Fast check before classification
2. Content Signature:

SHA256 of head (4MB) + tail (4MB)
Purpose: Detect renamed/moved files with identical content
Computed during classification
Database Schema
CREATE TABLE processed (
    sig TEXT PRIMARY KEY,           -- Path signature
    src_path TEXT NOT NULL,
    dest_path TEXT NOT NULL,
    file_size INTEGER,
    file_mtime REAL,
    staged_utc TEXT,
    last_seen_utc TEXT,
    classification TEXT,
    profile TEXT,
    content_sig TEXT                -- Content signature (SHA256)
);

CREATE INDEX idx_content_sig ON processed(content_sig);
Usage
from staging.db import init_db, path_signature, already_processed, record_processed

conn = init_db()

# Check if file was already processed
sig = path_signature(file_path)
if already_processed(conn, sig):
    print(f"Skipping {file_path}, already processed")
    return

# Check content signature for renamed files
content_sig = quick_hash(file_path)
if already_processed_by_content(conn, content_sig):
    print(f"Skipping {file_path}, content already processed")
    return

# Process file...
classification_result = classify(file_path)
dest_path = build_destination(file_path, classification_result)

# Record in database
record_processed(
    conn=conn,
    sig=sig,
    src_path=file_path,
    dest_path=dest_path,
    classification=classification_result.classification,
    profile="full",
    content_sig=content_sig
)
🗂️ Path Resolution
Destination Structure
DataSources/
└── <sourcetype>/              # e.g., "e01", "memory", "disk"
    └── <hostname>/            # Sanitized hostname
        └── <original_filename>
Sourcetype Mapping:

CLASSIFICATION_TO_SOURCETYPE = {
    "e01": "e01",
    "disk_raw": "disk",
    "memory": "memory",
    "vm_disk": "vm",
    "vm_package": "vm",
    "network_config": "network",
    "network_doc": "network",
    "malware": "malware",
    "misc": "misc"
}
Example Paths
Input: /home/autopsy/Staging/full/DESKTOP-ABC123_20251215.E01
Output: /home/autopsy/DataSources/e01/DESKTOP-ABC123/DESKTOP-ABC123_20251215.E01

Input: /home/autopsy/Staging/light/memory_dump.raw
Output: /home/autopsy/DataSources/memory/SERVER-XYZ/memory_dump.raw

Collision Handling:
If destination exists, append counter: file.E01, file_1.E01, file_2.E01, etc.

🎛️ Configuration
Environment Variables
Core Settings:

WADE_STAGINGDIR=/home/autopsy/Staging
WADE_DATADIR=/home/autopsy/DataSources
WADE_QUEUE_DIR=/home/autopsy/DataSources/_queue
WADE_LOG_DIR=/var/wade/logs
Behavior:

WADE_STAGE_STABLE_SECONDS=10       # Wait for file stability
WADE_STAGE_POLL_INTERVAL=30        # Directory scan interval
WADE_STAGE_REQUIRE_CLOSE_WRITE=true   # Wait for inotify CLOSE_WRITE
WADE_STAGE_VERIFY_NO_WRITERS=true     # Check lsof for open writers
WADE_STAGE_RECURSIVE=false            # Don't recurse subdirectories
WADE_STAGE_ACCEPT_DOCS=false          # Reject Office docs by default
WADE_STAGE_AUTO_DEFRAG_E01=false      # Don't auto-reassemble fragments
Tool Paths:

WADE_EWFINFO_PATH=/usr/bin/ewfinfo
WADE_EWFEXPORT_PATH=/usr/bin/ewfexport
WADE_VOLATILITY_PATH=/opt/volatility3/vol.py
WADE_LSOF_PATH=/usr/bin/lsof
Database:

WADE_STAGE_DB_PATH=/var/wade/staging/staging.db
Fragment Logging:

WADE_STAGE_FRAGMENT_LOG=/var/wade/logs/fragments.log
🚀 Usage
systemd Service
# Start staging daemon
sudo systemctl start wade-staging.service

# Enable on boot
sudo systemctl enable wade-staging.service

# Status
sudo systemctl status wade-staging.service

# Logs
journalctl -u wade-staging -f
Manual Execution
# One-time scan (process existing files and exit)
/opt/wade/staging/stage_daemon.py --scan-once

# Continuous monitoring (default)
/opt/wade/staging/stage_daemon.py

# Verbose logging
/opt/wade/staging/stage_daemon.py --verbose
Staging Directories
# Full pipeline (all tools)
cp evidence.E01 /home/autopsy/Staging/full/

# Light pipeline (minimal tools for triage)
cp memory.dmp /home/autopsy/Staging/light/
📊 Event Logging
All staging events are logged to /var/wade/logs/staging/stage_YYYY-MM-DD.jsonl in JSONL format.

Event Types:

staged — File successfully classified and enqueued
classification_error — Classification failed
dedup_skip — File skipped (already processed)
fragment_detected — E01 fragment detected
rejected — File rejected (unsupported type)
Example Event:

{
  "timestamp_utc": "2025-12-16T20:00:00.123Z",
  "event_type": "staged",
  "source": "staging_daemon",
  "status": "success",
  "file_path": "/home/autopsy/Staging/full/evidence.E01",
  "classification": "e01",
  "confidence": 0.95,
  "hostname": "DESKTOP-ABC123",
  "os_family": "Windows",
  "dest_path": "/home/autopsy/DataSources/e01/DESKTOP-ABC123/evidence.E01",
  "file_size_bytes": 52428800,
  "content_sig": "abc123...",
  "requested_tools": ["dissect", "hayabusa", "plaso"],
  "duration_sec": 2.5
}
🛠️ Troubleshooting
Files Not Being Processed
# Check service status
sudo systemctl status wade-staging.service

# Check logs
journalctl -u wade-staging -n 50

# Check directory permissions
ls -la /home/autopsy/Staging/full/
sudo chown -R autopsy:autopsy /home/autopsy/Staging/

# Verify file stability
watch -n 1 'ls -lh /home/autopsy/Staging/full/'
Classification Failures
# View recent classification errors
grep '"event_type": "classification_error"' /var/wade/logs/staging/stage_$(date +%Y-%m-%d).jsonl | tail -5

# Test classification manually
python3 -c "
from pathlib import Path
from staging.classifiers import get_classifier_registry

registry = get_classifier_registry()
result = registry.classify(Path('/path/to/file'))
print(f'Classification: {result.classification}')
print(f'Confidence: {result.confidence}')
print(f'Details: {result.details}')
print(f'Error: {result.error}')
"
Tool Detection Issues
# Check tool availability
which ewfinfo volatility target-info

# Set explicit paths
echo "WADE_EWFINFO_PATH=/usr/local/bin/ewfinfo" | sudo tee -a /etc/wade/wade.env
sudo systemctl restart wade-staging.service
Deduplication Issues
# View processed files
sqlite3 /var/wade/staging/staging.db "SELECT * FROM processed ORDER BY staged_utc DESC LIMIT 10;"

# Clear specific entry (use caution!)
sqlite3 /var/wade/staging/staging.db "DELETE FROM processed WHERE src_path='/path/to/file';"

# Rebuild database (nuclear option)
sudo systemctl stop wade-staging.service
sudo rm /var/wade/staging/staging.db
sudo systemctl start wade-staging.service
🧪 Testing
# Run staging tests
pytest staging/tests/ -v

# Test specific classifier
pytest staging/tests/test_classifiers.py::TestE01Classifier -v

# Test tool routing
pytest staging/tests/test_tool_routing.py -v

# Integration test (requires test fixtures)
pytest staging/tests/test_integration.py -v
📚 API Reference
StagingDaemon
class StagingDaemon:
    def __init__(self):
        """Initialize daemon with config, DB, logger."""
    
    def process_file(self, file_path: Path) -> bool:
        """Process a single file through the pipeline."""
    
    def scan_once(self) -> int:
        """Scan directories once, return count processed."""
    
    def watch_continuous(self) -> None:
        """Watch directories continuously (blocks)."""
ClassifierRegistry
class ClassifierRegistry:
    def register(self, classifier: Classifier) -> None:
        """Register a custom classifier."""
    
    def classify(self, path: Path) -> ClassificationResult:
        """Run priority-ordered classification."""

def get_classifier_registry() -> ClassifierRegistry:
    """Get the global registry singleton."""
ToolRouting
class ToolRouting:
    def __init__(self, config_path: Optional[Path] = None, env: Optional[Dict] = None):
        """Initialize with config and environment."""
    
    def select_tools(
        self,
        classification: str,
        profile: str,
        details: Optional[Dict] = None,
        location: Optional[str] = None
    ) -> List[str]:
        """Select tools based on classification and overrides."""
For more information:

Main README
Worker Documentation
Configuration Guide
