"""
Disk image classifier.

Detects raw disk images with partition tables (GPT, MBR) and filesystems.
"""
import subprocess
from pathlib import Path

from .base import ClassificationResult, Classifier
from ..config import MAGIC_DB
from ..file_ops import calculate_entropy


class DiskClassifier:
    """Classifier for raw disk images."""
    
    priority = 30  # After memory
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check for disk image indicators."""
        # Check for GPT signature
        if b"EFI PART" in head_bytes[:512]:
            return True
        
        # Check for MBR boot signature
        if len(head_bytes) >= 512 and head_bytes[510:512] == b"\x55\xAA":
            return True
        
        # Check for filesystem signatures
        for fs_type in ["ntfs", "fat32"]:
            for offset, magic in MAGIC_DB.get(fs_type, []):
                if len(head_bytes) >= offset + len(magic):
                    if head_bytes[offset:offset+len(magic)] == magic:
                        return True
        
        # Check filename patterns
        name_lower = path.name.lower()
        if any(ext in name_lower for ext in [".dd", ".img", ".raw", ".dmg"]):
            return True
        
        return False
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify disk image and detect partition type."""
        head = path.read_bytes()[:4096] if path.exists() else b""
        
        # Check partition table type
        partition_type = None
        if b"EFI PART" in head[:512]:
            partition_type = "gpt"
        elif len(head) >= 512 and head[510:512] == b"\x55\xAA":
            partition_type = "mbr"
        
        # Detect filesystem
        filesystem = self._detect_filesystem(head)
        
        # Try to extract hostname from filesystem (if mounted or via tools)
        hostname = self._try_extract_hostname(path)
        
        details = {
            "partition_type": partition_type,
            "filesystem": filesystem,
        }
        
        if hostname:
            details["hostname"] = hostname
        
        return ClassificationResult(
            classification="disk_raw",
            confidence=0.85,
            details=details,
        )
    
    def _detect_filesystem(self, head: bytes) -> str:
        """Detect filesystem type from magic bytes."""
        if len(head) >= 512:
            # NTFS
            if head[3:11] == b"NTFS    ":
                return "ntfs"
            
            # FAT32
            if len(head) >= 90 and head[82:90] == b"FAT32   ":
                return "fat32"
            
            # Ext2/3/4
            if len(head) >= 1080 and head[1080:1082] == b"\x53\xEF":
                return "ext"
        
        return "unknown"
    
    def _try_extract_hostname(self, path: Path) -> str:
        """Attempt to extract hostname from disk image.
        
        Uses dissect target-info if available.
        """
        try:
            import shutil
            if not shutil.which("target-info"):
                return None
            
            result = subprocess.run(
                ["target-info", "-J", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                import json
                for line in result.stdout.splitlines():
                    if line.strip().startswith("{"):
                        info = json.loads(line)
                        return info.get("hostname") or info.get("computer_name")
        
        except Exception:
            pass
        
        return None
