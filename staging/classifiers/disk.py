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
        """
        Determine whether the provided path or head bytes indicate a raw disk image.
        
        Parameters:
            path (Path): Filesystem path of the candidate file; used to check filename-based extensions.
            head_bytes (bytes): Leading bytes from the file (typically the first few kilobytes) used to detect GPT/MBR signatures or filesystem magic.
        
        Returns:
            bool: `True` if signatures or filename patterns suggest the file is a disk image, `False` otherwise.
        """
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
        """
        Classify a disk image file and collect partition and filesystem metadata.
        
        Parameters:
            path (Path): Filesystem path to the disk image to analyze.
        
        Returns:
            ClassificationResult: Classification with:
                - classification: "disk_raw"
                - confidence: 0.85
                - details: dict with keys
                    - "partition_type": "gpt", "mbr", or None
                    - "filesystem": detected filesystem type (e.g., "ntfs", "fat32", "ext") or "unknown"
                    - "hostname": present when a hostname could be extracted
        """
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
        """
        Detects the filesystem type present in a disk image header by checking known filesystem signatures.
        
        Returns:
            str: "ntfs", "fat32", "ext", or "unknown" if no recognized filesystem signature is found.
        """
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
        """
        Extract a hostname from the disk image at path using the external `target-info` utility when available.
        
        If `target-info` is not available, the output contains no hostname, or an error occurs, this function returns `None`.
        
        Parameters:
            path (Path): Filesystem path to the disk image to inspect.
        
        Returns:
            hostname (str): The discovered hostname or computer_name value, or `None` if not found or not obtainable.
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