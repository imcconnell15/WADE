"""
E01/Expert Witness Format classifier.

Detects EWF images (E01, Ex01) and extracts metadata using ewfinfo.
Handles fragmented E01 sets and optional auto-defragmentation.
"""
import re
import subprocess
from pathlib import Path
from typing import Optional

from .base import ClassificationResult, Classifier
from ..config import MAGIC_DB, EWFINFO_PATH, EWFEXPORT_PATH, AUTO_DEFRAG_E01, FRAGMENT_LOG
from ..file_ops import read_head


class E01Classifier:
    """Classifier for E01/EWF images."""
    
    priority = 10  # High priority (run early)
    
    def __init__(self):
        # Auto-detect ewfinfo if not configured
        self.ewfinfo_path = EWFINFO_PATH or self._find_ewfinfo()
    
    def _find_ewfinfo(self) -> Optional[str]:
        """Find ewfinfo on system."""
        import shutil
        return shutil.which("ewfinfo")
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check for EWF magic bytes."""
        for offset, magic in MAGIC_DB.get("ewf", []):
            if len(head_bytes) >= offset + len(magic):
                if head_bytes[offset:offset+len(magic)] == magic:
                    return True
        
        # Also check file extension
        suffix_lower = path.suffix.lower()
        if suffix_lower in (".e01", ".ex01", ".e02"):
            return True
        
        return False
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify E01 and extract metadata."""
        # Check if part of fragmented set
        if self._is_fragment(path):
            return self._handle_fragment(path)
        
        # Run ewfinfo to extract metadata
        if not self.ewfinfo_path:
            return ClassificationResult(
                classification="e01",
                confidence=0.7,
                details={"ewfinfo": "not_available"},
            )
        
        try:
            result = subprocess.run(
                [self.ewfinfo_path, str(path)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            
            if result.returncode != 0:
                return ClassificationResult(
                    classification="e01",
                    confidence=0.6,
                    error=f"ewfinfo failed: {result.stderr[:200]}",
                )
            
            # Parse ewfinfo output
            details = self._parse_ewfinfo(result.stdout)
            details["ewfinfo"] = "success"
            
            return ClassificationResult(
                classification="e01",
                confidence=0.95,
                details=details,
            )
        
        except subprocess.TimeoutExpired:
            return ClassificationResult(
                classification="e01",
                confidence=0.6,
                error="ewfinfo timeout",
            )
        except Exception as e:
            return ClassificationResult(
                classification="e01",
                confidence=0.6,
                error=f"ewfinfo error: {e}",
            )
    
    def _is_fragment(self, path: Path) -> bool:
        """Check if E01 is part of multi-segment set.
        
        Looks for E02, E03, etc. in same directory.
        """
        if not path.suffix.lower().startswith(".e"):
            return False
        
        # Get segment number
        match = re.match(r"\.e(\d+)", path.suffix.lower())
        if not match:
            return False
        
        segment_num = int(match.group(1))
        if segment_num == 1:
            # E01 is always the primary
            return False
        
        # Check if E01 exists
        base = path.with_suffix("")
        e01_upper = base.with_suffix(".E01")
        e01_lower = base.with_suffix(".e01")
        return e01_upper.exists() or e01_lower.exists()
    
    def _handle_fragment(self, path: Path) -> ClassificationResult:
        """Handle E01 fragment."""
        # Log fragment
        if FRAGMENT_LOG:
            try:
                with open(FRAGMENT_LOG, "a") as f:
                    f.write(f"{path}\n")
            except Exception:
                pass
        
        # If auto-defrag enabled, attempt merge
        if AUTO_DEFRAG_E01 and EWFEXPORT_PATH:
            merged = self._try_defrag(path)
            if merged:
                return ClassificationResult(
                    classification="e01",
                    confidence=0.9,
                    details={"defragmented": True, "merged_path": str(merged)},
                )
        
        # Otherwise skip fragment
        return ClassificationResult(
            classification="e01_fragment",
            confidence=0.9,
            details={"fragment": True, "skip": True},
        )
    
    def _try_defrag(self, path: Path) -> Optional[Path]:
        """Attempt to defragment E01 set using ewfexport.
        
        Returns:
            Path to merged raw image, or None on failure
        """
        
        # Find E01 base
        base = path.with_suffix("")
        e01_upper = base.with_suffix(".E01")
        e01_lower = base.with_suffix(".e01")
        
        if e01_upper.exists():
            e01 = e01_upper
        elif e01_lower.exists():
            e01 = e01_lower
        else:
            return None
        
        # Output path
        output = e01.parent / f"{e01.stem}_merged.dd"
        
        try:
            subprocess.run(
                [EWFEXPORT_PATH, "-t", str(output), "-f", "raw", str(e01)],
                capture_output=True,
                timeout=600,
                check=True,
            )
            
            if output.exists():
                return output
        
        except Exception:
            pass
        
        return None
    
    def _parse_ewfinfo(self, stdout: str) -> dict:
        """Parse ewfinfo output for metadata.
        
        Extracts:
          - hostname (from system/model/computer name)
          - os_family (from description)
          - date_collected (from acquisition date)
          - sectors, bytes per sector
        """
        details = {}
        
        # Regex patterns for metadata
        patterns = {
            "hostname": [
                r"Computer name\s*:\s*(.+)",
                r"System name\s*:\s*(.+)",
                r"Model\s*:\s*(.+)",
            ],
            "os": [
                r"Operating system\s*:\s*(.+)",
                r"OS version\s*:\s*(.+)",
            ],
            "date_collected": [
                r"Acquisition date\s*:\s*(.+)",
            ],
            "sectors": [
                r"Number of sectors\s*:\s*(\d+)",
            ],
            "bytes_per_sector": [
                r"Bytes per sector\s*:\s*(\d+)",
            ],
        }
        
        for key, regexes in patterns.items():
            for regex in regexes:
                match = re.search(regex, stdout, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if key == "sectors" or key == "bytes_per_sector":
                        details[key] = int(value)
                    else:
                        details[key] = value
                    break
        
        # Infer os_family from os string
        if "os" in details:
            os_str = details["os"].lower()
            if "windows" in os_str:
                details["os_family"] = "windows"
            elif "linux" in os_str:
                details["os_family"] = "linux"
            elif "mac" in os_str or "darwin" in os_str:
                details["os_family"] = "macos"
        
        return details
