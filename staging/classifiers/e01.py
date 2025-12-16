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
        """
        Initialize the classifier and determine the ewfinfo executable path.
        
        Sets self.ewfinfo_path to the configured EWFINFO_PATH if provided; otherwise attempts to locate ewfinfo via _find_ewfinfo().
        """
        self.ewfinfo_path = EWFINFO_PATH or self._find_ewfinfo()
    
    def _find_ewfinfo(self) -> Optional[str]:
        """
        Locate the `ewfinfo` executable on the system PATH.
        
        Returns:
            ewfinfo_path (Optional[str]): Full path to the `ewfinfo` executable if found, `None` otherwise.
        """
        import shutil
        return shutil.which("ewfinfo")
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """
        Determine whether a file is an Expert Witness Format (EWF) image by checking header magic at configured offsets or by known EWF file extensions.
        
        Parameters:
            head_bytes (bytes): Initial bytes read from the file used to check for EWF magic at configured offsets.
        
        Returns:
            `true` if the file matches EWF magic or has a known EWF extension (e.g., `.e01`, `.ex01`, `.e02`), `false` otherwise.
        """
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
        """
        Classify the given path as an E01/EWF image and extract available metadata.
        
        If the file is part of a fragmented EWF set, delegates to the fragment handler and returns its result. If ewfinfo is not available, returns a basic "e01" classification with confidence 0.7 and details noting ewfinfo unavailability. If ewfinfo runs but exits with an error, returns "e01" with confidence 0.6 and an error message containing the tool's stderr (truncated). On ewfinfo timeout, returns "e01" with confidence 0.6 and error "ewfinfo timeout". On successful ewfinfo execution, returns "e01" with confidence 0.95 and details populated from parsed ewfinfo output (includes a key "ewfinfo" set to "success"). Other exceptions produce an "e01" result with confidence 0.6 and an error describing the exception.
        
        Parameters:
            path (Path): Filesystem path to the candidate E01/EWF image.
        
        Returns:
            ClassificationResult: Classification outcome including `classification`, `confidence`, and either `details` (metadata) or `error` describing the failure.
        """
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
        """
        Determine whether the given path is a later segment of an EWF multi-segment set.
        
        Checks that the file's suffix indicates a numbered EWF segment greater than 1 (for example `.e02`) and that a corresponding primary `.E01` file exists for the same base path.
        
        Returns:
            `true` if the file is a segment numbered greater than 1 and a matching `.E01` primary exists, `false` otherwise.
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
        e01 = base.with_suffix(".E01")
        return e01.exists()
    
    def _handle_fragment(self, path: Path) -> ClassificationResult:
        """
        Handle an E01/EWF fragment file and optionally attempt defragmentation.
        
        If a fragment log is configured, appends the fragment path to the log. If auto-defragmentation is enabled and ewfexport is available, attempts to merge the fragment into a single raw image; on success returns a classification for the merged E01. If merging is not performed or fails, returns a fragment classification indicating the fragment was skipped.
        
        Parameters:
            path (Path): Path to the fragment file.
        
        Returns:
            ClassificationResult: If defragmentation succeeds, a result with classification `"e01"`, confidence 0.9, and details containing `{"defragmented": True, "merged_path": "<path>"}`. Otherwise, a result with classification `"e01_fragment"`, confidence 0.9, and details `{"fragment": True, "skip": True}`.
        """
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
        """
        Attempt to defragment an E01 multi-segment set into a merged raw image file.
        
        Parameters:
            path (Path): Path to an E01 segment within the multi-segment set.
        
        Returns:
            Optional[Path]: Path to the merged raw image (named "<base>_merged.dd" in the same directory) if defragmentation succeeded, `None` otherwise.
        """
        # Find E01 base
        base = path.with_suffix("")
        e01 = base.with_suffix(".E01")
        
        if not e01.exists():
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
        """
        Parse the text output produced by ewfinfo and extract EWF image metadata.
        
        Parses common labeled fields from the provided ewfinfo stdout (for example
        "Computer name", "Operating system", "Acquisition date", "Number of sectors",
        and "Bytes per sector") and returns a dictionary of the discovered values.
        Also derives an `os_family` key when the operating system string indicates
        Windows, Linux, or macOS.
        
        Parameters:
            stdout (str): The complete stdout text produced by ewfinfo for an image.
        
        Returns:
            dict: A mapping of extracted metadata. Possible keys include:
                - "hostname": host or model name string
                - "os": operating system string
                - "os_family": inferred OS family ("windows", "linux", "macos")
                - "date_collected": acquisition date string
                - "sectors": number of sectors (int)
                - "bytes_per_sector": bytes per sector (int)
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