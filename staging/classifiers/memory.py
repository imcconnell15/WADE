"""
Memory dump classifier.

Detects raw memory dumps, hibernation files, and LIME images.
Uses volatility for OS profile detection.
"""
import re
import subprocess
from pathlib import Path
from typing import Optional

from .base import ClassificationResult, Classifier
from ..config import MAGIC_DB, MEM_MIN_BYTES, VOLATILITY_PATH
from ..file_ops import calculate_entropy


class MemoryClassifier:
    """Classifier for memory dumps."""
    
    priority = 20  # After E01
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """
        Determine whether a file at `path` plausibly represents a memory-related image (raw memory, hibernation, or LIME).
        
        Parameters:
            path (Path): Filesystem path to the candidate file; used for filename pattern checks and size heuristics.
            head_bytes (bytes): Initial bytes read from the file (typically the file head); used to match known magic signatures.
        
        Returns:
            bool: `true` if magic signatures, filename patterns, or size heuristics indicate the file is a memory image, `false` otherwise.
        """
        # Check magic bytes
        for mem_type in ["hibr", "lime"]:
            for offset, magic in MAGIC_DB.get(mem_type, []):
                if len(head_bytes) >= offset + len(magic):
                    if head_bytes[offset:offset+len(magic)] == magic:
                        return True
        
        # Check filename patterns
        name_lower = path.name.lower()
        patterns = [
            r"mem(ory)?[\._-]?dump",
            r"\.vmem$",
            r"\.raw$",
            r"hiberfil",
            r"\.lime$",
            r"\.dmp$",
        ]
        for pattern in patterns:
            if re.search(pattern, name_lower):
                return True
        
        # Check size (memory dumps typically > 64MB)
        try:
            if path.stat().st_size >= MEM_MIN_BYTES:
                return True
        except OSError:
            pass
        
        return False
    
    def classify(self, path: Path) -> ClassificationResult:
        """
        Classifies the file at the given path as a memory artifact and attempts to determine its memory type and OS profile.
        
        Returns:
            ClassificationResult: Object containing 'classification' (e.g., "memory" or "unknown"), 'confidence' (float), and a 'details' dictionary with keys such as 'memory_type' and optional 'profile' and 'os_family'.
        """
        # Detect specific types
        head = path.read_bytes()[:512] if path.exists() else b""
        
        # Hibernation file
        if head.startswith(b"hibr") or head.startswith(b"HIBR"):
            return self._classify_hibernation(path)
        
        # LIME dump
        if head.startswith(b"EMiL"):
            return self._classify_lime(path)
        
        # Raw memory dump - try volatility detection
        return self._classify_raw_memory(path)
    
    def _classify_hibernation(self, path: Path) -> ClassificationResult:
        """
        Classify a Windows hibernation file.
        
        @returns ClassificationResult with classification "memory", confidence 0.95, and details: {"memory_type": "hibernation", "os_family": "windows"}.
        """
        return ClassificationResult(
            classification="memory",
            confidence=0.95,
            details={
                "memory_type": "hibernation",
                "os_family": "windows",
            },
        )
    
    def _classify_lime(self, path: Path) -> ClassificationResult:
        """
        Classify the given path as a Linux LIME memory image.
        
        Returns:
            ClassificationResult: A result with classification "memory", confidence 0.95, and details containing
            "memory_type": "lime" and "os_family": "linux".
        """
        return ClassificationResult(
            classification="memory",
            confidence=0.95,
            details={
                "memory_type": "lime",
                "os_family": "linux",
            },
        )
    
    def _classify_raw_memory(self, path: Path) -> ClassificationResult:
        """
        Classify a raw memory image and attempt to detect an OS/profile for it.
        
        Performs a 1 MB entropy sample to rule out low-entropy files; if the sample's entropy is less than 5.0 the function returns an "unknown" classification. If the sample appears consistent with memory, the function invokes volatility-based profile detection; when a profile is found the result contains the detected profile and operating-system family, otherwise it returns a memory classification with profile set to "unknown".
        
        Returns:
            ClassificationResult: If entropy is low: classification="unknown", confidence=0.0.
                                  If a volatility profile is detected: classification="memory", confidence=0.9, details include "memory_type": "raw", "profile": <name>, and "os_family".
                                  If no profile is detected: classification="memory", confidence=0.6, details include "memory_type": "raw" and "profile": "unknown".
        """
        # Quick entropy check (memory dumps have high entropy)
        try:
            sample = path.read_bytes()[:1024*1024]  # 1MB sample
            entropy = calculate_entropy(sample)
            
            if entropy < 5.0:
                # Low entropy; probably not memory
                return ClassificationResult(
                    classification="unknown",
                    confidence=0.0,
                )
        except Exception:
            pass
        
        # Try volatility imageinfo (expensive, so only if looks promising)
        profile, os_family = self._detect_profile_volatility(path)
        
        if profile:
            return ClassificationResult(
                classification="memory",
                confidence=0.9,
                details={
                    "memory_type": "raw",
                    "profile": profile,
                    "os_family": os_family,
                },
            )
        
        # Fallback: looks like memory but no profile
        return ClassificationResult(
            classification="memory",
            confidence=0.6,
            details={"memory_type": "raw", "profile": "unknown"},
        )
    
    def _detect_profile_volatility(self, path: Path) -> tuple:
        """
        Attempt to detect a memory profile for the given file by invoking the Volatility `windows.info` plugin.
        
        Runs Volatility against the provided path and parses its output to extract a suggested profile.
        
        Returns:
            tuple: (profile_name, os_family) where `profile_name` is the detected Volatility profile string or `None` if detection failed, and `os_family` is `"windows"` when a profile is found or `None` otherwise.
        """
        try:
            # Run vol.py -f <path> windows.info (fast check for Windows)
            result = subprocess.run(
                [VOLATILITY_PATH, "-f", str(path), "windows.info"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if result.returncode == 0:
                # Parse profile from output
                profile = self._parse_volatility_profile(result.stdout)
                return profile, "windows"
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None, None
    
    def _parse_volatility_profile(self, stdout: str) -> Optional[str]:
        """
        Extract the suggested Volatility profile name from Volatility tool output.
        
        Parameters:
            stdout (str): Text output produced by the Volatility tool to be searched for profile hints.
        
        Returns:
            Optional[str]: The first detected profile name (trimmed, first comma-separated token) if present, `None` otherwise.
        """
        # Look for "Suggested Profile(s)" or similar
        patterns = [
            r"Suggested Profile\(s\)\s*:\s*(.+)",
            r"Profile\s*:\s*(.+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, stdout, re.IGNORECASE)
            if match:
                profile = match.group(1).strip().split(",")[0]
                return profile
        
        return None