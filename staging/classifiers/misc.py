"""
Miscellaneous classifier (fallback).

Handles text files, documents, and unknown file types.
"""
from pathlib import Path
from typing import Optional

from .base import ClassificationResult, Classifier
from ..file_ops import is_probably_text
from ..config import WADE_STAGE_ACCEPT_DOCS


class MiscClassifier:
    """Fallback classifier for misc files."""
    
    priority = 100  # Lowest priority (run last)
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Always returns True (fallback)."""
        return True
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify misc file."""
        is_text, sample = is_probably_text(path)
        
        if is_text:
            return self._classify_text_file(path, sample)
        else:
            return self._classify_binary_file(path)
    
    def _classify_text_file(self, path: Path, sample: str) -> ClassificationResult:
        """Classify text file."""
        # Try to infer content type from sample
        sample_lower = sample.lower()
        
        # Check for structured data
        if sample.startswith("{") or sample.startswith("["):
            content_type = "json"
        elif sample.startswith("<?xml"):
            content_type = "xml"
        elif "," in sample and "\n" in sample:
            # CSV heuristic
            content_type = "csv"
        elif any(kw in sample_lower for kw in ["log", "timestamp", "error", "warning"]):
            content_type = "log"
        else:
            content_type = "text"
        
        return ClassificationResult(
            classification="misc",
            confidence=0.5,
            details={
                "file_type": "text",
                "content_type": content_type,
            },
        )
    
    def _classify_binary_file(self, path: Path) -> ClassificationResult:
        """Classify unknown binary file."""
        # Check if we should even accept this
        if not WADE_STAGE_ACCEPT_DOCS:
            return ClassificationResult(
                classification="unknown",
                confidence=0.0,
                details={"rejected": True},
            )
        
        # Classify by extension
        suffix = path.suffix.lower()
        
        known_extensions = {
            # Documents
            ".pdf": "document",
            ".docx": "document",
            ".doc": "document",
            ".xlsx": "spreadsheet",
            ".xls": "spreadsheet",
            
            # Archives
            ".zip": "archive",
            ".tar": "archive",
            ".gz": "archive",
            ".7z": "archive",
            
            # Executables
            ".exe": "executable",
            ".dll": "executable",
            ".so": "executable",
            
            # Media
            ".jpg": "image",
            ".png": "image",
            ".mp4": "video",
            ".mp3": "audio",
        }
        
        file_type = known_extensions.get(suffix, "binary")
        
        return ClassificationResult(
            classification="misc",
            confidence=0.4,
            details={
                "file_type": file_type,
                "extension": suffix,
            },
        )


class MalwareClassifier:
    """Classifier for suspected malware samples."""
    
    priority = 45  # Between network and misc
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check if file should be treated as malware."""
        name_lower = path.name.lower()
        
        # Check for malware indicators in filename
        indicators = [
            "malware", "suspicious", "sample", "dropper",
            "ransomware", "trojan", "virus", "infected",
        ]
        
        return any(ind in name_lower for ind in indicators)
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify as malware sample."""
        # Check if it's a Windows executable
        is_pe = path.read_bytes()[:2] == b"MZ" if path.exists() else False
        
        details = {}
        if is_pe:
            details["executable_type"] = "pe"
        
        return ClassificationResult(
            classification="malware",
            confidence=0.7,
            details=details,
        )
