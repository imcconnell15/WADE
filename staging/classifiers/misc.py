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
        """
        Indicate whether this classifier can handle the provided path; acts as a fallback that accepts any input.
        
        Returns:
            bool: `true` (this fallback classifier accepts all inputs).
        """
        return True
    
    def classify(self, path: Path) -> ClassificationResult:
        """
        Determine a miscellaneous classification for the file at the given path by detecting whether it is text or binary.
        
        Parameters:
            path (Path): Path to the file to classify.
        
        Returns:
            ClassificationResult: A result with classification "misc". For text files, details include `file_type` and `content_type`; for binary files, details include `file_type` and `extension`. Confidence reflects heuristic certainty.
        """
        is_text, sample = is_probably_text(path)
        
        if is_text:
            return self._classify_text_file(path, sample)
        else:
            return self._classify_binary_file(path)
    
    def _classify_text_file(self, path: Path, sample: str) -> ClassificationResult:
        """
        Infer a text file's broad content type and produce a misc classification.
        
        Parameters:
            path (Path): Path to the file being classified.
            sample (str): A text excerpt from the file used to infer content characteristics.
        
        Returns:
            ClassificationResult: A classification with:
                - classification: "misc"
                - confidence: 0.5
                - details: a dict containing
                    - "file_type": "text"
                    - "content_type": one of "json", "xml", "csv", "log", or "text" depending on the sample
        """
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
        """
        Classify a non-text file by extension or reject it when binary documents are disabled.
        
        If WADE_STAGE_ACCEPT_DOCS is False, returns an 'unknown' result with confidence 0.0 and details {'rejected': True}. Otherwise infers a broad file_type from the file's lowercase suffix (e.g., 'document', 'spreadsheet', 'archive', 'executable', 'image', 'video', 'audio', or 'binary') and returns a 'misc' classification with confidence 0.4; the details include 'file_type' and the 'extension'.
         
        Returns:
            ClassificationResult: The inferred classification result as described above.
        """
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
        """
        Determine whether the file's name suggests it is a malware sample.
        
        Parameters:
            path (Path): Filesystem path whose filename is checked for malware-related indicator substrings (case-insensitive).
            head_bytes (bytes): Initial bytes of the file (ignored by this classifier).
        
        Returns:
            bool: `true` if the filename contains any malware indicator substring, `false` otherwise.
        """
        name_lower = path.name.lower()
        
        # Check for malware indicators in filename
        indicators = [
            "malware", "suspicious", "sample", "dropper",
            "ransomware", "trojan", "virus", "infected",
        ]
        
        return any(ind in name_lower for ind in indicators)
    
    def classify(self, path: Path) -> ClassificationResult:
        """
        Classifies the given path as a malware sample.
        
        Parameters:
            path (Path): File system path to classify; if the file exists and begins with the PE header ("MZ"), the result will include executable type details.
        
        Returns:
            ClassificationResult: classification set to "malware", confidence set to 0.7, and details containing {"executable_type": "pe"} when the file is detected as a Windows PE executable.
        """
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