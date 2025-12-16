"""
Base classifier protocol for staging daemon.

All classifiers implement this protocol and return standardized results.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Dict, Any, Optional


@dataclass
class ClassificationResult:
    """Result from a classifier.
    
    Attributes:
        classification: Classification type (e.g., "e01", "memory", "unknown")
        confidence: Confidence score 0.0-1.0
        details: Metadata dict (hostname, os_family, etc.)
        error: Error message if classification failed
    """
    classification: str
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    @property
    def success(self) -> bool:
        """
        Indicates whether the classification represents a successful, non-error result.
        
        @returns `true` if the classification is not "unknown" and `error` is None, `false` otherwise.
        """
        return self.classification != "unknown" and self.error is None
    
    @property
    def is_unknown(self) -> bool:
        """
        Indicates whether the classification equals "unknown".
        
        Returns:
            True if classification equals "unknown", False otherwise.
        """
        return self.classification == "unknown"


class Classifier(Protocol):
    """Protocol for file classifiers.
    
    Classifiers examine files and return classification + metadata.
    """
    
    # Priority (lower = earlier in chain)
    priority: int
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """
        Determine whether this classifier should attempt to classify the given file.
        
        Parameters:
            path (Path): Path to the file to inspect.
            head_bytes (bytes): Leading bytes of the file (first N bytes) used for quick applicability checks.
        
        Returns:
            bool: `True` if the classifier should attempt classification, `False` otherwise.
        """
        ...
    
    def classify(self, path: Path) -> ClassificationResult:
        """
        Determine the file's classification and extract relevant metadata.
        
        May set `error` on the returned result if classification fails; `confidence` is in the range 0.0–1.0 and `details` contains classifier-specific metadata.
        
        Returns:
            ClassificationResult: Object containing the classification label, confidence, details, and optional error message.
        """
        ...