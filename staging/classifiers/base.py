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
        """True if classification succeeded."""
        return self.classification != "unknown" and self.error is None
    
    @property
    def is_unknown(self) -> bool:
        """True if classification is unknown."""
        return self.classification == "unknown"


class Classifier(Protocol):
    """Protocol for file classifiers.
    
    Classifiers examine files and return classification + metadata.
    """
    
    # Priority (lower = earlier in chain)
    priority: int
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Quick check if this classifier applies.
        
        Args:
            path: File path
            head_bytes: First N bytes of file
        
        Returns:
            True if classifier should attempt classification
        """
        ...
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify file and extract metadata.
        
        Args:
            path: File path
        
        Returns:
            ClassificationResult
        """
        ...
