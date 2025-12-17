"""
Classifier registry and orchestration.

Manages the chain of classifiers and executes them in priority order.
"""
from pathlib import Path
from typing import List, Optional

from .base import ClassificationResult, Classifier
from .e01 import E01Classifier
from .memory import MemoryClassifier
from .disk import DiskClassifier
from .vm import VMClassifier
from .network import NetworkConfigClassifier, NetworkDocumentClassifier
from .misc import MiscClassifier, MalwareClassifier

from ..file_ops import read_head


class ClassifierRegistry:
    """Registry of file classifiers."""
    
    def __init__(self):
        self.classifiers: List[Classifier] = []
        self._register_defaults()
    
     def _register_defaults(self) -> None:
         """Register default classifiers in priority order."""
        self.classifiers = sorted([
            E01Classifier(),
            MemoryClassifier(),
            VMClassifier(),
            DiskClassifier(),
            NetworkConfigClassifier(),
            MalwareClassifier(),
            NetworkDocumentClassifier(),
            MiscClassifier(),  # Fallback (should have lowest priority)
        ], key=lambda c: c.priority)
    
    def register(self, classifier: Classifier) -> None:
        """Register a custom classifier.
        
        Args:
            classifier: Classifier instance
        """
        self.classifiers.append(classifier)
        self.classifiers.sort(key=lambda c: c.priority)
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify a file using the registered classifiers.
        
        Runs classifiers in priority order until one succeeds.
        
        Args:
            path: File to classify
        
        Returns:
            ClassificationResult from the first successful classifier
        """
        # Read file head for quick magic byte checks
        head_bytes = read_head(path)
        
        # Try classifiers in order
        for classifier in self.classifiers:
            # Quick check before expensive classification
            if not classifier.can_classify(path, head_bytes):
                continue
            
            # Run full classification
            result = classifier.classify(path)
            
            # Return first successful classification
            if result.success:
                return result
            
            # Continue if classifier failed or returned unknown
        
        # No classifier succeeded; return unknown
        return ClassificationResult(
            classification="unknown",
            confidence=0.0,
            details={"reason": "no_classifier_matched"},
        )


# Global default registry
_default_registry: Optional[ClassifierRegistry] = None


def get_classifier_registry() -> ClassifierRegistry:
    """Get or create the global classifier registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = ClassifierRegistry()
    return _default_registry
