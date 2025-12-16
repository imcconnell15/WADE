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
        """
        Initialize the registry and populate it with the default classifier pipeline ordered by priority.
        
        Attributes:
            classifiers (List[Classifier]): Ordered list of registered classifiers; earlier entries have lower priority.
        """
        self.classifiers: List[Classifier] = []
        self._register_defaults()
    
    def _register_defaults(self) -> None:
        """
        Populate the registry with the module's default classifier instances in a deterministic priority order.
        
        Replaces self.classifiers with the built-in classifier pipeline and ensures the list is ordered by each classifier's priority (ascending). The MiscClassifier is included as a fallback and is intended to run last.
        """
        self.classifiers = [
            E01Classifier(),
            MemoryClassifier(),
            VMClassifier(),
            DiskClassifier(),
            NetworkConfigClassifier(),
            MalwareClassifier(),
            NetworkDocumentClassifier(),
            MiscClassifier(),  # Fallback (always last)
        ]
        
        # Sort by priority
        self.classifiers.sort(key=lambda c: c.priority)
    
    def register(self, classifier: Classifier) -> None:
        """
        Add a classifier to the registry and reorder the registry by ascending priority.
        
        Parameters:
            classifier (Classifier): Classifier instance to add. The classifier's numeric
                `priority` attribute is used to determine its position in the registry.
        """
        self.classifiers.append(classifier)
        self.classifiers.sort(key=lambda c: c.priority)
    
    def classify(self, path: Path) -> ClassificationResult:
        """
        Selects and runs registered classifiers in priority order and returns the first successful classification.
        
        Parameters:
            path (Path): Path to the file to classify.
        
        Returns:
            ClassificationResult: The result from the first classifier whose `success` is `True`. If no classifier succeeds, returns a result with `classification` set to `"unknown"`, `confidence` set to `0.0`, and `details` containing `{"reason": "no_classifier_matched"}`.
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
    """
    Return the singleton global classifier registry, creating and caching it on first access.
    
    @returns: The global ClassifierRegistry singleton instance.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = ClassifierRegistry()
    return _default_registry