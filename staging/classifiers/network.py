"""
Network configuration classifier.

Detects and parses network device configurations (Cisco, Juniper, etc.).
Extracts hostname and device type from config files.
"""
import re
from pathlib import Path
from typing import Optional, Tuple

from .base import ClassificationResult, Classifier
from ..file_ops import is_probably_text, extract_text_snippet


class NetworkConfigClassifier:
    """Classifier for network device configurations."""
    
    priority = 40  # After binary formats
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check if file looks like network config."""
        # Must be text
        is_text, sample = is_probably_text(path)
        if not is_text:
            return False
        
        # Check for network config indicators
        sample_lower = sample.lower()
        indicators = [
            "hostname",
            "interface ",
            "ip address",
            "router ",
            "switch",
            "vlan",
            "cisco",
            "juniper",
            "! last configuration change",
            "service timestamps",
            "enable secret",
        ]
        
        match_count = sum(1 for indicator in indicators if indicator in sample_lower)
        return match_count >= 2
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify network config and extract metadata."""
        text = extract_text_snippet(path, max_bytes=100*1024)  # 100KB sample
        
        # Detect device type
        device_type = self._detect_device_type(text)
        
        # Extract hostname
        hostname = self._extract_hostname(text, device_type)
        
        # Extract device model if present
        model = self._extract_model(text)
        
        details = {
            "device_type": device_type,
        }
        
        if hostname:
            details["hostname"] = hostname
        
        if model:
            details["model"] = model
        
        # Determine confidence
        confidence = 0.9 if hostname else 0.7
        
        return ClassificationResult(
            classification="network_config",
            confidence=confidence,
            details=details,
        )
    
    def _detect_device_type(self, text: str) -> str:
        """Detect network device vendor/type."""
        text_lower = text.lower()
        
        if "cisco" in text_lower or "ios " in text_lower:
            return "cisco"
        elif "juniper" in text_lower or "junos" in text_lower:
            return "juniper"
        elif "arista" in text_lower:
            return "arista"
        elif "hp " in text_lower or "procurve" in text_lower:
            return "hp"
        elif "dell" in text_lower:
            return "dell"
        elif "mikrotik" in text_lower or "routeros" in text_lower:
            return "mikrotik"
        
        return "generic"
    
    def _extract_hostname(self, text: str, device_type: str) -> Optional[str]:
        """Extract hostname from config."""
        # Try device-specific patterns first
        if device_type == "cisco":
            return self._extract_cisco_hostname(text)
        elif device_type == "juniper":
            return self._extract_juniper_hostname(text)
        
        # Generic patterns
        patterns = [
            r"^hostname\s+(\S+)",
            r"^set\s+system\s+host-name\s+(\S+)",
            r"^sysname\s+(\S+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_cisco_hostname(self, text: str) -> Optional[str]:
        """Extract hostname from Cisco IOS config."""
        # Pattern: hostname DEVICE-NAME
        match = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
        if match:
            return match.group(1)
        return None
    
    def _extract_juniper_hostname(self, text: str) -> Optional[str]:
        """Extract hostname from Juniper config."""
        # Pattern: set system host-name device-name
        match = re.search(r"^set\s+system\s+host-name\s+(\S+)", text, re.MULTILINE)
        if match:
            return match.group(1)
        return None
    
    def _extract_model(self, text: str) -> Optional[str]:
        """Extract device model from config comments."""
        patterns = [
            r"Cisco\s+([\w\-]+)\s+",
            r"model:\s*([\w\-]+)",
            r"Product:\s*([\w\-]+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None


class NetworkDocumentClassifier:
    """Classifier for network documentation (diagrams, spreadsheets, etc.)."""
    
    priority = 50  # Lower priority than configs
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check if file is network-related documentation."""
        name_lower = path.name.lower()
        
        # Check for network-related keywords in filename
        keywords = [
            "network", "topology", "diagram", "vlan", "subnet",
            "ip_address", "ip-address", "ipam", "firewall",
            "switch", "router", "infrastructure",
        ]
        
        has_keyword = any(kw in name_lower for kw in keywords)
        if not has_keyword:
            return False
        
        # Check for document formats
        doc_extensions = {".pdf", ".xlsx", ".xls", ".docx", ".doc", ".vsd", ".vsdx", ".csv"}
        return path.suffix.lower() in doc_extensions
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify network documentation."""
        return ClassificationResult(
            classification="network_doc",
            confidence=0.8,
            details={
                "doc_type": path.suffix.lower(),
            },
        )
