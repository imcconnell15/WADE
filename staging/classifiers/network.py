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
        """
        Determine whether a file likely contains a network device configuration.
        
        Checks that the file is text (via is_probably_text) and searches the extracted sample for common network-config indicators (e.g., hostname, interface, ip address, vendor names). The function returns true when at least two indicators are present.
        
        Parameters:
            path (Path): Filesystem path examined (used to determine if the file is text and to extract the sample).
            head_bytes (bytes): Unused by this classifier; present for compatibility with the classifier interface.
        
        Returns:
            `true` if the file sample contains at least two network configuration indicators, `false` otherwise.
        """
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
        """
        Classify a file as a network device configuration and extract device metadata.
        
        Extracts a text snippet from the file, detects the device type, and attempts to extract a hostname and device model. The returned details dictionary always contains "device_type" and includes "hostname" and "model" when found. Confidence is 0.9 when a hostname is present, otherwise 0.7.
        
        Parameters:
            path (Path): Filesystem path to the file to classify.
        
        Returns:
            ClassificationResult: Classification with `classification` set to "network_config", a numeric `confidence`, and a `details` dict containing "device_type" and optional "hostname" and "model".
        """
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
        """
        Identify the vendor/type of a network device from its configuration text.
        
        Returns:
            str: One of "cisco", "juniper", "arista", "hp", "dell", "mikrotik", or "generic" when no known vendor indicators are found. Matching is case-insensitive.
        """
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
        """
        Extract the hostname from a network device configuration text.
        
        Parameters:
            text (str): Configuration text to search for a hostname.
            device_type (str): Vendor or device type hint (e.g., "cisco", "juniper"); vendor-specific extraction is applied when recognized, otherwise generic patterns are used.
        
        Returns:
            hostname (Optional[str]): The extracted hostname, or None if no hostname is found.
        """
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
        """
        Extract the hostname from a Cisco IOS configuration text.
        
        @returns The hostname string if found, otherwise None.
        """
        # Pattern: hostname DEVICE-NAME
        match = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
        if match:
            return match.group(1)
        return None
    
    def _extract_juniper_hostname(self, text: str) -> Optional[str]:
        """
        Extracts the hostname from a Juniper configuration text.
        
        Returns:
            hostname (str): The configured hostname if a `set system host-name` line is present, `None` otherwise.
        """
        # Pattern: set system host-name device-name
        match = re.search(r"^set\s+system\s+host-name\s+(\S+)", text, re.MULTILINE)
        if match:
            return match.group(1)
        return None
    
    def _extract_model(self, text: str) -> Optional[str]:
        """
        Extract a device model identifier from configuration text.
        
        Searches the provided text for common vendor model markers (for example, Cisco product lines or explicit `model:`/`Product:` labels) and returns the first captured model token.
        
        Parameters:
            text (str): Configuration or comment text to search for a model identifier.
        
        Returns:
            str or None: The captured model identifier if found, `None` otherwise.
        """
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
        """
        Determine whether the given path likely refers to a network-related document by checking the filename for network-specific keywords and verifying the file extension is a supported document format.
        
        Parameters:
            path (Path): The file path to evaluate.
            head_bytes (bytes): Unused in this classifier; present to conform to the classifier interface.
        
        Returns:
            bool: `True` if the filename contains a network-related keyword and the file extension is one of the supported document formats (e.g., .pdf, .xlsx, .docx, .csv), `False` otherwise.
        """
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
        """
        Classify a network-related document file and produce basic metadata.
        
        Parameters:
            path (Path): Path to the file being classified; the file's suffix is used as the reported document type.
        
        Returns:
            ClassificationResult: A result with classification "network_doc", confidence 0.8, and details containing
            "doc_type" set to the file's suffix in lowercase.
        """
        return ClassificationResult(
            classification="network_doc",
            confidence=0.8,
            details={
                "doc_type": path.suffix.lower(),
            },
        )