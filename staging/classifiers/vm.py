"""
VM image classifier.

Detects virtual machine disk formats (QCOW, VHDX, VMDK, VDI, OVA).
"""
import tarfile
from pathlib import Path
from typing import Optional
from .base import ClassificationResult, Classifier
from ..config import MAGIC_DB


class VMClassifier:
    """Classifier for VM disk images."""
    
    priority = 25  # Between memory and disk
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """Check for VM format magic bytes."""
        for vm_type in ["qcow", "vhdx", "vmdk", "vdi"]:
            for offset, magic in MAGIC_DB.get(vm_type, []):
                if len(head_bytes) >= offset + len(magic):
                    if head_bytes[offset:offset+len(magic)] == magic:
                        return True
        
        # Check file extensions
        suffix_lower = path.suffix.lower()
        if suffix_lower in (".qcow", ".qcow2", ".vhdx", ".vhd", ".vmdk", ".vdi", ".ova", ".ovf"):
            return True
        
        return False
    
    def classify(self, path: Path) -> ClassificationResult:
        """Classify VM image and extract metadata."""
        suffix_lower = path.suffix.lower()
        
        # Detect format
        if suffix_lower in (".qcow", ".qcow2"):
            return self._classify_qcow(path)
        elif suffix_lower in (".vhdx", ".vhd"):
            return self._classify_vhdx(path)
        elif suffix_lower == ".vmdk":
            return self._classify_vmdk(path)
        elif suffix_lower == ".vdi":
            return self._classify_vdi(path)
        elif suffix_lower == ".ova":
            return self._classify_ova(path)
        elif suffix_lower == ".ovf":
            return self._classify_ovf(path)
        
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.6,
            details={"format": "unknown"},
        )
    
    def _classify_qcow(self, path: Path) -> ClassificationResult:
        """Classify QCOW2 image."""
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details={"format": "qcow2", "hypervisor": "qemu/kvm"},
        )
    
    def _classify_vhdx(self, path: Path) -> ClassificationResult:
        """Classify VHDX/VHD image."""
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details={"format": "vhdx", "hypervisor": "hyper-v"},
        )
    
    def _classify_vmdk(self, path: Path) -> ClassificationResult:
        """Classify VMDK image."""
        # Try to read descriptor (text-based VMDK)
        hostname = None
        try:
            text = path.read_text(errors="ignore")[:4096]
            if "vmware" in text.lower():
                # Parse displayName if present
                import re
                match = re.search(r'displayName\s*=\s*"([^"]+)"', text)
                if match:
                    hostname = match.group(1)
        except (OSError, UnicodeDecodeError):
            pass  # Binary VMDK or inaccessible file
        
        details = {"format": "vmdk", "hypervisor": "vmware"}
        if hostname:
            details["hostname"] = hostname
        
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details=details,
        )
    
    def _classify_vdi(self, path: Path) -> ClassificationResult:
        """Classify VirtualBox VDI image."""
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details={"format": "vdi", "hypervisor": "virtualbox"},
        )
    
    def _classify_ova(self, path: Path) -> ClassificationResult:
        """Classify OVA (VM package)."""
        # OVA is a tarball; try to peek inside
        hostname = None
        try:
            with tarfile.open(path, "r") as tar:
                members = tar.getnames()
                # Look for .ovf file
                ovf_files = [m for m in members if m.endswith(".ovf")]
                if ovf_files:
                    ovf_content = tar.extractfile(ovf_files[0]).read()
                    hostname = self._parse_ovf_hostname(ovf_content)
        except Exception:
            pass
        
        details = {"format": "ova", "package_type": "ovf"}
        if hostname:
            details["hostname"] = hostname
        
        return ClassificationResult(
            classification="vm_package",
            confidence=0.95,
            details=details,
        )
    
    def _classify_ovf(self, path: Path) -> ClassificationResult:
        """Classify OVF descriptor."""
        hostname = None
        try:
            content = path.read_bytes()
            hostname = self._parse_ovf_hostname(content)
        except Exception:
            pass
        
        details = {"format": "ovf"}
        if hostname:
            details["hostname"] = hostname
        
        return ClassificationResult(
            classification="vm_package",
            confidence=0.95,
            details=details,
        )
    
    def _parse_ovf_hostname(self, ovf_content: bytes) -> Optional[str]:
        """Extract hostname from OVF XML."""
        import re
        text = ovf_content.decode("utf-8", errors="ignore")
        
        # Look for <Name> tag
        match = re.search(r"<Name>([^<]+)</Name>", text)
        if match:
            return match.group(1)
        
        return None
