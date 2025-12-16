"""
VM image classifier.

Detects virtual machine disk formats (QCOW, VHDX, VMDK, VDI, OVA).
"""
import tarfile
from pathlib import Path

from .base import ClassificationResult, Classifier
from ..config import MAGIC_DB


class VMClassifier:
    """Classifier for VM disk images."""
    
    priority = 25  # Between memory and disk
    
    def can_classify(self, path: Path, head_bytes: bytes) -> bool:
        """
        Determine whether the given file is likely a VM disk image or VM package.
        
        Checks for known VM format magic bytes (qcow, vhdx, vmdk, vdi) using MAGIC_DB against the provided header bytes, and falls back to common VM-related file extensions (".qcow", ".qcow2", ".vhdx", ".vhd", ".vmdk", ".vdi", ".ova", ".ovf").
        
        Parameters:
            path (Path): Filesystem path of the file being inspected.
            head_bytes (bytes): Initial bytes from the file (header) used for magic-byte matching.
        
        Returns:
            `True` if the file appears to be a VM disk or VM package based on magic bytes or extension, `False` otherwise.
        """
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
        """
        Determine the VM image or package format and produce classification metadata.
        
        @returns: A ClassificationResult containing the classification ("vm_disk" or "vm_package"), a confidence score, and a details dictionary with at least a "format" key (e.g., "qcow2", "vmdk", "ova", "ovf") and optional keys such as "hypervisor", "package_type", or "hostname".
        """
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
        """
        Classify the given file as a QCOW2 virtual machine disk image.
        
        Returns:
            ClassificationResult: classification set to "vm_disk", confidence 0.95, and details containing {"format": "qcow2", "hypervisor": "qemu/kvm"}.
        """
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details={"format": "qcow2", "hypervisor": "qemu/kvm"},
        )
    
    def _classify_vhdx(self, path: Path) -> ClassificationResult:
        """
        Determine VHDX (or VHD) VM disk format and produce classification metadata.
        
        Returns:
            ClassificationResult: classification "vm_disk" with confidence 0.95 and details containing "format": "vhdx" and "hypervisor": "hyper-v".
        """
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details={"format": "vhdx", "hypervisor": "hyper-v"},
        )
    
    def _classify_vmdk(self, path: Path) -> ClassificationResult:
        """
        Classify a VMDK disk image and produce metadata including hypervisor and an optional hostname.
        
        Returns:
            ClassificationResult: classification "vm_disk" with confidence 0.95. The returned `details` dict contains `"format": "vmdk"`, `"hypervisor": "vmware"`, and includes `"hostname"` when a hostname can be extracted from the VMDK descriptor.
        """
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
        except Exception:
            pass
        
        details = {"format": "vmdk", "hypervisor": "vmware"}
        if hostname:
            details["hostname"] = hostname
        
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details=details,
        )
    
    def _classify_vdi(self, path: Path) -> ClassificationResult:
        """
        Classifies a VirtualBox VDI disk image and returns its classification metadata.
        
        Returns:
            ClassificationResult: classification "vm_disk", confidence 0.95, and details containing format "vdi" and hypervisor "virtualbox".
        """
        return ClassificationResult(
            classification="vm_disk",
            confidence=0.95,
            details={"format": "vdi", "hypervisor": "virtualbox"},
        )
    
    def _classify_ova(self, path: Path) -> ClassificationResult:
        """
        Classify an OVA archive and extract package metadata.
        
        Attempts to open the OVA as a tar archive, locate an OVF descriptor, and extract a hostname when present. The returned ClassificationResult has classification "vm_package", confidence 0.95, and a details dict containing "format": "ova", "package_type": "ovf", and "hostname" when one is found.
        
        Returns:
            ClassificationResult: Classification with details including format, package_type, and optional hostname.
        """
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
        """
        Classifies an OVF descriptor file and extracts its hostname if present.
        
        Parameters:
            path (Path): Path to the OVF descriptor file to inspect.
        
        Returns:
            ClassificationResult: A classification for a VM package with confidence 0.95.
            The `details` dictionary contains `"format": "ovf"` and includes `"hostname"` when one is found in the OVF content.
        """
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
    
    def _parse_ovf_hostname(self, ovf_content: bytes) -> str:
        """
        Extract the virtual machine name from OVF XML content.
        
        Returns:
            hostname (str or None): The text content of the first `<Name>` element found in the OVF XML, or `None` if no such element is present.
        """
        import re
        text = ovf_content.decode("utf-8", errors="ignore")
        
        # Look for <Name> tag
        match = re.search(r"<Name>([^<]+)</Name>", text)
        if match:
            return match.group(1)
        
        return None