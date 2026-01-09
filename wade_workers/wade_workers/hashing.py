"""
Unified content hashing with pluggable strategies.

Provides multiple hashing strategies optimized for different use cases:
- Full file hashing (forensics, integrity)
- Quick hashing (deduplication, staging)
- Streaming hashing (memory efficiency for large files)

Adding a new hash algorithm:
    class CustomHasher(HashStrategy):
        def hash(self, path: Path) -> dict:
            # Your implementation
            return {"custom_algo": "abc123..."}
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class HashResult:
    """Result of hashing a file.
    
    Attributes:
        path: File that was hashed
        hashes: Dictionary mapping algorithm name to hex digest
        file_size: Size in bytes
        sample_size: Bytes actually hashed (may be < file_size for quick hashing)
    """
    path: Path
    hashes: Dict[str, str]
    file_size: int
    sample_size: int
    
    def __getitem__(self, algo: str) -> str:
        """Allow dict-like access: result["sha256"]"""
        return self.hashes[algo]
    
    def __contains__(self, algo: str) -> bool:
        """Check if algorithm was computed: "md5" in result"""
        return algo in self.hashes


class HashStrategy(ABC):
    """Abstract base for hashing strategies.
    
    Subclass this to implement custom hashing logic.
    """
    
    @abstractmethod
    def hash(self, path: Path) -> HashResult:
        """Compute hash of file at path.
        
        Args:
            path: File to hash
        
        Returns:
            HashResult with computed hashes
        
        Raises:
            FileNotFoundError: If path doesn't exist
            PermissionError: If file is not readable
        """
        pass


class FullFileHasher(HashStrategy):
    """Compute cryptographic hashes of entire file.
    
    Use for: Forensics, integrity verification, malware analysis.
    Trade-off: Slow for large files, but authoritative.
    
    Example:
        hasher = FullFileHasher(algos=["md5", "sha1", "sha256"])
        result = hasher.hash(Path("suspicious.exe"))
        print(f"MD5: {result['md5']}")
    """
    
    SUPPORTED_ALGOS: ClassVar[Set[str]] = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
    DEFAULT_ALGOS: ClassVar[List[str]] = ["md5", "sha1", "sha256"]

    CHUNK_SIZE = 8192  # Read 8KB at a time
    
    def __init__(self, algos: Optional[List[str]] = None):
        """Initialize with list of algorithms to compute.
        
        Args:
            algos: List of algorithm names (default: md5, sha1, sha256)
        
        Raises:
            ValueError: If unsupported algorithm requested
        """
        self.algos = algos or self.DEFAULT_ALGOS
        
        # Validate algorithms
        unsupported = set(self.algos) - self.SUPPORTED_ALGOS
        if unsupported:
            raise ValueError(f"Unsupported algorithms: {unsupported}")
    
    def hash(self, path: Path) -> HashResult:
        """Hash entire file with all configured algorithms."""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        # Initialize hashers
        hashers = {algo: hashlib.new(algo) for algo in self.algos}
        
        # Read file in chunks and update all hashers
        file_size = 0
        with open(path, "rb") as f:
            while chunk := f.read(self.CHUNK_SIZE):
                file_size += len(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
        
        # Extract hex digests
        hashes = {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
        
        return HashResult(
            path=path,
            hashes=hashes,
            file_size=file_size,
            sample_size=file_size,
        )


class QuickHasher(HashStrategy):
    """Compute hash of file head + tail for fast deduplication.
    
    Use for: Staging, deduplication, quick similarity checks.
    Trade-off: Fast but not authoritative (can have collisions).
    
    Algorithm: SHA256(first N bytes + last N bytes)
    
    Example:
        hasher = QuickHasher(sample_bytes=4*1024*1024)  # 4MB head+tail
        result = hasher.hash(Path("image.E01"))
        sig = result["sha256"]  # Use as dedup key
    """
    
    def __init__(self, sample_bytes: int = 4 * 1024 * 1024, algo: str = "sha256"):
        """Initialize quick hasher.
        
        Args:
            sample_bytes: Bytes to read from head and tail (default: 4MB each)
            algo: Hash algorithm (default: sha256)
        """
        self.sample_bytes = sample_bytes
        self.algo = algo
    
    def hash(self, path: Path) -> HashResult:
        """Hash first and last N bytes of file."""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        file_size = path.stat().st_size
        
        hasher = hashlib.new(self.algo)
        bytes_hashed = 0
        
        with open(path, "rb") as f:
            # Hash head
            head = f.read(self.sample_bytes)
            hasher.update(head)
            bytes_hashed += len(head)
            
            # Hash tail if file is larger than sample_bytes
            if file_size > self.sample_bytes:
                f.seek(-min(self.sample_bytes, file_size - self.sample_bytes), 2)
                tail = f.read(self.sample_bytes)
                hasher.update(tail)
                bytes_hashed += len(tail)
        
        return HashResult(
            path=path,
            hashes={self.algo: hasher.hexdigest()},
            file_size=file_size,
            sample_size=bytes_hashed,
        )


class StreamingHasher(HashStrategy):
    """Memory-efficient streaming hasher for very large files.
    
    Use for: Files > 1GB where memory is constrained.
    Trade-off: Same speed as FullFileHasher but lower memory footprint.
    
    Example:
        hasher = StreamingHasher(algos=["sha256"], chunk_size=1024*1024)
        result = hasher.hash(Path("huge_disk.dd"))
    """
    
    def __init__(
        self,
        algos: Optional[List[str]] = None,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
    ):
        """Initialize streaming hasher.
        
        Args:
            algos: List of algorithms (default: sha256)
            chunk_size: Bytes per chunk (default: 1MB)
        """
        self.algos = algos or ["sha256"]
        self.chunk_size = chunk_size
    
    def hash(self, path: Path) -> HashResult:
        """Hash file in chunks without loading entire file."""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        hashers = {algo: hashlib.new(algo) for algo in self.algos}
        
        file_size = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                file_size += len(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
        
        hashes = {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
        
        return HashResult(
            path=path,
            hashes=hashes,
            file_size=file_size,
            sample_size=file_size,
        )


# Convenience functions for common use cases

def quick_hash(path: Path, sample_mb: int = 4) -> str:
    """Quick hash for deduplication (head+tail SHA256).
    
    Args:
        path: File to hash
        sample_mb: MB to sample from head and tail
    
    Returns:
        SHA256 hex digest string
    """
    hasher = QuickHasher(sample_bytes=sample_mb * 1024 * 1024)
    result = hasher.hash(path)
    return result["sha256"]


def forensic_hash(path: Path) -> Dict[str, str]:
    """Full MD5+SHA1+SHA256 for forensic analysis.
    
    Args:
        path: File to hash
    
    Returns:
        Dict mapping algo name to hex digest
    """
    hasher = FullFileHasher(algos=["md5", "sha1", "sha256"])
    result = hasher.hash(path)
    return result.hashes
