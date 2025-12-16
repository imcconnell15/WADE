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
        """
        Retrieve the hex digest for the given algorithm name.
        
        Parameters:
            algo (str): Name of the hash algorithm (e.g., "sha256").
        
        Returns:
            str: Hexadecimal digest for `algo`.
        
        Raises:
            KeyError: If `algo` is not present in the stored hashes.
        """
        return self.hashes[algo]
    
    def __contains__(self, algo: str) -> bool:
        """
        Determine whether a digest for the given algorithm exists in the result.
        
        Parameters:
            algo (str): Name of the hash algorithm to check (e.g., "sha256", "md5").
        
        Returns:
            bool: `True` if a digest for `algo` is present, `False` otherwise.
        """
        return algo in self.hashes


class HashStrategy(ABC):
    """Abstract base for hashing strategies.
    
    Subclass this to implement custom hashing logic.
    """
    
    @abstractmethod
    def hash(self, path: Path) -> HashResult:
        """
        Compute configured hash(es) for the file at the given path.
        
        Parameters:
            path (Path): Path to the file to hash.
        
        Returns:
            HashResult: Contains a mapping of algorithm names to hex digests, the file's total size in bytes, and the number of bytes actually sampled/processed.
        
        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read due to permission restrictions.
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
    
    SUPPORTED_ALGOS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
    DEFAULT_ALGOS = ["md5", "sha1", "sha256"]
    CHUNK_SIZE = 8192  # Read 8KB at a time
    
    def __init__(self, algos: Optional[List[str]] = None):
        """
        Create a FullFileHasher configured to compute the specified digest algorithms.
        
        Parameters:
            algos (Optional[List[str]]): Algorithm names to compute (e.g., "md5", "sha256"). If omitted, uses the default set.
        
        Raises:
            ValueError: If any algorithm in `algos` is not supported.
        """
        self.algos = algos or self.DEFAULT_ALGOS
        
        # Validate algorithms
        unsupported = set(self.algos) - self.SUPPORTED_ALGOS
        if unsupported:
            raise ValueError(f"Unsupported algorithms: {unsupported}")
    
    def hash(self, path: Path) -> HashResult:
        """
        Compute cryptographic digests of the entire file using the configured algorithms.
        
        Reads the file in fixed-size chunks and returns a HashResult containing per-algorithm hex digests,
        the total file_size in bytes, and sample_size equal to file_size.
        
        Returns:
            HashResult: Hashes mapping (algorithm -> hex digest), file_size, and sample_size.
        
        Raises:
            FileNotFoundError: If the given path does not exist.
        """
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
        """
        Initialize the QuickHasher with a sampling size and hash algorithm.
        
        Parameters:
            sample_bytes (int): Number of bytes to read from the file head and (if the file is larger) the tail when computing the quick hash; defaults to 4 MiB.
            algo (str): Name of the hash algorithm to use (e.g., "sha256"); defaults to "sha256".
        """
        self.sample_bytes = sample_bytes
        self.algo = algo
    
    def hash(self, path: Path) -> HashResult:
        """
        Compute a quick sample hash of a file by hashing its head and, if present, its tail using the configured algorithm.
        
        Returns:
            HashResult: Contains the file path, a mapping from algorithm name to hex digest, the total file size in bytes, and sample_size equal to the number of bytes actually hashed (head plus optional tail).
        
        Raises:
            FileNotFoundError: If the provided path does not exist.
        """
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
        """
        Configure the StreamingHasher with the hashing algorithms to compute and the read chunk size.
        
        Parameters:
            algos (Optional[List[str]]): Names of hash algorithms to compute (default: ["sha256"]).
            chunk_size (int): Number of bytes read per I/O chunk (default: 1_048_576).
        """
        self.algos = algos or ["sha256"]
        self.chunk_size = chunk_size
    
    def hash(self, path: Path) -> HashResult:
        """
        Compute cryptographic hashes of the entire file by reading it in fixed-size chunks.
        
        Parameters:
            path (Path): Path to the file to hash.
        
        Returns:
            HashResult: Contains the file path, a mapping of algorithm name to hex digest, the total file size in bytes, and sample_size equal to the number of bytes actually read.
        
        Raises:
            FileNotFoundError: If the given path does not exist.
        """
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
    """
    Compute a fast SHA-256 digest by hashing the file's head and tail samples for deduplication.
    
    Parameters:
        path (Path): Path to the file to hash.
        sample_mb (int): Number of megabytes to read from the head and from the tail (each); total bytes hashed is head + tail.
    
    Returns:
        str: Hexadecimal SHA-256 digest of the sampled data.
    """
    hasher = QuickHasher(sample_bytes=sample_mb * 1024 * 1024)
    result = hasher.hash(path)
    return result["sha256"]


def forensic_hash(path: Path) -> Dict[str, str]:
    """
    Compute MD5, SHA-1, and SHA-256 hashes of a file for forensic purposes.
    
    Parameters:
        path (Path): Path to the file to hash.
    
    Returns:
        Dict[str, str]: Mapping of algorithm name ('md5', 'sha1', 'sha256') to the corresponding hex digest.
    """
    hasher = FullFileHasher(algos=["md5", "sha1", "sha256"])
    result = hasher.hash(path)
    return result.hashes