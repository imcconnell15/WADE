"""
File I/O operations for staging daemon.

Utilities for safe file reading, stability checking, and writer detection.
"""
import os
import time
import subprocess
from pathlib import Path
from typing import Tuple, Optional

from .config import (
    HEAD_SCAN_BYTES,
    TEXT_SNIFF_BYTES,
    LSOF_CMD,
    VERIFY_NO_WRITERS,
    WAIT_STABLE_SEC,
)


def read_head(p: Path, max_bytes: int = HEAD_SCAN_BYTES) -> bytes:
    """Read head and tail of file for magic byte detection.
    
    For small files, reads entire content.
    For large files, reads first 256KB + last 256KB.
    
    Args:
        p: File path
        max_bytes: Maximum bytes to read (default: 512KB)
    
    Returns:
        Bytes from file head+tail
    """
    try:
        size = p.stat().st_size
    except OSError:
        return b""
    
    if size <= max_bytes:
        try:
            return p.read_bytes()
        except Exception:
            return b""
    
    # Read head + tail
    chunk = max_bytes // 2
    try:
        with p.open("rb") as f:
            head = f.read(chunk)
            f.seek(max(0, size - chunk))
            tail = f.read(chunk)
        return head + tail
    except Exception:
        return b""


def is_probably_text(p: Path, sample_bytes: int = TEXT_SNIFF_BYTES) -> Tuple[bool, str]:
    """Check if file is text and return sample.
    
    Args:
        p: File path
        sample_bytes: Bytes to sample (default: 4KB)
    
    Returns:
        Tuple of (is_text: bool, text_sample: str)
    """
    try:
        sample = p.read_bytes()[:sample_bytes]
    except Exception:
        return False, ""
    
    # Check for null bytes (binary indicator)
    if b"\x00" in sample:
        return False, ""
    
    # Try UTF-8 decode
    try:
        text = sample.decode("utf-8", errors="strict")
        # Check for reasonable text content (printable + whitespace)
        printable_ratio = sum(c.isprintable() or c.isspace() for c in text) / max(len(text), 1)
        if printable_ratio > 0.7:
            return True, text
    except UnicodeDecodeError:
        pass
    
    # Try Latin-1 fallback
    try:
        text = sample.decode("latin-1")
        return True, text
    except Exception:
        pass
    
    return False, ""


def extract_text_snippet(p: Path, max_bytes: int = 1024 * 1024) -> str:
    """Extract text snippet from file for OS detection.
    
    Reads up to max_bytes from file and attempts text decode.
    
    Args:
        p: File path
        max_bytes: Maximum bytes to read (default: 1MB)
    
    Returns:
        Decoded text (empty string on failure)
    """
    try:
        data = p.read_bytes()[:max_bytes]
    except Exception:
        return ""
    
    # Try UTF-8 first
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        pass
    
    # Fallback to latin-1
    try:
        return data.decode("latin-1", errors="ignore")
    except Exception:
        return ""


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence.
    
    Args:
        data: Byte sequence
    
    Returns:
        Entropy value (0.0 - 8.0)
    """
    if not data:
        return 0.0
    
    import math
    from collections import Counter
    
    counts = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


def no_open_writers(p: Path) -> bool:
    """Check if file has open writers using lsof.
    
    Args:
        p: File path
    
    Returns:
        True if no writers detected, False otherwise
    """
    if not VERIFY_NO_WRITERS:
        return True
    
    try:
        result = subprocess.run(
            [LSOF_CMD, "-t", "--", str(p)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # lsof returns 0 with PIDs if open; 1 if none
        if result.returncode == 0 and result.stdout.strip():
            return False
        return True
    except Exception:
        # lsof failed; assume safe
        return True


def wait_stable(p: Path, seconds: int = WAIT_STABLE_SEC) -> bool:
    """Wait for file size to stabilize.
    
    Polls file size every second until it remains constant
    for the specified duration.
    
    Args:
        p: File path
        seconds: Seconds to wait for stability
    
    Returns:
        True if stable, False if file disappeared
    """
    if not p.exists():
        return False
    
    try:
        last_size = p.stat().st_size
    except OSError:
        return False
    
    remaining = seconds
    while remaining > 0:
        time.sleep(1)
        
        if not p.exists():
            return False
        
        try:
            current_size = p.stat().st_size
        except OSError:
            return False
        
        if current_size == last_size:
            remaining -= 1
        else:
            # Size changed; reset timer
            last_size = current_size
            remaining = seconds
    
    return True


def ensure_dirs(*paths: Path) -> None:
    """Create directories if they don't exist.
    
    Args:
        *paths: Directory paths to create
    """
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def move_atomic(src: Path, dest: Path) -> None:
    """Move file atomically, falling back to copy+delete.
    
    Args:
        src: Source file
        dest: Destination file
    """
    import shutil
    
    try:
        # Try atomic rename (works within same filesystem)
        src.rename(dest)
    except OSError:
        # Cross-filesystem; copy then delete
        shutil.copy2(src, dest)
        src.unlink(missing_ok=True)
