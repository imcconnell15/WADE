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
    """
    Read initial and trailing bytes from a file to sample content for detection.
    
    If the file size cannot be obtained or a read error occurs, returns empty bytes. If the file size is less than or equal to max_bytes, returns the entire file. If the file is larger, returns the concatenation of the first max_bytes//2 bytes and the last max_bytes//2 bytes.
    
    Parameters:
        p (Path): Path to the file to sample.
        max_bytes (int): Maximum total bytes to return (default 512KB); when the file is larger, the returned bytes consist of a head and tail chunk of size max_bytes//2 each.
    
    Returns:
        bytes: Sampled bytes from the file, or empty bytes on error.
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
    """
    Determine whether a file is likely text and provide a decoded sample.
    
    Parameters:
        p (Path): Path to the file to inspect.
        sample_bytes (int): Maximum number of bytes to read from the file for analysis.
    
    Returns:
        (bool, str): `True` and a decoded text sample if the file is likely text; `False` and an empty string otherwise.
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
    """
    Extract a decoded text snippet from the start of a file for OS detection.
    
    Reads up to `max_bytes` from the file and returns a decoded string. Prefers UTF-8 decoding and falls back to Latin-1; returns an empty string on read or decode failure.
    
    Parameters:
        p (Path): Path of the file to read.
        max_bytes (int): Maximum number of bytes to read from the file (default: 1_048_576).
    
    Returns:
        str: Decoded text snippet, or an empty string on failure.
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
    """
    Compute the Shannon entropy of a byte sequence.
    
    Parameters:
        data (bytes): Bytes to analyze; if empty, the function returns 0.0.
    
    Returns:
        float: Shannon entropy in bits per byte, between 0.0 and 8.0.
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
    """
    Determine whether no processes have the file open for writing by probing lsof.
    
    Parameters:
        p (Path): Path to the file to check.
    
    Returns:
        bool: `True` if no writers are detected. Also returns `True` when verification is disabled or lsof fails; returns `False` if lsof reports one or more processes holding the file open.
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
    """
    Wait until the file's size remains unchanged for a continuous period.
    
    If the file does not exist or a stat error occurs, returns False. Any change in file size resets the stability timer; if the size stays identical for `seconds` consecutive seconds the function returns True.
    
    Parameters:
        p (Path): Path to the file to monitor.
        seconds (int): Number of consecutive seconds the size must remain unchanged.
    
    Returns:
        True if the file remained stable for the full duration, False if the file disappeared or a stat error occurred.
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
    """
    Create each provided directory path, including any missing parent directories.
    
    Parameters:
        *paths (Path): One or more directory paths to create. Existing directories are left unchanged.
    """
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def move_atomic(src: Path, dest: Path) -> None:
    """
    Move a file to a destination atomically when possible, falling back to copy-and-delete if an atomic rename is not available.
    
    If src and dest are on the same filesystem, an atomic rename is attempted. If that fails (for example, across filesystems), the file is copied with metadata preserved using shutil.copy2 and the source file is removed.
    
    Parameters:
        src (Path): Source file path.
        dest (Path): Destination file path.
    
    Raises:
        Exceptions from shutil.copy2 or Path.unlink may propagate if the fallback copy or delete fails.
    """
    import shutil
    
    try:
        # Try atomic rename (works within same filesystem)
        src.rename(dest)
    except OSError:
        # Cross-filesystem; copy then delete
        shutil.copy2(src, dest)
        src.unlink(missing_ok=True)