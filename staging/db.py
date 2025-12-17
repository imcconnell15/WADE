"""
SQLite-based deduplication database for staging daemon.

Tracks processed files by path signature and content hash to avoid
re-processing files that haven't changed.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import DB_PATH


def init_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Initialize staging database.
    
    Creates processed files table with deduplication tracking.
    
    Args:
        db_path: Path to SQLite database
    
    Returns:
        Database connection
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.Connection(str(db_path))
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed (
            sig TEXT PRIMARY KEY,
            src_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            dest_path TEXT NOT NULL,
            classification TEXT,
            profile TEXT,
            content_sig TEXT
        )
    """)
    
    # Index on content signature for content-based dedup
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_content_sig
        ON processed(content_sig)
        WHERE content_sig IS NOT NULL
    """)
    
    conn.commit()
    return conn


def path_signature(p: Path) -> str:
    """Generate signature from path + size + mtime.
    
    Args:
        p: File path
    
    Returns:
        Signature string
        
    Raises:
        OSError: If file is inaccessible
    """
    stat = p.stat()
    return f"{p.resolve()}:{stat.st_size}:{stat.st_mtime_ns}"


def already_processed(conn: sqlite3.Connection, sig: str) -> bool:
    """Check if file signature was already processed.
    
    Args:
        conn: Database connection
        sig: Path signature
    
    Returns:
        True if already processed
    """
    cursor = conn.execute(
        "SELECT 1 FROM processed WHERE sig = ?",
        (sig,)
    )
    return cursor.fetchone() is not None


def already_processed_by_content(
    conn: sqlite3.Connection,
    content_sig: Optional[str],
) -> bool:
    """Check if file content was already processed.
    
    Uses content hash (e.g., SHA256 of head+tail) for deduplication
    of renamed/moved files.
    
    Args:
        conn: Database connection
        content_sig: Content signature (hash)
    
    Returns:
        True if content already processed
    """
    if not content_sig:
        return False
    
    cursor = conn.execute(
        "SELECT 1 FROM processed WHERE content_sig = ?",
        (content_sig,)
    )
    return cursor.fetchone() is not None


def record_processed(
    conn: sqlite3.Connection,
    sig: str,
    src_path: Path,
    dest_path: Path,
    classification: str,
    profile: str,
    content_sig: Optional[str] = None,
) -> None:
    """Record processed file in database.
    
    Args:
        conn: Database connection
        sig: Path signature
        src_path: Source file path
        dest_path: Destination path
        classification: File classification
        profile: Staging profile (full/light)
        content_sig: Optional content hash
    """
    stat = src_path.stat()
    now = datetime.now(timezone.utc).isoformat()
    
    conn.execute("""
        INSERT INTO processed (
            sig, src_path, size, mtime_ns,
            first_seen, last_seen,
            dest_path, classification, profile, content_sig
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sig) DO UPDATE SET
            src_path = excluded.src_path,
            size = excluded.size,
            mtime_ns = excluded.mtime_ns,
            last_seen = excluded.last_seen,
            dest_path = excluded.dest_path,
            classification = excluded.classification,
            profile = excluded.profile,
            content_sig = excluded.content_sig
    """, (
        sig,
        str(src_path),
        stat.st_size,
        stat.st_mtime_ns,
        now,
        now,
        str(dest_path),
        classification,
        profile,
        content_sig,
    ))
    conn.commit()
