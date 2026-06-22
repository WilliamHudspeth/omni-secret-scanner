# SPDX-License-Identifier: MIT
"""Disk-based file hash cache for incremental scans.

Stores SHA-256 hashes of scanned files in a SQLite database so that
unchanged files can be skipped on re-scan.  Dramatically reduces work
on large repos after the first full scan.

Activated via --cache flag.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path

DEFAULT_CACHE_DB = ".omni-cache/filecache.db"


def _get_cache_path(repo_dir: str) -> Path:
    cache_dir = Path(repo_dir) / ".omni-cache"
    cache_dir.mkdir(exist_ok=True)
    return cache_dir / "filecache.db"


def _init_db(db_path: str | Path) -> sqlite3.Connection:
    """Initialize the cache database, creating tables if needed."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS file_cache (
            path       TEXT PRIMARY KEY,
            hash       TEXT NOT NULL,
            scanned_at REAL NOT NULL
        )"""
    )
    conn.commit()
    return conn


def get_file_hash(filepath: str | Path, chunk_size: int = 65536) -> str:
    """Compute SHA-256 hash of *filepath*."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def file_needs_scan(
    filepath: str | Path,
    cursor: sqlite3.Cursor,
) -> bool:
    """Return True if *filepath* should be (re-)scanned.

    Checks the cache database: if the stored hash matches the current
    file hash, the file is unchanged and can be skipped.
    """
    path_str = str(Path(filepath).resolve())
    current_hash = get_file_hash(filepath)
    if not current_hash:
        return True  # can't hash → scan it

    cursor.execute("SELECT hash FROM file_cache WHERE path = ?", (path_str,))
    row = cursor.fetchone()
    if row and row[0] == current_hash:
        return False  # unchanged → skip

    # Update cache
    cursor.execute(
        "INSERT OR REPLACE INTO file_cache (path, hash, scanned_at) VALUES (?, ?, ?)",
        (path_str, current_hash, time.time()),
    )
    return True


class ScanCache:
    """Manages a persistent SQLite cache of scanned file hashes."""

    def __init__(self, repo_dir: str):
        self.repo_dir = repo_dir
        self.db_path = _get_cache_path(repo_dir)
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = _init_db(self.db_path)
        return self._conn

    def should_scan(self, filepath: str | Path) -> bool:
        return file_needs_scan(filepath, self.conn.cursor())

    def invalidate(self, filepath: str | Path):
        """Force a file to be rescanned next time."""
        path_str = str(Path(filepath).resolve())
        self.conn.execute("DELETE FROM file_cache WHERE path = ?", (path_str,))
        self.conn.commit()

    def clear(self):
        """Clear all cached entries."""
        self.conn.execute("DELETE FROM file_cache")
        self.conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def stats(self) -> dict:
        """Return cache stats: total entries, approximate size."""
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM file_cache")
        count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM file_cache WHERE scanned_at > ?", (time.time() - 86400,))
        recent = c.fetchone()[0]
        return {"total": count, "recent_24h": recent}
