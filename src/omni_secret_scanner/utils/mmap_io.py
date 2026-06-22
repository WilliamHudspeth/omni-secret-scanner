# SPDX-License-Identifier: MIT
"""Memory-mapped file I/O for large file scanning.

When --mmap is active, files larger than *threshold* bytes are mapped
into virtual memory instead of being read entirely into RAM.  This
reduces peak memory and can improve throughput by avoiding copies.

Activated via --mmap flag (or --mmap-threshold to set the size cutoff).
"""

from __future__ import annotations

import mmap
import os
from pathlib import Path
from typing import Optional

# Default threshold: files > 1 MB use mmap
DEFAULT_MMAP_THRESHOLD: int = 1_000_000  # 1 MB


def read_file_content(
    filepath: str | Path,
    use_mmap: bool = False,
    threshold: int = DEFAULT_MMAP_THRESHOLD,
) -> Optional[str]:
    """Read *filepath* content, using mmap for large files when enabled.

    Returns the file content as a string, or None on failure.
    Gracefully falls back to regular read on any mmap error.
    """
    fp = Path(filepath)

    # Always try regular read for small files or when mmap disabled
    if not use_mmap:
        try:
            return fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    # Check file size
    try:
        st_size = fp.stat().st_size
    except OSError:
        return None

    if st_size < threshold:
        try:
            return fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    # Use mmap for large files
    try:
        with open(fp, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                return mm.read().decode("utf-8", errors="ignore")
    except Exception:
        # Fallback to regular read
        try:
            return fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None


def get_mmap_threshold(args_threshold: Optional[int] = None) -> int:
    """Return the mmap threshold, falling back to default."""
    if args_threshold is not None and args_threshold > 0:
        return args_threshold
    return DEFAULT_MMAP_THRESHOLD
