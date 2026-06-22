# SPDX-License-Identifier: MIT
"""Continuous file monitoring via watchdog (--watch).

Watches the repository for file changes and re-scans modified files
in real-time.  Prints compact one-line alerts for each finding.

Activated via --watch flag.  Requires `pip install watchdog`.
Gracefully degrades with install instructions if not available.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def run_watch_mode(
    repo_dir: str,
    scan_func,
    exclude_patterns: list[str],
    quiet: bool = False,
):
    """Start continuous monitoring of *repo_dir*.

    *scan_func* is a callable that takes a file path and returns a
    findings dict.  It receives ``(filepath: str) -> dict``.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print(
            "Error: The 'watchdog' package is required for --watch mode.\n"
            "Install it with: pip install watchdog",
            file=sys.stderr,
        )
        sys.exit(1)

    if not quiet:
        print(f"Watching {repo_dir} for changes... (Ctrl-C to stop)", file=sys.stderr)

    class ScanHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.is_directory:
                return
            filepath = event.src_path

            # Skip .git directory
            if ".git" in filepath.replace("\\", "/").split("/"):
                return

            # Check exclusions
            rel = os.path.relpath(filepath, repo_dir).replace("\\", "/")
            for pat in exclude_patterns:
                from fnmatch import fnmatch
                if fnmatch(rel, pat):
                    return

            if not quiet:
                print(f"\n[WATCH] Modified: {rel}", file=sys.stderr)

            try:
                findings = scan_func(filepath)
            except Exception as e:
                if not quiet:
                    print(f"  Error scanning: {e}", file=sys.stderr)
                return

            # Report findings compactly
            for s in findings.get("current_secrets", []):
                print(f"  [!] {s['type']} on line {s.get('line', '?')}: "
                      f"{s.get('match', '')[:80]}", file=sys.stderr)
            for p in findings.get("nlp_pii", []):
                print(f"  [PII] {p.get('type', 'PII')}: {p.get('match', '')[:60]}",
                      file=sys.stderr)

    # Build exclude pattern for watchdog (skip .git)
    watch_excludes = [".git", "__pycache__", "*.pyc", ".omni-cache"]
    watch_excludes.extend(exclude_patterns)

    observer = Observer()
    handler = ScanHandler()
    observer.schedule(handler, str(repo_dir), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        if not quiet:
            print("\nWatch mode stopped.", file=sys.stderr)
    observer.join()
