# SPDX-License-Identifier: MIT
"""Multi-process parallel file scanning.

Replaces ThreadPoolExecutor with ProcessPoolExecutor for CPU-bound
regex/entropy work.  Each worker process scans a chunk of files and
returns only findings — no shared state to avoid pickle issues.

Activated via --parallel flag.  Falls back to threaded scan when
only 1 file to scan or when multiprocessing is unavailable.

Note: the worker function must be importable (top-level, no closures)
so it can be pickled by ProcessPoolExecutor on all platforms.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys

from .file_tree import _scan_single_file


def _worker_scan_chunk(chunk: list[tuple]) -> dict:
    """Scan a chunk of file jobs — runs in a separate process.

    Each element of *chunk* is the same job tuple that _scan_single_file
    expects.  Returns merged findings dict.
    """
    local: dict = {
        "suspicious_files": [],
        "current_secrets": [],
        "nlp_pii": [],
        "injections": [],
        "taint": [],
        "stego": [],
    }
    for job in chunk:
        try:
            res = _scan_single_file(job)
            for key in local:
                if key in res:
                    local[key].extend(res[key])
        except Exception:
            pass
    return local


def scan_current_tree_parallel(
    file_jobs: list[tuple],
    quiet: bool = False,
    max_workers: int | None = None,
    progress: bool = True,
) -> dict:
    """Scan *file_jobs* in parallel using ProcessPoolExecutor.

    *file_jobs* is a list of job tuples (as assembled by scan_current_tree).
    Each tuple is the same shape that _scan_single_file expects.

    Returns merged findings dict. Falls back to threaded scan on failure.
    """
    n_files = len(file_jobs)
    if n_files == 0:
        return {
            "suspicious_files": [],
            "current_secrets": [],
            "nlp_pii": [],
            "injections": [],
            "taint": [],
            "stego": [],
        }

    # Single file — no point parallelising
    if n_files == 1:
        return _worker_scan_chunk(file_jobs)

    n_workers = max_workers or min(8, os.cpu_count() or 4)
    chunk_size = max(1, n_files // n_workers)
    chunks = [file_jobs[i : i + chunk_size] for i in range(0, n_files, chunk_size)]

    if not quiet:
        print(
            f"Scanning {n_files} files across {len(chunks)} "
            f"process chunk(s) ({n_workers} workers)...",
            file=sys.stderr,
        )

    findings: dict = {
        "suspicious_files": [],
        "current_secrets": [],
        "nlp_pii": [],
        "injections": [],
        "taint": [],
        "stego": [],
    }

    from ..reporters.base import deduplicate_findings

    try:
        # Windows requires 'spawn' context; Linux/macOS work with fork
        ctx = concurrent.futures.ProcessPoolExecutor
        with ctx(max_workers=n_workers) as executor:
            futures = {executor.submit(_worker_scan_chunk, chunk): chunk for chunk in chunks}
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    chunk_res = future.result()
                    for key in findings:
                        if key in chunk_res:
                            findings[key].extend(chunk_res[key])
                    completed += 1
                    if progress and not quiet:
                        print(
                            f"  Chunk {completed}/{len(chunks)} done",
                            file=sys.stderr,
                        )
                except Exception as e:
                    if not quiet:
                        print(f"  Worker error: {e}", file=sys.stderr)

        # Deduplicate
        findings["current_secrets"] = deduplicate_findings(
            findings["current_secrets"], ("type", "file", "line", "match")
        )
        findings["injections"] = deduplicate_findings(
            findings["injections"], ("type", "file", "line", "match")
        )
        findings["nlp_pii"] = deduplicate_findings(findings["nlp_pii"], ("type", "file", "match"))
        return findings

    except Exception as e:
        if not quiet:
            print(f"ProcessPool failed ({e}), falling back to threaded scan...", file=sys.stderr)
        # Fallback: user gets results even if multiprocessing fails
        return _worker_scan_chunk(file_jobs)
