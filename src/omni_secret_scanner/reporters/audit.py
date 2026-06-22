# SPDX-License-Identifier: MIT
"""Tamper-evident audit report generation (--audit-report).

Produces a JSON report with embedded SHA-256 hash for integrity
verification.  Includes git commit SHA, timestamp, and scan summary.

Activated via --audit-report OUTPUT.json flag.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__


def _get_git_commit(repo_dir: str) -> str:
    """Get the current HEAD SHA from the git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def generate_audit_report(
    repo_dir: str,
    findings_summary: dict,
    output_path: str,
) -> str:
    """Generate a tamper-evident JSON audit report and write to *output_path*.

    Returns the SHA-256 hash of the report content (before embedding).
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    git_commit = _get_git_commit(repo_dir)

    payload: dict = {
        "scanner": f"omni-secret-scanner v{__version__}",
        "timestamp": timestamp,
        "generated_at_epoch": time.time(),
        "repo": str(Path(repo_dir).resolve()),
        "git_commit": git_commit,
        "summary": _sanitize_summary(findings_summary),
    }

    # First pass: compute hash of payload
    payload_json = json.dumps(payload, sort_keys=True, indent=2)
    content_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    # Embed the hash
    payload["content_sha256"] = content_hash

    # Write final report
    final_json = json.dumps(payload, sort_keys=True, indent=2)
    Path(output_path).write_text(final_json, encoding="utf-8")

    return content_hash


def _sanitize_summary(summary: dict) -> dict:
    """Strip large/raw match data from summary for audit report compactness."""
    safe = {}
    for key in (
        "secrets_count",
        "pii_count",
        "entropy_count",
        "injection_count",
        "taint_count",
        "stego_count",
        "safety_score",
        "injection_risk",
    ):
        if key in summary:
            safe[key] = summary[key]
    # Counts from findings lists
    for list_key, count_key in (
        ("history_secrets", "history_secrets_count"),
        ("current_secrets", "current_secrets_count"),
        ("nlp_pii", "nlp_pii_count"),
        ("injections", "injections_count"),
        ("taint", "taint_count"),
        ("stego", "stego_count"),
        ("semgrep", "semgrep_count"),
        ("validated", "validated_count"),
    ):
        val = summary.get(list_key)
        if isinstance(val, list):
            safe[count_key] = len(val)
    # Top-level file count
    files = summary.get("files_scanned")
    if files is not None:
        safe["files_scanned"] = files
    return safe


def verify_audit_report(report_path: str) -> dict:
    """Verify the integrity of a previously generated audit report.

    Returns {"valid": bool, "stored_hash": str, "computed_hash": str}.
    """
    try:
        raw = Path(report_path).read_text(encoding="utf-8")
        data = json.loads(raw)
        stored_hash = data.pop("content_sha256", None)
        recomputed = json.dumps(data, sort_keys=True, indent=2)
        computed_hash = hashlib.sha256(recomputed.encode("utf-8")).hexdigest()
        return {
            "valid": stored_hash == computed_hash,
            "stored_hash": stored_hash or "",
            "computed_hash": computed_hash,
        }
    except Exception as e:
        return {"valid": False, "stored_hash": "", "computed_hash": "", "error": str(e)}
