# SPDX-License-Identifier: MIT
"""JSON/JSON output parser and signal pruner.

Takes raw scanner JSON, groups findings by file, and strips
low-confidence / high-noise hits before they reach the LLM.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


# ------------------------------------------------------------------
# Noise thresholds: findings below these levels are pruned
# ------------------------------------------------------------------

# Entropy hits with score below this are stripped
ENTROPY_MIN_SCORE: float = 3.8

# PII types that generate too many false positives in code
_PII_NOISE_TYPES: set[str] = {"PRONOUN"}

# Secret types that are known FP-heavy and get demoted
_SECRET_NOISE_PREFIXES: tuple[str, ...] = (
    "Cloudflare API Key",  # matches separator lines
    "Pinecone",            # matches UUIDs
)

# Maximum findings per file before we start summarising
_MAX_FINDINGS_PER_FILE: int = 25


# ------------------------------------------------------------------
# Parse and group
# ------------------------------------------------------------------

def parse_json_output(json_path: str | Path) -> dict[str, Any]:
    """Load scanner JSON output from *json_path* or raw JSON string."""
    raw = Path(json_path).read_text(encoding="utf-8") if isinstance(json_path, (str, Path)) and Path(json_path).exists() else str(json_path)
    return json.loads(raw) if isinstance(raw, str) else raw


def extract_all_findings(scan_data: dict) -> list[dict]:
    """Flatten all finding types from scanner output into a single list."""
    findings: list[dict] = []
    f = scan_data.get("findings", {})

    # History findings
    history = f.get("history", {})
    for key in ("secrets", "pii", "entropy", "injections"):
        items = history.get(key, [])
        for item in items:
            item["_source"] = f"history/{key}"
            findings.append(item)

    # Current tree findings
    tree = f.get("current_tree", {})
    for key in ("current_secrets", "nlp_pii", "injections"):
        items = tree.get(key, [])
        for item in items:
            item["_source"] = f"tree/{key}"
            findings.append(item)

    # Injection attacks
    for item in f.get("injection_attacks", []):
        item["_source"] = "injection"
        findings.append(item)

    # Semgrep
    for item in f.get("semgrep_sast", []):
        item["_source"] = "semgrep"
        findings.append(item)

    # Validated secrets
    for item in f.get("validated_secrets", []):
        item["_source"] = "validated"
        findings.append(item)

    # Taint
    for item in tree.get("taint", []):
        item["_source"] = "taint"
        findings.append(item)

    # Stego
    for item in tree.get("stego", []):
        item["_source"] = "stego"
        findings.append(item)

    return findings


def group_by_file(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by their file path."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        filepath = f.get("file") or f.get("original_file") or "unknown"
        groups[filepath].append(f)
    return dict(groups)


# ------------------------------------------------------------------
# Signal pruning
# ------------------------------------------------------------------

def _is_noise(finding: dict) -> bool:
    """Return True if *finding* is low-signal and should be pruned."""
    ftype = finding.get("type", "")

    # Strip known FP-heavy types
    if ftype in _PII_NOISE_TYPES:
        return True
    if ftype.startswith(_SECRET_NOISE_PREFIXES):
        return True

    # Strip low-entropy hits
    score = finding.get("entropy") or finding.get("score")
    if score is not None and isinstance(score, (int, float)) and score < ENTROPY_MIN_SCORE:
        return True

    return False


def prune_findings(grouped: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Remove noise from grouped findings. Returns cleaned dict."""
    cleaned: dict[str, list[dict]] = {}
    for filepath, items in grouped.items():
        kept = [f for f in items if not _is_noise(f)]
        if kept:
            cleaned[filepath] = kept
    return cleaned


# ------------------------------------------------------------------
# Risk classification
# ------------------------------------------------------------------

def classify_risk(findings: list[dict]) -> str:
    """Classify the overall risk level for a set of findings.

    Returns 'critical', 'high', 'medium', or 'low'.
    """
    has_validated = any("validated" in f.get("_source", "") for f in findings)
    has_taint = any(f.get("_source") == "taint" for f in findings)
    has_injection = any(f.get("_source") in ("injection", "tree/injections") for f in findings)
    has_stego = any(f.get("_source") == "stego" for f in findings)
    has_semgrep = any(f.get("_source") == "semgrep" for f in findings)

    if has_validated or has_stego:
        return "critical"
    if has_taint or (has_injection and has_semgrep):
        return "high"
    if has_injection or has_semgrep:
        return "medium"
    return "low"


def get_file_context(filepath: str, repo_dir: str = ".", context_lines: int = 5) -> str:
    """Read *context_lines* around any finding in *filepath*."""
    full = Path(repo_dir) / filepath
    if not full.exists():
        return f"[File not found: {filepath}]"
    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
        if len(lines) <= context_lines * 2 + 3:
            return "\n".join(f"  {i+1}: {l}" for i, l in enumerate(lines))
        # Show first and last N lines
        head = [f"  {i+1}: {l}" for i, l in enumerate(lines[:context_lines])]
        tail = [f"  {i+1}: {l}" for i, l in enumerate(lines[-context_lines:])]
        return "\n".join(head + [f"  ... ({len(lines) - 2*context_lines} lines omitted) ..."] + tail)
    except Exception:
        return f"[Cannot read: {filepath}]"


# ------------------------------------------------------------------
# Summary statistics
# ------------------------------------------------------------------

def build_stats(grouped: dict[str, list[dict]], scan_data: dict) -> dict:
    """Build summary statistics from grouped findings."""
    total = sum(len(v) for v in grouped.values())
    by_risk: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    for items in grouped.values():
        risk = classify_risk(items)
        by_risk[risk] += 1
        for f in items:
            by_type[f.get("type", "unknown")] += 1

    summary = scan_data.get("summary", {})
    return {
        "total_findings": total,
        "files_affected": len(grouped),
        "by_risk": dict(by_risk),
        "top_types": sorted(by_type.items(), key=lambda x: -x[1])[:10],
        "safety_score": summary.get("safety_score", 0),
        "injection_risk": summary.get("injection_risk", 0),
        "validated_live": summary.get("valid_live", 0),
        "validated_expired": summary.get("invalid_live", 0),
    }
