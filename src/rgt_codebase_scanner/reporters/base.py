# SPDX-License-Identifier: MIT
"""Shared reporter utilities: deduplication, flattening, and scoring."""

from typing import Any


def deduplicate_findings(items: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Remove duplicate findings using *key_fields* as the composite key."""
    seen: set[tuple[str, ...]] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        key = tuple(str(item.get(f, "")) for f in key_fields)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def injection_risk_score(hits: list[dict[str, Any]]) -> int:
    """Compute a 0–100 injection risk index from a list of injection findings."""
    weights = {
        "IGNORE_PREVIOUS": 10,
        "NEW_INSTRUCTIONS": 10,
        "SYSTEM_OVERRIDE": 9,
        "DELIMITER_ATTACK": 9,
        "ROLE_SWITCH": 8,
        "PROMPT_LEAK_REQUEST": 7,
        "ESCAPE_CONTEXT": 9,
        "REPEAT_AFTER_ME": 6,
        "INDIRECT_INJECTION": 8,
    }
    score = sum(weights.get(hit["type"].split(":")[-1], 5) for hit in hits)
    return min(score, 100)


def flatten_findings(
    history_findings: dict[str, Any],
    tree_findings: dict[str, Any],
    ps_findings: list[dict[str, Any]],
    semgrep_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Normalise all finding sources into a single flat list for TUI display."""
    flat: list[dict[str, Any]] = []

    for s in history_findings.get("secrets", []):
        flat.append(
            {
                "category": "History Secret",
                "file": s.get("file", "unknown"),
                "line": s.get("line", "?"),
                "type": s.get("type", "Secret"),
                "match": s.get("match", ""),
                "raw": s,
            }
        )
    for p in history_findings.get("pii", []):
        flat.append(
            {
                "category": "History PII",
                "file": p.get("file", "unknown"),
                "line": p.get("line", "?"),
                "type": p.get("type", "PII"),
                "match": p.get("match", ""),
                "raw": p,
            }
        )
    for e in history_findings.get("entropy", []):
        flat.append(
            {
                "category": "History Entropy",
                "file": e.get("file", "unknown"),
                "line": e.get("line", "?"),
                "type": "High Entropy",
                "match": e.get("token", ""),
                "entropy": e.get("entropy"),
                "raw": e,
            }
        )
    for s in tree_findings.get("current_secrets", []):
        flat.append(
            {
                "category": "Tree Secret",
                "file": s.get("file", "unknown"),
                "line": s.get("line", "?"),
                "type": s.get("type", "Secret"),
                "match": s.get("match", ""),
                "raw": s,
            }
        )
    for n in tree_findings.get("nlp_pii", []):
        flat.append(
            {
                "category": "NLP PII",
                "file": n.get("file", "unknown"),
                "line": "?",
                "type": n.get("type", "PII"),
                "match": n.get("match", ""),
                "raw": n,
            }
        )
    for p in ps_findings:
        flat.append(
            {
                "category": "PS Crosscheck",
                "file": p.get("File", "unknown"),
                "line": "?",
                "type": p.get("Type", "Crosscheck"),
                "match": p.get("Match", ""),
                "raw": p,
            }
        )
    if semgrep_findings:
        for s in semgrep_findings:
            flat.append(
                {
                    "category": "Semgrep SAST",
                    "file": s.get("file", "unknown"),
                    "line": s.get("line", "?"),
                    "type": f"SAST ({s.get('rule', 'Semgrep Rule')})",
                    "match": s.get("match", s.get("message", "")),
                    "raw": s,
                }
            )
    return flat


def calculate_safety_score(
    history_findings: dict[str, Any],
    tree_findings: dict[str, Any],
    ps_findings: list[dict[str, Any]],
    semgrep_findings: list[dict[str, Any]] | None = None,
) -> int:
    """Return a 0–100 safety score (100 = clean, 0 = severely compromised)."""
    if semgrep_findings is None:
        semgrep_findings = []
    score = 100
    score -= (
        len(history_findings.get("secrets", [])) + len(tree_findings.get("current_secrets", []))
    ) * 40
    score -= (
        len(history_findings.get("pii", []))
        + len(tree_findings.get("nlp_pii", []))
        + len(ps_findings)
    ) * 20
    score -= len(history_findings.get("entropy", [])) * 10
    score -= len(semgrep_findings) * 10
    return max(0, min(100, score))
