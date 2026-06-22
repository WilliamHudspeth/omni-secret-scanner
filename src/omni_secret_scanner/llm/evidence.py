# SPDX-License-Identifier: MIT
"""Stage 1: Evidence Collection.

Runs only cheap, fast signals — no LLM, no AST, no Semgrep, no Presidio.
Pure regex, entropy, and filename heuristics to gather raw evidence.

This is the high-volume, low-cost first pass that feeds the scorer.
"""

from __future__ import annotations

from .state_machine import Evidence, Finding, FindingState


def collect_evidence(raw_finding: dict) -> list[Evidence]:
    """Extract evidence signals from a raw scanner finding.

    Each signal gets a confidence score based on how strong the indicator is.
    The scorer (Stage 2) combines these into a risk score.
    """
    evidence: list[Evidence] = []

    ftype = raw_finding.get("type", "")
    match = raw_finding.get("match", "")
    filepath = raw_finding.get("file", "")
    source = raw_finding.get("_source", "")
    entropy_val = raw_finding.get("entropy")
    line = raw_finding.get("line", 0)

    # ------------------------------------------------------------------
    # Pattern match strength
    # ------------------------------------------------------------------
    if match:
        match_len = len(match)
        if match_len >= 40:
            evidence.append(Evidence("pattern_length", 0.85,
                                     f"Long match ({match_len} chars)"))
        elif match_len >= 20:
            evidence.append(Evidence("pattern_length", 0.60,
                                     f"Medium match ({match_len} chars)"))
        else:
            evidence.append(Evidence("pattern_length", 0.25,
                                     f"Short match ({match_len} chars)"))

    # Known strong patterns
    strong_prefixes = ("AKIA", "ghp_", "gho_", "sk-", "hf_", "pplx-",
                       "sk-ant-", "AIza", "nvapi-", "gsk_")
    if any(match.startswith(p) for p in strong_prefixes):
        evidence.append(Evidence("known_pattern", 0.95,
                                 f"Matches known secret format ({match[:12]}...)"))

    # ------------------------------------------------------------------
    # Entropy signal
    # ------------------------------------------------------------------
    if entropy_val is not None:
        if entropy_val >= 5.0:
            evidence.append(Evidence("entropy", 0.80,
                                     f"Very high entropy ({entropy_val:.1f})"))
        elif entropy_val >= 4.0:
            evidence.append(Evidence("entropy", 0.50,
                                     f"High entropy ({entropy_val:.1f})"))
        elif entropy_val >= 3.5:
            evidence.append(Evidence("entropy", 0.25,
                                     f"Moderate entropy ({entropy_val:.1f})"))

    # ------------------------------------------------------------------
    # File path heuristics
    # ------------------------------------------------------------------
    path_lower = filepath.lower()
    sensitive_paths = (".env", "config", "secret", "credential", "token",
                       "password", ".aws/", ".ssh/", "deploy")
    if any(p in path_lower for p in sensitive_paths):
        evidence.append(Evidence("sensitive_path", 0.70,
                                 f"File in sensitive location: {filepath}"))

    test_paths = ("test_", "_test.", "mock", "fixture", "example", "__pycache__")
    if any(p in path_lower for p in test_paths):
        evidence.append(Evidence("test_file", -0.60,
                                 f"Likely test/fixture file: {filepath}"))

    # ------------------------------------------------------------------
    # Finding source credibility
    # ------------------------------------------------------------------
    source_credibility = {
        "validated": 0.95,
        "semgrep": 0.80,
        "taint": 0.85,
        "tree/current_secrets": 0.50,
        "history/secrets": 0.60,
        "tree/nlp_pii": 0.40,
        "injection": 0.55,
    }
    cred = source_credibility.get(source, 0.30)
    evidence.append(Evidence("source_credibility", cred,
                             f"From {source} (credibility: {cred:.2f})"))

    # ------------------------------------------------------------------
    # Context heuristics (variable naming)
    # ------------------------------------------------------------------
    suspicious_names = ("password", "secret", "token", "key", "api_key",
                        "credential", "auth", "passwd")
    if any(name in ftype.lower() for name in suspicious_names):
        evidence.append(Evidence("suspicious_type", 0.60,
                                 f"Finding type suggests credential: {ftype}"))

    return evidence


def raw_to_finding(raw: dict, idx: int) -> Finding:
    """Convert a raw scanner finding dict into a Finding with evidence."""
    f = Finding(
        id=f"f{idx:06d}",
        file=raw.get("file") or raw.get("original_file", ""),
        line=raw.get("line") or raw.get("original_line", 0),
        match=raw.get("match") or raw.get("original_match", ""),
        finding_type=raw.get("type") or raw.get("original_type", "unknown"),
        state=FindingState.DISCOVER,
    )
    f.evidence = collect_evidence(raw)
    f.metadata["raw"] = raw
    return f
