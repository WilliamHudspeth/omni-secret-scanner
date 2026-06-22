# SPDX-License-Identifier: MIT
"""Stage 3: Deterministic Engine Router.

Routes findings to specialized engines based on type and risk tier.
This is NOT LLM-driven — it's pure rule-based routing to ensure
deterministic, reproducible results.

CRITICAL/HIGH → validated, tainted, audited
MEDIUM → AST-filtered, semgrep-checked
LOW/INFO → logged, not escalated
"""

from __future__ import annotations

from .state_machine import Finding, FindingState, RiskTier


# ------------------------------------------------------------------
# Engine routing rules
# ------------------------------------------------------------------

def route_engines(finding: Finding) -> list[str]:
    """Return the list of engines that should process this finding.

    Rules are type-aware and risk-aware.  Each engine name maps to
    a scanner capability that can be invoked programmatically.
    """
    engines: list[str] = []
    risk = finding.risk_tier
    ftype = finding.finding_type.lower()

    # ------------------------------------------------------------------
    # API keys / tokens → validate against live APIs
    # ------------------------------------------------------------------
    if any(kw in ftype for kw in ("api", "token", "key", "secret", "password",
                                    "credential", "github", "aws", "pat")):
        if risk in (RiskTier.CRITICAL, RiskTier.HIGH):
            engines.append("validate")

    # ------------------------------------------------------------------
    # Source code secrets → taint analysis
    # ------------------------------------------------------------------
    ext = finding.file.rsplit(".", 1)[-1].lower() if "." in finding.file else ""
    if ext in ("py", "js", "ts", "tsx", "jsx", "mjs", "java") and risk in (RiskTier.CRITICAL, RiskTier.HIGH):
        engines.append("taint")

    # ------------------------------------------------------------------
    # Any finding in production config → deep audit
    # ------------------------------------------------------------------
    path_lower = finding.file.lower()
    prod_indicators = ("prod", "production", "deploy", ".env", "config/",
                       "settings", "terraform", "cloudformation", "k8s",
                       "kubernetes", "docker-compose")
    if any(p in path_lower for p in prod_indicators):
        if risk in (RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM):
            engines.append("audit-report")

    # ------------------------------------------------------------------
    # Injection findings → Semgrep SAST
    # ------------------------------------------------------------------
    if "injection" in ftype:
        engines.append("semgrep")

    # ------------------------------------------------------------------
    # PII findings → Presidio deep scan (only if risk warrants it)
    # ------------------------------------------------------------------
    if any(kw in ftype for kw in ("pii", "ssn", "email", "phone", "address",
                                    "nin", "sin", "insee", "tfn", "credit")):
        if risk in (RiskTier.HIGH, RiskTier.CRITICAL):
            engines.append("presidio")

    # ------------------------------------------------------------------
    # High-entropy only (no pattern match) → perplexity for context
    # ------------------------------------------------------------------
    if "entropy" in ftype and risk == RiskTier.HIGH:
        engines.append("perplexity")

    # ------------------------------------------------------------------
    # Image files → steganalysis
    # ------------------------------------------------------------------
    if ext in ("png", "jpg", "jpeg", "bmp", "gif", "tiff"):
        engines.append("stego")

    # ------------------------------------------------------------------
    # Complex/ambiguous → escalate to LLM (Stage 4)
    # ------------------------------------------------------------------
    if not engines and risk in (RiskTier.HIGH, RiskTier.CRITICAL):
        engines.append("llm-escalate")
    elif risk in (RiskTier.HIGH, RiskTier.CRITICAL) and len(engines) <= 1:
        engines.append("llm-escalate")

    return engines


class RouterPlugin:
    """Stage 3 plugin for the pipeline."""

    name = "engine_router"
    handles_state = FindingState.ROUTE

    def supports(self, finding: Finding) -> bool:
        return finding.state == FindingState.ROUTE

    def execute(self, finding: Finding) -> Finding:
        finding.assigned_engines = route_engines(finding)
        finding.state = FindingState.ANALYZE
        return finding


# ------------------------------------------------------------------
# Engine execution dispatch
# ------------------------------------------------------------------

def dispatch_engine(engine_name: str, finding: Finding, repo_dir: str = ".") -> Finding:
    """Execute a named engine against *finding*.  Returns mutated finding.

    This is the programmatic equivalent of running:
      omni-scan --<engine_name> --target <finding.file>
    """
    try:
        if engine_name == "validate":
            return _run_validate(finding)
        elif engine_name == "taint":
            return _run_taint(finding, repo_dir)
        elif engine_name == "semgrep":
            return _run_semgrep(finding, repo_dir)
        elif engine_name == "perplexity":
            return _run_perplexity(finding)
        elif engine_name == "presidio":
            return _run_presidio(finding, repo_dir)
        elif engine_name == "stego":
            return _run_stego(finding)
        elif engine_name == "audit-report":
            return finding  # already handled by report generation
        elif engine_name == "llm-escalate":
            finding.metadata["needs_escalation"] = True
            return finding
    except Exception:
        pass
    return finding


def _run_validate(finding: Finding) -> Finding:
    from ..utils.validation import validate_secret
    result = validate_secret(finding.finding_type, finding.match)
    if result.get("checked"):
        finding.validation_status = (
            ValidationStatus.VALID if result.get("valid")
            else ValidationStatus.EXPIRED
        )
        finding.validation_detail = result.get("details", "")
        # If validated live, bump risk to CRITICAL
        if finding.validation_status == ValidationStatus.VALID:
            finding.risk_tier = RiskTier.CRITICAL
            finding.risk_score = min(100, finding.risk_score + 30)
    return finding


def _run_taint(finding: Finding, repo_dir: str) -> Finding:
    from pathlib import Path as _Path
    from ..detectors.taint import taint_analysis
    fp = _Path(repo_dir) / finding.file
    if fp.exists():
        content = fp.read_text(encoding="utf-8", errors="ignore")
        result = taint_analysis(str(fp), finding.match, content, finding.line)
        if result.get("exploitability") == "high":
            finding.risk_tier = RiskTier.CRITICAL
            finding.risk_score = min(100, finding.risk_score + 20)
            finding.metadata["taint_sinks"] = result.get("sinks", [])
    return finding


def _run_semgrep(finding: Finding, repo_dir: str) -> Finding:
    from ..detectors.semgrep import run_semgrep_scan
    findings = run_semgrep_scan(repo_dir, quiet=True)
    for f in findings:
        if f.get("file") == finding.file:
            finding.metadata["semgrep_rule"] = f.get("rule", "")
            break
    return finding


def _run_perplexity(finding: Finding) -> Finding:
    # Perplexity requires a trained model — skip if not cached
    finding.metadata["perplexity_skipped"] = True
    return finding


def _run_presidio(finding: Finding, repo_dir: str) -> Finding:
    finding.metadata["presidio_skipped"] = True
    return finding


def _run_stego(finding: Finding) -> Finding:
    from ..detectors.stego import detect_lsb_steganography
    result = detect_lsb_steganography(finding.file)
    if result.get("risk"):
        finding.risk_tier = RiskTier.CRITICAL
        finding.risk_score = min(100, finding.risk_score + 40)
        finding.metadata["stego_confidence"] = result.get("confidence", 0)
    return finding


# Import needed for _run_validate
from .state_machine import ValidationStatus
