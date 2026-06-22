# SPDX-License-Identifier: MIT
"""Stage 5-6: Verification + Correlation.

Verification: confirms findings against external sources
  (STS GetCallerIdentity, GitHub API, etc.).

Correlation: groups findings by asset rather than by file.
  "production-aws" has 4 findings, not "4 regexes matched".
"""

from __future__ import annotations

from collections import defaultdict

from .state_machine import Finding, FindingState, RiskTier, ValidationStatus


# ------------------------------------------------------------------
# Stage 5: Verification
# ------------------------------------------------------------------

def verify_finding(finding: Finding) -> Finding:
    """Verify a finding against external sources.

    Only validates CRITICAL/HIGH findings that haven't been verified yet.
    Lower-risk findings skip this step to save API calls.
    """
    if finding.validation_status != ValidationStatus.UNCHECKED:
        finding.state = FindingState.VERIFY
        return finding

    if finding.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
        # Attempt validation if the finding type is known
        from ..utils.validation import validate_secret
        result = validate_secret(finding.finding_type, finding.match, timeout=5)
        if result.get("checked"):
            finding.validation_status = (
                ValidationStatus.VALID if result.get("valid")
                else ValidationStatus.EXPIRED
            )
            finding.validation_detail = result.get("details", "")
            if finding.validation_status == ValidationStatus.VALID:
                finding.risk_tier = RiskTier.CRITICAL
                finding.risk_score = min(100, finding.risk_score + 30)

    finding.state = FindingState.VERIFY
    return finding


class VerifyPlugin:
    name = "verification"
    handles_state = FindingState.VERIFY

    def supports(self, finding: Finding) -> bool:
        return finding.state == FindingState.VERIFY

    def execute(self, finding: Finding) -> Finding:
        return verify_finding(finding)


# ------------------------------------------------------------------
# Stage 6: Correlation
# ------------------------------------------------------------------

# Asset grouping rules — maps file path patterns to asset IDs
_ASSET_RULES: list[tuple[str, str]] = [
    (r"\.aws[/\\]", "aws-config"),
    (r"terraform[/\\]", "terraform-iac"),
    (r"k8s[/\\]|kubernetes[/\\]", "kubernetes"),
    (r"docker[/\\]|Dockerfile", "docker"),
    (r"\.github[/\\]workflows[/\\]", "github-actions"),
    (r"\.github[/\\]", "github-config"),
    (r"deploy[/\\]|deployment[/\\]", "deployment"),
    (r"config[/\\]|settings[/\\]", "application-config"),
    (r"\.env", "environment-vars"),
    (r"src[/\\].*auth", "authentication"),
    (r"src[/\\].*api", "api-layer"),
    (r"src[/\\].*db|database", "database"),
    (r"tests?[/\\]", "test-code"),
    (r"scripts?[/\\]", "scripts"),
    (r"docs?[/\\]", "documentation"),
]


def _classify_asset(filepath: str) -> str:
    """Map a file path to an asset ID based on path patterns."""
    import re
    path_normalized = filepath.replace("\\", "/")
    for pattern, asset_id in _ASSET_RULES:
        if re.search(pattern, path_normalized, re.IGNORECASE):
            return asset_id
    return "uncategorized"


def correlate(findings: list[Finding]) -> dict[str, dict]:
    """Group findings by asset and compute per-asset risk.

    Returns dict of {asset_id: {risk, count, findings, summary}}.
    """
    assets: dict[str, dict] = defaultdict(lambda: {
        "findings": [],
        "risk_tier": RiskTier.INFO,
        "max_score": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
    })

    for f in findings:
        asset_id = _classify_asset(f.file)
        f.asset_id = asset_id
        assets[asset_id]["findings"].append(f.id)
        assets[asset_id]["max_score"] = max(assets[asset_id]["max_score"], f.risk_score)

        tier = f.risk_tier
        if tier == RiskTier.CRITICAL:
            assets[asset_id]["critical_count"] += 1
        elif tier == RiskTier.HIGH:
            assets[asset_id]["high_count"] += 1
        elif tier == RiskTier.MEDIUM:
            assets[asset_id]["medium_count"] += 1
        elif tier == RiskTier.LOW:
            assets[asset_id]["low_count"] += 1

    # Determine overall asset risk
    for asset_id, data in assets.items():
        if data["critical_count"] > 0 or data["max_score"] >= 80:
            data["risk_tier"] = RiskTier.CRITICAL
        elif data["high_count"] > 0 or data["max_score"] >= 60:
            data["risk_tier"] = RiskTier.HIGH
        elif data["medium_count"] > 0 or data["max_score"] >= 35:
            data["risk_tier"] = RiskTier.MEDIUM
        else:
            data["risk_tier"] = RiskTier.LOW

        data["total"] = len(data["findings"])
        data["summary"] = (
            f"{data['total']} findings: "
            f"{data['critical_count']}C/{data['high_count']}H/"
            f"{data['medium_count']}M/{data['low_count']}L"
        )

    return dict(assets)


class CorrelatePlugin:
    """Stage 6 plugin — runs at the batch level, not per-finding."""

    name = "correlation"
    handles_state = FindingState.CORRELATE

    def supports(self, finding: Finding) -> bool:
        return finding.state == FindingState.CORRELATE

    def execute(self, finding: Finding) -> Finding:
        finding.state = FindingState.REMEDIATE
        return finding


def correlate_batch(findings: list[Finding]) -> dict:
    """Run correlation across a batch of findings.  Returns asset summary."""
    return correlate(findings)
