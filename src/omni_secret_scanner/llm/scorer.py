# SPDX-License-Identifier: MIT
"""Stage 2: Risk Pre-Scoring.

Combines evidence signals into a 0-100 risk score.  This is pure rules —
no LLM, no ML, no external API calls.  Deterministic and fast.

The score determines the risk tier, which drives Stage 3 routing.
"""

from __future__ import annotations

from .state_machine import Finding, FindingState, RiskTier


def pre_score(finding: Finding) -> Finding:
    """Compute risk score from evidence and assign tier.

    Scoring rules (weighted additive, capped at 100):
      - Evidence confidence values are summed (negative evidence subtracts)
      - Base score starts at 10 (everything is slightly suspicious)
      - Strong known patterns get bonus
      - Test file penalty is applied last
    """
    score = 10  # base

    # Sum evidence signals
    for ev in finding.evidence:
        score += int(ev.confidence * 40)  # scale 0-1 conf to 0-40 points

    # Bonus for validated live secrets
    if finding.validation_status.value == "valid":
        score += 50

    # Test file penalty
    has_test_penalty = any(
        ev.source == "test_file" for ev in finding.evidence
    )
    if has_test_penalty:
        score = max(0, score - 30)

    # Clamp
    finding.risk_score = max(0, min(100, score))

    # Map to tier
    if finding.risk_score >= 80:
        finding.risk_tier = RiskTier.CRITICAL
    elif finding.risk_score >= 60:
        finding.risk_tier = RiskTier.HIGH
    elif finding.risk_score >= 35:
        finding.risk_tier = RiskTier.MEDIUM
    elif finding.risk_score >= 15:
        finding.risk_tier = RiskTier.LOW
    else:
        finding.risk_tier = RiskTier.INFO

    finding.state = FindingState.SCORE
    return finding


class ScorePlugin:
    """Stage 2 plugin for the pipeline."""

    name = "risk_scorer"
    handles_state = FindingState.SCORE

    def supports(self, finding: Finding) -> bool:
        return finding.state == FindingState.SCORE

    def execute(self, finding: Finding) -> Finding:
        return pre_score(finding)
