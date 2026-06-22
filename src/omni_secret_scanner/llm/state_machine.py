# SPDX-License-Identifier: MIT
"""
Security Analysis State Machine — the control plane.

Every finding progresses through a deterministic state pipeline:
  DISCOVER → SCORE → ROUTE → ANALYZE → VERIFY → CORRELATE → REMEDIATE

This is NOT an LLM wrapper.  The LLM is one sensor among many.
The state machine is the moat — it decides what runs, when, and why.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ------------------------------------------------------------------
# Finding state enum
# ------------------------------------------------------------------

class FindingState(str, Enum):
    DISCOVER = "discover"       # raw evidence collected
    SCORE = "score"             # risk pre-scored
    ROUTE = "route"             # engines assigned
    ANALYZE = "analyze"         # deep analysis complete
    VERIFY = "verify"           # verification against external source
    CORRELATE = "correlate"     # grouped into assets
    REMEDIATE = "remediate"     # fix generated
    CLOSED = "closed"           # done / false positive
    ESCALATED = "escalated"     # needs human review


class ValidationStatus(str, Enum):
    UNCHECKED = "unchecked"
    VALID = "valid"             # confirmed live
    EXPIRED = "expired"         # confirmed dead
    INCONCLUSIVE = "inconclusive"  # couldn't verify


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ------------------------------------------------------------------
# Finding data class
# ------------------------------------------------------------------

@dataclass
class Evidence:
    """A single piece of evidence attached to a finding."""
    source: str           # "regex", "entropy", "filename", "git_history"
    confidence: float     # 0.0 - 1.0
    detail: str = ""


@dataclass
class Finding:
    """The core unit of analysis.  Carries state through the pipeline."""

    id: str
    file: str = ""
    line: int = 0
    match: str = ""
    finding_type: str = ""     # "AWS Access Key ID", "GitHub Token", etc.

    # Pipeline state
    state: FindingState = FindingState.DISCOVER
    risk_tier: RiskTier = RiskTier.INFO
    risk_score: int = 0        # 0-100

    # Evidence collected in Stage 1
    evidence: list[Evidence] = field(default_factory=list)

    # Routing decisions (Stage 3)
    assigned_engines: list[str] = field(default_factory=list)

    # Analysis results (Stage 4-5)
    validation_status: ValidationStatus = ValidationStatus.UNCHECKED
    validation_detail: str = ""

    # Correlation (Stage 6)
    asset_id: str = ""
    correlated_findings: list[str] = field(default_factory=list)

    # Remediation (Stage 7)
    remediation: str = ""
    remediation_pr_url: str = ""

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------
# Plugin interface
# ------------------------------------------------------------------

class StagePlugin:
    """Base class for pipeline stage plugins.

    Each plugin declares which state it handles and provides
    ``supports()`` / ``execute()`` methods.
    """

    name: str = "base"
    handles_state: FindingState = FindingState.DISCOVER

    def supports(self, finding: Finding) -> bool:
        """Return True if this plugin should process *finding*."""
        return True

    def execute(self, finding: Finding) -> Finding:
        """Process *finding*, advancing its state. Returns mutated finding."""
        return finding


# ------------------------------------------------------------------
# Pipeline orchestrator
# ------------------------------------------------------------------

class Pipeline:
    """The security analysis control plane.

    Runs findings through the state machine, calling registered
    plugins at each stage.  Plugins are called in registration order;
    the first plugin whose ``supports()`` returns True handles the
    finding for that stage.
    """

    def __init__(self):
        self._plugins: dict[FindingState, list[StagePlugin]] = {
            s: [] for s in FindingState
        }

    def register(self, plugin: StagePlugin):
        """Register a plugin for its declared state."""
        self._plugins[plugin.handles_state].append(plugin)

    def run(self, findings: list[Finding],
            stop_at: FindingState = FindingState.REMEDIATE) -> list[Finding]:
        """Run *findings* through the pipeline up to *stop_at*."""
        states = list(FindingState)
        stop_idx = states.index(stop_at)

        for state in states[:stop_idx + 1]:
            plugins = self._plugins.get(state, [])
            if not plugins:
                continue

            for finding in findings:
                if finding.state != state:
                    continue
                for plugin in plugins:
                    if plugin.supports(finding):
                        finding = plugin.execute(finding)

        return findings

    def active_plugins(self) -> dict[str, list[str]]:
        """Return summary of registered plugins per state."""
        return {
            state.value: [p.name for p in plugins]
            for state, plugins in self._plugins.items()
            if plugins
        }
