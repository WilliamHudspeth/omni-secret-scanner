# SPDX-License-Identifier: MIT
"""
End-to-end security analysis pipeline using the state machine.

Orchestrates:
  0. DISCOVER — profile repo, collect cheap evidence
  1. SCORE    — risk pre-scoring from evidence
  2. ROUTE    — assign engines based on type + risk
  3. ANALYZE  — run assigned engines
  4. VERIFY   — external validation
  5. CORRELATE — group by asset
  6. REMEDIATE — (future) auto-fix

Activated via --pipeline flag.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .state_machine import (
    Finding, FindingState, Pipeline, RiskTier, ValidationStatus,
)
from .profiler import profile_repository, engines_to_skip
from .evidence import raw_to_finding
from .scorer import ScorePlugin
from .router import RouterPlugin, dispatch_engine
from .correlation import VerifyPlugin, correlate_batch


@dataclass
class PipelineConfig:
    """Configuration for the security analysis pipeline."""

    repo_dir: str = "."
    json_input: Optional[str] = None  # existing scan JSON, or None to run scan

    # Profiling
    profile: bool = True
    skip_engines: bool = True  # skip engines not needed per profile

    # Tiers
    max_findings: int = 500
    quiet: bool = False
    output_file: Optional[str] = None


def run_pipeline(config: PipelineConfig) -> dict:
    """Run the full security analysis pipeline.

    1. Profile repo (or load existing scan JSON)
    2. Convert raw findings → Finding objects with evidence
    3. Score each finding
    4. Route to engines
    5. Dispatch engines for CRITICAL/HIGH findings
    6. Verify against external sources
    7. Correlate into assets
    """
    t0 = time.time()
    result: dict = {}

    # ------------------------------------------------------------------
    # Stage 0: Repository profiling
    # ------------------------------------------------------------------
    if config.profile and not config.json_input:
        if not config.quiet:
            print("[Stage 0] Profiling repository...", file=sys.stderr)
        profile = profile_repository(config.repo_dir, quiet=config.quiet)
        result["profile"] = profile
        if config.skip_engines:
            skip = engines_to_skip(profile)
            if not config.quiet:
                print(f"  Languages: {dict(list(profile['languages'].items())[:5])}",
                      file=sys.stderr)
                print(f"  Frameworks: {profile['frameworks']}", file=sys.stderr)
                print(f"  Repo type: {profile['repo_type']}", file=sys.stderr)
                if skip:
                    print(f"  Skipping engines: {skip}", file=sys.stderr)
            result["engines_skipped"] = skip

    # ------------------------------------------------------------------
    # Stage 1: Evidence collection
    # ------------------------------------------------------------------
    if not config.quiet:
        print("[Stage 1] Collecting evidence...", file=sys.stderr)

    if config.json_input and Path(config.json_input).exists():
        scan_data = json.loads(Path(config.json_input).read_text(encoding="utf-8"))
    else:
        scan_data = _run_fast_scan(config)

    from .middleware import extract_all_findings
    raw_findings = extract_all_findings(scan_data)
    if not config.quiet:
        print(f"  Raw findings: {len(raw_findings)}", file=sys.stderr)

    findings = [raw_to_finding(r, i) for i, r in enumerate(raw_findings[:config.max_findings])]
    if not config.quiet:
        print(f"  Converted to evidence: {len(findings)}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Stage 2: Risk pre-scoring
    # ------------------------------------------------------------------
    if not config.quiet:
        print("[Stage 2] Pre-scoring risks...", file=sys.stderr)

    scorer = ScorePlugin()
    for f in findings:
        scorer.execute(f)

    by_tier: dict[str, int] = {}
    for f in findings:
        t = f.risk_tier.value
        by_tier[t] = by_tier.get(t, 0) + 1
    if not config.quiet:
        print(f"  Risk distribution: {by_tier}", file=sys.stderr)
    result["risk_distribution"] = by_tier

    # ------------------------------------------------------------------
    # Stage 3: Engine routing
    # ------------------------------------------------------------------
    if not config.quiet:
        print("[Stage 3] Routing to engines...", file=sys.stderr)

    router = RouterPlugin()
    routed_count = 0
    for f in findings:
        router.execute(f)
        if f.assigned_engines:
            routed_count += 1
    if not config.quiet:
        print(f"  Routed to engines: {routed_count} findings", file=sys.stderr)

    # ------------------------------------------------------------------
    # Stage 4: Deep analysis (engine dispatch)
    # ------------------------------------------------------------------
    if not config.quiet:
        print("[Stage 4] Running deep analysis...", file=sys.stderr)

    analyzed = 0
    escalated = 0
    for f in findings:
        if f.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
            for engine in f.assigned_engines:
                dispatch_engine(engine, f, config.repo_dir)
            analyzed += 1
            f.state = FindingState.ANALYZE
            if f.metadata.get("needs_escalation"):
                escalated += 1
        else:
            f.state = FindingState.ANALYZE  # skip for MEDIUM/LOW/INFO

    if not config.quiet:
        print(f"  Deep analysis: {analyzed} findings", file=sys.stderr)
        print(f"  Escalated to LLM: {escalated} findings", file=sys.stderr)
    result["deep_analysis_count"] = analyzed
    result["escalated_count"] = escalated

    # ------------------------------------------------------------------
    # Stage 5: Verification
    # ------------------------------------------------------------------
    if not config.quiet:
        print("[Stage 5] Verifying findings...", file=sys.stderr)

    verifier = VerifyPlugin()
    verified = 0
    validated = 0
    for f in findings:
        if f.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
            verifier.execute(f)
            verified += 1
            if f.validation_status == ValidationStatus.VALID:
                validated += 1

    if not config.quiet:
        print(f"  Verified: {verified} | Confirmed live: {validated}", file=sys.stderr)
    result["verified_count"] = verified
    result["validated_live"] = validated

    # ------------------------------------------------------------------
    # Stage 6: Correlation
    # ------------------------------------------------------------------
    if not config.quiet:
        print("[Stage 6] Correlating into assets...", file=sys.stderr)

    assets = correlate_batch(findings)
    if not config.quiet:
        for asset_id, data in sorted(assets.items(), key=lambda x: -x[1]["max_score"])[:10]:
            if data["total"] > 0:
                print(f"  [{data['risk_tier'].value.upper():8s}] {asset_id}: {data['summary']}",
                      file=sys.stderr)
    result["assets"] = {
        asset_id: {
            "risk": data["risk_tier"].value,
            "total": data["total"],
            "summary": data["summary"],
        }
        for asset_id, data in assets.items()
        if data["total"] > 0
    }

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    elapsed = round(time.time() - t0, 1)
    result["elapsed_seconds"] = elapsed
    result["total_findings"] = len(findings)

    if not config.quiet:
        print(f"\nPipeline complete ({elapsed}s)", file=sys.stderr)
        print(f"  Findings: {len(findings)}", file=sys.stderr)
        print(f"  Assets: {len(result['assets'])}", file=sys.stderr)
        if escalated:
            print(f"  Escalated (needs human): {escalated}", file=sys.stderr)

    # Write output
    if config.output_file:
        # Convert findings to serializable form
        serializable = {
            **result,
            "findings": [
                {
                    "id": f.id, "file": f.file, "line": f.line,
                    "type": f.finding_type, "risk_score": f.risk_score,
                    "risk_tier": f.risk_tier.value, "state": f.state.value,
                    "validation": f.validation_status.value,
                    "asset_id": f.asset_id,
                    "assigned_engines": f.assigned_engines,
                }
                for f in findings
            ],
        }
        Path(config.output_file).write_text(
            json.dumps(serializable, indent=2, default=str), encoding="utf-8"
        )
        if not config.quiet:
            print(f"Pipeline report: {config.output_file}", file=sys.stderr)

    return result


def _run_fast_scan(config: PipelineConfig) -> dict:
    """Run a fast, cheap scan for evidence collection."""
    import io
    from ..cli import main as cli_main

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    buf = io.StringIO()

    try:
        sys.stdout = buf
        sys.stderr = io.StringIO() if config.quiet else sys.stderr
        cli_main(argv=[
            "--format", "json", "--fast", "--quiet",
            "--repo-dir", config.repo_dir,
        ])
    except SystemExit:
        pass
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    try:
        return json.loads(buf.getvalue())
    except json.JSONDecodeError:
        return {"findings": {}}
