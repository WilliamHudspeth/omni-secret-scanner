# SPDX-License-Identifier: MIT
"""End-to-end LLM triage pipeline.

Ties together middleware → orchestrator → report generation.
Activated via --llm-triage flag on the CLI.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class LLMTriageConfig:
    """Configuration for the LLM triage pipeline."""

    # Input
    json_input: Optional[str] = None  # path to scanner JSON output, or None to run scan first

    # Model providers
    tier1_provider: str = "none"  # openai | anthropic | local | none
    tier1_model: str = "gpt-4o-mini"
    tier1_endpoint: str = "http://localhost:11434/api/generate"

    tier2_provider: str = "none"  # openai | anthropic | local | none
    tier2_model: str = "claude-sonnet-4-20250514"

    # Output
    output_file: Optional[str] = None  # write triage report to file
    quiet: bool = False

    # Scan options (used if json_input is None)
    repo_dir: str = "."
    scan_args: dict = field(default_factory=dict)

    # Limits
    max_files: int = 50  # max files to send to LLM
    min_risk: str = "medium"  # minimum risk level to send to LLM


def run_llm_triage(config: LLMTriageConfig) -> dict:
    """Run the full LLM triage pipeline.

    1. Get scanner JSON (run scan or load existing)
    2. Parse, group, prune findings
    3. Classify risk per file
    4. Route to tiered inference
    5. Generate triage report

    Returns the triage report dict.
    """
    t0 = time.time()

    # ------------------------------------------------------------------
    # Step 1: Get scanner data
    # ------------------------------------------------------------------
    if config.json_input and Path(config.json_input).exists():
        if not config.quiet:
            print(f"Loading existing scan: {config.json_input}", file=sys.stderr)
        scan_data = json.loads(Path(config.json_input).read_text(encoding="utf-8"))
    else:
        if not config.quiet:
            print("Running scanner...", file=sys.stderr)
        scan_data = _run_scanner(config)

    # ------------------------------------------------------------------
    # Step 2: Parse and group
    # ------------------------------------------------------------------
    from .middleware import (
        extract_all_findings, group_by_file, prune_findings,
        classify_risk, get_file_context, build_stats,
    )

    all_findings = extract_all_findings(scan_data)
    if not config.quiet:
        print(f"Total raw findings: {len(all_findings)}", file=sys.stderr)

    grouped = group_by_file(all_findings)
    if not config.quiet:
        print(f"Files affected: {len(grouped)}", file=sys.stderr)

    cleaned = prune_findings(grouped)
    if not config.quiet:
        total_clean = sum(len(v) for v in cleaned.values())
        print(f"After pruning: {total_clean} findings in {len(cleaned)} files",
              file=sys.stderr)

    stats = build_stats(cleaned, scan_data)

    # ------------------------------------------------------------------
    # Step 3: Classify and sort by risk
    # ------------------------------------------------------------------
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    file_risks: list[tuple[str, str, list[dict]]] = []
    for filepath, items in cleaned.items():
        risk = classify_risk(items)
        file_risks.append((filepath, risk, items))

    file_risks.sort(key=lambda x: risk_order.get(x[1], 99))

    # Filter by minimum risk level
    min_risk_val = risk_order.get(config.min_risk, 2)
    file_risks = [(fp, r, items) for fp, r, items in file_risks
                  if risk_order.get(r, 99) <= min_risk_val]

    if not config.quiet:
        print(f"Files to triage (risk >= {config.min_risk}): {len(file_risks)}",
              file=sys.stderr)

    # ------------------------------------------------------------------
    # Step 4: Tiered inference
    # ------------------------------------------------------------------
    from .orchestrator import TriageOrchestrator, create_provider

    tier1 = create_provider(config.tier1_provider,
                            model=config.tier1_model,
                            endpoint=config.tier1_endpoint)
    tier2 = create_provider(config.tier2_provider,
                            model=config.tier2_model)
    orchestrator = TriageOrchestrator(tier1=tier1, tier2=tier2)

    triaged_files: list[dict] = []

    for i, (filepath, risk, items) in enumerate(file_risks[:config.max_files]):
        if not config.quiet:
            print(f"  [{i+1}/{min(len(file_risks), config.max_files)}] "
                  f"Triaging {filepath} ({risk})...", file=sys.stderr)

        file_context = get_file_context(filepath, config.repo_dir)
        results = orchestrator.triage_file(filepath, items, risk, file_context)

        fp_count = sum(1 for r in results if r.get("triage_verdict") == "FALSE_POSITIVE")
        tp_count = sum(1 for r in results if r.get("triage_verdict") == "TRUE_POSITIVE")
        un_count = len(results) - fp_count - tp_count

        triaged_files.append({
            "file": filepath,
            "risk": risk,
            "total": len(results),
            "true_positives": tp_count,
            "false_positives": fp_count,
            "uncertain": un_count,
            "findings": results,
        })

        # Rate-limit: 1 request per second for API calls
        if tier1 or tier2:
            time.sleep(0.5)

    # ------------------------------------------------------------------
    # Step 5: Build report
    # ------------------------------------------------------------------
    from .prompts import build_summary_prompt

    top_files = [(tf["file"], tf["risk"], tf["total"]) for tf in triaged_files[:10]]
    summary_prompt = build_summary_prompt(stats, top_files)

    report = {
        "pipeline_version": "1.0.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_summary": stats,
        "executive_summary": summary_prompt,
        "files_triaged": len(triaged_files),
        "total_true_positives": sum(tf["true_positives"] for tf in triaged_files),
        "total_false_positives": sum(tf["false_positives"] for tf in triaged_files),
        "total_uncertain": sum(tf["uncertain"] for tf in triaged_files),
        "elapsed_seconds": round(time.time() - t0, 1),
        "triaged_files": triaged_files,
    }

    # Write output
    if config.output_file:
        Path(config.output_file).write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        if not config.quiet:
            print(f"\nTriage report written to {config.output_file}", file=sys.stderr)

    # Print summary
    if not config.quiet:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"LLM Triage complete ({report['elapsed_seconds']}s)", file=sys.stderr)
        print(f"  Files triaged:   {report['files_triaged']}", file=sys.stderr)
        print(f"  True positives:  {report['total_true_positives']}", file=sys.stderr)
        print(f"  False positives: {report['total_false_positives']}", file=sys.stderr)
        print(f"  Uncertain:       {report['total_uncertain']}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)

    return report


def _run_scanner(config: LLMTriageConfig) -> dict:
    """Run the scanner inline and capture JSON output."""
    import io
    from ..cli import main as cli_main

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    buf = io.StringIO()

    try:
        sys.stdout = buf
        sys.stderr = io.StringIO() if config.quiet else sys.stderr

        # Build minimal args for a scan
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--format", default="json")
        parser.add_argument("--fast", action="store_true")
        parser.add_argument("--quiet", action="store_true")
        parser.add_argument("--repo-dir", default=config.repo_dir)

        ns = parser.parse_args([
            "--format", "json",
            "--fast",
            "--quiet",
            "--repo-dir", config.repo_dir,
        ])
        cli_main(argv=["--format", "json", "--fast", "--quiet",
                        "--repo-dir", config.repo_dir])
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return json.loads(buf.getvalue())
