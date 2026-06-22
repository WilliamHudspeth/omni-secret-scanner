# SPDX-License-Identifier: MIT
"""
LLM Integration & Security Analysis Pipeline for RGT Codebase Scanner.

Architecture:
  state_machine.py — Finding state machine (DISCOVER→SCORE→ROUTE→...)
  profiler.py      — Stage 0: Repository profiling (--profile)
  evidence.py      — Stage 1: Evidence collection (cheap signals only)
  scorer.py        — Stage 2: Risk pre-scoring (rules, not ML)
  router.py        — Stage 3: Deterministic engine routing
  pipeline.py      — End-to-end pipeline orchestrator (--pipeline)
  correlation.py   — Stage 5-6: Verification + asset correlation
  middleware.py    — Legacy: JSON parser, grouper, noise filter
  orchestrator.py  — Legacy: Tiered inference routing
  prompts.py       — CISSP-grade system prompts
  tools.py         — Function-calling schema integration

Quick start:
  omni-scan --profile            # profile repo, recommend engines
  omni-scan --pipeline           # full analysis pipeline
  omni-scan --llm-triage         # legacy LLM triage mode
"""

# New state-machine pipeline
from .pipeline import run_pipeline, PipelineConfig

# Legacy triage pipeline (kept for backward compat)
from .middleware import (
    extract_all_findings, group_by_file, prune_findings,
    classify_risk, build_stats, get_file_context,
)

__all__ = [
    "run_pipeline",
    "PipelineConfig",
    "extract_all_findings",
    "group_by_file",
    "prune_findings",
    "classify_risk",
    "build_stats",
    "get_file_context",
]
