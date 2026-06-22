# SPDX-License-Identifier: MIT
"""
LLM Integration Pipeline for RGT Codebase Scanner.

Middleware that ingests scanner JSON output, groups findings by file
and risk level, prunes noise, and prepares structured prompts for
tiered LLM inference — maximising signal-to-noise before the data
hits the model.

Architecture:
    1. Middleware:  Parse JSON, group by file, prune low-signal hits
    2. Orchestrator: Tiered routing (small model for FP triage,
                     large model for exploitability analysis)
    3. Prompts:      CISSP-grade system prompts + per-file templates
    4. Tools:        Function-calling schema for targeted re-scans
"""

# Re-export the pipeline entry point
from .pipeline import run_llm_triage, LLMTriageConfig

__all__ = ["run_llm_triage", "LLMTriageConfig"]
