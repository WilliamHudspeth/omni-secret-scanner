# SPDX-License-Identifier: MIT
"""Detectors subpackage for rgt-codebase-scanner."""

from .ast_filter import ast_context_filter
from .external import run_gitleaks, run_trivy
from .file_tree import scan_current_tree
from .git_history import scan_diff, scan_history, scan_reflog, scan_stash
from .nlp import init_nlp_deidentifier, init_presidio_analyzer
from .parallel import scan_current_tree_parallel
from .perplexity import CharMarkovModel, collect_safe_corpus, get_model_cache_path
from .powershell import run_ps_crosscheck
from .semgrep import run_semgrep_scan
from .snippet import scan_ipynb, scan_obfuscated_secrets, scan_pbix, scan_snippet, scan_text
from .stego import detect_lsb_steganography, is_stego_candidate
from .taint import taint_analysis
from .watchdog import run_watch_mode

__all__ = [
    "scan_snippet",
    "scan_text",
    "scan_obfuscated_secrets",
    "scan_ipynb",
    "scan_pbix",
    "scan_history",
    "scan_reflog",
    "scan_diff",
    "scan_stash",
    "scan_current_tree",
    "run_ps_crosscheck",
    "run_semgrep_scan",
    "init_nlp_deidentifier",
    "init_presidio_analyzer",
    "ast_context_filter",
    "CharMarkovModel",
    "get_model_cache_path",
    "collect_safe_corpus",
    "taint_analysis",
    "detect_lsb_steganography",
    "is_stego_candidate",
    "scan_current_tree_parallel",
    "run_watch_mode",
    "run_gitleaks",
    "run_trivy",
]
