# SPDX-License-Identifier: MIT
"""Detectors subpackage for omni-secret-scanner."""

from .snippet import scan_snippet, scan_text, scan_obfuscated_secrets, scan_ipynb, scan_pbix
from .git_history import scan_history, scan_reflog, scan_diff, scan_stash
from .file_tree import scan_current_tree
from .powershell import run_ps_crosscheck
from .semgrep import run_semgrep_scan
from .nlp import init_nlp_deidentifier, init_presidio_analyzer
from .ast_filter import ast_context_filter
from .perplexity import CharMarkovModel, get_model_cache_path, collect_safe_corpus
from .taint import taint_analysis
from .stego import detect_lsb_steganography, is_stego_candidate
from .parallel import scan_current_tree_parallel

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
]
