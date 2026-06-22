# SPDX-License-Identifier: MIT
"""Shared utility helpers for omni-secret-scanner."""

from .entropy import shannon_entropy, is_ignored_entropy_token
from .redaction import redact_match, sanitize_match, redact_file_content, redact_file_in_place
from .git import (
    get_submodules,
    is_git_ignored,
    get_line_number_from_offset,
    load_secretsignore,
    match_exclude,
    extract_added_lines,
    scan_commit_messages,
    extract_markdown_code_blocks,
    get_context_snippet,
)
from .validation import SECRET_VALIDATORS, validate_secret
from .homoglyph import deconfuse, deconfuse_and_match, is_suspicious_unicode
from .mmap_io import read_file_content, get_mmap_threshold
from .cache import ScanCache
from .decay import decay_weight, apply_decay_to_findings
from .fix import redact_findings_in_files, stage_and_suggest_commit

__all__ = [
    "shannon_entropy",
    "is_ignored_entropy_token",
    "redact_match",
    "sanitize_match",
    "redact_file_content",
    "redact_file_in_place",
    "get_submodules",
    "is_git_ignored",
    "get_line_number_from_offset",
    "load_secretsignore",
    "match_exclude",
    "extract_added_lines",
    "scan_commit_messages",
    "extract_markdown_code_blocks",
    "get_context_snippet",
    "SECRET_VALIDATORS",
    "validate_secret",
    "deconfuse",
    "deconfuse_and_match",
    "is_suspicious_unicode",
    "decay_weight",
    "apply_decay_to_findings",
    "redact_findings_in_files",
    "stage_and_suggest_commit",
]
