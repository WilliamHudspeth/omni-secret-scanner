# SPDX-License-Identifier: MIT
"""Shared utility helpers for omni-secret-scanner."""

from .cache import ScanCache
from .decay import apply_decay_to_findings, decay_weight
from .entropy import is_ignored_entropy_token, shannon_entropy
from .fix import redact_findings_in_files, stage_and_suggest_commit
from .git import (
    extract_added_lines,
    extract_markdown_code_blocks,
    get_context_snippet,
    get_line_number_from_offset,
    get_submodules,
    is_git_ignored,
    load_secretsignore,
    match_exclude,
    scan_commit_messages,
)
from .homoglyph import deconfuse, deconfuse_and_match, is_suspicious_unicode
from .mmap_io import get_mmap_threshold, read_file_content
from .redaction import redact_file_content, redact_file_in_place, redact_match, sanitize_match
from .validation import SECRET_VALIDATORS, validate_secret

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
    "ScanCache",
    "get_mmap_threshold",
    "read_file_content",
]
