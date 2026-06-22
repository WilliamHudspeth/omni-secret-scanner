# SPDX-License-Identifier: MIT
"""rgt-codebase-scanner — enterprise secret, PII, and injection scanner."""

__version__ = "9.0.0"
__author__ = "rgt-codebase-scanner contributors"
__license__ = "MIT"

from .detectors import (
    run_semgrep_scan,
    scan_current_tree,
    scan_history,
    scan_snippet,
    scan_text,
)
from .reporters import generate_report

__all__ = [
    "__version__",
    "scan_snippet",
    "scan_text",
    "scan_history",
    "scan_current_tree",
    "run_semgrep_scan",
    "generate_report",
]
