# SPDX-License-Identifier: MIT
"""omni-secret-scanner — enterprise secret, PII, and injection scanner."""

__version__ = "9.0.0"
__author__ = "omni-secret-scanner contributors"
__license__ = "MIT"

from .detectors import (
    scan_snippet,
    scan_text,
    scan_history,
    scan_current_tree,
    run_semgrep_scan,
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
