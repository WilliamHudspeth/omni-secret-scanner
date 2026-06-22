#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Backwards-compatible shim for `python scan-secrets.py`.

All logic has been moved to the `omni_secret_scanner` package.
Use `omni-scan` (the installed console entry point) for new integrations.
"""

from omni_secret_scanner.cli import entry_point

if __name__ == "__main__":
    entry_point()
