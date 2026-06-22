#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Backwards-compatible shim. Use `rgt-scan` or `omni-scan` instead."""

from rgt_codebase_scanner.cli import entry_point

if __name__ == "__main__":
    entry_point()
