# SPDX-License-Identifier: MIT
"""Configuration loading for rgt-codebase-scanner."""

from .loader import load_external_patterns, load_toml_config

__all__ = ["load_toml_config", "load_external_patterns"]
