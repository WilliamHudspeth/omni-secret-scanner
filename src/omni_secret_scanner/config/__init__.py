# SPDX-License-Identifier: MIT
"""Configuration loading for omni-secret-scanner."""

from .loader import load_toml_config, load_external_patterns

__all__ = ["load_toml_config", "load_external_patterns"]
