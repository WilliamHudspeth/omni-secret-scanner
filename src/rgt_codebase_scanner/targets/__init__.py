# SPDX-License-Identifier: MIT
"""Scan target resolvers — one module per target type."""

from .resolver import resolve_target

__all__ = ["resolve_target"]
