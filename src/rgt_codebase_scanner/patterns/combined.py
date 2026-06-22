# SPDX-License-Identifier: MIT
"""Combined regex pattern compilation for faster single-pass matching.

Instead of iterating 100+ individual patterns per line, this module
builds a single giant regex with named groups using (?P<name>...).
One finditer() call per line catches all pattern types at once.

Activated internally when --fast flag is NOT set (pattern set is
large enough to benefit). Always available — no flag needed.
"""

from __future__ import annotations

import re


def build_combined_pattern(
    pattern_dict: dict[str, str],
    flags: int = 0,
) -> re.Pattern | None:
    """Build a single regex that matches all patterns in *pattern_dict*.

    Each pattern becomes a named group: (?P<name>pattern).
    Returns None if the combined pattern would be too large (>100 groups)
    or if compilation fails.

    Usage:
        combined = build_combined_pattern(ALL_SECRET_PATTERNS)
        if combined:
            for m in combined.finditer(line):
                for name, val in m.groupdict().items():
                    if val is not None:
                        # found a match for pattern 'name'
    """
    if not pattern_dict:
        return None

    parts: list[str] = []
    for name, pat in pattern_dict.items():
        # Sanitize the name for regex group naming
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        parts.append(f"(?P<{safe_name}>{pat})")

    # Limit: if too many patterns, combined regex can hit engine limits
    if len(parts) > 200:
        return None

    combined = "|".join(parts)
    try:
        return re.compile(combined, flags)
    except re.error:
        return None


def combined_pattern_find(
    line: str,
    combined: re.Pattern,
    name_map: dict[str, str],
) -> list[tuple[str, str]]:
    """Run *combined* regex against *line* and return [(name, match_text), ...].

    *name_map* maps safe group names back to original pattern names.
    """
    results: list[tuple[str, str]] = []
    for m in combined.finditer(line):
        for safe_name, val in m.groupdict().items():
            if val is not None:
                original = name_map.get(safe_name, safe_name)
                results.append((original, val.strip()))
    return results


def build_name_map(pattern_dict: dict[str, str]) -> dict[str, str]:
    """Build a mapping from safe group names to original pattern names."""
    return {re.sub(r"[^a-zA-Z0-9_]", "_", name): name for name in pattern_dict}
