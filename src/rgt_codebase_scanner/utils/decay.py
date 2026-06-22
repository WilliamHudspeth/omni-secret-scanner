# SPDX-License-Identifier: MIT
"""Decay-weighted history scoring for git commit age.

When --decay is active, each history finding gets a decay factor based
on how old the commit is.  Fresh leaks (today) score higher than leaks
from years ago — useful for prioritising remediation.

Activated via --decay flag.
"""

from __future__ import annotations

import math
import time
from datetime import UTC, datetime

# Half-life in days: after this many days, weight drops to 0.5
DEFAULT_HALF_LIFE_DAYS = 180  # 6 months


def parse_commit_date(commit_date_iso: str) -> float | None:
    """Parse an ISO-format git commit date to a Unix timestamp.

    Handles formats like:
        "2026-06-22T14:30:00+00:00"
        "2026-06-22 14:30:00 +0000"
        "2026-06-22T00:00:00Z"
    Returns None on parse failure.
    """
    # Try fromisoformat (Python 3.11+) which handles most ISO formats
    try:
        dt = datetime.fromisoformat(commit_date_iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except (ValueError, AttributeError):
        pass

    # Fallback: try multiple format strings
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(commit_date_iso[: len(fmt)], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
        except (ValueError, IndexError):
            continue

    # Handle +00:00 format manually (strip colon from tz)
    import re as _re

    fixed = _re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", commit_date_iso)
    if fixed != commit_date_iso:
        try:
            dt = datetime.strptime(fixed, "%Y-%m-%dT%H:%M:%S%z")
            return dt.timestamp()
        except ValueError:
            pass

    return None


def decay_weight(
    commit_date_iso: str,
    half_life_days: int = DEFAULT_HALF_LIFE_DAYS,
) -> float:
    """Return a decay weight for a commit, based on its age.

    Weight is 1.0 for today's commits and decays exponentially:
        weight = 0.5 ** (age_days / half_life_days)

    Returns 0.05 as floor (never zero — old leaks still matter).
    """
    ts = parse_commit_date(commit_date_iso)
    if ts is None:
        return 1.0  # can't parse → assume recent

    now = time.time()
    age_seconds = now - ts
    if age_seconds < 0:
        return 1.0  # future date → treat as recent

    age_days = age_seconds / 86400.0
    weight = math.pow(0.5, age_days / half_life_days)
    return max(0.05, weight)


def apply_decay_to_findings(
    findings: list[dict],
    half_life_days: int = DEFAULT_HALF_LIFE_DAYS,
) -> list[dict]:
    """Add 'decay_weight' and 'age_days' to each finding with a commit date.

    Modifies findings in-place and returns the list.
    """
    for f in findings:
        commit_date = f.get("commit_date") or f.get("date")
        if commit_date:
            weight = decay_weight(commit_date, half_life_days)
            ts = parse_commit_date(commit_date)
            age_days = (time.time() - ts) / 86400.0 if ts else 0
            f["decay_weight"] = round(weight, 4)
            f["age_days"] = round(age_days, 1)
        else:
            f["decay_weight"] = 1.0
            f["age_days"] = 0.0
    return findings
