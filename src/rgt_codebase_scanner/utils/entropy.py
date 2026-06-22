# SPDX-License-Identifier: MIT
"""Shannon entropy calculation and token filtering."""

import math
import re


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits per character) for the given string."""
    if not data:
        return 0.0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)


def is_ignored_entropy_token(token: str) -> bool:
    """Return True if the token is a known false-positive for entropy scanning.

    Filters UUIDs and Base64-encoded data that commonly trigger entropy rules.
    """
    if re.match(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        token,
    ):
        return True
    if re.match(r"^[A-Za-z0-9+/]{24,}={0,2}$", token):
        return True
    return False


def is_hex_hash(token: str) -> bool:
    """Return True if the token looks like a SHA/MD5 hex hash.

    Matches 32-char MD5, 40-char SHA1, and 64-char SHA256 hex strings.
    These commonly appear in CI configs, Makefiles, and changelogs.
    """
    stripped = token.strip()
    if len(stripped) not in (32, 40, 64):
        return False
    return bool(re.match(r"^[a-fA-F0-9]+$", stripped))
