# SPDX-License-Identifier: MIT
"""Unicode homoglyph / confusable character detection and normalization.

Detects attacks that use Cyrillic, Greek, or other lookalike characters
to smuggle strings past simple ASCII-based secret scanners.

Activated via --deconfuse flag.

Uses a curated confusables table plus Unicode NFKC normalization.
Also flags zero-width joiners and mixed-script attacks.
"""

from __future__ import annotations

import re
import unicodedata

# ------------------------------------------------------------------
# Zero-width / invisible character pattern
# ------------------------------------------------------------------

# Zero-width spaces, joiners, non-joiners, LRE/RLE/PDF overrides, word joiners
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\u00ad\ufeff]")

# ------------------------------------------------------------------
# Curated confusables table (Unicode code point → ASCII replacement)
# ------------------------------------------------------------------
# This is a focused subset of the full Unicode confusables.txt.
# Covers the most common homoglyph attacks against secret scanners.
# Full table: https://www.unicode.org/Public/security/latest/confusables.txt

_CONFUSABLES: dict[int, str] = {
    # --- Cyrillic → Latin ---
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M",
    0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C", 0x0422: "T",
    0x0423: "Y", 0x0425: "X", 0x0430: "a", 0x0435: "e", 0x043E: "o",
    0x0440: "p", 0x0441: "c", 0x0443: "y", 0x0445: "x", 0x0455: "s",
    0x0456: "i", 0x04BB: "h", 0x04D5: "a",
    # --- Greek → Latin ---
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O",
    0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
    0x03B1: "a", 0x03B2: "b", 0x03B5: "e", 0x03B7: "n", 0x03B9: "i",
    0x03BA: "k", 0x03BD: "v", 0x03BF: "o", 0x03C1: "p", 0x03C4: "t",
    0x03C5: "u", 0x03C7: "x",
    # --- Latin extensions / IPA → ASCII ---
    0x0261: "g", 0x026A: "i", 0x027E: "r", 0x0283: "s", 0x0292: "z",
    0x1D00: "a", 0x1D03: "b", 0x1D04: "c", 0x1D05: "d", 0x1D07: "e",
    0x1D0A: "j", 0x1D0B: "k", 0x1D0C: "l", 0x1D0D: "m", 0x1D0F: "o",
    0x1D18: "p", 0x1D20: "v", 0x1D21: "w", 0x1D22: "z",
    # --- Fullwidth → ASCII ---
    0xFF21: "A", 0xFF22: "B", 0xFF23: "C", 0xFF24: "D", 0xFF25: "E",
    0xFF28: "H", 0xFF29: "I", 0xFF2A: "J", 0xFF2B: "K", 0xFF2C: "L",
    0xFF2D: "M", 0xFF2E: "N", 0xFF2F: "O", 0xFF30: "P", 0xFF32: "R",
    0xFF33: "S", 0xFF34: "T", 0xFF35: "U", 0xFF36: "V", 0xFF37: "W",
    0xFF38: "X", 0xFF39: "Y", 0xFF3A: "Z",
    0xFF41: "a", 0xFF42: "b", 0xFF43: "c", 0xFF44: "d", 0xFF45: "e",
    0xFF47: "g", 0xFF48: "h", 0xFF49: "i", 0xFF4A: "j", 0xFF4B: "k",
    0xFF4C: "l", 0xFF4D: "m", 0xFF4E: "n", 0xFF4F: "o", 0xFF50: "p",
    0xFF52: "r", 0xFF53: "s", 0xFF54: "t", 0xFF55: "u", 0xFF56: "v",
    0xFF57: "w", 0xFF58: "x", 0xFF59: "y", 0xFF5A: "z",
    # --- Digits → ASCII ---
    0xFF10: "0", 0xFF11: "1", 0xFF12: "2", 0xFF13: "3", 0xFF14: "4",
    0xFF15: "5", 0xFF16: "6", 0xFF17: "7", 0xFF18: "8", 0xFF19: "9",
    # --- Mathematical / styled digits ---
    0x1D7E2: "0", 0x1D7E3: "1", 0x1D7E4: "2", 0x1D7E5: "3", 0x1D7E6: "4",
    0x1D7E7: "5", 0x1D7E8: "6", 0x1D7E9: "7", 0x1D7EA: "8", 0x1D7EB: "9",
    0x2460: "1", 0x2461: "2", 0x2462: "3", 0x2463: "4", 0x2464: "5",
    0x2465: "6", 0x2466: "7", 0x2467: "8", 0x2468: "9",
}


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def deconfuse(text: str) -> tuple[str, bool]:
    """Normalize *text* to ASCII and report whether obfuscation was detected.

    Returns (cleaned_text, was_suspicious).

    Processing steps:
    1. Strip zero-width / invisible characters
    2. Apply Unicode NFKC normalization
    3. Map confusable characters to ASCII equivalents
    4. Detect mixed Latin+Cyrillic+Greek scripts (suspicious)
    """
    if not text:
        return text, False

    original = text

    # Step 1: strip zero-width characters
    text = _ZERO_WIDTH_RE.sub("", text)

    # Step 2: NFKC normalization
    text = unicodedata.normalize("NFKC", text)

    # Step 3: confusables mapping
    text = text.translate(_CONFUSABLES)

    # Step 4: mixed-script detection
    scripts: set[str] = set()
    for ch in original:
        try:
            name = unicodedata.name(ch, "")
            if name:
                scripts.add(name.split()[0])
        except Exception:
            pass
    mixed_script = len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1

    was_suspicious = mixed_script or (text != original)
    return text, was_suspicious


def deconfuse_and_match(line: str, pattern: str, flags: int = 0) -> list[tuple[re.Match, bool]]:
    """Run *pattern* against both original and deconfused *line*.

    Returns list of (match_object, is_from_original).
    The boolean indicates whether the match came from the original line
    or was only discoverable after deconfusion.
    """
    results: list[tuple[re.Match, bool]] = []

    # Match against original line
    compiled = re.compile(pattern, flags)
    for m in compiled.finditer(line):
        results.append((m, True))

    # Match against deconfused line
    clean_line, flagged = deconfuse(line)
    if flagged:
        # Only re-scan if something actually changed
        compiled_clean = re.compile(pattern, flags)
        for m in compiled_clean.finditer(clean_line):
            results.append((m, False))

    return results


def is_suspicious_unicode(text: str) -> bool:
    """Quick check: does *text* contain confusable or invisible characters?"""
    if _ZERO_WIDTH_RE.search(text):
        return True
    for ch in text:
        if ord(ch) in _CONFUSABLES:
            return True
    return False
