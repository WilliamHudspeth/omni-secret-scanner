# SPDX-License-Identifier: MIT
"""Secret redaction and sanitization utilities."""

import base64
import re
from pathlib import Path
from typing import Optional

from ..patterns import CUSTOM_SECRET_PATTERNS, GITROB_CONTENT_PATTERNS, AI_PATTERNS, CUSTOM_PII_PATTERNS

_KNOWN_PREFIXES = (
    "AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "hf_", "gsk_", "pplx-", "sk-ant-", "sk-proj-", "sk-", "nvapi-", "sbp_",
)


def redact_match(match_str: str) -> str:
    """Redact a secret match while preserving its recognisable prefix."""
    if not match_str:
        return "[REDACTED]"
    if " (Decoded: " in match_str:
        base_part, decoded_part = match_str.split(" (Decoded: ", 1)
        return f"{redact_match(base_part)} (Decoded: {redact_match(decoded_part.rstrip(')'))})"
    if len(match_str) <= 4:
        return "[REDACTED]"
    for prefix in _KNOWN_PREFIXES:
        if match_str.startswith(prefix):
            return f"{prefix}[REDACTED]"
    return f"{match_str[:4]}[REDACTED]"


def sanitize_match(match_text: str) -> str:
    """Neutralise live injection strings so they are safe for LLM consumption."""
    import html
    match_text = re.sub(
        r"(?i)ignore\s+(all\s+)?previous\s+instructions", "[INJECTION_BLOCKED]", match_text
    )
    match_text = re.sub(r"<\|im_start\|>|<\|im_end\|>", "[DELIM_BLOCKED]", match_text)
    match_text = re.sub(r"(?i)(you\s+are\s+now\s+)", "[OVERRIDE_BLOCKED] ", match_text)
    match_text = re.sub(r"(?i)(act\s+as\s+)", "[ROLE_BLOCKED] ", match_text)
    match_text = re.sub(
        r"(?i)(print|show|reveal|display)\s+(your\s+)?(system\s+prompt|initial\s+instructions)",
        "[LEAK_BLOCKED]",
        match_text,
    )
    return html.escape(match_text)


def redact_file_content(content: str, sensitive_words: Optional[list] = None) -> str:
    """Return content with all detected secrets and PII replaced by redaction markers."""
    if sensitive_words is None:
        sensitive_words = []

    all_secret_patterns = {**CUSTOM_SECRET_PATTERNS, **GITROB_CONTENT_PATTERNS, **AI_PATTERNS}
    replacements: list[tuple[int, int, str]] = []

    for _name, pattern in all_secret_patterns.items():
        try:
            for m in re.finditer(pattern, content):
                replacements.append((m.start(), m.end(), redact_match(m.group(0))))
        except re.error:
            pass

    candidates = re.finditer(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", content)
    for m in candidates:
        token = m.group(0)
        try:
            pad_len = 4 - (len(token) % 4)
            token_padded = token + ("=" * pad_len) if pad_len < 4 else token
            decoded_bytes = base64.b64decode(token_padded)
            decoded_text = decoded_bytes.decode("utf-8", errors="strict")
            if len(decoded_text) > 10 and all(
                32 <= ord(c) < 127 or c in "\r\n\t" for c in decoded_text
            ):
                found_inner = any(
                    re.search(p, decoded_text) for p in all_secret_patterns.values()
                )
                if found_inner:
                    replacements.append((m.start(), m.end(), redact_match(token)))
        except Exception:
            pass

    for word in sensitive_words:
        for m in re.finditer(re.escape(word), content, re.IGNORECASE):
            replacements.append((m.start(), m.end(), redact_match(m.group(0))))

    for _name, pattern in CUSTOM_PII_PATTERNS.items():
        for m in re.finditer(pattern, content):
            replacements.append((m.start(), m.end(), redact_match(m.group(0))))

    replacements.sort(key=lambda x: (x[0], -x[1]))
    filtered: list[tuple[int, int, str]] = []
    last_end = -1
    for start, end, red_val in replacements:
        if start >= last_end:
            filtered.append((start, end, red_val))
            last_end = end

    chars = list(content)
    for start, end, red_val in sorted(filtered, key=lambda x: x[0], reverse=True):
        chars[start:end] = list(red_val)
    return "".join(chars)


def redact_file_in_place(
    filepath: str,
    sensitive_words: Optional[list] = None,
    dryrun: bool = False,
) -> bool:
    """Redact secrets in a file, creating a .bak backup first.

    Returns True on success (or when dry-run finds no issues).
    """
    from .entropy import shannon_entropy, is_ignored_entropy_token

    if sensitive_words is None:
        sensitive_words = []
    try:
        path = Path(filepath)
        if not path.exists():
            import sys
            print(f"Error: File {filepath} does not exist.", file=sys.stderr)
            return False
        if path.stat().st_size > 1_000_000:
            import sys
            print(
                f"Error: File {filepath} is too large (>1MB). Skipping redaction.",
                file=sys.stderr,
            )
            return False

        content = path.read_text(encoding="utf-8", errors="ignore")

        if dryrun:
            # Inline import to avoid circular dependency
            from ..detectors.snippet import scan_snippet

            print(f"\n[DRY RUN] Analysing {filepath} for secrets/PII to redact...")
            findings = scan_snippet(content, filepath, sensitive_words=sensitive_words)
            total = len(findings["secrets"]) + len(findings["pii"]) + len(findings["entropy"])
            if total > 0:
                print(f"[DRY RUN] Found {total} item(s) that would be redacted:")
                for s in findings["secrets"]:
                    print(f"  - SECRET: {s['type']} at line {s['line']} (value: {s['match']})")
                for p in findings["pii"]:
                    print(f"  - PII: {p['type']} at line {p['line']} (value: {p['match']})")
                for e in findings["entropy"]:
                    print(f"  - HIGH ENTROPY TOKEN: at line {e['line']} (value: {e['token']})")
                print(f"[DRY RUN] File {filepath} would be modified (backup would be saved).")
                return False
            print(f"[DRY RUN] No secrets, PII, or high-entropy tokens detected in {filepath}.")
            return True

        redacted = redact_file_content(content, sensitive_words)
        backup_path = path.with_suffix(path.suffix + ".bak")
        try:
            backup_path.write_text(content, encoding="utf-8")
        except Exception:
            pass
        path.write_text(redacted, encoding="utf-8")
        print(f"Successfully redacted {filepath} (backup saved as {backup_path.name})")
        return True
    except Exception as e:
        import sys
        print(f"Error redacting file {filepath}: {e}", file=sys.stderr)
        return False
