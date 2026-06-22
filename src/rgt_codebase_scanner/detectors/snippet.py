# SPDX-License-Identifier: MIT
"""Core pattern-matching engine: snippet, text, notebook, and binary archive scanning."""

import base64
import json
import re
import zipfile
from pathlib import Path

from ..patterns import (
    ALL_SECRET_PATTERNS,
    CUSTOM_PII_PATTERNS,
    INJECTION_PATTERNS,
)
from ..utils.entropy import is_ignored_entropy_token, shannon_entropy
from ..utils.git import extract_markdown_code_blocks, get_line_number_from_offset


def scan_obfuscated_secrets(
    text: str, source_identifier: str, all_secret_patterns: dict
) -> list[dict]:
    """Detect secrets encoded as Base64 within *text*."""
    local_hits: list[dict] = []
    candidates = re.finditer(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", text)
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
                for name, pattern in all_secret_patterns.items():
                    for match_obf in re.finditer(pattern, decoded_text):
                        local_hits.append(
                            {
                                "type": f"Obfuscated:{name}",
                                "file": source_identifier,
                                "match": f"{token} (Decoded: {match_obf.group(0).strip()})",
                            }
                        )
        except Exception:
            pass
    return local_hits


def scan_snippet(
    content: str,
    source_name: str,
    entropy_threshold: float = 3.8,
    ignore_tokens: list | None = None,
    extract_code_blocks: bool = False,
    sensitive_words: list | None = None,
    presidio_analyzer=None,
) -> dict:
    """Scan a text snippet for secrets, PII, entropy strings, and injection attacks.

    Returns a dict with keys ``secrets``, ``pii``, ``entropy``, ``injections``.
    """
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []

    if extract_code_blocks and (
        source_name.endswith(".md") or source_name in ("stdin", "text_snippet")
    ):
        blocks = extract_markdown_code_blocks(content)
        if blocks:
            content = "\n".join(blocks)

    findings: dict = {"secrets": [], "pii": [], "entropy": [], "injections": []}
    lines = content.splitlines()
    for idx, line in enumerate(lines):
        line_no = idx + 1

        for name, pattern in ALL_SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, line):
                    val = m.group(0).strip()
                    if val not in ignore_tokens:
                        findings["secrets"].append(
                            {"type": name, "file": source_name, "line": line_no, "match": val}
                        )
            except re.error:
                pass

        for hit in scan_obfuscated_secrets(line, source_name, ALL_SECRET_PATTERNS):
            if hit["match"] not in ignore_tokens:
                hit["line"] = line_no
                findings["secrets"].append(hit)

        for word in sensitive_words:
            if word.lower() in line.lower():
                for m in re.finditer(re.escape(word), line, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        findings["secrets"].append(
                            {
                                "type": f"Sensitive Word: {word}",
                                "file": source_name,
                                "line": line_no,
                                "match": val,
                            }
                        )

        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, line):
                val = m.group(0).strip()
                if val not in ignore_tokens:
                    findings["pii"].append(
                        {"type": name, "file": source_name, "line": line_no, "match": val}
                    )

        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", line)
        for m in candidates:
            token = m.group(0)
            if token.isdigit():
                continue
            if all(c in "0123456789abcdefABCDEF" for c in token) and len(token) in (32, 40):
                continue
            if is_ignored_entropy_token(token):
                continue
            if token in ignore_tokens:
                continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["entropy"].append(
                    {
                        "file": source_name,
                        "line": line_no,
                        "token": token,
                        "entropy": round(entropy, 2),
                    }
                )

        for inj_name, inj_pattern in INJECTION_PATTERNS.items():
            try:
                for m in re.finditer(inj_pattern, line):
                    findings["injections"].append(
                        {
                            "type": f"INJECTION:{inj_name}",
                            "file": source_name,
                            "line": line_no,
                            "match": m.group(0).strip(),
                        }
                    )
            except re.error:
                pass

    if presidio_analyzer:
        try:
            results = presidio_analyzer.analyze(
                text=content,
                language=getattr(presidio_analyzer, "_omni_language", "en"),
            )
            for res in results:
                val = content[res.start : res.end]
                if val not in ignore_tokens:
                    findings["pii"].append(
                        {
                            "type": f"Presidio:{res.entity_type}",
                            "file": source_name,
                            "line": get_line_number_from_offset(content, res.start),
                            "match": val,
                        }
                    )
        except Exception:
            pass

    return findings


def scan_text(text: str, source_identifier: str, all_secret_patterns: dict) -> list[dict]:
    """Simple line-by-line scan of *text* against *all_secret_patterns*."""
    local_hits: list[dict] = []
    for name, pattern in all_secret_patterns.items():
        try:
            for m in re.finditer(pattern, text):
                local_hits.append(
                    {"type": name, "file": source_identifier, "match": m.group(0).strip()}
                )
        except re.error:
            pass
    return local_hits


def scan_ipynb(path, all_secret_patterns: dict) -> list[dict]:
    """Scan a Jupyter notebook (.ipynb) for secrets in cell source and outputs."""
    local_hits: list[dict] = []
    try:
        nb = json.loads(Path(path).read_text(errors="ignore"))
    except Exception:
        return local_hits
    for i, cell in enumerate(nb.get("cells", [])):
        src = "".join(cell.get("source", []))
        local_hits += scan_text(src, f"{path}:cell{i}", all_secret_patterns)
        for out in cell.get("outputs", []):
            txt = ""
            if "text" in out:
                txt = "".join(out["text"])
            if "data" in out and "text/plain" in out["data"]:
                txt = "".join(out["data"]["text/plain"])
            local_hits += scan_text(txt, f"{path}:cell{i}:output", all_secret_patterns)
    return local_hits


def scan_pbix(path, all_secret_patterns: dict) -> list[dict]:
    """Scan a Power BI file (.pbix) by extracting its internal Mashup/schema content."""
    local_hits: list[dict] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if "DataModelSchema" in info.filename or info.filename.startswith("Mashup/"):
                    try:
                        content = zf.read(info.filename).decode(encoding="utf-8", errors="ignore")
                        for idx, line in enumerate(content.splitlines(), 1):
                            for name, pattern in all_secret_patterns.items():
                                try:
                                    for m in re.finditer(pattern, line):
                                        local_hits.append(
                                            {
                                                "type": name,
                                                "file": f"{path}/{info.filename}",
                                                "line": idx,
                                                "match": m.group(0).strip(),
                                            }
                                        )
                                except re.error:
                                    pass
                    except Exception:
                        pass
    except Exception:
        pass
    return local_hits
