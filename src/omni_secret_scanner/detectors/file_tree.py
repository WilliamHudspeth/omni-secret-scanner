# SPDX-License-Identifier: MIT
"""Parallel working-tree file scanner."""

import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from ..patterns import (
    ALL_SECRET_PATTERNS,
    CUSTOM_PII_PATTERNS,
    GITROB_SUSPICIOUS_FILES,
    INJECTION_PATTERNS,
    get_lang_rules_for_file,
)
from ..utils.entropy import shannon_entropy, is_ignored_entropy_token
from ..utils.git import (
    extract_markdown_code_blocks,
    get_line_number_from_offset,
    get_submodules,
    match_exclude,
)
from ..utils.homoglyph import deconfuse, deconfuse_and_match
from .snippet import scan_ipynb, scan_obfuscated_secrets, scan_pbix
from .ast_filter import ast_context_filter
from .stego import detect_lsb_steganography, is_stego_candidate
from .taint import taint_analysis


def _scan_single_file(job: tuple) -> dict:
    """Worker function for parallel scanning. Returns a findings dict for one file."""
    (
        path,
        file_rel_path,
        max_bytes,
        all_secret_patterns,
        ignore_tokens,
        sensitive_words,
        extract_code_blocks,
        nlp_deidentifier,
        presidio_analyzer,
        lang_rules_enabled,
        ast_filter_enabled,
        deconfuse_enabled,
        taint_enabled,
        stego_enabled,
        perplexity_model,
    ) = job

    lang_rules = get_lang_rules_for_file(file_rel_path, enabled=lang_rules_enabled)
    if lang_rules:
        all_secret_patterns = {**all_secret_patterns, **lang_rules}

    result: dict = {
        "suspicious_files": [],
        "current_secrets": [],
        "nlp_pii": [],
        "injections": [],
        "taint": [],
        "stego": [],
    }

    from fnmatch import fnmatch
    for glob_pat in GITROB_SUSPICIOUS_FILES:
        if fnmatch(path.name, glob_pat) or fnmatch(file_rel_path, glob_pat):
            result["suspicious_files"].append(file_rel_path)
            break

    try:
        if path.stat().st_size > max_bytes:
            return result
    except Exception:
        return result

    # ------------------------------------------------------------------
    # Steganography check (image files only, when --steganalysis active)
    # ------------------------------------------------------------------
    if stego_enabled and is_stego_candidate(str(path)):
        stego_result = detect_lsb_steganography(str(path))
        if stego_result.get("risk"):
            result["stego"].append({
                "file": file_rel_path,
                "type": "LSB_Steganography",
                "confidence": stego_result.get("confidence", 0),
                "rs_ratio": stego_result.get("rs_ratio", 0),
                "method": stego_result.get("method", "RS"),
            })

    if path.suffix == ".ipynb":
        for hit in scan_ipynb(path, all_secret_patterns):
            if hit["match"] not in ignore_tokens:
                result["current_secrets"].append(hit)
        return result

    if path.suffix == ".pbix":
        for hit in scan_pbix(path, all_secret_patterns):
            if hit["match"] not in ignore_tokens:
                result["current_secrets"].append(hit)
        return result

    try:
        with open(path, "rb") as _bf:
            if b"\x00" in _bf.read(8192):
                return result
    except Exception:
        return result

    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return result

    if extract_code_blocks and file_rel_path.endswith(".md"):
        blocks = extract_markdown_code_blocks(content)
        if blocks:
            content = "\n".join(blocks)

    lines = content.splitlines()
    for idx, line in enumerate(lines):
        line_no = idx + 1

        # Determine which match function to use
        _match_fn = deconfuse_and_match if deconfuse_enabled else None

        for name, pattern in all_secret_patterns.items():
            try:
                if _match_fn:
                    matches = _match_fn(line, pattern)
                    for m, _ in matches:
                        val = m.group(0).strip()
                        if val not in ignore_tokens:
                            result["current_secrets"].append(
                                {"type": name, "file": file_rel_path, "line": line_no, "match": val}
                            )
                else:
                    for m in re.finditer(pattern, line):
                        val = m.group(0).strip()
                        if val not in ignore_tokens:
                            result["current_secrets"].append(
                                {"type": name, "file": file_rel_path, "line": line_no, "match": val}
                            )
            except re.error:
                pass

        for hit in scan_obfuscated_secrets(line, file_rel_path, all_secret_patterns):
            if hit["match"] not in ignore_tokens:
                hit["line"] = line_no
                result["current_secrets"].append(hit)

        for word in sensitive_words:
            if word.lower() in line.lower():
                for m in re.finditer(re.escape(word), line, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        result["current_secrets"].append(
                            {
                                "type": f"Sensitive Word: {word}",
                                "file": file_rel_path,
                                "line": line_no,
                                "match": val,
                            }
                        )

        for name, pattern in CUSTOM_PII_PATTERNS.items():
            if _match_fn:
                matches = _match_fn(line, pattern)
                for m, _ in matches:
                    val = m.group(0).strip()
                    if val not in ignore_tokens:
                        result["current_secrets"].append(
                            {"type": f"PII:{name}", "file": file_rel_path, "line": line_no, "match": val}
                        )
            else:
                for m in re.finditer(pattern, line):
                    val = m.group(0).strip()
                    if val not in ignore_tokens:
                        result["current_secrets"].append(
                            {"type": f"PII:{name}", "file": file_rel_path, "line": line_no, "match": val}
                        )

        for inj_name, inj_pattern in INJECTION_PATTERNS.items():
            try:
                for m in re.finditer(inj_pattern, line):
                    result["injections"].append(
                        {
                            "type": f"INJECTION:{inj_name}",
                            "file": file_rel_path,
                            "line": line_no,
                            "match": m.group(0).strip(),
                        }
                    )
            except re.error:
                pass

    _NLP_EXTS = {".txt", ".md", ".csv", ".json", ".yml", ".yaml", ".py"}
    if nlp_deidentifier and path.suffix in _NLP_EXTS:
        try:
            nlp_deidentifier.deidentify(content)
            tokens = nlp_deidentifier.get_identified_elements()
            for ent in tokens.get("entities", []):
                val = ent["text"]
                if val not in ignore_tokens:
                    result["nlp_pii"].append({"file": file_rel_path, "type": "NAME", "match": val})
            for pron in tokens.get("pronouns", []):
                val = pron["text"]
                if val not in ignore_tokens:
                    result["nlp_pii"].append(
                        {"file": file_rel_path, "type": "PRONOUN", "match": pron["text"]}
                    )
        except Exception:
            pass

    _PRESIDIO_EXTS = {".txt", ".md", ".csv", ".json", ".yml", ".yaml", ".py", ".tf", "Dockerfile"}
    if presidio_analyzer and path.suffix in _PRESIDIO_EXTS:
        try:
            results = presidio_analyzer.analyze(
                text=content,
                language=getattr(presidio_analyzer, "_omni_language", "en"),
            )
            for res in results:
                val = content[res.start:res.end]
                if val not in ignore_tokens:
                    result["current_secrets"].append(
                        {
                            "type": f"Presidio:{res.entity_type}",
                            "file": file_rel_path,
                            "line": get_line_number_from_offset(content, res.start),
                            "match": val,
                        }
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Taint analysis (Python/JS files only, when --taint active)
    # ------------------------------------------------------------------
    if taint_enabled and path.suffix in (".py", ".js", ".mjs", ".ts", ".tsx") and result["current_secrets"]:
        for finding in result["current_secrets"]:
            try:
                taint = taint_analysis(
                    str(path),
                    finding.get("match", ""),
                    content,
                    finding.get("line", 0),
                )
                if taint.get("exploitability") in ("high", "medium"):
                    result["taint"].append({
                        "file": file_rel_path,
                        "line": finding.get("line"),
                        "token": finding.get("match", ""),
                        "exploitability": taint["exploitability"],
                        "sinks": taint.get("sinks", []),
                        "tainted_vars": taint.get("tainted_vars", []),
                        "method": taint.get("method", "none"),
                    })
            except Exception:
                pass

    if ast_filter_enabled and result["current_secrets"]:
        filtered = [
            f for f in result["current_secrets"]
            if not (f.get("line") and ast_context_filter(str(path), f["line"], enabled=True))
        ]
        result["current_secrets"] = filtered

    return result


def scan_current_tree(
    repo_dir: str,
    exclude_patterns: list[str],
    nlp_deidentifier=None,
    quiet: bool = False,
    ignore_tokens: Optional[list] = None,
    sensitive_words: Optional[list] = None,
    extract_code_blocks: bool = False,
    scan_submodules: bool = False,
    presidio_analyzer=None,
    max_file_size_kb: int = 1024,
    workers: int = 0,
    progress: bool = True,
    lang_rules_enabled: bool = False,
    ast_filter_enabled: bool = False,
    deconfuse_enabled: bool = False,
    taint_enabled: bool = False,
    stego_enabled: bool = False,
    perplexity_model=None,
) -> dict:
    """Scan the current working tree for secrets, PII, and injection attacks.

    Uses ``ThreadPoolExecutor`` for parallel file scanning.
    Set *workers=1* to force sequential execution (useful for debugging).
    """
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []

    findings: dict = {
        "suspicious_files": [],
        "current_secrets": [],
        "nlp_pii": [],
        "injections": [],
        "taint": [],
        "stego": [],
    }
    if not quiet:
        print("Scanning current working tree...", file=sys.stderr)

    max_bytes = max_file_size_kb * 1024
    file_jobs: list[tuple] = []

    for root_dir, dirs, files in os.walk(repo_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        try:
            rel_root = os.path.relpath(root_dir, repo_dir)
        except Exception:
            rel_root = "."
        if rel_root == ".":
            rel_root = ""

        active_dirs = []
        for d in dirs:
            dir_rel = os.path.join(rel_root, d).replace("\\", "/")
            if match_exclude(dir_rel, exclude_patterns) or match_exclude(
                dir_rel + "/", exclude_patterns
            ):
                continue
            active_dirs.append(d)
        dirs[:] = active_dirs

        for file in files:
            file_rel_path = os.path.join(rel_root, file).replace("\\", "/")
            if match_exclude(file_rel_path, exclude_patterns):
                continue
            path = Path(root_dir) / file
            file_jobs.append(
                (
                    path,
                    file_rel_path,
                    max_bytes,
                    ALL_SECRET_PATTERNS,
                    ignore_tokens,
                    sensitive_words,
                    extract_code_blocks,
                    nlp_deidentifier,
                    presidio_analyzer,
                    lang_rules_enabled,
                    ast_filter_enabled,
                    deconfuse_enabled,
                    taint_enabled,
                    stego_enabled,
                    perplexity_model,
                )
            )

    if workers <= 0:
        cpu_count = getattr(os, "cpu_count", lambda: 4)()
        workers = max(1, min(8, cpu_count)) if cpu_count else 4

    def _merge(res: dict) -> None:
        findings["suspicious_files"].extend(res["suspicious_files"])
        findings["current_secrets"].extend(res["current_secrets"])
        findings["nlp_pii"].extend(res["nlp_pii"])
        findings["injections"].extend(res["injections"])
        findings["taint"].extend(res.get("taint", []))
        findings["stego"].extend(res.get("stego", []))

    if workers == 1 or len(file_jobs) <= 1:
        _iter = file_jobs
        if progress and not quiet and len(file_jobs) > 1:
            try:
                from tqdm import tqdm
                _iter = tqdm(file_jobs, desc="Scanning files", unit="file", leave=True, file=sys.stderr)
            except ImportError:
                pass
        for job in _iter:
            _merge(_scan_single_file(job))
    else:
        if not quiet:
            print(f"Using {workers} workers for parallel file scan...", file=sys.stderr)
        _progress = None
        if progress and not quiet:
            try:
                from tqdm import tqdm
                _progress = tqdm(
                    total=len(file_jobs), desc="Scanning files", unit="file",
                    leave=True, file=sys.stderr,
                )
            except ImportError:
                pass

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_job = {executor.submit(_scan_single_file, job): job for job in file_jobs}
            for future in as_completed(future_to_job):
                try:
                    res = future.result()
                except Exception:
                    res = {"suspicious_files": [], "current_secrets": [], "nlp_pii": [], "injections": [], "taint": [], "stego": []}
                _merge(res)
                if _progress:
                    _progress.update(1)
        if _progress:
            _progress.close()

    if scan_submodules:
        submodules = get_submodules(repo_dir)
        for sub in submodules:
            sub_dir = Path(repo_dir) / sub
            if sub_dir.exists():
                if not quiet:
                    print(f"Scanning submodule current tree: {sub}...", file=sys.stderr)
                sub_findings = scan_current_tree(
                    str(sub_dir),
                    exclude_patterns,
                    nlp_deidentifier,
                    quiet=quiet,
                    ignore_tokens=ignore_tokens,
                    sensitive_words=sensitive_words,
                    extract_code_blocks=extract_code_blocks,
                    scan_submodules=True,
                    presidio_analyzer=presidio_analyzer,
                    max_file_size_kb=max_file_size_kb,
                    workers=workers,
                    progress=progress,
                    lang_rules_enabled=lang_rules_enabled,
                    ast_filter_enabled=ast_filter_enabled,
                    deconfuse_enabled=deconfuse_enabled,
                    taint_enabled=taint_enabled,
                    stego_enabled=stego_enabled,
                    perplexity_model=perplexity_model,
                )
                for s in sub_findings["current_secrets"]:
                    s["file"] = f"{sub}/{s['file']}"
                    findings["current_secrets"].append(s)
                for f_name in sub_findings["suspicious_files"]:
                    findings["suspicious_files"].append(f"{sub}/{f_name}")
                for p in sub_findings["nlp_pii"]:
                    p["file"] = f"{sub}/{p['file']}"
                    findings["nlp_pii"].append(p)

    from ..reporters.base import deduplicate_findings
    findings["current_secrets"] = deduplicate_findings(
        findings["current_secrets"], ("type", "file", "line", "match")
    )
    findings["injections"] = deduplicate_findings(
        findings["injections"], ("type", "file", "line", "match")
    )
    findings["nlp_pii"] = deduplicate_findings(
        findings["nlp_pii"], ("type", "file", "match")
    )
    return findings
