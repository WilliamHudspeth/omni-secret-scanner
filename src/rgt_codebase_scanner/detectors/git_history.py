# SPDX-License-Identifier: MIT
"""Git history, reflog, diff, and stash scanning."""

import re
import subprocess
import sys
from pathlib import Path

from ..patterns import (
    ALL_SECRET_PATTERNS,
    CUSTOM_PII_PATTERNS,
    INJECTION_PATTERNS,
)
from ..utils.entropy import is_ignored_entropy_token, shannon_entropy
from ..utils.git import (
    extract_added_lines,
    get_submodules,
    scan_commit_messages,
)
from .snippet import scan_obfuscated_secrets


def scan_history(
    exclude_patterns: list[str],
    all_branches: bool = False,
    quiet: bool = False,
    entropy_threshold: float = 3.8,
    ignore_tokens: list | None = None,
    sensitive_words: list | None = None,
    since: str | None = None,
    scan_submodules: bool = False,
    repo_cwd: str | None = None,
) -> dict:
    """Scan entire git history (all commits, diffs, and commit messages)."""
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []

    findings: dict = {
        "secrets": [],
        "pii": [],
        "entropy": [],
        "commits": [],
        "injections": [],
    }

    git_dir = Path(repo_cwd) / ".git" if repo_cwd else Path(".git")
    parent_git_dir = Path(repo_cwd) / "../.git" if repo_cwd else Path("../.git")
    if not git_dir.exists() and not parent_git_dir.exists():
        if not quiet:
            print(
                "Warning: Not running inside a Git repository. Skipping history scan.",
                file=sys.stderr,
            )
        return findings

    if not quiet:
        print(
            f"Scanning file history{' (all branches)' if all_branches else ''}...",
            file=sys.stderr,
        )

    cmd = ["git", "log", "-p", "--no-color"]
    if since:
        if any(x in since for x in ("-", "/", ":", "ago", "week", "day", "month", "year")):
            cmd.append(f"--since={since}")
        else:
            cmd.append(f"{since}..")
    if all_branches:
        cmd.append("--all")

    result = subprocess.run(cmd, cwd=repo_cwd, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        if not quiet:
            print("Fatal: not a git repository or git error", file=sys.stderr)
        return findings

    added_lines = extract_added_lines(result.stdout, exclude_patterns)

    for file_path, line_no, content in added_lines:
        for name, pattern in ALL_SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, content):
                    val = m.group(0).strip()
                    if val in ignore_tokens:
                        continue
                    findings["secrets"].append(
                        {"type": name, "file": file_path, "line": line_no, "match": val}
                    )
            except re.error:
                pass

        for hit in scan_obfuscated_secrets(content, file_path, ALL_SECRET_PATTERNS):
            if hit["match"] not in ignore_tokens:
                hit["line"] = line_no
                findings["secrets"].append(hit)

        for word in sensitive_words:
            if word.lower() in content.lower():
                for m in re.finditer(re.escape(word), content, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        findings["secrets"].append(
                            {
                                "type": f"Sensitive Word: {word}",
                                "file": file_path,
                                "line": line_no,
                                "match": val,
                            }
                        )

        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, content):
                val = m.group(0).strip()
                if val in ignore_tokens:
                    continue
                findings["pii"].append(
                    {"type": name, "file": file_path, "line": line_no, "match": val}
                )

        for inj_name, inj_pattern in INJECTION_PATTERNS.items():
            try:
                for m in re.finditer(inj_pattern, content):
                    findings["injections"].append(
                        {
                            "type": f"INJECTION:{inj_name}",
                            "file": file_path,
                            "line": line_no,
                            "match": m.group(0).strip(),
                        }
                    )
            except re.error:
                pass

        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", content)
        for m in candidates:
            token = m.group(0)
            if token.isdigit() or is_ignored_entropy_token(token) or token in ignore_tokens:
                continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["entropy"].append(
                    {
                        "file": file_path,
                        "line": line_no,
                        "token": token,
                        "entropy": round(entropy, 2),
                    }
                )

    if not quiet:
        print("Scanning commit messages...", file=sys.stderr)

    for commit_hash, message in scan_commit_messages(all_branches, repo_cwd=repo_cwd):
        for name, pattern in ALL_SECRET_PATTERNS.items():
            for m in re.finditer(pattern, message):
                val = m.group(0).strip()
                if val in ignore_tokens:
                    continue
                findings["commits"].append({"type": name, "commit": commit_hash[:8], "match": val})

        for hit in scan_obfuscated_secrets(message, commit_hash[:8], ALL_SECRET_PATTERNS):
            if hit["match"] not in ignore_tokens:
                findings["commits"].append(
                    {"type": hit["type"], "commit": commit_hash[:8], "match": hit["match"]}
                )

        for word in sensitive_words:
            if word.lower() in message.lower():
                for m in re.finditer(re.escape(word), message, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        findings["commits"].append(
                            {
                                "type": f"Sensitive Word: {word}",
                                "commit": commit_hash[:8],
                                "match": val,
                            }
                        )

        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, message):
                val = m.group(0).strip()
                if val in ignore_tokens:
                    continue
                findings["commits"].append(
                    {"type": f"PII:{name}", "commit": commit_hash[:8], "match": val}
                )

        for inj_name, inj_pattern in INJECTION_PATTERNS.items():
            try:
                for m in re.finditer(inj_pattern, message):
                    findings["injections"].append(
                        {
                            "type": f"INJECTION:{inj_name}",
                            "commit": commit_hash[:8],
                            "match": m.group(0).strip(),
                        }
                    )
            except re.error:
                pass

        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", message)
        for m in candidates:
            token = m.group(0)
            if token.isdigit() or is_ignored_entropy_token(token) or token in ignore_tokens:
                continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["commits"].append(
                    {
                        "type": "ENTROPY",
                        "commit": commit_hash[:8],
                        "token": token,
                        "entropy": round(entropy, 2),
                    }
                )

    if scan_submodules:
        submodules = get_submodules(repo_cwd or ".")
        for sub in submodules:
            sub_dir = Path(repo_cwd) / sub if repo_cwd else Path(sub)
            if sub_dir.exists():
                if not quiet:
                    print(f"Scanning submodule history: {sub}...", file=sys.stderr)
                sub_history = scan_history(
                    exclude_patterns=exclude_patterns,
                    all_branches=all_branches,
                    quiet=quiet,
                    entropy_threshold=entropy_threshold,
                    ignore_tokens=ignore_tokens,
                    sensitive_words=sensitive_words,
                    since=since,
                    scan_submodules=True,
                    repo_cwd=str(sub_dir),
                )
                for s in sub_history["secrets"]:
                    s["file"] = f"{sub}/{s['file']}"
                    findings["secrets"].append(s)
                for p in sub_history["pii"]:
                    p["file"] = f"{sub}/{p['file']}"
                    findings["pii"].append(p)
                for e in sub_history["entropy"]:
                    e["file"] = f"{sub}/{e['file']}"
                    findings["entropy"].append(e)
                for c in sub_history["commits"]:
                    c["commit"] = f"{sub}:{c['commit']}"
                    findings["commits"].append(c)

    return findings


def scan_reflog(
    exclude_patterns: list[str],
    quiet: bool = False,
    entropy_threshold: float = 3.8,
    ignore_tokens: list | None = None,
    sensitive_words: list | None = None,
) -> dict:
    """Scan git reflog to recover force-pushed and deleted commits."""
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []

    findings: dict = {"secrets": [], "pii": [], "entropy": [], "injections": []}
    if not Path(".git").exists() and not Path("../.git").exists():
        return findings

    if not quiet:
        print("Scanning Git reflog history...", file=sys.stderr)

    result = subprocess.run(
        ["git", "reflog", "show", "--all", "-p", "--no-color"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode != 0:
        return findings

    added_lines = extract_added_lines(result.stdout, exclude_patterns)
    for file_path, line_no, content in added_lines:
        reflog_path = f"reflog:{file_path}"
        for name, pattern in ALL_SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, content):
                    val = m.group(0).strip()
                    if val in ignore_tokens:
                        continue
                    findings["secrets"].append(
                        {"type": name, "file": reflog_path, "line": line_no, "match": val}
                    )
            except re.error:
                pass

        for hit in scan_obfuscated_secrets(content, reflog_path, ALL_SECRET_PATTERNS):
            if hit["match"] not in ignore_tokens:
                hit["line"] = line_no
                findings["secrets"].append(hit)

        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, content):
                val = m.group(0).strip()
                if val in ignore_tokens:
                    continue
                findings["pii"].append(
                    {"type": name, "file": reflog_path, "line": line_no, "match": val}
                )

        for inj_name, inj_pattern in INJECTION_PATTERNS.items():
            try:
                for m in re.finditer(inj_pattern, content):
                    findings["injections"].append(
                        {
                            "type": f"INJECTION:{inj_name}",
                            "file": reflog_path,
                            "line": line_no,
                            "match": m.group(0).strip(),
                        }
                    )
            except re.error:
                pass

        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", content)
        for m in candidates:
            token = m.group(0)
            if token.isdigit() or is_ignored_entropy_token(token) or token in ignore_tokens:
                continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["entropy"].append(
                    {
                        "file": reflog_path,
                        "line": line_no,
                        "token": token,
                        "entropy": round(entropy, 2),
                    }
                )

    return findings


def scan_diff(
    base_ref: str,
    exclude_patterns: list[str],
    quiet: bool = False,
    entropy_threshold: float = 3.8,
    ignore_tokens: list | None = None,
    sensitive_words: list | None = None,
) -> dict:
    """Scan only lines added since *base_ref* (incremental CI/CD mode)."""
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []

    findings: dict = {"secrets": [], "pii": [], "entropy": [], "commits": [], "injections": []}
    if not Path(".git").exists() and not Path("../.git").exists():
        return findings
    if not quiet:
        print(f"Scanning diff since {base_ref}...", file=sys.stderr)

    cmd = ["git", "diff", f"{base_ref}...HEAD", "--unified=0", "--no-color"]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        cmd = ["git", "diff", base_ref, "HEAD", "--unified=0", "--no-color"]
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if result.returncode != 0:
            return findings

    added_lines = extract_added_lines(result.stdout, exclude_patterns)
    for file_path, line_no, content in added_lines:
        for name, pattern in ALL_SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, content):
                    val = m.group(0).strip()
                    if val in ignore_tokens:
                        continue
                    findings["secrets"].append(
                        {"type": name, "file": file_path, "line": line_no, "match": val}
                    )
            except re.error:
                pass
        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, content):
                val = m.group(0).strip()
                if val in ignore_tokens:
                    continue
                findings["pii"].append(
                    {"type": name, "file": file_path, "line": line_no, "match": val}
                )
        for inj_name, inj_pattern in INJECTION_PATTERNS.items():
            try:
                for m in re.finditer(inj_pattern, content):
                    findings["injections"].append(
                        {
                            "type": f"INJECTION:{inj_name}",
                            "file": file_path,
                            "line": line_no,
                            "match": m.group(0).strip(),
                        }
                    )
            except re.error:
                pass
        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", content)
        for m in candidates:
            token = m.group(0)
            if token.isdigit() or is_ignored_entropy_token(token) or token in ignore_tokens:
                continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["entropy"].append(
                    {
                        "file": file_path,
                        "line": line_no,
                        "token": token,
                        "entropy": round(entropy, 2),
                    }
                )
    return findings


def scan_stash(
    exclude_patterns: list[str],
    quiet: bool = False,
    entropy_threshold: float = 3.8,
    ignore_tokens: list | None = None,
    sensitive_words: list | None = None,
) -> dict:
    """Scan all git stash entries for secrets."""
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []

    findings: dict = {"secrets": [], "pii": [], "entropy": [], "commits": [], "injections": []}
    if not Path(".git").exists() and not Path("../.git").exists():
        return findings

    stash_list = subprocess.run(
        ["git", "stash", "list"], capture_output=True, text=True, errors="replace"
    )
    if stash_list.returncode != 0 or not stash_list.stdout.strip():
        return findings

    stash_entries = [
        line.split(":")[0].strip() for line in stash_list.stdout.splitlines() if line.strip()
    ]
    if not quiet:
        print(f"Scanning {len(stash_entries)} stash entries...", file=sys.stderr)

    for stash_ref in stash_entries:
        result = subprocess.run(
            ["git", "stash", "show", "-p", stash_ref, "--no-color"],
            capture_output=True,
            text=True,
            errors="replace",
        )
        if result.returncode != 0:
            continue
        added_lines = extract_added_lines(result.stdout, exclude_patterns)
        for file_path, line_no, content in added_lines:
            src = f"stash:{stash_ref}:{file_path}"
            for name, pattern in ALL_SECRET_PATTERNS.items():
                try:
                    for m in re.finditer(pattern, content):
                        val = m.group(0).strip()
                        if val in ignore_tokens:
                            continue
                        findings["secrets"].append(
                            {"type": name, "file": src, "line": line_no, "match": val}
                        )
                except re.error:
                    pass
            for name, pattern in CUSTOM_PII_PATTERNS.items():
                for m in re.finditer(pattern, content):
                    val = m.group(0).strip()
                    if val in ignore_tokens:
                        continue
                    findings["pii"].append(
                        {"type": name, "file": src, "line": line_no, "match": val}
                    )
            for inj_name, inj_pattern in INJECTION_PATTERNS.items():
                try:
                    for m in re.finditer(inj_pattern, content):
                        findings["injections"].append(
                            {
                                "type": f"INJECTION:{inj_name}",
                                "file": src,
                                "line": line_no,
                                "match": m.group(0).strip(),
                            }
                        )
                except re.error:
                    pass
    return findings
