# SPDX-License-Identifier: MIT
"""Git repository utility helpers."""

import os
import re
import subprocess
from fnmatch import fnmatch
from pathlib import Path


def get_submodules(repo_dir: str) -> list[str]:
    """Return relative paths of all git submodules in repo_dir."""
    submodules: list[str] = []
    if not (Path(repo_dir) / ".gitmodules").exists():
        return submodules
    try:
        result = subprocess.run(
            ["git", "submodule", "status"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            errors="replace",
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    submodules.append(parts[1])
    except Exception:
        pass
    return submodules


def get_line_number_from_offset(text: str, offset: int) -> int:
    """Return 1-based line number for the given byte offset in text."""
    return text[:offset].count("\n") + 1


def load_secretsignore(repo_dir: str) -> tuple[list[str], list[str]]:
    """Parse .secretsignore in repo_dir.

    Returns (ignore_file_patterns, ignore_tokens).
    """
    ignore_files: list[str] = []
    ignore_tokens: list[str] = []
    ignore_path = Path(repo_dir) / ".secretsignore"
    if ignore_path.exists():
        try:
            for line in ignore_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("token:"):
                    ignore_tokens.append(line[len("token:"):].strip())
                else:
                    ignore_files.append(line)
        except Exception:
            pass
    return ignore_files, ignore_tokens


def is_git_ignored(file_path: str) -> bool:
    """Return True if file_path is tracked by .gitignore."""
    if not Path(".git").exists() and not Path("../.git").exists():
        return False
    try:
        result = subprocess.run(["git", "check-ignore", file_path], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False


def match_exclude(path: str, exclude_patterns: list[str]) -> bool:
    """Return True if path matches any of the exclude glob patterns."""
    for pat in exclude_patterns:
        if fnmatch(path, pat) or fnmatch(Path(path).name, pat):
            return True
    return False


def extract_added_lines(
    patch_text: str, exclude_patterns: list[str]
) -> list[tuple[str, int | None, str]]:
    """Parse unified diff output and return (file, line_no, content) for added lines."""
    records: list[tuple[str, int | None, str]] = []
    current_file: str | None = None
    line_no: int | None = None
    for line in patch_text.splitlines():
        if line.startswith("diff --git"):
            current_file = None
            line_no = None
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            if m:
                line_no = int(m.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            if not current_file or match_exclude(current_file, exclude_patterns):
                continue
            records.append((current_file, line_no, line[1:]))
            if line_no is not None:
                line_no += 1
    return records


def scan_commit_messages(all_branches: bool = False, repo_cwd: str | None = None):
    """Yield (commit_hash, message) pairs from git log."""
    cmd = ["git", "log", "--pretty=format:%H%n%B%n---END---"]
    if all_branches:
        cmd.insert(2, "--all")
    result = subprocess.run(
        cmd, cwd=repo_cwd, capture_output=True, text=True, errors="replace"
    )
    if result.returncode != 0:
        import sys
        print("Error running git log for commits", file=sys.stderr)
        return
    commits = result.stdout.split("---END---\n")
    for block in commits:
        if not block.strip():
            continue
        parts = block.split("\n", 1)
        if len(parts) == 2:
            commit_hash, message = parts
            yield commit_hash.strip(), message.strip()


def extract_markdown_code_blocks(text: str) -> list[str]:
    """Extract code fence contents from Markdown text."""
    pattern = r"```(?:[a-zA-Z0-9+#-]+)?\n(.*?)\n```"
    return [m.group(1) for m in re.finditer(pattern, text, re.DOTALL)]


def get_context_snippet(
    file_path: str,
    target_line: int,
    context_lines: int,
    content: str | None = None,
) -> str:
    """Return surrounding lines of source code centred on target_line."""
    if content is None:
        try:
            if os.path.exists(file_path):
                content = Path(file_path).read_text(errors="ignore")
        except Exception:
            return ""
    if not content:
        return ""
    lines = content.splitlines()
    start = max(0, target_line - 1 - context_lines)
    end = min(len(lines), target_line + context_lines)
    snippet_lines = []
    for idx in range(start, end):
        line_no = idx + 1
        indicator = " > " if line_no == target_line else "   "
        snippet_lines.append(f"{indicator}{line_no}: {lines[idx]}")
    return "\n".join(snippet_lines)
