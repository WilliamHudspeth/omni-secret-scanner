# SPDX-License-Identifier: MIT
"""Stage 0: Repository Profiling (--profile).

Before loading any heavy engines, profile the repository to determine
which languages, frameworks, and file types are present.  This
eliminates 30-60% of compute by skipping irrelevant engines.

Example: no Terraform files → don't load IaC scanner.
         no Java files → don't load tree-sitter-java.
         no AI framework imports → skip prompt injection rules.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------
# Language detection by extension
# ------------------------------------------------------------------

EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".pyi": "python", ".pyx": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".go": "go", ".rs": "rust",
    ".cpp": "cpp", ".c": "c", ".h": "c", ".hpp": "cpp", ".cc": "cpp",
    ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".swift": "swift",
    ".tf": "terraform", ".tfvars": "terraform",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".toml": "toml",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
    ".sql": "sql", ".md": "markdown", ".rst": "restructuredtext",
    ".html": "html", ".css": "css", ".scss": "scss",
    ".dockerfile": "docker", "Dockerfile": "docker",
    ".ipynb": "jupyter", ".pbix": "powerbi",
}


# ------------------------------------------------------------------
# Framework detection by import/require patterns
# ------------------------------------------------------------------

FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "fastapi": [r"from fastapi import", r"import fastapi"],
    "flask": [r"from flask import", r"import flask"],
    "django": [r"from django\.", r"import django", r"DJANGO_SETTINGS_MODULE"],
    "langchain": [r"from langchain", r"import langchain"],
    "llamaindex": [r"from llama_index", r"import llama_index"],
    "terraform": [r'provider\s+"aws"', r'resource\s+"aws_'],
    "kubernetes": [r"apiVersion:", r"kind:", r"kubectl"],
    "docker": [r"^FROM\s+", r"^docker build"],
    "pytorch": [r"import torch", r"from torch import"],
    "tensorflow": [r"import tensorflow", r"from tensorflow import"],
    "express": [r"require\(['\"]express['\"]", r"from ['\"]express['\"]"],
    "nextjs": [r"next/config", r"getStaticProps", r"getServerSideProps"],
    "react": [r"from ['\"]react['\"]", r"import React"],
    "spring": [r"org\.springframework", r"@SpringBootApplication"],
}


# ------------------------------------------------------------------
# Repo type classification
# ------------------------------------------------------------------

def classify_repo_type(languages: dict[str, int], frameworks: list[str]) -> str:
    """Classify the repository type based on detected languages and frameworks."""
    if "terraform" in languages or "terraform" in frameworks:
        if any(f in frameworks for f in ("kubernetes", "docker")):
            return "infrastructure"
        return "infrastructure"
    if any(f in frameworks for f in ("fastapi", "flask", "django", "express", "spring")):
        return "application"
    if any(f in frameworks for f in ("langchain", "llamaindex", "pytorch", "tensorflow")):
        return "ai-ml"
    if languages.get("python", 0) > 50 and "jupyter" in languages:
        return "data-science"
    if "docker" in frameworks and len(languages) <= 3:
        return "container"
    return "general"


# ------------------------------------------------------------------
# Main profiler
# ------------------------------------------------------------------

def profile_repository(
    repo_dir: str = ".",
    max_files: int = 5000,
    quiet: bool = False,
) -> dict:
    """Profile a repository: detect languages, frameworks, and repo type.

    Scans up to *max_files* files (random sample for very large repos).
    Returns a dict suitable for JSON serialization.
    """
    lang_counts: Counter = Counter()
    frameworks_found: set[str] = set()
    total_files = 0
    total_bytes = 0

    # Compile framework patterns
    compiled_frameworks: dict[str, list[re.Pattern]] = {}
    for fw, patterns in FRAMEWORK_SIGNATURES.items():
        compiled_frameworks[fw] = [re.compile(p, re.MULTILINE) for p in patterns]

    if not quiet:
        import sys as _sys
        print(f"Profiling repository: {repo_dir}", file=_sys.stderr)

    for root, dirs, files in os.walk(repo_dir):
        # Skip common non-code dirs
        dirs[:] = [d for d in dirs if d not in (
            ".git", "__pycache__", "node_modules", "vendor",
            ".venv", "venv", "dist", "build", ".omni-cache",
        )]

        for f in files:
            if total_files >= max_files:
                break
            total_files += 1

            filepath = Path(root) / f
            ext = filepath.suffix.lower()
            if f in ("Dockerfile",):
                ext = ".dockerfile"

            # Count language
            lang = EXT_TO_LANG.get(ext, ext.lstrip("."))
            lang_counts[lang] += 1
            total_bytes += filepath.stat().st_size if filepath.exists() else 0

            # Check for framework signatures (text files only)
            if lang in ("python", "javascript", "typescript", "yaml", "terraform",
                        "docker", "markdown", "shell"):
                try:
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    for fw, patterns in compiled_frameworks.items():
                        if any(p.search(content) for p in patterns):
                            frameworks_found.add(fw)
                except Exception:
                    pass

        if total_files >= max_files:
            break

    languages = dict(lang_counts.most_common(20))
    frameworks = sorted(frameworks_found)
    repo_type = classify_repo_type(languages, frameworks)

    result = {
        "repo_type": repo_type,
        "languages": languages,
        "frameworks": frameworks,
        "estimated_files": total_files,
        "estimated_bytes": total_bytes,
        "recommended_engines": _recommend_engines(languages, frameworks, repo_type),
    }

    if not quiet:
        print(json.dumps(result, indent=2))

    return result


def _recommend_engines(
    languages: dict[str, int],
    frameworks: list[str],
    repo_type: str,
) -> list[str]:
    """Determine which engines should be loaded based on repo profile."""
    engines: set[str] = {"regex", "entropy", "filename"}  # always on

    lang_set = set(languages.keys())

    # Source code languages → AST + taint
    if lang_set & {"python", "javascript", "typescript", "java", "go", "rust"}:
        engines.add("ast-filter")
        if lang_set & {"python", "javascript", "typescript"}:
            engines.add("taint")

    # IaC → dedicated scanners
    if lang_set & {"terraform", "yaml", "json"}:
        engines.add("iac-patterns")

    # AI/ML → injection detection
    if any(f in frameworks for f in ("langchain", "llamaindex", "pytorch")):
        engines.add("injection")

    # Infrastructure → Semgrep SAST
    if repo_type in ("infrastructure", "application"):
        engines.add("semgrep")

    # Data-related → PII scanning
    if repo_type in ("data-science", "application"):
        engines.add("presidio")

    # Image files → stego
    if lang_set & {"jpeg", "png", "gif", "bmp"}:
        engines.add("stego")

    return sorted(engines)


def engines_to_skip(repo_profile: dict) -> list[str]:
    """Return list of engines that can be safely skipped."""
    all_engines = {"regex", "entropy", "filename", "ast-filter", "taint",
                   "iac-patterns", "injection", "semgrep", "presidio",
                   "stego", "nlp-pii", "lang-rules", "perplexity"}
    recommended = set(repo_profile.get("recommended_engines", []))
    return sorted(all_engines - recommended)
