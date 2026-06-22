# SPDX-License-Identifier: MIT
"""Configuration loading: TOML project config and external pattern packs."""

import json
import re
import sys
from pathlib import Path


def load_toml_config(path: str | None = None, repo_dir: str | None = None) -> dict:
    """Load scanner configuration from a TOML file.

    Auto-detects ``.omni-scan.toml`` in *repo_dir* when no explicit path is
    given.  Returns a dict with config keys; CLI flags always take precedence.
    Gracefully degrades (returns ``{}``) when no TOML library is available.
    """
    config: dict = {}

    if path:
        toml_path = Path(path)
    elif repo_dir:
        toml_path = Path(repo_dir) / ".omni-scan.toml"
    else:
        toml_path = Path(".omni-scan.toml")

    if not toml_path.exists():
        return config

    toml_data = None
    for lib_name in ("tomllib", "tomli", "toml"):
        try:
            mod = __import__(lib_name)
            raw = toml_path.read_text(encoding="utf-8")
            if lib_name in ("tomllib", "tomli"):
                toml_data = mod.loads(raw)
            else:
                toml_data = mod.loads(raw)
            break
        except (ImportError, AttributeError):
            continue
        except Exception:
            continue

    if toml_data is None:
        return config

    scanner_cfg = toml_data.get("scanner", {})
    for key in (
        "entropy_threshold", "max_file_size_kb", "fast", "quiet",
        "mask", "sanitize", "validate", "all_branches", "progress", "context_lines",
    ):
        if key in scanner_cfg:
            config[key] = scanner_cfg[key]

    exclude_cfg = toml_data.get("exclude", {})
    if "patterns" in exclude_cfg:
        config["exclude_patterns"] = exclude_cfg["patterns"]
    if "tokens" in exclude_cfg:
        config["exclude_tokens"] = exclude_cfg["tokens"]

    custom_cfg = toml_data.get("custom_patterns", {})
    if custom_cfg:
        config["custom_secrets"] = custom_cfg.get("secrets", [])
        config["custom_pii"] = custom_cfg.get("pii", [])
        if isinstance(config["custom_secrets"], dict):
            config["custom_secrets"] = list(config["custom_secrets"].values())
        if isinstance(config["custom_pii"], dict):
            config["custom_pii"] = list(config["custom_pii"].values())

    report_cfg = toml_data.get("report", {})
    if "format" in report_cfg:
        config["format"] = report_cfg["format"]
    if "output" in report_cfg:
        config["output"] = report_cfg["output"]

    return config


def load_external_patterns(path: str, quiet: bool = False) -> tuple[dict, dict]:
    """Load custom secret and PII patterns from a YAML or JSON file.

    Returns ``(secret_patterns_dict, pii_patterns_dict)``.
    """
    extra_secrets: dict = {}
    extra_pii: dict = {}
    p = Path(path)
    if not p.exists():
        print(f"Warning: Pattern file not found: {path}", file=sys.stderr)
        return extra_secrets, extra_pii
    try:
        if p.suffix in (".yaml", ".yml"):
            import yaml  # type: ignore
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        else:
            data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Warning: Could not parse pattern file {path}: {e}", file=sys.stderr)
        return extra_secrets, extra_pii
    for entry in data.get("secrets", []):
        try:
            re.compile(entry["pattern"])
            extra_secrets[entry["name"]] = entry["pattern"]
        except re.error as e:
            if not quiet:
                print(f"Warning: Bad regex in pattern '{entry.get('name')}': {e}", file=sys.stderr)
    for entry in data.get("pii", []):
        try:
            re.compile(entry["pattern"])
            extra_pii[entry["name"]] = entry["pattern"]
        except re.error as e:
            if not quiet:
                print(
                    f"Warning: Bad PII regex in pattern '{entry.get('name')}': {e}",
                    file=sys.stderr,
                )
    if not quiet:
        print(
            f"Loaded {len(extra_secrets)} secret patterns and "
            f"{len(extra_pii)} PII patterns from {path}",
            file=sys.stderr,
        )
    return extra_secrets, extra_pii
