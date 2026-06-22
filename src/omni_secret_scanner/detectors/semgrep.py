# SPDX-License-Identifier: MIT
"""Semgrep SAST static analysis integration."""

import json
import shutil
import subprocess
import sys


def run_semgrep_scan(repo_dir: str, quiet: bool = False) -> list[dict]:
    """Run ``semgrep scan --config=auto`` and return structured findings.

    Returns an empty list when Semgrep is not installed or the scan fails.
    """
    findings: list[dict] = []
    semgrep_exe = shutil.which("semgrep")
    if not semgrep_exe:
        if not quiet:
            print(
                "Warning: 'semgrep' CLI is not installed. SAST scanning will be skipped.\n"
                "Install with: pip install semgrep",
                file=sys.stderr,
            )
        return findings

    if not quiet:
        print("Running Semgrep AST Static Analysis scan...", file=sys.stderr)
    try:
        result = subprocess.run(
            [semgrep_exe, "scan", "--config=auto", "--json", "--quiet"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            errors="replace",
        )
        if result.returncode in (0, 1) and result.stdout:
            try:
                data = json.loads(result.stdout)
                for res in data.get("results", []):
                    findings.append(
                        {
                            "file": res.get("path"),
                            "line": res.get("start", {}).get("line"),
                            "rule": res.get("check_id"),
                            "message": res.get("extra", {}).get("message"),
                            "match": res.get("extra", {}).get("lines"),
                            "severity": res.get("extra", {}).get("severity"),
                        }
                    )
            except Exception:
                pass
    except Exception as e:
        if not quiet:
            print(f"Warning: Error running Semgrep: {e}", file=sys.stderr)
    return findings
