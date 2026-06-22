# SPDX-License-Identifier: MIT
"""External tool integration: Gitleaks and Trivy.

Shells out to gitleaks and/or trivy if they are installed, parses their
JSON output, and merges findings into the standard report format.

Activated via --gitleaks and --trivy flags.  Gracefully degrades with
install instructions if the tools are not found.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys


def _find_tool(name: str) -> str | None:
    """Locate *name* on PATH. Returns path or None."""
    return shutil.which(name)


def run_gitleaks(repo_dir: str, quiet: bool = False) -> list[dict]:
    """Run gitleaks detect and return standardised findings.

    Returns list of dicts with keys: file, line, type, match, rule.
    """
    gitleaks = _find_tool("gitleaks")
    if not gitleaks:
        if not quiet:
            print(
                "Warning: 'gitleaks' not found on PATH. Skipping.\n"
                "Install: https://github.com/gitleaks/gitleaks#installing",
                file=sys.stderr,
            )
        return []

    if not quiet:
        print("Running Gitleaks scan...", file=sys.stderr)

    try:
        result = subprocess.run(
            [
                gitleaks,
                "detect",
                "--source",
                repo_dir,
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--no-git",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=repo_dir,
        )
        # gitleaks exits 1 when leaks are found (that's expected)
        if result.stdout.strip():
            data = json.loads(result.stdout)
            findings: list[dict] = []
            for item in (
                data if isinstance(data, list) else data.get("Findings", data.get("findings", []))
            ):
                findings.append(
                    {
                        "file": item.get("File") or item.get("file", ""),
                        "line": item.get("StartLine") or item.get("line", 0),
                        "type": f"Gitleaks:{item.get('RuleID', item.get('rule', 'unknown'))}",
                        "match": item.get("Secret") or item.get("Match", ""),
                        "rule": item.get("Description") or item.get("rule", ""),
                        "severity": item.get("Severity", "UNKNOWN"),
                    }
                )
            return findings
    except subprocess.TimeoutExpired:
        if not quiet:
            print("Warning: Gitleaks timed out after 120s", file=sys.stderr)
    except json.JSONDecodeError:
        if not quiet:
            print("Warning: Could not parse Gitleaks output", file=sys.stderr)
    except Exception as e:
        if not quiet:
            print(f"Warning: Gitleaks error: {e}", file=sys.stderr)

    return []


def run_trivy(repo_dir: str, quiet: bool = False) -> list[dict]:
    """Run trivy filesystem scan and return standardised findings.

    Returns list of dicts with keys: file, line, type, match, severity.
    """
    trivy = _find_tool("trivy")
    if not trivy:
        if not quiet:
            print(
                "Warning: 'trivy' not found on PATH. Skipping.\n"
                "Install: https://github.com/aquasecurity/trivy#install",
                file=sys.stderr,
            )
        return []

    if not quiet:
        print("Running Trivy secret scan...", file=sys.stderr)

    try:
        result = subprocess.run(
            [trivy, "fs", "--format", "json", "--scanners", "secret", "--quiet", str(repo_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            findings: list[dict] = []
            results = data.get("Results", [])
            for res in results:
                secrets = res.get("Secrets", [])
                for s in secrets:
                    findings.append(
                        {
                            "file": res.get("Target", ""),
                            "line": s.get("StartLine", 0),
                            "type": f"Trivy:{s.get('RuleID', 'unknown')}",
                            "match": s.get("Title", ""),
                            "severity": s.get("Severity", "UNKNOWN"),
                        }
                    )
            return findings
    except subprocess.TimeoutExpired:
        if not quiet:
            print("Warning: Trivy timed out after 120s", file=sys.stderr)
    except json.JSONDecodeError:
        if not quiet:
            print("Warning: Could not parse Trivy output", file=sys.stderr)
    except Exception as e:
        if not quiet:
            print(f"Warning: Trivy error: {e}", file=sys.stderr)

    return []
