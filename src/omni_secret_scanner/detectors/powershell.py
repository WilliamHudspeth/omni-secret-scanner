# SPDX-License-Identifier: MIT
"""PowerShell cross-check for OS-level regex validation."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Optional


def run_ps_crosscheck(
    repo_dir: str,
    quiet: bool = False,
    ignore_tokens: Optional[list] = None,
) -> list[dict]:
    """Run a PowerShell script to cross-validate regex-based detections.

    Returns a list of finding dicts with keys ``File``, ``Type``, ``Match``.
    Returns an empty list when PowerShell is not available.
    """
    if ignore_tokens is None:
        ignore_tokens = []

    ps_exe = shutil.which("pwsh") or shutil.which("powershell")
    if not ps_exe:
        if not quiet:
            print(
                "Warning: Neither 'pwsh' nor 'powershell' found on PATH. "
                "Skipping PowerShell cross-check.",
                file=sys.stderr,
            )
        return []

    if not quiet:
        print(f"Running PowerShell Cross-Check using {ps_exe}...", file=sys.stderr)

    ps_script = r"""
$gitDir = [IO.Path]::DirectorySeparatorChar + '.git' + [IO.Path]::DirectorySeparatorChar
$fileList = Get-ChildItem -Path "{repo_dir}" -Recurse -File |
    Where-Object {{ $_.FullName.Contains($gitDir) -ne $true }}
$findings = @()

foreach ($file in $fileList) {{
    switch -Regex ($file.Extension) {{
        "txt|csv|md|json|yml|yaml|env|py|xml" {{
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "(?!000|666|9\d{{2}})\d{{3}}[-\s]?(?!00)\d{{2}}[-\s]?(?!0000)\d{{4}}") {{
                $findings += [PSCustomObject]@{{
                    File  = $file.FullName
                    Type  = "SSN (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
            if ($content -match "AKIA[0-9A-Z]{{16}}") {{
                $findings += [PSCustomObject]@{{
                    File  = $file.FullName
                    Type  = "AWS API Key (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
            if ($content -match "AIza[0-9A-Za-z\-_]{{35}}") {{
                $findings += [PSCustomObject]@{{
                    File  = $file.FullName
                    Type  = "Google API Key (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
            if ($content -match "[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{{2,}}") {{
                $findings += [PSCustomObject]@{{
                    File  = $file.FullName
                    Type  = "Email (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
        }}
    }}
}}
$findings | ConvertTo-Json -Compress
"""
    safe_repo_dir = str(repo_dir).replace("\\", "\\\\")
    with tempfile.NamedTemporaryFile(
        suffix=".ps1", delete=False, mode="w", encoding="utf-8"
    ) as tf:
        tf.write(ps_script.format(repo_dir=safe_repo_dir))
        temp_script_path = tf.name

    try:
        result = subprocess.run(
            [ps_exe, "-ExecutionPolicy", "Bypass", "-File", temp_script_path],
            capture_output=True,
            text=True,
        )
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return [p for p in data if p.get("Match") not in ignore_tokens]
            except json.JSONDecodeError:
                return []
        return []
    finally:
        try:
            os.unlink(temp_script_path)
        except Exception:
            pass
