# SPDX-License-Identifier: MIT
"""Auto-fix mode: redact secrets in-place across the entire repo.

When --fix is set, all found secrets and PII are redacted in-place,
changed files are staged, and a ready-to-run git commit command is
printed.  Always creates .bak backups before modifying files.

Activated via --fix flag.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def redact_findings_in_files(
    findings: list[dict],
    repo_dir: str,
    dry_run: bool = False,
    quiet: bool = False,
) -> list[str]:
    """Redact all *findings* in their source files.

    Each finding must have 'file', 'match', and optionally 'line' keys.
    Creates .bak backups.  Returns list of modified file paths.
    """
    from ..utils.redaction import redact_file_content

    # Group findings by file
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fpath = f.get("file", "")
        if fpath:
            by_file.setdefault(fpath, []).append(f)

    modified: list[str] = []

    for fpath, items in by_file.items():
        full_path = Path(repo_dir) / fpath
        if not full_path.exists():
            continue

        # Collect all sensitive strings for this file
        sensitive_words = list({i["match"] for i in items if i.get("match")})

        if dry_run:
            if not quiet:
                print(
                    f"  [DRY RUN] Would redact {len(sensitive_words)} matches in {fpath}",
                    file=sys.stderr,
                )
            modified.append(fpath)
            continue

        # Create backup
        bak_path = full_path.with_suffix(full_path.suffix + ".bak")
        shutil.copy2(full_path, bak_path)

        try:
            success = redact_file_content(str(full_path), sensitive_words)
            if success:
                modified.append(fpath)
                if not quiet:
                    print(f"  Redacted {len(sensitive_words)} matches in {fpath}", file=sys.stderr)
        except Exception as e:
            if not quiet:
                print(f"  Error redacting {fpath}: {e}", file=sys.stderr)
            # Restore from backup
            shutil.copy2(bak_path, full_path)

    return modified


def stage_and_suggest_commit(
    modified_files: list[str],
    repo_dir: str,
    quiet: bool = False,
) -> str:
    """Stage modified files and return a suggested git commit command.

    Returns the suggested command string.
    """
    if not modified_files:
        return ""

    # Stage files
    try:
        subprocess.run(
            ["git", "add"] + modified_files,
            cwd=repo_dir,
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass

    cmd = (
        'git commit -m "security: remove hardcoded secrets '
        f"({len(modified_files)} files) "
        '[omni-secret-scanner --fix]"'
    )

    if not quiet:
        print(f"\nStaged {len(modified_files)} files.", file=sys.stderr)
        print(f"Suggested commit:\n  {cmd}", file=sys.stderr)
        print("\nBackups saved as .bak files. Review changes before committing!", file=sys.stderr)

    return cmd
