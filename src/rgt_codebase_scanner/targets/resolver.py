# SPDX-License-Identifier: MIT
"""Resolve a scan target to a list of (path, content_bytes) pairs."""

from __future__ import annotations

import io
import os
import sys
import tarfile
import urllib.request
from collections.abc import Iterator
from pathlib import Path

TARGET_TYPES = ("repo", "path", "url", "docker", "env", "clipboard")


def resolve_target(
    target_type: str,
    target: str | None,
    quiet: bool = False,
    exclude_patterns: list[str] | None = None,
) -> Iterator[tuple[str, bytes]]:
    """Yield ``(label, content)`` pairs for the given target type.

    ``label`` is a human-readable identifier (file path, URL, env-var name …).
    ``content`` is the raw bytes of the content to scan.
    """
    if target_type == "repo":
        return

    if target_type == "path":
        yield from _resolve_path(target or ".", quiet, exclude_patterns or [])

    elif target_type == "url":
        if not target:
            print("Error: --target-type url requires a URL argument.", file=sys.stderr)
            return
        yield from _resolve_url(target, quiet)

    elif target_type == "docker":
        if not target:
            print("Error: --target-type docker requires an image name.", file=sys.stderr)
            return
        yield from _resolve_docker(target, quiet)

    elif target_type == "env":
        yield from _resolve_env()

    elif target_type == "clipboard":
        yield from _resolve_clipboard(quiet)

    else:
        print(f"Error: Unknown target type '{target_type}'.", file=sys.stderr)


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------


def _resolve_path(root: str, quiet: bool, exclude_patterns: list[str]) -> Iterator[tuple[str, bytes]]:
    from ..utils.git import match_exclude

    p = Path(root)
    if not p.exists():
        print(f"Error: Path not found: {root}", file=sys.stderr)
        return
    if p.is_file():
        try:
            yield (str(p), p.read_bytes())
        except OSError as e:
            if not quiet:
                print(f"Warning: Could not read {p}: {e}", file=sys.stderr)
        return
    for child in sorted(p.rglob("*")):
        if not child.is_file():
            continue
        rel = str(child.relative_to(p)).replace("\\", "/")
        if match_exclude(rel, exclude_patterns):
            continue
        try:
            yield (str(child), child.read_bytes())
        except OSError as e:
            if not quiet:
                print(f"Warning: Could not read {child}: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# url
# ---------------------------------------------------------------------------


def _resolve_url(url: str, quiet: bool) -> Iterator[tuple[str, bytes]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rgt-scan/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            content = resp.read()
        yield (url, content)
    except Exception as e:
        print(f"Error fetching {url}: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# docker
# ---------------------------------------------------------------------------


def _resolve_docker(image: str, quiet: bool) -> Iterator[tuple[str, bytes]]:
    import subprocess

    if not quiet:
        print(f"Saving Docker image '{image}' …", file=sys.stderr)
    try:
        result = subprocess.run(
            ["docker", "save", image],
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError:
        print("Error: 'docker' CLI not found.", file=sys.stderr)
        return
    except subprocess.TimeoutExpired:
        print("Error: docker save timed out.", file=sys.stderr)
        return

    if result.returncode != 0:
        print(f"Error: docker save failed: {result.stderr.decode()}", file=sys.stderr)
        return

    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as outer:
        for member in outer.getmembers():
            if not member.isfile():
                continue
            f = outer.extractfile(member)
            if f is None:
                continue
            data = f.read()
            # Layer tarballs contain the actual files
            if member.name.endswith(".tar"):
                try:
                    with tarfile.open(fileobj=io.BytesIO(data)) as layer:
                        for lmember in layer.getmembers():
                            if not lmember.isfile():
                                continue
                            lf = layer.extractfile(lmember)
                            if lf is None:
                                continue
                            yield (f"{image}::{lmember.name}", lf.read())
                except tarfile.TarError:
                    yield (f"{image}::{member.name}", data)
            else:
                yield (f"{image}::{member.name}", data)


# ---------------------------------------------------------------------------
# env
# ---------------------------------------------------------------------------


def _resolve_env() -> Iterator[tuple[str, bytes]]:
    for key, value in os.environ.items():
        yield (f"env:{key}", value.encode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# clipboard
# ---------------------------------------------------------------------------


def _resolve_clipboard(quiet: bool) -> Iterator[tuple[str, bytes]]:
    try:
        import pyperclip  # noqa: PLC0415

        text = pyperclip.paste()
        yield ("clipboard", text.encode("utf-8", errors="replace"))
    except ImportError:
        print(
            "Error: 'pyperclip' is not installed. Install with: pip install pyperclip",
            file=sys.stderr,
        )
    except Exception as e:
        if not quiet:
            print(f"Error reading clipboard: {e}", file=sys.stderr)
