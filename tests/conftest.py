# SPDX-License-Identifier: MIT
"""Shared pytest fixtures for omni-secret-scanner tests."""

import pytest


@pytest.fixture
def tmp_git_repo(tmp_path):
    """Create a temporary directory initialised as a bare git repo."""
    import subprocess
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=str(tmp_path), check=True, capture_output=True,
    )
    return tmp_path
