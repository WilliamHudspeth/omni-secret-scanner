# SPDX-License-Identifier: MIT
"""Backward-compatibility shim. Use rgt_codebase_scanner directly."""

from rgt_codebase_scanner import *  # noqa: F401, F403
from rgt_codebase_scanner import (  # noqa: F401
    __author__ as __author__,
)
from rgt_codebase_scanner import (
    __license__ as __license__,
)
from rgt_codebase_scanner import (
    __version__ as __version__,
)
