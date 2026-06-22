# SPDX-License-Identifier: MIT
"""Pattern libraries for rgt-codebase-scanner."""

from .ai_keys import AI_PATTERNS
from .injection import INJECTION_PATTERNS
from .lang_rules import (
    FILE_EXT_TO_LANG_RULES,
    LANG_RULES_JAVA,
    LANG_RULES_NODEJS,
    LANG_RULES_PYTHON,
    get_lang_rules_for_file,
)
from .pii import CUSTOM_PII_PATTERNS, PII_IGNORE_VALUES
from .secrets import CUSTOM_SECRET_PATTERNS, GITROB_CONTENT_PATTERNS, GITROB_SUSPICIOUS_FILES

ALL_SECRET_PATTERNS: dict[str, str] = {
    **CUSTOM_SECRET_PATTERNS,
    **GITROB_CONTENT_PATTERNS,
    **AI_PATTERNS,
}

__all__ = [
    "CUSTOM_SECRET_PATTERNS",
    "GITROB_CONTENT_PATTERNS",
    "GITROB_SUSPICIOUS_FILES",
    "CUSTOM_PII_PATTERNS",
    "AI_PATTERNS",
    "INJECTION_PATTERNS",
    "LANG_RULES_PYTHON",
    "LANG_RULES_NODEJS",
    "LANG_RULES_JAVA",
    "FILE_EXT_TO_LANG_RULES",
    "get_lang_rules_for_file",
    "ALL_SECRET_PATTERNS",
]
