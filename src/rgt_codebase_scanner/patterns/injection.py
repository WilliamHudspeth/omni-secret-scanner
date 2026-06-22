# SPDX-License-Identifier: MIT
"""Prompt-injection attack detection patterns."""

INJECTION_PATTERNS: dict[str, str] = {
    "IGNORE_PREVIOUS": r"(?i)(ignore\s+(all\s+)?(previous|above)\s+(instructions|commands|prompts))",
    "NEW_INSTRUCTIONS": r"(?i)(new\s+(instructions|task|command|role)\s*:)",
    "SYSTEM_OVERRIDE": r"(?i)(you\s+are\s+now\s+(a\s+)?(?!helpful)(\w+\s+){0,3}(assistant|bot|AI))",
    "DELIMITER_ATTACK": r"#{2,}\s*(instructions|system|assistant)\s*:#{2,}|<\|im_start\|>|<\|im_end\|>",
    "ROLE_SWITCH": r"(?i)(act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(?!user)(\w+\s+){0,3}(developer|admin|hacker|evil))",
    "PROMPT_LEAK_REQUEST": r"(?i)(print|show|reveal|display)\s+(your\s+)?(system\s+prompt|initial\s+instructions)",
    "ESCAPE_CONTEXT": r"(?i)(\[INST\].*\[/INST\]|<\s*\|instruction\|\s*>|<\s*\|user\|\s*>)",
    "REPEAT_AFTER_ME": r"(?i)repeat\s+(after\s+me\s*:|everything\s+I\s+say)",
    "INDIRECT_INJECTION": r"(?i)(<\s*(?:script|img|iframe|object|embed)\s[^>]*src\s*=\s*[\"'][^\"']*prompt[^\"']*[\"'])",
}
