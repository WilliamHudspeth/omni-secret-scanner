# SPDX-License-Identifier: MIT
"""Language-specific heuristic rule packs for detecting hardcoded secrets."""

import os as _os

LANG_RULES_PYTHON: dict[str, str] = {
    "PYTHON_HARDCODED_OS_ENVIRON": r'os\.environ\[[\'"]\w+[\'"]\]\s*=\s*[\'"]([^\'"]{6,})[\'"]',
    "PYTHON_DOTENV_ASSIGNMENT": r'(?:load_dotenv|dotenv_values)\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*#',
    "PYTHON_FLASK_SECRET": r'app\.config\[[\'"]SECRET_KEY[\'"]\]\s*=\s*[\'"]([^\'"]{6,})[\'"]',
    "PYTHON_DJANGO_SECRET": r'SECRET_KEY\s*=\s*[\'"]([^\'"]{10,})[\'"]',
    "PYTHON_REQUESTS_AUTH_HEADER": r'headers\s*=\s*\{[^}]*[\'"]Authorization[\'"][^}]*[\'"]([^\'"]{10,})[\'"]',
    "PYTHON_LOGGING_CREDENTIALS": r'log(?:ging|ger)\.(?:info|debug|warning)\(\s*[\'"].*?(?:password|token|secret|key).*?[\'"]\s*[,%]',
    "PYTHON_HARDCODED_DB_URL": r'(?:DATABASE_URL|DB_URL)\s*=\s*[\'"]([a-z]+://[^@]+:[^@]+@[^\'"]+)[\'"]',
}

LANG_RULES_NODEJS: dict[str, str] = {
    "NODE_PROCESS_ENV_ASSIGN": r'process\.env\.\w+\s*=\s*[\'"]([^\'"]{6,})[\'"]',
    "NODE_DOTENV_REQUIRE": r'require\([\'"]dotenv[\'"]\)\.config\(\s*\{[^}]*path:\s*[\'"]([^\'"]+)[\'"]',
    "NODE_EXPRESS_SESSION_SECRET": r'app\.use\(session\(\s*\{[^}]*secret:\s*[\'"]([^\'"]{6,})[\'"]',
    "NODE_AXIOS_AUTH_HEADER": r'(?:axios|fetch)\([^)]*headers:\s*\{[^}]*[\'"]Authorization[\'"]\s*:\s*[\'"](\S{10,})[\'"]',
    "NODE_CONFIG_JSON_SECRET": r'config\.get\([\'"](?:secret|password|token|key)[\'"]\)',
    "NODE_ENV_FILE_COMMENTED_CRED": r'#.*\.env.*(?:secret|password|token|key)\s*=\s*\S{6,}',
}

LANG_RULES_JAVA: dict[str, str] = {
    "JAVA_SPRING_PROPERTY": r'(?:spring\.datasource\.password|spring\.security\.oauth2\.client-secret)\s*=\s*(\S{6,})',
    "JAVA_PROPERTIES_CREDENTIAL": r'(?:password|api[._-]?key|secret[._-]?key|token)\s*=\s*(\S{6,})',
    "JAVA_YAML_CREDENTIAL": r'(?:password|api-key|secret-key|token)\s*:\s*(\S{6,})',
    "JAVA_SYSTEM_GETENV_HARDCODED": r'System\.getenv\([\'"][A-Z_]+[\'"]\)\s*;\s*//\s*fallback',
    "JAVA_STRING_LITERAL_SECRET": r'String\s+\w*(?:secret|password|token|key)\w*\s*=\s*"([^"]{8,})"',
}

FILE_EXT_TO_LANG_RULES: dict[str, dict[str, str]] = {
    ".py": LANG_RULES_PYTHON,
    ".pyi": LANG_RULES_PYTHON,
    ".pyx": LANG_RULES_PYTHON,
    ".js": LANG_RULES_NODEJS,
    ".mjs": LANG_RULES_NODEJS,
    ".cjs": LANG_RULES_NODEJS,
    ".ts": LANG_RULES_NODEJS,
    ".tsx": LANG_RULES_NODEJS,
    ".jsx": LANG_RULES_NODEJS,
    ".java": LANG_RULES_JAVA,
    ".properties": LANG_RULES_JAVA,
    ".yml": LANG_RULES_JAVA,
    ".yaml": LANG_RULES_JAVA,
}


def get_lang_rules_for_file(filepath: str, enabled: bool = True) -> dict[str, str]:
    """Return language-specific heuristic patterns for a given file path.

    Returns an empty dict if enabled=False or no rules match the file extension.
    """
    if not enabled:
        return {}
    ext = _os.path.splitext(filepath)[1].lower()
    return FILE_EXT_TO_LANG_RULES.get(ext, {})
