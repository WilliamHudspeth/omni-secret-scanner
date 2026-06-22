# SPDX-License-Identifier: MIT
"""Lightweight intra-file taint analysis.

Uses tree-sitter to track how secret-bearing variables flow to
sensitive sinks (HTTP clients, subprocess calls, logging, etc.).

Activated via --taint flag.  Falls back to regex heuristics when
tree-sitter is not installed.

Supports: Python (AST), JavaScript/TypeScript (AST), generic (regex).
"""

from __future__ import annotations

import re
from pathlib import Path

# ------------------------------------------------------------------
# Sink definitions
# ------------------------------------------------------------------

PYTHON_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.Session",
    "urllib.request.urlopen",
    "httpx.get",
    "httpx.post",
    "aiohttp.ClientSession",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system",
    "os.popen",
    "open",
    "print",
    "logging.info",
    "logging.debug",
    "logging.warning",
    "logging.error",
}

JS_SINKS = {
    "fetch",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "XMLHttpRequest",
    "http.request",
    "https.request",
    "console.log",
    "console.info",
    "console.warn",
    "console.error",
    "fs.writeFile",
    "fs.appendFile",
}

# ------------------------------------------------------------------
# Regex fallback (works for any language)
# ------------------------------------------------------------------

_REGEX_SINKS = [
    r"requests\.",
    r"urllib",
    r"http\.",
    r"httpx",
    r"subprocess",
    r"os\.system",
    r"os\.popen",
    r"open\(",
    r"logging\.",
    r"fetch\(",
    r"axios",
    r"console\.log",
    r"console\.error",
    r"fs\.writeFile",
    r"java\.net\.",
    r"HttpURLConnection",
    r"curl_exec",
    r"file_put_contents",
]

# ------------------------------------------------------------------
# Tree-sitter based analysis
# ------------------------------------------------------------------

# Lazy-initialized caches
_ts_parsers: dict[str, object] = {}
_ts_available: bool | None = None


def _init_treesitter(language: str):
    """Lazy-load tree-sitter parser for *language*. Returns parser or None."""
    global _ts_available
    if language in _ts_parsers:
        return _ts_parsers.get(language)

    if _ts_available is None:
        try:
            import tree_sitter

            _ts_available = True
        except ImportError:
            _ts_available = False
            return None

    if not _ts_available:
        return None

    try:
        import tree_sitter

        lang_pkg = None
        candidates = {
            "python": ["tree_sitter_python"],
            "javascript": ["tree_sitter_javascript"],
            "typescript": ["tree_sitter_typescript"],
        }
        for candidate in candidates.get(language, []):
            try:
                lang_pkg = __import__(candidate, fromlist=["language"])
                break
            except ImportError:
                continue

        if lang_pkg is None:
            return None

        ts_lang = tree_sitter.Language(lang_pkg.language())
        parser = tree_sitter.Parser()
        parser.set_language(ts_lang)
        _ts_parsers[language] = parser
        return parser
    except Exception:
        return None


def _get_language_for_file(filepath: str) -> str | None:
    ext = Path(filepath).suffix.lower()
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    return lang_map.get(ext)


# ------------------------------------------------------------------
# Main API
# ------------------------------------------------------------------


def taint_analysis(
    filepath: str,
    token: str,
    content: str,
    line_no: int = 0,
) -> dict:
    """Analyze whether *token* (a detected secret) flows to a sensitive sink.

    Returns:
        {
            "exploitability": "high" | "medium" | "low",
            "sinks": [str, ...],
            "tainted_vars": [str, ...],
            "method": "treesitter" | "regex" | "none",
        }
    """
    result: dict = {
        "exploitability": "low",
        "sinks": [],
        "tainted_vars": [],
        "method": "none",
    }

    # Try tree-sitter first (more accurate)
    lang = _get_language_for_file(filepath)
    if lang:
        parser = _init_treesitter(lang)
        if parser is not None:
            return _ts_taint_analysis(parser, content, token, lang, result)

    # Fall back to regex heuristics
    return _regex_taint_analysis(content, token, line_no, result)


def _ts_taint_analysis(parser, content: str, token: str, lang: str, result: dict) -> dict:
    """Tree-sitter based taint tracking."""
    try:
        source_bytes = content.encode("utf-8")
        tree = parser.parse(source_bytes)
    except Exception:
        return _regex_taint_analysis(content, token, 0, result)

    root = tree.root_node
    sinks = PYTHON_SINKS if lang == "python" else JS_SINKS

    # Step 1: find variable names assigned to *token*
    var_names: list[str] = []

    def find_assignments(node):
        if node.type in ("assignment", "variable_declaration", "augmented_assignment"):
            node_text = _node_text(node, content)
            if token in node_text:
                # Extract variable name
                left = node.child_by_field_name("left")
                if left is None:
                    # For variable_declaration, try first child
                    for child in node.children:
                        if child.type in ("identifier", "variable_declarator"):
                            left = child
                            break
                if left:
                    name = _node_text(left, content).strip()
                    if name:
                        var_names.append(name)
        for child in node.children:
            find_assignments(child)

    find_assignments(root)

    if not var_names:
        return result

    result["tainted_vars"] = var_names

    # Step 2: find uses of those variables near sink calls
    found_sinks: set[str] = set()

    def find_uses(node):
        node_text = _node_text(node, content)
        # Check if this node mentions any tainted variable
        if any(v in node_text for v in var_names):
            # Walk up to find enclosing call
            p = node
            while p and p.type not in ("call", "call_expression", "new_expression"):
                p = p.parent
            if p:
                func_node = p.child_by_field_name("function")
                if func_node:
                    func_text = _node_text(func_node, content)
                    for sink in sinks:
                        if sink in func_text:
                            found_sinks.add(sink)
        for child in node.children:
            find_uses(child)

    find_uses(root)

    if found_sinks:
        result["sinks"] = sorted(found_sinks)
        result["exploitability"] = "high"
        result["method"] = "treesitter"
    elif var_names:
        result["exploitability"] = "medium"
        result["method"] = "treesitter"

    return result


def _regex_taint_analysis(content: str, token: str, line_no: int, result: dict) -> dict:
    """Regex-based taint analysis as fallback."""
    lines = content.splitlines()
    start = max(0, line_no - 5)
    end = min(len(lines), line_no + 20)
    window = "\n".join(lines[start:end])

    found_sinks: list[str] = []
    for sink_pattern in _REGEX_SINKS:
        if re.search(rf"{sink_pattern}.*?{re.escape(token)}", window, re.IGNORECASE | re.DOTALL):
            found_sinks.append(sink_pattern)

    if found_sinks:
        result["sinks"] = found_sinks[:5]  # cap at 5
        result["exploitability"] = "high"
        result["method"] = "regex"
    elif token in content:
        result["exploitability"] = "low"
        result["method"] = "regex"

    return result


def _node_text(node, source: str) -> str:
    """Extract text of a tree-sitter node from source."""
    try:
        return source[node.start_byte : node.end_byte]
    except Exception:
        return ""
