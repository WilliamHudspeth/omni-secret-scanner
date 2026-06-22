# SPDX-License-Identifier: MIT
"""Tree-sitter AST context filtering to remove false positives in test/mock/comment code."""

from pathlib import Path

TREESITTER_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".cs": "c_sharp",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
}

_FILTER_NODE_TYPES: frozenset[str] = frozenset({"comment", "block_comment", "line_comment"})
_FILTER_FUNCTION_NAMES: frozenset[str] = frozenset(
    {
        "test_",
        "mock_",
        "fake_",
        "stub_",
        "dummy_",
        "setup",
        "teardown",
        "setUp",
        "tearDown",
        "beforeEach",
        "afterEach",
        "beforeAll",
        "afterAll",
        "describe",
        "it(",
        "spec_",
        "example_",
    }
)

_treesitter_cache: dict = {}


def _init_treesitter() -> bool:
    if _treesitter_cache.get("_checked"):
        return _treesitter_cache.get("_available", False)
    _treesitter_cache["_checked"] = True
    try:
        import tree_sitter  # noqa: F401

        _treesitter_cache["_available"] = True
        return True
    except ImportError:
        _treesitter_cache["_available"] = False
        return False


def _get_treesitter_parser(filepath: str):
    """Return (parser, language_obj) for *filepath*, or (None, None) on failure."""
    import os

    if not _init_treesitter():
        return None, None
    ext = os.path.splitext(filepath)[1].lower()
    lang_name = TREESITTER_LANG_MAP.get(ext)
    if not lang_name:
        return None, None
    if lang_name in _treesitter_cache:
        return _treesitter_cache[lang_name]
    try:
        import tree_sitter

        lang_pkg = None
        for pkg_name in (f"tree_sitter_{lang_name}", f"tree-sitter-{lang_name}"):
            try:
                lang_pkg = __import__(pkg_name.replace("-", "_"), fromlist=["language"])
                break
            except ImportError:
                continue
        if lang_pkg is None:
            return None, None
        language = tree_sitter.Language(lang_pkg.language())
        parser = tree_sitter.Parser()
        parser.set_language(language)
        _treesitter_cache[lang_name] = (parser, language)
        return parser, language
    except Exception:
        return None, None


def ast_context_filter(filepath: str, line_number: int, enabled: bool = True) -> bool:
    """Return True if the match at *line_number* is in a safe context (test/mock/comment).

    When True, the caller should treat the finding as a false positive and discard it.
    Returns False (keep the finding) on any error or when *enabled* is False.
    """
    if not enabled:
        return False
    parser, _language = _get_treesitter_parser(filepath)
    if parser is None:
        return False
    try:
        file_path = Path(filepath)
        if not file_path.exists():
            return False
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:
        return False

    lines = source.split("\n")
    if line_number < 1 or line_number > len(lines):
        return False
    byte_offset = sum(len(lines[i].encode("utf-8")) + 1 for i in range(line_number - 1))
    node = tree.root_node.descendant_for_byte_range(byte_offset, byte_offset + 1)
    if node is None:
        return False

    current = node
    while current is not None:
        if current.type in _FILTER_NODE_TYPES:
            return True
        if current.type in (
            "function_definition",
            "method_definition",
            "function_declaration",
            "arrow_function",
            "function",
        ):
            name_node = current.child_by_field_name("name")
            if name_node:
                func_name = source[name_node.start_byte : name_node.end_byte]
                if any(pat in func_name for pat in _FILTER_FUNCTION_NAMES):
                    return True
        if current.type in ("class_definition", "class_declaration"):
            name_node = current.child_by_field_name("name")
            if name_node:
                class_name = source[name_node.start_byte : name_node.end_byte]
                if any(pat in class_name for pat in _FILTER_FUNCTION_NAMES):
                    return True
        current = current.parent
    return False
