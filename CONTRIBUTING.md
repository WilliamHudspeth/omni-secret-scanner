# Contributing to omni-secret-scanner

Thank you for considering a contribution!

## Quick start

```bash
git clone https://github.com/williamhudspeth/omni-secret-scanner.git
cd omni-secret-scanner
pip install -e ".[dev]"
pre-commit install
```

## Project layout

```
src/omni_secret_scanner/
├── __init__.py          # Public API + __version__
├── cli.py               # Argument parser and main() entry point
├── config/              # TOML config loader
├── detectors/           # All scanning engines
│   ├── snippet.py       # In-memory text / file scanning
│   ├── git_history.py   # Commit history scanning
│   ├── file_tree.py     # Parallel working-tree scanner
│   ├── semgrep.py       # Semgrep SAST integration
│   ├── powershell.py    # PowerShell cross-check
│   ├── nlp.py           # spaCy / Presidio NLP init helpers
│   └── ast_filter.py    # tree-sitter false-positive filter
├── patterns/            # Regex pattern dictionaries
├── reporters/           # Output formatters (text/JSON/SARIF/HTML)
├── tui/                 # Interactive terminal UI
└── utils/               # Shared helpers (entropy, git, redaction, validation)
```

## Running tests

```bash
pytest tests/
```

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Adding a new pattern

1. Choose the right module in `src/omni_secret_scanner/patterns/`.
2. Add the regex to the appropriate dict (e.g. `CUSTOM_SECRET_PATTERNS`).
3. Write a test in `tests/test_patterns.py` with a synthetic example that must
   trigger *and* a benign counter-example that must not.

## Pull request checklist

- [ ] `pytest tests/` passes
- [ ] `ruff check` and `ruff format --check` pass
- [ ] New patterns include both positive and negative test cases
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Reporting bugs

Open an issue at <https://github.com/williamhudspeth/omni-secret-scanner/issues>
and include the relevant portion of `omni-scan --format json` output (with secrets
redacted using `--mask`).
