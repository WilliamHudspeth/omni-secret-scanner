# Contributing to RGT Codebase Scanner

## Setup

```bash
git clone https://github.com/williamhudspeth/omni-secret-scanner.git
cd omni-secret-scanner
pip install -e ".[dev]"
pre-commit install
```

## Project layout

```
src/rgt_codebase_scanner/
├── cli.py               # Argument parser and entry point
├── config/              # TOML config loader
├── detectors/           # All scanning engines
│   ├── snippet.py       # In-memory text / file scanning
│   ├── git_history.py   # Commit history scanning
│   ├── file_tree.py     # Working-tree scanner
│   ├── nlp.py           # spaCy / Presidio init helpers
│   ├── ast_filter.py    # tree-sitter false-positive filter
│   └── ...
├── patterns/            # Regex pattern dicts
├── reporters/           # Output formatters (text/JSON/SARIF/HTML)
├── targets/             # Scan target resolvers (path/url/docker/env/clipboard)
├── tui/                 # Interactive terminal UI
└── utils/               # Shared helpers
```

## Tests

```bash
pytest tests/
```

## Style

```bash
ruff check src/ tests/
ruff format src/ tests/
mypy src/rgt_codebase_scanner --ignore-missing-imports
```

## Adding a pattern

1. Add the regex to the right dict in `src/rgt_codebase_scanner/patterns/`.
2. Write a test in `tests/` with a positive and a negative example.
3. Update `CHANGELOG.md`.

## PR checklist

- [ ] `pytest tests/` passes
- [ ] `ruff check` and `ruff format --check` pass
- [ ] New patterns include positive and negative test cases
- [ ] `CHANGELOG.md` updated

## Bug reports

Open an issue at <https://github.com/williamhudspeth/omni-secret-scanner/issues>.
Include the relevant portion of `rgt-scan --format json` output with `--mask`.
