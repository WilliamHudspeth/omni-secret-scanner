# Changelog

All notable changes to omni-secret-scanner are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [9.0.0] — 2026-06-22

### Changed (Breaking)
- **Package restructure**: Monolithic `scan-secrets.py` (3 936 lines) split into
  an installable `src/` layout Python package (`omni_secret_scanner`).
- Entry point renamed from `python scan-secrets.py` to `omni-scan` (pip-installed
  console script).
- Global mutable state (`_lang_rules_enabled`, `_ast_filter_enabled`) converted to
  explicit function parameters.

### Added
- `pyproject.toml` with optional dependency groups (`nlp`, `presidio`, `ast`, `all`, `dev`).
- `omni-scan` console entry point installed by `pip install omni-secret-scanner`.
- Docker image (`docker/Dockerfile`) with non-root user and multi-stage build.
- `.pre-commit-config.yaml` for local hooks and code hygiene.
- GitHub Actions CI (`ci.yml`): lint, test (Python 3.11 + 3.12), type-check, self-test.
- GitHub Actions release pipeline (`release.yml`): PyPI publish + GitHub release.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`.
- `tests/` package with `conftest.py` and updated test imports.

### Fixed
- Circular import between `file_tree` → `reporters` resolved via inline import.
- `deduplicate_findings_helper` reference (non-existent) removed from `file_tree.py`.

---

## [8.x] — Prior releases

See git history for earlier change records.
