# RGT Codebase Scanner

Part of the RGT suite.

Scans codebases, files, URLs, Docker images, and environment variables for secrets, PII, high-entropy tokens, and prompt injection.

---

## Install

```bash
# Quick scan — stdlib only, no extras required
pip install rgt-codebase-scanner

# Full scan — all detectors
pip install "rgt-codebase-scanner[all]"
```

---

## Quick Start

```bash
# Scan current repo (secrets + PII)
rgt-scan

# Scan a directory
rgt-scan --target-type path /path/to/dir

# Scan a URL
rgt-scan --target-type url https://pastebin.com/raw/abc123

# JSON output
rgt-scan --format json --output findings.json

# Interactive mode picker (TUI)
rgt-scan --interactive
```

---

## Scan Modes

| Mode | Deps | Description |
|------|------|-------------|
| Quick | none | Secrets, PII, entropy, git history. stdlib only. |
| Full | `[all]` | Adds NLP/Presidio, AST, Semgrep, external tools, watch mode. |

---

## Scan Targets (`--target-type`)

| Value | Description |
|-------|-------------|
| `repo` | Local git repo (default) |
| `path` | File or directory tree |
| `url` | Fetch raw content from URL |
| `docker` | Scan Docker image layers |
| `env` | Scan current process environment variables |
| `clipboard` | Read from system clipboard (requires `pyperclip`) |

---

## Detectors

| Flag | Extra | What it finds |
|------|-------|---------------|
| _(always on)_ | none | Secrets, API keys, tokens via regex |
| _(always on)_ | none | High-entropy strings |
| `--pii` | none | Email, phone, SSN, IP, credit card via regex |
| `--nlp` | `[nlp]` | Names, addresses via spaCy / text-deidentification |
| `--presidio` | `[presidio]` | PII via Microsoft Presidio |
| `--injection` | none | Prompt injection patterns |
| `--semgrep` | semgrep CLI | SAST rules |
| `--perplexity` | none | Low-perplexity (obfuscated) strings |
| `--homoglyph` | none | Unicode lookalike characters |
| `--taint` | none | Taint-flow analysis |
| `--stego` | none | LSB steganography candidates |
| `--gitleaks` | gitleaks CLI | External secret scanning |
| `--trivy` | trivy CLI | Vulnerability + secret scanning |
| `--watch` | `[all]` | Watch mode — re-scan on file change |

---

## Output Formats

```bash
rgt-scan --format text    # default
rgt-scan --format json    # machine-readable
rgt-scan --format sarif   # SARIF 2.1.0 (GitHub Code Scanning)
rgt-scan --format html    # standalone HTML report
```

---

## Configuration

`.omni-scan.toml` in the repo root (auto-detected):

```toml
[scanner]
entropy_threshold = 4.5
max_file_size_kb = 512
fast = false
mask = true

[exclude]
patterns = ["*.lock", "node_modules/"]
tokens = ["EXAMPLE_TOKEN", "placeholder"]

[custom_patterns]
secrets = [
  { name = "Internal API Key", pattern = "int_[A-Za-z0-9]{32}" }
]

[report]
format = "json"
output = "scan-results.json"
```

---

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/williamhudspeth/omni-secret-scanner
    rev: v9.0.0
    hooks:
      - id: rgt-scan
```

---

## Docker

```bash
docker run --rm -v $(pwd):/repo ghcr.io/williamhudspeth/rgt-codebase-scanner:latest rgt-scan /repo
```

---

## LLM Integration

```bash
# Print OpenAI/Anthropic function-calling schema
rgt-scan --tool-schema

# Self-test
rgt-scan --self-test
```

See `llms.txt` at the repo root for plain-text LLM instructions.

---

## CLI Reference

```
usage: rgt-scan [-h] [--target-type {repo,path,url,docker,env,clipboard}]
                [--path PATH] [--branch BRANCH] [--all-branches]
                [--entropy-threshold FLOAT] [--max-file-size-kb INT]
                [--pii] [--nlp] [--presidio] [--injection] [--semgrep]
                [--perplexity] [--homoglyph] [--taint] [--stego]
                [--gitleaks] [--trivy] [--watch]
                [--exclude PATTERN [PATTERN ...]]
                [--exclude-token TOKEN [TOKEN ...]]
                [--pattern-file FILE] [--config FILE]
                [--format {text,json,sarif,html}] [--output FILE]
                [--mask] [--sanitize] [--quiet] [--fast] [--progress]
                [--context-lines INT] [--parallel] [--cache]
                [--language LANG] [--interactive] [--menu]
                [--tool-schema] [--self-test] [--version]
```

---

## Legacy

`omni-scan` is a registered alias for `rgt-scan`. `scan-secrets.py` still works as a shim.
