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

```bash
# Install hooks (one command)
rgt-scan --install-all-hooks       # pre-commit + pre-push
rgt-scan --install-hook            # pre-commit only
rgt-scan --install-hook-strict     # pre-commit with NLP + PowerShell
rgt-scan --install-hook-push       # pre-push only
```

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

## Integration Guide

### Local Development — Stop secrets before they leave your machine

| Integration | Command | What it does |
|---|---|---|
| Pre-commit hook | `rgt-scan --install-hook` | Blocks commits with secrets in milliseconds |
| Pre-push hook | `rgt-scan --install-hook-push` | Scans new commits before they reach the remote |
| Watch mode | `rgt-scan --watch` | Daemon — flags secrets the moment you save a file |
| Snippet scanning | `rgt-scan --stdin` | Pipe LLM output or clipboard before pasting |
| TUI | `rgt-scan --tui` | Interactive browser for findings without remembering flags |

```bash
# One-time setup
rgt-scan --install-all-hooks

# Real-time monitoring
rgt-scan --watch &

# Pipe before pasting AI-generated code
pbpaste | rgt-scan --stdin --quiet
```

### CI/CD — Gate every pull request

| Platform | File | What it does |
|---|---|---|
| GitHub Actions | `.github/workflows/ci.yml` | Lint, test, SARIF upload, self-test. Fails on secrets. |
| GitLab CI | `.gitlab-ci.yml.example` | MR diff scan + nightly full sweep with `--validate` |
| Bitbucket | `bitbucket-pipelines.yml.example` | PR scan, SARIF artifact upload |

```yaml
# GitHub Actions — minimal setup
- name: Secret scan
  run: |
    pip install rgt-codebase-scanner
    rgt-scan --fast --format sarif --output results.sarif --quiet
    python -c "import json; d=json.load(open('results.sarif')); exit(len(d.get('runs',[{}])[0].get('results',[])))"
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

```yaml
# GitLab CI — MR scan
secret-scan:
  script:
    - pip install rgt-codebase-scanner
    - rgt-scan --diff $CI_MERGE_REQUEST_DIFF_BASE_SHA.. --quiet
```

### Pre-push hook behavior

The pre-push hook (`--install-hook-push`) reads git refs from stdin and runs `--diff` to scan only new commits:

```bash
# Installed as .git/hooks/pre-push
while read local_ref local_sha remote_ref remote_sha; do
    rgt-scan --diff $remote_sha.. --fast --quiet || exit 1
done
```

If secrets are found, the push is blocked with:
```
==========================================
  SECRETS DETECTED — PUSH BLOCKED
  Run: rgt-scan --diff <sha>..
  Fix: rgt-scan --fix
==========================================
```

### Automated Remediation

| Scenario | Command | What happens |
|---|---|---|
| Redact single file | `rgt-scan --redact-file config.py` | In-place replacement, `.bak` backup |
| Fix entire repo | `rgt-scan --fix` | Redacts all, stages changes, prints commit command |
| Scrub git history | `rgt-scan --generate-filter-repo` | Writes `replacements.txt` for `git filter-repo` |

```bash
# Find secrets → fix them → commit → scrub history
rgt-scan --fix
git commit -m "security: remove hardcoded secrets"
rgt-scan --generate-filter-repo
git filter-repo --replace-text replacements.txt --force
```

### Continuous Monitoring

```bash
# Cron job: scan every 6 hours, alert Slack if live keys found
0 */6 * * * /path/to/scripts/monitor.sh /path/to/repo --webhook https://hooks.slack.com/xxx

# Standalone API microservice
pip install fastapi uvicorn
python minimal_api.py            # POST /scan, GET /health, GET /schema
```

The monitoring script (`scripts/monitor.sh`) checks `validated_live` count and only alerts when confirmed-active keys are present — avoiding alert fatigue.

### LLM Integration

| Bridge | Command | Use case |
|---|---|---|
| Function-calling schema | `rgt-scan --tool-schema` | LLMs call the scanner as a tool |
| API endpoint | `python minimal_api.py` | `POST /scan` for any internal tool |
| Self-correct prompt | `rgt-scan --self-correct-prompt` | Feed to LLM for auto-remediation |
| Snippet scan | `rgt-scan --stdin` | Check AI-generated code before accepting |

```bash
# Generate schema for OpenAI/Anthropic function calling
rgt-scan --tool-schema

# Start API server (any tool can POST /scan)
uvicorn minimal_api:app --host 0.0.0.0 --port 8000

# When an LLM leaks a secret, generate a fix prompt
rgt-scan --self-correct-prompt fix-instructions.md
```

### Enterprise Configuration

Drop `.omni-scan.toml` and `.secretsignore` in the repo root — every developer and CI run uses the same settings without extra flags:

```toml
[scanner]
entropy_threshold = 4.2
sensitive_words = ["acme-corp", "INTERNAL"]
fast = false
format = "sarif"
confidence_score = true

[exclude]
patterns = ["vendor/", "*.min.js", "fixtures/"]
tokens = ["EXAMPLE_KEY", "placeholder-token"]

[report]
format = "json"
output = "scan-results.json"
```

### Incremental Adoption (large codebases)

| Strategy | Flag | Effect |
|---|---|---|
| Fast first pass | `--fast` | Working tree only, sub-second |
| File cache | `--cache` | Skips unchanged files on re-scan |
| Multi-core | `--parallel` | All CPU cores for large repos |
| AST filter | `--ast-filter` | Skips comments, test files, mocks |
| Noise reduction | `--noise-filter` | Strips low-confidence entropy hits |

```bash
# First scan: fast, cache results
rgt-scan --fast --cache --quiet

# Subsequent scans: instant for unchanged files
rgt-scan --fast --cache --quiet

# Full sweep: only when needed
rgt-scan --all-branches --validate --semgrep --parallel
```

---

## LLM Integration

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
