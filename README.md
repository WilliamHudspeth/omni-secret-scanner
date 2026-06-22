# 🔒 omni-secret-scanner

A unified, production-grade Git repository secret scanner that combines 9 distinct detection strategies into a single zero-dependency Python script.

![omni-secret-scanner v9.0.0](https://img.shields.io/badge/version-v9.0.0-blue)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-green)
![License: MIT](https://img.shields.io/badge/license-MIT-purple)

## 🌟 Features

**omni-secret-scanner** is uniquely designed to catch standard API keys, AI-specific keys, PII, and prompt-injections simultaneously:

1. **Deep History Scanning**: Automatically parses `git log -p`, reflogs, and stashes to find secrets that were committed and subsequently deleted or force-pushed over.
2. **AI & LLM Keys**: Tailored to catch AI provider secrets (OpenAI, Anthropic, Gemini, Groq, LangChain, LiteLLM) and deeply parses `.ipynb` / `.pbix` notebooks.
3. **Prompt Injection Detection**: Built-in AST-level tracking for prompt injections (e.g. "ignore previous instructions") to protect your LLM pipelines.
4. **NLP PII Detection**: Context-aware detection for Names and Pronouns via spaCy & Microsoft Presidio, plus regex engines for global IDs, emails, and SSNs.
5. **Shannon Entropy Analysis**: Mathematically identifies highly random strings (>16 chars) that might be unknown cryptographic keys.
6. **OS-Native Cross-Check**: Uses native PowerShell regex engines on Windows for extreme accuracy.
7. **Semgrep SAST Integration**: Merges AST-level static analysis for 30+ programming languages.
8. **Interactive Terminal UI (TUI)**: Beautiful arrow-key navigation menu to review secrets.
9. **Dark-Mode HTML Reports**: Generate self-contained beautiful audit reports (`--format html`).

## 🚀 Quick Start

The scanner is completely self-contained in a single file (`scan-secrets.py`)! You do not need to install any external dependencies unless you want optional power-ups (like `tqdm`, `semgrep`, or `spacy`).

### Basic Scan
```bash
# Scan the current directory
python scan-secrets.py --repo-dir .

# Scan another directory and output a JSON report
python scan-secrets.py --repo-dir /path/to/repo --format json
```

### Pre-commit CI Usage (Fast Mode)
```bash
# Skips deep history and heavy NLP to run in milliseconds
python scan-secrets.py --fast

# Only scan lines changed vs a specific branch
python scan-secrets.py --diff main
```

### Interactive TUI Mode
```bash
python scan-secrets.py --tui
```

### Output to HTML Report
```bash
python scan-secrets.py --format html --output audit_report.html
```

## 🛠 Command Line Options

```text
--repo-dir DIR             Path to git repository (default: current dir)
--output FILE              Save report to file (default: stdout only)
--format FMT               Output format: text, json, sarif, html (default: text)
--tui                      Start the interactive terminal user interface
--fast                     Fast mode: skip history, NLP, Semgrep (pre-commit optimized)
--diff BASE                Incremental scan: scan only lines added since BASE ref
--scan-stash               Scan all git stash entries for secrets
--submodules               Scan submodules recursively in working tree and history
--all-branches             Scan all git branches and history
--reflog                   Scan git reflog for force-pushed commits
--since DATE               Incremental scan start commit/date (e.g. HEAD~3, 2026-06-01)
--max-file-size KB         Skip files larger than this size in KB (default: 1024)
--entropy-threshold NUM    Threshold for Shannon entropy (default: 3.8)
--nlp-pii                  Enable heavy NLP scanning for Names/Pronouns via spaCy
--presidio                 Enable Microsoft Presidio NLP scanning for PII
--ps-crosscheck            Enable PowerShell cross-checking for SSNs and common keys
--semgrep                  Enable Semgrep AST static analysis scanning
--sanitize                 Sanitize injection attack strings in report output
--mask                     Redact all matched secrets in output files/stdout
--redact-file FILE         Redact all secrets and PII from a local file in-place
--autofix-gitignore        Append flagged secret files to .gitignore (with backup)
--generate-filter-repo     Generate replacements.txt for git filter-repo
--install-hook             Install standard fast pre-commit hook
--print-tool-schema        Print OpenAI/Anthropic function-calling tool schema and exit
--self-test                Run built-in detection validation suite and exit
```

## 🔌 Optional Requirements
Install the power-ups via the provided `requirements.txt`:
```bash
pip install -r requirements.txt
```

## 📄 License
MIT License
