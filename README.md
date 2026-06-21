# Omni Secret Scanner

A unified, powerful Git repository secret scanner that combines multiple detection strategies into a single Python script.

## Features

1. **Gitrob Patterns**: Scans suspicious filenames (`.env`, `id_rsa`) and content using known API key regexes (AWS, Stripe, Slack, etc.).
2. **Wiz Research AI Patterns**: Specifically tailored to catch AI provider secrets (OpenAI, Anthropic, Gemini, Groq, etc.) and deeply parses `.ipynb` notebook cells and outputs for leaked keys.
3. **Deep History Scanning**: Automatically parses `git log -p` to find secrets that were committed and subsequently deleted.
4. **Shannon Entropy Analysis**: Mathematically identifies highly random strings (>16 chars) that might be unknown cryptographic keys.
5. **PII Detection**: Looks for Emails, SSNs, and Zip Codes.

## Usage

You do not need to install any external dependencies.

```bash
python scan-secrets.py --repo-dir /path/to/your/repo --output report.txt
```

It will scan both the entire commit history and the current working directory, and generate a unified report.
