# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 9.x     | Yes       |
| < 9.0   | No        |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email the maintainer listed in `pyproject.toml` with:

1. Description of the vulnerability and potential impact.
2. Steps to reproduce.
3. Known mitigations.

You will receive an acknowledgement within 72 hours. Confirmed vulnerabilities
are patched in a new release and disclosed publicly after a fix is available.

## Threat model

RGT Codebase Scanner processes arbitrary file content and git history.

- **ReDoS**: All regex patterns are reviewed for worst-case complexity.
- **Command injection**: External tools (`git`, `semgrep`, etc.) are invoked
  with argument lists, never via `shell=True`.
- **Path traversal**: File paths from git output are sanitised before use.
- **Malicious pattern files**: `--patterns` only compiles regexes; no code is
  executed. Invalid patterns are skipped.

## Responsible use

Use only on repositories you own or have explicit permission to audit.
