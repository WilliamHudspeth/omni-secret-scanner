# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 9.x     | ✅ Yes    |
| < 9.0   | ❌ No     |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email the maintainer at the address listed in `pyproject.toml` with:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce (minimised test case preferred).
3. Any known mitigations.

You will receive an acknowledgement within 72 hours. Confirmed vulnerabilities
will be patched in a new patch release and disclosed publicly after a fix is
available (coordinated disclosure).

## Threat model

omni-secret-scanner processes arbitrary file content and git history. The key
risks are:

- **ReDoS**: Maliciously crafted input designed to cause catastrophic backtracking
  in regex patterns. All patterns are reviewed for worst-case complexity.
- **Command injection**: The scanner invokes `git`, `semgrep`, and (optionally)
  PowerShell as subprocesses. Arguments are always passed as lists (never via
  `shell=True`), preventing injection.
- **Path traversal**: File paths from git output are sanitised before use.
- **Malicious patterns file**: Loading patterns via `--patterns` executes no code
  — only regex compilation. Invalid patterns are silently skipped.

## Responsible use

omni-secret-scanner is intended for authorised security testing of repositories
you own or have explicit permission to audit. Do not use it against repositories
without authorisation.
