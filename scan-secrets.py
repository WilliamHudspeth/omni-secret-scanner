#!/usr/bin/env python3
"""
scan-secrets.py – Complete secret & PII scanner for Git repositories.
Combines:
  1. Deep history scanning (all commits, diffs)
  2. Gitrob-like current-tree scanning (suspicious filenames + content regexes)
  3. Wiz Research AI secret patterns & .ipynb notebook parsing
  4. NLP PII De-identification (Names/Pronouns) via text-deidentification
  5. PowerShell Cross-Checking for robust OS-level regex validation

Usage:
    python scan-secrets.py [--repo-dir /path/to/repo] [--output report.txt] [--nlp-pii] [--ps-crosscheck]

Optional Dependencies & Setup:
    - `text-deidentification` (for NLP PII scanning):
        pip install text-deidentification
    - `spaCy` English model (required by text-deidentification):
        python -m spacy download en_core_web_sm
    - `powershell` or `pwsh` (PowerShell Core) (for OS-level cross-checking):
        Ensure 'pwsh' or 'powershell' is installed and available in your system's PATH.

Requirements:
    - Python 3.6+
    - Git installed and available in PATH
"""

import argparse
import math
import os
import re
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime

# ------------------------------------------------------------------------------
# CONFIGURATION – Custom & Gitrob & Wiz AI patterns
# ------------------------------------------------------------------------------

CUSTOM_SECRET_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey|secret).{0,10}['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
    "Private Key Header": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9\-_]+",
    "Stripe Key": r"(sk|rk)_(live|test)_[A-Za-z0-9]+",
    "Generic Password Assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]+)['\"]",
    "Vercel Token": r"vercel_[A-Za-z0-9]{24,}",
    "Supabase Token": r"sbp_[a-zA-Z0-9]{40}",
    "Cloudflare API Key": r"[a-zA-Z0-9_\-]{40}",
    "Snowflake Password": r"(?i)snowflake.*password.*['\"][^'\"]+['\"]",
    "Datadog API Key": r"(?i)datadog.*['\"][a-f0-9]{32}['\"]",
}

CUSTOM_PII_PATTERNS = {
    "Email Address": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    "Phone Number (US)": r"\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}",
    # Upgraded SSN Regex via User's PowerShell cross-check recommendation
    "SSN (US)": r"(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}",
    "Street Address (simple)": r"\d{1,5}\s[A-Za-z0-9\s]+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct)\b",
    "Zip Code (US)": r"\b\d{5}(-\d{4})?\b",
}

AI_PATTERNS = {
    "HuggingFace": r"hf_[A-Za-z0-9]{30,40}",
    "Groq": r"gsk_[A-Za-z0-9]{20,}",
    "Perplexity": r"pplx-[A-Za-z0-9]{20,}",
    "OpenAI": r"sk-(proj-)?[A-Za-z0-9]{20,}",
    "Anthropic": r"sk-ant-[A-Za-z0-9\-]{20,}",
    "WeightsAndBiases": r"(?i)wandb.*?[A-Za-z0-9]{40}",
    "AzureOpenAI": r"(?i)azure.*openai.*[A-Za-z0-9]{32}",
    "NVIDIA": r"nvapi-[A-Za-z0-9_\-]{20,}",
    "TogetherAI": r"[0-9a-f]{64}",
    "Cohere": r"(?i)cohere.*?[\'\"][A-Za-z0-9\-]{30,}[\'\"]",
    "Pinecone": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Gemini": r"AIza[0-9A-Za-z\-_]{35}",
    "Moonshot": r"sk-[A-Za-z0-9]{20,}",
}

GITROB_SUSPICIOUS_FILES = [
    "id_rsa", "id_dsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key", "*.pkcs12",
    "*.pfx", "*.p12", "*.crt", "*.cert", "*.ca-bundle", "*.jks", "*.keystore",
    "*.keytab", "credentials*", "secrets*", "secret*", ".env", ".env.*", "*.env",
    "config.yml", "config.yaml", "config.json", "config.xml", "config.properties",
    "*.config", ".git-credentials", ".s3cfg", ".tugboat", "proftpdpasswd",
    ".htpasswd", ".netrc", "wp-config.php", "database.yml", "settings.py",
    ".bash_history", ".mysql_history", ".psql_history", ".pgpass", "shadow", "passwd",
    "mcp.json"
]

GITROB_CONTENT_PATTERNS = {
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
    "Google Cloud Platform API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub OAuth Access Token": r"gho_[0-9a-zA-Z]{36,255}",
    "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Auth Token": r"[a-zA-Z0-9]{32}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "SendGrid API Key": r"SG\.[\w_-]{22,68}\.[\w_-]{22,68}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal/Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Twitter Access Token": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth Secret": r"[a-zA-Z0-9]{35,44}",
    "LinkedIn Client ID": r"^[0-9A-Za-z]{14,16}$",
    "Connection String": r"(?i)(?:mongodb|mysql|postgresql|redis|sqlite)://[^ \n]+",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
}

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

def is_ignored_entropy_token(token: str) -> bool:
    # 1. UUID check
    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", token):
        return True
    # 2. Base64-like pattern check (24+ characters of A-Z, a-z, 0-9, +, /, maybe ending with =)
    if re.match(r"^[A-Za-z0-9+/]{24,}={0,2}$", token):
        return True
    return False

def redact_match(match_str: str) -> str:
    if not match_str:
        return "[REDACTED]"
    if " (Decoded: " in match_str:
        parts = match_str.split(" (Decoded: ", 1)
        base64_token = parts[0]
        decoded_secret = parts[1].rstrip(")")
        redacted_base64 = redact_match(base64_token)
        redacted_decoded = redact_match(decoded_secret)
        return f"{redacted_base64} (Decoded: {redacted_decoded})"
    if len(match_str) <= 4:
        return "[REDACTED]"
    for prefix in ["AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "hf_", "gsk_", "pplx-", "sk-ant-", "sk-proj-", "sk-", "nvapi-", "sbp_"]:
        if match_str.startswith(prefix):
            return f"{prefix}[REDACTED]"
    return f"{match_str[:4]}[REDACTED]"

def load_secretsignore(repo_dir: str):
    ignore_files = []
    ignore_tokens = []
    ignore_path = Path(repo_dir) / ".secretsignore"
    if ignore_path.exists():
        try:
            for line in ignore_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("token:"):
                    ignore_tokens.append(line[len("token:"):].strip())
                else:
                    ignore_files.append(line)
        except Exception:
            pass
    return ignore_files, ignore_tokens

def is_git_ignored(file_path: str) -> bool:
    if not Path(".git").exists() and not Path("../.git").exists():
        return False
    try:
        result = subprocess.run(["git", "check-ignore", file_path], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False

def extract_markdown_code_blocks(text: str) -> list:
    blocks = []
    pattern = r"```(?:[a-zA-Z0-9+#-]+)?\n(.*?)\n```"
    for m in re.finditer(pattern, text, re.DOTALL):
        blocks.append(m.group(1))
    return blocks

def get_context_snippet(file_path: str, target_line: int, context_lines: int, content=None) -> str:
    if content is None:
        try:
            if os.path.exists(file_path):
                content = Path(file_path).read_text(errors="ignore")
        except Exception:
            return ""
    if not content:
        return ""
    lines = content.splitlines()
    start = max(0, target_line - 1 - context_lines)
    end = min(len(lines), target_line + context_lines)
    
    snippet_lines = []
    for idx in range(start, end):
        line_no = idx + 1
        indicator = " > " if line_no == target_line else "   "
        snippet_lines.append(f"{indicator}{line_no}: {lines[idx]}")
    return "\n".join(snippet_lines)

def scan_obfuscated_secrets(text: str, source_identifier: str, all_secret_patterns: dict) -> list:
    import base64
    local_hits = []
    candidates = re.finditer(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", text)
    for m in candidates:
        token = m.group(0)
        try:
            pad_len = 4 - (len(token) % 4)
            if pad_len < 4:
                token_padded = token + ("=" * pad_len)
            else:
                token_padded = token
            decoded_bytes = base64.b64decode(token_padded)
            decoded_text = decoded_bytes.decode('utf-8', errors='strict')
            if len(decoded_text) > 10 and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in decoded_text):
                for name, pattern in all_secret_patterns.items():
                    for match_obf in re.finditer(pattern, decoded_text):
                        local_hits.append({
                            "type": f"Obfuscated:{name}",
                            "file": source_identifier,
                            "match": f"{token} (Decoded: {match_obf.group(0).strip()})"
                        })
        except Exception:
            pass
    return local_hits

def scan_snippet(content: str, source_name: str, entropy_threshold=3.8, ignore_tokens=None, extract_code_blocks=False, sensitive_words=None) -> dict:
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []
        
    if extract_code_blocks and (source_name.endswith(".md") or source_name in ("stdin", "text_snippet")):
        blocks = extract_markdown_code_blocks(content)
        if blocks:
            content = "\n".join(blocks)
            
    all_secret_patterns = {**CUSTOM_SECRET_PATTERNS, **GITROB_CONTENT_PATTERNS, **AI_PATTERNS}
    findings = {
        "secrets": [],
        "pii": [],
        "entropy": []
    }
    
    lines = content.splitlines()
    for idx, line in enumerate(lines):
        line_no = idx + 1
        
        # Standard Secrets
        for name, pattern in all_secret_patterns.items():
            try:
                for m in re.finditer(pattern, line):
                    val = m.group(0).strip()
                    if val not in ignore_tokens:
                        findings["secrets"].append({
                            "type": name,
                            "file": source_name,
                            "line": line_no,
                            "match": val
                        })
            except re.error:
                pass
                
        # Obfuscated Base64 Secrets
        obf_hits = scan_obfuscated_secrets(line, source_name, all_secret_patterns)
        for hit in obf_hits:
            if hit["match"] not in ignore_tokens:
                hit["line"] = line_no
                findings["secrets"].append(hit)
                
        # Sensitive Words
        for word in sensitive_words:
            if word.lower() in line.lower():
                for m in re.finditer(re.escape(word), line, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        findings["secrets"].append({
                            "type": f"Sensitive Word: {word}",
                            "file": source_name,
                            "line": line_no,
                            "match": val
                        })
                        
        # Regex PII
        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, line):
                val = m.group(0).strip()
                if val not in ignore_tokens:
                    findings["pii"].append({
                        "type": name,
                        "file": source_name,
                        "line": line_no,
                        "match": val
                    })
                    
        # Entropy
        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", line)
        for m in candidates:
            token = m.group(0)
            if token.isdigit(): continue
            if all(c in "0123456789abcdefABCDEF" for c in token) and len(token) in (32, 40): continue
            if is_ignored_entropy_token(token): continue
            if token in ignore_tokens: continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["entropy"].append({
                    "file": source_name,
                    "line": line_no,
                    "token": token,
                    "entropy": round(entropy, 2)
                })
                
    return findings

def match_exclude(path: str, exclude_patterns: list) -> bool:
    from fnmatch import fnmatch
    for pat in exclude_patterns:
        if fnmatch(path, pat) or fnmatch(Path(path).name, pat):
            return True
    return False

def extract_added_lines(patch_text: str, exclude_patterns: list) -> list:
    records = []
    current_file = None
    line_no = None
    for line in patch_text.splitlines():
        if line.startswith("diff --git"):
            current_file = None
            line_no = None
        elif line.startswith("--- a/") or line.startswith("+++ b/"):
            current_file = line[6:] if line.startswith("+++ b/") else current_file
        elif line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if match:
                line_no = int(match.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            if not current_file or match_exclude(current_file, exclude_patterns):
                continue
            records.append((current_file, line_no, line[1:]))
            if line_no is not None:
                line_no += 1
    return records

def scan_commit_messages(all_branches=False):
    cmd = ["git", "log", "--pretty=format:%H%n%B%n---END---"]
    if all_branches:
        cmd.insert(2, "--all")
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        print("Error running git log for commits", file=sys.stderr)
        sys.exit(1)
    commits = result.stdout.split("---END---\n")
    for block in commits:
        if not block.strip():
            continue
        parts = block.split("\n", 1)
        if len(parts) == 2:
            commit_hash, message = parts
            yield commit_hash.strip(), message.strip()

def scan_history(exclude_patterns: list, all_branches=False, quiet=False, entropy_threshold=3.8, ignore_tokens=None, sensitive_words=None) -> dict:
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []
    findings = {
        "secrets": [],
        "pii": [],
        "entropy": [],
        "commits": [],
    }
    
    # Check if .git exists to avoid failure if running outside git
    if not Path(".git").exists() and not Path("../.git").exists():
        if not quiet:
            print("Warning: Not running inside a Git repository. Skipping history scan.", file=sys.stderr)
        return findings

    if not quiet:
        print(f"Scanning file history{' (all branches)' if all_branches else ''}...", file=sys.stderr)
    cmd = ["git", "log", "-p", "--no-color"]
    if all_branches:
        cmd.insert(2, "--all")
    result = subprocess.run(
        cmd,
        capture_output=True, text=True, errors="replace"
    )
    if result.returncode != 0:
        if not quiet:
            print("Fatal: not a git repository or git error", file=sys.stderr)
        return findings

    added_lines = extract_added_lines(result.stdout, exclude_patterns)
    all_secret_patterns = {**CUSTOM_SECRET_PATTERNS, **GITROB_CONTENT_PATTERNS, **AI_PATTERNS}

    for file_path, line_no, content in added_lines:
        for name, pattern in all_secret_patterns.items():
            try:
                for m in re.finditer(pattern, content):
                    val = m.group(0).strip()
                    if val in ignore_tokens: continue
                    findings["secrets"].append({"type": name, "file": file_path, "line": line_no, "match": val})
            except re.error:
                pass
                
        obf_hits = scan_obfuscated_secrets(content, file_path, all_secret_patterns)
        for hit in obf_hits:
            if hit["match"] not in ignore_tokens:
                hit["line"] = line_no
                findings["secrets"].append(hit)
                
        for word in sensitive_words:
            if word.lower() in content.lower():
                for m in re.finditer(re.escape(word), content, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        findings["secrets"].append({
                            "type": f"Sensitive Word: {word}",
                            "file": file_path,
                            "line": line_no,
                            "match": val
                        })
                        
        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, content):
                val = m.group(0).strip()
                if val in ignore_tokens: continue
                findings["pii"].append({"type": name, "file": file_path, "line": line_no, "match": val})
        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", content)
        for m in candidates:
            token = m.group(0)
            if token.isdigit(): continue
            if all(c in "0123456789abcdefABCDEF" for c in token) and len(token) in (32, 40): continue
            if is_ignored_entropy_token(token): continue
            if token in ignore_tokens: continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["entropy"].append({"file": file_path, "line": line_no, "token": token, "entropy": round(entropy, 2)})

    if not quiet:
        print("Scanning commit messages...", file=sys.stderr)
    for commit_hash, message in scan_commit_messages(all_branches):
        for name, pattern in all_secret_patterns.items():
            for m in re.finditer(pattern, message):
                val = m.group(0).strip()
                if val in ignore_tokens: continue
                findings["commits"].append({"type": name, "commit": commit_hash[:8], "match": val})
                
        obf_hits = scan_obfuscated_secrets(message, commit_hash[:8], all_secret_patterns)
        for hit in obf_hits:
            if hit["match"] not in ignore_tokens:
                findings["commits"].append({"type": hit["type"], "commit": commit_hash[:8], "match": hit["match"]})
                
        for word in sensitive_words:
            if word.lower() in message.lower():
                for m in re.finditer(re.escape(word), message, re.IGNORECASE):
                    val = m.group(0)
                    if val not in ignore_tokens:
                        findings["commits"].append({
                            "type": f"Sensitive Word: {word}",
                            "commit": commit_hash[:8],
                            "match": val
                        })
                        
        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, message):
                val = m.group(0).strip()
                if val in ignore_tokens: continue
                findings["commits"].append({"type": f"PII:{name}", "commit": commit_hash[:8], "match": val})
        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", message)
        for m in candidates:
            token = m.group(0)
            if token.isdigit(): continue
            if is_ignored_entropy_token(token): continue
            if token in ignore_tokens: continue
            entropy = shannon_entropy(token)
            if entropy >= entropy_threshold:
                findings["commits"].append({"type": "ENTROPY", "commit": commit_hash[:8], "token": token, "entropy": round(entropy, 2)})

    return findings

def scan_text(text, source_identifier, all_secret_patterns):
    local_hits = []
    for name, pattern in all_secret_patterns.items():
        try:
            for m in re.finditer(pattern, text):
                local_hits.append({"type": name, "file": source_identifier, "match": m.group(0).strip()})
        except re.error:
            pass
    return local_hits

def scan_ipynb(path, all_secret_patterns):
    local_hits = []
    try:
        nb = json.loads(Path(path).read_text(errors='ignore'))
    except Exception:
        return local_hits
    for i, cell in enumerate(nb.get('cells', [])):
        src = ''.join(cell.get('source', []))
        local_hits += scan_text(src, f"{path}:cell{i}", all_secret_patterns)
        for out in cell.get('outputs', []):
            txt = ''
            if 'text' in out: txt = ''.join(out['text'])
            if 'data' in out and 'text/plain' in out['data']:
                txt = ''.join(out['data']['text/plain'])
            local_hits += scan_text(txt, f"{path}:cell{i}:output", all_secret_patterns)
    return local_hits

# ------------------------------------------------------------------------------
# NLP & PowerShell Integrations
# ------------------------------------------------------------------------------

def init_nlp_deidentifier(quiet=False):
    try:
        from deidentification import Deidentification, DeidentificationConfig
    except ImportError:
        if not quiet:
            print("Warning: The 'text-deidentification' package is not installed. NLP scanning will be skipped.", file=sys.stderr)
            print("Please install it by running: pip install text-deidentification", file=sys.stderr)
        return None
        
    try:
        config = DeidentificationConfig(spacy_model='en_core_web_sm', save_tokens=True, excluded_entities=set())
        deidentifier = Deidentification(config)
        return deidentifier
    except Exception as e:
        if not quiet:
            print(f"Warning: Error loading NLP model ({e}). NLP scanning will be skipped.", file=sys.stderr)
            print("Please ensure the spaCy model is downloaded: python -m spacy download en_core_web_sm", file=sys.stderr)
        return None

def run_ps_crosscheck(repo_dir: str, quiet=False, ignore_tokens=None):
    import shutil
    import tempfile

    if ignore_tokens is None:
        ignore_tokens = []

    ps_exe = None
    if shutil.which("pwsh"):
        ps_exe = "pwsh"
    elif shutil.which("powershell"):
        ps_exe = "powershell"

    if not ps_exe:
        if not quiet:
            print("Warning: Neither 'pwsh' nor 'powershell' was found on PATH. Skipping PowerShell cross-check.", file=sys.stderr)
        return []

    if not quiet:
        print(f"Running PowerShell Cross-Check using {ps_exe}...", file=sys.stderr)

    ps_script = """
$gitDir = [IO.Path]::DirectorySeparatorChar + '.git' + [IO.Path]::DirectorySeparatorChar
$fileList = Get-ChildItem -Path "{repo_dir}" -Recurse -File | Where-Object {{ $_.FullName.Contains($gitDir) -ne $true }}
$findings = @()

foreach ($file in $fileList) {{
    switch -Regex ($file.Extension) {{
        "txt|csv|md|json|yml|yaml|env|py|xml" {{
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "(?!000|666|9\d{{2}})\d{{3}}[-\s]?(?!00)\d{{2}}[-\s]?(?!0000)\d{{4}}") {{
                $findings += [PSCustomObject]@{{
                    File = $file.FullName
                    Type = "SSN (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
            if ($content -match "AKIA[0-9A-Z]{{16}}") {{
                $findings += [PSCustomObject]@{{
                    File = $file.FullName
                    Type = "AWS API Key (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
            if ($content -match "AIza[0-9A-Za-z\-_]{{35}}") {{
                $findings += [PSCustomObject]@{{
                    File = $file.FullName
                    Type = "Google API Key (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
            if ($content -match "[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{{2,}}") {{
                $findings += [PSCustomObject]@{{
                    File = $file.FullName
                    Type = "Email (Cross-Check)"
                    Match = $matches[0]
                }}
            }}
        }}
    }}
}}
$findings | ConvertTo-Json -Compress
"""
    safe_repo_dir = str(repo_dir).replace("\\", "\\\\")
    
    with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w", encoding="utf-8") as tf:
        tf.write(ps_script.format(repo_dir=safe_repo_dir))
        temp_script_path = tf.name

    try:
        result = subprocess.run([ps_exe, "-ExecutionPolicy", "Bypass", "-File", temp_script_path], capture_output=True, text=True)
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                filtered_data = []
                for p in data:
                    if p.get("Match") not in ignore_tokens:
                        filtered_data.append(p)
                return filtered_data
            except json.JSONDecodeError:
                return []
        return []
    finally:
        try:
            os.unlink(temp_script_path)
        except Exception:
            pass

def scan_current_tree(repo_dir: str, exclude_patterns: list, nlp_deidentifier=None, quiet=False, ignore_tokens=None, sensitive_words=None, extract_code_blocks=False) -> dict:
    if ignore_tokens is None:
        ignore_tokens = []
    if sensitive_words is None:
        sensitive_words = []
    findings = {
        "suspicious_files": [],
        "current_secrets": [],
        "nlp_pii": []
    }
    if not quiet:
        print("Scanning current working tree...", file=sys.stderr)
    root = Path(repo_dir).resolve()
    all_secret_patterns = {**CUSTOM_SECRET_PATTERNS, **GITROB_CONTENT_PATTERNS, **AI_PATTERNS}

    for root_dir, dirs, files in os.walk(repo_dir):
        # Avoid descending into .git completely
        if '.git' in dirs:
            dirs.remove('.git')
            
        # Avoid descending into other excluded folders
        try:
            rel_root = os.path.relpath(root_dir, repo_dir)
        except Exception:
            rel_root = "."
        if rel_root == ".":
            rel_root = ""

        active_dirs = []
        for d in dirs:
            dir_rel = os.path.join(rel_root, d).replace("\\", "/")
            if match_exclude(dir_rel, exclude_patterns) or match_exclude(dir_rel + "/", exclude_patterns):
                continue
            active_dirs.append(d)
        dirs[:] = active_dirs

        for file in files:
            file_rel_path = os.path.join(rel_root, file).replace("\\", "/")
            if match_exclude(file_rel_path, exclude_patterns):
                continue

            path = Path(root_dir) / file
            
            # Check suspicious file names (safe even for large files)
            for glob_pat in GITROB_SUSPICIOUS_FILES:
                from fnmatch import fnmatch
                if fnmatch(path.name, glob_pat) or fnmatch(file_rel_path, glob_pat):
                    findings["suspicious_files"].append(file_rel_path)
                    break

            # Skip scanning content of files larger than 1MB
            try:
                if path.stat().st_size > 1_000_000:
                    continue
            except Exception:
                continue

            if path.suffix == '.ipynb':
                # Filter scan_ipynb results with ignore_tokens
                raw_hits = scan_ipynb(path, all_secret_patterns)
                for hit in raw_hits:
                    if hit["match"] not in ignore_tokens:
                        findings["current_secrets"].append(hit)
            else:
                try: 
                    content = path.read_text(errors="ignore")
                except Exception: 
                    continue
                
                # Extract code blocks if requested
                if extract_code_blocks and file_rel_path.endswith(".md"):
                    blocks = extract_markdown_code_blocks(content)
                    if blocks:
                        content = "\n".join(blocks)
                
                # Scan line-by-line to get line numbers
                lines = content.splitlines()
                for idx, line in enumerate(lines):
                    line_no = idx + 1
                    
                    # Standard Secrets
                    for name, pattern in all_secret_patterns.items():
                        try:
                            for m in re.finditer(pattern, line):
                                val = m.group(0).strip()
                                if val not in ignore_tokens:
                                    findings["current_secrets"].append({
                                        "type": name,
                                        "file": file_rel_path,
                                        "line": line_no,
                                        "match": val
                                    })
                        except re.error:
                            pass
                            
                    # Obfuscated Base64 Secrets
                    obf_hits = scan_obfuscated_secrets(line, file_rel_path, all_secret_patterns)
                    for hit in obf_hits:
                        if hit["match"] not in ignore_tokens:
                            hit["line"] = line_no
                            findings["current_secrets"].append(hit)
                            
                    # Sensitive Words
                    for word in sensitive_words:
                        if word.lower() in line.lower():
                            for m in re.finditer(re.escape(word), line, re.IGNORECASE):
                                val = m.group(0)
                                if val not in ignore_tokens:
                                    findings["current_secrets"].append({
                                        "type": f"Sensitive Word: {word}",
                                        "file": file_rel_path,
                                        "line": line_no,
                                        "match": val
                                    })
                                    
                    # Regex PII
                    for name, pattern in CUSTOM_PII_PATTERNS.items():
                        for m in re.finditer(pattern, line):
                            val = m.group(0).strip()
                            if val not in ignore_tokens:
                                findings["current_secrets"].append({
                                    "type": f"PII:{name}",
                                    "file": file_rel_path,
                                    "line": line_no,
                                    "match": val
                                })

                # NLP PII Scanning
                if nlp_deidentifier and path.suffix in ['.txt', '.md', '.csv', '.json', '.yml', '.yaml', '.py']:
                    try:
                        # Run it backwards over the text to populate tokens dictionary
                        nlp_deidentifier.deidentify(content)
                        tokens = nlp_deidentifier.get_identified_elements()
                        for ent in tokens.get("entities", []):
                            val = ent["text"]
                            if val not in ignore_tokens:
                                findings["nlp_pii"].append({"file": file_rel_path, "type": "NAME", "match": val})
                        for pron in tokens.get("pronouns", []):
                            val = pron["text"]
                            if val not in ignore_tokens:
                                findings["nlp_pii"].append({"file": file_rel_path, "type": "PRONOUN", "match": pron["text"]})
                    except Exception:
                        pass

    return findings

# ------------------------------------------------------------------------------
# Report generation
# ------------------------------------------------------------------------------
def generate_report(history_findings: dict, tree_findings: dict, ps_findings: list, output_file=None, output_format="text", mask=False, context_lines=0, show_score=False, snippet_content=None):
    has_secrets = len(history_findings["secrets"]) > 0 or len(tree_findings["current_secrets"]) > 0
    has_pii = len(history_findings["pii"]) > 0 or len(tree_findings["nlp_pii"]) > 0 or len(ps_findings) > 0
    total_issues = (
        len(history_findings["secrets"]) + len(history_findings["pii"]) + len(history_findings["entropy"]) +
        len(history_findings["commits"]) + len(tree_findings["current_secrets"]) + len(tree_findings["nlp_pii"]) +
        len(ps_findings)
    )

    if output_format == "json":
        import copy
        history_copy = copy.deepcopy(history_findings)
        tree_copy = copy.deepcopy(tree_findings)
        ps_copy = copy.deepcopy(ps_findings)
        
        if mask:
            for s in history_copy["secrets"]: s["match"] = redact_match(s["match"])
            for p in history_copy["pii"]: p["match"] = redact_match(p["match"])
            for e in history_copy["entropy"]: e["token"] = redact_match(e["token"])
            for c in history_copy["commits"]:
                if "match" in c: c["match"] = redact_match(c["match"])
                if "token" in c: c["token"] = redact_match(c["token"])
            for s in tree_copy["current_secrets"]: s["match"] = redact_match(s["match"])
            for p in tree_copy["nlp_pii"]: p["match"] = redact_match(p["match"])
            for p in ps_copy: p["Match"] = redact_match(p["Match"])

        # Calculate score
        score = 100
        score -= (len(history_findings["secrets"]) + len(tree_findings["current_secrets"])) * 40
        score -= (len(history_findings["pii"]) + len(tree_findings["nlp_pii"]) + len(ps_findings)) * 20
        score -= len(history_findings["entropy"]) * 10
        score = max(0, min(100, score))

        report = {
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_issues": total_issues,
                "has_secrets": has_secrets,
                "has_pii": has_pii,
                "safety_score": score
            },
            "findings": {
                "history": history_copy,
                "current_tree": tree_copy,
                "powershell_crosscheck": ps_copy
            }
        }
        json_out = json.dumps(report, indent=2)
        if output_file:
            with open(output_file, "w") as f:
                f.write(json_out)
            print(f"JSON report saved to {output_file}")
        else:
            print(json_out)
        return total_issues

    elif output_format == "sarif":
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "omni-secret-scanner",
                            "informationUri": "https://github.com/WilliamHudspeth/omni-secret-scanner",
                            "rules": [
                                {
                                    "id": "OSS001",
                                    "name": "SecretFound",
                                    "shortDescription": {"text": "A hardcoded secret was found."}
                                },
                                {
                                    "id": "OSS002",
                                    "name": "PIIFound",
                                    "shortDescription": {"text": "Personally Identifiable Information was found."}
                                }
                            ]
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for s in tree_findings["current_secrets"]:
            match_str = redact_match(s["match"]) if mask else s["match"]
            sarif["runs"][0]["results"].append({
                "ruleId": "OSS001" if not str(s["type"]).startswith("PII") else "OSS002",
                "message": {"text": f"Found {s['type']} in current tree: {match_str}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": s["file"]}}}]
            })
        for s in history_findings["secrets"]:
            match_str = redact_match(s["match"]) if mask else s["match"]
            sarif["runs"][0]["results"].append({
                "ruleId": "OSS001",
                "message": {"text": f"Found {s['type']} in git history: {match_str}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": s["file"]}}}]
            })
            
        json_out = json.dumps(sarif, indent=2)
        if output_file:
            with open(output_file, "w") as f:
                f.write(json_out)
            print(f"SARIF report saved to {output_file}")
        else:
            print(json_out)
        return total_issues

    # Fallback to text format
    out = []
    def w(txt=""): out.append(txt)
    def section(title):
        w(f"\n{'='*60}")
        w(f"  {title}")
        w(f"{'='*60}")

    section("HISTORY SCAN – SECRETS / CREDENTIALS")
    if history_findings["secrets"]:
        for s in history_findings["secrets"]:
            m_val = redact_match(s['match']) if mask else s['match']
            w(f"[{s['type']}] {s['file']}:{s.get('line', '?')} -> {m_val}")
            if context_lines > 0 and s.get('line') and snippet_content:
                context = get_context_snippet(s['file'], s['line'], context_lines, content=snippet_content)
                if context:
                    if mask:
                        context = context.replace(s['match'], redact_match(s['match']))
                    w(context)
                    w()
    else: w("None found.")

    section("HISTORY SCAN – PII")
    if history_findings["pii"]:
        for p in history_findings["pii"]:
            m_val = redact_match(p['match']) if mask else p['match']
            w(f"[{p['type']}] {p['file']}:{p.get('line', '?')} -> {m_val}")
    else: w("None found.")

    section("HISTORY SCAN – HIGH ENTROPY STRINGS")
    if history_findings["entropy"]:
        for e in history_findings["entropy"]:
            t_val = redact_match(e['token']) if mask else e['token']
            w(f"File {e['file']}:{e.get('line', '?')}  entropy={e['entropy']} -> {t_val}")
    else: w("None found.")

    section("HISTORY SCAN – COMMIT MESSAGES")
    if history_findings["commits"]:
        for c in history_findings["commits"]:
            token_val = c.get('match') or c.get('token')
            if token_val and mask:
                token_val = redact_match(token_val)
            w(f"Commit {c['commit']} [{c['type']}] -> {token_val}")
    else: w("No suspicious content in commit messages.")

    section("CURRENT TREE – SUSPICIOUS FILENAMES")
    if tree_findings["suspicious_files"]:
        for f in tree_findings["suspicious_files"]: w(f"  Suspicious file: {f}")
    else: w("No suspicious filenames found.")

    section("CURRENT TREE – CONTENT SECRETS & REGEX PII")
    if tree_findings["current_secrets"]:
        for s in tree_findings["current_secrets"]:
            m_val = redact_match(s['match']) if mask else s['match']
            w(f"[{s['type']}] {s['file']}:{s.get('line', '?')} -> {m_val}")
            if context_lines > 0 and s.get('line'):
                context = get_context_snippet(s['file'], s['line'], context_lines)
                if context:
                    if mask:
                        context = context.replace(s['match'], redact_match(s['match']))
                    w(context)
                    w()
    else: w("No secrets found in current files.")

    if tree_findings["nlp_pii"]:
        section("CURRENT TREE – NLP PII (NAMES & PRONOUNS)")
        for n in tree_findings["nlp_pii"]:
            m_val = redact_match(n['match']) if mask else n['match']
            w(f"[{n['type']}] {n['file']} -> {m_val}")

    if ps_findings:
        section("POWERSHELL CROSS-CHECK FINDINGS")
        for p in ps_findings:
            m_val = redact_match(p['Match']) if mask else p['Match']
            w(f"[{p['Type']}] {p['File']} -> {m_val}")

    # Generate gitignore suggestions
    gitignore_suggestions = []
    files_to_check = set(tree_findings["suspicious_files"])
    for s in tree_findings["current_secrets"]:
        files_to_check.add(s["file"])
    for p in tree_findings["nlp_pii"]:
        files_to_check.add(p["file"])
        
    for f in sorted(files_to_check):
        if os.path.exists(f) and not is_git_ignored(f):
            if f not in ("scan-secrets.py", "report.json", "report.sarif", output_file):
                gitignore_suggestions.append(f)

    if gitignore_suggestions:
        section("RECOMMENDED .GITIGNORE ADDITIONS")
        w("The following files contain secrets or have suspicious filenames, but are NOT ignored by Git:")
        for f in gitignore_suggestions:
            w(f"- {f}")
        w("\nIt is highly recommended to add these to your .gitignore file to prevent accidental leaks.")

    # Safety score
    if show_score:
        score = 100
        score -= (len(history_findings["secrets"]) + len(tree_findings["current_secrets"])) * 40
        score -= (len(history_findings["pii"]) + len(tree_findings["nlp_pii"]) + len(ps_findings)) * 20
        score -= len(history_findings["entropy"]) * 10
        score = max(0, min(100, score))
        
        section("SECURITY SUMMARY & SAFE-TO-SHARE SCORE")
        risk_label = "GREEN (Safe to Share)"
        if score < 50:
            risk_label = "RED (High Risk - Do Not Share)"
        elif score < 90:
            risk_label = "YELLOW (Medium Risk - Inspect Before Sharing)"
            
        w(f"Confidence Score: {score}/100 - {risk_label}")
        w(f"- Leaked Secrets: {len(history_findings['secrets']) + len(tree_findings['current_secrets'])}")
        w(f"- PII Detections: {len(history_findings['pii']) + len(tree_findings['nlp_pii']) + len(ps_findings)}")
        w(f"- High Entropy Tokens: {len(history_findings['entropy'])}")

    # LLM Remediation Prompt Section
    section("LLM REMEDIATION PROMPTS")
    w("Use these prompts with ChatGPT/Claude/Gemini to help clean your repository based on our findings.\n")
    
    if has_secrets:
        prompt = (
            "**For Credential Leaks:**\n"
            "I have leaked sensitive credentials in my GitHub repository. "
            "Based on the principle that 'anything pushed to a public repo is already compromised', "
            "what are the exact, step-by-step instructions I must follow to:\n"
            "1. Rotate and revoke these specific credentials at their source.\n"
            "2. Scrub my git history using `git filter-repo` to remove all traces of these secrets.\n"
            "Please be as specific as possible. The leaked credentials include:\n"
        )
        secret_records = []
        for s in history_findings["secrets"]:
            redacted = redact_match(s["match"])
            secret_records.append(f"- {s['type']} in {s['file']}:{s['line']} -> {redacted}")
        for s in tree_findings["current_secrets"]:
            if not s["type"].startswith("PII"):
                redacted = redact_match(s["match"])
                line_str = f":{s['line']}" if "line" in s else ""
                secret_records.append(f"- {s['type']} in {s['file']}{line_str} -> {redacted}")
                
        for rec in sorted(set(secret_records)):
            prompt += f"{rec}\n"
        w(prompt)
    
    if has_pii:
        prompt = (
            "**For PII (Personally Identifiable Information):**\n"
            "I have found Personally Identifiable Information (like names, emails, SSNs, or addresses) "
            "committed to my code repository. What is the best strategy to securely remove this data "
            "using `git filter-repo` while maintaining my project's functionality? Specifically, I need to remove:\n"
        )
        pii_records = []
        for p in history_findings["pii"]:
            redacted = redact_match(p["match"])
            pii_records.append(f"- {p['type']} in {p['file']}:{p['line']} -> {redacted}")
        for p in tree_findings["nlp_pii"]:
            redacted = redact_match(p["match"])
            pii_records.append(f"- {p['type']} in {p['file']} -> {redacted}")
        for p in ps_findings:
            redacted = redact_match(p["Match"])
            pii_records.append(f"- {p['Type']} in {p['File']} -> {redacted}")
            
        for rec in sorted(set(pii_records)):
            prompt += f"{rec}\n"
        w(prompt)

    if not has_secrets and not has_pii:
        w("**All Clear!**")
        w("No credentials or PII were found! You are safe. If you want to ask an LLM for general advice:")
        w("Prompt: How do I ensure my git repository remains free of secrets and PII in the future using pre-commit hooks?")

    report = "\n".join(out)
    print(report)
    if output_file:
        with open(output_file, "w") as f: f.write(report)
        print(f"\nReport saved to {output_file}")

    return total_issues

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full repository secret scanner")
    parser.add_argument("--repo-dir", help="Path to git repository (default: current dir)")
    parser.add_argument("--output", help="Save report to file (default: stdout only)")
    parser.add_argument("--nlp-pii", action="store_true", help="Enable heavy NLP scanning for Names/Pronouns via spaCy")
    parser.add_argument("--ps-crosscheck", action="store_true", help="Enable PowerShell cross-checking for SSNs and common keys")
    parser.add_argument("--all-branches", action="store_true", help="Scan all git branches and history")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format")
    parser.add_argument("--install-hook", action="store_true", help="Install standard fast pre-commit hook")
    parser.add_argument("--install-hook-strict", action="store_true", help="Install strict pre-commit hook (runs NLP and PowerShell crosscheck)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress stderr status messages")
    parser.add_argument("--generate-filter-repo", action="store_true", help="Generate replacements.txt for git filter-repo and print command")
    parser.add_argument("--stdin", action="store_true", help="Scan content from standard input")
    parser.add_argument("--text", help="Scan the text snippet provided in this argument")
    parser.add_argument("--mask", action="store_true", help="Redact all matched secrets in output files/stdout")
    parser.add_argument("--entropy-threshold", type=float, default=3.8, help="Threshold for Shannon entropy (default: 3.8)")
    parser.add_argument("--sensitive-words", help="Comma-separated list of sensitive words to scan for")
    parser.add_argument("--extract-code-blocks", action="store_true", help="Extract and scan only code blocks from Markdown files/snippets")
    parser.add_argument("--context-lines", type=int, default=0, help="Number of surrounding lines of context to print in text report")
    parser.add_argument("--confidence-score", action="store_true", help="Calculate and print a 'Safe-to-Share' confidence score (0-100)")
    args = parser.parse_args()

    if args.install_hook or args.install_hook_strict:
        hook_path = Path(".git/hooks/pre-commit")
        if not Path(".git").exists():
            print("Error: Must run from the root of a git repository to install hooks.")
            sys.exit(1)
        
        cmd_args = ""
        if args.install_hook_strict:
            cmd_args = " --nlp-pii --ps-crosscheck"
            
        hook_content = f"""#!/usr/bin/env bash
echo "Running omni-secret-scanner..."
python scan-secrets.py{cmd_args}
if [ $? -ne 0 ]; then
    echo "❌ Secrets or PII detected! Commit blocked."
    exit 1
fi
"""
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(hook_content, encoding="utf-8")
        try:
            hook_path.chmod(0o755)
        except Exception:
            pass
        mode = "Strict" if args.install_hook_strict else "Standard"
        print(f"{mode} pre-commit hook installed successfully at .git/hooks/pre-commit")
        sys.exit(0)

    if args.repo_dir: os.chdir(args.repo_dir)
    repo_dir = os.getcwd()

    # Load .secretsignore if present
    ignore_files, ignore_tokens = load_secretsignore(repo_dir)

    sensitive_words = []
    if args.sensitive_words:
        sensitive_words = [w.strip() for w in args.sensitive_words.split(",") if w.strip()]

    # Snippet / Stdin scan mode
    if args.stdin or args.text:
        content = ""
        source = "stdin"
        if args.stdin:
            content = sys.stdin.read()
        else:
            content = args.text
            source = "text_snippet"

        snippet_findings = scan_snippet(content, source, entropy_threshold=args.entropy_threshold, ignore_tokens=ignore_tokens, extract_code_blocks=args.extract_code_blocks, sensitive_words=sensitive_words)
        
        # Format snippet findings to match generate_report expected structure
        history_findings = {
            "secrets": snippet_findings["secrets"],
            "pii": snippet_findings["pii"],
            "entropy": snippet_findings["entropy"],
            "commits": []
        }
        tree_findings = {
            "suspicious_files": [],
            "current_secrets": [],
            "nlp_pii": []
        }
        ps_findings = []
        
        total_issues = generate_report(history_findings, tree_findings, ps_findings, args.output, args.format, mask=args.mask, context_lines=args.context_lines, show_score=args.confidence_score, snippet_content=content)
        sys.exit(1 if total_issues > 0 else 0)

    nlp_deidentifier = None
    if args.nlp_pii:
        nlp_deidentifier = init_nlp_deidentifier(quiet=args.quiet)

    ps_findings = []
    if args.ps_crosscheck:
        ps_findings = run_ps_crosscheck(repo_dir, quiet=args.quiet, ignore_tokens=ignore_tokens)

    EXCLUDE_PATTERNS = [
        "*.lock", "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.woff*",
        "*.ttf", "*.eot", "*.min.js", "*.min.css", "package-lock.json", "*.sum",
        ".gitignore", ".gitattributes", ".git/", "node_modules/", "vendor/", "dist/",
        "build/", "__pycache__/", "*.pyc",
    ]
    # Add files from .secretsignore to exclusion list
    EXCLUDE_PATTERNS.extend(ignore_files)

    history_findings = scan_history(EXCLUDE_PATTERNS, args.all_branches, quiet=args.quiet, entropy_threshold=args.entropy_threshold, ignore_tokens=ignore_tokens, sensitive_words=sensitive_words)
    tree_findings = scan_current_tree(repo_dir, EXCLUDE_PATTERNS, nlp_deidentifier, quiet=args.quiet, ignore_tokens=ignore_tokens, sensitive_words=sensitive_words, extract_code_blocks=args.extract_code_blocks)
    
    total_issues = generate_report(history_findings, tree_findings, ps_findings, args.output, args.format, mask=args.mask, context_lines=args.context_lines, show_score=args.confidence_score)

    # Automated git filter-repo Generator
    if args.generate_filter_repo:
        unique_secrets = set()
        for s in history_findings["secrets"]:
            unique_secrets.add(s["match"])
        for p in history_findings["pii"]:
            unique_secrets.add(p["match"])
        for e in history_findings["entropy"]:
            unique_secrets.add(e["token"])
        for s in tree_findings["current_secrets"]:
            unique_secrets.add(s["match"])
        for p in ps_findings:
            unique_secrets.add(p["Match"])

        # Filter out empty strings
        unique_secrets = {sec.strip() for sec in unique_secrets if sec.strip()}

        if unique_secrets:
            with open("replacements.txt", "w", encoding="utf-8") as f:
                for sec in sorted(unique_secrets):
                    f.write(f"{sec}==>[REDACTED]\n")
            print(f"\nGenerated replacements.txt with {len(unique_secrets)} unique secrets/PII items.")
            
            # Automatically append replacements.txt to .gitignore if not present
            gitignore_path = Path(".gitignore")
            add_to_gitignore = True
            if gitignore_path.exists():
                try:
                    lines = gitignore_path.read_text(encoding="utf-8").splitlines()
                    if any("replacements.txt" in line for line in lines):
                        add_to_gitignore = False
                except Exception:
                    pass
            
            if add_to_gitignore:
                try:
                    with open(gitignore_path, "a", encoding="utf-8") as f:
                        f.write("\n# Omni-Secret-Scanner filter-repo replacements\nreplacements.txt\n")
                    print("Added replacements.txt to .gitignore")
                except Exception as e:
                    print(f"Warning: Could not update .gitignore: {e}", file=sys.stderr)

            print("\nTo scrub these secrets from your repository history, run:")
            print("git filter-repo --replace-text replacements.txt --force")
        else:
            print("\nNo secrets or PII were found to redact. replacements.txt was not generated.")
    
    # Exit code > 0 if secrets/PII were found so pre-commit hooks can fail
    if total_issues > 0:
        sys.exit(1)
