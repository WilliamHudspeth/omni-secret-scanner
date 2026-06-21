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
}

CUSTOM_PII_PATTERNS = {
    "Email Address": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    "Phone Number (US)": r"\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}",
    # Upgraded SSN Regex via User's PowerShell cross-check recommendation
    "SSN (US)": r"(?!(000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}",
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

def scan_commit_messages():
    cmd = ["git", "log", "--pretty=format:%H%n%B%n---END---"]
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

def scan_history(exclude_patterns: list) -> dict:
    findings = {
        "secrets": [],
        "pii": [],
        "entropy": [],
        "commits": [],
    }
    
    # Check if .git exists to avoid failure if running outside git
    if not Path(".git").exists() and not Path("../.git").exists():
        print("Warning: Not running inside a Git repository. Skipping history scan.", file=sys.stderr)
        return findings

    print("Scanning file history...", file=sys.stderr)
    result = subprocess.run(
        ["git", "log", "-p", "--no-color"],
        capture_output=True, text=True, errors="replace"
    )
    if result.returncode != 0:
        print("Fatal: not a git repository or git error", file=sys.stderr)
        return findings

    added_lines = extract_added_lines(result.stdout, exclude_patterns)
    all_secret_patterns = {**CUSTOM_SECRET_PATTERNS, **GITROB_CONTENT_PATTERNS, **AI_PATTERNS}

    for file_path, line_no, content in added_lines:
        for name, pattern in all_secret_patterns.items():
            try:
                for m in re.finditer(pattern, content):
                    findings["secrets"].append({"type": name, "file": file_path, "line": line_no, "match": m.group(0).strip()})
            except re.error:
                pass
        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, content):
                findings["pii"].append({"type": name, "file": file_path, "line": line_no, "match": m.group(0).strip()})
        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", content)
        for m in candidates:
            token = m.group(0)
            if token.isdigit(): continue
            if all(c in "0123456789abcdefABCDEF" for c in token) and len(token) in (32, 40): continue
            entropy = shannon_entropy(token)
            if entropy > 3.8:
                findings["entropy"].append({"file": file_path, "line": line_no, "token": token, "entropy": round(entropy, 2)})

    print("Scanning commit messages...", file=sys.stderr)
    for commit_hash, message in scan_commit_messages():
        for name, pattern in all_secret_patterns.items():
            for m in re.finditer(pattern, message):
                findings["commits"].append({"type": name, "commit": commit_hash[:8], "match": m.group(0).strip()})
        for name, pattern in CUSTOM_PII_PATTERNS.items():
            for m in re.finditer(pattern, message):
                findings["commits"].append({"type": f"PII:{name}", "commit": commit_hash[:8], "match": m.group(0).strip()})
        candidates = re.finditer(r"\b[A-Za-z0-9_\-]{16,}\b", message)
        for m in candidates:
            token = m.group(0)
            if token.isdigit(): continue
            entropy = shannon_entropy(token)
            if entropy > 3.8:
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

def init_nlp_deidentifier():
    try:
        from deidentification import Deidentification, DeidentificationConfig
    except ImportError:
        print("Error: The 'text-deidentification' package is not installed.", file=sys.stderr)
        print("Please install it by running: pip install text-deidentification", file=sys.stderr)
        sys.exit(1)
        
    try:
        config = DeidentificationConfig(spacy_model='en_core_web_sm', save_tokens=True, excluded_entities=set())
        deidentifier = Deidentification(config)
        return deidentifier
    except Exception as e:
        print(f"Error loading NLP model: {e}", file=sys.stderr)
        print("Please ensure the spaCy model is downloaded: python -m spacy download en_core_web_sm", file=sys.stderr)
        sys.exit(1)

def run_ps_crosscheck(repo_dir: str):
    print("Running PowerShell Cross-Check...", file=sys.stderr)
    ps_script = """
$fileList = Get-ChildItem -Path "{repo_dir}" -Recurse -File
$findings = @()

foreach ($file in $fileList) {{
    switch -Regex ($file.Extension) {{
        "txt|csv|md|json|yml|yaml|env|py|xml" {{
            $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "(?!(000|666|9))\d{{3}}-(?!00)\d{{2}}-(?!0000)\d{{4}}") {{
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
    # Replace backslashes for PowerShell path
    safe_repo_dir = str(repo_dir).replace("\\", "\\\\")
    script_path = Path(repo_dir) / ".ps_crosscheck.ps1"
    script_path.write_text(ps_script.format(repo_dir=safe_repo_dir))
    
    try:
        result = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)], capture_output=True, text=True)
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
            except json.JSONDecodeError:
                return []
        return []
    finally:
        if script_path.exists():
            script_path.unlink()

def scan_current_tree(repo_dir: str, exclude_patterns: list, nlp_deidentifier=None) -> dict:
    findings = {
        "suspicious_files": [],
        "current_secrets": [],
        "nlp_pii": []
    }
    print("Scanning current working tree...", file=sys.stderr)
    root = Path(repo_dir).resolve()
    all_secret_patterns = {**CUSTOM_SECRET_PATTERNS, **GITROB_CONTENT_PATTERNS, **AI_PATTERNS}

    for path in root.rglob("*"):
        if path.is_dir(): continue
        rel_path = str(path.relative_to(root))
        if match_exclude(rel_path, exclude_patterns): continue

        for glob_pat in GITROB_SUSPICIOUS_FILES:
            from fnmatch import fnmatch
            if fnmatch(path.name, glob_pat) or fnmatch(rel_path, glob_pat):
                findings["suspicious_files"].append(rel_path)
                break

        if path.suffix == '.ipynb':
            findings["current_secrets"].extend(scan_ipynb(path, all_secret_patterns))
        else:
            try: 
                content = path.read_text(errors="ignore")
            except Exception: 
                continue
            
            # Standard Secret/Regex PII Scanning
            findings["current_secrets"].extend(scan_text(content, rel_path, all_secret_patterns))
            for name, pattern in CUSTOM_PII_PATTERNS.items():
                for m in re.finditer(pattern, content):
                    findings["current_secrets"].append({"type": f"PII:{name}", "file": rel_path, "match": m.group(0).strip()})

            # NLP PII Scanning
            if nlp_deidentifier and path.suffix in ['.txt', '.md', '.csv', '.json', '.yml', '.yaml', '.py']:
                try:
                    # Run it backwards over the text to populate tokens dictionary
                    nlp_deidentifier.deidentify(content)
                    tokens = nlp_deidentifier.get_identified_elements()
                    for ent in tokens.get("entities", []):
                        findings["nlp_pii"].append({"file": rel_path, "type": "NAME", "match": ent["text"]})
                    for pron in tokens.get("pronouns", []):
                        findings["nlp_pii"].append({"file": rel_path, "type": "PRONOUN", "match": pron["text"]})
                except Exception:
                    pass

    return findings

# ------------------------------------------------------------------------------
# Report generation
# ------------------------------------------------------------------------------
def print_report(history_findings: dict, tree_findings: dict, ps_findings: list, output_file=None):
    out = []
    def w(txt=""): out.append(txt)
    def section(title):
        w(f"\n{'='*60}")
        w(f"  {title}")
        w(f"{'='*60}")

    section("HISTORY SCAN – SECRETS / CREDENTIALS")
    if history_findings["secrets"]:
        for s in history_findings["secrets"]: w(f"[{s['type']}] {s['file']}:{s['line']} -> {s['match']}")
    else: w("None found.")

    section("HISTORY SCAN – PII")
    if history_findings["pii"]:
        for p in history_findings["pii"]: w(f"[{p['type']}] {p['file']}:{p['line']} -> {p['match']}")
    else: w("None found.")

    section("HISTORY SCAN – HIGH ENTROPY STRINGS")
    if history_findings["entropy"]:
        for e in history_findings["entropy"]: w(f"File {e['file']}:{e['line']}  entropy={e['entropy']} -> {e['token']}")
    else: w("None found.")

    section("HISTORY SCAN – COMMIT MESSAGES")
    if history_findings["commits"]:
        for c in history_findings["commits"]: w(f"Commit {c['commit']} [{c['type']}] -> {c.get('match') or c.get('token')}")
    else: w("No suspicious content in commit messages.")

    section("CURRENT TREE – SUSPICIOUS FILENAMES")
    if tree_findings["suspicious_files"]:
        for f in tree_findings["suspicious_files"]: w(f"  Suspicious file: {f}")
    else: w("No suspicious filenames found.")

    section("CURRENT TREE – CONTENT SECRETS & REGEX PII")
    if tree_findings["current_secrets"]:
        for s in tree_findings["current_secrets"]: w(f"[{s['type']}] {s['file']} -> {s['match']}")
    else: w("No secrets found in current files.")

    if tree_findings["nlp_pii"]:
        section("CURRENT TREE – NLP PII (NAMES & PRONOUNS)")
        for n in tree_findings["nlp_pii"]:
            w(f"[{n['type']}] {n['file']} -> {n['match']}")

    if ps_findings:
        section("POWERSHELL CROSS-CHECK FINDINGS")
        for p in ps_findings:
            w(f"[{p['Type']}] {p['File']} -> {p['Match']}")

    # LLM Remediation Prompt Section
    section("LLM REMEDIATION PROMPTS")
    w("Use these prompts with ChatGPT/Claude/Gemini to help clean your repository based on our findings.\n")
    
    has_secrets = len(history_findings["secrets"]) > 0 or len(tree_findings["current_secrets"]) > 0
    has_pii = len(history_findings["pii"]) > 0 or len(tree_findings["nlp_pii"]) > 0 or len(ps_findings) > 0

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
        types_leaked = set()
        for s in history_findings["secrets"]: types_leaked.add(s["type"])
        for s in tree_findings["current_secrets"]: 
            if not s["type"].startswith("PII"): types_leaked.add(s["type"])
        for t in types_leaked:
            prompt += f"- {t}\n"
        w(prompt)
    
    if has_pii:
        prompt = (
            "**For PII (Personally Identifiable Information):**\n"
            "I have found Personally Identifiable Information (like names, emails, SSNs, or addresses) "
            "committed to my code repository. What is the best strategy to securely remove this data "
            "using `git filter-repo` while maintaining my project's functionality? Specifically, I need to remove:\n"
        )
        types_leaked = set()
        for p in history_findings["pii"]: types_leaked.add(p["type"])
        for p in tree_findings["nlp_pii"]: types_leaked.add(p["type"])
        for p in ps_findings: types_leaked.add(p["Type"])
        for t in types_leaked:
            prompt += f"- {t}\n"
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full repository secret scanner")
    parser.add_argument("--repo-dir", help="Path to git repository (default: current dir)")
    parser.add_argument("--output", help="Save report to file (default: stdout only)")
    parser.add_argument("--nlp-pii", action="store_true", help="Enable heavy NLP scanning for Names/Pronouns via spaCy")
    parser.add_argument("--ps-crosscheck", action="store_true", help="Enable PowerShell cross-checking for SSNs and common keys")
    args = parser.parse_args()

    if args.repo_dir: os.chdir(args.repo_dir)
    repo_dir = os.getcwd()

    nlp_deidentifier = None
    if args.nlp_pii:
        nlp_deidentifier = init_nlp_deidentifier()

    ps_findings = []
    if args.ps_crosscheck:
        ps_findings = run_ps_crosscheck(repo_dir)

    EXCLUDE_PATTERNS = [
        "*.lock", "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.woff*",
        "*.ttf", "*.eot", "*.min.js", "*.min.css", "package-lock.json", "*.sum",
        ".gitignore", ".gitattributes", ".git/", "node_modules/", "vendor/", "dist/",
        "build/", "__pycache__/", "*.pyc",
    ]

    history_findings = scan_history(EXCLUDE_PATTERNS)
    tree_findings = scan_current_tree(repo_dir, EXCLUDE_PATTERNS, nlp_deidentifier)
    print_report(history_findings, tree_findings, ps_findings, args.output)
