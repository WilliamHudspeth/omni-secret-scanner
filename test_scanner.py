import os
import sys
import re
import pytest
import shutil
from pathlib import Path

# Add parent directory to sys.path to import the scanner module
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import target functions from scan-secrets.py
import importlib
scanner = importlib.import_module("scan-secrets")

# ==============================================================================
# 1. Entropy & Token Exclusion Tests
# ==============================================================================

def test_shannon_entropy():
    # Test empty string
    assert scanner.shannon_entropy("") == 0.0
    # Test identical characters (minimum entropy)
    assert scanner.shannon_entropy("aaaaa") == 0.0
    # Test uniform characters (higher entropy)
    # log2(4) = 2.0
    assert scanner.shannon_entropy("abcd") == 2.0
    # Test deterministic calculation
    h1 = scanner.shannon_entropy("randomString123!#")
    h2 = scanner.shannon_entropy("randomString123!#")
    assert h1 == h2
    assert h1 > 3.0

def test_is_ignored_entropy_token():
    # Test standard UUID exclusion
    assert scanner.is_ignored_entropy_token("123e4567-e89b-12d3-a456-426614174000") is True
    # Test invalid UUID format
    assert scanner.is_ignored_entropy_token("123e4567-e89b-12d3-a456-42661417400g") is False
    # Test base64 string exclusion (24+ characters of A-Za-z0-9+/ with up to two '=' padding)
    assert scanner.is_ignored_entropy_token("c29tZVJhbmRvbUJhc2U2NFN0cmluZ1Rlc3Q=") is True
    # Test short string
    assert scanner.is_ignored_entropy_token("short") is False

# ==============================================================================
# 2. Path, Line Offset, and Ignore File Tests
# ==============================================================================

def test_get_line_number_from_offset():
    text = "line1\nline2\nline3\nline4"
    assert scanner.get_line_number_from_offset(text, 0) == 1  # 'l' in line1
    assert scanner.get_line_number_from_offset(text, 5) == 1  # '\n' after line1
    assert scanner.get_line_number_from_offset(text, 6) == 2  # 'l' in line2
    assert scanner.get_line_number_from_offset(text, 12) == 3 # 'l' in line3
    assert scanner.get_line_number_from_offset(text, len(text)) == 4

def test_match_exclude():
    exclude_patterns = ["*.lock", "node_modules/", "vendor/*", "secrets.json"]
    # Match direct extension glob
    assert scanner.match_exclude("package.lock", exclude_patterns) is True
    # Match directory base name with trailing slash
    assert scanner.match_exclude("node_modules/", exclude_patterns) is True
    # Match file basename
    assert scanner.match_exclude("secrets.json", exclude_patterns) is True
    # No match
    assert scanner.match_exclude("src/index.js", exclude_patterns) is False

def test_load_secretsignore(tmp_path):
    # Verify behavior when no ignore file exists
    ignore_files, ignore_tokens = scanner.load_secretsignore(str(tmp_path))
    assert ignore_files == []
    assert ignore_tokens == []

    # Create dummy .secretsignore
    ignore_content = (
        "# Comment line\n"
        "*.log\n"
        "token: ghp_myFakePersonalGithubToken123456\n"
        "token: sbp_mySupabaseTokenRepresentation\n"
        "config/settings.json\n"
    )
    ignore_file_path = tmp_path / ".secretsignore"
    ignore_file_path.write_text(ignore_content, encoding="utf-8")

    ignore_files, ignore_tokens = scanner.load_secretsignore(str(tmp_path))
    assert "*.log" in ignore_files
    assert "config/settings.json" in ignore_files
    assert "ghp_myFakePersonalGithubToken123456" in ignore_tokens
    assert "sbp_mySupabaseTokenRepresentation" in ignore_tokens

# ==============================================================================
# 3. Patch Extraction Tests
# ==============================================================================

def test_extract_added_lines():
    patch_text = (
        "diff --git a/src/main.py b/src/main.py\n"
        "index 123456..789012 100644\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "@@ -1,4 +1,5 @@\n"
        " import os\n"
        "+api_key = \"AIzaSyFakeGoogleApiKey1234567890\"\n"
        " def main():\n"
        "+    print(\"Hello\")\n"
    )
    exclude_patterns = ["tests/"]
    added_lines = scanner.extract_added_lines(patch_text, exclude_patterns)
    assert len(added_lines) == 2
    # Check first added line
    file_path, line_no, content = added_lines[0]
    assert file_path == "src/main.py"
    assert line_no == 1
    assert "AIzaSyFakeGoogleApiKey1234567890" in content

# ==============================================================================
# 4. Scanner Engines & Detections
# ==============================================================================

def test_scan_snippet_regex_detections():
    # AWS key detection
    res = scanner.scan_snippet("export AWS_KEY=AKIA1234567890ABCDEF", "snippet")
    assert any(x["type"] == "AWS Access Key ID" for x in res["secrets"])
    assert any(x["match"] == "AKIA1234567890ABCDEF" for x in res["secrets"])

    # Google API Key detection
    res = scanner.scan_snippet("const key = 'AIzaSyA12345678901234567890123456789012'", "snippet")
    assert any(x["type"] == "Google API Key" for x in res["secrets"])

    # GitHub Token detection
    res = scanner.scan_snippet("ghp_myGitHubPersonalAccessSecretToken123456", "snippet")
    assert any(x["type"] == "GitHub Token" for x in res["secrets"])

    # Phone & SSN detections (PII)
    res = scanner.scan_snippet("Contact me at (555) 123-4567 or SSN 123-45-6789", "snippet")
    assert any(x["type"] == "Phone Number (US)" for x in res["pii"])
    assert any(x["type"] == "SSN (US)" for x in res["pii"])

    # Credit Card & IBAN detections (PII)
    res = scanner.scan_snippet("Card: 4111 2222 3333 4444, IBAN: DE89370400440532013000", "snippet")
    assert any(x["type"] == "Credit Card" for x in res["pii"])
    assert any(x["type"] == "IBAN" for x in res["pii"])

def test_scan_snippet_config_detections():
    # Docker config detection
    res = scanner.scan_snippet("ENV SECRET_KEY = 'super_secret_docker_password'", "snippet")
    assert any(x["type"] == "Docker Password/Token" for x in res["secrets"])

    # Kubernetes client-cert detection
    res = scanner.scan_snippet("client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCgRFRVJUSUZJQ0FURS0tLS0tCg==", "snippet")
    assert any(x["type"] == "Kubernetes Config Secret" for x in res["secrets"])

    # Terraform provider credentials
    res = scanner.scan_snippet("aws_access_key = \"my_terraform_access_key\"", "snippet")
    assert any(x["type"] == "Terraform Hardcoded Credential" for x in res["secrets"])

def test_scan_snippet_obfuscation():
    # Test base64 obfuscation: 'AKIA1234567890ABCDEF' base64 encoded is 'QUtJQTEyMzQ1Njc4OTBBQkNERUY='
    b64_secret = "QUtJQTEyMzQ1Njc4OTBBQkNERUY="
    res = scanner.scan_snippet(f"const hidden = '{b64_secret}'", "snippet")
    assert any(x["type"] == "Obfuscated:AWS Access Key ID" for x in res["secrets"])

def test_scan_snippet_sensitive_words():
    res = scanner.scan_snippet("some random text with confidential data", "snippet", sensitive_words=["confidential"])
    assert any(x["type"] == "Sensitive Word: confidential" for x in res["secrets"])

def test_scan_snippet_code_blocks():
    md_content = (
        "This is an ignored paragraph with an API key AIzaSyA1234567890123456789012345678901\n"
        "```python\n"
        "key = 'ghp_myGitHubPersonalAccessSecretToken123456'\n"
        "```\n"
    )
    # extract_code_blocks = True: should skip Google key outside code block, capture GitHub key inside code block
    res = scanner.scan_snippet(md_content, "readme.md", extract_code_blocks=True)
    assert any(x["type"] == "GitHub Token" for x in res["secrets"])
    assert not any(x["type"] == "Google API Key" for x in res["secrets"])

# ==============================================================================
# 5. Redaction Core & Dry Run Tests
# ==============================================================================

def test_redact_file_content():
    content = (
        "AWS key: AKIA1234567890ABCDEF\n"
        "Contact: 555-123-4567\n"
        "Keep confidential stuff secret."
    )
    redacted = scanner.redact_file_content(content, sensitive_words=["confidential"])
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "555-123-4567" not in redacted
    assert "confidential" not in redacted
    assert "AKIA[REDACTED]" in redacted
    assert "555-[REDACTED]" in redacted

def test_redact_file_in_place(tmp_path):
    file_path = tmp_path / "leaks.txt"
    file_path.write_text("AWS API: AKIA1234567890ABCDEF\nNormal line here.", encoding="utf-8")

    # Regular redaction (modifies file, saves backup)
    success = scanner.redact_file_in_place(str(file_path))
    assert success is True
    assert file_path.exists()
    assert "AKIA1234567890ABCDEF" not in file_path.read_text(encoding="utf-8")
    
    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
    assert backup_path.exists()
    assert "AKIA1234567890ABCDEF" in backup_path.read_text(encoding="utf-8")

def test_redact_file_in_place_dryrun(tmp_path):
    file_path = tmp_path / "leaks_dryrun.txt"
    original_content = "AWS API: AKIA1234567890ABCDEF\nNormal line here."
    file_path.write_text(original_content, encoding="utf-8")

    # Dryrun redaction (does not modify file, does not create backup, returns False since leaks exist)
    success = scanner.redact_file_in_place(str(file_path), dryrun=True)
    assert success is False
    assert file_path.read_text(encoding="utf-8") == original_content
    
    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
    assert not backup_path.exists()

# ==============================================================================
# 6. Current Working Tree & Submodule Scans
# ==============================================================================

def test_scan_current_tree(tmp_path):
    # Setup mock workspace files
    leak_file = tmp_path / "leaks.py"
    leak_file.write_text("api_key = 'AIzaSyA12345678901234567890123456789012'", encoding="utf-8")
    
    ignored_file = tmp_path / "vendor" / "dep.py"
    ignored_file.parent.mkdir(parents=True, exist_ok=True)
    ignored_file.write_text("api_key = 'AIzaSyA12345678901234567890123456789012'", encoding="utf-8")

    suspicious_file = tmp_path / ".env"
    suspicious_file.write_text("PORT=8080", encoding="utf-8")

    exclude_patterns = ["vendor/", ".git/"]
    findings = scanner.scan_current_tree(str(tmp_path), exclude_patterns)

    # Detections check
    assert any(x["type"] == "Google API Key" and x["file"] == "leaks.py" for x in findings["current_secrets"])
    # Ignore check
    assert not any(x["file"] == "vendor/dep.py" for x in findings["current_secrets"])
    # Suspicious filename check
    assert ".env" in findings["suspicious_files"]

def test_get_submodules_empty(tmp_path):
    # No .gitmodules
    assert scanner.get_submodules(str(tmp_path)) == []

# ==============================================================================
# 7. Dry-Run Repo Output Verification
# ==============================================================================

def test_run_dryrun_repo_scan(capsys, tmp_path):
    # Create structure
    (tmp_path / "main.py").write_text("print(1)", encoding="utf-8")
    (tmp_path / "secrets.key").write_text("secret", encoding="utf-8")
    exclude_patterns = [".git/"]
    
    scanner.run_dryrun_repo_scan(str(tmp_path), exclude_patterns, scan_submodules=False, all_branches=False, reflog=False)
    captured = capsys.readouterr()
    
    assert "DRY RUN: SECRET SCANNER AUDIT REPORT" in captured.out
    assert "Total files to scan: 2" in captured.out
    assert "secrets.key" in captured.out
