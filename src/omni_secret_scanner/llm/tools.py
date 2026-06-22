# SPDX-License-Identifier: MIT
"""Function-calling tools integration.

Exports the scanner's function-calling schema and a tool-execution
interface so LLMs can invoke targeted re-scans during triage.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def get_tool_schema() -> dict[str, Any]:
    """Return the OpenAI/Anthropic function-calling JSON schema for the scanner."""
    return {
        "name": "scan_secrets",
        "description": (
            "Scan a code snippet or text for hardcoded secrets, PII (emails, "
            "SSNs, phone numbers), high-entropy tokens, and prompt-injection "
            "attacks. Returns structured findings and a safety score (0-100)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The code or text to scan.",
                },
                "entropy_threshold": {
                    "type": "number",
                    "description": "Shannon entropy threshold. Default: 3.8",
                    "default": 3.8,
                },
                "mask": {
                    "type": "boolean",
                    "description": "Redact matched secrets in output. Default: false.",
                    "default": False,
                },
                "sanitize": {
                    "type": "boolean",
                    "description": "Neutralise injection strings in output. Default: false.",
                    "default": False,
                },
            },
            "required": ["text"],
        },
        "returns": {
            "type": "object",
            "description": (
                "Findings dict with keys: secrets, pii, entropy, injections, "
                "safety_score, injection_risk."
            ),
        },
    }


def execute_tool_call(tool_name: str, arguments: dict) -> dict:
    """Execute a tool call from an LLM. Returns the tool response.

    Currently supports only 'scan_secrets'. Extensible for future tools.
    """
    if tool_name == "scan_secrets":
        from ..detectors import scan_snippet

        text = arguments.get("text", "")
        entropy_threshold = arguments.get("entropy_threshold", 3.8)
        mask = arguments.get("mask", False)

        findings = scan_snippet(
            text,
            "llm_tool_call",
            entropy_threshold=entropy_threshold,
        )

        from ..reporters.base import injection_risk_score

        inj_risk = injection_risk_score(findings.get("injections", []))
        score = max(0, min(100,
            100 - len(findings.get("secrets", [])) * 40
                - len(findings.get("pii", [])) * 20
                - len(findings.get("entropy", [])) * 10
        ))

        if mask:
            from ..utils.redaction import redact_match
            for section in ("secrets", "pii", "entropy"):
                for f in findings.get(section, []):
                    f["match"] = redact_match(f.get("match", ""))

        return {
            "findings": findings,
            "safety_score": score,
            "injection_risk": inj_risk,
        }

    return {"error": f"Unknown tool: {tool_name}"}


def get_tools_for_openai() -> list[dict]:
    """Return tools array in OpenAI function-calling format."""
    schema = get_tool_schema()
    return [{
        "type": "function",
        "function": {
            "name": schema["name"],
            "description": schema["description"],
            "parameters": schema["parameters"],
        },
    }]


def get_tools_for_anthropic() -> list[dict]:
    """Return tools array in Anthropic tool-use format."""
    schema = get_tool_schema()
    return [{
        "name": schema["name"],
        "description": schema["description"],
        "input_schema": schema["parameters"],
    }]
