# SPDX-License-Identifier: MIT
"""Tiered inference orchestrator.

Routes findings to the appropriate model tier:
  - Tier 1 (fast/cheap): Binary FP triage on high-volume findings
  - Tier 2 (slow/expensive): Deep exploitability analysis on complex findings

Supports local models (via HTTP endpoint) and cloud APIs (OpenAI, Anthropic).
Falls back to deterministic heuristics when no model is configured.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Callable, Optional


# ------------------------------------------------------------------
# Model provider abstraction
# ------------------------------------------------------------------

class ModelProvider:
    """Abstract interface for LLM providers."""

    def complete(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        raise NotImplementedError


class OpenAIModel(ModelProvider):
    """OpenAI API provider."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def complete(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        if not self.api_key:
            return "[ERROR: OPENAI_API_KEY not set]"
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=kwargs.get("max_tokens", 1024),
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"[ERROR: OpenAI API call failed: {e}]"


class AnthropicModel(ModelProvider):
    """Anthropic API provider."""

    def __init__(self, model: str = "claude-sonnet-4-20250514", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def complete(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        if not self.api_key:
            return "[ERROR: ANTHROPIC_API_KEY not set]"
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=kwargs.get("max_tokens", 1024),
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        except Exception as e:
            return f"[ERROR: Anthropic API call failed: {e}]"


class LocalModel(ModelProvider):
    """Local model via HTTP endpoint (Ollama, vLLM, llama.cpp server)."""

    def __init__(self, endpoint: str = "http://localhost:11434/api/generate",
                 model: str = "qwen2.5-coder:3b"):
        self.endpoint = endpoint
        self.model = model

    def complete(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        try:
            import urllib.request
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            payload = json.dumps({
                "model": self.model,
                "prompt": full_prompt,
                "stream": False,
                "options": {"temperature": 0.0, "num_predict": kwargs.get("max_tokens", 512)},
            }).encode()
            req = urllib.request.Request(self.endpoint, data=payload,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read()).get("response", "")
        except Exception as e:
            return f"[ERROR: Local model call failed: {e}]"


# ------------------------------------------------------------------
# Deterministic fallback (no LLM needed)
# ------------------------------------------------------------------

def _deterministic_triage(findings: list[dict]) -> list[dict]:
    """Rule-based triage when no LLM is available."""
    results: list[dict] = []
    for f in findings:
        ftype = f.get("type", "")
        match = f.get("match", "")
        source = f.get("_source", "")
        is_fp = False

        # Known false positive patterns
        if any(p in (ftype or "") for p in ("Cloudflare API Key", "Pinecone", "PRONOUN")):
            is_fp = True
        elif match and len(match) < 6:
            is_fp = True
        elif "validated" in source:
            is_fp = False  # API-validated = real
        elif "taint" in source:
            is_fp = False  # taint = needs review

        results.append({
            **f,
            "triage_verdict": "FALSE_POSITIVE" if is_fp else "TRUE_POSITIVE",
            "triage_confidence": 85 if is_fp else 70,
            "triage_method": "deterministic",
        })
    return results


# ------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------

class TriageOrchestrator:
    """Routes findings through tiered inference pipeline."""

    def __init__(
        self,
        tier1: Optional[ModelProvider] = None,
        tier2: Optional[ModelProvider] = None,
    ):
        self.tier1 = tier1
        self.tier2 = tier2

    def triage_file(
        self,
        filepath: str,
        findings: list[dict],
        risk_level: str,
        file_context: str,
    ) -> list[dict]:
        """Triage all findings for a single file.

        Routes based on risk level:
        - 'critical'/'high' → Tier 2 (deep analysis) if available
        - 'medium'/'low' → Tier 1 (fast binary) if available
        - All → deterministic fallback if no model configured
        """
        from .prompts import build_file_prompt, TRIAGE_SYSTEM_PROMPT, EXPLOITABILITY_SYSTEM_PROMPT

        # Build structured summary of findings
        summary_lines: list[str] = []
        for i, f in enumerate(findings[:20], 1):  # cap at 20 per file
            summary_lines.append(
                f"  {i}. [{f.get('_source', '?')}] {f.get('type', '?')}: "
                f"{f.get('match', '')[:80]}"
            )
        summary = "\n".join(summary_lines)

        if not self.tier1 and not self.tier2:
            return _deterministic_triage(findings)

        # Select tier based on risk
        use_tier2 = risk_level in ("critical", "high") and self.tier2
        model = self.tier2 if use_tier2 else (self.tier1 or self.tier2)
        system = EXPLOITABILITY_SYSTEM_PROMPT if use_tier2 else TRIAGE_SYSTEM_PROMPT
        user = build_file_prompt(filepath, findings, risk_level, file_context, summary)

        if model is None:
            return _deterministic_triage(findings)

        response = model.complete(system, user, max_tokens=2048 if use_tier2 else 512)

        # Parse response into findings
        return self._parse_response(findings, response, use_tier2)

    def _parse_response(
        self, findings: list[dict], response: str, deep: bool = False
    ) -> list[dict]:
        """Parse LLM response and attach verdicts to findings."""
        # Simple heuristic: if response contains TRUE_POSITIVE/FALSE_POSITIVE,
        # apply to findings in order
        results: list[dict] = []
        verdicts = []
        for line in response.splitlines():
            if "TRUE_POSITIVE" in line.upper():
                verdicts.append("TRUE_POSITIVE")
            elif "FALSE_POSITIVE" in line.upper():
                verdicts.append("FALSE_POSITIVE")

        for i, f in enumerate(findings):
            verdict = verdicts[i] if i < len(verdicts) else "UNCERTAIN"
            results.append({
                **f,
                "triage_verdict": verdict,
                "triage_confidence": 90 if deep else 75,
                "triage_method": "llm",
                "triage_response": response[:500] if i == 0 else "",
            })
        return results


# ------------------------------------------------------------------
# Provider factory
# ------------------------------------------------------------------

def create_provider(kind: str, **kwargs) -> Optional[ModelProvider]:
    """Create a model provider from a kind string.

    Supported kinds:
        openai, anthropic, local, none
    """
    if kind == "openai":
        return OpenAIModel(**kwargs)
    elif kind == "anthropic":
        return AnthropicModel(**kwargs)
    elif kind == "local":
        return LocalModel(**kwargs)
    elif kind == "none":
        return None
    else:
        print(f"Warning: Unknown provider '{kind}'. Using deterministic fallback.",
              file=sys.stderr)
        return None
