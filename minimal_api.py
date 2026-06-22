# SPDX-License-Identifier: MIT
"""
minimal_api.py — FastAPI microservice wrapper for omni-secret-scanner.

Exposes scan_snippet as an HTTP endpoint.  Not part of the core package;
this is a standalone file you can run directly.

Usage:
    pip install fastapi uvicorn
    python minimal_api.py

Endpoints:
    POST /scan       — scan a text snippet
    GET  /health     — health check
    GET  /schema     — LLM tool schema

Run with: uvicorn minimal_api:app --reload
"""

from __future__ import annotations

import json
import sys
from typing import Optional

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
except ImportError:
    print(
        "fastapi and pydantic are required.  Install with:\n"
        "  pip install fastapi uvicorn pydantic",
        file=sys.stderr,
    )
    sys.exit(1)

from omni_secret_scanner import __version__
from omni_secret_scanner.detectors import scan_snippet
from omni_secret_scanner.reporters.base import injection_risk_score


app = FastAPI(
    title="omni-secret-scanner API",
    version=__version__,
    description="Production-grade secret, PII & injection scanner — HTTP API",
)


class ScanRequest(BaseModel):
    text: str
    entropy_threshold: float = 3.8
    mask: bool = False
    sanitize: bool = False


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    """Scan a text snippet for secrets, PII, and injection attacks."""
    findings = scan_snippet(
        req.text,
        "api_snippet",
        entropy_threshold=req.entropy_threshold,
    )

    score = max(0, min(100,
        100 - len(findings["secrets"]) * 40
            - len(findings["pii"]) * 20
            - len(findings.get("entropy", [])) * 10
    ))
    inj_risk = injection_risk_score(findings.get("injections", []))

    return {
        "findings": findings,
        "safety_score": score,
        "injection_risk": inj_risk,
        "scanner_version": __version__,
    }


@app.get("/health")
def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "version": __version__}


@app.get("/schema")
def schema() -> dict:
    """Return the OpenAI function-calling tool schema."""
    from omni_secret_scanner.cli import print_tool_schema
    import io
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        print_tool_schema()
    finally:
        sys.stdout = old_stdout
    return json.loads(buf.getvalue())


# ------------------------------------------------------------------
# Run directly
# ------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    print(f"omni-secret-scanner API v{__version__}", file=sys.stderr)
    print("Endpoints:", file=sys.stderr)
    print("  POST /scan   — scan a text snippet", file=sys.stderr)
    print("  GET  /health — health check", file=sys.stderr)
    print("  GET  /schema — LLM tool schema", file=sys.stderr)
    uvicorn.run(app, host="0.0.0.0", port=8000)
