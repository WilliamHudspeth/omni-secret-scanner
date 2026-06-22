# SPDX-License-Identifier: MIT
"""HTML report generator — self-contained dark-mode interactive report."""

import html as _html
from datetime import datetime

from .base import calculate_safety_score, injection_risk_score

_VERSION = "9.0.0"


def generate_html_report(
    history_findings: dict,
    tree_findings: dict,
    ps_findings: list,
    semgrep_findings: list,
    injection_findings: list,
    mask: bool = False,
    sanitize: bool = False,
) -> str:
    """Return a fully self-contained dark-mode HTML audit report string."""
    from ..utils.redaction import redact_match, sanitize_match

    def esc(s: str) -> str:
        return _html.escape(str(s))

    def redact_if(s: str) -> str:
        return redact_match(s) if mask else s

    def sanitize_if(s: str) -> str:
        return sanitize_match(s) if sanitize else s

    score = calculate_safety_score(history_findings, tree_findings, ps_findings, semgrep_findings)
    inj_risk = injection_risk_score(injection_findings)
    total_secrets = len(history_findings["secrets"]) + len(tree_findings["current_secrets"])
    total_pii = len(history_findings["pii"]) + len(tree_findings["nlp_pii"]) + len(ps_findings)
    total_entropy = len(history_findings["entropy"])
    total_semgrep = len(semgrep_findings)

    score_color = "#22c55e" if score >= 90 else ("#f97316" if score >= 50 else "#ef4444")
    inj_color = "#a855f7" if inj_risk > 0 else "#22c55e"

    def make_rows(items: list, cols: list) -> str:
        if not items:
            return '<tr><td colspan="100%" class="empty">None found.</td></tr>'
        rows = []
        for item in items:
            cells = "".join(f"<td>{esc(redact_if(str(item.get(c, ''))))}</td>" for c in cols)
            rows.append(f"<tr>{cells}</tr>")
        return "".join(rows)

    def section(
        title: str, badge_count: int, badge_color: str, table_html: str, icon: str = "⚠"
    ) -> str:
        badge_cls = "badge-danger" if badge_count > 0 else "badge-ok"
        return (
            f"<details {'open' if badge_count > 0 else ''}>"
            f'<summary>{icon} {esc(title)} <span class="badge {badge_cls}">{badge_count}</span></summary>'
            f'<div class="table-wrap">{table_html}</div></details>'
        )

    def table(headers: list, rows_html: str) -> str:
        ths = "".join(f"<th>{esc(h)}</th>" for h in headers)
        return f"<table><thead><tr>{ths}</tr></thead><tbody>{rows_html}</tbody></table>"

    def secret_rows(items: list, commit_mode: bool = False) -> str:
        if not items:
            return '<tr><td colspan="4" class="empty">None found.</td></tr>'
        rows = []
        for s in items:
            val = redact_if(s.get("match", s.get("token", "")))
            loc = (
                esc(str(s.get("commit", "?")))
                if commit_mode
                else esc(f"{s.get('file', '?')}:{s.get('line', '?')}")
            )
            rows.append(
                f"<tr><td>{esc(s['type'])}</td><td>{loc}</td>"
                f'<td class="mono copy-cell" title="Click to copy" onclick="copyText(this)">{esc(val)}</td></tr>'
            )
        return "".join(rows)

    inj_rows = (
        "".join(
            f"<tr><td>{esc(inj['type'])}</td>"
            f"<td>{esc(inj.get('file', inj.get('commit', '?')))}</td>"
            f"<td>{esc(str(inj.get('line', '?')))}</td>"
            f'<td class="mono copy-cell" onclick="copyText(this)">'
            f"{esc(sanitize_if(inj.get('match', '')))}</td></tr>"
            for inj in injection_findings
        )
        or '<tr><td colspan="4" class="empty">None found.</td></tr>'
    )

    ps_rows = (
        "".join(
            f"<tr><td>{esc(p['Type'])}</td><td>{esc(p['File'])}</td>"
            f'<td class="mono copy-cell" onclick="copyText(this)">{esc(redact_if(p["Match"]))}</td></tr>'
            for p in ps_findings
        )
        or '<tr><td colspan="3" class="empty">None found.</td></tr>'
    )

    sg_rows = (
        "".join(
            f"<tr><td>{esc(s['rule'])}</td>"
            f"<td>{esc('{}:{}'.format(s.get('file', '?'), s.get('line', '?')))}</td>"
            f"<td>{esc(s.get('severity', ''))}</td>"
            f'<td class="mono">{esc(s.get("message", ""))}</td></tr>'
            for s in semgrep_findings
        )
        or '<tr><td colspan="4" class="empty">None found.</td></tr>'
    )

    susp_rows = (
        "".join(f"<tr><td>{esc(f)}</td></tr>" for f in tree_findings["suspicious_files"])
        or '<tr><td class="empty">None found.</td></tr>'
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    LOCK, PERSON, CHART, MEMO = "\U0001f510", "\U0001f464", "\U0001f4ca", "\U0001f4dd"
    FOLDER, SIREN, BRAIN, DESKTOP = "\U0001f4c2", "\U0001f6a8", "\U0001f9e0", "\U0001f5a5"
    MAG, SKULL = "\U0001f50d", "\U0001f480"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>omni-secret-scanner – Audit Report</title>
<style>
:root{{--bg:#0d1117;--surface:#161b22;--surface2:#1e2530;--border:#30363d;--text:#e6edf3;
--muted:#8b949e;--red:#f85149;--orange:#f97316;--yellow:#d29922;--green:#3fb950;
--cyan:#79c0ff;--purple:#bc8cff;--radius:8px;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;}}
header{{background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);padding:2rem;border-bottom:1px solid var(--border);}}
header h1{{font-size:1.8rem;color:var(--cyan);letter-spacing:-.5px;}}
header p{{color:var(--muted);font-size:.9rem;margin-top:.3rem;}}
.container{{max-width:1200px;margin:0 auto;padding:2rem 1.5rem;}}
.score-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem;}}
.score-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.2rem;text-align:center;}}
.score-card .number{{font-size:2.4rem;font-weight:700;line-height:1;}}
.score-card .label{{font-size:.75rem;color:var(--muted);margin-top:.4rem;text-transform:uppercase;letter-spacing:.05em;}}
details{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1rem;overflow:hidden;}}
summary{{padding:.9rem 1.2rem;cursor:pointer;font-weight:600;font-size:.95rem;display:flex;align-items:center;gap:.6rem;list-style:none;user-select:none;}}
summary::-webkit-details-marker{{display:none;}}
summary:hover{{background:var(--surface2);}}
.badge{{display:inline-flex;align-items:center;justify-content:center;min-width:1.6rem;height:1.4rem;border-radius:9999px;font-size:.7rem;font-weight:700;padding:0 .45rem;margin-left:auto;}}
.badge-danger{{background:#3d1a1a;color:var(--red);border:1px solid var(--red);}}
.badge-ok{{background:#0d2a0d;color:var(--green);border:1px solid var(--green);}}
.table-wrap{{overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;font-size:.87rem;}}
th{{background:var(--surface2);color:var(--muted);text-align:left;padding:.6rem 1rem;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);}}
td{{padding:.55rem 1rem;border-bottom:1px solid var(--border);vertical-align:top;}}
tr:last-child td{{border-bottom:none;}}
tr:hover td{{background:var(--surface2);}}
.mono{{font-family:'Cascadia Code','Consolas',monospace;font-size:.82rem;color:var(--cyan);word-break:break-all;}}
.copy-cell{{cursor:pointer;}}
.copy-cell:hover{{color:var(--green);}}
.empty{{color:var(--muted);font-style:italic;text-align:center;padding:1rem!important;}}
footer{{text-align:center;padding:2rem;color:var(--muted);font-size:.8rem;border-top:1px solid var(--border);margin-top:2rem;}}
#toast{{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--surface);border:1px solid var(--green);color:var(--green);padding:.6rem 1.2rem;border-radius:var(--radius);opacity:0;transition:opacity .3s;font-size:.85rem;pointer-events:none;}}
</style>
</head>
<body>
<div id="toast">Copied!</div>
<header>
  <h1>&#x1F512; omni-secret-scanner v{_VERSION}</h1>
  <p>Audit Report &mdash; {now}</p>
</header>
<div class="container">
<div class="score-grid">
  <div class="score-card"><div class="number" style="color:{esc(score_color)}">{score}</div><div class="label">Safety Score /100</div></div>
  <div class="score-card"><div class="number" style="color:{"#ef4444" if total_secrets > 0 else "#22c55e"}">{total_secrets}</div><div class="label">Secrets</div></div>
  <div class="score-card"><div class="number" style="color:{"#f97316" if total_pii > 0 else "#22c55e"}">{total_pii}</div><div class="label">PII</div></div>
  <div class="score-card"><div class="number" style="color:{"#d29922" if total_entropy > 0 else "#22c55e"}">{total_entropy}</div><div class="label">Entropy Strings</div></div>
  <div class="score-card"><div class="number" style="color:{esc(inj_color)}">{inj_risk}</div><div class="label">Injection Risk /100</div></div>
  <div class="score-card"><div class="number" style="color:{"#bc8cff" if total_semgrep > 0 else "#22c55e"}">{total_semgrep}</div><div class="label">SAST Issues</div></div>
</div>
{section("History – Secrets & Credentials", len(history_findings["secrets"]), "#ef4444", table(["Type", "Location", "Match"], secret_rows(history_findings["secrets"])), LOCK)}
{section("History – PII", len(history_findings["pii"]), "#f97316", table(["Type", "Location", "Match"], secret_rows(history_findings["pii"])), PERSON)}
{section("History – High-Entropy Strings", len(history_findings["entropy"]), "#d29922", table(["Type", "Location", "Token"], secret_rows(history_findings["entropy"])), CHART)}
{section("History – Suspicious Commit Messages", len(history_findings["commits"]), "#f97316", table(["Type", "Commit", "Match"], secret_rows(history_findings["commits"], commit_mode=True)), MEMO)}
{section("Current Tree – Suspicious Filenames", len(tree_findings["suspicious_files"]), "#d29922", table(["File"], susp_rows), FOLDER)}
{section("Current Tree – Secrets & PII", len(tree_findings["current_secrets"]), "#ef4444", table(["Type", "Location", "Match"], secret_rows(tree_findings["current_secrets"])), SIREN)}
{section("Current Tree – NLP PII", len(tree_findings["nlp_pii"]), "#f97316", table(["Type", "Location", "Match"], secret_rows(tree_findings["nlp_pii"])), BRAIN)}
{section("PowerShell Cross-Check", len(ps_findings), "#f97316", table(["Type", "File", "Match"], ps_rows), DESKTOP)}
{section("Semgrep SAST", len(semgrep_findings), "#bc8cff", table(["Rule", "Location", "Severity", "Message"], sg_rows), MAG)}
{section("Prompt Injection Detections", len(injection_findings), "#bc8cff", table(["Type", "Location", "Line", "Match"], inj_rows), SKULL)}
</div>
<footer>Generated by <strong>omni-secret-scanner v{_VERSION}</strong> &mdash; {now}</footer>
<script>
function copyText(el){{const txt=el.innerText;navigator.clipboard.writeText(txt).then(()=>{{
const t=document.getElementById('toast');t.style.opacity=1;
setTimeout(()=>{{t.style.opacity=0;}},1800);}});}}
</script>
</body></html>"""
