"""X-Ray diagnostic HTML report.

Self-contained HTML with inline CSS. Sections:
  - Grade banner
  - State summary
  - Findings table
  - "What's missing for next grade" CTA
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from assay.xray import XRayResult


# ---------------------------------------------------------------------------
# Grade styling
# ---------------------------------------------------------------------------

_GRADE_COLORS = {
    "A": "#4c1",
    "B": "#97ca00",
    "C": "#dfb317",
    "D": "#fe7d37",
    "F": "#e05d44",
}

_SEVERITY_COLORS = {
    "pass": "#4c1",
    "warn": "#dfb317",
    "fail": "#e05d44",
    "info": "#9f9f9f",
}

_SEVERITY_LABELS = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "info": "INFO",
}


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 900px; margin: 0 auto; padding: 24px; background: #fafafa; color: #1a1a1a; }
h1 { font-size: 1.6rem; margin-bottom: 4px; }
h2 { font-size: 1.1rem; margin: 24px 0 8px; border-bottom: 2px solid #e0e0e0; padding-bottom: 4px; }
.grade-banner { display: flex; align-items: center; gap: 16px; padding: 20px; border-radius: 8px;
                margin-bottom: 24px; }
.grade-letter { font-size: 3rem; font-weight: 800; line-height: 1; }
.grade-detail { flex: 1; }
.grade-detail .path { font-size: 0.85rem; color: #666; word-break: break-all; }
.state-bar { display: flex; gap: 12px; margin-bottom: 16px; }
.state-chip { padding: 4px 12px; border-radius: 12px; font-size: 0.85rem; font-weight: 600; }
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e0e0e0; font-size: 0.9rem; }
th { background: #f0f0f0; font-weight: 600; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700;
       font-size: 0.75rem; color: #fff; }
.cta { background: #f0f7ff; border: 1px solid #cce0ff; border-radius: 8px; padding: 16px;
       margin-top: 16px; }
.cta h3 { font-size: 1rem; margin-bottom: 8px; }
.cta ul { margin-left: 20px; }
.cta li { margin-bottom: 4px; font-size: 0.9rem; }
.footer { margin-top: 24px; padding-top: 12px; border-top: 1px solid #e0e0e0;
          font-size: 0.8rem; color: #999; }
"""


# ---------------------------------------------------------------------------
# Render functions
# ---------------------------------------------------------------------------

def _esc(text: Any) -> str:
    return html.escape(str(text)) if text else ""


def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#999")
    label = _SEVERITY_LABELS.get(severity, severity.upper())
    return f'<span class="sev" style="background:{color}">{label}</span>'


def render_xray_html(result: XRayResult) -> str:
    """Render X-Ray result as self-contained HTML."""
    grade_color = _GRADE_COLORS.get(result.overall_grade, "#999")
    state_label = result.state.state if result.state else "UNKNOWN"
    state_reason = result.state.reason if result.state else ""

    # State chip color
    state_colors = {
        "FRESH": "#4c1", "STALE": "#fe7d37", "CHALLENGED": "#dfb317",
        "SUPERSEDED": "#9f9f9f", "REVOKED": "#e05d44",
    }
    state_color = state_colors.get(state_label, "#999")

    # Build findings table rows
    rows = []
    for f in result.findings:
        rows.append(
            f"<tr><td>{_severity_badge(f.severity)}</td>"
            f"<td>{_esc(f.category)}</td>"
            f"<td><strong>{_esc(f.title)}</strong><br>"
            f"<span style='color:#666;font-size:0.85rem'>{_esc(f.detail)}</span></td>"
            f"<td style='font-size:0.85rem'>{_esc(f.remediation)}</td></tr>"
        )
    findings_html = "\n".join(rows)

    # CTA for next grade
    cta_html = ""
    if result.missing_for_next_grade:
        items = "\n".join(f"<li>{_esc(m)}</li>" for m in result.missing_for_next_grade)
        cta_html = f"""
        <div class="cta">
            <h3>To improve from grade {_esc(result.overall_grade)}:</h3>
            <ul>{items}</ul>
        </div>
        """

    # Finding counts
    counts = result.to_dict().get("finding_counts", {})
    counts_text = " / ".join(
        f"{v} {k}" for k, v in counts.items() if v > 0
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assay X-Ray: Grade {_esc(result.overall_grade)}</title>
<style>{_CSS}</style>
</head>
<body>

<div class="grade-banner" style="background:{grade_color}20; border-left: 6px solid {grade_color}">
    <div class="grade-letter" style="color:{grade_color}">{_esc(result.overall_grade)}</div>
    <div class="grade-detail">
        <h1>Passport X-Ray</h1>
        <div class="path">{_esc(result.passport_path)}</div>
    </div>
</div>

<div class="state-bar">
    <span class="state-chip" style="background:{state_color}20; color:{state_color}; border:1px solid {state_color}">
        {_esc(state_label)}
    </span>
    <span style="font-size:0.85rem; color:#666; align-self:center">{_esc(state_reason)}</span>
</div>

<h2>Findings ({_esc(counts_text)})</h2>
<table>
<tr><th style="width:70px">Status</th><th style="width:100px">Category</th><th>Finding</th><th style="width:200px">Remediation</th></tr>
{findings_html}
</table>

{cta_html}

<div class="footer">
    Generated by Assay X-Ray &middot; {now}
</div>

</body>
</html>
"""
