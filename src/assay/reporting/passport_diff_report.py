"""Passport Diff HTML report.

Self-contained HTML with inline CSS. Sections:
  - Verdict banner (regression / no regression / integrity failure)
  - Reliance change (R-class comparison)
  - Claim delta table
  - Coverage delta
  - Scope changes
  - Supersession chain
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from assay.passport_diff import PassportDiffResult


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

_VERDICT_COLORS = {
    0: ("#4c1", "No Regression"),
    1: ("#e05d44", "Regression Detected"),
    2: ("#e05d44", "Integrity Failure"),
}

_STATUS_COLORS = {
    "new": "#97ca00",
    "removed": "#e05d44",
    "improved": "#4c1",
    "regressed": "#e05d44",
    "unchanged": "#9f9f9f",
}

_CSS = """\
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 900px; margin: 0 auto; padding: 24px; background: #fafafa; color: #1a1a1a; }
h1 { font-size: 1.5rem; margin-bottom: 4px; }
h2 { font-size: 1.1rem; margin: 24px 0 8px; border-bottom: 2px solid #e0e0e0; padding-bottom: 4px; }
.verdict-banner { padding: 20px; border-radius: 8px; margin-bottom: 24px; }
.verdict-banner h1 { color: #fff; }
.verdict-banner .ids { font-size: 0.8rem; color: rgba(255,255,255,0.8); word-break: break-all; }
.reliance-box { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; padding: 12px;
                background: #f5f5f5; border-radius: 8px; }
.r-class { font-size: 2rem; font-weight: 800; }
.r-arrow { font-size: 1.5rem; color: #999; }
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e0e0e0; font-size: 0.9rem; }
th { background: #f0f0f0; font-weight: 600; }
.status-chip { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700;
               font-size: 0.75rem; color: #fff; }
.coverage-bar { height: 12px; border-radius: 6px; background: #e0e0e0; margin: 4px 0; }
.coverage-fill { height: 100%; border-radius: 6px; }
.scope-section { margin-bottom: 12px; }
.scope-added { color: #4c1; }
.scope-removed { color: #e05d44; }
.supersession { background: #f0f7ff; border: 1px solid #cce0ff; border-radius: 8px; padding: 16px;
                margin-bottom: 16px; }
.footer { margin-top: 24px; padding-top: 12px; border-top: 1px solid #e0e0e0;
          font-size: 0.8rem; color: #999; }
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(text: Any) -> str:
    return html.escape(str(text)) if text else ""


def _status_chip(status: str) -> str:
    color = _STATUS_COLORS.get(status, "#999")
    return f'<span class="status-chip" style="background:{color}">{status.upper()}</span>'


def _coverage_bar(pct: int, color: str) -> str:
    return (
        f'<div class="coverage-bar">'
        f'<div class="coverage-fill" style="width:{pct}%;background:{color}"></div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_passport_diff_html(result: PassportDiffResult) -> str:
    """Render passport diff result as self-contained HTML."""
    exit_code = result.exit_code
    verdict_color, verdict_label = _VERDICT_COLORS.get(exit_code, ("#999", "Unknown"))

    if result.integrity_error:
        verdict_detail = _esc(result.integrity_error)
    elif result.has_regression:
        regression_types = []
        if any(d.status == "regressed" for d in result.claim_deltas):
            regression_types.append("claims")
        if result.coverage_delta and result.coverage_delta.status == "regressed":
            regression_types.append("coverage")
        if result.reliance_changed:
            from assay.passport_diff import _RELIANCE_ORDER
            if _RELIANCE_ORDER.get(result.reliance_b, 0) < _RELIANCE_ORDER.get(result.reliance_a, 0):
                regression_types.append("reliance class")
        verdict_detail = f"Regression in: {', '.join(regression_types)}"
    else:
        verdict_detail = "No regressions detected between passports."

    # Reliance comparison
    reliance_html = ""
    if result.reliance_a or result.reliance_b:
        r_a_color = "#4c1" if result.reliance_a >= result.reliance_b else "#e05d44"
        r_b_color = "#4c1" if result.reliance_b >= result.reliance_a else "#e05d44"
        reliance_html = f"""
        <h2>Reliance Class</h2>
        <div class="reliance-box">
            <span class="r-class" style="color:{r_a_color}">{_esc(result.reliance_a or '—')}</span>
            <span class="r-arrow">&rarr;</span>
            <span class="r-class" style="color:{r_b_color}">{_esc(result.reliance_b or '—')}</span>
            <span style="color:#666;font-size:0.9rem">
                {'Changed' if result.reliance_changed else 'Unchanged'}
            </span>
        </div>
        """

    # Claim delta table
    claims_html = ""
    if result.claim_deltas:
        rows = []
        for d in result.claim_deltas:
            rows.append(
                f"<tr><td>{_esc(d.claim_id)}</td>"
                f"<td>{_esc(d.a_result or '—')}</td>"
                f"<td>{_esc(d.b_result or '—')}</td>"
                f"<td>{_status_chip(d.status)}</td></tr>"
            )
        claims_html = f"""
        <h2>Claims</h2>
        <table>
        <tr><th>Claim</th><th>A Result</th><th>B Result</th><th>Status</th></tr>
        {''.join(rows)}
        </table>
        """

    # Coverage delta
    coverage_html = ""
    if result.coverage_delta:
        cd = result.coverage_delta
        cd_dict = cd.to_dict()
        a_pct = cd_dict.get("a_pct", 0)
        b_pct = cd_dict.get("b_pct", 0)
        cov_color = "#4c1" if cd.status != "regressed" else "#e05d44"

        sites_html = ""
        if cd.added_sites:
            sites_html += "<div><strong>Added:</strong> " + ", ".join(_esc(s) for s in cd.added_sites) + "</div>"
        if cd.removed_sites:
            sites_html += "<div><strong>Removed:</strong> " + ", ".join(_esc(s) for s in cd.removed_sites) + "</div>"

        coverage_html = f"""
        <h2>Coverage</h2>
        <div style="display:flex;gap:24px;margin-bottom:12px">
            <div style="flex:1">
                <div style="font-size:0.85rem;color:#666">Passport A: {cd.a_covered}/{cd.a_total} ({a_pct}%)</div>
                {_coverage_bar(a_pct, '#999')}
            </div>
            <div style="flex:1">
                <div style="font-size:0.85rem;color:#666">Passport B: {cd.b_covered}/{cd.b_total} ({b_pct}%)</div>
                {_coverage_bar(b_pct, cov_color)}
            </div>
        </div>
        <div>{_status_chip(cd.status)}</div>
        {sites_html}
        """

    # Scope changes
    scope_html = ""
    if result.scope_changes:
        sections = []
        for key, changes in result.scope_changes.items():
            added = changes.get("added", [])
            removed = changes.get("removed", [])
            parts = []
            if added:
                parts.append(
                    f"<div class='scope-added'>+ {', '.join(_esc(a) for a in added)}</div>"
                )
            if removed:
                parts.append(
                    f"<div class='scope-removed'>- {', '.join(_esc(r) for r in removed)}</div>"
                )
            sections.append(
                f"<div class='scope-section'><strong>{_esc(key)}:</strong>{''.join(parts)}</div>"
            )
        scope_html = f"""
        <h2>Scope Changes</h2>
        {''.join(sections)}
        """

    # Supersession
    supersession_html = ""
    if result.is_supersession:
        supersession_html = f"""
        <div class="supersession">
            <strong>Supersession detected:</strong> Passport B supersedes Passport A.
        </div>
        """

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assay Trust Diff</title>
<style>{_CSS}</style>
</head>
<body>

<div class="verdict-banner" style="background:{verdict_color}">
    <h1>{_esc(verdict_label)}</h1>
    <div style="font-size:0.9rem;color:rgba(255,255,255,0.9);margin-top:4px">{verdict_detail}</div>
    <div class="ids">A: {_esc(result.passport_a_id)} &rarr; B: {_esc(result.passport_b_id)}</div>
</div>

{supersession_html}
{reliance_html}
{claims_html}
{coverage_html}
{scope_html}

<div class="footer">
    Generated by Assay Trust Diff &middot; {now}
</div>

</body>
</html>
"""
