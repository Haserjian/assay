"""Diff Proof Report: self-contained HTML artifact from assay diff results.

Generates a single HTML file (all CSS inline, no external dependencies) for
sharing diff proof results as a portable, shareable artifact.

Two-layer verdict model:
  Layer 1 (Trust): Comparable | Unverifiable
  Layer 2 (Outcome, only if Comparable): Reproduced | Drifted
"""
from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay import __version__
from assay.diff import DiffResult


# ---------------------------------------------------------------------------
# Verdict / explanation logic
# ---------------------------------------------------------------------------

def compute_verdict(result: DiffResult) -> Tuple[str, Optional[str]]:
    """Compute the two-layer verdict.

    Returns:
        (trust, outcome) where trust is 'Comparable' or 'Unverifiable',
        and outcome is 'Reproduced', 'Drifted', or None (when Unverifiable).
    """
    if not result.both_valid:
        return "Unverifiable", None

    # Check for meaningful deltas
    has_claim_changes = any(cd.status != "unchanged" for cd in result.claim_deltas)
    has_material_delta = _has_material_delta(result)

    if not has_claim_changes and not has_material_delta:
        return "Comparable", "Reproduced"
    return "Comparable", "Drifted"


def _has_material_delta(result: DiffResult) -> bool:
    """Return True if any material delta exists (model, cost, latency, errors, signer, version)."""
    if result.signer_changed or result.version_changed:
        return True
    if result.model_deltas:
        return True
    if result.a_analysis and result.b_analysis:
        a, b = result.a_analysis, result.b_analysis
        if abs(b.cost_usd - a.cost_usd) > 1e-6:
            return True
        if b.errors != a.errors:
            return True
        if (a.latency_p50 is not None and b.latency_p50 is not None
                and abs((b.latency_p50 or 0) - (a.latency_p50 or 0)) > 0):
            return True
    return False


def compute_explanation(result: DiffResult, trust: str, outcome: Optional[str]) -> str:
    """Generate a one-sentence explanation for the verdict."""
    if trust == "Unverifiable":
        return (
            "One or both packs failed integrity verification; "
            "this comparison cannot be trusted."
        )

    parts: List[str] = []

    # Claim summary
    changed = sum(1 for cd in result.claim_deltas if cd.status != "unchanged")
    total = len(result.claim_deltas)
    if changed == 0:
        parts.append("all claims unchanged")
    else:
        parts.append(f"{changed} of {total} claim outcome{'s' if total != 1 else ''} changed")

    # Most notable delta
    notable = _most_notable_delta(result)
    if notable:
        parts.append(notable)

    body = "; ".join(parts)
    return f"The runs are validly comparable; {body}."


def _most_notable_delta(result: DiffResult) -> str:
    """Return the most notable material delta as a short phrase."""
    if result.signer_changed:
        return "signer identity changed"
    if result.version_changed:
        return "verifier version changed"
    if result.a_analysis and result.b_analysis:
        a, b = result.a_analysis, result.b_analysis
        # Latency
        if a.latency_p95 is not None and b.latency_p95 is not None and a.latency_p95 > 0:
            delta_pct = _pct_change(a.latency_p95, b.latency_p95)
            if abs(delta_pct) >= 5:
                direction = "increased" if delta_pct > 0 else "decreased"
                return f"latency {direction} {abs(delta_pct):.0f}%"
        # Cost
        if a.cost_usd > 0:
            delta_pct = _pct_change(a.cost_usd, b.cost_usd)
            if abs(delta_pct) >= 5:
                direction = "increased" if delta_pct > 0 else "decreased"
                return f"cost {direction} {abs(delta_pct):.0f}%"
        # Errors
        if b.errors != a.errors:
            return f"errors changed ({a.errors} → {b.errors})"
    if result.model_deltas:
        added = [m for m in result.model_deltas if m.status == "added"]
        removed = [m for m in result.model_deltas if m.status == "removed"]
        if added or removed:
            return f"model mix changed ({len(added)} added, {len(removed)} removed)"
    return ""


def _pct_change(a: float, b: float) -> float:
    """Return percentage change from a to b. Assumes a > 0."""
    return ((b - a) / a) * 100


def compute_bullets(result: DiffResult, trust: str, outcome: Optional[str]) -> List[str]:
    """Generate up to 3 bullet points explaining the conclusion."""
    bullets: List[str] = []

    # Bullet 1: Trust/comparability reason
    if trust == "Unverifiable":
        bullets.append(
            "One or both packs failed integrity checks — comparison cannot be trusted"
        )
        if result.integrity_errors:
            bullets.append(result.integrity_errors[0])
        return bullets[:3]

    bullets.append("Both packs are structurally valid and safely comparable")

    # Bullet 2: Claim change summary
    changed = sum(1 for cd in result.claim_deltas if cd.status != "unchanged")
    total = len(result.claim_deltas)
    if total == 0:
        bullets.append("No claim data available")
    elif changed == 0:
        bullets.append("All claims unchanged")
    else:
        regressed = sum(1 for cd in result.claim_deltas if cd.regressed)
        detail = f"{changed} of {total} claim outcomes changed"
        if regressed:
            detail += f" ({regressed} regressed)"
        bullets.append(detail)

    # Bullet 3: Most notable material delta
    notable = _most_notable_delta(result)
    if notable:
        bullets.append(notable.capitalize())
    else:
        bullets.append("No material deltas detected")

    return bullets[:3]


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def generate_diff_json(result: DiffResult, output_path: Path) -> Path:
    """Write diff_result.json alongside the HTML report.

    The JSON matches DiffResult.to_dict() plus verdict/explanation fields.
    """
    trust, outcome = compute_verdict(result)
    explanation = compute_explanation(result, trust, outcome)
    payload: Dict[str, Any] = result.to_dict()
    payload["verdict"] = {
        "trust": trust,
        "outcome": outcome,
        "explanation": explanation,
        "bullets": compute_bullets(result, trust, outcome),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# HTML generation helpers
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --blue: #58a6ff;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
a { color: var(--blue); }
.wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
h1 { margin: 0 0 6px; font-size: 22px; }
h2 { margin: 0 0 12px; font-size: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.badge {
  display: inline-block; border-radius: 6px; padding: 3px 10px;
  font-size: 13px; font-weight: 700; margin-right: 8px;
}
.badge-green { background: rgba(63,185,80,.15); color: var(--green); border: 1px solid var(--green); }
.badge-red   { background: rgba(248,81,73,.15);  color: var(--red);   border: 1px solid var(--red);   }
.badge-yellow{ background: rgba(210,153,34,.15); color: var(--yellow); border: 1px solid var(--yellow); }
.badge-blue  { background: rgba(88,166,255,.15); color: var(--blue);  border: 1px solid var(--blue);  }
.muted { color: var(--muted); }
.mono { font-family: var(--mono); font-size: 12px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 640px) { .grid2 { grid-template-columns: 1fr; } }
.pack-card { background: #0d1117; border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
.pack-card h3 { margin: 0 0 10px; font-size: 14px; }
.kv { margin-bottom: 6px; }
.kv .k { color: var(--muted); font-size: 12px; }
.kv .v { font-weight: 500; margin-top: 1px; word-break: break-all; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; border-bottom: 1px solid var(--border); padding: 8px 10px; vertical-align: middle; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
tr.regressed td { background: rgba(248,81,73,.08); }
tr.improved td  { background: rgba(63,185,80,.08); }
tr.new td       { background: rgba(88,166,255,.08); }
.status-pass  { color: var(--green); font-weight: 600; }
.status-fail  { color: var(--red);   font-weight: 600; }
.status-absent{ color: var(--muted); }
.delta-badge { display: inline-block; border-radius: 4px; padding: 1px 7px; font-size: 12px; font-weight: 700; }
.delta-unchanged { color: var(--muted); }
.delta-improved  { color: var(--green); }
.delta-regressed { color: var(--red); background: rgba(248,81,73,.15); }
.delta-new       { color: var(--blue); }
.delta-removed   { color: var(--muted); text-decoration: line-through; }
.bullets { margin: 10px 0 0; padding-left: 20px; }
.bullets li { margin-bottom: 4px; }
.explanation { font-style: italic; color: var(--muted); margin-top: 8px; }
.footer-hash { font-family: var(--mono); font-size: 11px; color: var(--muted); word-break: break-all; }
.section-label { font-size: 12px; color: var(--muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px; }
"""


def _esc(v: Any) -> str:
    return html.escape(str(v))


def _bool_badge(val: Optional[bool], true_text: str = "PASS", false_text: str = "FAIL") -> str:
    if val is True:
        return f'<span class="badge badge-green">{_esc(true_text)}</span>'
    if val is False:
        return f'<span class="badge badge-red">{_esc(false_text)}</span>'
    return f'<span class="badge badge-yellow">N/A</span>'


def _status_cell(val: Optional[bool]) -> str:
    if val is True:
        return '<span class="status-pass">PASS</span>'
    if val is False:
        return '<span class="status-fail">FAIL</span>'
    return '<span class="status-absent">–</span>'


def _delta_badge(status: str) -> str:
    symbols = {
        "unchanged": ("▸", "delta-unchanged"),
        "improved":  ("↑", "delta-improved"),
        "regressed": ("↓ regressed", "delta-regressed"),
        "new":       ("★ new", "delta-new"),
        "removed":   ("✕ removed", "delta-removed"),
    }
    text, cls = symbols.get(status, (status, "delta-unchanged"))
    return f'<span class="delta-badge {_esc(cls)}">{_esc(text)}</span>'


def _pct_str(a: float, b: float) -> str:
    if a == 0:
        return "–"
    pct = ((b - a) / a) * 100
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}%"


def _fmt_cost(v: float) -> str:
    return f"${v:.4f}"


def _fmt_ms(v: Optional[float]) -> str:
    if v is None:
        return "–"
    return f"{v:.0f} ms"


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_header(result: DiffResult, trust: str, outcome: Optional[str],
                   explanation: str, bullets: List[str], generated_at: str) -> str:
    trust_badge = (
        f'<span class="badge badge-green">Comparable</span>'
        if trust == "Comparable"
        else f'<span class="badge badge-red">Unverifiable</span>'
    )
    outcome_badge = ""
    if outcome == "Reproduced":
        outcome_badge = '<span class="badge badge-green">Reproduced</span>'
    elif outcome == "Drifted":
        outcome_badge = '<span class="badge badge-yellow">Drifted</span>'

    bullets_html = "".join(f"<li>{_esc(b)}</li>" for b in bullets)

    return f"""
<div class="card">
  <h1>Assay Diff Proof Report</h1>
  <div style="margin-bottom:10px">
    {trust_badge}{outcome_badge}
  </div>
  <p class="explanation">{_esc(explanation)}</p>
  <ul class="bullets">
    {bullets_html}
  </ul>
  <div class="muted" style="margin-top:12px;font-size:12px">
    Generated {_esc(generated_at)} &middot; Assay {_esc(__version__)}
  </div>
</div>
"""


def _render_summary_cards(result: DiffResult) -> str:
    def _pack_card(info: Any, label: str) -> str:
        integrity_badge = _bool_badge(info.integrity == "PASS")
        claim_badge = _bool_badge(
            None if info.claim_check == "N/A" else info.claim_check == "PASS"
        )
        fp = info.signer_fingerprint
        fp_display = (fp[:16] + "…" + fp[-8:]) if len(fp) > 28 else fp
        ts = info.timestamp_start[:10] if info.timestamp_start else "–"
        return f"""
<div class="pack-card">
  <h3>{_esc(label)}</h3>
  <div class="kv"><div class="k">Pack ID</div><div class="v mono">{_esc(info.pack_id or "–")}</div></div>
  <div class="kv"><div class="k">Created</div><div class="v">{_esc(ts)}</div></div>
  <div class="kv"><div class="k">Signer fingerprint</div>
    <div class="v mono" title="{_esc(fp)}">{_esc(fp_display or "–")}</div></div>
  <div class="kv"><div class="k">Integrity</div><div class="v">{integrity_badge}</div></div>
  <div class="kv"><div class="k">Claim check</div><div class="v">{claim_badge}</div></div>
  <div class="kv"><div class="k">Receipts</div><div class="v">{_esc(info.n_receipts)}</div></div>
</div>"""

    return f"""
<div class="card">
  <h2>Pack Summary</h2>
  <div class="grid2">
    {_pack_card(result.pack_a, "Pack A — Baseline")}
    {_pack_card(result.pack_b, "Pack B — Current")}
  </div>
</div>
"""


def _render_claims(result: DiffResult) -> str:
    if not result.claim_deltas:
        return """
<div class="card">
  <h2>Claims</h2>
  <p class="muted">No claim data available.</p>
</div>
"""
    rows = []
    for cd in result.claim_deltas:
        row_cls = ""
        if cd.regressed:
            row_cls = "regressed"
        elif cd.status == "improved":
            row_cls = "improved"
        elif cd.status == "new":
            row_cls = "new"
        rows.append(
            f"<tr class='{_esc(row_cls)}'>"
            f"<td class='mono'>{_esc(cd.claim_id)}</td>"
            f"<td>{_status_cell(cd.a_passed)}</td>"
            f"<td>{_status_cell(cd.b_passed)}</td>"
            f"<td>{_delta_badge(cd.status)}</td>"
            f"</tr>"
        )
    tbody = "\n".join(rows)
    return f"""
<div class="card">
  <h2>Claims</h2>
  <table>
    <thead><tr>
      <th>Claim ID</th><th>Pack A</th><th>Pack B</th><th>Delta</th>
    </tr></thead>
    <tbody>{tbody}</tbody>
  </table>
</div>
"""


def _render_material_deltas(result: DiffResult) -> str:
    sections: List[str] = []

    # Signer / Version
    if result.signer_changed:
        sections.append(
            f"<div><strong>Signer:</strong> changed — "
            f"{_esc(result.pack_a.signer_id)} → {_esc(result.pack_b.signer_id)}</div>"
        )
    if result.version_changed:
        sections.append(
            f"<div><strong>Verifier version:</strong> changed — "
            f"{_esc(result.pack_a.verifier_version)} → {_esc(result.pack_b.verifier_version)}</div>"
        )

    # Model mix
    if result.model_deltas:
        model_rows = []
        for md in result.model_deltas:
            delta_str = f"{md.calls_delta:+d}" if md.calls_delta != 0 else "0"
            model_rows.append(
                f"<tr><td class='mono'>{_esc(md.model_id)}</td>"
                f"<td>{_esc(md.a_calls)}</td><td>{_esc(md.b_calls)}</td>"
                f"<td>{_esc(delta_str)}</td>"
                f"<td>{_esc(md.status)}</td></tr>"
            )
        model_table = (
            "<table><thead><tr>"
            "<th>Model</th><th>A calls</th><th>B calls</th><th>Delta</th><th>Status</th>"
            "</tr></thead><tbody>"
            + "\n".join(model_rows)
            + "</tbody></table>"
        )
        sections.append(f"<div><strong>Model Mix</strong>{model_table}</div>")

    # Cost / Latency / Errors
    if result.a_analysis and result.b_analysis:
        a, b = result.a_analysis, result.b_analysis

        # Cost
        cost_delta = b.cost_usd - a.cost_usd
        cost_pct = _pct_str(a.cost_usd, b.cost_usd)
        sections.append(
            f"<div><strong>Cost:</strong> "
            f"{_esc(_fmt_cost(a.cost_usd))} → {_esc(_fmt_cost(b.cost_usd))} "
            f"(Δ {_esc(_fmt_cost(cost_delta))}, {_esc(cost_pct)})</div>"
        )

        # Latency
        if a.latency_p50 is not None or b.latency_p50 is not None:
            p50_a = _fmt_ms(a.latency_p50)
            p50_b = _fmt_ms(b.latency_p50)
            p95_a = _fmt_ms(a.latency_p95)
            p95_b = _fmt_ms(b.latency_p95)
            sections.append(
                f"<div><strong>Latency:</strong> "
                f"p50: {_esc(p50_a)} → {_esc(p50_b)}; "
                f"p95: {_esc(p95_a)} → {_esc(p95_b)}</div>"
            )

        # Errors
        err_delta = b.errors - a.errors
        sections.append(
            f"<div><strong>Errors:</strong> "
            f"{_esc(a.errors)} → {_esc(b.errors)} "
            f"(Δ {'+' if err_delta >= 0 else ''}{_esc(err_delta)})</div>"
        )

    if not sections:
        return ""

    body = "\n".join(f"<div style='margin-bottom:10px'>{s}</div>" for s in sections)
    return f"""
<div class="card">
  <h2>Material Deltas</h2>
  {body}
</div>
"""


def _manifest_sha256(pack_path: str) -> str:
    manifest_path = Path(pack_path) / "pack_manifest.json"
    if not manifest_path.exists():
        return ""
    data = manifest_path.read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _render_footer(result: DiffResult) -> str:
    sha_a = _manifest_sha256(result.pack_a.path)
    sha_b = _manifest_sha256(result.pack_b.path)
    integrity_a = result.pack_a.integrity or "–"
    integrity_b = result.pack_b.integrity or "–"
    fp_a = result.pack_a.signer_fingerprint or "–"
    fp_b = result.pack_b.signer_fingerprint or "–"

    def _int_badge(v: str) -> str:
        if v == "PASS":
            return '<span class="badge badge-green">PASS</span>'
        if v == "FAIL":
            return '<span class="badge badge-red">FAIL</span>'
        return f'<span class="badge badge-yellow">{_esc(v)}</span>'

    return f"""
<div class="card">
  <h2>Proof Footer</h2>
  <div class="kv">
    <div class="k">Pack A path</div>
    <div class="v mono">{_esc(result.pack_a.path)}</div>
  </div>
  <div class="kv">
    <div class="k">Pack A manifest sha256</div>
    <div class="footer-hash">{_esc(sha_a or "–")}</div>
  </div>
  <div class="kv">
    <div class="k">Pack A integrity</div>
    <div class="v">{_int_badge(integrity_a)}</div>
  </div>
  <div class="kv">
    <div class="k">Pack A signer</div>
    <div class="v mono">{_esc(fp_a)}</div>
  </div>
  <div class="kv" style="margin-top:12px">
    <div class="k">Pack B path</div>
    <div class="v mono">{_esc(result.pack_b.path)}</div>
  </div>
  <div class="kv">
    <div class="k">Pack B manifest sha256</div>
    <div class="footer-hash">{_esc(sha_b or "–")}</div>
  </div>
  <div class="kv">
    <div class="k">Pack B integrity</div>
    <div class="v">{_int_badge(integrity_b)}</div>
  </div>
  <div class="kv">
    <div class="k">Pack B signer</div>
    <div class="v mono">{_esc(fp_b)}</div>
  </div>
  <div class="muted" style="margin-top:14px;font-size:12px">
    Verify independently: <code>assay verify-pack ./path/</code>
  </div>
</div>
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def render_html(result: DiffResult) -> str:
    """Render a self-contained HTML proof report from a DiffResult."""
    trust, outcome = compute_verdict(result)
    explanation = compute_explanation(result, trust, outcome)
    bullets = compute_bullets(result, trust, outcome)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header = _render_header(result, trust, outcome, explanation, bullets, generated_at)
    cards = _render_summary_cards(result)
    claims = _render_claims(result)
    deltas = _render_material_deltas(result)
    footer = _render_footer(result)

    title = "Assay Diff Proof Report"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_esc(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="wrap">
    {header}
    {cards}
    {claims}
    {deltas}
    {footer}
  </div>
</body>
</html>"""


def generate_diff_report(result: DiffResult, output_path: Path) -> Path:
    """Generate a self-contained HTML proof report and write it to disk.

    Args:
        result: The DiffResult from diff_packs().
        output_path: Where to write the HTML file.

    Returns:
        The resolved output path.
    """
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(result), encoding="utf-8")
    return output_path
