"""Render a compiled Reviewer Packet directory as a single self-contained HTML file.

This module is a pure presentation layer. It reads already-compiled packet
artifacts (SETTLEMENT.json, COVERAGE_MATRIX.md, etc.) and produces HTML.
No settlement logic lives here — that belongs in reviewer_packet_compile.py.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Required and optional files
# ---------------------------------------------------------------------------

_REQUIRED_FILES = ("SETTLEMENT.json", "COVERAGE_MATRIX.md")
_OPTIONAL_FILES = ("EXECUTIVE_SUMMARY.md", "REVIEWER_GUIDE.md", "CHALLENGE.md", "VERIFY.md")


class PacketRenderError(ValueError):
    """Raised when required packet files are missing or malformed."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_packet_html(packet_dir: Path) -> str:
    """Render a compiled reviewer packet directory as a single self-contained HTML.

    Required files (raises PacketRenderError if absent):
      SETTLEMENT.json, COVERAGE_MATRIX.md

    Optional files (rendered if present, omitted if absent):
      EXECUTIVE_SUMMARY.md, REVIEWER_GUIDE.md, CHALLENGE.md, VERIFY.md
    """
    packet_dir = Path(packet_dir)
    _assert_required_files(packet_dir)

    settlement = _load_json(packet_dir / "SETTLEMENT.json")
    coverage_md = _read(packet_dir / "COVERAGE_MATRIX.md")
    executive_md = _read_optional(packet_dir / "EXECUTIVE_SUMMARY.md")
    reviewer_guide_md = _read_optional(packet_dir / "REVIEWER_GUIDE.md")
    challenge_md = _read_optional(packet_dir / "CHALLENGE.md")
    verify_md = _read_optional(packet_dir / "VERIFY.md")
    scope_manifest = _load_json_optional(packet_dir / "SCOPE_MANIFEST.json")

    state = settlement.get("settlement_state", "UNKNOWN")
    color = _STATE_COLORS.get(state, "#555")
    label = _STATE_LABELS.get(state, "")
    packet_id = settlement.get("packet_id", "unknown")
    workflow_name = scope_manifest.get("workflow_name", "") if scope_manifest else ""
    title = workflow_name or packet_id
    generated_at = settlement.get("generated_at", "")
    expires_at = settlement.get("expires_at", "")
    integrity = settlement.get("integrity_state", "—")
    claim = settlement.get("claim_state", "—")
    freshness = settlement.get("freshness_state", "—")
    scope = settlement.get("scope_state", "—")
    regression = settlement.get("regression_state", "—")
    trust_tier = settlement.get("trust_tier", "—")
    signer_identity = settlement.get("signer", {}).get("identity", "—")
    signer_fingerprint = settlement.get("signer", {}).get("fingerprint", "")
    settlement_basis = settlement.get("settlement_basis", [])
    primary_reason = settlement_basis[0] if settlement_basis else ""

    coverage_html = _coverage_md_to_html(coverage_md)

    sections: list[str] = []
    if executive_md:
        sections.append(_section("Summary", _md_to_html(executive_md)))
    sections.append(_section("Coverage", coverage_html))
    if reviewer_guide_md:
        sections.append(_section("Reviewer guide", _md_to_html(reviewer_guide_md)))
    if challenge_md:
        sections.append(_section("Challenge", _md_to_html(challenge_md)))
    if verify_md:
        sections.append(_section("Verify yourself", _md_to_html(verify_md)))

    fingerprint_html = (
        f'<div class="meta-cell"><span class="label">Signer fingerprint</span>'
        f'<code class="fingerprint">{_esc(signer_fingerprint[:16])}…</code></div>'
        if signer_fingerprint else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Reviewer Packet — {_esc(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="shell">

    <header>
      <p class="eyebrow">Reviewer Packet</p>
      <h1>{_esc(title)}</h1>
      <div class="verdict" style="background:{color}">
        <strong>{_esc(state.replace("_", " ").title())}</strong>
        {f'<span>{_esc(label)}</span>' if label else ''}
        {f'<span class="basis">{_esc(primary_reason)}</span>' if primary_reason else ''}
      </div>
    </header>

    <section class="meta-grid">
      <div class="meta-cell">
        <span class="label">Packet ID</span>
        <code>{_esc(packet_id)}</code>
      </div>
      <div class="meta-cell">
        <span class="label">Integrity</span>
        <strong class="{_tone(integrity)}">{_esc(integrity)}</strong>
      </div>
      <div class="meta-cell">
        <span class="label">Claims</span>
        <strong class="{_tone(claim)}">{_esc(claim)}</strong>
      </div>
      <div class="meta-cell">
        <span class="label">Freshness</span>
        <strong class="{_freshness_tone(freshness)}">{_esc(freshness)}</strong>
      </div>
      <div class="meta-cell">
        <span class="label">Scope</span>
        <strong class="{_scope_tone(scope)}">{_esc(scope)}</strong>
      </div>
      <div class="meta-cell">
        <span class="label">Regression</span>
        <strong class="{_regression_tone(regression)}">{_esc(regression)}</strong>
      </div>
      <div class="meta-cell">
        <span class="label">Trust tier</span>
        <strong>{_esc(trust_tier)}</strong>
      </div>
      <div class="meta-cell">
        <span class="label">Signer</span>
        <strong>{_esc(signer_identity)}</strong>
      </div>
      {fingerprint_html}
      <div class="meta-cell">
        <span class="label">Generated</span>
        <span>{_esc(generated_at[:10] if generated_at else "—")}</span>
      </div>
      <div class="meta-cell">
        <span class="label">Expires</span>
        <span>{_esc(expires_at[:10] if expires_at else "—")}</span>
      </div>
    </section>

    {''.join(sections)}

    <footer>
      <p>Generated by Assay &middot; <code>{_esc(packet_id)}</code></p>
    </footer>

  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Internals: file I/O
# ---------------------------------------------------------------------------

def _assert_required_files(packet_dir: Path) -> None:
    missing = [name for name in _REQUIRED_FILES if not (packet_dir / name).exists()]
    if missing:
        raise PacketRenderError(
            f"Required packet file(s) missing in {packet_dir}: {', '.join(missing)}"
        )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PacketRenderError(f"Malformed JSON in {path}: {exc}") from exc


def _load_json_optional(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Internals: HTML helpers
# ---------------------------------------------------------------------------

def _section(heading: str, content: str) -> str:
    return (
        f'<section class="section">'
        f"<h2>{_esc(heading)}</h2>"
        f"{content}"
        f"</section>"
    )


def _esc(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _tone(value: str) -> str:
    if value == "PASS":
        return "pass"
    if value == "FAIL":
        return "fail"
    return ""


def _freshness_tone(value: str) -> str:
    if value == "FRESH":
        return "pass"
    if value == "STALE":
        return "warn"
    return ""


def _scope_tone(value: str) -> str:
    if value == "BOUNDED":
        return "pass"
    if value == "OUT_OF_SCOPE":
        return "fail"
    return ""


def _regression_tone(value: str) -> str:
    if value == "NONE":
        return "pass"
    if value == "REGRESSED":
        return "fail"
    return ""


def _md_to_html(text: str) -> str:
    """Minimal Markdown → HTML for prose sections. No external dependencies."""
    lines = text.splitlines()
    out: list[str] = []
    in_pre = False
    in_list = False

    for line in lines:
        stripped = line.rstrip()

        if in_pre:
            if stripped.startswith("```"):
                out.append("</code></pre>")
                in_pre = False
            else:
                out.append(_esc(stripped))
            continue

        if stripped.startswith("```"):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("<pre><code>")
            in_pre = True
            continue

        if stripped.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h4>{_esc(stripped[4:])}</h4>")
        elif stripped.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{_esc(stripped[3:])}</h3>")
        elif stripped.startswith("# "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<h3>{_esc(stripped[2:])}</h3>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
        elif stripped == "":
            if in_list:
                out.append("</ul>")
                in_list = False
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{_inline(stripped)}</p>")

    if in_list:
        out.append("</ul>")
    if in_pre:
        out.append("</code></pre>")

    return "\n".join(out)


def _inline(text: str) -> str:
    """Inline Markdown: bold, code, links."""
    text = _esc(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        r'<a href="\2" rel="noopener">\1</a>',
        text,
    )
    return text


def _coverage_md_to_html(md: str) -> str:
    """Convert a COVERAGE_MATRIX.md pipe table to an HTML table."""
    lines = [l.strip() for l in md.splitlines()]
    table_lines = [l for l in lines if l.startswith("|")]
    if not table_lines:
        return f"<div class='prose'><pre>{_esc(md)}</pre></div>"

    rows = [
        [c.strip() for c in line.strip("|").split("|")]
        for line in table_lines
    ]
    if len(rows) < 2:
        return f"<div class='prose'><pre>{_esc(md)}</pre></div>"

    headers = rows[0]
    data_rows = rows[2:]  # rows[1] is the separator line

    header_html = "".join(f"<th>{_esc(h)}</th>" for h in headers)

    body_rows: list[str] = []
    for row in data_rows:
        cells = row + [""] * max(0, len(headers) - len(row))
        status = cells[1].strip().upper() if len(cells) > 1 else ""
        tds = "".join(
            f'<td{" class=" + repr(_STATUS_CLASS.get(status, "")) if i == 1 and status else ""}>{_esc(c)}</td>'
            for i, c in enumerate(cells)
        )
        body_rows.append(f"<tr>{tds}</tr>")

    return (
        '<div class="table-wrap">'
        "<table>"
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "</div>"
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STATE_COLORS: dict[str, str] = {
    "VERIFIED": "#2d6a3f",
    "VERIFIED_WITH_GAPS": "#7d5a00",
    "INCOMPLETE_EVIDENCE": "#b94700",
    "EVIDENCE_REGRESSION": "#b94700",
    "TAMPERED": "#8b1a1a",
    "OUT_OF_SCOPE": "#444",
    "UNKNOWN": "#444",
}

_STATE_LABELS: dict[str, str] = {
    "VERIFIED": "All claims verified and the packet is intact.",
    "VERIFIED_WITH_GAPS": "Verified — some evidence is partial or human-attested.",
    "INCOMPLETE_EVIDENCE": "Evidence is missing or incomplete.",
    "EVIDENCE_REGRESSION": "Evidence is weaker than a prior packet.",
    "TAMPERED": "Packet integrity check failed.",
    "OUT_OF_SCOPE": "No in-scope questions were evaluated.",
}

_STATUS_CLASS: dict[str, str] = {
    "EVIDENCED": "status-pass",
    "PARTIAL": "status-warn",
    "FAILED": "status-fail",
    "HUMAN_ATTESTED": "status-attested",
    "OUT_OF_SCOPE": "status-oos",
}

_CSS = textwrap.dedent("""\
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: #f7f5f0;
        color: #1a201a;
        line-height: 1.65;
        font-size: 15px;
    }
    .shell { max-width: 880px; margin: 0 auto; padding: 48px 24px 96px; }
    header { margin-bottom: 36px; }
    .eyebrow {
        font-size: 11px;
        letter-spacing: .14em;
        text-transform: uppercase;
        color: #777;
        margin-bottom: 10px;
    }
    h1 {
        font-size: clamp(1.6rem, 4vw, 2.4rem);
        line-height: 1.18;
        font-weight: 700;
        margin-bottom: 22px;
        letter-spacing: -.02em;
    }
    .verdict {
        display: inline-flex;
        flex-direction: column;
        gap: 5px;
        padding: 16px 22px;
        border-radius: 10px;
        color: #fff;
        max-width: 680px;
    }
    .verdict strong { font-size: 1.05rem; font-weight: 700; }
    .verdict span { font-size: .88rem; opacity: .9; line-height: 1.5; }
    .verdict .basis { opacity: .8; font-style: italic; }
    .meta-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
        gap: 10px;
        margin: 30px 0 40px;
    }
    .meta-cell {
        background: #fff;
        border: 1px solid #ddd8cc;
        border-radius: 8px;
        padding: 12px 14px;
    }
    .label {
        display: block;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: .07em;
        color: #888;
        margin-bottom: 5px;
    }
    .meta-cell strong, .meta-cell code, .meta-cell span { display: block; word-break: break-all; }
    .pass { color: #2d6a3f; font-weight: 700; }
    .fail { color: #8b1a1a; font-weight: 700; }
    .warn { color: #7d5a00; font-weight: 700; }
    .fingerprint { font-size: .78rem; color: #666; }
    .section { margin-bottom: 44px; }
    .section h2 {
        font-size: 1.15rem;
        font-weight: 700;
        margin-bottom: 16px;
        padding-bottom: 10px;
        border-bottom: 1px solid #ddd8cc;
        letter-spacing: -.01em;
    }
    .section h3 { font-size: 1rem; margin: 20px 0 8px; }
    .section h4 { font-size: .92rem; margin: 16px 0 6px; color: #444; }
    .prose p, .prose li { margin-bottom: 10px; line-height: 1.7; }
    .prose ul { padding-left: 22px; margin-bottom: 12px; }
    .prose pre {
        background: #1a201a;
        color: #d4edda;
        padding: 16px;
        border-radius: 8px;
        overflow-x: auto;
        font-size: .85rem;
        margin: 12px 0;
        font-family: 'SFMono-Regular', Consolas, monospace;
    }
    .prose code {
        background: #edeae3;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: .88em;
        font-family: 'SFMono-Regular', Consolas, monospace;
    }
    .table-wrap { overflow-x: auto; margin-bottom: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: .88rem; }
    thead tr { background: #1a201a; }
    th {
        color: #e8f0e4;
        padding: 10px 14px;
        text-align: left;
        font-weight: 600;
        font-size: .82rem;
        letter-spacing: .04em;
        text-transform: uppercase;
        white-space: nowrap;
    }
    td { padding: 10px 14px; border-bottom: 1px solid #ddd8cc; vertical-align: top; }
    tr:nth-child(even) td { background: #f9f7f3; }
    td.status-pass { color: #2d6a3f; font-weight: 700; }
    td.status-warn { color: #7d5a00; font-weight: 700; }
    td.status-fail { color: #8b1a1a; font-weight: 700; }
    td.status-attested { color: #1a4a7a; font-weight: 700; }
    td.status-oos { color: #777; }
    code { font-family: 'SFMono-Regular', Consolas, monospace; }
    footer {
        margin-top: 64px;
        padding-top: 20px;
        border-top: 1px solid #ddd8cc;
        color: #999;
        font-size: .82rem;
    }
    @media (max-width: 560px) {
        .meta-grid { grid-template-columns: repeat(2, 1fr); }
        h1 { font-size: 1.5rem; }
    }
""")
