"""Diff Gate Report: self-contained HTML artifact from assay diff results.

Generates a single HTML file with inline CSS for sharing gate failures/passes
with non-CLI stakeholders.
"""
from __future__ import annotations

import hashlib
import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay import __version__
from assay.diff import DiffResult, GateEvaluation, WhyExplanation


@dataclass
class DiffGateReport:
    """Structured payload for diff gate reports."""

    meta: Dict[str, Any]
    integrity: Dict[str, Any]
    claims: Dict[str, Any]
    gates: Dict[str, Any]
    summary: Dict[str, Any]
    models: Dict[str, Any]
    why: List[Dict[str, Any]] = field(default_factory=list)
    footer: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _manifest_sha256(pack_path: str) -> str:
    manifest_path = Path(pack_path) / "pack_manifest.json"
    if not manifest_path.exists():
        return ""
    data = manifest_path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def _claim_bool_to_status(val: Optional[bool]) -> str:
    if val is True:
        return "PASS"
    if val is False:
        return "FAIL"
    return "--"


def _delta(a_val: float, b_val: float) -> Dict[str, Optional[float]]:
    delta_val = b_val - a_val
    pct_val: Optional[float] = None
    if a_val != 0:
        pct_val = (delta_val / a_val) * 100.0
    return {
        "a": a_val,
        "b": b_val,
        "delta": delta_val,
        "pct": pct_val,
    }


def build_report(
    result: DiffResult,
    *,
    gate_eval: Optional[GateEvaluation] = None,
    why_results: Optional[List[WhyExplanation]] = None,
    exit_code: Optional[int] = None,
    gate_strict: bool = False,
) -> DiffGateReport:
    """Build a structured report payload from diff output."""
    final_exit = result.exit_code if exit_code is None else exit_code
    verdict = "PASS" if final_exit == 0 else "FAIL"

    integrity = {
        "passed": result.both_valid,
        "errors": result.integrity_errors,
        "signer_changed": result.signer_changed,
        "version_changed": result.version_changed,
        "pack_a_signer_id": result.pack_a.signer_id,
        "pack_b_signer_id": result.pack_b.signer_id,
        "pack_a_signer_fingerprint": result.pack_a.signer_fingerprint,
        "pack_b_signer_fingerprint": result.pack_b.signer_fingerprint,
    }

    claims = {
        "regression_count": sum(1 for cd in result.claim_deltas if cd.regressed),
        "rows": [
            {
                "claim_id": cd.claim_id,
                "pack_a": _claim_bool_to_status(cd.a_passed),
                "pack_b": _claim_bool_to_status(cd.b_passed),
                "status": cd.status,
                "regressed": cd.regressed,
            }
            for cd in result.claim_deltas
        ],
    }

    gate_rows: List[Dict[str, Any]] = []
    if gate_eval is not None:
        for g in gate_eval.results:
            if g.skipped and g.passed:
                verdict_text = "skipped"
                actual = None
            elif g.skipped and not g.passed:
                verdict_text = "FAIL"
                actual = None
            else:
                verdict_text = "PASS" if g.passed else "FAIL"
                actual = g.actual
            gate_rows.append(
                {
                    "name": g.name,
                    "threshold": g.threshold,
                    "actual": actual,
                    "unit": g.unit,
                    "passed": g.passed,
                    "skipped": g.skipped,
                    "verdict": verdict_text,
                }
            )
    gates = {
        "strict": gate_strict,
        "all_passed": True if gate_eval is None else gate_eval.all_passed,
        "rows": gate_rows,
        "passed_count": 0 if gate_eval is None else sum(1 for g in gate_eval.results if g.passed and not g.skipped),
        "failed_count": 0 if gate_eval is None else sum(1 for g in gate_eval.results if not g.passed),
        "skipped_count": 0 if gate_eval is None else sum(1 for g in gate_eval.results if g.skipped and g.passed),
    }

    summary_rows: List[Dict[str, Any]] = []
    if result.a_analysis is not None and result.b_analysis is not None:
        a = result.a_analysis
        b = result.b_analysis
        summary_rows.append({"metric": "Model calls", "unit": "count", **_delta(float(a.model_calls), float(b.model_calls))})
        summary_rows.append({"metric": "Total tokens", "unit": "count", **_delta(float(a.total_tokens), float(b.total_tokens))})
        summary_rows.append({"metric": "Est. cost", "unit": "usd", **_delta(float(a.cost_usd), float(b.cost_usd))})
        summary_rows.append({"metric": "Errors", "unit": "count", **_delta(float(a.errors), float(b.errors))})
        if a.latency_p50 is not None and b.latency_p50 is not None:
            summary_rows.append({"metric": "Latency p50", "unit": "ms", **_delta(float(a.latency_p50), float(b.latency_p50))})
        if a.latency_p95 is not None and b.latency_p95 is not None:
            summary_rows.append({"metric": "Latency p95", "unit": "ms", **_delta(float(a.latency_p95), float(b.latency_p95))})

    models = {
        "rows": [
            {
                "model_id": md.model_id,
                "a_calls": md.a_calls,
                "b_calls": md.b_calls,
                "delta_calls": md.calls_delta,
                "status": md.status,
            }
            for md in result.model_deltas
        ]
    }

    why_dicts = [w.to_dict() for w in (why_results or [])]

    return DiffGateReport(
        meta={
            "title": "Assay Diff Gate Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assay_version": __version__,
            "pack_a_path": result.pack_a.path,
            "pack_b_path": result.pack_b.path,
            "pack_a_timestamp": result.pack_a.timestamp_start,
            "pack_b_timestamp": result.pack_b.timestamp_start,
            "verdict": verdict,
            "exit_code": final_exit,
        },
        integrity=integrity,
        claims=claims,
        gates=gates,
        summary={"rows": summary_rows},
        models=models,
        why=why_dicts,
        footer={
            "pack_a_manifest_sha256": _manifest_sha256(result.pack_a.path),
            "pack_b_manifest_sha256": _manifest_sha256(result.pack_b.path),
            "exit_code_meaning": {
                0: "No regression",
                1: "Claim regression or gate threshold exceeded",
                2: "Integrity failure (tampered pack)",
                3: "Bad input",
            }.get(final_exit, "Unknown"),
            "verified_with": "https://github.com/Haserjian/assay",
        },
    )


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _fmt_value(value: Optional[float], unit: str) -> str:
    if value is None:
        return "--"
    if unit == "usd":
        return f"${value:.4f}"
    if unit == "pct":
        return f"{value:.1f}%"
    if unit == "ms":
        return f"{int(value)}ms"
    if unit == "count":
        return str(int(value))
    return str(value)


def _fmt_delta(delta: float, pct: Optional[float], unit: str) -> str:
    if unit == "usd":
        base = f"{'+' if delta >= 0 else '-'}${abs(delta):.4f}"
    elif unit == "ms":
        base = f"{delta:+.0f}ms"
    elif unit == "count":
        base = f"{delta:+.0f}"
    else:
        base = f"{delta:+.1f}"
    if pct is None:
        return base
    return f"{base} ({pct:+.0f}%)"


def render_html(report: DiffGateReport) -> str:
    """Render a self-contained HTML report."""
    d = report.to_dict()

    claims_rows = []
    for row in d["claims"]["rows"]:
        cls = "claim-unchanged"
        if row["regressed"]:
            cls = "claim-regressed"
        elif row["status"] == "improved":
            cls = "claim-improved"
        elif row["status"] in ("new", "removed"):
            cls = "claim-structural"
        claims_rows.append(
            "<tr class='{cls}'><td>{claim_id}</td><td>{a}</td><td>{b}</td><td>{status}</td></tr>".format(
                cls=_esc(cls),
                claim_id=_esc(row["claim_id"]),
                a=_esc(row["pack_a"]),
                b=_esc(row["pack_b"]),
                status=_esc(row["status"]),
            )
        )

    gate_rows = []
    for row in d["gates"]["rows"]:
        if row["skipped"] and row["passed"]:
            verdict = "skipped (no data)"
            cls = "gate-skipped"
        elif row["skipped"] and not row["passed"]:
            verdict = "FAIL (missing data, strict mode)"
            cls = "gate-fail"
        else:
            verdict = row["verdict"]
            cls = "gate-pass" if row["passed"] else "gate-fail"
        gate_rows.append(
            "<tr class='{cls}'><td>{name}</td><td>{threshold}</td><td>{actual}</td><td>{verdict}</td></tr>".format(
                cls=_esc(cls),
                name=_esc(row["name"]),
                threshold=_esc(_fmt_value(row["threshold"], row["unit"])),
                actual=_esc(_fmt_value(row["actual"], row["unit"])),
                verdict=_esc(verdict),
            )
        )

    summary_rows = []
    for row in d["summary"]["rows"]:
        summary_rows.append(
            "<tr><td>{metric}</td><td>{a}</td><td>{b}</td><td>{delta}</td></tr>".format(
                metric=_esc(row["metric"]),
                a=_esc(_fmt_value(row["a"], row["unit"])),
                b=_esc(_fmt_value(row["b"], row["unit"])),
                delta=_esc(_fmt_delta(row["delta"], row["pct"], row["unit"])),
            )
        )

    model_rows = []
    for row in d["models"]["rows"]:
        model_rows.append(
            "<tr><td>{model}</td><td>{a}</td><td>{b}</td><td>{delta}</td><td>{status}</td></tr>".format(
                model=_esc(row["model_id"]),
                a=_esc(row["a_calls"]),
                b=_esc(row["b_calls"]),
                delta=_esc(row["delta_calls"]),
                status=_esc(row["status"]),
            )
        )

    why_blocks = []
    for w in d.get("why", []):
        lines = [
            f"<div><strong>{_esc(w['claim_id'])}</strong></div>",
            f"<div>Expected: {_esc(w.get('expected', ''))}</div>",
            f"<div>Actual: {_esc(w.get('actual', ''))}</div>",
        ]
        evidence = w.get("evidence_receipt_ids", [])
        if evidence:
            lines.append(f"<div>Evidence: {_esc(', '.join(evidence))}</div>")
        for chain in w.get("causal_chains", []):
            parts = []
            for r in chain:
                rid = str(r.get("receipt_id", ""))[:16]
                rtype = r.get("type", "?")
                parts.append(f"{rid} ({rtype})")
            lines.append(f"<div>Chain: {_esc(' <- '.join(parts))}</div>")
        why_blocks.append("<div class='why-block'>{}</div>".format("".join(lines)))

    verdict_cls = "verdict-pass" if d["meta"]["verdict"] == "PASS" else "verdict-fail"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_esc(d["meta"]["title"])}</title>
  <style>
    :root {{
      --bg: #0b1020;
      --card: #111831;
      --ink: #e8ecf5;
      --muted: #9aa6bf;
      --line: #2a3555;
      --good: #1fbf75;
      --warn: #ffb020;
      --bad: #ff5d5d;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
    .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; margin-bottom: 14px; }}
    h1, h2 {{ margin: 0 0 10px; }}
    h1 {{ font-size: 20px; }}
    h2 {{ font-size: 16px; }}
    .muted {{ color: var(--muted); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px; }}
    .kv {{ background: #0f1530; border: 1px solid var(--line); border-radius: 8px; padding: 10px; }}
    .kv .k {{ color: var(--muted); font-size: 12px; }}
    .kv .v {{ font-weight: 600; margin-top: 2px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; border-bottom: 1px solid var(--line); padding: 8px; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .claim-regressed td {{ background: rgba(255, 93, 93, 0.12); }}
    .claim-improved td {{ background: rgba(31, 191, 117, 0.12); }}
    .claim-structural td {{ background: rgba(255, 176, 32, 0.12); }}
    .gate-pass td:last-child {{ color: var(--good); font-weight: 700; }}
    .gate-fail td:last-child {{ color: var(--bad); font-weight: 700; }}
    .gate-skipped td:last-child {{ color: var(--muted); }}
    .verdict-pass {{ color: var(--good); font-weight: 700; }}
    .verdict-fail {{ color: var(--bad); font-weight: 700; }}
    code {{ background: #0f1530; border: 1px solid var(--line); border-radius: 4px; padding: 1px 6px; }}
    .why-block {{ border: 1px solid var(--line); border-radius: 8px; padding: 10px; margin-bottom: 8px; background: #0f1530; }}
    .list {{ margin: 6px 0 0; padding-left: 18px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>{_esc(d["meta"]["title"])}</h1>
      <div class="grid">
        <div class="kv"><div class="k">Verdict</div><div class="v {verdict_cls}">{_esc(d["meta"]["verdict"])}</div></div>
        <div class="kv"><div class="k">Exit code</div><div class="v">{_esc(d["meta"]["exit_code"])} ({_esc(d["footer"]["exit_code_meaning"])})</div></div>
        <div class="kv"><div class="k">Generated at</div><div class="v">{_esc(d["meta"]["generated_at"])}</div></div>
        <div class="kv"><div class="k">Assay version</div><div class="v">{_esc(d["meta"]["assay_version"])}</div></div>
        <div class="kv"><div class="k">Pack A</div><div class="v"><code>{_esc(d["meta"]["pack_a_path"])}</code></div></div>
        <div class="kv"><div class="k">Pack B</div><div class="v"><code>{_esc(d["meta"]["pack_b_path"])}</code></div></div>
      </div>
    </div>

    <div class="card">
      <h2>1. Integrity</h2>
      <div>Integrity status: <strong class="{'verdict-pass' if d['integrity']['passed'] else 'verdict-fail'}">{'PASS' if d['integrity']['passed'] else 'FAIL'}</strong></div>
      <div class="muted">Signer changed: {_esc(d["integrity"]["signer_changed"])} | Verifier changed: {_esc(d["integrity"]["version_changed"])}</div>
      <div class="muted">Pack A signer: {_esc(d["integrity"]["pack_a_signer_id"])} ({_esc(d["integrity"]["pack_a_signer_fingerprint"])})</div>
      <div class="muted">Pack B signer: {_esc(d["integrity"]["pack_b_signer_id"])} ({_esc(d["integrity"]["pack_b_signer_fingerprint"])})</div>
      {"<ul class='list'>" + "".join(f"<li>{_esc(err)}</li>" for err in d["integrity"]["errors"]) + "</ul>" if d["integrity"]["errors"] else ""}
    </div>

    <div class="card">
      <h2>2. Claims (regressions: {_esc(d["claims"]["regression_count"])})</h2>
      <table>
        <thead><tr><th>Claim ID</th><th>Pack A</th><th>Pack B</th><th>Status</th></tr></thead>
        <tbody>{"".join(claims_rows) if claims_rows else "<tr><td colspan='4' class='muted'>No claim data</td></tr>"}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>3. Gates</h2>
      <div class="muted">Strict mode: {_esc(d["gates"]["strict"])}</div>
      <table>
        <thead><tr><th>Gate</th><th>Threshold</th><th>Actual</th><th>Verdict</th></tr></thead>
        <tbody>{"".join(gate_rows) if gate_rows else "<tr><td colspan='4' class='muted'>No gates were requested</td></tr>"}</tbody>
      </table>
      <div class="muted">{_esc(d["gates"]["passed_count"])} passed, {_esc(d["gates"]["failed_count"])} failed, {_esc(d["gates"]["skipped_count"])} skipped</div>
    </div>

    <div class="card">
      <h2>4. Summary Deltas</h2>
      <table>
        <thead><tr><th>Metric</th><th>Pack A</th><th>Pack B</th><th>Delta</th></tr></thead>
        <tbody>{"".join(summary_rows) if summary_rows else "<tr><td colspan='4' class='muted'>No receipt analysis available</td></tr>"}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>5. Model Churn</h2>
      <table>
        <thead><tr><th>Model</th><th>A Calls</th><th>B Calls</th><th>Delta</th><th>Status</th></tr></thead>
        <tbody>{"".join(model_rows) if model_rows else "<tr><td colspan='5' class='muted'>No model usage deltas</td></tr>"}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Why (forensics)</h2>
      {"".join(why_blocks) if why_blocks else "<div class='muted'>No forensic traces requested or no regressions detected.</div>"}
    </div>

    <div class="card">
      <h2>Footer</h2>
      <div class="muted">Pack A manifest sha256: <code>{_esc(d["footer"]["pack_a_manifest_sha256"] or "unknown")}</code></div>
      <div class="muted">Pack B manifest sha256: <code>{_esc(d["footer"]["pack_b_manifest_sha256"] or "unknown")}</code></div>
      <div class="muted">Verified with Assay: <code>{_esc(d["footer"]["verified_with"])}</code></div>
    </div>
  </div>
</body>
</html>"""


def write_report(html_text: str, path: Path) -> None:
    """Write HTML report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_text, encoding="utf-8")


def write_json(report: DiffGateReport, path: Path) -> None:
    """Write structured report payload to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

