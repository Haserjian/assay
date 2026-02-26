"""Unified Evidence Readiness Report: self-contained HTML + markdown + SARIF.

Generates a single-file HTML report combining score card, evidence gap map,
CI gate status, and next actions. Includes a what-if score simulator,
tamper-evident content hash, and print-ready @media styles.

Also emits:
- Markdown for $GITHUB_STEP_SUMMARY / PR comments
- SARIF 2.1.0 for GitHub Code Scanning UI
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.reporting.evidence_gap import (
    ReportFinding,
    ReportMeta,
    _detect_provider,
    _git_info,
    _is_test_path,
    _repo_name,
)


@dataclass
class UnifiedReport:
    """Complete report payload for rendering."""

    meta: ReportMeta
    score: Dict[str, Any]
    facts: Dict[str, Any]
    evidence_gaps: List[ReportFinding] = field(default_factory=list)
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _compute_content_hash(score: Dict[str, Any], facts: Dict[str, Any]) -> str:
    """SHA-256 of deterministic JSON serialization of score + facts."""
    payload = json.dumps({"score": score, "facts": facts}, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_score_report(
    facts: Dict[str, Any],
    score: Dict[str, Any],
    repo_path: Path,
) -> UnifiedReport:
    """Assemble a UnifiedReport from gathered facts and computed score."""
    from assay import __version__

    git = _git_info(repo_path)
    meta = ReportMeta(
        assay_version=__version__,
        generated_at=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        repo_name=_repo_name(repo_path),
        repo_root=str(repo_path),
        git_branch=git.get("branch"),
        git_commit=git.get("commit"),
        git_dirty=git.get("dirty"),
    )

    # Build evidence gap findings from scan data in facts
    evidence_gaps: List[ReportFinding] = []
    scan = facts.get("scan", {})
    findings_raw = scan.get("findings", [])
    for f in findings_raw:
        if not f.get("instrumented", True):
            evidence_gaps.append(
                ReportFinding(
                    path=f.get("path", ""),
                    line=f.get("line", 0),
                    call=f.get("call", ""),
                    confidence=f.get("confidence", "medium"),
                    instrumented=False,
                    provider=_detect_provider(f.get("call", "")),
                    is_test=_is_test_path(f.get("path", "")),
                    fix=f.get("fix"),
                )
            )

    content_hash = _compute_content_hash(score, facts)

    return UnifiedReport(
        meta=meta,
        score=score,
        facts=facts,
        evidence_gaps=evidence_gaps,
        content_hash=content_hash,
    )


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


def _hash_payload_string(score: Dict[str, Any], facts: Dict[str, Any]) -> str:
    """Return the exact JSON string used for content hashing.

    This is embedded verbatim in the HTML so JS can hash the identical bytes
    without needing to re-serialize (JSON.stringify key order differs from
    Python's sort_keys=True).
    """
    return json.dumps({"score": score, "facts": facts}, sort_keys=True, default=str)


def render_html(report: UnifiedReport) -> str:
    """Render a UnifiedReport as a single self-contained HTML string."""
    data_json = json.dumps(report.to_dict(), indent=2, sort_keys=True, default=str)
    safe_json = data_json.replace("</", "<\\/")
    # Embed the exact payload bytes used for hashing so JS can verify
    hash_payload = _hash_payload_string(report.score, report.facts)
    safe_hash_payload = hash_payload.replace("</", "<\\/")
    html = _HTML_TEMPLATE.replace("/* __REPORT_DATA__ */", safe_json)
    html = html.replace("/* __HASH_PAYLOAD__ */", safe_hash_payload)
    return html


def write_report(html: str, path: Path) -> None:
    """Write the HTML report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def write_json(report: UnifiedReport, path: Path) -> None:
    """Write the JSON sidecar to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def render_markdown(report: UnifiedReport) -> str:
    """Render a condensed markdown summary for GITHUB_STEP_SUMMARY / PR comments."""
    s = report.score
    grade = s.get("grade", "?")
    score_val = s.get("score", 0)
    breakdown = s.get("breakdown", {})

    lines: List[str] = []
    lines.append(f"### Assay Evidence Readiness: **{grade}** ({score_val:.1f} / 100)")
    lines.append("")
    lines.append("| Component | Points | Weight | Status |")
    lines.append("|-----------|--------|--------|--------|")
    for key in ("coverage", "lockfile", "ci_gate", "receipts", "key_setup"):
        comp = breakdown.get(key, {})
        lines.append(
            f"| {key} | {comp.get('points', 0):.1f} | {comp.get('weight', 0)} | {comp.get('status', '-')} |"
        )
    lines.append("")

    caps = s.get("caps_applied", [])
    if caps:
        lines.append("**Caps:**")
        for cap in caps:
            lines.append(f"- {cap['id']}: {cap['reason']}")
        lines.append("")

    fp = s.get("fastest_path")
    if fp:
        lines.append(f"**Next:** `{fp['command']}` (+{fp['points_est']:.0f} pts est.)")
        lines.append("")

    lines.append(f"> {s.get('disclaimer', '')}")
    lines.append(f"> Generated by Assay v{report.meta.assay_version}")
    return "\n".join(lines)


def write_markdown(md: str, path: Path) -> None:
    """Write the markdown report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(md, encoding="utf-8")


# ---------------------------------------------------------------------------
# SARIF renderer
# ---------------------------------------------------------------------------

_CONFIDENCE_TO_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(report: UnifiedReport) -> Dict[str, Any]:
    """Render SARIF 2.1.0 output for GitHub Code Scanning."""
    results: List[Dict[str, Any]] = []
    for gap in report.evidence_gaps:
        results.append(
            {
                "ruleId": "assay/evidence-gap",
                "ruleIndex": 0,
                "level": _CONFIDENCE_TO_LEVEL.get(gap.confidence, "warning"),
                "message": {
                    "text": f"Uninstrumented AI call site: {gap.call}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": gap.path},
                            "region": {"startLine": gap.line},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "assay",
                        "semanticVersion": report.meta.assay_version,
                        "informationUri": "https://github.com/Haserjian/assay",
                        "rules": [
                            {
                                "id": "assay/evidence-gap",
                                "shortDescription": {
                                    "text": "AI call site without evidence receipt"
                                },
                                "helpUri": "https://github.com/Haserjian/assay",
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {
                                    "tags": [
                                        "ai-governance",
                                        "evidence",
                                        "compliance",
                                    ]
                                },
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(sarif_dict: Dict[str, Any], path: Path) -> None:
    """Write the SARIF report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sarif_dict, indent=2, sort_keys=True),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="assay-content-hash" content="">
<title>Evidence Readiness Report</title>
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --text-dim: #8b949e;
  --red: #f85149;
  --red-bg: rgba(248, 81, 73, 0.1);
  --yellow: #d29922;
  --yellow-bg: rgba(210, 153, 34, 0.1);
  --green: #3fb950;
  --green-bg: rgba(63, 185, 80, 0.1);
  --blue: #58a6ff;
  --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }

/* Header */
.header {
  text-align: center;
  padding: 24px 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 8px;
}
.header h1 {
  font-size: 20px;
  font-weight: 600;
  color: var(--text-dim);
  letter-spacing: 0.5px;
  text-transform: uppercase;
}
.header .repo-name {
  font-size: 28px;
  font-weight: 700;
  color: var(--text);
  margin-top: 4px;
}
.header .meta-line {
  font-size: 13px;
  color: var(--text-dim);
  margin-top: 8px;
  font-family: var(--mono);
}

/* Score Card */
.score-card {
  text-align: center;
  padding: 48px 24px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 32px;
}
.grade-letter {
  font-size: 120px;
  font-weight: 900;
  line-height: 1;
  font-family: var(--mono);
}
.grade-letter.grade-A, .grade-letter.grade-B { color: var(--green); }
.grade-letter.grade-C { color: var(--yellow); }
.grade-letter.grade-D { color: var(--yellow); }
.grade-letter.grade-F { color: var(--red); }
.score-number {
  font-size: 32px;
  font-weight: 700;
  font-family: var(--mono);
  color: var(--text);
  margin-top: 8px;
}
.score-label {
  font-size: 14px;
  color: var(--text-dim);
  margin-top: 4px;
}

/* Section headings */
.section {
  margin-bottom: 32px;
  padding-bottom: 32px;
  border-bottom: 1px solid var(--border);
}
.section:last-child { border-bottom: none; }
.section h2 {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-dim);
  margin-bottom: 16px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Breakdown table */
.breakdown-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}
.breakdown-table th, .breakdown-table td {
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.breakdown-table th {
  font-weight: 600;
  color: var(--text-dim);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.breakdown-table td.num { text-align: right; font-family: var(--mono); }
.status-pass { color: var(--green); }
.status-partial { color: var(--yellow); }
.status-fail { color: var(--red); }
.status-unknown { color: var(--text-dim); }

/* What-if simulator */
.whatif-row { display: flex; align-items: center; gap: 8px; }
.whatif-row input[type="checkbox"] { accent-color: var(--green); }
.whatif-row label { font-size: 13px; color: var(--text-dim); cursor: pointer; }
.whatif-projected {
  text-align: center;
  margin-top: 16px;
  padding: 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.whatif-projected .projected-score {
  font-size: 36px;
  font-weight: 700;
  font-family: var(--mono);
}

/* Caps */
.cap-item {
  background: var(--red-bg);
  border: 1px solid var(--red);
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 8px;
  font-size: 14px;
}
.cap-id { font-weight: 700; color: var(--red); }

/* Fastest path */
.fastest-path-box {
  background: var(--green-bg);
  border: 1px solid var(--green);
  border-radius: 8px;
  padding: 16px;
}
.fastest-path-box .fp-command {
  font-family: var(--mono);
  font-size: 14px;
  background: var(--surface);
  padding: 8px 12px;
  border-radius: 4px;
  margin-top: 8px;
  display: inline-block;
}

/* Evidence gaps summary */
.gap-list { list-style: none; }
.gap-item {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  margin-bottom: 6px;
  font-size: 13px;
  font-family: var(--mono);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.gap-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.gap-badge.high { background: var(--red-bg); color: var(--red); }
.gap-badge.medium { background: var(--yellow-bg); color: var(--yellow); }
.gap-badge.low { background: var(--surface); color: var(--text-dim); border: 1px solid var(--border); }

/* CI status */
.ci-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}
.ci-item {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  text-align: center;
}
.ci-item .ci-label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; }
.ci-item .ci-value { font-size: 18px; font-weight: 700; margin-top: 4px; }

/* Next actions */
.action-list { list-style: none; counter-reset: actions; }
.action-item {
  counter-increment: actions;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  margin-bottom: 8px;
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.action-item::before {
  content: counter(actions);
  background: var(--blue);
  color: var(--bg);
  font-weight: 700;
  font-size: 12px;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-top: 2px;
}
.action-text { font-size: 14px; flex: 1; }
.action-command {
  font-family: var(--mono);
  font-size: 13px;
  background: var(--bg);
  padding: 4px 8px;
  border-radius: 4px;
  margin-top: 4px;
  display: inline-block;
  cursor: pointer;
}
.action-points {
  font-size: 12px;
  color: var(--green);
  font-family: var(--mono);
  white-space: nowrap;
}

/* Verification footer */
.verify-section {
  text-align: center;
  padding: 24px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.verify-btn {
  background: var(--blue);
  color: var(--bg);
  border: none;
  padding: 8px 20px;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  margin-top: 8px;
}
.verify-btn:hover { opacity: 0.9; }
.verify-result {
  margin-top: 12px;
  font-size: 14px;
  font-weight: 600;
}
.verify-ok { color: var(--green); }
.verify-fail { color: var(--red); }

/* Footer */
.footer {
  text-align: center;
  padding: 24px 0;
  font-size: 12px;
  color: var(--text-dim);
}
.footer a { color: var(--blue); text-decoration: none; }

/* Expand toggle */
.expand-btn {
  background: none;
  border: 1px solid var(--border);
  color: var(--blue);
  padding: 6px 16px;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  margin-top: 8px;
}
.expand-btn:hover { background: var(--surface); }
.hidden { display: none; }

/* Print styles */
@media print {
  :root {
    --bg: #fff;
    --surface: #f6f8fa;
    --border: #d0d7de;
    --text: #1f2328;
    --text-dim: #656d76;
    --red: #cf222e;
    --yellow: #9a6700;
    --green: #1a7f37;
    --blue: #0969da;
  }
  body { background: #fff; color: #1f2328; }
  .whatif-row, .whatif-projected, .verify-section,
  .expand-btn, .action-command { display: none !important; }
  .hidden { display: block !important; }
  .section { page-break-inside: avoid; }
  .score-card { page-break-after: avoid; }
  .grade-letter { font-size: 72px; }
}
</style>
</head>
<body>
<div class="container" id="report-root"></div>

<script type="application/json" id="report-data">
/* __REPORT_DATA__ */
</script>

<script type="application/json" id="hash-payload">
/* __HASH_PAYLOAD__ */
</script>

<script>
(function() {
  "use strict";
  var data = JSON.parse(document.getElementById("report-data").textContent);
  var root = document.getElementById("report-root");
  var meta = data.meta || {};
  var score = data.score || {};
  var facts = data.facts || {};
  var gaps = data.evidence_gaps || [];
  var contentHash = data.content_hash || "";

  // Set content hash meta tag
  var hashMeta = document.querySelector('meta[name="assay-content-hash"]');
  if (hashMeta) hashMeta.setAttribute("content", contentHash);

  // DOM builder (XSS-safe: uses textContent only, no raw HTML injection)
  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function(k) {
        if (k === "className") e.className = attrs[k];
        else if (k === "textContent") e.textContent = attrs[k];
        else if (k.indexOf("on") === 0) e.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
        else e.setAttribute(k, attrs[k]);
      });
    }
    if (children) {
      children.forEach(function(c) {
        if (typeof c === "string") e.appendChild(document.createTextNode(c));
        else if (c) e.appendChild(c);
      });
    }
    return e;
  }

  function text(s) { return document.createTextNode(s); }

  // Grade color class
  var grade = score.grade || "F";
  var gradeClass = "grade-" + grade;

  // -- Header --
  var metaLine = [];
  if (meta.git_branch) metaLine.push(meta.git_branch);
  if (meta.git_commit) metaLine.push(meta.git_commit);
  if (meta.git_dirty) metaLine.push("(dirty)");
  var header = el("div", {className: "header"}, [
    el("h1", {textContent: "Evidence Readiness Report"}),
    el("div", {className: "repo-name", textContent: meta.repo_name || "unknown"}),
    el("div", {className: "meta-line", textContent: metaLine.join(" | ") + " | " + (meta.generated_at || "")})
  ]);
  root.appendChild(header);

  // -- Score Card --
  var scoreCard = el("div", {className: "score-card"}, [
    el("div", {className: "grade-letter " + gradeClass, textContent: grade, id: "hero-grade"}),
    el("div", {className: "score-number", id: "hero-score"}, [
      text((score.score || 0).toFixed(1) + " / 100")
    ]),
    el("div", {className: "score-label", textContent: score.grade_description || ""})
  ]);
  root.appendChild(scoreCard);

  // -- Component Breakdown with What-If --
  var breakdownSection = el("div", {className: "section"}, [
    el("h2", {textContent: "Component Breakdown"})
  ]);

  var table = el("table", {className: "breakdown-table"});
  var thead = el("thead", {}, [
    el("tr", {}, [
      el("th", {textContent: "Component"}),
      el("th", {textContent: "Points"}),
      el("th", {textContent: "Weight"}),
      el("th", {textContent: "Status"}),
      el("th", {textContent: "Note"})
    ])
  ]);
  table.appendChild(thead);

  var tbody = el("tbody");
  var comps = ["coverage", "lockfile", "ci_gate", "receipts", "key_setup"];
  var breakdown = score.breakdown || {};

  comps.forEach(function(key) {
    var comp = breakdown[key] || {};
    var statusClass = "status-" + (comp.status || "unknown");
    var tr = el("tr", {}, [
      el("td", {textContent: key}),
      el("td", {className: "num", textContent: (comp.points || 0).toFixed(1)}),
      el("td", {className: "num", textContent: String(comp.weight || 0)}),
      el("td", {className: statusClass, textContent: comp.status || "-"}),
      el("td", {textContent: comp.note || ""})
    ]);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  breakdownSection.appendChild(table);

  // What-if simulator
  var whatifActions = (score.next_actions_detail || []).filter(function(a) {
    return a.points_est > 0;
  });

  // Cap rules: component -> max score when that component is still failing.
  // CAP_NO_RECEIPTS_MAX_D caps at 69.9 unless receipts are enabled.
  var capRules = [
    {component: "receipts", maxScore: 69.9, maxGrade: "D", id: "CAP_NO_RECEIPTS_MAX_D"}
  ];

  if (whatifActions.length > 0) {
    var whatifDiv = el("div", {className: "section"}, [
      el("h2", {textContent: "What-If Score Simulator"})
    ]);
    var currentScore = score.score || 0;

    var projected = el("div", {className: "whatif-projected"}, [
      el("div", {className: "score-label", textContent: "Projected Score"}),
      el("div", {className: "projected-score", id: "projected-score", textContent: currentScore.toFixed(1)})
    ]);

    whatifActions.forEach(function(action) {
      var cb = el("input", {type: "checkbox", id: "whatif-" + action.component});
      var label = el("label", {}, [
        text(action.action + " (+" + action.points_est.toFixed(0) + " pts)")
      ]);
      label.setAttribute("for", "whatif-" + action.component);
      var row = el("div", {className: "whatif-row"}, [cb, label]);
      whatifDiv.appendChild(row);

      cb.addEventListener("change", function() {
        updateWhatIf();
      });
    });

    whatifDiv.appendChild(projected);
    breakdownSection.appendChild(whatifDiv);

    function updateWhatIf() {
      // Start from raw_score (before caps) and add toggled improvements
      var proj = score.raw_score || currentScore;
      var enabledComponents = {};
      whatifActions.forEach(function(action) {
        var cb = document.getElementById("whatif-" + action.component);
        if (cb && cb.checked) {
          proj += action.points_est;
          enabledComponents[action.component] = true;
        }
      });
      proj = Math.min(proj, 100);

      // Re-apply caps for components that are still failing
      capRules.forEach(function(rule) {
        // Cap applies if the component is currently failing AND not toggled on
        var comp = breakdown[rule.component] || {};
        var isFailing = comp.status === "fail";
        var isToggled = enabledComponents[rule.component];
        if (isFailing && !isToggled) {
          proj = Math.min(proj, rule.maxScore);
        }
      });

      var projEl = document.getElementById("projected-score");
      if (projEl) projEl.textContent = proj.toFixed(1);

      // Update hero display
      var heroScore = document.getElementById("hero-score");
      var heroGrade = document.getElementById("hero-grade");
      if (heroScore) heroScore.textContent = proj.toFixed(1) + " / 100";
      var g = proj >= 90 ? "A" : proj >= 80 ? "B" : proj >= 70 ? "C" : proj >= 60 ? "D" : "F";
      if (heroGrade) {
        heroGrade.textContent = g;
        heroGrade.className = "grade-letter grade-" + g;
      }
    }
  }

  root.appendChild(breakdownSection);

  // -- Caps Applied --
  var caps = score.caps_applied || [];
  if (caps.length > 0) {
    var capsSection = el("div", {className: "section"}, [
      el("h2", {textContent: "Caps Applied"})
    ]);
    caps.forEach(function(cap) {
      capsSection.appendChild(el("div", {className: "cap-item"}, [
        el("span", {className: "cap-id", textContent: cap.id + ": "}),
        text(cap.reason)
      ]));
    });
    root.appendChild(capsSection);
  }

  // -- Fastest Path --
  var fp = score.fastest_path;
  if (fp) {
    var fpSection = el("div", {className: "section"}, [
      el("h2", {textContent: "Fastest Path to " + fp.target_grade})
    ]);
    fpSection.appendChild(el("div", {className: "fastest-path-box"}, [
      text("Run this to reach " + fp.target_grade + " (" + fp.target_score + "+):"),
      el("div", {className: "fp-command", textContent: fp.command}),
      el("div", {}, [
        text(" +" + fp.points_est.toFixed(0) + " pts -> ~" + fp.projected_score.toFixed(1))
      ])
    ]));
    root.appendChild(fpSection);
  }

  // -- Evidence Gap Summary (top 10 + expand) --
  if (gaps.length > 0) {
    var gapSection = el("div", {className: "section"}, [
      el("h2", {textContent: "Evidence Gaps (" + gaps.length + " uninstrumented sites)"})
    ]);
    var gapList = el("ul", {className: "gap-list"});
    var showCount = Math.min(gaps.length, 10);

    // Sort by severity: high > medium > low
    var severityOrder = {high: 0, medium: 1, low: 2};
    var sorted = gaps.slice().sort(function(a, b) {
      return (severityOrder[a.confidence] || 2) - (severityOrder[b.confidence] || 2);
    });

    sorted.forEach(function(gap, i) {
      var item = el("li", {className: "gap-item" + (i >= showCount ? " hidden" : ""), "data-gap": "1"}, [
        el("span", {}, [text(gap.path + ":" + gap.line + " " + gap.call)]),
        el("span", {className: "gap-badge " + gap.confidence, textContent: gap.confidence})
      ]);
      gapList.appendChild(item);
    });
    gapSection.appendChild(gapList);

    if (gaps.length > showCount) {
      var expandBtn = el("button", {className: "expand-btn", textContent: "Show all " + gaps.length + " gaps"});
      expandBtn.addEventListener("click", function() {
        var hidden = gapList.querySelectorAll(".hidden");
        for (var j = 0; j < hidden.length; j++) hidden[j].classList.remove("hidden");
        expandBtn.classList.add("hidden");
      });
      gapSection.appendChild(expandBtn);
    }

    root.appendChild(gapSection);
  }

  // -- CI Gate Status --
  var ci = facts.ci || {};
  var ciSection = el("div", {className: "section"}, [
    el("h2", {textContent: "CI Gate Status"})
  ]);
  var ciGrid = el("div", {className: "ci-grid"});
  var ciItems = [
    {label: "Workflows", value: String(ci.workflow_count || 0)},
    {label: "Assay Ref", value: ci.has_assay_ref ? "Yes" : "No", ok: ci.has_assay_ref},
    {label: "Run Step", value: ci.has_run ? "Yes" : "No", ok: ci.has_run},
    {label: "Verify Step", value: ci.has_verify ? "Yes" : "No", ok: ci.has_verify},
    {label: "Lock Enforced", value: ci.has_lock ? "Yes" : "No", ok: ci.has_lock}
  ];
  ciItems.forEach(function(item) {
    var valueClass = item.ok === undefined ? "" : (item.ok ? " status-pass" : " status-fail");
    ciGrid.appendChild(el("div", {className: "ci-item"}, [
      el("div", {className: "ci-label", textContent: item.label}),
      el("div", {className: "ci-value" + valueClass, textContent: item.value})
    ]));
  });
  ciSection.appendChild(ciGrid);
  root.appendChild(ciSection);

  // -- Next Actions --
  var actions = score.next_actions_detail || [];
  if (actions.length > 0) {
    var actionsSection = el("div", {className: "section"}, [
      el("h2", {textContent: "Next Actions"})
    ]);
    var actionList = el("ol", {className: "action-list"});
    actions.forEach(function(action) {
      var cmdEl = el("span", {className: "action-command", textContent: action.command, title: "Click to copy"});
      cmdEl.addEventListener("click", function() {
        if (navigator.clipboard) {
          navigator.clipboard.writeText(action.command);
          cmdEl.textContent = "Copied!";
          setTimeout(function() { cmdEl.textContent = action.command; }, 1500);
        }
      });
      var pts = action.points_est > 0 ? "+" + action.points_est.toFixed(0) + " pts" : "";
      var item = el("li", {className: "action-item"}, [
        el("div", {className: "action-text"}, [
          text(action.action),
          el("br"),
          cmdEl
        ]),
        el("span", {className: "action-points", textContent: pts})
      ]);
      actionList.appendChild(item);
    });
    actionsSection.appendChild(actionList);
    root.appendChild(actionsSection);
  }

  // -- Verification --
  var verifySection = el("div", {className: "section"}, [
    el("div", {className: "verify-section"}, [
      el("div", {}, [text("Content hash: "), el("code", {textContent: contentHash})]),
      el("button", {className: "verify-btn", textContent: "Verify Report Integrity", onClick: verifyHash}),
      el("div", {className: "verify-result", id: "verify-result"})
    ])
  ]);
  root.appendChild(verifySection);

  function verifyHash() {
    var resultEl = document.getElementById("verify-result");
    if (!window.crypto || !window.crypto.subtle) {
      resultEl.textContent = "Verification requires HTTPS or localhost (file:// is not supported by browsers)";
      resultEl.className = "verify-result verify-fail";
      return;
    }
    // Read the exact pre-serialized payload embedded by Python -- avoids
    // JSON.stringify key-order differences vs Python's sort_keys=True.
    var hashPayloadEl = document.getElementById("hash-payload");
    if (!hashPayloadEl) {
      resultEl.textContent = "Hash payload element not found";
      resultEl.className = "verify-result verify-fail";
      return;
    }
    var payloadStr = hashPayloadEl.textContent;
    var enc = new TextEncoder().encode(payloadStr);
    crypto.subtle.digest("SHA-256", enc).then(function(buf) {
      var arr = Array.from(new Uint8Array(buf));
      var hex = arr.map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
      var computed = "sha256:" + hex;
      if (computed === contentHash) {
        resultEl.textContent = "Verified: content hash matches";
        resultEl.className = "verify-result verify-ok";
      } else {
        resultEl.textContent = "MISMATCH: report may have been tampered with";
        resultEl.className = "verify-result verify-fail";
      }
    });
  }

  // -- Footer --
  var footer = el("div", {className: "footer"}, [
    text("Generated by Assay v" + (meta.assay_version || "?") + " | " + (meta.generated_at || "")),
    el("br"),
    text(score.disclaimer || ""),
    el("br"),
    el("a", {href: "https://github.com/Haserjian/assay", textContent: "github.com/Haserjian/assay"})
  ]);
  root.appendChild(footer);

})();
</script>
</body>
</html>"""
