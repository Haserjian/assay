"""Evidence Gap Report: self-contained HTML artifact from scan results.

Generates a single HTML file with inline CSS/JS that visualizes evidence
coverage gaps. Designed to be screenshot-worthy and forwardable -- the
artifact IS the argument.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ReportMeta:
    """Metadata about the scan environment."""
    assay_version: str
    generated_at: str
    repo_name: str
    repo_root: str
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None
    git_dirty: Optional[bool] = None


@dataclass
class ReportSummary:
    """Coverage statistics for the hero number."""
    sites_total: int
    instrumented: int
    uninstrumented: int
    high: int
    medium: int
    low: int
    coverage_pct: float  # instrumented / (HIGH+MEDIUM total) * 100
    prod_total: int = 0
    prod_uninstrumented: int = 0
    test_total: int = 0
    test_uninstrumented: int = 0
    excluded_frameworks: Dict[str, int] = field(default_factory=dict)


def _detect_provider(call: str) -> str:
    """Detect provider from call site string."""
    call_lower = call.lower()
    if "openai" in call_lower or "chat.completions" in call_lower or "chatopenai" in call_lower:
        return "openai"
    if "anthropic" in call_lower or "messages.create" in call_lower or "chatanthropic" in call_lower:
        return "anthropic"
    if "litellm" in call_lower:
        return "litellm"
    # LangChain patterns: .invoke(), .ainvoke(), llm.predict, etc.
    if any(p in call_lower for p in (".invoke", ".ainvoke", "llm.predict", "llm.apredict",
                                      "chain.", "agent.", "retriever.", "parser.",
                                      "prompt.", "model.invoke", "model.ainvoke")):
        return "langchain"
    return "other"


def _is_test_path(path: str) -> bool:
    """Detect if a file path is in a test directory."""
    parts = path.replace("\\", "/").split("/")
    for part in parts:
        if part in ("test", "tests", "testing", "test_utils"):
            return True
        if part.startswith("test_") or part.endswith("_test.py"):
            return True
    return False


@dataclass
class ReportFinding:
    """A single call site finding for the report table."""
    path: str
    line: int
    call: str
    confidence: str  # "high", "medium", "low"
    instrumented: bool
    provider: str = "other"
    is_test: bool = False
    fix: Optional[str] = None


@dataclass
class EvidenceGapReport:
    """Complete report payload for rendering."""
    meta: ReportMeta
    summary: ReportSummary
    findings: List[ReportFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _git_info(repo_root: Path) -> dict:
    """Best-effort git metadata. Returns empty dict on failure."""
    info: dict = {}
    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
        if branch.returncode == 0:
            info["branch"] = branch.stdout.strip()

        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
        if commit.returncode == 0:
            info["commit"] = commit.stdout.strip()

        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
        if dirty.returncode == 0:
            info["dirty"] = len(dirty.stdout.strip()) > 0

        if not info.get("branch"):
            remote = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=repo_root, capture_output=True, text=True, timeout=5,
            )
            if remote.returncode == 0:
                info["remote"] = remote.stdout.strip()
    except Exception:
        pass
    return info


def _repo_name(repo_root: Path) -> str:
    """Best-effort repo name from git remote or folder name."""
    try:
        remote = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
        if remote.returncode == 0:
            url = remote.stdout.strip()
            # Handle both HTTPS and SSH URLs
            name = url.rstrip("/").rsplit("/", 1)[-1]
            if name.endswith(".git"):
                name = name[:-4]
            return name
    except Exception:
        pass
    return repo_root.resolve().name


def build_report(scan_result_dict: Dict[str, Any], repo_root: Path) -> EvidenceGapReport:
    """Build an EvidenceGapReport from a ScanResult.to_dict() payload."""
    from assay import __version__

    git = _git_info(repo_root)
    summary_raw = scan_result_dict["summary"]

    # Coverage = instrumented / (total HIGH + MEDIUM sites) * 100
    # LOW excluded from denominator.
    # LangChain/LiteLLM excluded from denominator (no runtime callsite_id support).
    _EXCLUDED_FRAMEWORKS = {"langchain", "litellm"}
    findings_raw = scan_result_dict.get("findings", [])

    # Count excluded framework findings (HIGH+MEDIUM only)
    excluded_frameworks: Dict[str, int] = {}
    for f in findings_raw:
        fw = f.get("framework", "")
        if fw in _EXCLUDED_FRAMEWORKS and f["confidence"] in ("high", "medium"):
            excluded_frameworks[fw] = excluded_frameworks.get(fw, 0) + 1

    high_medium_total = sum(
        1 for f in findings_raw
        if f["confidence"] in ("high", "medium")
        and f.get("framework", "") not in _EXCLUDED_FRAMEWORKS
    )
    instrumented_hm = sum(
        1 for f in findings_raw
        if f["confidence"] in ("high", "medium") and f["instrumented"]
        and f.get("framework", "") not in _EXCLUDED_FRAMEWORKS
    )
    if high_medium_total > 0:
        coverage_pct = round(instrumented_hm / high_medium_total * 100, 1)
    else:
        coverage_pct = 100.0 if not findings_raw else 0.0

    meta = ReportMeta(
        assay_version=__version__,
        generated_at=datetime.now(timezone.utc).isoformat(),
        repo_name=_repo_name(repo_root),
        repo_root=str(repo_root.resolve()),
        git_branch=git.get("branch"),
        git_commit=git.get("commit"),
        git_dirty=git.get("dirty"),
    )

    summary = ReportSummary(
        sites_total=summary_raw["sites_total"],
        instrumented=summary_raw["instrumented"],
        uninstrumented=summary_raw["uninstrumented"],
        high=summary_raw["high"],
        medium=summary_raw["medium"],
        low=summary_raw["low"],
        coverage_pct=coverage_pct,
    )

    findings = [
        ReportFinding(
            path=f["path"],
            line=f["line"],
            call=f["call"],
            confidence=f["confidence"],
            instrumented=f["instrumented"],
            provider=_detect_provider(f["call"]),
            is_test=_is_test_path(f["path"]),
            fix=f.get("fix"),
        )
        for f in findings_raw
    ]

    # Compute prod/test split
    prod = [f for f in findings if not f.is_test]
    tests = [f for f in findings if f.is_test]
    summary.prod_total = len(prod)
    summary.prod_uninstrumented = sum(1 for f in prod if not f.instrumented)
    summary.test_total = len(tests)
    summary.test_uninstrumented = sum(1 for f in tests if not f.instrumented)
    summary.excluded_frameworks = excluded_frameworks

    return EvidenceGapReport(meta=meta, summary=summary, findings=findings)


def render_html(report: EvidenceGapReport) -> str:
    """Render an EvidenceGapReport as a single self-contained HTML string."""
    data_json = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    # Prevent accidental script-tag termination when embedding JSON in HTML.
    safe_json = data_json.replace("</", "<\\/")
    return _HTML_TEMPLATE.replace("/* __REPORT_DATA__ */", safe_json)


def write_report(html: str, path: Path) -> None:
    """Write the HTML report to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def write_json(report: EvidenceGapReport, path: Path) -> None:
    """Write the JSON sidecar to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True),
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
<title>Evidence Gap Report</title>
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

/* Hero */
.hero {
  text-align: center;
  padding: 48px 24px 40px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 32px;
}
.hero h1 {
  font-size: 20px;
  font-weight: 600;
  color: var(--text-dim);
  margin-bottom: 8px;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}
.hero .repo-name {
  font-size: 28px;
  font-weight: 700;
  margin-bottom: 32px;
  color: var(--text);
}
.hero-number {
  font-size: 96px;
  font-weight: 800;
  line-height: 1;
  margin-bottom: 8px;
  font-family: var(--mono);
}
.hero-number.red { color: var(--red); }
.hero-number.yellow { color: var(--yellow); }
.hero-number.green { color: var(--green); }
.hero-label {
  font-size: 18px;
  color: var(--text-dim);
  margin-bottom: 32px;
}
.hero-stats {
  display: flex;
  justify-content: center;
  gap: 48px;
  flex-wrap: wrap;
}
.stat { text-align: center; }
.stat-value {
  font-size: 32px;
  font-weight: 700;
  font-family: var(--mono);
}
.stat-label {
  font-size: 13px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.scope-split {
  display: flex;
  justify-content: center;
  gap: 40px;
  margin-top: 24px;
  flex-wrap: wrap;
}
.scope-box {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 24px;
  text-align: center;
  min-width: 180px;
}
.scope-box .scope-label {
  font-size: 12px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 4px;
}
.scope-box .scope-value {
  font-size: 24px;
  font-weight: 700;
  font-family: var(--mono);
}
.scope-box .scope-detail {
  font-size: 12px;
  color: var(--text-dim);
  margin-top: 2px;
}

/* Explainer */
.explainer {
  margin-bottom: 32px;
  padding-bottom: 32px;
  border-bottom: 1px solid var(--border);
}
.explainer h2 {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
  color: var(--text-dim);
}
.explainer-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
@media (max-width: 700px) {
  .explainer-grid { grid-template-columns: 1fr; }
}
.explainer-item {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
}
.explainer-term {
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--blue);
  margin-bottom: 4px;
}
.explainer-def {
  font-size: 13px;
  color: var(--text-dim);
  line-height: 1.5;
}

/* Filters */
.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  align-items: center;
}
.filters input, .filters select {
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 14px;
  font-family: inherit;
}
.filters input { flex: 1; min-width: 200px; }
.filters select { min-width: 120px; }
.filters input:focus, .filters select:focus {
  outline: none;
  border-color: var(--blue);
}

/* Top offenders */
.offenders {
  margin-bottom: 32px;
}
.offenders h2 {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
  color: var(--text-dim);
}
.offender-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
}
.offender-row:last-child { border-bottom: none; }
.offender-bar-bg {
  flex: 0 0 120px;
  height: 6px;
  background: var(--border);
  border-radius: 3px;
  overflow: hidden;
}
.offender-bar {
  height: 100%;
  background: var(--red);
  border-radius: 3px;
}
.offender-count {
  font-family: var(--mono);
  font-weight: 600;
  color: var(--red);
  min-width: 30px;
  text-align: right;
}
.offender-path {
  font-family: var(--mono);
  color: var(--text);
  word-break: break-all;
}
.offender-scope {
  font-size: 11px;
  color: var(--text-dim);
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--surface);
  border: 1px solid var(--border);
  white-space: nowrap;
}

/* Table */
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 32px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}
th {
  background: var(--surface);
  padding: 10px 14px;
  text-align: left;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}
th:hover { color: var(--text); }
th .sort-arrow { margin-left: 4px; opacity: 0.4; }
th.sorted .sort-arrow { opacity: 1; }
td {
  padding: 8px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tr:last-child td { border-bottom: none; }
tr:hover { background: rgba(255,255,255,0.02); }
.path-cell {
  font-family: var(--mono);
  font-size: 13px;
  word-break: break-all;
}
.call-cell {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--text-dim);
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Badges */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.badge-high { background: var(--red-bg); color: var(--red); }
.badge-medium { background: var(--yellow-bg); color: var(--yellow); }
.badge-low { background: rgba(139, 148, 158, 0.15); color: var(--text-dim); }
.badge-instrumented { background: var(--green-bg); color: var(--green); }
.badge-uninstrumented { background: var(--red-bg); color: var(--red); }
.badge-test { background: rgba(139, 148, 158, 0.1); color: var(--text-dim); font-size: 10px; margin-left: 6px; }

/* Tooltip */
.has-tooltip { position: relative; }
.has-tooltip .tooltip {
  display: none;
  position: absolute;
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 12px;
  font-weight: 400;
  text-transform: none;
  letter-spacing: 0;
  color: var(--text);
  white-space: normal;
  width: 260px;
  z-index: 10;
  line-height: 1.4;
}
.has-tooltip:hover .tooltip { display: block; }

/* Fix button */
.fix-btn {
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--blue);
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-family: var(--mono);
  cursor: pointer;
  white-space: nowrap;
}
.fix-btn:hover { border-color: var(--blue); }
.fix-btn.copied {
  color: var(--green);
  border-color: var(--green);
}

/* Sections */
.section {
  margin-bottom: 40px;
}
.section h2 {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

/* Before/After */
.before-after {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 16px;
}
@media (max-width: 700px) {
  .before-after { grid-template-columns: 1fr; }
  .hero-stats { gap: 24px; }
  .hero-number { font-size: 64px; }
  .scope-split { gap: 12px; }
}
.code-block {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  font-family: var(--mono);
  font-size: 13px;
  line-height: 1.6;
  overflow-x: auto;
  white-space: pre;
}
.code-label {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
  color: var(--text-dim);
}

/* Footer */
.footer {
  border-top: 1px solid var(--border);
  padding-top: 32px;
  margin-top: 48px;
}
.footer-cta {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  text-align: center;
  margin-bottom: 24px;
}
.footer-cta code {
  display: inline-block;
  background: var(--bg);
  padding: 8px 16px;
  border-radius: 6px;
  font-family: var(--mono);
  font-size: 14px;
  margin-top: 8px;
  color: var(--blue);
}
.limitations {
  font-size: 13px;
  color: var(--text-dim);
  line-height: 1.7;
}
.limitations summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--text-dim);
  margin-bottom: 8px;
}
.limitations ul {
  padding-left: 20px;
  margin-top: 8px;
}
.limitations li { margin-bottom: 4px; }
.footer-brand {
  text-align: center;
  font-size: 12px;
  color: var(--text-dim);
  margin-top: 24px;
}

/* Empty state */
.empty-state {
  text-align: center;
  padding: 64px 24px;
  color: var(--text-dim);
}
.empty-state .check { font-size: 48px; margin-bottom: 16px; color: var(--green); }
.count-note {
  font-size: 13px;
  color: var(--text-dim);
  margin-top: 4px;
}
</style>
</head>
<body>

<script type="application/json" id="report-data">
/* __REPORT_DATA__ */
</script>

<div class="container" id="app"></div>

<script>
(function() {
  "use strict";

  var raw = document.getElementById("report-data").textContent;
  var DATA = JSON.parse(raw);
  var meta = DATA.meta;
  var summary = DATA.summary;
  var findings = DATA.findings;
  var app = document.getElementById("app");

  // --- Helpers (security: never use innerHTML for dynamic data) ---
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

  // --- Hero ---
  var coverageColor = summary.coverage_pct < 25 ? "red"
    : summary.coverage_pct < 75 ? "yellow" : "green";

  var hero = el("div", {className: "hero"}, [
    el("h1", {textContent: "Evidence Gap Report"}),
    el("div", {className: "repo-name", textContent: meta.repo_name}),
    el("div", {className: "hero-number " + coverageColor,
      textContent: summary.coverage_pct + "%"}),
    el("div", {className: "hero-label", textContent: "of your AI calls can be independently proven"}),
    el("div", {className: "hero-stats"}, [
      makeStat(summary.sites_total, "AI call sites"),
      makeStat(summary.instrumented, "have receipts"),
      makeStat(summary.uninstrumented, "no proof"),
    ]),
  ]);

  // Prod vs test split
  if (summary.prod_total > 0 || summary.test_total > 0) {
    var scopeSplit = el("div", {className: "scope-split"});

    var prodBox = el("div", {className: "scope-box"});
    prodBox.appendChild(el("div", {className: "scope-label", textContent: "Production code"}));
    prodBox.appendChild(el("div", {className: "scope-value", textContent: summary.prod_uninstrumented + " gaps"}));
    prodBox.appendChild(el("div", {className: "scope-detail",
      textContent: summary.prod_total + " call sites total"}));
    scopeSplit.appendChild(prodBox);

    var testBox = el("div", {className: "scope-box"});
    testBox.appendChild(el("div", {className: "scope-label", textContent: "Test code"}));
    testBox.appendChild(el("div", {className: "scope-value", textContent: summary.test_uninstrumented + " gaps"}));
    testBox.appendChild(el("div", {className: "scope-detail",
      textContent: summary.test_total + " call sites total"}));
    scopeSplit.appendChild(testBox);

    hero.appendChild(scopeSplit);
  }

  if (summary.low > 0) {
    hero.appendChild(el("div", {className: "count-note",
      textContent: summary.low + " LOW-confidence finding" + (summary.low !== 1 ? "s" : "") + " excluded from coverage"}));
  }

  var excl = summary.excluded_frameworks || {};
  var exclKeys = Object.keys(excl);
  if (exclKeys.length > 0) {
    var reasons = {
      "langchain": "uses callbacks, not global patching",
      "litellm": "wraps upstream SDK; instrument the SDK directly"
    };
    var parts = exclKeys.map(function(k) { return excl[k] + " " + k; });
    var reasonParts = exclKeys.map(function(k) { return k + ": " + (reasons[k] || "framework-level wrapping"); });
    hero.appendChild(el("div", {className: "count-note",
      textContent: parts.join(" + ") + " finding(s) excluded from denominator (" + reasonParts.join("; ") + ")"}));
  }

  app.appendChild(hero);

  function makeStat(val, label) {
    return el("div", {className: "stat"}, [
      el("div", {className: "stat-value", textContent: String(val)}),
      el("div", {className: "stat-label", textContent: label}),
    ]);
  }

  // --- How to read this report ---
  var explainer = el("div", {className: "explainer"});
  explainer.appendChild(el("h2", {textContent: "How to read this report"}));
  var terms = el("div", {className: "explainer-grid"});

  var defs = [
    ["Call site", "A place in your code that calls an AI model (OpenAI, Anthropic, LangChain, etc). Each one is a decision your system makes that someone might later ask you to explain."],
    ["Instrumented", "This call site produces a signed receipt -- a tamper-evident record of what went in and what came out. If someone asks \"prove it,\" you can."],
    ["No receipt", "This call site has no evidence emission. If something goes wrong here, you have logs at best -- and whoever controls the server controls the logs."],
    ["Evidence coverage", "The percentage of your AI calls that produce independently verifiable proof. The rest is trust-me territory."],
  ];
  defs.forEach(function(d) {
    var item = el("div", {className: "explainer-item"});
    item.appendChild(el("div", {className: "explainer-term", textContent: d[0]}));
    item.appendChild(el("div", {className: "explainer-def", textContent: d[1]}));
    terms.appendChild(item);
  });
  explainer.appendChild(terms);
  app.appendChild(explainer);

  if (findings.length === 0) {
    app.appendChild(el("div", {className: "empty-state"}, [
      el("div", {className: "check", textContent: "\u2713"}),
      el("div", {textContent: "No LLM call sites detected."}),
      el("div", {className: "count-note",
        textContent: "If you use custom wrappers, add manual receipt emission."}),
    ]));
    appendFooter();
    return;
  }

  // --- Fix These First ---
  var fileCounts = {};
  findings.forEach(function(f) {
    if (!f.instrumented) {
      if (!fileCounts[f.path]) fileCounts[f.path] = {count: 0, is_test: f.is_test};
      fileCounts[f.path].count++;
    }
  });
  var offenderList = Object.keys(fileCounts).map(function(p) {
    return {path: p, count: fileCounts[p].count, is_test: fileCounts[p].is_test};
  }).sort(function(a, b) { return b.count - a.count; }).slice(0, 8);

  if (offenderList.length > 0) {
    var maxCount = offenderList[0].count;
    var offSection = el("div", {className: "offenders"});
    offSection.appendChild(el("h2", {textContent: "Fix These First"}));
    offenderList.forEach(function(o) {
      var row = el("div", {className: "offender-row"});
      row.appendChild(el("span", {className: "offender-count", textContent: String(o.count)}));
      var barBg = el("div", {className: "offender-bar-bg"});
      var bar = el("div", {className: "offender-bar"});
      bar.style.width = Math.round(o.count / maxCount * 100) + "%";
      barBg.appendChild(bar);
      row.appendChild(barBg);
      row.appendChild(el("span", {className: "offender-path", textContent: o.path}));
      if (o.is_test) row.appendChild(el("span", {className: "offender-scope", textContent: "test"}));
      offSection.appendChild(row);
    });
    app.appendChild(offSection);
  }

  // --- Filters ---
  var state = { search: "", confidence: "all", provider: "all", status: "all", scope: "all", sortCol: null, sortAsc: true };

  var searchInput = el("input", {type: "text", placeholder: "Filter by file path..."});
  var confSelect = makeSelect("all", ["all", "high", "medium", "low"], ["All confidence", "HIGH", "MEDIUM", "LOW"]);
  var provSelect = makeSelect("all", uniqueProviders(), null);
  var statusSelect = makeSelect("all", ["all", "uninstrumented", "instrumented"], ["All status", "Uninstrumented", "Instrumented"]);
  var scopeSelect = makeSelect("all", ["all", "prod", "test"], ["All code", "Production only", "Tests only"]);

  function makeSelect(initial, values, labels) {
    var s = el("select");
    values.forEach(function(v, i) {
      var o = el("option", {value: v});
      o.textContent = (labels ? labels[i] : (v === "all" ? "All providers" : v));
      s.appendChild(o);
    });
    s.value = initial;
    return s;
  }

  function uniqueProviders() {
    var seen = {all: true};
    var result = ["all"];
    findings.forEach(function(f) {
      var p = f.provider || "other";
      if (!seen[p]) { seen[p] = true; result.push(p); }
    });
    return result;
  }

  var filtersDiv = el("div", {className: "filters"}, [searchInput, confSelect, provSelect, statusSelect, scopeSelect]);
  app.appendChild(filtersDiv);

  searchInput.addEventListener("input", function() { state.search = this.value.toLowerCase(); renderTable(); });
  confSelect.addEventListener("change", function() { state.confidence = this.value; renderTable(); });
  provSelect.addEventListener("change", function() { state.provider = this.value; renderTable(); });
  statusSelect.addEventListener("change", function() { state.status = this.value; renderTable(); });
  scopeSelect.addEventListener("change", function() { state.scope = this.value; renderTable(); });

  // --- Table ---
  var tableWrap = el("div", {className: "table-wrap"});
  app.appendChild(tableWrap);

  // Confidence tooltips
  var CONF_TIPS = {
    high: "Direct SDK call detected (e.g. client.chat.completions.create). Very likely a real LLM invocation.",
    medium: "Framework call detected via import evidence (e.g. LangChain .invoke with matching import). Likely an LLM call.",
    low: "Heuristic name match (e.g. function named llm_call). May be a false positive."
  };

  var columns = [
    {key: "confidence", label: "Confidence", width: "110px"},
    {key: "path", label: "File", width: null},
    {key: "line", label: "Line", width: "70px"},
    {key: "provider", label: "Provider", width: "100px"},
    {key: "instrumented", label: "Status", width: "130px"},
    {key: "fix", label: "Fix", width: "200px"},
  ];

  function renderTable() {
    while (tableWrap.firstChild) tableWrap.removeChild(tableWrap.firstChild);

    var filtered = findings.filter(function(f) {
      if (state.search && f.path.toLowerCase().indexOf(state.search) === -1) return false;
      if (state.confidence !== "all" && f.confidence !== state.confidence) return false;
      if (state.provider !== "all" && (f.provider || "other") !== state.provider) return false;
      if (state.status === "uninstrumented" && f.instrumented) return false;
      if (state.status === "instrumented" && !f.instrumented) return false;
      if (state.scope === "prod" && f.is_test) return false;
      if (state.scope === "test" && !f.is_test) return false;
      return true;
    });

    if (state.sortCol !== null) {
      var col = columns[state.sortCol].key;
      filtered.sort(function(a, b) {
        var va = a[col], vb = b[col];
        if (va == null) va = "";
        if (vb == null) vb = "";
        if (typeof va === "boolean") { va = va ? 1 : 0; vb = vb ? 1 : 0; }
        if (typeof va === "number") return state.sortAsc ? va - vb : vb - va;
        va = String(va).toLowerCase(); vb = String(vb).toLowerCase();
        return state.sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      });
    }

    var table = el("table");
    var thead = el("thead");
    var headerRow = el("tr");
    columns.forEach(function(c, i) {
      var th = el("th", {className: c.key === "confidence" ? "has-tooltip" : ""}, [
        text(c.label),
        el("span", {className: "sort-arrow", textContent: state.sortCol === i ? (state.sortAsc ? " \u25B2" : " \u25BC") : " \u25B2"}),
      ]);
      if (c.key === "confidence") {
        var tip = el("div", {className: "tooltip",
          textContent: "HIGH = direct SDK call. MEDIUM = framework call with import evidence. LOW = heuristic name match (may be false positive)."});
        th.appendChild(tip);
      }
      if (state.sortCol === i) th.classList.add("sorted");
      if (c.width) th.style.width = c.width;
      th.addEventListener("click", function() {
        if (state.sortCol === i) state.sortAsc = !state.sortAsc;
        else { state.sortCol = i; state.sortAsc = true; }
        renderTable();
      });
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = el("tbody");
    filtered.forEach(function(f) {
      var row = el("tr");

      // Confidence badge with tooltip
      var confCell = el("td", {className: "has-tooltip"});
      confCell.appendChild(el("span", {className: "badge badge-" + f.confidence, textContent: f.confidence.toUpperCase()}));
      if (CONF_TIPS[f.confidence]) {
        confCell.appendChild(el("div", {className: "tooltip", textContent: CONF_TIPS[f.confidence]}));
      }
      row.appendChild(confCell);

      // Path (with test badge)
      var pathCell = el("td", {className: "path-cell"});
      pathCell.appendChild(text(f.path));
      if (f.is_test) pathCell.appendChild(el("span", {className: "badge badge-test", textContent: "test"}));
      row.appendChild(pathCell);

      // Line
      row.appendChild(el("td", {textContent: String(f.line)}));

      // Provider
      row.appendChild(el("td", {textContent: f.provider || "other"}));

      // Status
      var statusClass = f.instrumented ? "badge-instrumented" : "badge-uninstrumented";
      var statusText = f.instrumented ? "INSTRUMENTED" : "NO RECEIPT";
      row.appendChild(el("td", {}, [el("span", {className: "badge " + statusClass, textContent: statusText})]));

      // Fix
      if (f.fix && !f.instrumented) {
        var btn = el("button", {className: "fix-btn", textContent: f.fix});
        btn.addEventListener("click", function() {
          if (navigator.clipboard) {
            navigator.clipboard.writeText(f.fix).then(function() {
              btn.textContent = "Copied!";
              btn.className = "fix-btn copied";
              setTimeout(function() { btn.textContent = f.fix; btn.className = "fix-btn"; }, 1500);
            });
          }
        });
        row.appendChild(el("td", {}, [btn]));
      } else {
        row.appendChild(el("td", {className: "call-cell", textContent: f.instrumented ? "\u2014" : ""}));
      }

      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    tableWrap.appendChild(table);

    // Count
    var existing = document.getElementById("filter-count");
    if (existing) existing.parentNode.removeChild(existing);
    var countDiv = el("div", {id: "filter-count",
      className: "count-note",
      textContent: "Showing " + filtered.length + " of " + findings.length + " findings"});
    countDiv.style.marginTop = "8px";
    tableWrap.parentNode.insertBefore(countDiv, tableWrap.nextSibling);
  }

  renderTable();

  // --- Before/After Example ---
  var exampleSection = el("div", {className: "section"});
  exampleSection.appendChild(el("h2", {textContent: "What Instrumented Looks Like"}));

  var beforeAfter = el("div", {className: "before-after"});

  var beforeBlock = el("div");
  beforeBlock.appendChild(el("div", {className: "code-label", textContent: "Before (no evidence)"}));
  var beforeCode = el("div", {className: "code-block"});
  beforeCode.textContent = "import openai\nclient = openai.OpenAI()\nresp = client.chat.completions.create(\n    model=\"gpt-4\",\n    messages=[{\"role\": \"user\", \"content\": prompt}]\n)";
  beforeBlock.appendChild(beforeCode);

  var afterBlock = el("div");
  afterBlock.appendChild(el("div", {className: "code-label", textContent: "After (tamper-evident)"}));
  var afterCode = el("div", {className: "code-block"});
  afterCode.textContent = "import openai\nfrom assay.integrations.openai import patch\npatch()  # one line\n\nclient = openai.OpenAI()\nresp = client.chat.completions.create(\n    model=\"gpt-4\",\n    messages=[{\"role\": \"user\", \"content\": prompt}]\n)\n# Every call now emits a signed receipt";
  afterBlock.appendChild(afterCode);

  beforeAfter.appendChild(beforeBlock);
  beforeAfter.appendChild(afterBlock);
  exampleSection.appendChild(beforeAfter);

  var instrNote = el("div", {className: "count-note"});
  instrNote.textContent = "The patch() call monkey-patches the SDK. No other code changes needed. Each call produces a receipt in the active proof pack.";
  exampleSection.appendChild(instrNote);

  app.appendChild(exampleSection);

  // --- Footer ---
  appendFooter();

  function appendFooter() {
    var footer = el("div", {className: "footer"});

    // Next Steps walkthrough
    var steps = el("div", {className: "section"});
    steps.appendChild(el("h2", {textContent: "Next Steps: Close the Gaps"}));

    var stepData = [
      ["1. Instrument", "Add 2 lines per SDK. Your business logic stays the same.",
       "from assay.integrations.openai import patch\npatch()  # every SDK call now emits a signed receipt"],
      ["2. Run under proof", "Wrap your app (or tests) to collect receipts and sign a proof pack.",
       "assay run -- python your_app.py\nassay run -- pytest"],
      ["3. Verify", "Check the proof pack. Exit code 0 = authentic, 2 = tampered, 1 = claim gate failed (with --require-claim-pass).",
       "assay verify-pack proof_pack_*/\nassay verify-pack proof_pack_*/ --require-claim-pass"],
      ["4. Lock it in CI", "Add to your pipeline so every merge produces a verified proof pack.",
       "assay ci init github   # generates a GitHub Actions workflow"],
    ];

    stepData.forEach(function(s) {
      var stepEl = el("div", {className: "explainer-item"});
      stepEl.style.marginBottom = "12px";
      stepEl.appendChild(el("div", {className: "explainer-term", textContent: s[0]}));
      stepEl.appendChild(el("div", {className: "explainer-def", textContent: s[1]}));
      var codeEl = el("div", {className: "code-block"});
      codeEl.style.marginTop = "8px";
      codeEl.style.fontSize = "12px";
      codeEl.textContent = s[2];
      stepEl.appendChild(codeEl);
      steps.appendChild(stepEl);
    });

    var tryTamper = el("div", {className: "count-note"});
    tryTamper.style.marginTop = "16px";
    tryTamper.textContent = "Want to see tamper detection? Run: assay demo-challenge && assay verify-pack challenge_pack/tampered/";
    steps.appendChild(tryTamper);

    footer.appendChild(steps);

    var cta = el("div", {className: "footer-cta"}, [
      el("div", {textContent: "Get started:"}),
      el("code", {textContent: "pip install assay-ai && assay scan . --report"}),
    ]);
    footer.appendChild(cta);

    var lim = el("details", {className: "limitations"});
    var limSummary = el("summary", {textContent: "What this report does NOT prove"});
    lim.appendChild(limSummary);
    var limList = el("ul", {}, [
      el("li", {textContent: "This report does not prove your AI is correct or safe."}),
      el("li", {textContent: "Coverage is based on static analysis, which cannot find all call sites (custom wrappers, dynamic dispatch, runtime-only paths)."}),
      el("li", {textContent: "Instrumentation proves evidence integrity (receipts were not tampered with), not source honesty (the system could still lie at the source)."}),
      el("li", {textContent: "LOW-confidence findings are heuristic and may include false positives."}),
      el("li", {textContent: "This scan is file-scoped: instrumentation in one file does not cover calls in another."}),
    ]);
    lim.appendChild(limList);
    footer.appendChild(lim);

    var brand = el("div", {className: "footer-brand"});
    brand.textContent = "Generated by Assay v" + meta.assay_version + " \u2022 " + meta.generated_at.split("T")[0];
    footer.appendChild(brand);

    app.appendChild(footer);
  }
})();
</script>
</body>
</html>"""
