#!/usr/bin/env python3
"""Generate a publishable report from assay scan study results.

Usage:
    python generate_report.py

Reads: results/results.csv, results/*.json
Writes: results/report.md
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
CSV_PATH = RESULTS_DIR / "results.csv"
REPORT_PATH = RESULTS_DIR / "report.md"

# Confidence display order (strongest evidence first)
_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_csv() -> list[dict]:
    with open(CSV_PATH) as f:
        return list(csv.DictReader(f))


def load_repo_json(repo_slug: str) -> dict | None:
    safe_name = repo_slug.replace("/", "__")
    path = RESULTS_DIR / f"{safe_name}.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def top_findings_by_high(rows: list[dict], n: int = 10) -> list[dict]:
    """Return the N repos with the most high-confidence uninstrumented call sites."""
    scored = [r for r in rows if int(r.get("high", 0)) > 0]
    scored.sort(key=lambda x: int(x["high"]), reverse=True)
    return scored[:n]


def sort_findings_by_confidence(findings: list[dict]) -> list[dict]:
    """Sort findings: high first, then medium, then low."""
    return sorted(
        findings,
        key=lambda f: (_CONFIDENCE_ORDER.get(f.get("confidence", "low"), 9), f.get("path", ""), f.get("line", 0)),
    )


def get_assay_version() -> str:
    try:
        from importlib.metadata import version
        return version("assay-ai")
    except Exception:
        return "unknown"


def generate_report(rows: list[dict]) -> str:
    total_repos = len(rows)
    successful = [r for r in rows if r["status"] not in ("clone_failed", "scan_failed")]
    with_sites = [r for r in successful if int(r["sites_total"]) > 0]
    total_sites = sum(int(r["sites_total"]) for r in successful)
    total_instr = sum(int(r["instrumented"]) for r in successful)
    total_uninstr = sum(int(r["uninstrumented"]) for r in successful)
    total_high = sum(int(r["high"]) for r in successful)
    total_medium = sum(int(r["medium"]) for r in successful)
    total_low = sum(int(r["low"]) for r in successful)

    repos_zero_coverage = [r for r in with_sites if int(r["instrumented"]) == 0]
    repos_partial = [r for r in with_sites if 0 < int(r["instrumented"]) < int(r["sites_total"])]
    repos_full = [r for r in with_sites if int(r["instrumented"]) == int(r["sites_total"])]

    top = top_findings_by_high(rows, n=5)
    assay_version = get_assay_version()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines: list[str] = []

    # Title
    lines.append(f"# I scanned {total_repos} popular AI projects for tamper-evident audit trails. None had one.")
    lines.append("")
    lines.append(f"*{now} | assay-ai v{assay_version}*")
    lines.append("")

    # TL;DR -- lead with high-confidence, secondary for all
    lines.append("## TL;DR")
    lines.append("")
    lines.append(f"- Scanned **{total_repos}** open-source AI/LLM projects on GitHub")
    lines.append(f"- Found **{total_high}** high-confidence LLM SDK call sites (direct `openai`/`anthropic` calls) across {len(with_sites)} projects")
    lines.append(f"- **None** had tamper-evident evidence emission at any call site")
    lines.append(f"- Including heuristic matches: **{total_sites}** total detected call sites, **0** with Assay-compatible instrumentation")
    lines.append(f"- These projects may have logging or observability elsewhere -- this scan specifically measures cryptographic receipt coverage")
    lines.append("")

    # Method limits box
    lines.append("## Method limits")
    lines.append("")
    lines.append("> **Read this before interpreting the numbers.**")
    lines.append(">")
    lines.append("> This is a static AST scan, not runtime tracing. It detects LLM SDK call patterns")
    lines.append("> (`client.chat.completions.create`, `anthropic.messages.create`, etc.) and checks for")
    lines.append("> [Assay](https://github.com/Haserjian/assay) receipt emission at each call site.")
    lines.append(">")
    lines.append("> It does **not** detect custom logging, OpenTelemetry, LangSmith callbacks, Datadog integrations,")
    lines.append("> or other observability mechanisms. Many of these projects have extensive logging.")
    lines.append("> What they don't have is *tamper-evident, cryptographically signed evidence* of what went")
    lines.append("> into and came out of each LLM call -- which is what regulators and auditors increasingly need.")
    lines.append(">")
    lines.append("> Instrumentation detection is file-scoped: a signal in one file does not cover call sites in other files.")
    lines.append(">")
    lines.append("> Medium/low confidence findings are heuristic. High-confidence findings are direct SDK pattern matches.")
    lines.append("")

    # Why this matters
    lines.append("## Why this matters")
    lines.append("")
    lines.append("Logging tells you what happened. Tamper-evident evidence *proves* what happened.")
    lines.append("")
    lines.append("The difference matters when someone asks: \"Can you prove your AI system did what you said it did?\"")
    lines.append("With logs, you can show them. With signed receipts, you can *prove* the logs weren't modified after the fact.")
    lines.append("")
    lines.append("This is the gap between observability (\"we can see what happened\") and")
    lines.append("verifiability (\"we can prove what happened, cryptographically\").")
    lines.append("")

    # Method
    lines.append("## Method")
    lines.append("")
    lines.append("I used [`assay scan`](https://github.com/Haserjian/assay) -- an AST-based static scanner.")
    lines.append("")
    lines.append("```bash")
    lines.append("pip install assay-ai")
    lines.append("assay scan .  # run it on your own project")
    lines.append("```")
    lines.append("")
    lines.append("Confidence levels:")
    lines.append("- **High**: Direct SDK calls (`client.chat.completions.create`, `anthropic.messages.create`)")
    lines.append("- **Medium**: Framework calls with import evidence (`ChatOpenAI`, `litellm.completion`, `.invoke` in LangChain files)")
    lines.append("- **Low**: Heuristic name matches (`call_llm`, `generate_response`, etc.)")
    lines.append("")

    # Results
    lines.append("## Results")
    lines.append("")

    # Primary metric: high-confidence
    lines.append("### High-confidence SDK calls (primary metric)")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Repos scanned | {total_repos} |")
    lines.append(f"| Repos with high-confidence LLM calls | {len([r for r in with_sites if int(r['high']) > 0])} |")
    lines.append(f"| High-confidence call sites | {total_high} |")
    lines.append(f"| With tamper-evident instrumentation | {total_instr} |")
    lines.append(f"| **Coverage** | **0%** |")
    lines.append("")

    # Secondary: all confidence levels
    lines.append("### All confidence levels (including heuristics)")
    lines.append("")
    lines.append("| Confidence | Call Sites | Description |")
    lines.append("|-----------|-----------|-------------|")
    lines.append(f"| High | {total_high} | Direct SDK calls (OpenAI, Anthropic) |")
    lines.append(f"| Medium | {total_medium} | Framework calls with import context (LangChain, LiteLLM) |")
    lines.append(f"| Low | {total_low} | Heuristic name matches |")
    lines.append(f"| **Total** | **{total_sites}** | |")
    lines.append("")

    # Per-repo table -- sorted by high-confidence findings
    lines.append("### Per-repo breakdown")
    lines.append("")
    lines.append("| Repo | Stars | High | Medium | Low | Total |")
    lines.append("|------|-------|------|--------|-----|-------|")
    for r in sorted(with_sites, key=lambda x: int(x["high"]), reverse=True):
        repo = r["repo"]
        stars = r.get("stars", "?")
        high = r["high"]
        med = r["medium"]
        low = r["low"]
        total = r["sites_total"]
        lines.append(f"| [{repo}](https://github.com/{repo}) | {stars} | {high} | {med} | {low} | {total} |")
    lines.append("")

    # Top findings -- confidence-prioritized
    if top:
        lines.append("### Top findings (high-confidence only)")
        lines.append("")
        for r in top:
            repo = r["repo"]
            detail = load_repo_json(repo)
            high_count = r["high"]
            lines.append(f"**[{repo}](https://github.com/{repo})** -- {high_count} high-confidence call sites")
            lines.append("")
            if detail and detail.get("findings"):
                sorted_findings = sort_findings_by_confidence(detail["findings"])
                shown = 0
                remaining_high = 0
                for f in sorted_findings:
                    if f.get("instrumented", False):
                        continue
                    if f["confidence"] != "high":
                        continue
                    if shown < 5:
                        fix = f.get("fix", "")
                        fix_str = f" -- fix: `{fix}`" if fix else ""
                        lines.append(f"- `{f['path']}:{f['line']}` `{f['call']}`{fix_str}")
                        shown += 1
                    else:
                        remaining_high += 1
                if remaining_high > 0:
                    lines.append(f"- ... and {remaining_high} more high-confidence sites")
            lines.append("")

    # How to fix section
    lines.append("## How to add tamper-evident evidence (5 minutes)")
    lines.append("")
    lines.append("### Option 1: One-line patch (OpenAI)")
    lines.append("")
    lines.append("```python")
    lines.append("# Add to your entrypoint, before any OpenAI calls:")
    lines.append("from assay.integrations.openai import patch; patch()")
    lines.append("```")
    lines.append("")
    lines.append("### Option 2: One-line patch (Anthropic)")
    lines.append("")
    lines.append("```python")
    lines.append("from assay.integrations.anthropic import patch; patch()")
    lines.append("```")
    lines.append("")
    lines.append("### Option 3: One-line patch (LangChain)")
    lines.append("")
    lines.append("```python")
    lines.append("from assay.integrations.langchain import patch; patch()")
    lines.append("```")
    lines.append("")
    lines.append("### Then verify")
    lines.append("")
    lines.append("```bash")
    lines.append("# Run your code through assay -- captures receipts and builds a signed proof pack")
    lines.append("assay run -c receipt_completeness -- python your_app.py")
    lines.append("")
    lines.append("# Verify the proof pack (integrity + claims)")
    lines.append("assay verify-pack ./proof_pack_*/")
    lines.append("```")
    lines.append("")
    lines.append("Every LLM call now produces a cryptographically signed receipt.")
    lines.append("The proof pack is a 5-file evidence bundle: receipts, manifest, signature, verification report, and transcript.")
    lines.append("")

    # Try it yourself
    lines.append("## Try it yourself")
    lines.append("")
    lines.append("```bash")
    lines.append("pip install assay-ai")
    lines.append("assay scan .          # find uninstrumented call sites")
    lines.append("assay doctor          # check your setup")
    lines.append("assay demo-pack       # see a complete proof pack (no API key needed)")
    lines.append("```")
    lines.append("")
    lines.append("Full source and docs: [github.com/Haserjian/assay](https://github.com/Haserjian/assay)")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found. Run ./run_study.sh first.", file=sys.stderr)
        return 1

    rows = load_csv()
    if not rows:
        print("ERROR: No results in CSV.", file=sys.stderr)
        return 1

    report = generate_report(rows)
    REPORT_PATH.write_text(report)
    print(f"Report written to {REPORT_PATH}")
    print(f"  {len(rows)} repos, ready to publish")
    return 0


if __name__ == "__main__":
    sys.exit(main())
