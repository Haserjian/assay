#!/usr/bin/env python3
"""3-Agent Constitutional Verification Demo. Single file. No abstractions."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import anthropic

MODEL = "claude-sonnet-4-6"
DEMO_DIR = Path(__file__).parent
SCENARIO_DIR = DEMO_DIR / "scenario"
OUTPUT_DIR = DEMO_DIR / "demo_output"

ANALYST_PROMPT = """You are a verification analyst. You receive an AI-generated assessment and extract the specific claims it makes.

For each claim:
- State the exact assertion being made
- State what evidence would be needed to verify it
- Note the risk if the claim is false

"COMPLIANT" is a strong assertion. Extract what is actually being claimed, not a summary.

Output ONLY a valid JSON object with this structure, no other text:
{
  "claims": [
    {"id": "CLAIM-1", "text": "exact assertion", "verification_requirement": "what evidence is needed", "risk_if_false": "consequence"},
    ...
  ],
  "limitations": ["what this analysis cannot check"]
}"""

VERIFIER_PROMPT = """You are a verification agent. You receive a verification plan and an evidence corpus. For each claim, check it against the evidence and grade honestly.

Grading rules:
- CONFIRMED: evidence directly and fully supports the claim
- PREDICTED: claim might be true but evidence is insufficient to confirm
- AMBIGUOUS: evidence is mixed or only partially supports the claim
- BLOCKED: evidence contradicts the claim or a critical gap exists

Do not round up. If evidence partially supports a claim, it is partially supported — not confirmed. If the AI said "all" but evidence shows exceptions, that is not confirmed.

For each claim provide:
- status: one of CONFIRMED / PREDICTED / AMBIGUOUS / BLOCKED
- supporting_artifacts: what evidence you examined
- verification_artifacts: what specifically confirms or refutes the claim
- finding: one sentence — what did the evidence actually show?
- promotion_rule: if not CONFIRMED, what would upgrade this claim? (null if CONFIRMED)

Output ONLY a valid JSON object, no other text:
{"results": [{"claim_id": "CLAIM-1", "status": "...", "supporting_artifacts": ["..."], "verification_artifacts": ["..."], "finding": "...", "promotion_rule": "..."}, ...]}"""

WITNESS_PROMPT = """You are an independent witness reviewing a verification process. You do NOT trust the verifier's self-assessment.

For each claim result, ask:
1. Did the verifier actually check what was required?
2. Is the grade honest? Would you grade differently?
3. If the verifier was too generous, override and say why.

You are not a rubber stamp. If the verifier called something AMBIGUOUS but the evidence shows a material gap, upgrade to BLOCKED. If the AI assessment made a claim the evidence directly contradicts, that is not "ambiguous" or "predicted" — it is wrong.

If the overall AI conclusion is not supported by evidence, issue an honest_fail_declaration stating exactly what is wrong and what must change.

Output ONLY a valid JSON object, no other text:
{
  "verdict": "complete or partial or inconclusive or blocked",
  "overrides": [{"claim_id": "...", "verifier_status": "...", "witness_status": "...", "rationale": "..."}],
  "agreements": [{"claim_id": "...", "status": "...", "note": "..."}],
  "honest_fail_declaration": "string or null",
  "scope_limitations": ["..."]
}"""


def extract_json(text):
    """Pull first JSON object from LLM response text."""
    # Try to find JSON block in markdown code fence first
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        return fence.group(1)
    # Fall back to first { to last }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        return text[start : end + 1]
    raise ValueError(f"No JSON found in response:\n{text[:500]}")


def call_agent(client, role, prompt, user_message):
    """Single Claude API call. No retry. No abstraction."""
    print(f"  [{role}] calling {MODEL}...")
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=prompt,
        messages=[{"role": "user", "content": user_message}],
    )
    raw = response.content[0].text
    parsed = json.loads(extract_json(raw))
    print(f"  [{role}] done.")
    return parsed, raw


def generate_summary(plan, results, verdict):
    """Build proof_summary.md from receipt data. String formatting only."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build override map: claim_id -> witness_status
    overrides = verdict.get("overrides", [])
    override_map = {o["claim_id"]: o["witness_status"].upper() for o in overrides}

    # Build results table using FINAL status (after witness overrides)
    rows = []
    status_counts = {"CONFIRMED": 0, "PREDICTED": 0, "AMBIGUOUS": 0, "BLOCKED": 0}
    for r in results.get("results", []):
        verifier_status = r["status"]
        final_status = override_map.get(r["claim_id"], verifier_status)
        status_counts[final_status] = status_counts.get(final_status, 0) + 1
        # Find matching claim text from plan
        claim_text = r["claim_id"]
        for c in plan.get("claims", []):
            if c["id"] == r["claim_id"]:
                claim_text = c["text"]
                break
        # Show override marker if witness changed the grade
        if r["claim_id"] in override_map:
            rows.append(f"| {claim_text} | COMPLIANT | **{final_status}** (was {verifier_status}) | {r['finding']} |")
        else:
            rows.append(f"| {claim_text} | COMPLIANT | **{final_status}** | {r['finding']} |")

    results_table = "\n".join(rows)
    total = len(results.get("results", []))
    ai_claim = f"{total}/{total} COMPLIANT"

    # Build overrides section
    overrides_text = ""
    if overrides:
        override_lines = []
        for o in overrides:
            override_lines.append(
                f"- **{o['claim_id']}**: {o['verifier_status']} -> {o['witness_status']} — {o['rationale']}"
            )
        overrides_text = "## Witness Overrides\n\n" + "\n".join(override_lines)

    # Summary line from final counts
    confirmed = status_counts.get("CONFIRMED", 0)
    blocked = status_counts.get("BLOCKED", 0)
    ambiguous = status_counts.get("AMBIGUOUS", 0)
    predicted = status_counts.get("PREDICTED", 0)
    parts = []
    if confirmed:
        parts.append(f"{confirmed} Confirmed")
    if predicted:
        parts.append(f"{predicted} Predicted")
    if ambiguous:
        parts.append(f"{ambiguous} Ambiguous")
    if blocked:
        parts.append(f"{blocked} Blocked")
    verified_summary = ", ".join(parts)

    # Honest-fail
    honest_fail = verdict.get("honest_fail_declaration")
    honest_fail_text = ""
    if honest_fail:
        honest_fail_text = f"## Honest-Fail Declaration\n\n> {honest_fail}"

    # Scope limitations
    limitations = verdict.get("scope_limitations", [])
    limitations_text = ""
    if limitations:
        limitations_text = "## What Was NOT Checked\n\n" + "\n".join(
            f"- {l}" for l in limitations
        )

    return f"""# Constitutional Verification Report

**Subject**: Company X SOC2 Readiness Assessment
**Verified**: {now}
**Original AI verdict**: READY FOR AUDIT ({ai_claim})
**Verified verdict**: {verdict.get('verdict', 'unknown').upper()} ({verified_summary})

## Per-Claim Results

| Claim | AI Rating | Verified Status | Finding |
|-------|-----------|-----------------|---------|
{results_table}

{overrides_text}

{honest_fail_text}

{limitations_text}

## Evidence Bundle

All receipts available in this directory. Every claim links to its evidence source.
Verify independently.
"""


def main():
    print("Constitutional Verification Demo")
    print("=" * 40)
    print()

    # Preflight
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_assessment = (SCENARIO_DIR / "ai_assessment.md").exists()
    evidence_files = sorted(f for f in (SCENARIO_DIR / "evidence").iterdir() if f.suffix == ".md") if (SCENARIO_DIR / "evidence").exists() else []

    print(f"  Assessment file: {'found' if has_assessment else 'MISSING'}")
    print(f"  Evidence files:  {len(evidence_files)} found")
    print(f"  Anthropic key:   {'present' if has_key else 'MISSING'}")
    print()

    if not has_key:
        print("ERROR: Missing ANTHROPIC_API_KEY.")
        print("  export ANTHROPIC_API_KEY=your-key")
        print("  python3 run.py")
        raise SystemExit(1)

    if not has_assessment or not evidence_files:
        print("ERROR: Scenario files missing. Check scenario/ directory.")
        raise SystemExit(1)

    client = anthropic.Anthropic()

    # Read inputs
    ai_assessment = (SCENARIO_DIR / "ai_assessment.md").read_text()
    evidence_texts = {}
    for f in sorted((SCENARIO_DIR / "evidence").iterdir()):
        if f.suffix == ".md":
            evidence_texts[f.stem] = f.read_text()

    evidence_block = "\n\n---\n\n".join(
        f"## {name}\n{content}" for name, content in evidence_texts.items()
    )

    # Agent 1: Analyst
    print("Phase 1: Analyst extracting claims...")
    plan, plan_raw = call_agent(
        client,
        "analyst",
        ANALYST_PROMPT,
        f"Analyze this AI-generated assessment and extract its claims:\n\n{ai_assessment}",
    )

    # Agent 2: Verifier
    print("Phase 2: Verifier checking claims against evidence...")
    results, results_raw = call_agent(
        client,
        "verifier",
        VERIFIER_PROMPT,
        f"Verification plan:\n{json.dumps(plan, indent=2)}\n\nEvidence corpus:\n{evidence_block}",
    )

    # Agent 3: Witness
    print("Phase 3: Witness reviewing verification...")
    verdict, verdict_raw = call_agent(
        client,
        "witness",
        WITNESS_PROMPT,
        f"Verification plan:\n{json.dumps(plan, indent=2)}\n\nVerifier results:\n{json.dumps(results, indent=2)}",
    )

    # Write outputs
    OUTPUT_DIR.mkdir(exist_ok=True)
    receipts_dir = OUTPUT_DIR / "receipts"
    receipts_dir.mkdir(exist_ok=True)

    (receipts_dir / "verification_plan.json").write_text(json.dumps(plan, indent=2))
    (receipts_dir / "verification_results.json").write_text(
        json.dumps(results, indent=2)
    )
    (receipts_dir / "witness_verdict.json").write_text(json.dumps(verdict, indent=2))

    summary = generate_summary(plan, results, verdict)
    (OUTPUT_DIR / "proof_summary.md").write_text(summary)

    # Done
    print()
    print("=" * 40)
    print(f"Done. Read: {OUTPUT_DIR / 'proof_summary.md'}")
    print()

    # Print the headline
    total = len(results.get("results", []))
    statuses = [r["status"] for r in results.get("results", [])]
    confirmed = statuses.count("CONFIRMED")
    print(f"Original AI assessment: {total}/{total} COMPLIANT — READY FOR AUDIT")
    print(
        f"Constitutional verification: {confirmed}/{total} CONFIRMED — {verdict.get('verdict', '?').upper()}"
    )

    if verdict.get("honest_fail_declaration"):
        print()
        print(f"Honest-fail: {verdict['honest_fail_declaration']}")


if __name__ == "__main__":
    main()
