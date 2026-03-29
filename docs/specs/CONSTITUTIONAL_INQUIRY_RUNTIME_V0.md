# Constitutional Inquiry Runtime v0

Version: 0.1.0
Created: 2026-03-28
Status: Doctrine note (stabilizer, not specification)

---

## Problem

Evaluation claims travel without governed evidence. A team runs an
LLM-as-judge evaluation, observes a score delta, and ships a blog post.
Nobody checks whether the judging instrument changed between runs.

The delta is real arithmetic. The claim it supports is structurally
invalid.

This is not a tooling gap. It is a constitutional gap: there is no
authority that governs which comparisons are admissible and which are
not.

## Core Claim

Evaluation is admissibility-governed, not score-governed.

A score delta is a number. An admissible claim is a delta that
survived a constitutional check: the measurement instrument was
preserved, the comparison conditions were declared, and the evidence
bundle is complete.

Raw deltas are unsafe not because the arithmetic is wrong, but because
the instrument identity is unverified.

## The Constitutional Object

An **inquiry episode** is a governed transaction with:

| Component | Role |
|-----------|------|
| **Claim under test** | The assertion to be evaluated for admissibility |
| **Requested configuration** | What the operator intended to run |
| **Executed configuration** | What actually ran |
| **Evidence bundle** | Declared metadata for each run (15 parity fields in judge domain) |
| **Comparability contract** | Which fields must match, at what severity |
| **Verdict** | SATISFIED / DOWNGRADED / DENIED / UNDETERMINED |
| **Consequence** | Blocked actions, required actions, claim status |
| **Receipt** | Machine-readable record of the verdict and its basis |

An inquiry episode is not a request-response pair. It is a
constitutional transaction: the system either admits the claim or
denies it, with reasons and consequences.

## Why Raw Deltas Are Unsafe

Six classes of instrument drift can invalidate a comparison:

| Drift class | Example | Effect |
|-------------|---------|--------|
| **Judge model drift** | gpt-4o-2024-08-06 → gpt-4o-2024-11-20 | Different scoring distribution |
| **Prompt drift** | "Rate helpfulness" → "Rate helpfulness, be lenient on formatting" | Altered scoring criteria |
| **Rubric drift** | 5-point → 7-point scale, or different anchors | Incomparable score spaces |
| **Missing bundle members** | Temperature not declared | Cannot verify execution parity |
| **Provenance ambiguity** | Field from env var vs config file vs inference | Unknown authority of field value |
| **Hash instability** | CRLF vs LF in prompt template | False mismatch from formatting noise |

Any one of these is sufficient to make a delta inadmissible. The
comparability contract defines which are invalidating (forces denial),
which are degrading (allows claim with caveat), and which are
informational.

## Comparability Law

Four rules govern what may be compared:

1. **Instrument identity is the primary invariant.** If the
   measurement instrument changed, the delta is inadmissible. Model
   version, prompt template, scoring rubric, and score type/range are
   instrument identity fields. A change to any one is an instrument
   change.

2. **Execution parameters are secondary.** Temperature, max tokens,
   top-p, and judge passes affect reproducibility but not instrument
   identity. Mismatches degrade the claim; they do not deny it.

3. **Evaluation surface defines the measured object.** Dataset,
   dataset version, presentation order, and input format define what
   was measured. Changes here mean the measurement applies to a
   different object.

4. **Completeness is a precondition.** If required fields are missing
   from either bundle, the verdict is UNDETERMINED — not DENIED, not
   SATISFIED. Absence of evidence is not evidence of absence, but it
   is also not evidence of compliance.

## Receipts

Every verdict emits a machine-readable receipt containing:

- Verdict and claim status
- Mismatches with severity, rule, and explanation
- Instrument continuity assessment (PRESERVED / BROKEN / UNKNOWN)
- Bundle completeness for both sides
- Consequence: blocked and required actions
- Contract identity and hash (for amendment lineage)
- Diff ID for supersession tracking

Receipts are the output contract. Advisory verdicts and enforcement
verdicts use the same receipt format. The difference is whether the
consequence is enforced (gate) or reported (compare).

## First Wedge: LLM-as-Judge Claim Governance

The first domain is LLM-as-judge evaluation comparability.

**What ships:**
- `assay compare` — advisory verdict with reasons and consequences
- `assay gate compare` — enforcement gate (fail-closed on UNDETERMINED)
- `judge-comparability-v1.yaml` — 15-field contract for judge evaluation parity
- Organic examples: DENIED (model + prompt drift), SATISFIED (pinned config), DOWNGRADED, UNDETERMINED

**What this proves:**
- Comparability law catches instrument drift mechanically
- Inadmissible deltas are denied with reasons and consequences
- Rerun under parity yields admissible claims with smaller, true deltas
- The 11.1% fake gain collapses to 4.7% real gain when the judge is pinned

**What this does not prove:**
- All evaluation fraud is solved
- All governance domains are covered
- Judges are well-calibrated
- Rubrics are well-designed
- The evaluated system is actually better
- General constitutional runtime is complete

## Bridge to Larger Pattern

This is the first constitutional transaction primitive, not the whole
runtime.

The pattern generalizes: any domain where two measurement runs are
compared under declared conditions can be governed by a comparability
contract. Scientific reproducibility, A/B testing, model selection,
benchmark claims — all share the structure of "claim under declared
parity, with verdict and consequence."

That generalization is real but deferred. The current scope is
judge-governance for LLM-as-judge evaluation. Widening happens after
the first denial has teeth, not before.

## Non-Goals (Explicit)

- Generic scientific query engine
- MemoryGraph promotion or belief management
- Broad multi-domain claim governance (until one domain is proven)
- Universal question planner
- Agent coordination or orchestration
- Truth determination (this governs admissibility, not truth)
