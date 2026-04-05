# Assay Pilot Program

Two entry points. Same product. Different pain.

---

## Which pilot fits your situation?

| | **Eval Comparability Pilot** | **Evidence Instrumentation Pilot** |
|---|---|---|
| **Pain** | Eval improvements that don't replicate; benchmark claims you can't defend | Auditor asks "show me what your AI did" and the answer is server logs |
| **Buyer** | Eval owner, ML platform lead | Compliance lead, CISO, VP Eng |
| **Entry event** | Judge drift caught; benchmark claim challenged; eval infrastructure investment | SOC 2 audit, EU AI Act readiness, procurement questionnaire, incident |
| **First step** | [Free comparability diagnostic](#eval-comparability-pilot) | [Free coverage diagnostic](#evidence-instrumentation-pilot) |

If you're not sure which fits: start with the coverage diagnostic. It shows
you every uninstrumented AI call site in your codebase — that's relevant to both.

---

## Eval Comparability Pilot

**What it catches**: Apparent eval improvements that are actually judge drift —
when the judge model version changes, the prompt changes, or the rubric shifts,
and the delta reflects instrument change, not system improvement.

**Demo (60 seconds)**:
```bash
pip install assay-ai
git clone https://github.com/Haserjian/assay.git && cd assay
bash examples/llm_judge/run_demo.sh --non-interactive
```
Shows: +11.1% apparent gain → DENIED (judge model + prompt drift) → rerun
→ SATISFIED at +4.7%. The 6.4% difference was instrument drift, not improvement.

**Free diagnostic**: Send us two recent eval run configs. We check whether
the claimed comparison is structurally valid. Takes 30 minutes. You keep the results.

**Pilot scope**:
- We author a comparability contract for your eval regime
- Wire `assay compare` and `assay gate compare` into your pipeline
- Deliver the CI gate + evidence trail + handoff doc
- Timeline: 1-2 weeks

**Pricing**:
- Single eval regime, one comparability contract: 1 week, $10K
- Multiple regimes or model types: 2 weeks, $25K
- Enterprise (multiple teams, custom contracts): quote

---

## Evidence Instrumentation Pilot

**What it produces**: Signed evidence packs that a third party can verify
offline — no server access, no credentials required. Today the trust anchor
is the producer's signing key (T0: vendor-signed, origin trusted by policy).
Tamper detection is unconditional: edit one byte after signing and verification
fails, regardless of who holds the key.

**The difference from observability**: An observability trace explains your
system to you. An Assay evidence pack transfers to an auditor and lets them
verify on their own machine — without accessing your server or depending on your platform.

**Free coverage diagnostic**: We show you every uninstrumented AI call site
in your codebase and what evidence you'd have today if asked to produce it.
No install required on your end.

**What the pilot produces**:
- CI gate running on every PR
- Signed evidence packs built automatically on every merge
- Baseline pack for regression comparison
- Reviewer Packet — a settlement-verdict artifact
  (VERIFIED / VERIFIED_WITH_GAPS / INCOMPLETE_EVIDENCE / EVIDENCE_REGRESSION)
  that an auditor can verify with one command on their own machine

**Timeline and pricing**:
- Single service (1-5 call sites): 1 week, $10K
- Multi-service (5-20 call sites): 2 weeks, $25K
- Enterprise (20+ call sites, multiple repos): custom quote

**Qualification**: requires at least one LLM call site in production code,
a CI/CD pipeline (GitHub Actions or equivalent), and Python 3.9+.

---

## What to expect

**Before kickoff**: fill out the [intake form](pilot/intake-template.md).
Takes 10 minutes. Means the kickoff call is scoping decisions, not data collection.

**Week 1**: Instrument call sites, set up CI gate, first evidence pack verified.

**Week 2** (multi-service): Harden thresholds, separate signing keys,
threshold tuning on real PRs.

**Closeout**: Evidence pack verified on a machine that has never seen
your code. Time from "give me evidence for this run" to verified pack: under 5 minutes.
Full handoff doc — including what this evidence means for your security/compliance team.

---

## What this is not

- Not observability or monitoring (for that: LangSmith, Langfuse, Braintrust)
- Not a compliance determination (evidence maps to regulatory requirements;
  your legal team determines compliance)
- Not a replacement for eval methodology (Assay verifies comparability and
  produces evidence; it does not tell you what to measure or how to design rubrics)

---

## Current trust posture (T0)

Proof packs are vendor-signed today. The operator holds the signing key.
This is the honest T0 claim: tamper-evident, offline-verifiable, origin
trusted by policy. T1 (CI-witnessed signing) is on our near-term roadmap
and is not yet operational.

See `PILOT_TRUTH_STATEMENT.md` (internal doc, not in this repo) for the full
Green/Yellow/Red claims ledger before any external conversation.

---

## Start here

**Eval-drift entry**: [docs/outbound/START_HERE.md](outbound/START_HERE.md)
**Coverage diagnostic**: `pip install assay-ai && assay scan . --report`
**Gallery**: `https://github.com/Haserjian/assay-proof-gallery`
**Intake form**: [pilot/intake-template.md](pilot/intake-template.md)
