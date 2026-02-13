# Pre-written Comment Replies

Copy/paste and adapt as needed. Keep replies short on HN.

---

## 1. "We already have logging / OpenTelemetry / LangSmith / W&B"

Great -- those are observability tools and they're valuable. Assay targets a different layer: tamper-evident evidence. The distinction is between "we can see what happened" (logs under your control) and "we can prove what happened" (signed receipts a third party can independently verify without access to your infrastructure). Many of the scanned projects have extensive logging. What they don't have is a portable, cryptographically signed artifact an auditor could check.

---

## 2. "This is just signatures, not truth"

Correct. Assay proves *integrity* of recorded events and conformance to declared checks (RunCards), not semantic correctness. It's evidence plumbing -- "these bytes were not modified after pack creation" and "these receipts satisfy the declared claims." Truth/correctness is a separate layer that sits on top of evidence.

---

## 3. "Your scanner can be wrong / static analysis can't prove X"

Agreed. That's why we split findings by confidence level: high-confidence = direct SDK calls (unambiguous), medium = framework calls gated behind import evidence, low = heuristic name matches. The method limits section in the report covers this explicitly. Repo SHAs are in the CSV so anyone can rerun and challenge specific findings.

---

## 4. "Why not just use Sigstore / SLSA / in-toto / supply chain tools?"

Those secure artifacts and builds (the software supply chain). Assay targets *runtime AI calls* -- what went into and came out of each LLM invocation during execution. The output is a portable proof pack that can be verified offline. Different attack surface, complementary tools.

---

## 5. "This seems like compliance theater"

The goal is courtroom-grade replayability: show what happened, when, under which policy hash, with cryptographic integrity. The CI gate is three commands: `assay run -c receipt_completeness -- python your_app.py` (produce evidence), `assay verify-pack ./proof_pack_*/ --lock assay.lock` (check integrity + contract), `assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict` (enforce budget thresholds). Exit 0 = clean, exit 1 = regression or threshold exceeded, exit 2 = tampered. That's a concrete, falsifiable contract, not a checkbox.

---

## 6. "Where's the money? / Is this a product?"

The CLI is free and open source (Apache-2.0). The scan creates a quantified gap; the paid product is a fixed-scope integration sprint (instrument a codebase + lock it in CI so every merge produces a verified proof pack). The integration itself is 2 lines per SDK -- the sprint is about coverage, lockfile configuration, and CI wiring. I'm taking 3 pilot integrations this month -- if your team has LLM calls in production and needs audit-ready evidence, reach out.

---

## 7. "If the system is malicious it can emit fake receipts"

Right. Assay prevents *post-hoc editing* of evidence (tamper-evidence), not *lying at the source* (source attestation). Those are different trust boundaries. We start with tamper-evidence because it's the minimum viable trust primitive and deployable everywhere without hardware dependencies. Stronger anchors (TEE, external witness, transparency log) are a separate layer.

---

## 8. "So this proves the AI is correct / safe?"

No. Assay proves tamper-evident evidence integrity and control conformance, not model correctness. It answers "was this evidence modified after creation?" and "did the run satisfy declared checks?" -- not "was the output right." Correctness is a separate layer that sits on top of evidence.

---

## 9. "Why should I trust your tool?"

You don't have to. The verifier is open source -- `assay verify-pack` is ~200 lines of deterministic hash + signature checking. Read it, run it, or write your own. The trust chain is public: assay repo, verify action, ledger. No phone-home, no SaaS dependency for verification.

---

## 10. "How hard is this to integrate?" / "How many lines of code?"

Two lines per SDK. For OpenAI:

```python
from assay.integrations.openai import patch
patch()
```

That monkey-patches the SDK -- every `client.chat.completions.create()` call now emits a signed receipt into the active proof pack. Same pattern for Anthropic and LangChain. Your business logic doesn't change at all.

Then wrap your app with `assay run -- python your_app.py` (or `assay run -- pytest`) and you get a proof pack: receipts, manifest, Ed25519 signature, verification report. The full CI gate is three commands:

```bash
assay run -c receipt_completeness -- python your_app.py
assay verify-pack ./proof_pack_*/ --lock assay.lock
assay diff ./baseline_pack/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0 --gate-strict
```

Lockfile catches config drift. Verify-pack catches tampering (exit 2). Diff catches regressions and budget overruns (exit 1). `assay scan . --report` generates an HTML report showing which call sites have receipts and which don't.

---

## 11. "Can you help us integrate this?" (pilot CTA -- use as a reply, not in post body)

I'm taking 3 pilot integrations this month -- 1-week sprint to instrument a codebase and lock it in CI so every merge produces a verified proof pack. If your team has LLM calls in production and needs audit-ready evidence, DM me.
