# Assay Deep Dive (2026 Q1)

Assay is a receipt-native evidence system for AI execution.

When someone asks:

> "Prove what your AI did."

...you need more than logs. Logs live on your infrastructure, under your control. They can be edited, deleted, or selectively presented.

Assay produces **signed evidence bundles (Proof Packs)** that anyone can verify independently -- **no access to your systems required**.

If you're currently filling out spreadsheets to document AI behavior for reviews or audits, Assay aims to replace that process with one CI step that produces portable evidence on every merge.

---

## TL;DR (The Primitive)

Assay introduces an atomic primitive:

**A signed, portable, independently verifiable evidence bundle for AI execution.**

Everything else composes around it:

- receipts -> packs
- packs -> verification
- verification semantics pinned by lockfile
- CI gates + audit exports on top

The key insight is the **Integrity vs Claims** split:

- Integrity answers: "Were these bytes tampered with after creation?"
- Claims answer: "Does this evidence satisfy our declared governance checks?"

That separation enables the most important outcome:

**Integrity PASS + Claims FAIL = Honest Failure**
Authentic evidence proving the run violated standards (not a cover-up, not theater).

---

## The Golden Path (Easier Than a Spreadsheet)

You win when producing evidence is easier than maintaining a compliance spreadsheet.

### 0) See it work (no API key)

```bash
assay demo-pack
assay demo-incident
assay demo-challenge
```

### 1) Find your gap

```bash
assay scan .
```

### 2) Instrument (one line)

```python
from assay.integrations.openai import patch; patch()
# or anthropic/langchain equivalents
```

### 3) Produce packs automatically

```bash
assay run -c receipt_completeness -c guardian_enforcement -- python my_app.py
```

### 4) Verify anywhere

```bash
assay verify-pack ./proof_pack_*/
assay explain ./proof_pack_*/
```

### 5) Lock the verification contract (governance)

```bash
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

---

## Core Concepts

### 1) Receipts

A receipt is a single evidence event: "this action happened."

Receipts are not logs. Logs are mutable narrative. Receipts are structured evidence bytes designed to be portable inputs to independent verification.

Minimal emission:

```python
from assay import emit_receipt

emit_receipt("model_call", {
  "provider": "openai",
  "model_id": "gpt-4",
  "request_sha256": "...",
  "response_sha256": "...",
  "latency_ms": 812,
  "input_tokens": 1234,
  "output_tokens": 456,
})

emit_receipt("guardian_verdict", {"verdict": "allow", "policy_hash": "..."})
```

Assay auto-generates IDs and timestamps and binds receipts to a trace when running under `assay run`.

---

### 2) Proof Packs

A Proof Pack is a **5-file signed evidence bundle**:

| File | Purpose |
|------|---------|
| `receipt_pack.jsonl` | Append-only receipt stream for the run |
| `pack_manifest.json` | File hashes + metadata used for verification |
| `pack_signature.sig` | Detached Ed25519 signature |
| `verify_report.json` | Machine-readable verdicts |
| `verify_transcript.md` | Human-readable summary |

Packs may also include presentation files (`PACK_SUMMARY.md`) that don't affect verification semantics. The verifier only requires the 5-file kernel.

**Portability invariant:** you can hand this folder to someone who doesn't trust you or your infrastructure. They run `assay verify-pack` and get a deterministic verdict.

---

### 3) Integrity vs Claims (the trust split)

Assay intentionally separates two questions:

#### Integrity: "Were these bytes tampered with after creation?"

Integrity checks are structural:

- required files exist
- file hashes match manifest
- signature verifies
- schema/version constraints

Integrity failure means: **do not trust this evidence**.

#### Claims: "Does the evidence satisfy declared behavioral checks?"

Claims are semantic checks over receipts:

- required receipt types exist (e.g. `guardian_verdict`)
- counts / fields meet thresholds
- ordering constraints
- schema consistency rules

Claims failure means: **evidence is authentic, but standards were violated.**

This enables the 4 outcomes:

| Integrity | Claims | Exit Code | Meaning |
|-----------|--------|-----------|---------|
| PASS | PASS | 0 | Evidence checks out; behavior meets standards |
| PASS | FAIL | 1 | **Honest failure**: authentic evidence proving standards were violated |
| FAIL | -- | 2 | Evidence cannot be trusted (tampering / structural error) |
| PASS | SKIPPED | 0 | Evidence authentic; no standards declared |

**Honest failure is the differentiator.** It's the opposite of compliance theater.

---

### 4) Lockfile = machine-readable governance contract (the moat)

Without a lockfile, you can quietly weaken verification semantics between runs.

A lockfile pins:

- which claim checks exist
- their exact semantics (hashes)
- required checks and fail/allow behavior
- allowed signers and minimum versions
- fail-closed rules

In other words: it makes governance drift detectable.

Basic usage:

```bash
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
assay lock check assay.lock
assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
```

Lock mismatch fails closed with exit code **2**.

---

## Commands (How the Pieces Fit)

### `assay scan`

Purpose: detect likely LLM call sites and whether they are instrumented.

Scanner is a wedge, not epistemic truth.

- It creates urgency
- It points to likely integration work
- It's honest about confidence and limitations

Confidence tiers:

- **high**: direct SDK calls (OpenAI, Anthropic)
- **medium**: framework wrappers (LangChain/LiteLLM)
- **low**: heuristics (naming patterns, wrappers)

CI gating:

```bash
assay scan . --ci --fail-on high
```

If scan finds nothing, it directs the user toward runtime patching, manual receipt emission, or `assay demo-incident` as a starting point.

---

### `assay run`

Purpose: run a command under Assay collection, build and sign a Proof Pack.

```bash
assay run -c receipt_completeness -c guardian_enforcement -- python my_app.py
```

This does:

1. set trace context
2. run command
3. collect receipts
4. build pack files
5. sign manifest
6. write PACK_SUMMARY.md
7. print summary + location

---

### `assay verify-pack`

Purpose: verify integrity + (optionally) claim checks.

```bash
assay verify-pack ./proof_pack_abc123/
```

Fail-closed gating:

```bash
assay verify-pack ./proof_pack_abc123/ --lock assay.lock --require-claim-pass
```

---

### `assay explain`

Purpose: plain-English proof pack explanation for humans.

```bash
assay explain ./proof_pack_abc123/
```

It answers:

- what happened (counts, providers/models)
- integrity verdict + why
- claims verdict + why
- what is proven vs not proven
- signer identity

This is the artifact people paste into security questionnaires and audit threads. Use `--format md` for markdown output or `--format json` for machine-readable.

---

### `assay doctor`

Purpose: preflight readiness checker.

```bash
assay doctor
assay doctor --profile ci
assay doctor --profile ledger --strict
```

Doctor prints the *single next command* to become "green."

---

## Integrations: Patching vs Manual Emission

Assay supports two main paths:

### 1) Integration patching (fastest adoption)

Monkey-patch the SDK so calls emit receipts automatically.

```python
from assay.integrations.openai import patch
patch()
```

This is the fastest "easier than spreadsheet" route.

### 2) Manual receipt emission (universal)

Any framework can emit receipts directly:

```python
from assay import emit_receipt
emit_receipt("model_call", {"provider": "...", "model_id": "..."})
```

This is how you support custom wrappers, internal gateways, and non-Python ecosystems.

---

## Verifier ABI and Conformance (Protocol-Ready)

Assay is designed so independent verifiers can be implemented in other languages.

Key choices that support this:

- canonical JSON (JCS / RFC 8785 style canonicalization)
- detached signature
- stable file layout
- machine-readable verify report
- conformance corpus with expected outcomes

Conformance corpus principle:

- good packs -> exit 0
- claim-fail packs -> exit 1
- tampered packs -> exit 2

The verifier contract matters because Assay's long-term destiny is interoperability: multiple orgs producing and verifying packs without shared infrastructure trust.

---

## Trust Boundaries: What Assay Does NOT Prove

Assay produces **self-attested evidence**.

Integrity verification proves evidence hasn't been tampered with *after creation*. It does not prove evidence was honestly created in the first place.

Assay does **not** prove:

- **Completeness**: Assay verifies receipts that exist. It cannot prove receipts that should exist but were never emitted.
- **Freshness**: Without challenge nonces or a freshness window, a pack could be replayed.
- **External attestation**: No third-party witness quorum in v1.2.0.
- **Timestamp honesty**: Local timestamps can be fabricated without an external time authority (RFC 3161).
- **Signer key health**: If the signing key is compromised, an attacker can produce "valid" packs.

These are stated limitations, not hidden ones. Over-claiming destroys trust faster than bugs.

---

## Why "Honest Failure" Is the Centerpiece

Most compliance systems incentivize "everything passed."

Assay encodes the opposite incentive:

- **Integrity PASS + Claims FAIL** is not embarrassing
- it's proof the system can tell the truth even when the news is bad

That is the difference between:

- compliance theater ("we passed") and
- accountability ("we can prove we failed honestly under a fixed contract")

---

## Why Lockfiles Matter More Than Packs (Strategically)

Proof Packs are the portable evidence primitive.

The lockfile is the retention primitive.

Once a repo has:

- `assay.lock`
- CI enforcing `verify-pack --lock --require-claim-pass`
- and a stable signer policy

...removing Assay means losing audit posture and drift detection. That is switching cost, but it's also the thing standards bodies and auditors actually want: a pinned verification contract.

---

## "Easier Than a Spreadsheet" Test (Marketing + UX)

Every piece of messaging should pass this check:

> Does this sound easier than maintaining a compliance spreadsheet?

If not, you are losing.

The winning pitch is not "tamper-evident evidence bundles" (sounds hard).
It's:

> "Stop filling out the AI compliance spreadsheet. Add one CI step. Every merge emits portable evidence."

---

## What Comes Next (Only After Signal)

These are good second-order products, but they should be demand-driven:

### Compliance adapters (likely step 2)

Exports that map evidence to audit language:

- `assay export --format soc2`
- `assay export --format eu-ai-act`

This keeps the independence value prop intact (exports are local artifacts).

### Evidence freshness and posture reports

A posture artifact summarizing:

- evidence freshness window
- drift from last known-good pack
- signer age / rotation status
- new call sites / coverage changes

### Receipt schema formalization

Receipts are a hidden API contract. Formalize schemas so others can implement emitters/integrations correctly.

---

## Appendix: Mental Model (One Sentence Each)

- **Receipt**: one evidence event
- **Pack**: signed bundle of receipts
- **Integrity**: tamper detection
- **Claims**: behavioral standards checking
- **Honest failure**: authentic evidence of violation
- **Lockfile**: pinned governance contract
- **Scanner**: urgency wedge, not truth
- **Verifier ABI**: interoperable verification contract

---

## Read Next

- [Quickstart](README_quickstart.md) -- install, golden path, command reference
- [Decision Log](ASSAY_DECISION_LOG.md) -- every locked decision and why
