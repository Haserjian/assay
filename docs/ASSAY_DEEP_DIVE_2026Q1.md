# Assay Deep Dive 2026Q1

Purpose: provide one long-form, implementation-accurate document for what Assay is, how it works, what shipped, what is still risky, and how current work across CCIO and Quintet connects.

Audience:
- engineering leads implementing Assay
- operators running CI gates
- security/compliance reviewers validating evidence claims
- collaborators integrating Assay into external stacks

Status:
- Assay is published (`pip install assay-ai`)
- Proof Pack v1 flow is live (`assay run`, `assay verify-pack`)
- lockfile contract is live (`assay lock write`, `assay lock check`, `assay verify-pack --lock`)
- conformance corpus is live (`conformance/corpus_v1`)
- external integration work exists in `~/puppetlabs` (Quintet router + demos + CI gate)

---

## 1) What Assay Is

Assay is a verification layer for AI systems.

It does two different jobs on purpose:
- Courthouse job: prove structural integrity of evidence
- Laboratory job: test behavioral claims against that evidence

This split is the central invariant:
- integrity can pass while claims fail
- this is not a bug, it is the honesty property

Assay is not a general-purpose agent framework. It is the evidence and verification spine you attach to an existing runtime.

---

## 2) Core Concepts

### 2.1 Receipts

Receipts are structured records emitted during execution:
- examples: `model_call`, `guardian_verdict`, `capability_use`
- minimum required fields are enforced by Assay internals when emitted through `emit_receipt`

Canonical fields include:
- `receipt_id`
- `type`
- `timestamp`
- `schema_version`
- `seq`

Optional domain fields carry behavior context:
- model/provider/tokens/latency
- guardian decisions
- capability metadata

### 2.2 Proof Pack

A Proof Pack is the portable evidence unit. Current kernel:
- `receipt_pack.jsonl`
- `pack_manifest.json`
- `pack_signature.sig`
- `verify_report.json`
- `verify_transcript.md`

Key property:
- one folder can be forwarded and independently verified offline

### 2.3 Two Verifiers

Integrity verifier:
- validates signature, hashes, schema, required files, omission/tamper failures
- this decides structural truth

Claim verifier:
- executes RunCard claim specs on receipts
- this decides semantic truth

Orthogonality rule:
- claim results never upgrade integrity
- integrity fail is always authoritative

### 2.4 Exit Contract

`assay verify-pack` exit semantics:
- `0`: integrity pass and (if required) claims pass
- `1`: integrity pass, claim gate fail (`--require-claim-pass`)
- `2`: integrity fail or lock mismatch fail

---

## 3) End-to-End Operational Flow

### 3.1 Recommended Golden Path

```bash
pip install assay-ai
assay demo-pack
```

Then instrument real code:

```python
from assay import emit_receipt

emit_receipt("model_call", {"model": "gpt-4", "total_tokens": 1200})
emit_receipt("guardian_verdict", {"verdict": "allow", "tool": "web_search"})
```

Run wrapped execution:

```bash
assay run -c receipt_completeness -c guardian_enforcement -- python my_agent.py
```

Verify output pack:

```bash
assay verify-pack ./proof_pack_<id>/ --require-claim-pass
```

### 3.2 Lock-Enforced Verification

Write lockfile:

```bash
assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
```

Validate lockfile:

```bash
assay lock check assay.lock
```

Enforce lock during verify:

```bash
assay verify-pack ./proof_pack_<id>/ --lock assay.lock --require-claim-pass
```

### 3.3 Preflight Check

Before running Assay in a new environment, use `assay doctor` to verify readiness:

```bash
assay doctor                          # local dev (default)
assay doctor --profile ci             # CI environment
assay doctor --profile ledger         # ledger submission readiness
assay doctor --profile ledger --strict  # prod: require signature_verified
```

Doctor checks install, keys, run cards, lockfile, pack integrity, and CI integration.
It prints the single next command to become "green":

```
assay doctor (profile=local)

  PASS  DOCTOR_CORE_001  Assay CLI available (1.0.1)
  PASS  DOCTOR_KEY_001   Signer key present (assay-local)
  WARN  DOCTOR_LOCK_001  No lockfile found at assay.lock

  PASS: 5 | WARN: 1

  Next: assay lock write --cards receipt_completeness,guardian_enforcement -o assay.lock
```

Use `--json` for CI automation, `--fix` to auto-generate missing keys and lockfiles.

---

## 4) Implementation Surfaces in This Repo

### 4.1 CLI Surface

Primary commands currently used in production workflow:
- `assay demo-pack`
- `assay run`
- `assay verify-pack`
- `assay lock write`
- `assay lock check`

Note:
- legacy commands still exist in CLI for backward compatibility
- production docs should emphasize the Proof Pack path above

### 4.2 Lockfile Contract

Implementation: `src/assay/lockfile.py`

Lockfile fields include:
- `lock_version`
- `assay_version_min`
- `pack_format_version`
- `receipt_schema_version`
- `run_cards[]` with per-card `claim_set_hash`
- `claim_set_hash` (flattened, aligns to Proof Pack claim hash)
- `run_cards_composite_hash`
- `exit_contract`
- `signer_policy`

Current behavior:
- mismatch on pack format / claim set / signer allowlist triggers lock mismatch and exit `2`

### 4.3 Conformance Corpus

Generator: `conformance/generate_corpus.py`  
Verifier: `conformance/run_corpus.py`  
Outcome table: `conformance/corpus_v1/expected_outcomes.json`

Corpus v1 includes 6 packs:
- `good_01`, `good_02`, `good_03` -> expect `0`
- `claimfail_01` -> expect `1`
- `tampered_01`, `tampered_02` -> expect `2`

This is the verifier ABI contract fixture.

### 4.4 CI Surfaces

Primary CI file: `.github/workflows/ci.yml`

Notable jobs:
- `test`
- `wheel_smoke`
- `conformance`

Reusable verification workflow:
- `.github/workflows/assay-verify.yml`

This gives both in-repo verification and drop-in cross-repo gating.

---

## 5) Cross-Repo Map (What You Already Have)

Assay is now usable across your existing ecosystem, not just in `~/ccio`.

### 5.1 Verified downstream integration

Location: `~/puppetlabs` (external to this repo)

Shipped there:
- router-level optional Assay emission
- positive demo (`scripts/assay_demo.py`)
- adversarial two-act demo (`scripts/assay_demo_evil.py`)
- integration tests and CI gate
- Make targets (`make assay-smoke`, `make assay-evil`)

Why this matters:
- proves Assay works outside its home repo
- demonstrates integrity PASS / claim FAIL using realistic LLM call topology
- provides an operator-facing smoke path that is easy to rerun

### 5.2 Integration-ready surfaces across your repos

| Repo | Surface | What Assay can prove now |
|------|---------|---------------------------|
| `~/ccio` | `src/assay/integrations/*`, `assay run`, `assay verify-pack` | Portable pack integrity + claim gates in CI |
| `~/puppetlabs` | `quintet/model/router.py`, demos, CI job | Router-level LLM receipts and guardian evidence |
| `~/loom-labs/Loom` | `tools/agent_harness/*` pipeline | Multi-stage writer/checker/guardian execution evidence |
| `~/csp-tool-safety-profile` | policy contract layer | Policy-level conformance constraints mapped into RunCards |

Boundary note:
- downstream repos are not vendored into `~/ccio`; treat them as independent integrators with their own CI and release cadence.

---

## 6) Security and Trust Posture (Current Reality)

Assay currently provides:
- tamper-evident bundles
- deterministic verifier behavior
- explicit split between structural and semantic verification

Assay does not currently provide:
- universal runtime honesty guarantees if emitter runtime is compromised
- third-party witness trust by default
- court-grade external timestamp anchoring by default

Practical interpretation:
- Assay is strong evidence infrastructure
- not a magical truth oracle

---

## 7) QA State and Remaining Gaps

### 7.1 Verified in latest cycle (2026-02-07)

- 295 tests passing across 12 test files
- lockfile unit tests: 25 tests (`tests/assay/test_lockfile.py`)
  - 4 write tests, 2 validate tests, 5 check tests
  - 4 fail-closed load tests (missing fields, bad mode, bad fingerprints, bad version)
  - 4 fail-closed validate tests (missing hash, missing format, version below min, empty allowlist)
  - 5 semantic check tests (composite hash drift, claim hash drift, version below min, bad mode, missing fields)
  - 1 conformance corpus test
- corpus runner passes all 6 expected outcomes (`conformance/run_corpus.py`)
- lock write/check CLI path works
- lock mismatch exits with code `2`
- `verify-pack --lock` runs `check_lockfile()` BEFORE `validate_against_lock()` -- invalid lockfiles are rejected at entry
- `load_lockfile()` validates required fields, signer mode enum, PEP 440 version parseability
- `validate_against_lock()` treats missing fields as mismatches (not skips), checks version minimum
- `check_lockfile()` recomputes both `claim_set_hash` and `run_cards_composite_hash` from current card definitions
- corpus generation is deterministic (SHA-256 seeded IDs, no UUIDs)
- private corpus signing key excluded via `conformance/.gitignore`
- `packaging>=21.0` added to `pyproject.toml` dependencies

### 7.2 Completed hardening items

- [x] fail-closed lock enforcement in `verify-pack --lock`
- [x] full semantic validation in `check_lockfile()` (hash recomputation, version comparison)
- [x] remove private corpus signing key from tracked fixtures (`.gitignore`)
- [x] deterministic corpus generation (seeded receipt IDs, fixed timestamps)
- [x] 13 new fail-closed tests covering all rejection paths

### 7.3 Open hardening items (priority)

P1:
- formalize stochastic acceptance method in docs and code comments (default interval method + minimum trials; spec exists in `assay_master_plan.md` section 5.4)
- codify pre/post key revocation verifier semantics (non-retroactivity and conflict resolution order; spec exists in `assay_master_plan.md` section 4.2)

P1/P2:
- reduce PYTHONPATH coupling in base CI test job where feasible
- converge lint strategy to avoid broad unrelated debt blocking critical paths
- add CI assertion that regenerated corpus diffs are empty when inputs are unchanged

---

## 8) Architecture Notes Worth Keeping Stable

### 8.1 Keep the orthogonality contract stable

Never merge integrity and claim verification into one opaque verdict path.

### 8.2 Keep verifier semantics boring

Verifier should remain deterministic, strict, and small-surface.

### 8.3 Keep docs explicit on what is and is not proven

Over-claiming destroys trust faster than bugs.

### 8.4 Keep conformance packs as artifacts, not screenshots

The pack itself is the product primitive.

---

## 9) 30-Day Practical Plan (No Theater)

Week 1 (DONE):
- [x] fail-closed lock enforcement (`load_lockfile`, `validate_against_lock`, `verify-pack --lock`)
- [x] full semantic `check_lockfile()` with hash recomputation
- [x] remove tracked corpus private key + `.gitignore`
- [x] deterministic corpus fixture generation (seeded IDs, fixed timestamps)
- [x] 13 fail-closed tests covering all rejection paths
- [x] `packaging>=21.0` dependency added

Week 2:
- add CI assertion that regenerated corpus diffs are empty when inputs are unchanged
- finalize lockfile/verifier semantic contract doc: lock precedence, revocation ordering, exit code authority
- add explicit statistical acceptance defaults for stochastic claims (method + min trials)
- keep phase dependency gate explicit in docs and reviews: Phase 3 starts only after Phase 2 gate is passed

Week 3:
- run one external integration using only published docs + reusable workflow (no source edits by core team)
- collect integration friction as issue labels: docs ambiguity, CLI ambiguity, schema ambiguity
- tune quickstart and one-pager language for procurement-safe wording

Week 4:
- cut `v1.0.1` hardening release focused on verifier contract stability
- publish a public conformance corpus usage page with reproducible commands
- finalize one design-partner evidence pack from non-CCIO runtime

---

## 10) Document Map (Read Order)

Primary:
- `docs/README_quickstart.md`
- `docs/ASSAY_DEEP_DIVE_2026Q1.md` (this doc)
- `docs/assay_master_plan.md`
- `docs/ASSAY_DECISION_LOG.md`

Execution:
- `docs/PHASE_0_1_CUT_LIST.md`
- `docs/14_DAY_EXECUTION_BOARD.md`
- `docs/PROOF_PACK_SPRINT_ONE_PAGER.md`

Schemas and contracts:
- `docs/schemas/pack_manifest.schema.json`
- `docs/schemas/pack_manifest_unsigned.schema.json`
- `docs/schemas/attestation.schema.json`

Verification fixtures:
- `conformance/corpus_v1/expected_outcomes.json`
- `conformance/generate_corpus.py`
- `conformance/run_corpus.py`

Cross-repo integration context:
- `docs/DOC_OF_LINKS_ADDENDA.md`

---

## 11) Summary

Assay has crossed from concept to executable contract:
- signed pack format
- deterministic verifier semantics
- lockfile contract
- conformance corpus ABI
- external integration precedent

Contract hardening is now complete:
- fail-closed lock semantics (load, validate, check all fail-closed)
- deterministic corpus fixtures (seeded IDs, `.gitignore` for keys)
- 295 tests, all passing

The next value step is external operator usability:
- one external integration using only published docs
- friction logging and quickstart tuning
- v1.0.1 hardening release

That is the path from "interesting toolkit" to "trusted verification substrate."
