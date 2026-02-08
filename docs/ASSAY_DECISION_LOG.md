# Assay Decision Log

Last updated: 2026-02-07
Verification status: see CI jobs (`test`, `wheel_smoke`, `conformance`) for current counts.

---

## Part 1: Constitutional Principles

These are non-negotiable. If a future change violates any of these, it's wrong.

### P1. Integrity and claims are orthogonal axes

- **Integrity** (Courthouse): "Was the evidence tampered/forged/omitted?"
- **Claims** (Laboratory): "Does the evidence prove what you claim?"
- These are verified by separate code paths (`integrity.py` vs `claim_verifier.py`).
- A pack can be integrity-PASS and claim-FAIL. That is a success condition:
  it proves the system is honest about failing behavior.

### P2. Claims cannot upgrade integrity

Integrity can gate claim verification (if the pack is tampered, don't trust receipts).
Claims must never affect integrity output. One-way dependency only.

### P3. The verifier stays small

Under 500 LOC (enforced by test), under 5 dependencies, no business logic in
`integrity.py`. Claims, RunCards, policy engines -- all live outside the verifier
boundary.

**Enforcement**: `tests/assay/test_integrity_mutants.py::TestVerifierBudget`
asserts `integrity.py <= 500 LOC`. Currently 498.

### P4. Fail closed on unknowns

Unknown severity labels -> critical failure (not silent downgrade).
Unknown check function names -> automatic fail.
Missing required fields -> fail, never skip.

### P5. Determinism is sacred

Same inputs -> same outputs, always. JCS canonicalization (RFC 8785) is the
canonical form. Fingerprints, hashes, verification results must be reproducible
across runs, machines, and time.

### P6. Snapshots are court records; deltas are operational telemetry

Proof Packs are the portable audit unit (the court record).
Any future Differential Proof Pack (DPP) is additive and must anchor to a
snapshot via `base_pack_root_sha256`. Deltas never replace snapshots.

---

## Part 2: Locked Decisions (Implemented)

These are in the code, tested, and shipping.

### D1. Two-verifier architecture

| Component | Purpose | File | LOC |
|-----------|---------|------|-----|
| `integrity.py` | Structural truth (tamper, omission, signatures) | `src/assay/integrity.py` | 498 |
| `claim_verifier.py` | Semantic truth (behavior claims against receipts) | `src/assay/claim_verifier.py` | 318 |

### D2. Proof Pack v0: 5-file signed kernel

Files: `receipt_pack.jsonl`, `verify_report.json`, `verify_transcript.md`,
`pack_manifest.json`, `pack_signature.sig`.

Circular dependency resolved: `pack_manifest.json` and `pack_signature.sig`
cannot be in the hash-covered `files` array. Protected by Ed25519 signature
and detached-sig parity check respectively.

### D3. Claim wiring into ProofPack

`ProofPack(claims=[...])` runs `verify_claims()` after integrity check.
Attestation gets `claim_check: PASS|FAIL|N/A` and `discrepancy_fingerprint`.
`verify_report.json` includes `claim_verification` section when claims exist.
`claim_set_hash` auto-computed from claim specs via JCS when claims provided.

### D4. 5 built-in RunCards

| Card ID | What it checks | Status |
|---------|---------------|--------|
| `guardian_enforcement` | Guardian verdict receipts exist | Shipped |
| `receipt_completeness` | Min receipt count + model_call present | Shipped |
| `no_breakglass` | No breakglass override receipts in pack | Renamed from `no_unauthorized_override` (B16) |
| `timestamp_ordering` | Timestamps non-decreasing | Shipped |
| `schema_consistency` | All model_call receipts have schema_version 3.0 | Renamed from `policy_binding` (B16) |

Card IDs are now frozen. These names appear in signed packs and lockfiles.

### D5. Severity model: fail-closed allowlist

Only `critical` and `warning` accepted (case-insensitive normalization).
Invalid severities -> critical failure result. Warnings don't fail the claim set.

### D6. Audit-hardening fields in attestation

| Field | Value | Purpose |
|-------|-------|---------|
| `proof_tier` | `"signed-pack"` | Prevents over-claiming (not signed-receipts) |
| `time_authority` | `"local_clock"` | Honest about timestamp source |
| `head_hash_algorithm` | `"last-receipt-digest-v0"` | Documents chain construction |
| `canon_impl` | `"receipts.jcs"` | Pins canonicalization implementation |
| `canon_impl_version` | version string | Detects library drift |

### D7. Embedded public key for offline verification

Manifest contains `signer_pubkey` (base64 Ed25519) and `signer_pubkey_sha256`.
Verifier uses embedded key first; keystore is fallback only.

**Trust contract**:
- Integrity PASS does not depend on local keystore if `signer_pubkey` is embedded
  and signature verifies against it.
- Local keystore mismatch -> warning ("key fingerprint differs"), not failure.
  This is trust-store divergence, not integrity failure.
- Keystore mismatch cannot downgrade integrity; it only warns about local config.
- Future: `--require-keystore-match` flag for pinned-trust environments where
  embedded key alone is insufficient (e.g., supply chain verification).

### D8. `pack_root_sha256` (D12 implemented)

Now: `pack_root_sha256 = attestation_sha256` (D12 implemented 2026-02-07).
The attestation is the single immutable identifier for the evidence unit.

### D9. Naming decisions

| Internal name | Keep? | Notes |
|--------------|-------|-------|
| `claim_check` | YES | Not "verdict" -- check implies spec, verdict implies judgment |
| `discrepancy_fingerprint` | YES | Precise even when result is pass (identifies what was tested) |
| `run_id` | YES | Canonical name; `trace_id` accepted as backward-compat alias |
| `receipt_integrity` | YES | Structural only |

External-facing synonyms (for docs/marketing, not code):
- `claim_check` -> "behavior checks"
- `discrepancy_fingerprint` -> keep as-is (or "check fingerprint" if you must simplify)

### D10. Discrepancy fingerprint formula (v0)

**v0 canonical formula** (stamped as stable):

Canonical claim outcome material for fingerprint hashing:
```
sorted by claim_id: [{claim_id, passed, expected, actual, severity}]
```
Serialized via JCS, then SHA-256.

**Future evolution** (D17+): may add `reason_code`, `claim_version`,
`policy_hash`, `suite_id` to canonical material. Any change creates a new
formula version (fingerprints are not comparable across formula versions).

### D11. JSONL invariant

One JCS-canonical JSON object per line, no blank lines.
Non-empty packs end with exactly one trailing newline.
Empty packs produce a 0-byte file (no newline).
Verifier counts non-empty lines (`line.strip()`).

### D20. Verifier lockfile contract (implemented)

Lockfile commands are now part of the stable verification surface:
- `assay lock write`
- `assay lock check`
- `assay verify-pack --lock assay.lock`

The lockfile freezes:
- active RunCards and claim hash contract
- pack format/version expectations
- signer policy expectations
- exit contract documentation (`0/1/2`)

Current behavior:
- lock mismatch is a hard verification failure (`exit 2`)
- lock contract is enforced in `verify-pack` flow

### D21. Conformance corpus ABI (implemented)

Assay now ships a conformance corpus:
- generated by `conformance/generate_corpus.py`
- verified by `conformance/run_corpus.py`
- expected outcomes pinned in `conformance/corpus_v1/expected_outcomes.json`

The corpus encodes verifier ABI expectations:
- good packs -> `0`
- claim-fail packs -> `1`
- tampered packs -> `2`

This is the regression harness for external interoperability and release gating.

---

## Part 3: Agreed Decisions (Not Yet Implemented)

These are decided but need code.

### D12. pack_root = attestation_sha256 [IMPLEMENTED 2026-02-07]

`pack_root_sha256 = attestation_sha256` in both builder and verifier.

**Rationale**: Multi-witness co-signatures should not change pack identity.
Pack identity represents "what happened + what was checked," not "who signed."

### D13. Claim identity is `(claim_id, claim_version)`

**Rule**: Claims evolve per-claim, not per-claim-set.

Pack records: `executed_claims: [{claim_id, claim_version, check_id, severity, result_hash}]`
`claim_set_hash` derived from sorted executed_claims list + specs.

Verifier modes:
- `--claim-mode=strict`: exact version match required
- `--claim-mode=compatible`: newer verifier can re-evaluate, results stored separately

**Why**: Real compliance requirements change one at a time, not as atomic frameworks.
**When**: Must ship before packs escape into the wild.

### D14. Claim proof tiers (non-deterministic claims)

Claims must declare their evaluation mode via `claim_proof_mode`:

| Tier | Meaning | Determinism |
|------|---------|-------------|
| `structural` | Pure receipt constraints | Fully deterministic |
| `semantic_model` | LLM-evaluated; evaluator metadata recorded | Deterministic within evaluator spec |
| `semantic_human` | Human co-sign receipt required | N/A (human judgment) |
| `statistical_ktrial` | K trials + acceptance rule | Statistical guarantee |

Default: `structural`. v0 only implements `structural`.

If `semantic_model` is used, must receipt: evaluator model+version, temperature,
prompt template hash, policy hash, evaluator output hash.

### D15. Attestation authority taxonomy

Receipts are **self-attested** by default. Say it explicitly.

Fields to add to attestation:
```
attestation_sources:
  time_authority: local | tsa
  witness: none | host | external
  transparency: none | rekor | ...
```

v0 ships: `time_authority: local, witness: none, transparency: none`.
This is honest. The fields exist so the data structure can grow.

### D16. Assurance level as derived field

`assurance_level` should be computed from evidence, not author-declared:
- L0: integrity PASS only
- L1: integrity PASS + all critical claims PASS
- L2: L1 + witness attestation
- L3: L2 + transparency log anchoring

No manual setting. Prevents marketing from creeping into facts.

### D17. Reason codes for claim failures

Add to ClaimResult:
- `reason_code` (enum, machine-readable)
- `evidence_refs` (receipt_ids / hashes / indices)
- `details` (optional human text)

Initial enum:
```
MISSING_REQUIRED_RECEIPT
FORBIDDEN_RECEIPT_TYPE
POLICY_HASH_MISMATCH
FIELD_VALUE_MISMATCH
THRESHOLD_NOT_MET
TIMESTAMP_VIOLATION
UNKNOWN_CHECK_ID
INVALID_SEVERITY
```

### D18. Claim function ABI (compiler-friendly)

Hard rules for check functions:
- Pure function: `check(receipts, context) -> ClaimResult`
- No network calls, no filesystem, no time.now(), no randomness
- Deterministic given `(receipt_pack, claim_spec)`

v0.5: ClaimSpec supports declarative core for common patterns
(required types, required fields, forbidden types, thresholds, ordering).
Complex checks use Python plugin functions.

### D19. Differential Proof Pack (DPP)

Additive operational layer on top of snapshots (P6).

**Core rules:**
- DPP must anchor to a snapshot: `base_pack_root_sha256` (required),
  `prev_pack_root_sha256` (optional for chaining)
- Checkpoint rule: require a new full snapshot every N deltas (e.g., 10)
- Append-only evidence: no `removed_receipt_ids`. Use RevocationReceipt for
  semantic removal instead of physical deletion.
- Signer continuity: DPP must include `prev_signer_set_hash` /
  `current_signer_set_hash` or verification fails.
- Verifier split preserved: integrity verifier validates delta structure/
  signature/anchors; claim_verifier computes claim_delta semantics.

**v0 DPP schema** (`delta_pack.json`, signed, offline verifiable):
```
delta_id
base_pack_root_sha256
prev_pack_root_sha256
current_pack_root_sha256
timestamp_start / timestamp_end
added_receipt_ids_hash  (sorted JCS-hash for v0)
claim_delta: [{claim_id, claim_version, from, to, severity, evidence_refs_hash}]
evidence_debt_delta: numeric fields
witnesses: optional co-sign blocks
signature (+ detached sig file)
```

**Deterministic diff contract:**
- Diff over canonical claim tuples only: `(claim_id, claim_version, from, to,
  severity, evidence_refs_hash)`.
- No free-text in signed core; human explanation goes in transcript.

**CLI:**
- `assay diff <prev_pack_dir> <current_pack_dir> -> delta_pack/`
- `assay verify-diff <delta_pack_dir> [--with-base <base_pack_dir>]`

**When**: Only after runner path exists. DPP multiplies value once packs are
produced routinely. Phase N.

---

## Part 4: Prioritized Backlog

### Tier 1: Ship evaluation bundle (next 3-5 days)

These let someone evaluate Assay without you in the room.

| # | Item | Status | Notes |
|---|------|--------|-------|
| B1 | Implement D12 (pack_root = attestation_sha256) | DONE | Implemented 2026-02-07. Builder + verifier + tests updated |
| B2 | Wire RunCards/claims into CLI `assay proof-pack` | DONE | `--run-card` / `-c` flag, builtin or JSON file. Implemented 2026-02-07 |
| B3 | `assay verify-pack <dir> --require-claim-pass` | DONE | CI gate: exits 1 if claim_check != PASS. Implemented 2026-02-07 |
| B4 | "Same integrity, different claim sets" demo test | DONE | TestOrthogonalAxes: 2 tests proving P1/P2. Implemented 2026-02-07 |
| B5 | Evaluation bundle: quickstart + example + sample pack | DONE | examples/proof_pack_demo.py, examples/sample_pack/. Implemented 2026-02-07 |

**Evaluation bundle spec:**
1. `README_quickstart.md` -- install, run, produce pack, verify, interpret
2. `examples/fastapi_min/` -- tiny app + single RunCard suite
3. "What this proves / what it doesn't" one-pager (explicit threat model + limits)
4. One sample Proof Pack committed as release artifact

### Tier 2: Runner and real workloads (week 4)

| # | Item | Status | Notes |
|---|------|--------|-------|
| B6 | `assay run -- <cmd>` | DONE | Runner wraps command, builds proof pack. Auto-generates key. Implemented 2026-02-07 |
| B7 | `assay pack --format` flag | NOT STARTED | |
| B8 | ASSAY_MODE / ASSAY_OUTPUT_DIR env vars | NOT STARTED | |
| B9 | Blessed FastAPI middleware emitter | NOT STARTED | RequestReceipt, ToolCallReceipt, GuardianVerdictReceipt, ResponseReceipt |
| B10 | Legacy migration path | NOT STARTED | |

### Tier 3: Hardening and contracts (week 5)

| # | Item | Status | Notes |
|---|------|--------|-------|
| B11 | Implement D13 (per-claim versioning) | NOT STARTED | Must ship before packs escape into the wild |
| B12 | Implement D17 (reason codes) | NOT STARTED | |
| B13 | Implement D16 (derived assurance level) | NOT STARTED | |
| B14 | Manifest schema enforcement at runtime | DONE | manifest_schema.py validates at build + verify. 4 tests. Implemented 2026-02-07 |
| B15 | MANIFEST.in fix (sdist leaks 1,497 files) | NOT STARTED | Another Claude was working on this |
| B16 | Rename RunCards pre-release (D4 naming action) | DONE | `policy_binding`->`schema_consistency`, `no_unauthorized_override`->`no_breakglass`. Implemented 2026-02-07 |

### Tier 4: Distribution (week 6+)

| # | Item | Status | Notes |
|---|------|--------|-------|
| B17 | GitHub Action (CI wedge) | NOT STARTED | Only after runner maps to real workloads |
| B18 | PyPI publish (`pip install assay-ai`) | DONE | v1.0.0 published on PyPI |
| B19 | 90-second demo video | NOT STARTED | |
| B20 | LangChain callback integration | NOT STARTED | |

### Phase N: Future (not in v0 scope)

- Differential Proof Pack (D19) -- after runner exists
- Multi-witness co-signing (witness mode)
- Transparency log anchoring (L3)
- Registry indexing
- Semantic/model-evaluated claims (D14 tiers)
- Human-in-the-loop claim signoff
- `--require-keystore-match` flag (D7 pinned trust)
- delta_pack.schema.json + `assay diff` / `assay verify-diff` commands

---

## Part 5: Open Questions

### Q1. Where do receipts come from in a real system?

The Loom/CCIO integration is the Phase 4A bottleneck. Three layers must be explicit:
1. **Instrumentation** (emission): hooks at model call, tool call, Guardian decision boundaries
2. **Assay store** (writer): JSONL receipts with run_id/seq
3. **Assay verifier/bundler** (proof pack): offline evidence

Current state: unclear how tight the CCIO Guardian -> receipt emission path is.
Minimum viable: FastAPI middleware that emits 4 receipt types.

### Q2. How does claim_set_hash evolve across versions?

Per D13, decided on per-claim versioning. But the exact `executed_claims` schema
and verification compatibility rules need spec'd before packs escape into the wild.

### Q3. Error code namespace for claim failures

**Decision**: Claim failures get their own `E_CLAIM_*` namespace.
Never overload structural integrity codes with claim semantics.

Current reserved codes: `E_SIG_INVALID`, `E_CHAIN_BROKEN` -- keep these for
receipt-level signatures only (future). Never let "signature invalid" mean
"claim failed."

### Q4. Discrepancy fingerprint contract alignment

Master plan specifies: `policy_hash + suite_id + failure slices + severities`.
Current v0 implementation: `sorted [{claim_id, passed, expected, actual, severity}]`.

**Decision**: v0 formula is stamped as canonical (see D10). Future formula versions
are explicitly versioned and fingerprints are not comparable across versions.

---

## Part 6: GTM Strategy

### The two doors

| Door | Customer | Pitch | Cycle |
|------|----------|-------|-------|
| **A: AI startups** | Companies selling AI to enterprises | "Pass enterprise security review faster" | Short, technical buyer |
| **B: Enterprises** | Companies auditing their own AI | "Make your agent program defensible" | Long, procurement buyer |

**Recommendation**: Lead with Door A. Same artifact, different story.
Door B is the inevitable expansion but Door A has faster feedback loops.

Door A sells **procurement acceleration artifacts**:
- "Here's a proof pack from *your* tenant window"
- "Here is the exact claim set hash you required"
- "Here's a diff between last week and this week"

Assay as **trust plumbing**, not governance theater.

### Sprint structure (auditor model, not consultant)

Day 1-2: Formalize customer's requirements as a claim set.
Day 3-4: Instrument, run Assay, deliver first proof pack.
Day 5: Walk through pack. Show what passed/failed. Don't tell them how to fix it.
Week 2+: They fix, rerun, compare fingerprints. If claims pass, ship.

**Key insight**: They keep running Assay after you leave.
Sprint teaches them to read packs. Subscription is continuous pack production.

**Deliverable is the proof pack, not remediation advice.**
Consultants get hired once. Auditors get hired quarterly.

### The anti-bullshit demo (90 seconds)

1. Run workload
2. Show integrity PASS
3. Show claim FAIL
4. Show fingerprint
5. Change a policy knob
6. Rerun, show claim PASS
7. Show fingerprint changed

This is the demo that sells without a deck.

---

## Part 7: Current State Snapshot (updated 2026-02-07)

### Test counts

| File | Tests | Category |
|------|-------|----------|
| `test_proof_pack.py` | 97 | Proof Pack builder, claims, audit hardening, strict mode, QA regression |
| `test_bridge.py` | 42 | OpenClaw-style tool policy bridge |
| `test_lockfile.py` | 25 | Lockfile write/load/validate/check + fail-closed + semantic + corpus |
| `test_evidence_pack.py` | 24 | Legacy evidence pack + merkle + export |
| `test_integrations.py` | 22 | Provider integrations (OpenAI, Anthropic, LangChain) |
| `test_openclaw_bridge.py` | 19 | OpenClaw bridge receipts |
| `test_store.py` | 18 | AssayStore receipt emission |
| `test_launch_check.py` | 16 | Launch readiness checks |
| `test_integrity_mutants.py` | 13 | Phase 0 mutant gate + LOC budget |
| `test_health.py` | 9 | Health + grace window |
| `test_guardian.py` | 7 | Guardian dignity enforcement |
| `test_assay_pipeline.py` | 3 | End-to-end CLI pipeline |
| **Total** | **295** | **ALL PASS** |

### Key files

| File | LOC | Purpose |
|------|-----|---------|
| `src/assay/commands.py` | 2,315 | CLI command surface (Typer) |
| `src/assay/integrity.py` | 496 | Core integrity verifier (P3 budget: 500) |
| `src/assay/lockfile.py` | 407 | Verifier lockfile contract |
| `src/assay/proof_pack.py` | 399 | 5-file Proof Pack builder |
| `src/assay/claim_verifier.py` | 336 | Semantic claim verification engine |
| `src/assay/run_cards.py` | 228 | 5 built-in RunCards + JSON loader |
| `src/assay/keystore.py` | 100 | Ed25519 key management |
| `src/assay/manifest_schema.py` | 99 | Runtime manifest schema validation |
| `tests/assay/test_proof_pack.py` | 1,516 | Main test suite |
| `tests/assay/test_lockfile.py` | 355 | Lockfile contract tests |
| `tests/assay/test_integrity_mutants.py` | 259 | Phase 0 gate + LOC budget |

### Constitution compliance

| Principle | Status | Evidence |
|-----------|--------|----------|
| P1. Orthogonal axes | COMPLIANT | Two separate verifiers, tested independently |
| P2. One-way dependency | COMPLIANT | claim_verifier imports nothing from integrity |
| P3. Verifier < 500 LOC | COMPLIANT | 496 LOC, enforced by test |
| P4. Fail closed | COMPLIANT | Severity allowlist + unknown check -> fail + lockfile fail-closed |
| P5. Determinism | COMPLIANT | JCS everywhere, locked test vectors, deterministic corpus |
| P6. Snapshots > deltas | COMPLIANT | DPP is Phase N, not started |
