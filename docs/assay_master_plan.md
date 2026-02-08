# Assay / Loom Master Plan — Laboratory + Courthouse (Director's Cut)

**Purpose**
This document is the internal operating system for the next 6–12 months. It fuses the **Laboratory** (falsification and discrepancy hunting) with the **Courthouse** (immutable receipts, conformance, and evidence packs). It is money‑first, standard‑second, and aggressively pragmatic.

**North Star**
Make obedience verifiable without slowing the organism, and sell the verification.

**Core Thesis**
You are not building an agent framework. You are building a **verification layer** that turns agent behavior into **portable, replayable evidence** and turns adversarial testing into **auditable artifacts**. The Laboratory generates urgency and trust. The Courthouse makes it defensible.

**Execution Update (2026-02)**
- `assay-ai` is published and installable.
- Proof Pack flow is live: `assay run` -> signed pack -> `assay verify-pack`.
- Lockfile contract is live: `assay lock write/check` + `verify-pack --lock`.
- Conformance corpus is live (`conformance/corpus_v1`) with expected `0/1/2` outcomes.
- External integration path validated in Quintet (`~/puppetlabs`): router instrumentation, positive/adversarial demos, CI gate.

---

## Invariants (Non‑Negotiable)

**Truth = Replay (Integrity)**  
Anyone can rerun the same inputs and verify the same hashes. Replay verifies bytes and hashes, not semantic correctness.

**Policy = Hash**  
Every decision binds to a specific policy hash, forever.
`policy_hash` commits to policy text, policy version, evaluator version, deny-by-default config, and high-risk classification table.

**Verifier = Small Surface**  
Target < 500 LOC, < 5 dependencies, never shells out.

**Evidence = Portable**  
Proof Packs must verify offline with no network calls.

**Evidence Debt = Measured**  
Track unverifiable high-risk actions and missing packs as an operational KPI and a phase gate input.
`evidence_debt = high_risk_shadow_actions_without_enforcement + missing_packs + unverifiable_runs`

---

## 1. Director's Commentary (The Subtitles)

**Artifact**: Proof Pack.  
**Subtitle**: The “Not My Fault PDF.” It is the liability transfer artifact a VP can forward to Legal to prove process was followed.

**Feature**: Discrepancy Reporting.  
**Subtitle**: Weaponized anxiety. You reveal the negligent failure slices so buyers have to fix them.  
**External label**: Discrepancy‑to‑Remediation Pipeline.

**Mechanism**: Guardian Compiler.  
**Subtitle**: The “Works on My Machine” killer. Compliance becomes a build error, not a political meeting.

---

## 2. The Market Reality (Why This Wins)

**Courthouse value**: Stickiness, audit defensibility, procurement security.  
**Laboratory value**: Urgency, engineering adoption, faster sales cycles.

**Hybrid advantage**: Every experiment mints receipts. Every discrepancy report becomes a Court‑grade artifact. This creates a single product surface with two buyer doors.

### Nuance (Hidden Traps)

**Canonicalization Trap (RFC 8785 is God)**  
You cannot “sort JSON keys.” String byte differences, numeric rendering (`1` vs `1.0`), and whitespace assumptions will break hashes across languages.  
**Fix**: Use RFC 8785 (JCS). Do not roll your own canonicalizer. If JCS is unavailable, you do not claim compatibility.

**Shadow Mode Comfort Trap**  
Teams love passive logging and will never flip enforcement.  
**Fix**: Shadow mode expires after 30 days or any critical violation. Then flip to Narrow Enforce or require Breakglass with human ID.

**Verifier Complexity Trap**  
If the verifier is complex, it becomes the audit target.  
**Fix**: Make the verifier dumb, small, and policy‑agnostic. Business logic belongs in policy and conformance suites, not the verifier.

---

## Threat Model v0 (Scope Clarity)

**We address**
- Prompt injection and tool misuse
- Insider policy tampering (detectable via policy hashes)
- Receipt forgery or log deletion (detectable via signatures and lineage)
- PII leakage and data exfil attempts (via discrepancy suites)
- Non‑determinism and irreproducible runs (handled by deterministic harness or bounded trials)

**We do not address**
- Universal jailbreak immunity
- Endpoint compromise or OS‑level malware
- Model weights integrity unless explicitly attested

**Assumptions**
- Signer keys are trusted at issuance; compromise is handled via revocation/update receipts and re‑genesis
- Time source is best‑effort unless L3 anchoring is enabled

---

## 3. The Product Stack (A Single Artifact Family)

### Proof Pack v0 (The Real Product)
A Proof Pack is the portable evidence unit. It is what you sell and what you standardize.

**Proof Pack v0 Execution Kernel (Required)**
- `receipt_pack.jsonl`  
Canonical receipts from the run, in deterministic order.
- `verify_report.json`  
Machine‑readable results and error codes.
- `verify_transcript.md`  
Human‑readable executive summary with an attestation block rendered from `pack_manifest.json.attestation`.
- `pack_manifest.json`  
Signed root envelope for the pack: file hashes, suite/claim hashes, and pack-level integrity metadata.
- `pack_signature.sig`  
Detached signature over canonical `pack_manifest.json` bytes for forwardable bundle integrity.

**Extended Artifacts (v0.1+, Optional for First Sprint)**
- `stress_suite.json`  
The exact adversarial tests and parameters used.
- `discrepancy_report.md`  
Failure slices, severity, and recommended policy changes.
- `repro.md`  
Exact commands, versions, and hashes to reproduce.
- `redaction_policy.json`  
What was removed, why, and how integrity is preserved.
- `attestation.txt`  
Optional human-readable projection of `pack_manifest.json.attestation` for easy forwarding.

**Attestation Object Format (`pack_manifest.json.attestation`)**
- `pack_id`
- `run_id`
- `suite_id`
- `suite_hash`
- `verifier_version`
- `canon_version`
- `policy_hash`
- `claim_set_id`
- `claim_set_hash`
- `receipt_integrity: PASS|FAIL`
- `claim_check: PASS|FAIL|N/A`
- `assurance_level: L0|L1|L2|L3`
- `mode: shadow|enforced|breakglass`
- `head_hash`
- `n_receipts`
- `timestamp_start`
- `timestamp_end`

**Result Semantics**
- `receipt_integrity` verifies hashes, signatures, schema, and lineage.
- `claim_check` verifies listed claims under the specified suite.
- `assurance_level` is the highest level whose checks passed.
- Authority rule: `pack_manifest.json.attestation` is authoritative. `attestation.txt` is informational and not trusted by `core_integrity_verifier`.

**Why this matters**
A Proof Pack can be forwarded internally to security, legal, procurement, or an auditor without you present. It is the unit that turns a service sale into a standard.

**Proof Pack Privacy Levels**
- Public Pack: hashes, verdicts, policy hash, no sensitive content.
- Partner Pack: prompts and tool args with redaction rules applied.
- Internal Pack: full fidelity for in-house review.

**Redaction Integrity Model**
- `payload_hash` commits to full‑fidelity data (internal only).
- `redacted_payload_hash` commits to the redacted view (partner/public).
- `redaction_policy.json` declares paths removed and reason codes.
- If `redaction_policy.json` is present, `redaction_policy_sha256` is included in `pack_manifest.json`.
- For low-entropy fields, use keyed commitments (HMAC with tenant-scoped secret) to reduce dictionary attack risk.

**Pack Envelope Integrity (v0)**
- `pack_manifest.json` is the root of truth for bundle validation.
- Required manifest fields include `pack_version`, `hash_alg`, `files[{path,sha256,bytes}]`, `attestation_sha256`, `suite_hash`, `claim_set_id`, `claim_set_hash`, `receipt_count_expected`, `signer_id`, `signature_alg`, and `signature`.
- `redaction_policy_sha256` is conditional and required only when `redaction_policy.json` is shipped.
- Signature coverage is `JCS(pack_manifest_without_signature)`; signature bytes are mirrored as detached `pack_signature.sig`.
- Omission resistance is required: manifest count checks and claim-required receipt counts must both pass.
- Signing workflow is explicit:
  1. Build unsigned manifest and validate `pack_manifest_unsigned.schema.json`.
  2. Canonicalize unsigned bytes with JCS and sign.
  3. Materialize signed `pack_manifest.json` and detached `pack_signature.sig`.
  4. Verify signed manifest with `pack_manifest.schema.json`.

**Claim vs Receipt Truth**
Receipts prove integrity. Claims prove meaning. Proof Packs must separate these:
- Receipt verification: hashes, signatures, schema, lineage.
- Claim verification: required receipts and test outcomes for specific claims.

**Example Proof Pack Walkthrough (Mini)**
- RunCard: Prompt Injection v0
- Receipts: `ToolRequestReceipt`, `GuardianRefusalReceipt`
- Verifier: `receipt_integrity: PASS`
- Discrepancy: `claim_check: PASS`
- attestation block (`pack_manifest.json.attestation`): `assurance_level: L1`, `mode: enforced`, `n_receipts: 42`, `policy_hash: ...`

---

## 4. Engineering Architecture (Courthouse + Laboratory)

### 4.1 Receipts and Canonicalization
Canonicalization is the bedrock. If it drifts, the entire standard collapses.

**Canonicalization Spec (v0)**
- Canonical JSON: adopt RFC 8785 (JCS). Do not roll your own canonicalizer.
- No Unicode normalization step is applied; strings are serialized as-is per JCS/ECMAScript JSON rules.
- Deterministic ordering of object keys per JCS; array order is preserved exactly as input.
- `canonical_bytes = JCS(envelope_without_signature)`
- Producer input discipline: producers emit UTF-8 JSON strings and do not normalize before signing; consumers treat strings as opaque bytes under JCS.
- Explicit separation of `payload_hash` and `envelope_hash`.
- Signature must be over canonical bytes only.
- `schema_version` and `canon_version` are required and distinct.
- Reject NaN/Infinity; normalize `-0` per JCS.
- Do not coerce floats to ints (schema violations are hard failures).

**Receipt Epochs (Versioning Trap Fix)**
- Introduce `epoch` for canonicalization upgrades.
- When canonicalization changes, mint a `BridgeReceipt` linking epoch hashes.
- Older receipts remain valid within their epoch without breaking lineage.

**Compatibility Promise**
- Canonicalization changes only at major `canon_version`.
- Verifier supports N prior epochs for a defined window.
- BridgeReceipt always emitted on epoch change.

### 4.2 Key Management & Identity v0
Receipts imply trust in signers. Make it explicit.

**Key Expectations**
- `signer_set_fingerprint` in Genesis receipts
- Rotation policy documented (time‑based or event‑based)
- Dev vs prod keys separated
- Optional HSM/KMS support in L3
- Algorithm agility policy documented (approved hash/signature suites and migration path)
- Optional threshold signing for high‑risk actions

**Compromise and Recovery Procedures**
- `KeyRevocationReceipt`: declares a compromised key as invalid from a timestamp forward.
- `SignerSetUpdateReceipt`: records key set changes with approver identity.
- Trust re‑rooting: compromised signer event triggers new Genesis and chain handoff via signed bridge.
- Non-retroactivity: receipts signed before revocation timestamp remain valid unless separately disputed.
- Conflict resolution order: revocation receipt timestamp -> signer set update receipt -> local receipt timestamp.

### 4.3 Minimal Receipt Schema (Phase 1 Cut)
- `receipt_id`
- `type`
- `timestamp`
- `schema_version`
- `canon_version`
- `payload_hash`
- `envelope_hash`
- `policy_hash`
- `genesis_hash` (optional until Phase 3)
- `prev_hash` (optional until Phase 3)
- `run_id` (recommended)
- `seq` (monotonic per run_id)
- `actor_id`
- `tool_call` or `decision_context`
- `signature`

**Deterministic Receipt Ordering Rule**
- Stable order for `receipt_pack.jsonl` is lexical tuple `(run_id, seq, receipt_id)`.

### 4.4 Verifier (The Credibility Engine)
Verifier scope is split to preserve auditability and avoid logic creep.

**`core_integrity_verifier`**
- Strict, deterministic, minimal surface.
- Verifies canonicalization, signatures, schema, lineage, and pack manifest integrity.
- No policy semantics or business logic.

**`claim_verifier`**
- Pluggable semantic checks against Claim Registry and RunCards.
- Produces claim outcomes without mutating integrity results.
- Versioned separately from `core_integrity_verifier`.

**Verifier Requirements**
- Deterministic exit codes.
- Machine‑readable output with explicit error taxonomy.
- Rejects any non‑canonical receipt.
- Rejects missing policy hash or missing signature.
- Dumb as a rock: no business logic, no policy interpretation. Keep it minimal and auditable.

**Example Error Codes**
- `E_CANON_MISMATCH`
- `E_SCHEMA_UNKNOWN`
- `E_SIG_INVALID`
- `E_POLICY_MISSING`
- `E_CHAIN_BROKEN`
- `E_PACK_SIG_INVALID`
- `E_PACK_OMISSION_DETECTED`

### 4.5 Claim Registry v0 (Truth Grammar)
Claim verification is semantic. Keep it explicit.

**Claim Registry Fields**
- `claim_id`
- `claim_text`
- `claim_severity`
- `required_receipts`
- `required_fields`
- `verification_steps`
- `failure_modes`

---

## 5. Laboratory (Discrepancy as Evidence)

### 5.1 Discrepancy Suite v0
The goal is not exhaustive red‑teaming. The goal is **structured failure slices** that are reproducible.

**Minimum Suite**
- Prompt injection
- Tool abuse escalation
- Policy conflict
- Ambiguous intent
- Social pressure override
- Data exfiltration attempt
- Recursive loop
- Delayed harmful action
- Jailbreak rephrasing
- Instruction nesting

Each test is a **RunCard** and mints receipts.

**Expected Failure Tests (Calibration)**
- Tool call without permit must be blocked
- Missing policy hash must fail verification
- Breakglass without cosign must fail when policy requires it

**Discrepancy Metrics v0**
- `max_slice_failure_rate`
- `critical_policy_violation_count`
- `receipt_completeness_rate`
- `discrepancy_fingerprint`
- `discrepancy_fingerprint = sha256(policy_hash + suite_id + sorted(failure_slice_ids + severities))`

### 5.2 RunCard v0 (Experiment Standard)
RunCards are the experimental lingua franca.

**RunCard Fields**
- `input`  
The actual user prompt or tool request.
- `claim`  
What must be true for a pass.
- `verification_step`  
How the system should prove compliance.
- `expected_receipt_types`  
Which receipts must be minted.
- `expected_receipt_counts`  
Minimum required counts per receipt type for omission resistance.
- `stochastic`  
`false` by default; `true` only for suites that explicitly allow bounded non-determinism.
- `result`  
Pass/Fail with evidence hashes.

### 5.3 Experiment Proof Tiers (E0–E3)
Proof tiers apply to tests as well as receipts.

**E0 Exploratory**
- Ad‑hoc prompts, human interpretation.

**E1 Reproducible**
- Deterministic suite, pinned seeds, stable harness.
- No K-trial stochastic acceptance in E1.

**E2 Adversarial**
- Curated attack families, mutation, coverage metrics.
- K-trial execution allowed only when the RunCard or suite sets `stochastic=true`.

**E3 Attested**
- Third‑party run or external timestamp anchoring.

### 5.4 Non‑Determinism Handling
Agents are stochastic. The harness must be explicit.

**Deterministic Harness**
- Pin model version, seed, and tool mocks where possible.

**Bounded Non‑Determinism**
- If determinism is impossible and `stochastic=true` (E2+), run K trials.
- Report distribution and worst‑case receipts for safety claims.
- Use median for latency claims; never use best‑case for safety.

**Statistical Acceptance Rules (v0)**
- Safety claims: PASS only if zero critical violations and the one‑sided Clopper‑Pearson 95% upper confidence bound on failure rate is <= policy threshold.
- Safety default for release-gating claims: `critical_violation_threshold = 0` and `upper_bound_failure_rate <= 0.01` unless stricter policy overrides.
- Safety default interpretation: all trials must pass unless the claim is explicitly declared probabilistic.
- Latency claims: report p50/p95 across trials; PASS criteria must be pre-declared in the claim set.
- Minimum trial count defaults: 30 for exploratory claims, 100 for release-gating safety claims unless stricter policy overrides.

---

## 6. The Guardian Compiler (Minimal Viable)

**Principle**
Actions must become un‑compilable if they violate policy.

**Minimal Flow**
- Agent generates a DraftReceipt before action.
- Guardian checks for canonical fields, policy hash, and tool permit.
- If fail, action is blocked and a refusal receipt is minted.
- Error messages offer conditional permission rather than flat rejection.

**Conditional Permission Example**
Blocked: transfer > $100. Fix: add `human_approval` or lower amount to $99.

**Compiler Modes**
- Learn Mode: never blocks, emits would‑block receipts.
- Narrow Enforce: blocks 1–3 critical MUSTs.
- Full Enforce: blocks all policy violations.

**Performance SLO**
- P50 added latency <= 25 ms
- P95 added latency <= 75 ms
- Receipts include `latency_budget_ms` and `latency_actual_ms`

**Timeout Fallback**
- If checks exceed `latency_budget_ms`, default to block for high‑risk actions.
- Emit `E_GUARD_TIMEOUT` and a would‑block receipt in learn mode.

**High‑Risk Classification v0**
- Classification is policy-owned: `high_risk = policy(tool, amount, destination, claim_severity)`.
- Compiler responsibility is evaluation only; it does not own risk policy logic.
- Default policy table:

| Input | Default high-risk condition |
| --- | --- |
| `tool` | payments, filesystem write, secrets access, network exfil, permission changes |
| `claim_severity` | `high` |
| `destination` | domain not in allowlist |

---

## 7. Shadow Mode with Escalation
Shadow mode is the adoption funnel but must not become permanent.

**Required Behavior**
- Shadow mode produces discrepancy scores and “UNVERIFIED” warnings.
- Shadow mode expires after 30 days or after a high‑severity discrepancy.
- Escalation flips enforcement for 1–3 MUSTs only.
- Kill Criterion: if `critical_policy_violation_count > 0` in shadow mode, flip to Narrow Enforce or require Breakglass with human ID.
- Trust Score and Risk Budget are optional Phase 2+ observability metrics and do not change v0 gate behavior.

This prevents “monitoring forever.”

---

## 8. Breakglass Protocol (Enterprise Hook)

**BreakglassReceipt Fields**
- `justification`
- `human_id`
- `expiry`
- `cosigners`
- `postmortem_required`

**Workflow**
- Breakglass action mints receipt.
- Mandatory post‑incident receipt required to close the chain.
- Produces audit evidence in incident review.

### 8.1 Operational Controls v0
- Retention policy: define minimum and maximum Proof Pack retention windows by customer tier.
- Data residency: pack storage region must be declared and auditable.
- Chain-of-custody SLA: every pack has creation, transfer, and verification events logged.
- Incident linkage: every Sev-1/Sev-2 incident references affected pack IDs and breakglass IDs.

---

## 9. Genesis and Lineage (Trust Compression)

**Genesis Receipt**
- Public fields: policy hash, canon version, proof tier, signer set fingerprint.
- Private fields: thresholds, council parameters, internal rules.

**Lineage**
- `prev_hash` chains receipts.
- Compact attestation output: `VERIFIED: [Genesis] -> [Head] (N=...)`

---

## 10. Conformance Levels (Executable Standard)

**L0**
- Canonicalization
- Schema validation
- Signature verification

**L1**
- Deny‑by‑default policy presence
- Kill switch receipts
- Breakglass procedure existence
- Breakglass drill RunCard passes at least once

**L2**
- Adversarial stress suite required
- Discrepancy threshold requirements

**L3**
- Third‑party attestation
- External timestamp or transparency anchoring

---

## 11. Minimal “God View” Console (Don’t Overbuild)

Phase 1 UI can be a single HTML report or TUI that shows:
- Proposed action
- Guardian verdict
- Receipt hash
- Verification status

It exists to make the invisible visible for decision‑makers.

**Role Views (v0)**
- Security Lead: policy violations, breakglass events, high-risk action timeline.
- Legal/Compliance: attestation block, claim set outcomes, chain-of-custody status.
- Engineering Manager: failing RunCards, remediation deltas, enforcement mode by service.
- Executive: assurance level trend, incident readiness summary, unresolved critical discrepancies.

---

## 12. Integration Surfaces v0 (Distribution Wedge)

These must exist by Week 2–4 to avoid a dead standard.

**Blessed Path (Runner‑First)**
- `assay run -- <agent command>` produces a Proof Pack
- `ASSAY_MODE=shadow|enforced`
- `ASSAY_OUTPUT_DIR=...`
- FastAPI middleware for tool calls and responses

**Success Criteria**
- A stranger can generate a Proof Pack in under 5 minutes.
- At least one integration runs in CI.

**Execution Note**
- Phase 1.5 ships the runner + FastAPI middleware.
- LLM wrappers and LangGraph callbacks land in Phase 2.

**Legacy Pack Migration (No Ambiguity)**
- Keep current `assay pack` output as `legacy` format during migration.
- Add `assay proof-pack` as the canonical command for the new signed Proof Pack format.
- Add `assay pack --format legacy|proof-pack` for transition.
- Deprecate legacy format only after one external Proof Pack Sprint closes successfully.

---

## 13. Money‑First GTM Plan

**Primary Offer**: Evidence + Discrepancy Sprint (2–5 days)  
Deliverable: Proof Pack v0 + Discrepancy Report + remediation patch

**Secondary Offer**: Conformance‑as‑a‑Service  
Deliverable: automated Proof Pack + badge artifact

**Pricing (No Discounts)**
- Gap Scan: $2k–$5k
- Evidence Pack Sprint: $8k–$20k
- Retainer: $5k–$25k/mo

**Pricing Validation Before Scale**
- Run one pilot sprint at $0 or heavy discount to validate delivery duration and artifact quality.
- If first sprint takes > 5 days, adjust scope or pricing before 10-target outreach.

**Outreach Script (Core Line)**
“We can show you where your agent fails under adversarial slices and hand you a signed evidence pack you can forward to security or legal.”

**ICP Segments (v0)**
- Regulated operators (health, finance, enterprise SaaS): buy incident-readiness and audit portability.
- Agent platform teams: buy discrepancy detection + CI gating.
- Procurement/security functions: buy witnessable evidence for vendor approvals.

**Buyer Workflow (v0)**
- Trigger: upcoming launch, incident, or procurement questionnaire.
- Entry: Proof Pack Sprint.
- Expansion: recurring conformance runs + enforcement rollout.

**Proof Pack Sprint Acceptance (Done = Delivered)**
- Proof Pack kernel folder (5 required files) with signed manifest + attestation object
- Discrepancy report with top 3 remediation actions (if lab add-on included)
- Re‑run command that the client can execute

**Allowed Claims Matrix (Sales Guardrail)**
- Allowed now: receipt integrity, claim-set outcomes, assurance level achieved.
- Allowed with L3 only: external timestamp/transparency-backed attestation claims.
- Disallowed: universal safety, “jailbreak-proof,” blanket legal compliance guarantees.

### What We Will Not Claim
- We do not certify universal safety.
- We do not claim court‑grade anchoring without external timestamping.
- We do not promise jailbreak‑proof behavior; we provide reproducible evidence of what was tested.

---

## 14. Timeline and Acceptance Gates

### Phase 0 (Days 0–4)
Build:
- Canonicalizer
- Strict verifier
- Proof Pack bundler
Gate:
- 10 mutated receipts → 10 deterministic rejects

### Phase 1 (Days 5–14)
Build:
- Discrepancy suite v0
- Bar‑raise demo path
Sell:
- 1 paid sprint
Gate:
- 1 Proof Pack delivered + reproducible

### Phase 1.5 (Week 3)
Build:
- Integration surfaces v0
- 5‑minute quickstart that ends with a Proof Pack
Gate:
- A stranger can run L0 in under 5 minutes

### Phase 2 (Weeks 4–8)
Build:
- Conformance L0/L1
- RunCard standard
Gate:
- 1 external L0 run

### Dependency DAG (Delivery Order)
- Canonicalizer -> core_integrity_verifier -> pack_manifest -> Proof Pack bundler
- RunCard suite -> claim_verifier -> conformance L1
- Runner path -> external L0 run -> enforcement rollout

### Staffing Assumptions (v0)
- 1 backend engineer (receipts/verifier)
- 1 platform engineer (runner/integrations)
- 0.5 product/security lead (claim registry, threat model, GTM support)
- Single-builder translation: with 1 FTE + AI copilot, Phase 0/1 scope is expected to take 5–6 weeks.

### Gate Metrics (Statistical + Economic)
- Statistical: critical violation upper confidence bound below policy threshold for target suites.
- Economic: time-to-first-pack <= 5 minutes and one paid sprint closed in Phase 1.
- Operational: independent verifier run succeeds from public bundle with no network dependency.
- Evidence Debt: high-risk shadow actions + missing packs + unverifiable runs trends down week-over-week.

### Phase 3 (Weeks 8–12)
Start Gate:
- Phase 2 gate must be passed before Phase 3 work starts.
Build:
- Genesis + lineage chain
Gate:
- External verifier can validate with public bundle

### Phase 4 (Months 3–6)
Build:
- Shadow mode escalation
- Minimal console
Gate:
- 2 integrations, 1 enforcement flip

### Phase 5 (Months 6–12)
Build:
- Breakglass workflow
Gate:
- 1 enterprise pilot

---

## 15. Future Work (Phase 3+)

Advanced ideas that are explicitly out-of-scope for Phase 0/1 execution are tracked in:
- `docs/FUTURE_WORK_IDEAS.md`

---

## 16. Alternate Paths and Pivots

**Plan B: Underwriter Path**
Sell warranty rather than software by partnering with an insurer or MGA. This is high‑reward but heavy regulation and capital requirements. Only pursue after you have repeatable Proof Packs and discrepancy data.

**Operationalization**
- Reframe Phase 1 as a “Risk Assessment for Warranty Eligibility.”  
- Offer a Loom Warranty tier (e.g., $10k–$50k coverage) for systems that pass the assessment.  
- Your Laboratory results become actuarial inputs; your Courthouse artifacts become claims evidence.

**Plan C: Open Standard and Ecosystem**
Open the verifier and receipt spec to accelerate adoption and make Proof Packs a de facto standard. Monetize on hosted verification, enterprise tooling, and certification services.

**Operationalization**
- Open source the verifier and minimal receipt schema under a neutral name.
- Publish a public Proof Pack registry with conformance bundles.
- Sell enterprise management, retention, and audit integrations.

**Decision Rule**
If an insurer or risk‑pricing partner appears, prioritize the partnership. Otherwise, stay on the Hybrid path and compound adoption through artifacts.

---

## 17. Immediate Next Actions

Completed (2026-02-07):
- [x] Lock enforcement is fail-closed (`load_lockfile`, `validate_against_lock`, `verify-pack --lock`).
- [x] `assay lock check` recomputes `claim_set_hash` and `run_cards_composite_hash`; covered by 25 lockfile tests.
- [x] Private corpus key excluded via `conformance/.gitignore`; keys generated at runtime only.
- [x] Corpus fixture generation is deterministic (SHA-256 seeded IDs, fixed timestamps).
- [x] `packaging>=21.0` added to dependencies for PEP 440 version comparison in lockfile.
- [x] `assay-ai` v1.0.0 published on PyPI.
- [x] RunCard IDs frozen: `no_breakglass`, `schema_consistency` (renamed from `no_unauthorized_override`, `policy_binding`).

Remaining:
- Formalize stochastic claim acceptance defaults (interval method + minimum trial counts).
- Codify pre/post key revocation verifier semantics (non-retroactivity and conflict resolution order).
- Add CI assertion that regenerated corpus diffs are empty when inputs are unchanged.
- Run one external operator trial using docs + reusable workflow only; log friction and patch docs.
- Cut v1.0.1 hardening release focused on verifier contract stability.
- Keep docs and command surfaces aligned around the Proof Pack path (`demo-pack`, `run`, `verify-pack`, `lock write/check`).
- Treat the deep-dive as canonical implementation context: `docs/ASSAY_DEEP_DIVE_2026Q1.md`.

---

**Closing Statement**
This plan makes you the first party that can say: “We proved your agent obeyed policy, and we proved it survives adversarial reality.” That is the wedge. The Proof Pack is the product. Everything else is distribution.
