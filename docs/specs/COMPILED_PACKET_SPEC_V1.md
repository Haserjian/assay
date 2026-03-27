# Compiled Packet Specification v1

**Date**: 2026-03-26
**Status**: DRAFT — design specification, not yet implemented.
**Depends on**: Pack Contract v0 (PACK_CONTRACT.md), VendorQ schemas v1

---

## Motivation

Proof packs are execution evidence. They prove what happened. They do not answer a reviewer's question.

A compiled packet is a reviewer-facing artifact that binds questionnaire items to specific claims backed by specific proof material. It is the transformation layer between proof-shaped evidence and review-shaped evidence.

**Wedge sentence**: Assay's near-term wedge is a reviewer-ready evidence packet flow that ingests one questionnaire, binds answers to claims backed by proof packs, compiles a portable packet, and enables offline verification by the reviewer.

**Core invariant**: Proof packs remain the evidentiary substrate. Compiled packets are derived, review-shaped containers with explicit claim bindings. A compiled packet references and binds proof packs — it does not replace or swallow them.

---

## 1. Artifact Model

### 1.1 Proof Pack (existing, unchanged)

The trust root. Contains execution evidence, receipts, and signatures. Defined by PACK_CONTRACT.md. A compiled packet MUST NOT modify, repackage, or re-sign proof packs.

### 1.2 Claim Binding (new primitive)

A machine-readable record that maps a single questionnaire item to zero or more evidence references from proof packs.

**In v1, claim bindings are explicit authored artifacts validated by the compiler, not inferred truths discovered by the system.**

```json
{
  "binding_id": "bind_20260326T143000_a8f3e2c1",
  "questionnaire_item_id": "SEC-3.2",
  "claim_type": "TECH_CONTROL",
  "binding_status": "SUPPORTED",
  "evidence_basis": "MACHINE",
  "evidence_refs": [
    {
      "pack_id": "pack_20260325_f1a2b3c4",
      "pack_root_sha256": "a1b2c3d4...",
      "receipt_id": "r_001",
      "evidence_kind": "RECEIPT",
      "target": {
        "path": "receipt_pack.jsonl",
        "pointer": ""
      },
      "span_hash": "e5f6a7b8...",
      "field_path": "",
      "time_authority": "local_clock",
      "evidence_timestamp": "2026-03-25T14:30:00Z"
    }
  ],
  "answer_summary": "Encryption at rest enforced via AES-256-GCM. Evidence from model evaluation receipts covering storage layer.",
  "scope_notes": "Applies to primary data store only. Backup encryption covered separately under SEC-3.3.",
  "freshness_anchor": "2026-03-25T14:30:00Z",
  "missing_evidence": []
}
```

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `binding_id` | string | yes | Unique identifier. Format: `bind_{ISO8601compact}_{uuid8}` |
| `questionnaire_item_id` | string | yes | References a specific item in the questionnaire |
| `claim_type` | enum | yes | One of: `CERTIFICATION`, `PROCESS`, `TECH_CONTROL`, `INCIDENT`, `METRIC`, `COMMITMENT`, `LEGAL` (matches VendorQ v1) |
| `binding_status` | enum | yes | Disposition of this binding — see §1.2.1 |
| `evidence_basis` | enum | yes | What kind of evidence supports this binding — see §1.2.2 |
| `evidence_refs` | array | yes | Zero or more evidence references. Schema extends `vendorq.evidence_ref.v1` with required `pack_root_sha256` |
| `answer_summary` | string | yes | Human-readable answer text. May be empty string for `NON_CLAIM` status |
| `scope_notes` | string | yes | Declares what this binding covers and explicitly does not cover. May be empty string |
| `freshness_anchor` | string (ISO 8601) | **provisional** | Timestamp of the most recent evidence referenced. Semantics TBD pending first proof loop |
| `missing_evidence` | array of string | yes | Explicitly names evidence that would strengthen or complete this binding |

`confidence` was considered and cut from v1. Numeric confidence on a binding is fake precision without a mechanistic definition of what is being measured (mapping certainty? evidence completeness? freshness quality?). If needed later, it must be defined mechanistically, not as a free-floating 0–1 number.

#### 1.2.1 Binding Status (disposition)

What is the operator's assertion about this questionnaire item?

| Status | Meaning | Example |
|--------|---------|---------|
| `SUPPORTED` | Claim is backed by evidence from referenced proof packs | "Yes, we encrypt at rest. See pack evidence." |
| `PARTIAL` | Some evidence exists but coverage is incomplete. `missing_evidence` MUST be non-empty | "We encrypt primary stores. Backup encryption evidence pending." |
| `UNSUPPORTED` | No evidence found. Binding exists to declare the gap explicitly | "We cannot currently demonstrate this." |
| `OUT_OF_SCOPE` | Questionnaire item does not apply to the assessed system | "We do not process PII, so GDPR data subject access does not apply." |
| `NON_CLAIM` | Item acknowledged but intentionally not claimed | "We do not offer SLA guarantees for this tier." |

#### 1.2.2 Evidence Basis (what supports the binding)

Orthogonal to status. A `SUPPORTED` binding might have `MIXED` basis (some machine evidence, some human attestation). An `UNSUPPORTED` binding has `NONE`.

| Basis | Meaning | Example |
|-------|---------|---------|
| `MACHINE` | All evidence is machine-verifiable from proof packs | Receipts from automated test runs |
| `HUMAN` | All evidence is human-attested with no machine-verifiable backing | "Our CISO confirmed this in writing" |
| `MIXED` | Some machine evidence, some human attestation | Automated scan results + manual pen test report |
| `NONE` | No evidence of any kind. Used with `UNSUPPORTED` or `NON_CLAIM` | Gap declaration |

**Constraint**: `evidence_basis` MUST be consistent with `evidence_refs`:
- `MACHINE` or `MIXED` → `evidence_refs` MUST be non-empty
- `NONE` → `evidence_refs` MUST be empty
- `HUMAN` → `evidence_refs` MAY be empty (human attestation may not have a pack reference) or MAY reference a pack containing the attestation record

**Fail-closed rule**: If a questionnaire item has no binding, the packet is incomplete. The coverage report (§1.3) MUST flag unbound items.

#### 1.2.3 Binding Authorship Model (v1)

Claim bindings are **operator-authored or transform-authored artifacts**. The compiler validates them; it does not infer them.

**Authorship modes** (v1 supports all three):

1. **Manual authorship**: Operator writes `claim_bindings.jsonl` by hand or with tooling assistance. The compiler validates schema, evidence references, and status/basis consistency. This is the most honest mode and the expected starting point.

2. **Transform from VendorQ answers**: If the operator has already run VendorQ and has a `vendorq.answer.v1` artifact, the compiler can transform those answers into claim bindings mechanically. The mapping is 1:1 and deterministic — each VendorQ answer becomes one claim binding. The operator reviews and approves the result before signing.

3. **Stub generation**: For any questionnaire item without a binding, the compiler generates an `UNSUPPORTED` / `NONE` stub. This makes coverage gaps explicit rather than silent.

**What the compiler does NOT do**:
- Infer which receipts answer which questions
- Judge whether evidence is sufficient
- Auto-promote `UNSUPPORTED` to `PARTIAL` or `SUPPORTED`
- Generate `answer_summary` text from evidence content

The compiler is a **validator and packager**, not an inference engine. Binding judgment is the operator's responsibility, subject to reviewer scrutiny.

#### 1.2.4 Evidence Reference Extension

Claim binding evidence refs extend the existing `vendorq.evidence_ref.v1` schema with one additional required field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pack_root_sha256` | string (hex64) | yes | The `pack_root_sha256` from the referenced pack's manifest. Enables verification without resolving pack_id |

This is the binding's cryptographic anchor to the proof pack. A verifier can confirm that the referenced pack has this root hash without needing to know where the pack lives.

### 1.3 Compiled Packet (new artifact)

A portable, canonical, reviewer-facing artifact that binds questionnaire items to specific claims and supporting proof material.

#### Layout

```
packet_dir/
  packet_manifest.json       # Signed root envelope
  packet_signature.sig       # Detached Ed25519 signature (raw bytes)
  claim_bindings.jsonl       # One claim binding per line, JCS-canonical
  questionnaire_import.json  # Imported questionnaire structure
  coverage_report.json       # Coverage analysis, non-claims, gaps
  packs/                     # Bundled proof packs (when portable)
    pack_20260325_f1a2b3c4/
      receipt_pack.jsonl
      pack_manifest.json
      pack_signature.sig
      verify_report.json
      verify_transcript.md
    pack_20260325_d5e6f7a8/
      ...
```

#### Kernel Files (required)

| File | Description |
|------|-------------|
| `packet_manifest.json` | Signed root envelope with pack references, binding hash, questionnaire hash |
| `packet_signature.sig` | Detached Ed25519 signature (raw bytes, same convention as proof packs) |
| `claim_bindings.jsonl` | One JCS-canonical claim binding per line, sorted by `questionnaire_item_id` |
| `questionnaire_import.json` | The questionnaire structure this packet responds to |
| `coverage_report.json` | Machine-readable coverage analysis |

#### Optional Content

| Path | Description |
|------|-------------|
| `packs/` | Bundled proof packs for offline handoff. Presence is declared in manifest |

#### Modes

**Referenced mode**: Packet manifest lists pack references by `pack_id` + `pack_root_sha256`. Packs are not bundled. Suitable when reviewer has access to the same pack store.

**Bundled mode**: Packs are copied into `packs/` directory. Manifest declares bundled packs with file hashes. This is the portable handoff artifact — one directory (or zip) contains everything needed for offline verification.

A compiled packet MUST be valid in exactly one mode. The manifest declares which mode via `bundle_mode`.

### 1.4 Packet Verification Result (new artifact)

The independent verifier's output after checking a compiled packet.

```json
{
  "schema_version": "packet_verification.v1",
  "packet_id": "pkt_20260326_b1c2d3e4",
  "packet_root_sha256": "...",
  "verified_at": "2026-03-26T15:00:00Z",
  "verifier_id": "assay-verify-ts@0.2.0",
  "verdict": "PARTIAL",
  "packet_integrity": {
    "manifest_valid": true,
    "signature_valid": true,
    "bindings_hash_valid": true,
    "questionnaire_hash_valid": true,
    "coverage_hash_valid": true
  },
  "pack_results": [
    {
      "pack_id": "pack_20260325_f1a2b3c4",
      "pack_root_sha256": "a1b2c3d4...",
      "pack_present": true,
      "pack_integrity": "PASS",
      "errors": []
    },
    {
      "pack_id": "pack_20260325_d5e6f7a8",
      "pack_root_sha256": "...",
      "pack_present": false,
      "pack_integrity": "MISSING",
      "errors": ["Referenced pack not found in bundle"]
    }
  ],
  "binding_results": {
    "total": 25,
    "valid_refs": 22,
    "invalid_refs": 0,
    "missing_pack_refs": 3,
    "stale_refs": 0
  },
  "coverage": {
    "total_items": 30,
    "bound_items": 25,
    "supported": 18,
    "partial": 4,
    "human_basis": 2,
    "unsupported": 1,
    "out_of_scope": 3,
    "non_claim": 2,
    "unbound": 5
  },
  "warnings": [
    "3 claim bindings reference packs not present in bundle",
    "5 questionnaire items have no binding"
  ],
  "errors": []
}
```

#### Verdict Values

| Verdict | Meaning |
|---------|---------|
| `PASS` | Packet intact, all referenced packs valid, all bindings structurally sound |
| `PARTIAL` | Packet intact but some packs missing, some bindings unresolvable, or coverage gaps |
| `TAMPERED` | Packet integrity check failed (hash mismatch, signature invalid, structural invariant broken) |
| `STALE` | Packet intact but evidence freshness exceeds policy threshold |
| `INVALID` | Packet is structurally malformed (cannot be verified at all) |

**Fail-closed**: Any verification error that cannot be classified → `INVALID`.

---

## 2. Trust Boundary

### 2.1 What Is Signed Where

| Artifact | Signed By | Signature Covers |
|----------|-----------|-----------------|
| Proof pack | Pack signer (existing) | `JCS(manifest − {signature, pack_root_sha256})` |
| Compiled packet | Packet compiler | `JCS(packet_manifest − {signature, packet_root_sha256})` |

The packet signature covers the packet manifest, which includes hashes of all kernel files and references to all proof packs. This creates a single signature that transitively covers the entire evidence chain.

**The packet signer and pack signer MAY be different entities.** The packet compiler attests to the compilation (binding correctness, coverage completeness). The pack signer attests to the execution evidence. These are different trust claims.

### 2.2 What Is Canonicalized Where

| Content | Canonicalization | Rule |
|---------|-----------------|------|
| `claim_bindings.jsonl` | JCS per line (Layer 1) | Same as `receipt_pack.jsonl` — one canonical JSON per line |
| `packet_manifest.json` | Stored pretty-printed, signed over JCS | Same convention as `pack_manifest.json` |
| `questionnaire_import.json` | JCS-canonical | Ensures deterministic hashing regardless of source formatting |
| `coverage_report.json` | JCS-canonical | Ensures deterministic hashing |

### 2.3 Derived vs Source Evidence

| Artifact | Classification | Trust Implication |
|----------|---------------|-------------------|
| Proof pack | **Source evidence** | Trust root. Independently verifiable. Not derived from anything in the packet |
| Claim bindings | **Derived** | Created by the compiler. Claims that specific evidence supports specific questions. Verifiable for structural integrity but the mapping judgment is the compiler's |
| Coverage report | **Derived** | Computed from bindings and questionnaire. Fully deterministic given inputs |
| Questionnaire import | **External input** | Not created by Assay. Integrity-protected by hash in manifest, but content is the reviewer's/framework's |
| Verification result | **Independent output** | Created by the verifier, not the compiler. The reviewer's trust artifact |

**Key distinction**: A verifier can confirm that claim bindings are structurally valid and that referenced evidence exists and is intact. A verifier CANNOT confirm that the binding judgment is correct — that "this receipt actually answers this question" is the compiler's claim, subject to human review.

---

## 3. Verification Semantics

### 3.1 Packet Verification Steps

**Mechanical verification** (what a verifier MUST check):

1. **Manifest schema validation** — packet_manifest.json conforms to schema
2. **File hash verification** — SHA-256 of each kernel file matches manifest
3. **Signature verification** — Ed25519 signature over `JCS(unsigned_manifest)` is valid
4. **Detached signature parity** — `packet_signature.sig` matches manifest signature
5. **Packet root invariant** — `packet_root_sha256` matches recomputed root over questionnaire hash + bindings hash + pack reference hashes (see §7)
6. **Questionnaire hash** — `SHA256(JCS(questionnaire_import.json))` matches manifest
7. **Bindings hash** — `SHA256(claim_bindings.jsonl bytes)` matches manifest
8. **Coverage hash** — `SHA256(coverage_report.json bytes)` matches manifest
9. **Pack reference validation** — for each referenced pack:
   a. If bundled: verify pack integrity (full pack verification per PACK_CONTRACT.md)
   b. If referenced-only: record as unresolvable (not an error, but a coverage gap)
10. **Binding reference validation** — each `evidence_ref` in each binding:
    a. `pack_id` + `pack_root_sha256` matches a declared pack reference
    b. `receipt_id` exists in the referenced pack (if pack is present)
    c. `span_hash` matches (if pack is present and receipt is resolvable)
11. **Coverage completeness** — every questionnaire item has a binding or is flagged unbound
12. **(Optional) Freshness** — `freshness_anchor` of bindings within policy threshold

### 3.2 Verdict Determination

```
if manifest_invalid or schema_error:       → INVALID
if signature_invalid or hash_mismatch:     → TAMPERED
if all_packs_valid and all_refs_valid:
  if freshness_exceeded:                   → STALE
  if full_coverage:                        → PASS
  else:                                    → PARTIAL
if some_packs_missing or some_refs_broken: → PARTIAL
```

### 3.3 Error Codes (packet-level)

| Code | Fault Class | Meaning |
|------|-------------|---------|
| `E_PKT_SCHEMA` | schema_violation | Manifest or kernel file malformed |
| `E_PKT_TAMPER` | file_integrity_violation | File hash does not match manifest |
| `E_PKT_SIG_INVALID` | signature_authenticity_failure | Packet signature invalid |
| `E_PKT_ROOT_INVARIANT` | structural_invariant_violation | Packet root hash mismatch |
| `E_PKT_PACK_MISSING` | reference_gap | Referenced pack not present in bundle |
| `E_PKT_PACK_INVALID` | nested_integrity_failure | Bundled pack fails its own verification |
| `E_PKT_REF_BROKEN` | reference_gap | Binding references a receipt/pack that doesn't exist |
| `E_PKT_REF_MISMATCH` | reference_integrity_failure | `pack_root_sha256` in binding doesn't match pack |
| `E_PKT_COVERAGE_GAP` | coverage_violation | Questionnaire item has no binding (warning, not error) |
| `E_PKT_STALE` | temporal_violation | Evidence freshness exceeds threshold |

---

## 4. V1 Scope Cuts

### In scope

- One questionnaire format: VendorQ `vendorq.question.v1` schema
- One packet schema: `compiled_packet.v1`
- One claim binding schema: `claim_binding.v1`
- Bundled mode for offline handoff (directory or zip)
- Referenced mode for same-store scenarios
- Ed25519 signing (same key infrastructure as proof packs)
- JCS canonicalization (same profile as proof packs)
- Python CLI: `assay packet compile` and `assay packet verify`
- TypeScript verification: `assay-verify-ts` extended to verify packets

### Out of scope (v1)

- **No hosted reviewer portal.** The artifact is the interface.
- **No dynamic evidence fetching.** All evidence is bundled or pre-resolved.
- **No arbitrary questionnaire formats.** VendorQ v1 only.
- **No questionnaire intelligence.** No auto-mapping, no NLP, no "smart" binding.
- **No multi-party signing.** One compiler, one signature.
- **No incremental updates.** A new packet replaces the old one entirely.
- **No redaction.** If evidence cannot be shared, v1 does not support redaction. The binding must instead be expressed as a human-supported claim with no shared machine evidence (`evidence_basis: HUMAN`), or as an explicit non-claim or out-of-scope declaration (`binding_status: NON_CLAIM` / `OUT_OF_SCOPE`), whichever is truthful. These are not interchangeable escape hatches — status and basis are orthogonal axes.
- **No custom ontologies.** Claim types are the existing VendorQ enum.

### Explicit non-goals

- The compiled packet is not a dashboard export
- The compiled packet is not a PDF report
- The compiled packet is not a "trust score"
- The compiler does not judge whether evidence is *good enough* — it binds and reports coverage

---

## 5. CLI Target

### Compile

The compile step has two phases: **authoring** (operator labor) and **packaging** (one command).

#### Phase 1: Authoring (operator does this)

The operator prepares claim bindings before compilation. This is the real work — deciding what evidence answers what questions.

```bash
# Option A: Transform from existing VendorQ answers
assay packet init \
  --questionnaire vendor_security_review.json \
  --answers vendorq_answers.json \
  --packs ./evidence/pack_001 ./evidence/pack_002 \
  --output ./review_packet_draft/

# This produces a draft claim_bindings.jsonl that the operator reviews and edits.
# UNSUPPORTED stubs are generated for any questionnaire items not covered by answers.

# Option B: Start from scratch
assay packet init \
  --questionnaire vendor_security_review.json \
  --packs ./evidence/pack_001 ./evidence/pack_002 \
  --output ./review_packet_draft/

# This produces all-UNSUPPORTED stubs. Operator authors bindings manually.
```

The operator edits `review_packet_draft/claim_bindings.jsonl` until satisfied. This is where judgment lives.

#### Phase 2: Packaging (one command)

```bash
# Validate, canonicalize, sign, and package
assay packet compile \
  --draft ./review_packet_draft/ \
  --output ./review_packet/ \
  --bundle                    # include packs in output (default: referenced)
  --signer assay-local        # signing key (default: assay-local)
```

**What this does**:
1. Load questionnaire (validate against `vendorq.question.v1`)
2. Load proof packs (validate each against PACK_CONTRACT.md)
3. Validate claim bindings (schema, evidence refs, status/basis consistency)
4. Reject if any evidence refs point to non-existent packs or receipts
5. Compute coverage report
6. Canonicalize all kernel files
7. Build and sign packet manifest
8. Write packet directory

**One command to package. But the operator did the hard work first.**

The split is intentional: `init` scaffolds, the operator authors, `compile` validates and signs. The signature means "I, the compiler operator, attest that these bindings represent my review mapping." That is a human act, not an automated inference.

### Verify

```bash
# Verify a compiled packet (offline, no network)
assay packet verify ./review_packet/

# Machine-readable output
assay packet verify ./review_packet/ --format json
```

**What this does**:
1. Verify packet integrity (steps 1-8 from §3.1)
2. Verify bundled packs (step 9)
3. Validate binding references (step 10)
4. Check coverage completeness (step 11)
5. Emit verification result (§1.4)

**One command. Independent verification.**

### TypeScript (reviewer side)

```bash
# Reviewer verifies with independent tooling
npx assay-verify-ts verify-packet ./review_packet/
```

Same verification, different implementation, different trust boundary. The reviewer runs *their* verifier, not yours.

---

## 6. First Proof Loop

### Goal

End-to-end: create one real compiled packet, hand it off, verify it on a separate machine, collect objections, tighten schema.

### Steps

1. **Create packet from one real questionnaire**
   - Use an existing VendorQ questionnaire (e.g., the demo security review)
   - Use existing proof packs from `examples/vendorq/demo_pack/` or generate fresh
   - Run `assay packet compile` → produces `review_packet/`

2. **Verify locally**
   - Run `assay packet verify ./review_packet/` → `PASS`
   - Run `npx assay-verify-ts verify-packet ./review_packet/` → `PASS`
   - Both verifiers agree on verdict

3. **Hand to reviewer (separate machine)**
   - Zip the bundled packet directory
   - Transfer to a machine that has never seen the signing key or proof packs
   - Install `assay-verify-ts` from npm
   - Run `npx assay-verify-ts verify-packet ./review_packet/`
   - Confirm: verification succeeds with embedded public key (self-contained)

4. **Tamper test**
   - Modify one receipt in a bundled pack → re-verify → `TAMPERED`
   - Remove a bundled pack → re-verify → `PARTIAL` with `E_PKT_PACK_MISSING`
   - Modify a claim binding → re-verify → `TAMPERED`
   - Modify the questionnaire → re-verify → `TAMPERED`

5. **Collect objections**
   - What was unclear in the verification output?
   - What was missing from the coverage report?
   - What would the reviewer need to see that isn't there?

6. **Tighten schema**
   - Incorporate objections into schema and verification semantics
   - Update conformance corpus with adversarial specimens
   - Cut v1.0 schema

### Success Criteria

- Packet compiles from real evidence in one command
- Both Python and TS verifiers produce identical verdicts
- Reviewer can verify offline without any trust in the compiler's tooling
- Tampered artifacts are detected and correctly classified
- Coverage gaps are visible and actionable

---

## 7. Packet Manifest Schema (preliminary)

```json
{
  "packet_id": "pkt_{ISO8601compact}_{uuid8}",
  "packet_version": "0.1.0",
  "manifest_version": "1.0.0",
  "schema_version": "compiled_packet.v1",
  "hash_alg": "sha256",

  "questionnaire_id": "...",
  "questionnaire_sha256": "<SHA256(JCS(questionnaire_import.json))>",

  "bindings_sha256": "<SHA256(claim_bindings.jsonl bytes)>",
  "bindings_count": 25,

  "coverage_sha256": "<SHA256(coverage_report.json bytes)>",

  "pack_references": [
    {
      "pack_id": "pack_20260325_f1a2b3c4",
      "pack_root_sha256": "a1b2c3d4...",
      "bundled": true,
      "bundle_path": "packs/pack_20260325_f1a2b3c4/"
    }
  ],

  "bundle_mode": "bundled",

  "files": [
    {"path": "claim_bindings.jsonl", "sha256": "...", "bytes": 1234},
    {"path": "questionnaire_import.json", "sha256": "...", "bytes": 567},
    {"path": "coverage_report.json", "sha256": "...", "bytes": 890}
  ],
  "expected_files": [
    "claim_bindings.jsonl",
    "questionnaire_import.json",
    "coverage_report.json",
    "packet_manifest.json",
    "packet_signature.sig"
  ],

  "compiled_at": "2026-03-26T15:00:00Z",
  "compiler_version": "1.20.0",

  "signer_id": "assay-local",
  "signer_pubkey": "<base64(ed25519_pubkey)>",
  "signer_pubkey_sha256": "<SHA256(raw_pubkey_bytes)>",
  "signature_alg": "ed25519",
  "signature_scope": "JCS(packet_manifest_excluding_signature_and_packet_root_sha256)",
  "signature": "<base64(ed25519_signature)>",
  "packet_root_sha256": "..."
}
```

**Design notes**:
- Follows the same signing convention as proof packs (pretty-printed storage, JCS-canonical signing base)
- `pack_references` is the binding between packet and packs — by `pack_root_sha256`, not by path or URL
- `bundle_mode` is `"bundled"` or `"referenced"` — exactly one value per packet

#### Packet Root Identity (first principles)

In proof packs, `pack_root_sha256 == attestation_sha256` (the D12 invariant). This works because the attestation is a natural single object that summarizes the entire pack's content.

A compiled packet is different. There is no single attestation object — the packet's identity is the *composition* of questionnaire + bindings + pack references. The root must cover all three, or it doesn't actually identify the compilation.

**V1 definition (provisional)**:

```
packet_root_sha256 = SHA256(JCS({
  "questionnaire_sha256": <questionnaire hash>,
  "bindings_sha256": <bindings file hash>,
  "pack_references": <sorted pack_root_sha256 values>
}))
```

This roots the packet identity over the three things that make a compilation unique: which questions were asked, how they were bound, and which evidence was referenced. The coverage report is deterministically derived from these inputs and is therefore not an independent root input.

**Why not just use the manifest hash?** The manifest contains mutable metadata (compiler_version, compiled_at, signer fields). The root should identify the *content* of the compilation, not the *act* of compiling it. Two compilations of the same bindings against the same questionnaire and packs should produce the same root, even if compiled at different times or by different signers.

**This definition is provisional.** It may change during the first proof loop. The requirement is stable: the root must identify the compilation content, not the compilation metadata.

---

## Relationship to Existing Schemas

| Existing | Compiled Packet Relation |
|----------|------------------------|
| `vendorq.question.v1` | Questionnaire import source. Packet validates against this schema |
| `vendorq.answer.v1` | Compiler MAY use existing VendorQ answers as input to generate claim bindings. The answer schema is an input format, not the packet format |
| `vendorq.evidence_ref.v1` | Claim binding `evidence_refs` extend this schema (adding `pack_root_sha256`) |
| `pack_manifest.schema.json` | Bundled packs are validated against this schema. Packet manifest is a parallel schema, not a superset |
| PACK_CONTRACT.md | All pack-level verification rules apply to bundled packs. Packet verification delegates to pack verification |

---

## 8. Provisional Fields

The following fields and invariants are included for experimentation but are **not yet constitutional**. They may change or be cut based on first proof loop findings:

| Field / Invariant | Status | What Could Change |
|-------------------|--------|-------------------|
| `freshness_anchor` | Provisional | Semantics unclear: is it the latest evidence timestamp? The latest pack timestamp? The latest receipt timestamp? Resolve empirically. |
| `packet_root_sha256` derivation | Provisional | The three-input root (questionnaire + bindings + pack refs) is a hypothesis. The first proof loop will reveal whether this is the right identity model. |
| `coverage_report.json` schema | Provisional | Unknown what reviewers actually need. Resolve during step 5 of proof loop. |
| Binding sort collation | Provisional | `questionnaire_item_id` ascending is natural but collation rules (lexicographic? numeric-aware?) are undefined. |
| `NON_CLAIM` vs `OUT_OF_SCOPE` boundary | Provisional | Semantically clear in examples below, but real-world reviewers may push back on the distinction. Watch for confusion. |

---

## 9. Worked Examples

### Example 1: SUPPORTED / MACHINE

> **Questionnaire item SEC-3.2**: "Is data encrypted at rest?"

```json
{
  "binding_id": "bind_20260326T143000_a8f3e2c1",
  "questionnaire_item_id": "SEC-3.2",
  "claim_type": "TECH_CONTROL",
  "binding_status": "SUPPORTED",
  "evidence_basis": "MACHINE",
  "evidence_refs": [
    {
      "pack_id": "pack_20260325_f1a2b3c4",
      "pack_root_sha256": "a1b2c3d4e5f6...",
      "receipt_id": "r_enc_check_001",
      "evidence_kind": "RECEIPT",
      "target": {"path": "receipt_pack.jsonl", "pointer": ""},
      "span_hash": "b7c8d9e0f1a2...",
      "field_path": "",
      "time_authority": "local_clock",
      "evidence_timestamp": "2026-03-25T14:30:00Z"
    }
  ],
  "answer_summary": "AES-256-GCM encryption at rest enforced on primary data store. Verified by automated storage-layer evaluation.",
  "scope_notes": "Covers primary PostgreSQL data store. Backup encryption is SEC-3.3.",
  "freshness_anchor": "2026-03-25T14:30:00Z",
  "missing_evidence": []
}
```

Straightforward: machine evidence from a proof pack, fully supported, no gaps.

### Example 2: PARTIAL / MIXED

> **Questionnaire item SEC-5.1**: "Do you perform regular penetration testing?"

```json
{
  "binding_id": "bind_20260326T143100_c2d3e4f5",
  "questionnaire_item_id": "SEC-5.1",
  "claim_type": "PROCESS",
  "binding_status": "PARTIAL",
  "evidence_basis": "MIXED",
  "evidence_refs": [
    {
      "pack_id": "pack_20260320_aabbccdd",
      "pack_root_sha256": "1122334455...",
      "receipt_id": "r_vuln_scan_042",
      "evidence_kind": "RECEIPT",
      "target": {"path": "receipt_pack.jsonl", "pointer": ""},
      "span_hash": "5566778899...",
      "field_path": "",
      "time_authority": "local_clock",
      "evidence_timestamp": "2026-03-20T09:00:00Z"
    }
  ],
  "answer_summary": "Automated vulnerability scanning runs weekly (see evidence). Annual third-party pen test completed 2026-01 per CISO attestation. Pen test report not yet digitized into proof pack.",
  "scope_notes": "Automated scanning covers external attack surface. Pen test covered internal and external.",
  "freshness_anchor": "2026-03-20T09:00:00Z",
  "missing_evidence": ["Third-party penetration test report as proof pack"]
}
```

Machine evidence for the automated part, human attestation for the pen test. `PARTIAL` because the pen test evidence isn't yet in a proof pack. `missing_evidence` names the gap explicitly.

### Example 3: OUT_OF_SCOPE / NONE

> **Questionnaire item GDPR-2.4**: "How do you handle data subject access requests?"

```json
{
  "binding_id": "bind_20260326T143200_d4e5f6a7",
  "questionnaire_item_id": "GDPR-2.4",
  "claim_type": "LEGAL",
  "binding_status": "OUT_OF_SCOPE",
  "evidence_basis": "NONE",
  "evidence_refs": [],
  "answer_summary": "This system does not process personal data of EU data subjects. GDPR data subject access provisions do not apply.",
  "scope_notes": "System processes only aggregated, anonymized telemetry. No PII ingestion path exists.",
  "freshness_anchor": "2026-03-26T14:32:00Z",
  "missing_evidence": []
}
```

Not a gap — a deliberate scope declaration. The reviewer can challenge this ("are you sure no PII enters?"), but the binding is explicit about the claim.

### Example 4: NON_CLAIM / NONE

> **Questionnaire item SLA-1.2**: "What is your guaranteed uptime SLA?"

```json
{
  "binding_id": "bind_20260326T143300_e5f6a7b8",
  "questionnaire_item_id": "SLA-1.2",
  "claim_type": "COMMITMENT",
  "binding_status": "NON_CLAIM",
  "evidence_basis": "NONE",
  "evidence_refs": [],
  "answer_summary": "We do not offer a guaranteed uptime SLA for this service tier. Observed uptime is tracked but not contractually committed.",
  "scope_notes": "Enterprise tier includes SLA. This assessment covers the standard tier only.",
  "freshness_anchor": "2026-03-26T14:33:00Z",
  "missing_evidence": []
}
```

Different from `OUT_OF_SCOPE`: the question applies, but the answer is "we decline to assert this." The reviewer sees an honest non-claim rather than silence.

### Example 5: UNSUPPORTED / NONE

> **Questionnaire item SEC-7.3**: "Do you maintain a software bill of materials (SBOM)?"

```json
{
  "binding_id": "bind_20260326T143400_f6a7b8c9",
  "questionnaire_item_id": "SEC-7.3",
  "claim_type": "PROCESS",
  "binding_status": "UNSUPPORTED",
  "evidence_basis": "NONE",
  "evidence_refs": [],
  "answer_summary": "",
  "scope_notes": "SBOM generation is planned but not yet implemented.",
  "freshness_anchor": "2026-03-26T14:34:00Z",
  "missing_evidence": ["SBOM generation tooling output", "Dependency inventory proof pack"]
}
```

An honest gap. No evidence, no claim, but the binding exists so the coverage report shows this as a known deficiency rather than an oversight.

---

## Open Questions (to resolve during first proof loop)

1. **Coverage report schema**: What fields does the reviewer actually need? Resolve empirically during step 5.
2. **Bundle compression**: Should `assay packet compile --bundle` produce a directory or a `.zip`? Leaning toward: directory by default, `--zip` flag for portability.
3. **Pack freshness in packet context**: A pack might be stale relative to the packet compilation time but still valid. Define policy.
4. **Bundled pack byte-exactness**: When packs are copied into `packs/`, are directory names part of trust semantics? What if filesystem metadata changes? V1 position: only file *content* hashes matter (same as proof pack verification), not filesystem metadata. But this needs explicit testing.
5. **Transform fidelity from VendorQ answers**: The mechanical 1:1 transform from `vendorq.answer.v1` to claim bindings needs precise field mapping. Define during implementation.
