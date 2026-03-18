# Canonical Evidence Semantics Matrix

**Status**: Provisional copy. Canonical ownership belongs in CCIO (`ccio/docs/architecture/`) as cross-repo constitutional law. This Assay copy is a working reference until the canonical source is established.
**Purpose**: Pin the meanings so they do not drift between layers, repos, or surfaces.
**Rule**: When terms from different layers seem equivalent, this matrix says whether they are.

## 1. Decision Planes

These are **orthogonal**. Do not map across planes.

| Plane | Values | Layer | Answers |
|-------|--------|-------|---------|
| **Verification verdict** | PASS, HONEST_FAIL, TAMPERED, INSUFFICIENT_EVIDENCE | `verification_status.py` | "Is the evidence intact and do claims hold?" |
| **Governance verdict** | APPROVE, REFUSE, DEFER, ABSTAIN, ROLLBACK, CONFLICT | `decision_receipt.py` | "What should the organism do about this?" |
| **Trust authorization** | authorized, recognized, unrecognized, revoked, not_evaluated | `trust/types.py` | "Is this signer permitted for this artifact?" |
| **Trust acceptance** | accept, warn, reject, not_evaluated | `trust/types.py` | "Is this artifact acceptable for this target?" |
| **Reliance verdict** | PASS, WARN, FAIL | `verdict.py` | "Should downstream consumers rely on this?" |

**Critical invariant**: verification verdicts and governance verdicts are orthogonal.
A pack can be PASS (intact evidence) and REFUSE (governance says no).
A pack can be HONEST_FAIL (claims failed) and APPROVE (governance accepts the failure as honest).

## 2. Exit Codes

| Code | Meaning | Who uses it |
|------|---------|-------------|
| 0 | All checks pass | `assay verify-pack`, `assay-verify-action` |
| 1 | Integrity PASS but claims/policy/expiry/trust gate failed | `assay verify-pack`, `assay-verify-action` |
| 2 | Integrity FAIL (evidence may be tampered/corrupted) | `assay verify-pack`, `assay-verify-action` |
| 3 | Input/config error (bad args, missing files) | `assay verify-pack` |

Exit 1 is **not tool failure**. It is the tool working correctly to report an honest failure.

## 3. Proof Tiers

| Tier | Ordinal | Meaning | Who defines it |
|------|---------|---------|----------------|
| DRAFT | 0 | Unverified claim | `decision_receipt.py` |
| CHECKED | 1 | Basic structural validation | `decision_receipt.py` |
| TOOL_VERIFIED | 2 | Automated tool verification | `decision_receipt.py` |
| ADVERSARIAL | 3 | Tested against adversarial scenarios | `decision_receipt.py` |
| CONSTITUTIONAL | 4 | Full constitutional review | `decision_receipt.py` |

These are internal governance tiers, not the same as public trust tiers.

## 4. Assurance Levels (Public)

| Level | Meaning | Requirements |
|-------|---------|--------------|
| L0 | Signed, verified | Pack exists, signature valid |

Higher levels (L1+) are reserved and not yet defined.

## 5. Artifact Taxonomy

| Artifact | Emitter | Verifier | Proves | Does not prove | Audience |
|----------|---------|----------|--------|---------------|----------|
| **Proof pack** | `assay run` / `ProofPack.build()` | `assay verify-pack` | Integrity + declared claims | Evidence was honestly created | Public |
| **Witness envelope** | `agentmesh commit` | `agentmesh witness verify` | Commit provenance + patch identity | Patch correctness | Internal |
| **Ledger entry** | `accept-submission.yml` | `validate_ledger.py` + `witness_verify.py` | Pack fingerprint was submitted + optionally witnessed | Pack content | Public |
| **ADC** | `ProofPack.build(emit_adc=True)` | Schema + signature validation | Issuer attested to claim outcomes | Claim truth | Public |
| **Decision receipt** | Governance layer (CCIO) | `decision_receipt.py` validator | Governance decision was made with stated evidence | Decision was correct | Internal |
| **Reviewer packet** | `assay reviewer packet` | Human review | Evidence was organized for review | Evidence was reviewed | Public |
| **Passport** | `assay passport` | `assay passport verify` | Multiple packs form coherent history | System safety | Public |

## 6. Verification Error Families

| Family | Error codes | Meaning |
|--------|------------|---------|
| `tamper_detected` | E_MANIFEST_TAMPER, E_PACK_OMISSION_DETECTED, E_PACK_SIG_INVALID, E_SIG_INVALID, E_PATH_ESCAPE | Evidence integrity compromised |
| `schema_mismatch` | E_SCHEMA_UNKNOWN, E_CANON_MISMATCH, E_DUPLICATE_ID | Structure invalid |
| `witness_gap` | E_SIG_MISSING, E_CHAIN_BROKEN | Proof material absent |
| `stale_evidence` | E_PACK_STALE, E_TIMESTAMP_INVALID | Temporal validity failed |
| `policy_conflict` | E_POLICY_MISSING, E_CI_BINDING_MISSING, E_CI_BINDING_MISMATCH | Policy requirements unmet |

## 7. Cross-Repo Transport

| Object | Transport metadata? | Evidence-bearing? | Signed? | Public? |
|--------|-------------------|-------------------|---------|---------|
| Proof pack (5-file kernel) | No | Yes | Yes (Ed25519) | Yes |
| `pack_manifest.json` | No | Yes (root envelope) | Yes | Yes |
| `receipt_pack.jsonl` | No | Yes (receipt chain) | Covered by manifest sig | Yes |
| `pack_signature.sig` | No | Detached signature | Is the signature | Yes |
| Witness trailers (git) | Yes (commit metadata) | Yes (patch identity) | Yes (Ed25519) | Per repo |
| CCOI envelope | Yes (authority routing) | Carries authority class | No | Internal |
| Ledger JSONL line | No | Fingerprint record | Optional (witness_status) | Public |
| Trust evaluation JSON | Yes (advisory output) | No (computed, not attested) | No | Operator |

## 8. Vocabulary Law

When the same word appears at different layers, this is the canonical meaning:

| Term | Canonical meaning | What it does NOT mean |
|------|------------------|----------------------|
| **verified** | Cryptographic integrity check passed | Not "approved" or "trusted" or "accepted" |
| **authorized** | Signer has an explicit grant for this artifact/purpose | Not "recognized" (known but unganted) |
| **accepted** | Artifact meets target-specific policy for a named consumer | Not universally trusted; always target-bound |
| **honest fail** | Evidence is intact but behavioral claims did not pass | Not tool failure; not tamper |
| **receipt** | A structured record of what happened (action, decision, event) | Not a proof of correctness |
| **proof pack** | A signed, verifiable bundle of receipts with attestation | Not a safety certificate |
| **witness** | A cryptographic attestation of patch/commit provenance | Not a guarantee of code quality |
| **not_evaluated** | Trust policy was not loaded or not requested | Not "passed" or "failed" |

## 9. What This Matrix Does NOT Cover

- Internal CCIO constitutional semantics (authority classes, runtime condition vectors)
- Loom episode state machines (ATTEMPT/CHECK/VERIFY/REPAIR/FINALIZE)
- AgentMesh operational semantics (task states, spawn lifecycle)
- Future trust tier definitions beyond L0
- Cross-ledger or cross-repo trust federation
- KMS/HSM key management

Those belong to their own governing documents in their respective repos.

## 10. Maintenance Rule

When a new verdict value, artifact type, or tier is added to any repo in the
Assay ecosystem, this matrix must be updated in the same transaction.
A vocabulary change without a matrix update is a constitutional violation.
