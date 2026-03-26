# Attestation Semantics

**Date**: 2026-03-26
**Status**: First specimens. Not yet cross-implementation conformance.

This document explains what the semantic fields in a pack attestation mean in practical terms, anchored to executable specimens.

---

## The Two Verification Layers

A proof pack is checked in two layers:

1. **Mechanical integrity** — Is the pack intact? File hashes, signature, Merkle structure, D12 invariant. This is cross-implementation conformance (Python + TS agree).

2. **Claim evaluation** — Does the evidence support what's claimed? Currently Python-only (`claim_verifier.py`). Produces `claim_check` and `discrepancy_fingerprint` in the attestation.

These layers are independent. A pack can be mechanically valid but semantically insufficient (evidence intact but doesn't prove the claim). Or mechanically invalid and semantically moot (tampered, claims don't matter).

---

## Semantic Attestation Fields

### `claim_check`

**Values**: `PASS` | `FAIL` | `N/A`

| Value | Meaning |
|-------|---------|
| `PASS` | All critical claims in the claim set were satisfied by the evidence |
| `FAIL` | At least one critical claim was NOT satisfied |
| `N/A` | No claims were evaluated (claim set not provided at build time) |

**What PASS means**: The supplied evidence satisfied the specified claim set under the referenced policy logic. This does NOT mean:
- The underlying events are metaphysically true (receipts may be honestly produced but wrong)
- The policy is normatively sufficient for all contexts (different reviewers may require stronger evidence)
- No additional evidence could alter review conclusions
- The pack is globally trustworthy outside the evaluated claim scope (trust depends on signer, key integrity, governance)

**Mechanical validity is necessary for trustworthy transport, but not sufficient for semantic sufficiency.** A pack can pass all mechanical checks and still fail claim evaluation.

**What FAIL means**: At least one critical claim could not be supported by the evidence. The `discrepancy_fingerprint` identifies which combination of claims failed. The `verify_report.json` contains per-claim details.

### `claim_set_id` / `claim_set_hash`

Identifies what was being claimed. The `claim_set_id` is a human-readable name. The `claim_set_hash` is `SHA256(JCS(claim_specs))` — a deterministic fingerprint of the claim definitions.

Two packs with the same `claim_set_hash` evaluated the same claims. Two packs with different hashes may have evaluated different claim sets even if the IDs look similar.

### `discrepancy_fingerprint`

A deterministic hash of the claim evaluation results. Computed via `SHA256(JCS(sorted_claim_results))`.

- Same fingerprint = same combination of pass/fail across all claims
- Different fingerprint = different evaluation outcome

This is useful for: grouping packs by evaluation outcome, detecting regressions, comparing runs.

The fingerprint is a **triage affordance**, not a truth primitive. Fingerprint equality means the same combination of claims passed/failed — it does not mean the underlying evidence is equivalent. It is stable across re-runs of the same receipts + claims + policy.

### `policy_hash`

`SHA256(b"default-policy-v0")` when no explicit policy is provided. Otherwise, the hash of the governing policy document.

The policy hash identifies **under whose rules** the evaluation happened. Different policies may evaluate the same evidence differently.

---

## Specimens

Two executable specimens exist at `tests/contracts/vectors/semantic/`:

### `claim_pass`

- 2 receipts: model_call + guardian_verdict
- 2 claims: "model was executed" + "guardian check happened"
- Both claims satisfied → `claim_check: PASS`
- **Reviewer interpretation**: Evidence supports that the model was executed under guardian oversight. Sufficient for the stated claim set.

### `claim_insufficient`

- 1 receipt: model_call only
- Same 2 claims as above
- Guardian claim fails → `claim_check: FAIL`
- **Reviewer interpretation**: Evidence shows model execution but no guardian check. One claim is unsupported. This is an evidence gap, not necessarily a system failure.

---

## Semantic Failure Classes

Claim evaluation can fail for different reasons. These are not yet fully encoded in the conformance specimens but should be tracked as distinct categories:

| Failure Class | Meaning | Current Specimen |
|--------------|---------|-----------------|
| **Insufficiency** | Required evidence is absent. A claim cannot be supported because the relevant receipts are missing. | `claim_insufficient` |
| **Contradiction** | Evidence is present but conflicts. Receipts contain contradictory signals that prevent a clean evaluation. | Not yet implemented |
| **Policy mismatch** | Evidence exists but does not satisfy the specific policy's requirements (e.g., wrong assurance level, expired timestamp). | Not yet implemented |

The `claim_insufficient` specimen demonstrates the first class. The second and third are reserved for future specimens. These categories matter because they require different reviewer responses: insufficiency is "look for more evidence," contradiction is "investigate the conflict."

## Current Runtime Limitation

These specimens define the operational interpretation of attestation fields **as implemented by the Python claim evaluator** (`claim_verifier.py`). They do not yet define language-independent semantic equivalence.

If another runtime later implements claim evaluation, these specimens can serve as ground-truth exemplars — but the claim evaluation contract itself is not yet cross-implementation conformance.

## What This Is NOT

- This is NOT cross-implementation conformance (only Python evaluates claims today)
- This is NOT a governance framework (no rules about what counts as "enough")
- This is NOT a proof-tier specification (no mapping from claim outcomes to assurance levels)
- This is NOT a reviewer decision procedure (reviewers bring their own judgment)

It IS the first specimen-backed documentation of what attestation semantic fields mean.
