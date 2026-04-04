# Security Posture Today

This file is the short current-state security surface for Assay and the adjacent Assay-integrated workflow. It is the plain-English companion to [`SECURITY_AUDIT_ADJUDICATION_2026-04-03.md`](SECURITY_AUDIT_ADJUDICATION_2026-04-03.md), [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md), and [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md).

## What Assay Verifies Today

Assay today verifies signed proof packs offline.

That means:
- `assay verify-pack` checks proof-pack integrity against the proof-pack contract.
- It verifies the cryptographic envelope for the pack surface Assay defines today.
- It reports declared claims honestly: pass, fail, or tampered.
- It works on the pack artifact another party receives, not on the producer's live server.

At the current public trust tier, proof packs are still fundamentally self-signed artifacts. Assay gives strong tamper evidence for the artifact it produced, but it does not by itself prove that every upstream system component was honest.

## What `assay gate check` Is And Is Not

`assay gate check` is an evidence-readiness score and receipt-presence analysis.

It is:
- a quick signal about workflow hygiene and evidence posture
- a score/report surface for whether evidence artifacts exist in the expected shape

It is not:
- a cryptographic verifier
- a signature checker
- a substitute for `assay verify-pack`

If the question is "did this proof pack verify cryptographically?" the right surface is `assay verify-pack`.

## What `assay verify-pack` Is And Is Not

`assay verify-pack` is the cryptographic proof-pack verification step.

It is:
- the offline verifier for Assay proof packs
- the place where artifact integrity and declared pack-level checks are evaluated

It is not:
- a blanket verifier for every richer receipt schema in the broader ecosystem
- a claim that all gateway/reference receipt contracts are identical to the proof-pack contract

The proof-pack contract is its own surface and must be judged against [`docs/contracts/PACK_CONTRACT.md`](../contracts/PACK_CONTRACT.md).

## Field-Name Policy Today

Assay now rejects non-ASCII object member names before projection and other attestation input is formed.

That means:
- spoof-like non-ASCII field names do not reach `canonical_projection`
- the same ASCII-only rule also applies to the historical receipt hashing path before JCS is invoked

This is intentionally a higher-layer identifier policy above JCS.

It is not:
- a change to RFC 8785 behavior
- a claim that Assay performs full Unicode TR39-style confusable or mixed-script screening beyond the current ASCII-only field-name rule

## Trusted Signer Posture Today

At the low-level ReceiptV2 verifier layer, `trusted_signer` is narrower than full signer authorization.

Today that means:
- the ReceiptV2 layer can distinguish raw signature validity from signer trust inputs
- a higher-level trust and policy layer can still reject a key that was available for low-level verification
- strong signer-policy language still depends on explicit bootstrap and activation of a non-empty trusted signer policy

Current honest language is:
- Assay separates raw signature validity from higher-level signer policy
- default strong signer-policy activation is still a deployment and bootstrap choice

Current operating decision: keep default signer posture loose/local until a non-empty trusted signer policy is explicitly activated. See [`SIGNER_BOOTSTRAP_DECISION.md`](SIGNER_BOOTSTRAP_DECISION.md).

## Ledger Witness Scope Today

Assay Ledger is an append-only transparency layer.

For witnessed submissions today, it verifies:
- the signed manifest
- the attestation linkage/hash-chain surface
- the ledger append rules for the entry it records

It does not currently:
- fetch the full proof-pack directory from the original source
- recompute receipt and file hashes from the full pack tree before acceptance

Current honest language is:
- the ledger witnesses manifest and attestation scope
- full-pack verification still requires the original pack and `assay verify-pack`

If stronger language is desired, that requires a protocol and workflow change rather than another wording pass.

Current operating decision: keep public ledger claims at manifest/attestation witness scope unless the protocol changes. See [`LEDGER_SCOPE_DECISION.md`](LEDGER_SCOPE_DECISION.md).

## AgentMesh Integration Today

In the Assay-integrated reference workflow:
- AgentMesh records lineage, coordination, and provenance
- Assay handles proof-pack verification and trust-artifact packaging

Current honest CI language is:
- `assay-gate` is the baseline evidence-readiness score
- `assay-verify` is the cryptographic proof-pack verification step
- required enforcement on GitHub depends on explicit branch-protection configuration

CI existing is not the same thing as branch protection existing.

## Current Decisions And Remaining Work

Two operating decisions are now explicit:

1. Default signer posture remains loose/local until a non-empty trusted signer policy is explicitly activated.
2. Public ledger claims remain at manifest/attestation witness scope; no full-pack independent re-verification claim ships today.

The remaining short queue is:

3. If desired later, add broader TR39-style confusable or mixed-script screening above the current ASCII-only field-name policy.
4. If product strategy changes later, implement stronger signer policy and/or stronger ledger verification first, then widen the claim surface after the code and workflow land.

The main mixed-contract panic has already been retired.
