# Ledger Scope Decision

**Status**: Current operating decision with stronger design parked

**Decision date**: 2026-04-04

This note freezes the current ledger scope for Assay's public claim surface and records the smallest path to stronger independent assurance if that becomes desirable later.

## Decision

Assay's public ledger claims remain at manifest and attestation witness scope.

That means today's honest claim is:
- the ledger witnesses submitted manifest and attestation linkage metadata
- the ledger enforces append rules for the entry it records
- full proof-pack cryptographic verification still requires the original pack and `assay verify-pack`

Do not claim that the ledger independently re-verifies full proof-pack contents before acceptance.

## Why This Is The Current Default

- It matches the workflow actually implemented today.
- It keeps the transparency layer honest without overstating independent artifact verification.
- It preserves a small, tractable submission flow while stronger protocol work is still unbuilt.

## Desired Stronger Scope If Reopened

If stronger public language is wanted later, the target is:
- the ledger receives or fetches the full proof pack
- it recomputes file or receipt hashes from the actual pack tree
- it verifies pack integrity before append
- it records which verification mode and artifact root were independently checked

## Minimal Protocol Delta

1. Submission must include either the full pack bytes or a stable artifact locator the ledger can fetch deterministically.
2. The acceptance workflow must materialize the exact pack bytes under review.
3. The ledger must recompute manifest-linked file hashes and run the pack verification step before append.
4. Acceptance must fail closed on fetch failure, hash mismatch, or verification failure.
5. The witness entry must record that full-pack independent verification occurred and against which verification contract version.

## Reopen Triggers

- The project wants stronger public claims about independent verification.
- A customer, auditor, or partner requires full-pack witness assurance.
- The storage, network, and availability trade-offs become acceptable.

## Current Claim Boundary

Use this language:
- the ledger is a transparency and witness layer for submitted metadata at manifest and attestation scope
- independent full-pack verification remains a future protocol upgrade

Do not use this language:
- the ledger independently re-verifies the whole proof pack before acceptance
