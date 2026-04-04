# Signer Bootstrap Decision

**Status**: Current operating decision

**Decision date**: 2026-04-04

This note freezes the current signer-bootstrap posture for Assay's public claim surface. It prevents `trusted_signer` language from drifting into implied default authorization.

## Decision

Assay's default public posture remains loose/local until a non-empty trusted signer policy is explicitly activated.

That means:
- low-level ReceiptV2 verification may resolve a key and verify signature math
- higher-level signer authorization is not implied by default
- public materials must not say that Assay enforces a non-empty authorized signer policy by default

## Why This Is The Current Default

- It matches today's shipping behavior and the current claim ledger.
- It preserves local, dev, and T0 self-signed workflows without pretending there is a global production registry in place.
- It keeps `trusted_signer` aligned with its actual low-level meaning.
- It avoids widening public assurance language ahead of an explicit bootstrap path.

## What A Stronger Default Would Require

1. A canonical non-empty signer registry or trust policy shipped as part of the product or required deployment contract.
2. A documented production resolver path that fails closed when the signer is not authorized.
3. Clear separation between local or dev override behavior and production behavior.
4. Updates to [`CLAIM_LEDGER.md`](CLAIM_LEDGER.md), [`SECURITY_INVARIANTS.md`](SECURITY_INVARIANTS.md), [`SECURITY_POSTURE_TODAY.md`](SECURITY_POSTURE_TODAY.md), and release checks before stronger public language ships.

## Reopen Triggers

- Assay standardizes a production signer registry and resolver path.
- The public trust tier moves beyond self-signed or T0 packaging.
- A partner, regulator, or customer requires default authorized-signer enforcement.

## Current Claim Boundary

Use this language:
- Assay separates raw signature validity from higher-level signer policy.
- Default strong signer authorization is not active unless a non-empty policy is explicitly configured.

Do not use this language:
- Assay enforces a non-empty authorized signer policy by default.
