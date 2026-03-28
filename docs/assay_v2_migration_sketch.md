# Assay v2 Migration Sketch

**Date**: 2026-03-26
**Status**: PLANNING SKETCH ONLY — not normative, not constitutional, not implementation-ready

> **Blocked.** Do not act on this document until both prerequisite findings are resolved.
>
> | Finding | Classification | Status |
> |---------|---------------|--------|
> | Finding 1: ADC consumed without signature verification | LIVE_EXPLOIT | **Patched** — `15a44d9` in assay main repo (`replay_judge.py`) |
> | Finding 2: TS verifier skips Ed25519 when `signer_pubkey` absent | LIVE_EXPLOIT | **Open** — in `assay-verify-ts`, not yet patched |
>
> This sketch describes substrate migration options for v2. None of them should be
> implemented until Finding 2 is patched in the TS verifier. Domain separation does
> not fix unsigned trust — those are separate bugs that must land first.
>
> See `docs/assay_domain_audit_adjudication.md` for the full finding record.

---

## What can be added without breaking corpus

These changes are additive. Existing v1 packs, vectors, and the TS verifier
continue to work unchanged.

1. **`_receipts/domain_hash.py`** — New module with domain-separated hash function.
   Does not replace any existing call site. Exists alongside `_sha256_hex`.

2. **Invariant tests** — Assert key-set disjointness between receipt and
   attestation schemas. Assert domain-separated hashes of identical bytes
   differ across domains. Assert wrong-domain digest is rejected by
   appropriate verifier. These test the future, not the present.

3. **`attestation_sha256_v2` field** — Added to manifest alongside existing
   `attestation_sha256`. Both computed at build time. Verifier ignores
   unknown fields. Old verifiers see only `attestation_sha256`.

4. **`head_hash_algorithm: "last-receipt-digest-v2"`** — New algorithm
   identifier. Old verifiers see `"last-receipt-digest-v0"` and use existing
   path. New verifiers check algorithm field and dispatch.

---

## What needs dual-read

These changes require the verifier to support both old and new formats
simultaneously.

1. **`attestation_sha256` vs `attestation_sha256_v2`** — Verifier must accept
   manifests with only v1, only v2, or both. Acceptance rules:
   - `manifest_version == "1.0.0"`: MUST have `attestation_sha256` (v1 hash).
     `attestation_sha256_v2` OPTIONAL (informational).
   - `manifest_version == "2.0.0"`: MUST have `attestation_sha256_v2` (v2 hash).
     `attestation_sha256` OPTIONAL (backward compat tooling).
   - Verifier dispatches on `manifest_version`, not on field presence.

2. **head_hash verification** — Verifier reads `head_hash_algorithm` from
   attestation. `"last-receipt-digest-v0"` → existing SHA256(JCS(receipt)).
   `"last-receipt-digest-v2"` → domain_hash("receipt", JCS(receipt)).

---

## What needs dual-write

The builder must produce both v1 and v2 values during the transition period
so that old and new verifiers both accept the pack.

1. **attestation_sha256 + attestation_sha256_v2** — Builder computes both.
2. **head_hash** — Builder stores the value matching the declared algorithm.
   During transition, builder writes `head_hash_algorithm: "last-receipt-digest-v0"`
   (existing behavior). v2 builder writes `"last-receipt-digest-v2"`.
3. **pack_root_sha256** — D12 invariant: must equal whichever attestation hash
   is normative for that manifest version.

---

## What forces verifier branching

These changes require conditional logic in the verifier. The branching
condition is `manifest_version`.

1. **Manifest signing base** — v1: `Ed25519(JCS(unsigned_manifest))`. v2:
   `Ed25519(b"assay:manifest:v1:" + JCS(unsigned_manifest))`. The verifier
   must reconstruct the correct signing input based on manifest_version.

2. **Attestation hash check** — v1: `SHA256(JCS(attestation))`. v2:
   `SHA256(b"assay:attestation:v1:" + JCS(attestation))`. Dispatch on
   manifest_version.

3. **Head hash check** — v1: `SHA256(JCS(receipt))`. v2:
   `SHA256(b"assay:receipt:v1:" + JCS(receipt))`. Dispatch on
   `head_hash_algorithm`.

**Critical rule**: Do NOT dispatch on `signature_scope`. It is descriptive.
Add explicit normative fields (`manifest_version`, `head_hash_algorithm`)
for version dispatch.

---

## What test vectors must exist before any switch

Before ANY production pack is built with v2 semantics:

1. **v2 golden valid pack** — Domain-separated hashes, v2 signing surface.
   Must pass v2 verifier. Must be rejected by v1 verifier (or accepted with
   v2 fields ignored, depending on upgrade policy).

2. **v1 golden valid pack** — Existing `golden_minimal`. Must continue to
   pass both v1 and v2 verifiers.

3. **v2 adversarial specimens** — At minimum:
   - Wrong domain prefix (receipt hash used where attestation hash expected)
   - Stripped domain prefix (v1-style hash submitted to v2 verifier)
   - Cross-domain signed manifest (manifest signed with receipt domain prefix)

4. **Cross-implementation parity** — TS verifier must produce identical v2
   hashes for the same inputs. Add to `conformance-fixtures.json` (v2 section).

5. **Empty-pack sentinel v2** — Resolve the v1 empty-pack divergence
   (Finding 3) before introducing v2. Do not carry the ambiguity forward.

---

## What should be gated behind proof tier / promotion only

Not everything needs to ship at once. Gate progression:

**Tier 0: Immediate (no substrate change)**
- Fix ADC signature verification in replay_judge.py
- Fix TS missing-pubkey crypto bypass
- Add key-set disjointness invariant test
- Resolve empty-pack sentinel in contract

**Tier 1: Substrate module (no production usage)**
- Ship `_receipts/domain_hash.py`
- Ship invariant tests (cross-domain hash disjointness)
- Ship `assay:` namespace prefix design
- No production packs use v2 yet

**Tier 2: Dual-write builder**
- Builder emits both v1 and v2 attestation hashes
- Manifest version remains "1.0.0" (v2 fields informational)
- Verifier still uses v1 path
- Conformance corpus v2 generated and tested

**Tier 3: v2 verifier**
- Verifier supports manifest_version "2.0.0"
- TS verifier updated in lockstep
- Cross-implementation parity vectors pass
- v2 packs can be produced and verified

**Tier 4: v2-only (future)**
- New packs built as v2 by default
- v1 verification retained for historical packs
- v1 builder deprecated

---

## Open questions (not decided here)

1. **Domain prefix format**: `b"assay:receipt:v1:"` vs `b"assay:receipt/v1:"` vs
   `b"assay\x1freceipt\x1fv1\x1f"`. The delimiter choice affects parsability
   and ambiguity. Colon is human-readable. Unit separator (0x1F) is
   machine-unambiguous. Slash matches URI convention.

2. **Manifest version bump semantics**: Is "2.0.0" the right signal? Or should
   a separate `hash_substrate_version` field be introduced to decouple manifest
   structure changes from hash algorithm changes?

3. **Downgrade policy**: If a v2 manifest is presented to a v1-only verifier,
   should it fail closed (reject unknown manifest_version) or fail open
   (ignore v2 fields, verify v1 fields if present)? Current behavior: v1
   verifier ignores unknown fields and verifies what it knows.

4. **ADC migration**: The ADC is currently unsigned-but-signed (signature
   written, never verified). After fixing Finding 1, should ADC verification
   be added to the pack verification pipeline (not just replay_judge)?
   This elevates ADC from sidecar to kernel-adjacent.
