# Integrity Port Compatibility Checklist

**Status:** normative checklist
**Scope:** independent verifier ports for the Assay integrity surface
**Source of truth:** [INTEGRITY_SURFACE_SPEC_V1.md](./INTEGRITY_SURFACE_SPEC_V1.md)

This checklist is the practical conformance gate for any non-Python verifier
that wants to claim compatibility with Assay's integrity model.

To claim compatibility, a port MUST satisfy every item below.

---

## 1. Byte-surface compatibility

- [ ] File entry hashes are computed from raw file bytes, not canonicalized JSON.
- [ ] Attestation hashes are computed from JCS-canonicalized attestation JSON.
- [ ] Receipt payload hashes use the Layer 2 exclusion set from the spec.
- [ ] Manifest signatures are computed from the unsigned manifest surface only.
- [ ] No other serialization route is substituted for any of the four surfaces.

## 2. Exclusion-set compatibility

- [ ] Receipt hashing strips exactly the top-level fields listed in the spec.
- [ ] The receipt exclusion set version matches the spec's current version.
- [ ] The manifest signing base excludes exactly `signature` and `pack_root_sha256`.
- [ ] `signature_scope` is treated as descriptive only, not as a source of truth.

## 3. Verification-order compatibility

- [ ] Schema validation runs before all other manifest checks.
- [ ] Path containment is checked before file-hash verification.
- [ ] File hashes are verified before receipt and attestation checks.
- [ ] Receipt verification runs before manifest signature verification.
- [ ] Attestation hash verification runs before the D12 invariant check.
- [ ] Manifest signature verification runs before the D12 invariant check.
- [ ] Freshness checks remain optional and run only after structural checks.

Note: Section 4 is a compatibility target for verifier ports. The current
Python reference verifier is still presence-only on `receipt.type`; closed-enum
rejection is the target described in the source spec.

## 4. Invariant compatibility

- [ ] `pack_root_sha256 == attestation_sha256` is enforced as the D12 invariant.
- [ ] A mismatch fails as a manifest incoherence error, not as a hash-surface error.
- [ ] `receipt.type` presence is required.
- [ ] Unknown `receipt.type` values are rejected in strict conformance mode.
- [ ] Numeric receipt fields follow the spec's integer and decimal rules.

## 5. Error-behavior compatibility

- [ ] Failures are mapped to the same semantic classes as the reference implementation.
- [ ] A verifier does not silently accept an unknown receipt or manifest shape.
- [ ] A verifier does not reorder checks to “pass early” on an unverified surface.
- [ ] A verifier reports when the manifest is internally incoherent even if earlier
      checks succeeded.

## 6. Diagnostic compatibility

- [ ] Error messages identify which surface failed.
- [ ] Error messages identify which invariant failed.
- [ ] Debug output is not required for conformance.
- [ ] Canonicalized bytes or hash digests can be reproduced deterministically.

## 7. Port acceptance criteria

A port may claim compatibility only when:

- [ ] It passes the reference vectors for all four byte surfaces.
- [ ] It matches the reference verification order.
- [ ] It enforces the normative exclusions and invariants.
- [ ] It rejects at least one deliberately malformed pack in the same way as the
      reference implementation.
- [ ] It documents any remaining hardening gaps explicitly.

## 8. Out-of-scope for v1

The following are not required for conformance yet, but should be called out if a
port supports them:

- Domain-separated hashing.
- Closed-enum enforcement for all future receipt types beyond the current spec gap.
- Policy or admissibility logic outside the integrity surface itself.

## 9. Minimal verifier claim

If you want the shortest possible claim, it is this:

> This verifier reproduces Assay's integrity surface semantics for file hashes,
> receipt payload hashes, attestation hashes, manifest signatures, and the D12
> invariant, in the order defined by `INTEGRITY_SURFACE_SPEC_V1.md`.

Anything weaker is a partial implementation, not a compatibility claim.
