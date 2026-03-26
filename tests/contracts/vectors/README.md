# Conformance Vectors

**Generated**: 2026-03-25
**Contract version**: Pack Contract v0 (see `docs/contracts/PACK_CONTRACT.md` for freeze status)
**Hash format**: Raw hex (OCD-1 resolved)

## What This Corpus Covers

### Component Vectors

| File | Layer | Vectors | Proves |
|------|-------|---------|--------|
| `jcs_vectors.json` | Layer 1 (RFC 8785) | 16 golden | JCS canonicalization produces exact bytes and hashes |
| `merkle_vectors.json` | Layer 1 (SHA-256 tree) | 4 golden + 2 adversarial | Merkle root, inclusion proofs, odd-node duplication |
| `receipt_projection_vectors.json` | Layer 2 (projection) | 3 golden + 2 assertions | Signature stripping, root-only doctrine, hash equivalence |

### Full Pack Specimen

| Directory | Receipts | Proves |
|-----------|----------|--------|
| `pack/golden_minimal/` | 2 | Full 11-step verification pipeline end-to-end |

The `golden_minimal` specimen is a real 5-file proof pack (not a JSON abstraction).
It exercises: schema validation, file hash verification, receipt count cross-check,
head hash computation, attestation hash check, detached signature parity, unsigned
manifest reconstruction, Ed25519 verification (self-contained via embedded pubkey),
D12 invariant, and signer fingerprint verification.

Expected verification outputs are in `pack/expected_outputs.json`. The specimen was
generated with a deterministic Ed25519 keypair (32 zero-byte seed) and fixed timestamp
(`2026-01-15T12:00:00+00:00`), so it is reproducible. **The key material is for
conformance testing only — do not use zero-byte seeds for operational signing.**

## What This Corpus Does Not Cover

- Adversarial/tampered pack variants (PK-A01 through PK-A18)
- PK-A11, PK-A13b (blocked by OCD-9: direct vs indirect verifier obligations)
- Schema validation vectors (isolated)
- CI binding vectors
- Freshness policy vectors

## How to Use

### Component vectors

A conforming second implementation must:
1. Parse each vector's `input`
2. Produce the exact `expected_canonical_utf8` bytes (JCS vectors)
3. Hash those bytes with SHA-256 and match `expected_sha256`
4. For Merkle vectors: compute root from leaves and match `expected_root`
5. For receipt vectors: strip v0 signature fields from root level, then canonicalize

### Pack specimen

A conforming verifier must:
1. Load `pack/golden_minimal/pack_manifest.json`
2. Run the full verification pipeline against the 5-file directory
3. Produce `passed: true` with 0 errors
4. Match all expected values in `pack/expected_outputs.json` (head_hash, attestation_sha256, file hashes, etc.)
5. Ed25519 verification uses only the embedded `signer_pubkey` — no external keystore needed

## Specimen Trust Model

This corpus uses deterministic test material to make outputs reproducible; it is
not an example operational signing workflow. The distinction matters:

| Property | Conformance specimen | Operational signing |
|----------|---------------------|-------------------|
| Key material | Deterministic seed (zero bytes) | Real generated keypair |
| Embedded pubkey | Authoritative for verification | Supplementary — trust root is keystore |
| Purpose | Prove contract portability | Prove evidence integrity |

Do not use conformance specimen patterns as a template for production trust chains.

## Contract References

- JCS: `docs/contracts/PACK_CONTRACT.md` §3
- Merkle: `docs/contracts/PACK_CONTRACT.md` §7
- Receipt projection: `docs/contracts/PACK_CONTRACT.md` §4
- Pack verification: `docs/contracts/PACK_CONTRACT.md` §8-§11
- Layer doctrine: `docs/contracts/VERIFICATION_LAYERS.md`
