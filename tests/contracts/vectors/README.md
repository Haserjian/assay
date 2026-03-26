# Conformance Vectors — First Pass

**Generated**: 2026-03-25
**Contract version**: Pack Contract v0 (see `docs/contracts/PACK_CONTRACT.md` for freeze status)
**Hash format**: Raw hex (OCD-1 resolved)

## What This Corpus Covers

| File | Layer | Vectors | Proves |
|------|-------|---------|--------|
| `jcs_vectors.json` | Layer 1 (RFC 8785) | 16 golden | JCS canonicalization produces exact bytes and hashes |
| `merkle_vectors.json` | Layer 1 (SHA-256 tree) | 4 golden + 2 adversarial | Merkle root, inclusion proofs, odd-node duplication |
| `receipt_projection_vectors.json` | Layer 2 (projection) | 3 golden + 2 assertions | Signature stripping, root-only doctrine, hash equivalence |

## What This Corpus Does Not Cover

- Full pack vectors (require building real signed packs — deferred to second pass)
- Pack adversarial vectors (PK-A01 through PK-A18 — require pack fixtures)
- PK-A11, PK-A13b (blocked by OCD-9: direct vs indirect verifier obligations)
- Schema validation vectors
- CI binding vectors

## How to Use

A conforming second implementation must:
1. Parse each vector's `input`
2. Produce the exact `expected_canonical_utf8` bytes (JCS vectors)
3. Hash those bytes with SHA-256 and match `expected_sha256`
4. For Merkle vectors: compute root from leaves and match `expected_root`
5. For receipt vectors: strip v0 signature fields from root level, then canonicalize

## Contract References

- JCS: `docs/contracts/PACK_CONTRACT.md` §3
- Merkle: `docs/contracts/PACK_CONTRACT.md` §7
- Receipt projection: `docs/contracts/PACK_CONTRACT.md` §4
- Layer doctrine: `docs/contracts/VERIFICATION_LAYERS.md`
