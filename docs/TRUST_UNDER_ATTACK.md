# Trust Under Attack: Assay Adversarial Verification Report

**16 attacks. 16 deterministic catches. 0 false passes.**

Assay's verifier is tested against a suite of adversarial attacks that simulate real-world tampering of AI execution evidence. Every attack produces a deterministic error code. Every attack is caught. This report documents the results.

Run it yourself: `pip install assay-ai && pytest tests/assay/test_adversarial_attacks.py -v`

---

## Results

| # | Attack | What the attacker does | Expected error | Result |
|---|--------|----------------------|----------------|--------|
| A1 | **Dropped step** | Remove an inconvenient receipt from the middle of the chain | `E_MANIFEST_TAMPER` | CAUGHT |
| A2 | **Reordered steps** | Shuffle receipts to disguise execution order | `E_MANIFEST_TAMPER` | CAUGHT |
| A3 | **Receipt injection** | Insert a fabricated receipt to inflate evidence | `E_MANIFEST_TAMPER` | CAUGHT |
| A4 | **Timestamp rollback** | Backdate receipt timestamps to appear fresher | `E_MANIFEST_TAMPER` | CAUGHT |
| A5 | **Stale evidence replay** | Submit an old valid pack as if it were current | `E_PACK_STALE` | CAUGHT |
| A6 | **Cross-signer forgery** | Sign a pack with an unauthorized key | Lockfile `signer_policy` rejection | CAUGHT |
| A7 | **Evidence substitution** | Swap receipt contents from a different valid pack | `E_MANIFEST_TAMPER` | CAUGHT |
| A8 | **Replayed receipt** | Duplicate a legitimate receipt into a pack | `E_MANIFEST_TAMPER` | CAUGHT |
| A9 | **Receipt count lie** | Modify manifest to claim fewer receipts than exist | `E_PACK_SIG_INVALID` | CAUGHT |
| A10 | **Attestation integrity lie** | Claim PASS in attestation but corrupt the receipts | `E_PACK_SIG_INVALID` | CAUGHT |
| A11 | **Upgraded status** | Change answer from PARTIAL to ANSWERED without adding evidence | `VQ001_MISSING_CITATION` | CAUGHT |
| A12a | **Prohibited term: "guarantee"** | Inject commitment language into answers | `VQ005_PROHIBITED_COMMITMENT` | CAUGHT |
| A12b | **Prohibited term: "always"** | Inject absolutist language into answers | `VQ005_PROHIBITED_COMMITMENT` | CAUGHT |
| A13 | **Commitment type bypass** | Use COMMITMENT claim type under conservative policy | `VQ010_CLAIM_TYPE_POLICY_VIOLATION` | CAUGHT |
| A14 | **Lockfile hash swap** | Modify answers after lockfile was pinned | `VQ003_PACK_HASH_MISMATCH` | CAUGHT |
| A15 | **Inconsistent status** | Mark INSUFFICIENT_EVIDENCE but assert answer_bool=true | `VQ008_ANSWER_STATUS_INVALID` | CAUGHT |

---

## How Detection Works

### Proof pack integrity (A1-A10)

Every Assay proof pack contains 5 files:

```
proof_pack/
  receipt_pack.jsonl      # AI execution receipts (JCS-canonical, hash-chained)
  verify_report.json      # Integrity check results
  verify_transcript.md    # Human-readable summary
  pack_manifest.json      # SHA-256 hashes of all files + attestation
  pack_signature.sig      # Ed25519 signature over pack_manifest.json
```

**Any change to any file** breaks the SHA-256 hash in the manifest. Any change to the manifest breaks the Ed25519 signature. This is why attacks A1-A4 and A7-A8 all produce `E_MANIFEST_TAMPER`: the file hash no longer matches.

**Coordinated tampering** (changing a file AND updating its hash in the manifest) still fails because the manifest signature was computed over the original content (A9, A10).

**Stale replay** (A5) is caught by `--max-age-hours`, which checks the pack's timestamp against the current time.

**Cross-signer forgery** (A6) is caught at L1+ by the lockfile's `signer_policy: allowlist`, which pins allowed signer fingerprints. At L0 (no lockfile), any signer can produce a valid pack -- this is by design for developer evaluation.

### VendorQ answer verification (A11-A15)

VendorQ adds 10 deterministic rules on top of pack integrity:

- **VQ001**: Every factual claim must cite evidence
- **VQ003**: Answer hash must match lockfile
- **VQ005**: Prohibited commitment terms are blocked ("guarantee", "always", "will ensure")
- **VQ008**: Status must be consistent with content (INSUFFICIENT_EVIDENCE cannot assert true)
- **VQ009**: answer_bool=true requires affirmative evidence support
- **VQ010**: COMMITMENT claim type is blocked under conservative policy

These rules are fail-closed: if the verifier can't confirm a claim, it flags it. No false passes.

---

## What This Proves and Does Not Prove

**Proves:**
- Any post-creation modification to receipts, manifests, signatures, answers, or lockfiles is detected
- Detection is deterministic: same inputs always produce the same error codes
- 16 distinct attack strategies all fail with specific, documented error codes

**Does not prove:**
- That the original data was truthful (a compromised host can fabricate consistent receipts)
- That instrumentation is complete (uninstrumented calls produce no receipts)
- Legal or regulatory compliance

**Boundary statement:** Assay proves that evidence hasn't been tampered with and that claims trace to that evidence. It does not prove the evidence is true, complete, or legally sufficient. Each gap has a named upgrade path (trust tiers T0-T3).

---

## Reproduce These Results

```bash
pip install assay-ai
git clone https://github.com/Haserjian/assay.git
cd assay
pip install -e ".[dev]"
pytest tests/assay/test_adversarial_attacks.py -v
```

All 16 tests pass in < 1 second on commodity hardware. The test suite runs in CI on every pull request.

---

*Assay v1.15.1+ | Test suite: `tests/assay/test_adversarial_attacks.py` | 16 tests, 0 failures*
