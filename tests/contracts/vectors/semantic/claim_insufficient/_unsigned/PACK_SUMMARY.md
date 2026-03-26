# Proof Pack Summary

**Pack ID:** `pack_deterministic_a1efcfcc`
**Run ID:** `sem-run-002`
**Signed by:** `semantics-signer`

## Verdicts

| Check | Result |
|-------|--------|
| Integrity | **PASS** |
| Claims | **FAILED** |

> **Honest failure**: the evidence is authentic (not tampered with),
> and it proves this run violated the declared standards.

## What Happened

- **1 receipts** recorded: 1 model_call
- **Time window:** 2026-01-15T11:59:00+00:00 to 2026-01-15T11:59:00+00:00

## Integrity Check

All file hashes match. The Ed25519 signature is valid.
This evidence has not been tampered with since creation.

## Claim Checks

| Claim | Result |
|-------|--------|
| `model_executed` | **PASS** |
| `guardian_checked` | **FAIL** |

## What This Proves

- The recorded evidence is authentic (signed, hash-verified)
- Some declared behavioral checks failed (see above)
- This is an honest failure: authentic evidence of a standards violation

## What This Does NOT Prove

- That every action was recorded (only recorded actions are in the pack)
- That model outputs are correct or safe
- That receipts were honestly created (tamper-evidence, not source attestation)
- That timestamps are externally anchored (local clock was used)
- That the signer key was not compromised

## Verify Independently

```bash
python3 -m pip install assay-ai && assay verify-pack tests/contracts/vectors/semantic/.assay_pack_staging_557z9auo
```
