# Proof Pack Summary

**Pack ID:** `pack_20260304T061703_2c002032`
**Run ID:** `trace_20260304T061702_506b8914`
**Signed by:** `assay-local`

## Verdicts

| Check | Result |
|-------|--------|
| Integrity | **PASS** |
| Claims | **PASSED** |

## What Happened

- **4 receipts** recorded: 4 model_call
- **Providers:** anthropic, openai
- **Models:** claude-sonnet-4-5-20250929, gpt-4o, gpt-4o-mini
- **Total tokens:** 1,371
- **Time window:** 2026-03-04T06:17:02.807979+00:00 to 2026-03-04T06:17:02.973799+00:00

## Integrity Check

All file hashes match. The Ed25519 signature is valid.
This evidence has not been tampered with since creation.

## Claim Checks

| Claim | Result |
|-------|--------|
| `min_receipt_count` | **PASS** |
| `model_call_present` | **PASS** |

## What This Proves

- The recorded evidence is authentic (signed, hash-verified)
- All declared behavioral checks passed

## What This Does NOT Prove

- That every action was recorded (only recorded actions are in the pack)
- That model outputs are correct or safe
- That receipts were honestly created (tamper-evidence, not source attestation)
- That timestamps are externally anchored (local clock was used)
- That the signer key was not compromised

## Verify Independently

```bash
pip install assay-ai && assay verify-pack proof_pack_trace_20260304T061702_506b8914
```
