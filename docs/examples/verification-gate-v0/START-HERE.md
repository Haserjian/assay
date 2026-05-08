# Start Here: Verification Gate v0

You do not need to read code or JSON to understand this sample.

## One-Minute Version

This sample checks whether a GitHub workflow signed a verification report about
a specific evidence pack. The sample passed the integrity check. It did not
evaluate claim correctness, replay, or trust policy.

This sample answers one question:

Can someone verify that a GitHub workflow produced a signed verification
judgment about a specific evidence pack?

## The Three Objects

| Human Name | Technical File | Meaning |
|---|---|---|
| Evidence Box | `proof-pack/pack_manifest.json` | The thing being checked. |
| Inspection Note / Verification Report | `signed-report/verify_report.json` | What verification decided. |
| Signature Proof | `signed-report/verify_report.sigstore.json` | Who signed the decision. |

The Inspection Note is the verification report.

## Run One Command

From the repository root:

```bash
bash scripts/verify_verification_gate_sample.sh
```

Expected result:

```text
Result: VERIFIED OK
```

If you see extra technical output from `cosign`, that is normal. The important
final line is `Result: VERIFIED OK`.

Expected output summary:

```text
Result: VERIFIED OK
Integrity: PASS
Claim correctness: NOT_EVALUATED
Replay: NOT_RUN
Trust policy: NOT_EVALUATED
```

## What "Verified OK" Means

It means:

- The Inspection Note / Verification Report refers to the same Evidence Box.
- The Evidence Box passed the required integrity check.
- The Inspection Note / Verification Report was signed by the expected GitHub
  Actions workflow.

Important: `overall_verdict=PASS` only means the required integrity check
passed. It does not mean every possible check was run.

## What Passed

- Integrity: `PASS`

In plain English: the evidence pack matched its manifest, and the signed
judgment points to that same pack.

## What Did Not Run

- Claim correctness: `NOT_EVALUATED`
- Replay: `NOT_RUN`
- Trust policy: `NOT_EVALUATED`

In plain English: this sample does not judge whether a claim is true, does not
rerun behavior, and does not apply a trust policy.

## Do Not Infer

Do not infer that this sample proves:

- legal compliance
- production approval
- full claim correctness
- replay equivalence
- trust-policy approval
- ledger acceptance
- scorecard interpretation

## Correct One-Sentence Summary

This sample proves that the evidence pack passed integrity verification and
that the verification judgment was signed by the expected GitHub workflow.

## If You Are Reviewing This For Tim

Send back:

- I got `Result: VERIFIED OK` / I did not get `Result: VERIFIED OK`.
- I think the Evidence Box is:
- I think the Inspection Note / Verification Report is:
- I think the Signature Proof is:
- I understand integrity passed while claim/replay/trust were not evaluated:
  yes/no
- Confusing part:

## Questions To Answer Back

1. What is the Evidence Box?
2. What is the Inspection Note / Verification Report?
3. What is the Signature Proof?
4. Which channel passed?
5. Which channels were not evaluated?
6. What should not be inferred from this sample?
