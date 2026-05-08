# Signed Verification Report - Sample

Internal milestone name: Verification Gate v0.

You do not need to read code or JSON to understand this sample.

## One-Minute Version

This sample checks whether a GitHub workflow signed a verification report about
a specific evidence pack. The sample passed the integrity check. It did not
evaluate claim correctness, replay, or trust policy.

Correct summary:

> The evidence pack passed integrity verification, and the verification report
> was signed by the expected GitHub workflow.

## Before You Start

You need three command-line tools:

- `jq` - reads JSON
- `cosign` - verifies the signature
- `python3` - already installed on most Macs

On macOS with Homebrew:

```bash
brew install jq cosign
```

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y jq python3
```

Install `cosign` using the current Sigstore instructions for your platform:

```text
https://docs.sigstore.dev/cosign/system_config/installation/
```

On Linux, that usually means downloading the latest `cosign-linux-amd64` or
matching architecture binary from Sigstore's release instructions, making it
executable, and putting it somewhere on your `PATH`.

Check your tools:

```bash
jq --version
cosign version
python3 --version
```

If one of these commands is missing, install it first.

## What This Sample Answers

This sample answers one question:

Can someone verify that a GitHub workflow produced a signed verification
judgment about a specific evidence pack?

## The Three Objects

| Human Name | Technical File | Meaning |
|---|---|---|
| Evidence Box | `proof-pack/pack_manifest.json` | The thing being checked. |
| Verification Report | `signed-report/verify_report.json` | What verification decided. |
| Signature Proof | `signed-report/verify_report.sigstore.json` | Who signed the decision. |

There are two signatures in this sample:

- `proof-pack/pack_signature.sig` belongs to the proof pack itself.
- `signed-report/verify_report.sigstore.json` belongs to the public
  Verification Report.

This walkthrough focuses on the Sigstore-signed public Verification Report.
The proof pack's Ed25519 signature is part of the artifact, but this script
does not exercise that signature.

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
Overall: PASS for integrity_required profile
```

The script prints more detail than this. These are the lines to look for first.

## What "Verified OK" Means

It means:

- The Verification Report refers to the same Evidence Box.
- The Evidence Box passed the required integrity check.
- The Verification Report was signed by the expected GitHub Actions workflow.

The workflow identity must match the expected
`https://github.com/Haserjian/assay/.github/workflows/...` identity. This is
an exact identity check, not a substring search; a workflow from another repo
or fork would not satisfy the command.

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

## If You Are Reviewing This Sample

Send back:

- I got `Result: VERIFIED OK` / I did not get `Result: VERIFIED OK`.
- I think the Evidence Box is:
- I think the Verification Report is:
- I think the Signature Proof is:
- I understand integrity passed while claim/replay/trust were not evaluated:
  yes/no
- Confusing part:

## Questions To Answer Back

1. What is the Evidence Box?
2. What is the Verification Report?
3. What is the Signature Proof?
4. Which channel passed?
5. Which channels were not evaluated?
6. What should not be inferred from this sample?

## Glossary

Some internal notes used the phrase "Inspection Note." In this sample, the
public name is Verification Report.

## Want This For Your Own Repo?

This sample is part of an Evidence Sprint: a fixed-scope pilot that turns one
AI/software claim set into a reviewer-ready evidence packet.

See [Evidence Sprint one-pager](../../evidence-sprint-one-pager.md).
