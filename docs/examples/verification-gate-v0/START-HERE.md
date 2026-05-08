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
- `assay` - only needed for the optional tamper demo

On macOS with Homebrew:

```bash
brew install jq cosign
```

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y jq python3
```

For `cosign`, use Sigstore's official installation instructions for your
platform:

```text
https://docs.sigstore.dev/cosign/system_config/installation/
```

If you use Linuxbrew, the macOS command also works:

```bash
brew install jq cosign
```

On Ubuntu/Debian without Linuxbrew, Sigstore documents release binaries and
`.deb` packages. Follow that page for your CPU architecture, then put the
`cosign` binary on your `PATH`. For stricter environments, verify the Cosign
binary itself using Sigstore's release-verification instructions on the same
page.

Check your tools:

```bash
jq --version
cosign version
python3 --version
```

For the optional tamper demo, install the Assay CLI:

```bash
python3 -m pip install assay-ai
assay --help
```

If one of these commands is missing, install it first.

## What This Sample Answers

This sample answers one question:

Can someone verify that a GitHub workflow produced a signed verification
judgment about a specific evidence pack?

GitHub and Sigstore can prove an artifact was produced by a workflow. Assay
adds the reviewer packet around that proof: the evidence object, the
verification judgment, separate verdict channels, scope language, and explicit
caveats about what did and did not run.

## The Three Objects

| Human Name | Technical File | Meaning |
|---|---|---|
| Evidence Box | `proof-pack/pack_manifest.json` | The thing being checked. |
| Verification Report | `signed-report/verify_report.json` | What verification decided. |
| Signature Proof | `signed-report/verify_report.sigstore.json` | Who signed the decision. |

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
Overall: PASS (profile: integrity_required)
```

The script prints more detail than this. These are the lines to look for first.

## Optional: See Tamper Rejection

This demo copies the sample to a temporary directory, changes it, and shows
that verification rejects the changed copy:

```bash
bash scripts/demo_tamper_verification_gate_sample.sh
```

Expected result:

```text
Clean sample result: VERIFIED OK
Report tamper result: REJECTED
Pack tamper result: REJECTED
```

The report tamper changes the signed Verification Report. The pack tamper
changes a file inside the Evidence Box while leaving the manifest behind.

## What "Verified OK" Means

It means:

- The Verification Report refers to the same Evidence Box.
- The Evidence Box passed the required integrity check.
- The Verification Report was signed by the expected GitHub Actions workflow.

The certificate identity must exactly match:

```text
https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge
```

This is the workflow identity for this one sample. Future runs will have their
own expected workflow identity. This is an exact identity check, not a
substring search; a workflow from another repo or fork would not satisfy the
command.

There are two signature layers:

- `proof-pack/pack_signature.sig` belongs to the proof pack itself.
- `signed-report/verify_report.sigstore.json` belongs to the public
  Verification Report.

The main verification script checks the Sigstore signature on the public
Verification Report and checks the proof-pack manifest hashes. The tamper demo
also uses `assay verify-pack` to show that changing a file inside the proof
pack is rejected. The proof pack's Ed25519 signature is present in this sample;
the public reviewer walkthrough focuses on the signed Verification Report and
does not make a trust claim about the proof-pack signer identity.

Important: `overall_verdict=PASS` only means the required integrity check
passed for `evaluation_profile=integrity_required`. It does not mean every
possible check was run. A screenshot of `overall_verdict=PASS` without the
evaluation profile is incomplete.

## What Passed

- Integrity: `PASS`

In plain English: the evidence pack matched its manifest, and the signed
judgment points to that same pack.

## What Did Not Run

- Claim correctness: `NOT_EVALUATED`
- Replay: `NOT_RUN`
- Trust policy: `NOT_EVALUATED`

In plain English: this sample does not judge whether a claim is true, does not
rerun behavior, and does not apply a trust policy. That is normal for this
integrity-only sample; a stricter packet would need those channels turned on
and documented.

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
