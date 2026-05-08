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

This sample says nothing about whether any model, eval, or claim inside the
Evidence Box is true. It only proves the box was not altered under the
integrity check and that the report came from the expected workflow.

## Before You Start

For the main verification script, you need three command-line tools:

- `jq` - reads JSON
- `cosign` - verifies the signature
- `python3` - already installed on most Macs

The optional tamper demo also needs `assay`.

On macOS with Homebrew:

```bash
brew install jq cosign
```

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y jq python3
```

`cosign` is not installed by the `apt-get` command above. Install it with the
Sigstore instructions below.

For `cosign`, use Sigstore's official installation instructions for your
platform: [Cosign installation](https://docs.sigstore.dev/cosign/system_config/installation/).

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

A verdict channel is one kind of check. This sample shows four channels:
Integrity, Claim correctness, Replay, and Trust policy. Only Integrity is
required for this sample.

GitHub and Sigstore can prove an artifact was produced by a workflow. Assay
adds the reviewer packet around that proof: the evidence object, the
verification judgment, separate verdict channels, scope language, and explicit
caveats about what did and did not run.

## The Three Objects

| Human Name | Technical File | Meaning |
|---|---|---|
| Evidence Box | `proof-pack/pack_manifest.json` | The thing being checked. |
| Verification Report | `signed-report/verify_report.json` | What verification decided. |
| Signature Proof | `signed-report/verify_report.sigstore.json` | Who signed the public Verification Report. This is not `proof-pack/pack_signature.sig`. |

## Why Does The Identity Mention PR #116?

This committed sample is a frozen snapshot from a historical PR `#116`
workflow run, so the certificate identity ends in `@refs/pull/116/merge`.
That is expected.

The signature remains valid for this committed artifact, but this exact sample
is not meant to be reproduced from `main` or a release tag. Future stable
samples should be signed from their own stable workflow ref.

## Run One Command

From the repository root:

```bash
bash scripts/verify_verification_gate_sample.sh
```

Expected result:

```text
Result: INTEGRITY VERIFIED
```

If you see `Verified OK` from `cosign`, that is the signature check. The
important final line from this walkthrough is `Result: INTEGRITY VERIFIED`.

Expected output summary:

```text
Result: INTEGRITY VERIFIED
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
Clean sample result: INTEGRITY VERIFIED
Report tamper result: REJECTED
Pack tamper result: REJECTED
```

The report tamper changes the signed Verification Report. The pack tamper
changes a file inside the Evidence Box while leaving the manifest behind.

## What "Integrity Verified" Means

It means:

- The Verification Report refers to the same Evidence Box.
- The Evidence Box passed the required integrity check.
- The Verification Report was signed by the expected GitHub Actions workflow.
- Cosign verified the report against the Sigstore bundle, including the
  transparency-log material carried by the bundle.

Claim correctness, replay, and trust policy are visible so reviewers can see
they did not run.

The certificate identity must exactly match:

```text
https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge
```

This is an exact identity check, not a substring search; a workflow from
another repo or fork would not satisfy the command.

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

Could someone swap in a different proof pack? Not without detection here: the
Verification Report contains `pack_root_sha256`, the script checks it matches
the Evidence Box manifest, and the script checks the files against that
manifest. Changing the report to point at another pack would break the
Sigstore signature.

Important: `overall_verdict=PASS` only means the required integrity check
passed for `evaluation_profile=integrity_required`. It does not mean every
possible check was run. A screenshot of `overall_verdict=PASS` without the
evaluation profile is incomplete.

The `integrity_required` profile means this sample requires only the Integrity
channel to pass. This sample does not define or demonstrate stricter profiles;
a stricter packet would need claim, replay, or trust channels turned on and
documented.

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

`NOT_EVALUATED` and `NOT_RUN` both mean the channel did not contribute to the
sample passing. Replay says `NOT_RUN` because no replay was attempted.

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

- I got `Result: INTEGRITY VERIFIED` / I did not get it.
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
4. Which verdict channel passed?
5. Which verdict channels were not evaluated?
6. What should not be inferred from this sample?
7. If you ran the script, what certificate identity was printed under "Signed
   by expected GitHub Actions identity"?
