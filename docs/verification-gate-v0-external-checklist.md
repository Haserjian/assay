# Verification Gate v0 External Checklist

Use this checklist when asking an external reviewer to verify the Assay
Verification Gate v0 sample.

The goal is not for the reviewer to approve Assay as a product. The goal is
for the reviewer to verify the sample artifact and explain what it proves and
what it does not prove.

## Prerequisites

Required for the committed sample:

```bash
jq --version
cosign version
python3 --version
```

Only needed for the optional tamper demo:

```bash
assay --help
```

On macOS or Linuxbrew:

```bash
brew install jq cosign
```

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y jq python3
```

`cosign` is not installed by the `apt-get` command above. Install it with
Sigstore's official instructions: [Cosign installation](https://docs.sigstore.dev/cosign/system_config/installation/).

For stricter environments, verify the Cosign binary itself using Sigstore's
release-verification instructions before using it as the verifier.

Install the Assay CLI only if you want to run the optional tamper demo:

```bash
python3 -m pip install assay-ai
```

Optional for downloading the live workflow artifact:

```bash
gh auth status
```

## Option A: Verify The Committed Sample

For a no-code introduction, read:

```text
docs/examples/verification-gate-v0/START-HERE.md
```

From the repository root:

```bash
bash scripts/verify_verification_gate_sample.sh
```

Expected result:

```text
Result: INTEGRITY VERIFIED
```

The script also prints the report's verdict channels and confirms that
`signed-report/verify_report.json` and `proof-pack/pack_manifest.json` name the same
`pack_root_sha256`.

A verdict channel is one kind of check. In this sample, only Integrity is
required. Claim, replay, and trust are visible so reviewers can see they did
not run.

Optional tamper check:

```bash
bash scripts/demo_tamper_verification_gate_sample.sh
```

Expected result:

```text
Clean sample result: INTEGRITY VERIFIED
Report tamper result: REJECTED
Pack tamper result: REJECTED
```

## Option B: Download The Live Run Artifact

The live proof run is:

- Workflow run: `25539107447`
- Artifact: `assay-verify-report`
- Certificate identity:
  `https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge`

That certificate identity is exact for this one-shot PR proof run. This packet
is a frozen snapshot, not a reproducible build target; future runs will sign
under their own expected workflow identity.

The identity ends in `@refs/pull/116/merge` because this sample is tied to a
historical PR workflow run, not a stable `main` or tag workflow. The signature
remains valid for this committed artifact; a future stable sample should be
signed from its own stable workflow ref.

Workflow artifacts are operational delivery objects and may expire according
to repository retention settings. If this download fails because the artifact
is no longer available, use Option A with the committed sample artifact. The
committed sample keeps the complete proof pack under
`docs/examples/verification-gate-v0/proof-pack/` and the signed public report
under `docs/examples/verification-gate-v0/signed-report/`.

```bash
rm -rf /tmp/assay-buyer-check
mkdir -p /tmp/assay-buyer-check

gh run download 25539107447 \
  -R Haserjian/assay \
  -n assay-verify-report \
  -D /tmp/assay-buyer-check

cd /tmp/assay-buyer-check
find . -maxdepth 2 -type f | sort
```

Expected files:

```text
pack_manifest.json
verify.stdout.json
verify_report.json
verify_report.sigstore.json
```

Inspect the verdict channels:

```bash
jq '{
  pack_root_sha256,
  integrity_verdict,
  claim_verdict,
  replay_verdict,
  trust_verdict,
  overall_verdict,
  evaluation_profile,
  required_channels,
  optional_channels,
  unevaluated_channels
}' verify_report.json
```

Verify the signed report:

```bash
cosign verify-blob verify_report.json \
  --bundle verify_report.sigstore.json \
  --certificate-identity "https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The `--certificate-identity` value is an exact identity check, not a substring
search. A workflow from another repo or fork would not satisfy this command.

## Questions The Reviewer Should Answer

1. What is the evidence object?
2. What is the verification judgment?
3. What identity signed the judgment?
4. Which verdict channels were evaluated?
5. Which verdict channels were not evaluated?
6. What should not be inferred from this sample?
7. If the reviewer ran the script, what certificate identity was printed under
   "Signed by expected GitHub Actions identity"?

## Expected Answers

1. For the committed sample, `proof-pack/pack_manifest.json` identifies the
   evidence object. For the live workflow download, this file is
   `pack_manifest.json`.
2. For the committed sample, `signed-report/verify_report.json` states the
   verification judgment. For the live workflow download, this file is
   `verify_report.json`.
3. For the committed sample, `signed-report/verify_report.sigstore.json`
   proves the judgment was signed by the expected GitHub Actions workflow
   identity for PR `#116`. For the live workflow download, this file is
   `verify_report.sigstore.json`.
4. The Integrity verdict channel was evaluated and passed for the
   `integrity_required` profile.
5. Claim, replay, and trust channels were not evaluated in this sample.
6. The sample does not prove production authorization, legal compliance,
   ledger acceptance, scorecard interpretation, full claim evaluation, replay
   evaluation, or trust-policy evaluation.
7. The script prints:
   `https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge`.

Important: a screenshot of `overall_verdict=PASS` without
`evaluation_profile=integrity_required` is incomplete.

The `integrity_required` profile means only the Integrity channel is required
for this sample. This checklist does not define or demonstrate stricter
profiles.
