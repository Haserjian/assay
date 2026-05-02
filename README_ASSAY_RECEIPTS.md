# Assay CI Receipts

This repository emits a portable pytest evidence pack:

- `results.xml` - JUnit test output
- `pytest.log` - pytest stdout/stderr capture
- `pytest-exit-code.txt` - original pytest process exit code
- `receipt-status.txt` - receipt generation status
- `signature-status.txt` - Sigstore signing status
- `verification-status.txt` - Sigstore verification status
- `receipt.json` - the signed receipt blob
- `receipt.json.sigstore.json` - the Sigstore bundle for the signed blob

The invariant is byte-level: a gated episode is not just "CI passed." It is
"these exact bytes were tested by this exact workflow identity, produced these
exact artifacts, and the receipt can be independently verified later."

## Settlement States

`PASS` means pytest exited `0`, receipt generation succeeded, the Sigstore
bundle was created, the bundle verified against the expected GitHub Actions
workflow identity, and GitHub accepted the evidence artifact upload.

`HONEST_FAIL` means pytest exited nonzero, but `receipt-status.txt`,
`signature-status.txt`, and `verification-status.txt` are all `ok`, and the
workflow's final gate observed a successful `actions/upload-artifact` outcome.
This is a trusted receipt for a failed test run.

`TAMPERED_OR_BROKEN` means receipt generation, signing, verification, upload, or
artifact hash verification failed. Treat this as an integrity failure, not a
pytest failure.

Pytest failure is allowed to be honest. Receipt, signature, verification, and
upload failure is not.

One operational detail: upload success is only knowable after the evidence pack
has already been sent. The portable evidence pack therefore does not include an
`upload-status.txt` claim. The workflow keeps that as workspace-only final-gate
state, derived from the `actions/upload-artifact` step outcome.

## Signed Blob and Bundle

Keep the Sigstore bundle beside the receipt. Do not embed it inside
`receipt.json`.

`receipt.json` is the signed blob. `receipt.json.sigstore.json` contains the
signature, certificate, and transparency-log verification material needed by
Cosign.

## CI Verification

The workflow signs and verifies the receipt with GitHub OIDC keyless signing:

```bash
cosign verify-blob receipt.json \
  --bundle receipt.json.sigstore.json \
  --certificate-identity "https://github.com/OWNER/REPO/.github/workflows/assay-receipt.yml@refs/heads/BRANCH" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

For this repository on `main`, the expected identity is:

```text
https://github.com/Haserjian/assay/.github/workflows/assay-receipt.yml@refs/heads/main
```

For pull requests or release branches, replace the final ref with the workflow
ref stored in `receipt.json` at `workflow.workflow_ref`.

For pull request events, the receipt subject is the exact tree GitHub checked
out for that event. Depending on the event configuration, that may be a PR merge
ref rather than only the contributor head commit.

## Proof Tier

This flow is Tier 3 once `receipt.json` has a verified
`receipt.json.sigstore.json` bundle:

- Tier 0: test outputs captured
- Tier 1: artifact bytes pinned with SHA-256
- Tier 2: GitHub Actions run and workflow identity captured
- Tier 3: receipt signed and verified with Sigstore keyless identity

The workflow also attempts to emit a GitHub artifact attestation for
`receipt.json`. Treat that as a non-blocking Tier 4 add-on in this MVP, not the
primitive receipt. The portable nucleus remains `receipt.json` plus
`receipt.json.sigstore.json`.

## Local Emitter Check

You can exercise the unsigned local emitter with:

```bash
make assay-receipt-local
```

This produces local `results.xml`, `pytest.log`, `pytest-exit-code.txt`, and
`receipt.json`. Local output is useful for script development, but it is not a
Tier 3 receipt until `receipt.json` is signed and verified with a Sigstore
bundle.
