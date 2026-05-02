# Assay CI Receipts

This repository emits a portable pytest evidence pack:

- `results.xml` - JUnit test output
- `pytest.log` - pytest stdout/stderr capture
- `pytest-exit-code.txt` - original pytest process exit code
- `receipt-status.txt` - receipt generation status
- `signature-status.txt` - Sigstore signing status
- `verification-status.txt` - Sigstore verification status
- `upload-status.txt` - upload status used by the final gate
- `receipt.json` - the signed receipt blob
- `receipt.json.sigstore.json` - the Sigstore bundle for the signed blob

The invariant is byte-level: a gated episode is not just "CI passed." It is
"these exact bytes were tested by this exact workflow identity, produced these
exact artifacts, and the receipt can be independently verified later."

## Settlement States

`PASS` means pytest exited `0`, receipt generation succeeded, the Sigstore
bundle was created, the bundle verified against the expected GitHub Actions
workflow identity, and the evidence upload step succeeded.

`HONEST_FAIL` means pytest exited nonzero, but `receipt-status.txt`,
`signature-status.txt`, `verification-status.txt`, and `upload-status.txt` are
all `ok`. This is a trusted receipt for a failed test run.

`TAMPERED_OR_BROKEN` means receipt generation, signing, verification, upload, or
artifact hash verification failed. Treat this as an integrity failure, not a
pytest failure.

Pytest failure is allowed to be honest. Receipt, signature, verification, and
upload failure is not.

One operational detail: upload success is only knowable after the evidence pack
has already been sent. The workflow therefore includes the status breadcrumbs in
the uploaded evidence pack, then updates the workspace copy of
`upload-status.txt` from the `actions/upload-artifact` outcome before the final
gate runs.

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
