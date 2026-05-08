# Verify an Assay PR Verification Report

This runbook verifies a signed Assay PR verification artifact.

The artifact set is:

```text
pack_manifest.json
verify_report.json
verify_report.sigstore.json
```

`pack_manifest.json` identifies the evidence object. `verify_report.json`
states the verification judgment. `verify_report.sigstore.json` proves which
GitHub Actions workflow signed that judgment.

This is not ledger acceptance, production authorization, or a scorecard. It is
the portable verification judgment for one evidence pack.

## Prerequisites

```bash
gh auth status
cosign version
python3 --version
```

On macOS, install `cosign` with:

```bash
brew install cosign
```

## Download the live artifact

The first live signed Verification Gate artifact was produced by Assay PR
`#114`, workflow run `25538860666`.

```bash
rm -rf /tmp/assay-verify-artifact
mkdir -p /tmp/assay-verify-artifact

gh run download 25538860666 \
  -R Haserjian/assay \
  -n assay-verify-report \
  -D /tmp/assay-verify-artifact

cd /tmp/assay-verify-artifact
ls -1
```

Expected files:

```text
pack_manifest.json
verify.stdout.json
verify_report.json
verify_report.sigstore.json
```

`verify.stdout.json` is included for operator diagnostics. The portable public
contract is `verify_report.json` plus `pack_manifest.json`.

## Inspect the report

```bash
python -m json.tool verify_report.json | head -80
```

Confirm the separated verdict channels:

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
  overall_reason
}' verify_report.json
```

For the first live artifact, the important fields were:

```text
integrity_verdict=PASS
claim_verdict=NOT_EVALUATED
replay_verdict=NOT_RUN
trust_verdict=NOT_EVALUATED
overall_verdict=PASS
evaluation_profile=integrity_required
required_channels=integrity
```

That means the evidence object was intact under the `integrity_required`
profile. It does not mean claim, replay, or trust channels were evaluated.

## Confirm the pack root

The report and manifest must name the same pack root:

```bash
python - <<'PY'
import json
from pathlib import Path

report = json.loads(Path("verify_report.json").read_text())
manifest = json.loads(Path("pack_manifest.json").read_text())

report_root = report["pack_root_sha256"]
manifest_root = manifest["pack_root_sha256"]

print("report_pack_root =", report_root)
print("manifest_pack_root =", manifest_root)

if report_root != manifest_root:
    raise SystemExit("pack root mismatch")
PY
```

## Verify the signature

For the first live PR artifact, the Sigstore certificate identity was:

```text
https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/114/merge
```

Verify the report with that exact identity and the GitHub Actions OIDC issuer:

```bash
cosign verify-blob verify_report.json \
  --bundle verify_report.sigstore.json \
  --certificate-identity "https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/114/merge" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Expected output:

```text
Verified OK
```

Do not verify only that "some valid signer" signed the report. Verify the
expected workflow identity for the run you are trusting.

## Inspect the signing identity for another run

Future pull-request runs will use a different `refs/pull/<number>/merge`
identity. Extract the certificate from the bundle and inspect the subject
alternative name:

```bash
python - <<'PY'
import base64
import json
from pathlib import Path

bundle = json.loads(Path("verify_report.sigstore.json").read_text())
Path("cert.pem").write_bytes(base64.b64decode(bundle["cert"]))
PY

openssl x509 \
  -in cert.pem \
  -noout \
  -subject \
  -issuer \
  -ext subjectAltName
```

Use the URI from `X509v3 Subject Alternative Name` as the
`--certificate-identity` value.

## What this proves

- The workflow uploaded a portable `verify_report.json`.
- The report binds back to `pack_manifest.json` through `pack_root_sha256`.
- The report signature verifies against a specific GitHub Actions workflow
  identity.
- The report separates integrity, claim, replay, trust, and overall verdicts.

## What this does not prove

- It does not prove production authorization.
- It does not prove ledger acceptance.
- It does not prove a scorecard interpretation.
- It does not prove that optional channels were evaluated when they say
  `NOT_EVALUATED` or `NOT_RUN`.
- It does not prove trust in a workflow identity unless the verifier expected
  that exact identity.

Doctrine:

```text
Pack root proves the evidence object.
Verify report states the verification judgment.
Signature bundle proves provenance of the judgment.
Ledger index proves accepted/citable position.
Scorecard explains interpretation.
```
