#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE_DIR="$ROOT_DIR/docs/examples/verification-gate-v0"
REPORT="$SAMPLE_DIR/signed-report/verify_report.json"
BUNDLE="$SAMPLE_DIR/signed-report/verify_report.sigstore.json"
MANIFEST="$SAMPLE_DIR/proof-pack/pack_manifest.json"
IDENTITY="https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge"
ISSUER="https://token.actions.githubusercontent.com"

for command in jq cosign python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 127
  fi
done

for path in "$REPORT" "$BUNDLE" "$MANIFEST"; do
  if [[ ! -f "$path" ]]; then
    echo "missing sample file: $path" >&2
    exit 1
  fi
done

echo "Assay Verification Gate v0 sample"
echo "This verifies the signed public report and checks it binds to the proof-pack manifest."
echo
echo "Verdict channels:"
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
  unevaluated_channels,
  overall_reason
}' "$REPORT"

echo
echo "Checking report/manifest pack root..."
python3 - "$REPORT" "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
manifest = json.loads(Path(sys.argv[2]).read_text())

report_root = report["pack_root_sha256"]
manifest_root = manifest["pack_root_sha256"]

print(f"report_pack_root = {report_root}")
print(f"manifest_pack_root = {manifest_root}")

if report_root != manifest_root:
    raise SystemExit("pack root mismatch")
PY

echo
echo "Checking proof-pack manifest file set..."
python3 - "$SAMPLE_DIR/proof-pack" <<'PY'
import json
import sys
from pathlib import Path

pack_dir = Path(sys.argv[1])
manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
missing = [
    name
    for name in manifest["expected_files"]
    if not (pack_dir / name).exists()
]
if missing:
    raise SystemExit("missing proof-pack file(s): " + ", ".join(missing))
print("proof_pack_files = " + ", ".join(manifest["expected_files"]))
PY

echo
echo "Verifying Sigstore bundle..."
cosign verify-blob "$REPORT" \
  --bundle "$BUNDLE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
