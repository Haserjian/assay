#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/docs/examples/verification-gate-v0"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

for command in cosign python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 127
  fi
done

cp -R "$SOURCE_DIR" "$TMP_ROOT/verification-gate-v0"

REPORT="$TMP_ROOT/verification-gate-v0/signed-report/verify_report.json"
BUNDLE="$TMP_ROOT/verification-gate-v0/signed-report/verify_report.sigstore.json"
IDENTITY="https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge"
ISSUER="https://token.actions.githubusercontent.com"

echo "Clean sample:"
cosign verify-blob "$REPORT" \
  --bundle "$BUNDLE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
echo "Clean sample result: VERIFIED OK"

python3 - "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text())
data["tamper_demo_note"] = "This field was added after signing."
path.write_text(json.dumps(data, indent=2) + "\n")
PY

echo
echo "Tampered sample:"
if cosign verify-blob "$REPORT" \
  --bundle "$BUNDLE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"; then
  echo "Tampered sample unexpectedly verified." >&2
  exit 1
else
  echo "Tampered sample result: REJECTED"
fi
