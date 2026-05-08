#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/docs/examples/verification-gate-v0"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
VERBOSE=0

if [[ "${1:-}" == "--verbose" ]]; then
  VERBOSE=1
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--verbose]" >&2
  exit 2
fi

for command in assay cosign python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    if [[ "$command" == "assay" ]]; then
      echo "missing required command: assay" >&2
      echo "install it with: python3 -m pip install assay-ai" >&2
      echo "assay is only needed for the optional proof-pack tamper demo." >&2
    else
      echo "missing required command: $command" >&2
    fi
    exit 127
  fi
done

IDENTITY="https://github.com/Haserjian/assay/.github/workflows/lineage.yml@refs/pull/116/merge"
ISSUER="https://token.actions.githubusercontent.com"

run_cosign_verify() {
  local report="$1"
  local bundle="$2"

  if [[ "$VERBOSE" -eq 1 ]]; then
    cosign verify-blob "$report" \
      --bundle "$bundle" \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER"
  else
    cosign verify-blob "$report" \
      --bundle "$bundle" \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER" >/dev/null 2>&1
  fi
}

run_pack_verify() {
  local pack_dir="$1"

  if [[ "$VERBOSE" -eq 1 ]]; then
    assay verify-pack "$pack_dir"
  else
    assay verify-pack "$pack_dir" >/dev/null 2>&1
  fi
}

cp -R "$SOURCE_DIR" "$TMP_ROOT/clean"
cp -R "$SOURCE_DIR" "$TMP_ROOT/report-tamper"
cp -R "$SOURCE_DIR" "$TMP_ROOT/pack-tamper"

CLEAN_REPORT="$TMP_ROOT/clean/signed-report/verify_report.json"
CLEAN_BUNDLE="$TMP_ROOT/clean/signed-report/verify_report.sigstore.json"
CLEAN_PACK="$TMP_ROOT/clean/proof-pack"

echo "Clean sample:"
run_cosign_verify "$CLEAN_REPORT" "$CLEAN_BUNDLE"
run_pack_verify "$CLEAN_PACK"
echo "Clean sample result: VERIFIED OK"

REPORT_TAMPER_REPORT="$TMP_ROOT/report-tamper/signed-report/verify_report.json"
REPORT_TAMPER_BUNDLE="$TMP_ROOT/report-tamper/signed-report/verify_report.sigstore.json"

python3 - "$REPORT_TAMPER_REPORT" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text())
data["tamper_demo_note"] = "This field was added after signing."
path.write_text(json.dumps(data, indent=2) + "\n")
PY

echo
echo "Report tamper:"
if run_cosign_verify "$REPORT_TAMPER_REPORT" "$REPORT_TAMPER_BUNDLE"; then
  echo "Report tamper unexpectedly verified." >&2
  exit 1
else
  echo "Report tamper result: REJECTED"
  echo "Reason: signature did not match the tampered report; this is expected."
fi

PACK_TAMPER_PACK="$TMP_ROOT/pack-tamper/proof-pack"
printf '\nTAMPERED BY DEMO\n' >> "$PACK_TAMPER_PACK/verify_transcript.md"

echo
echo "Pack tamper:"
if run_pack_verify "$PACK_TAMPER_PACK"; then
  echo "Pack tamper unexpectedly verified." >&2
  exit 1
else
  echo "Pack tamper result: REJECTED"
  echo "Reason: proof-pack file hash no longer matches pack_manifest.json; this is expected."
fi
