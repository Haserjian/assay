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
echo "This verifies the signed public report, checks it binds to the proof-pack manifest, and asserts the report verdict."
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
echo "Checking proof-pack manifest file set and hashes..."
python3 - "$SAMPLE_DIR/proof-pack" <<'PY'
import hashlib
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

hash_failures = []
for file_info in manifest["files"]:
    path = pack_dir / file_info["path"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = file_info["sha256"]
    if actual != expected:
        hash_failures.append(f"{file_info['path']}: expected {expected}, got {actual}")

if hash_failures:
    raise SystemExit("proof-pack file hash mismatch: " + "; ".join(hash_failures))

print("proof_pack_files = " + ", ".join(manifest["expected_files"]))
PY

echo
echo "Checking report verdict..."
jq -e '
  (.passed == true) and
  (.overall_verdict == "PASS") and
  (.integrity_verdict == "PASS") and
  (.evaluation_profile == "integrity_required")
' "$REPORT" >/dev/null || {
  echo "verification report verdict is not PASS for integrity_required profile" >&2
  exit 1
}

echo
echo "Verifying Sigstore bundle and expected signer identity..."
cosign verify-blob "$REPORT" \
  --bundle "$BUNDLE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"

echo
echo "Result: VERIFIED OK"
echo
echo "Human summary:"
echo "  Evidence Box: $MANIFEST"
echo "  Verification Report: $REPORT"
echo "  Signature Proof: $BUNDLE"
echo "  Integrity: $(jq -r '.integrity_verdict' "$REPORT")"
echo "  Claim correctness: $(jq -r '.claim_verdict' "$REPORT")"
echo "  Replay: $(jq -r '.replay_verdict' "$REPORT")"
echo "  Trust policy: $(jq -r '.trust_verdict' "$REPORT")"
echo "  Overall: $(jq -r '.overall_verdict' "$REPORT") for $(jq -r '.evaluation_profile' "$REPORT") profile"
echo "    This means the required integrity check passed."
echo "    It does not mean every possible check was run."
echo "  Signed by expected GitHub Actions identity:"
echo "    $IDENTITY"
echo
echo "Plain English:"
echo "  This proves the public verification report is intact, refers to the"
echo "  right evidence pack, and was signed by the expected GitHub workflow."
echo
echo "Do NOT infer:"
echo "  legal compliance, production approval, full claim correctness,"
echo "  replay equivalence, trust-policy approval, ledger acceptance, or"
echo "  scorecard interpretation."
