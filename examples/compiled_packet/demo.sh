#!/usr/bin/env bash
# Compiled Packet Demo: init → compile → verify → gate
#
# Demonstrates the full compiled packet lifecycle:
#   1. Init a draft from a questionnaire
#   2. Compile a sealed, signed packet bound to a subject
#   3. Verify the packet (two-axis: integrity × completeness)
#   4. Run the fail-closed gate
#   5. Tamper with the manifest and show the gate blocking
#
# Usage (from repo root):
#   bash examples/compiled_packet/demo.sh
#
# Requires: assay installed (`pip install assay-ai`), Python 3.9+
# Exit 0 = demo completed. Exit 1 = something broke.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
PACK_DIR="$REPO_ROOT/examples/vendorq/demo_pack"
WORK_DIR="/tmp/compiled_packet_demo"

# ── Preflight ─────────────────────────────────────────────────────────
echo "=== Preflight ==="
preflight_ok=true
check() {
  if ! "$@" > /dev/null 2>&1; then
    echo "  FAIL: $*"; preflight_ok=false
  else
    echo "  OK:   $*"
  fi
}

check python3 -c "import assay"
check python3 -c "from assay.compiled_packet import compile_packet, verify_packet"
check command -v assay
check test -f "$DEMO_DIR/questionnaire.csv"
check test -d "$PACK_DIR"
check test -f "$REPO_ROOT/scripts/assay-gate.sh"

if [ "$preflight_ok" = false ]; then
  echo ""; echo "Preflight FAILED. Fix errors above before demoing."; exit 1
fi
echo ""

# ── Clean ─────────────────────────────────────────────────────────────
echo "=== Clean ==="
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
echo "  Work dir: $WORK_DIR"
echo ""

# ── Step 1: Derive subject digest from a real artifact ─────────────────
# In practice this is the SHA-256 of the artifact being assessed
# (a model checkpoint, a container image digest, a release tarball, etc.)
SUBJECT_DIGEST=$(python3 -c "
import hashlib, pathlib
# Demo: hash the questionnaire file as the 'artifact'
content = pathlib.Path('$DEMO_DIR/questionnaire.csv').read_bytes()
print('sha256:' + hashlib.sha256(content).hexdigest())
")
echo "=== 1. Subject ==="
echo "  subject_type:   artifact"
echo "  subject_id:     demo:compiled-packet-example@v1"
echo "  subject_digest: ${SUBJECT_DIGEST:0:32}..."
echo ""

# ── Step 2: Init draft ─────────────────────────────────────────────────
echo "=== 2. Init draft ==="
assay packet init \
  --questionnaire "$DEMO_DIR/questionnaire.csv" \
  --packs "$PACK_DIR" \
  --output "$WORK_DIR/draft"
echo ""

# ── Step 3: Compile sealed packet ─────────────────────────────────────
echo "=== 3. Compile ==="
assay packet compile \
  --draft "$WORK_DIR/draft" \
  --packs "$PACK_DIR" \
  --subject-type artifact \
  --subject-id "demo:compiled-packet-example@v1" \
  --subject-digest "$SUBJECT_DIGEST" \
  --output "$WORK_DIR/packet"
echo ""

# ── Step 4: Verify (human-readable) ───────────────────────────────────
echo "=== 4. Verify (human-readable) ==="
assay packet verify "$WORK_DIR/packet"
echo ""

# ── Step 5: Verify (JSON — the gate's input) ──────────────────────────
echo "=== 5. Verify --json ==="
VERIFY_JSON=$(assay packet verify "$WORK_DIR/packet" --json 2>/dev/null)
INTEGRITY=$(echo "$VERIFY_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['integrity_verdict'])")
ADMISSIBLE=$(echo "$VERIFY_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['admissible'])")
VERDICT=$(echo "$VERIFY_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])")
echo "  integrity:  $INTEGRITY"
echo "  admissible: $ADMISSIBLE"
echo "  verdict:    $VERDICT"
echo ""

# ── Step 6: Gate (should PASS) ────────────────────────────────────────
echo "=== 6. Gate (expect PASS) ==="
bash "$REPO_ROOT/scripts/assay-gate.sh" "$WORK_DIR/packet"
echo ""

# ── Step 7: Tamper with subject_digest and show gate blocking ─────────
echo "=== 7. Tamper: change subject_digest in manifest ==="
python3 -c "
import json, pathlib
p = pathlib.Path('$WORK_DIR/packet/packet_manifest.json')
manifest = json.loads(p.read_bytes())
manifest['subject']['subject_digest'] = 'sha256:' + 'cafebabe' * 8
p.write_text(json.dumps(manifest, indent=2))
print('  Mutated subject_digest → sha256:cafebabecafebabe...')
"
echo ""

echo "=== 8. Gate (expect BLOCKED) ==="
set +e
bash "$REPO_ROOT/scripts/assay-gate.sh" "$WORK_DIR/packet"
GATE_EXIT=$?
set -e
if [ "$GATE_EXIT" -ne 1 ]; then
  echo "  UNEXPECTED: gate returned exit $GATE_EXIT (expected 1)"
  exit 1
fi
echo ""
echo "  Gate correctly blocked tampered packet (exit 1)"
echo ""

# ── Summary ───────────────────────────────────────────────────────────
echo "========================================="
echo "  DEMO COMPLETE"
echo "========================================="
echo ""
echo "  Questionnaire:     $DEMO_DIR/questionnaire.csv"
echo "  Compiled packet:   $WORK_DIR/packet/"
echo "  Manifest:          $WORK_DIR/packet/packet_manifest.json"
echo "  Bindings:          $WORK_DIR/packet/claim_bindings.jsonl"
echo "  Signature:         $WORK_DIR/packet/packet_signature.sig"
echo "  Bundled packs:     $WORK_DIR/packet/packs/"
echo ""
echo "  Verify contract:   docs/specs/COMPILED_PACKET_VERIFY_CONTRACT.md"
echo "  Architecture:      docs/specs/COMPILED_PACKET_ARCHITECTURE.md"
echo ""
