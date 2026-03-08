#!/usr/bin/env bash
# VendorQ Demo Reset: single-command rebuild of all demo artifacts.
#
# Usage (from repo root):
#   bash examples/vendorq/demo_reset.sh
#
# Produces: /tmp/vq_demo/ with all artifacts + runs tamper path.
# Exit 0 = ready to demo.  Exit 1 = something broke (fix before call).
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
WORK_DIR="/tmp/vq_demo"
PACK_DIR="$DEMO_DIR/demo_pack"

# ── Preflight ─────────────────────────────────────────────────────────
preflight_ok=true

check() {
  if ! "$@" > /dev/null 2>&1; then
    echo "  FAIL: $*"
    preflight_ok=false
  else
    echo "  OK:   $*"
  fi
}

echo "=== Preflight ==="
check python3 -c "import assay"
check python3 -c "from assay.vendorq_models import SCHEMA_VERSION_QUESTION"
check python3 -c "from assay.keystore import AssayKeyStore"
check python3 -c "from assay.proof_pack import ProofPack"
check test -f "$DEMO_DIR/sample_questionnaire.csv"
check test -f "$DEMO_DIR/build_demo_pack.py"
check command -v assay

if [ "$preflight_ok" = false ]; then
  echo ""
  echo "Preflight FAILED. Fix errors above before demoing."
  exit 1
fi
echo ""

# ── Clean ─────────────────────────────────────────────────────────────
echo "=== Clean ==="
rm -rf "$PACK_DIR" "$DEMO_DIR/.keys" "$WORK_DIR"
mkdir -p "$WORK_DIR"
echo "  Cleaned: $PACK_DIR, $DEMO_DIR/.keys, $WORK_DIR"
echo ""

# ── Build ─────────────────────────────────────────────────────────────
echo "=== 1. Build demo pack ==="
python3 "$DEMO_DIR/build_demo_pack.py"
echo ""

echo "=== 2. Ingest ==="
assay vendorq ingest \
  --in "$DEMO_DIR/sample_questionnaire.csv" \
  --out "$WORK_DIR/questions.json" \
  --source-label "vendorq-gold-demo" \
  --json > "$WORK_DIR/ingest_output.json"
echo "  $(python3 -c "import json; d=json.load(open('$WORK_DIR/ingest_output.json')); print(f'questions: {d[\"question_count\"]}')")"
echo ""

echo "=== 3. Compile ==="
assay vendorq compile \
  --questions "$WORK_DIR/questions.json" \
  --pack "$PACK_DIR" \
  --policy conservative \
  --out "$WORK_DIR/answers.json" \
  --json > "$WORK_DIR/compile_output.json"
echo "  $(python3 -c "import json; d=json.load(open('$WORK_DIR/compile_output.json')); print(f'answers: {d[\"answer_count\"]}, policy: {d[\"policy_profile\"]}')")"
echo ""

echo "=== 4. Lock ==="
assay vendorq lock write \
  --answers "$WORK_DIR/answers.json" \
  --pack "$PACK_DIR" \
  --out "$WORK_DIR/vendorq.lock" \
  --json > "$WORK_DIR/lock_output.json"
echo "  $(python3 -c "import json; d=json.load(open('$WORK_DIR/lock_output.json')); print(f'fingerprint: {d[\"fingerprint\"][:16]}...')")"
echo ""

echo "=== 5. Verify (expect PASS) ==="
assay vendorq verify \
  --answers "$WORK_DIR/answers.json" \
  --pack "$PACK_DIR" \
  --lock "$WORK_DIR/vendorq.lock" \
  --strict \
  --report-out "$WORK_DIR/verify_report.json" \
  --json > "$WORK_DIR/verify_output.json"
STATUS=$(python3 -c "import json; print(json.load(open('$WORK_DIR/verify_output.json'))['status'])")
if [ "$STATUS" != "ok" ]; then
  echo "  FAIL: verify returned '$STATUS' (expected 'ok')"
  exit 1
fi
echo "  PASS: status=ok, errors=0"
echo ""

echo "=== 6. Export ==="
assay vendorq export \
  --answers "$WORK_DIR/answers.json" \
  --verify-report "$WORK_DIR/verify_report.json" \
  --format md \
  --out "$WORK_DIR/vendor_packet.md" \
  --coverage-out "$WORK_DIR/coverage_receipt.json" \
  --json > "$WORK_DIR/export_output.json"
echo "  Exported: $WORK_DIR/vendor_packet.md"
echo "  Coverage: $WORK_DIR/coverage_receipt.json"
echo ""

# ── Tamper path ───────────────────────────────────────────────────────
echo "=== 7. Tamper ==="
cp "$WORK_DIR/answers.json" "$WORK_DIR/answers_clean.json"
python3 -c "
import json, pathlib
p = pathlib.Path('$WORK_DIR/answers.json')
obj = json.loads(p.read_text())
obj['answers'][0]['status'] = 'ANSWERED'
obj['answers'][0]['answer_bool'] = True
obj['answers'][0]['missing_evidence_requests'] = []
p.write_text(json.dumps(obj, indent=2) + '\n')
"
echo "  Tampered Q1: PARTIAL -> ANSWERED, answer_bool=true"
echo ""

echo "=== 8. Verify tampered (expect FAIL) ==="
set +e
assay vendorq verify \
  --answers "$WORK_DIR/answers.json" \
  --pack "$PACK_DIR" \
  --lock "$WORK_DIR/vendorq.lock" \
  --strict \
  --report-out "$WORK_DIR/verify_report_tampered.json" \
  --json > "$WORK_DIR/verify_tampered_output.json" 2>&1
TAMPER_EXIT=$?
set -e

if [ "$TAMPER_EXIT" -ne 2 ]; then
  echo "  FAIL: exit code $TAMPER_EXIT (expected 2)"
  exit 1
fi
TAMPER_ERRORS=$(python3 -c "import json; d=json.load(open('$WORK_DIR/verify_tampered_output.json')); print(d['summary']['errors'])")
echo "  FAIL (correct): exit=2, errors=$TAMPER_ERRORS"
echo ""

# ── Restore clean state for live demo ─────────────────────────────────
cp "$WORK_DIR/answers_clean.json" "$WORK_DIR/answers.json"
echo "=== Restored clean answers.json for live demo ==="
echo ""

# ── Summary ───────────────────────────────────────────────────────────
echo "========================================="
echo "  DEMO READY"
echo "========================================="
echo ""
echo "  Pack:             $PACK_DIR"
echo "  Work dir:         $WORK_DIR"
echo "  Clean answers:    $WORK_DIR/answers.json"
echo "  Lockfile:         $WORK_DIR/vendorq.lock"
echo "  Verify report:    $WORK_DIR/verify_report.json"
echo "  Markdown packet:  $WORK_DIR/vendor_packet.md"
echo "  Coverage receipt: $WORK_DIR/coverage_receipt.json"
echo ""
echo "  During the demo, tamper with:"
echo "    python3 -c \"import json,pathlib; p=pathlib.Path('$WORK_DIR/answers.json'); o=json.loads(p.read_text()); o['answers'][0]['status']='ANSWERED'; o['answers'][0]['answer_bool']=True; o['answers'][0]['missing_evidence_requests']=[]; p.write_text(json.dumps(o,indent=2)+'\\\\n')\""
echo ""
echo "  Then re-verify:"
echo "    assay vendorq verify --answers $WORK_DIR/answers.json --pack $PACK_DIR --lock $WORK_DIR/vendorq.lock --strict --report-out $WORK_DIR/verify_report_tampered.json"
echo ""
