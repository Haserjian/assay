#!/usr/bin/env bash
# VendorQ Gold Demo: build → compile → verify PASS → tamper → verify FAIL
#
# Usage:
#   cd <assay-repo-root>
#   bash examples/vendorq/verify.sh
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== VendorQ Gold Demo ==="
echo ""

# ── 1. Build demo proof pack ──────────────────────────────────────────
echo "Step 1: Building demo proof pack..."
python "$DEMO_DIR/build_demo_pack.py"
PACK_DIR="$DEMO_DIR/demo_pack"
echo "  Pack: $PACK_DIR"
echo ""

# ── 2. Ingest questionnaire ──────────────────────────────────────────
echo "Step 2: Ingesting questionnaire..."
assay vendorq ingest \
  --in "$DEMO_DIR/sample_questionnaire.csv" \
  --out "$WORK_DIR/questions.json" \
  --source-label "vendorq-gold-demo" \
  --json | python -m json.tool
echo ""

# ── 3. Compile answers ───────────────────────────────────────────────
echo "Step 3: Compiling answers from pack..."
assay vendorq compile \
  --questions "$WORK_DIR/questions.json" \
  --pack "$PACK_DIR" \
  --policy conservative \
  --out "$WORK_DIR/answers.json" \
  --json | python -m json.tool
echo ""

# ── 4. Write lockfile ────────────────────────────────────────────────
echo "Step 4: Pinning lockfile..."
assay vendorq lock write \
  --answers "$WORK_DIR/answers.json" \
  --pack "$PACK_DIR" \
  --out "$WORK_DIR/vendorq.lock" \
  --json | python -m json.tool
echo ""

# ── 5. Verify (expect PASS) ──────────────────────────────────────────
echo "Step 5: Verifying (expect PASS)..."
assay vendorq verify \
  --answers "$WORK_DIR/answers.json" \
  --pack "$PACK_DIR" \
  --lock "$WORK_DIR/vendorq.lock" \
  --strict \
  --report-out "$WORK_DIR/verify_report.json" \
  --json | python -m json.tool
echo ""
echo "  ✓ VERIFICATION PASSED"
echo ""

# ── 6. Export markdown packet ─────────────────────────────────────────
echo "Step 6: Exporting markdown packet..."
assay vendorq export \
  --answers "$WORK_DIR/answers.json" \
  --verify-report "$WORK_DIR/verify_report.json" \
  --format md \
  --out "$WORK_DIR/vendor_packet.md" \
  --json | python -m json.tool
echo ""

# ── 7. Tamper and re-verify (expect FAIL) ─────────────────────────────
echo "Step 7: Tampering with answers..."
python3 -c "
import json, pathlib
p = pathlib.Path('$WORK_DIR/answers.json')
obj = json.loads(p.read_text())
obj['answers'][0]['status'] = 'ANSWERED'
obj['answers'][0]['answer_bool'] = True
obj['answers'][0]['missing_evidence_requests'] = []
p.write_text(json.dumps(obj, indent=2) + '\n')
print('  Tampered: forced Q1 to ANSWERED + answer_bool=true')
"
echo ""

echo "Step 8: Re-verifying tampered answers (expect FAIL)..."
set +e
assay vendorq verify \
  --answers "$WORK_DIR/answers.json" \
  --pack "$PACK_DIR" \
  --lock "$WORK_DIR/vendorq.lock" \
  --strict \
  --report-out "$WORK_DIR/verify_report_tampered.json" \
  --json 2>&1 | python -m json.tool
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 2 ]; then
  echo ""
  echo "  ✓ TAMPER DETECTED (exit code 2) -- verification correctly failed"
else
  echo ""
  echo "  ✗ UNEXPECTED EXIT CODE: $EXIT_CODE (expected 2)"
  exit 1
fi

echo ""
echo "=== Demo complete ==="
echo "  Artifacts in: $WORK_DIR"
echo "  Markdown packet: $WORK_DIR/vendor_packet.md"
