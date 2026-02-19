#!/usr/bin/env bash
# Assay end-to-end smoke test.
# Verifies the full pipeline works on a fresh install.
# Exit on first failure.
set -euo pipefail

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "=== Assay Smoke Test ==="
echo "Work dir: $WORK"
echo ""

# 0. Version
echo "--- version ---"
python -c "import assay; print(f'assay {assay.__version__}')"
echo ""

# 1. Doctor
echo "--- assay doctor ---"
assay doctor || true
echo ""

# 2. Scan (tiny project with one OpenAI call site)
echo "--- assay scan ---"
mkdir -p project
cat > project/app.py << 'PYEOF'
from openai import OpenAI
client = OpenAI(api_key="test")
resp = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "hi"}])
PYEOF
assay scan project || true
echo ""

# 3. Run (emit a synthetic receipt, build signed pack)
echo "--- assay run ---"
assay run -c receipt_completeness -- python -c "
from assay.store import emit_receipt
emit_receipt(type='model_call', data={'model': 'gpt-4', 'provider': 'openai'})
"
PACK=$(ls -d proof_pack_*/ 2>/dev/null | head -1)
echo "  Pack: $PACK"
echo ""

# 4. Verify
echo "--- assay verify-pack ---"
assay verify-pack "$PACK"
echo ""

# 5. Explain
echo "--- assay explain ---"
assay explain "$PACK"
echo ""

# 6. Diff (pack against itself -- no regressions)
echo "--- assay diff ---"
assay diff "$PACK" "$PACK" || true
echo ""

# 7. MCP proxy (help check -- command exists and wired)
echo "--- assay mcp-proxy ---"
assay mcp-proxy --help 2>&1 | head -5 || true
echo ""

# 8. Key list
echo "--- assay key list ---"
assay key list || true
echo ""

# 9. Packs list (v1.6.0)
echo "--- assay packs list ---"
assay packs list || true
echo ""

# 10. Packs show (v1.6.0)
echo "--- assay packs show ---"
assay packs show "$PACK" --json || true
echo ""

# 11. Verify signer (v1.6.0)
echo "--- assay verify-signer ---"
assay verify-signer "$PACK" --json || true
echo ""

# 12. Audit bundle (v1.6.0)
echo "--- assay audit bundle ---"
assay audit bundle "$PACK" --json || true
echo ""

# 13. Flow try dry-run (v1.6.0)
echo "--- assay flow try ---"
assay flow try --json || true
echo ""

# 14. Key info (v1.6.0)
echo "--- assay key info ---"
assay key info --json || true
echo ""

echo "=== Smoke test complete ==="
