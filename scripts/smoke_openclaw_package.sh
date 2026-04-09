#!/usr/bin/env bash
# Build the current checkout into a wheel, install it into a clean temp venv,
# and verify that the packaged OpenClaw demo surface actually works.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
KEEP_TMP="${KEEP_OPENCLAW_PACKAGE_SMOKE:-0}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/assay-openclaw-package-smoke.XXXXXX")"
cleanup() {
  if [[ "${KEEP_TMP}" == "1" ]]; then
    echo "Keeping temp directory: ${WORK_DIR}"
    return
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

DIST_DIR="${WORK_DIR}/dist"
VENV_DIR="${WORK_DIR}/venv"
RUN_DIR="${WORK_DIR}/run"
mkdir -p "${DIST_DIR}" "${RUN_DIR}"

echo "=== Assay OpenClaw Package Smoke ==="
echo "Repo: ${ROOT_DIR}"
echo "Work dir: ${WORK_DIR}"

echo ""
echo "--- release-slice gate ---"
if ! "${PYTHON_BIN}" "${ROOT_DIR}/scripts/check_openclaw_release_slice.py"; then
  echo ""
  echo "ERROR: OpenClaw release slice is not isolated."
  echo "Export an isolated slice with python3 scripts/export_openclaw_release_slice.py --output <dir> --run-smoke or remove out-of-scope changes before retrying package smoke." >&2
  exit 1
fi

if command -v git >/dev/null 2>&1; then
  DIRTY="$(git -C "${ROOT_DIR}" status --short)"
  if [[ -n "${DIRTY}" ]]; then
    echo ""
    echo "--- git status (warning: dirty tree) ---"
    echo "${DIRTY}"
  fi
fi

echo ""
echo "--- build wheel ---"
(
  cd "${ROOT_DIR}"
  "${PYTHON_BIN}" -m pip wheel . --no-deps -w "${DIST_DIR}"
)
WHEEL_PATH="$(find "${DIST_DIR}" -maxdepth 1 -name 'assay_ai-*.whl' | head -n 1)"
if [[ -z "${WHEEL_PATH}" ]]; then
  echo "ERROR: wheel build succeeded but no assay wheel was found" >&2
  exit 1
fi
echo "Wheel: ${WHEEL_PATH}"

echo ""
echo "--- create clean venv ---"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip >/dev/null
"${VENV_DIR}/bin/python" -m pip install "${WHEEL_PATH}" >/dev/null

echo ""
echo "--- packaged help surface ---"
HELP_OUTPUT="$("${VENV_DIR}/bin/assay" --help)"
echo "${HELP_OUTPUT}" | sed -n '1,40p'
if ! echo "${HELP_OUTPUT}" | grep -q "try-openclaw"; then
  echo "ERROR: packaged CLI does not expose try-openclaw" >&2
  exit 1
fi

echo ""
echo "--- packaged try-openclaw ---"
(
  cd "${RUN_DIR}"
  "${VENV_DIR}/bin/assay" try-openclaw --json > openclaw.json
)
cat "${RUN_DIR}/openclaw.json"

echo ""
echo "--- validate demo JSON ---"
"${VENV_DIR}/bin/python" - <<'PY' "${RUN_DIR}/openclaw.json"
import json
import pathlib
import sys

json_path = pathlib.Path(sys.argv[1]).resolve()
run_dir = json_path.parent
payload = json.loads(json_path.read_text(encoding="utf-8"))
assert payload["command"] == "try-openclaw", payload
assert payload["status"] == "ok", payload
assert payload["verification"] == "PASS", payload
assert payload["import_status"] in {"clean", "partial"}, payload
assert payload["projected_receipts"] >= 4, payload
pack_dir = (run_dir / payload["pack_dir"]).resolve()
assert pack_dir.exists(), payload
print(json.dumps({
    "verification": payload["verification"],
    "import_status": payload["import_status"],
    "projected_receipts": payload["projected_receipts"],
    "pack_dir": str(pack_dir),
}, indent=2))
PY

PACK_DIR="$("${VENV_DIR}/bin/python" - <<'PY' "${RUN_DIR}/openclaw.json"
import json
import pathlib
import sys

json_path = pathlib.Path(sys.argv[1]).resolve()
run_dir = json_path.parent
payload = json.loads(json_path.read_text(encoding="utf-8"))
print((run_dir / payload["pack_dir"]).resolve())
PY
)"

echo ""
echo "--- packaged verify-pack ---"
(
  cd "${RUN_DIR}"
  "${VENV_DIR}/bin/assay" verify-pack "${PACK_DIR}"
)

echo ""
echo "--- metadata-floor check ---"
"${PYTHON_BIN}" "${ROOT_DIR}/scripts/check_openclaw_metadata_floor.py" --openclaw-json "${RUN_DIR}/openclaw.json"

echo ""
echo "=== OpenClaw package smoke complete ==="
