#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${REPO_ROOT}/.venv/bin/python}"
PORT="${SPECIMEN_PORT:-8787}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/assay-specimen.XXXXXX")"
SERVER_LOG="${WORKDIR}/mock_server.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "error: python interpreter not found at ${PYTHON_BIN}" >&2
  exit 1
fi

if ! "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
  "${PYTHON_BIN}" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi

if ! "${PYTHON_BIN}" - <<'PY' >/dev/null 2>&1
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("openai") else 1)
PY
then
  echo "error: openai is not installed for ${PYTHON_BIN}" >&2
  echo "hint: ${PYTHON_BIN} -m ensurepip --upgrade && ${PYTHON_BIN} -m pip install -e \".[openai]\"" >&2
  exit 1
fi

cp "${SCRIPT_DIR}/sample_app.before.py" "${WORKDIR}/sample_app.py"

echo "== workspace =="
echo "${WORKDIR}"
echo

echo "== scan =="
"${PYTHON_BIN}" -m assay.cli scan "${WORKDIR}" --json > "${WORKDIR}/scan.json"
"${PYTHON_BIN}" -m assay.cli scan "${WORKDIR}" --report --report-path "${WORKDIR}/evidence_gap_report.html" >/dev/null
echo "scan report: ${WORKDIR}/scan.json"
echo "html report: ${WORKDIR}/evidence_gap_report.html"
echo

echo "== patch =="
"${PYTHON_BIN}" -m assay.cli patch "${WORKDIR}" --entrypoint sample_app.py -y >/dev/null
diff -u "${SCRIPT_DIR}/sample_app.before.py" "${WORKDIR}/sample_app.py" > "${WORKDIR}/patch.diff" || true
echo "patch diff: ${WORKDIR}/patch.diff"
echo

echo "== mock server =="
"${PYTHON_BIN}" "${SCRIPT_DIR}/mock_openai_server.py" --port "${PORT}" > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 1
echo "server log: ${SERVER_LOG}"
echo

echo "== run =="
(
  cd "${WORKDIR}"
  OPENAI_API_KEY="specimen-local-key" \
  SPECIMEN_BASE_URL="http://127.0.0.1:${PORT}/v1" \
  "${PYTHON_BIN}" -m assay.cli run -c receipt_completeness -- "${PYTHON_BIN}" sample_app.py | tee "${WORKDIR}/run.log"
)
PACK_DIR="$(find "${WORKDIR}" -maxdepth 1 -type d -name 'proof_pack_*' | sort | tail -n 1)"
if [[ -z "${PACK_DIR}" ]]; then
  echo "error: proof pack not found in ${WORKDIR}" >&2
  exit 1
fi
echo "proof pack: ${PACK_DIR}"
echo

echo "== verify =="
"${PYTHON_BIN}" -m assay.cli verify-pack "${PACK_DIR}" | tee "${WORKDIR}/verify.log"
echo

echo "== reviewer packet =="
REVIEWER_OUT="${WORKDIR}/reviewer_packet"
"${PYTHON_BIN}" -m assay.cli vendorq export-reviewer \
  --proof-pack "${PACK_DIR}" \
  --boundary "${SCRIPT_DIR}/specimen_boundary.json" \
  --mapping "${SCRIPT_DIR}/specimen_mapping.json" \
  --out "${REVIEWER_OUT}" >/dev/null
"${PYTHON_BIN}" -m assay.cli reviewer verify "${REVIEWER_OUT}" | tee "${WORKDIR}/reviewer_verify.log"
echo "reviewer packet: ${REVIEWER_OUT}"
echo

echo "== done =="
echo "workspace: ${WORKDIR}"
echo "proof pack: ${PACK_DIR}"
echo "reviewer packet: ${REVIEWER_OUT}"
