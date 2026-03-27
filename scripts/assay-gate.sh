#!/usr/bin/env bash
# assay-gate.sh — Fail-closed gate that consumes packet verifier output.
#
# Usage:
#   scripts/assay-gate.sh <packet_dir>
#
# The gate checks:
#   1. Packet exists and is verifiable
#   2. Integrity is INTACT (not DEGRADED, TAMPERED, or INVALID)
#   3. Admissible = true
#
# Exit codes:
#   0 = gate passes (proceed)
#   1 = gate blocks (do not proceed)
#
# The gate consumes verifier output. It does not reconstruct trust from scratch.

set -euo pipefail

PACKET_DIR="${1:-}"

if [ -z "$PACKET_DIR" ]; then
    echo "GATE BLOCKED: no packet directory specified" >&2
    echo "Usage: $0 <packet_dir>" >&2
    exit 1
fi

if [ ! -d "$PACKET_DIR" ]; then
    echo "GATE BLOCKED: packet directory does not exist: $PACKET_DIR" >&2
    exit 1
fi

# Run verifier and capture JSON from stdout only.
# stderr is sent to /dev/null so warnings/Rich formatting don't corrupt JSON.
# The verifier may return non-zero for non-admissible packets — that's expected.
VERIFY_OUTPUT=$(assay packet verify "$PACKET_DIR" --json 2>/dev/null) || true

if [ -z "$VERIFY_OUTPUT" ]; then
    echo "GATE BLOCKED: verifier failed to produce output" >&2
    exit 1
fi

# Extract verdicts from JSON
INTEGRITY=$(echo "$VERIFY_OUTPUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['integrity_verdict'])" 2>/dev/null)
ADMISSIBLE=$(echo "$VERIFY_OUTPUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['admissible'])" 2>/dev/null)
VERDICT=$(echo "$VERIFY_OUTPUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])" 2>/dev/null)
SUBJECT_ID=$(echo "$VERIFY_OUTPUT" | python3 -c "import json,sys; s=json.load(sys.stdin).get('subject',{}); print(f\"{s.get('subject_type','?')}:{s.get('subject_id','?')}\")" 2>/dev/null)

if [ -z "$INTEGRITY" ] || [ -z "$ADMISSIBLE" ]; then
    echo "GATE BLOCKED: could not parse verifier output" >&2
    exit 1
fi

echo "--- Assay Gate ---"
echo "Packet:     $PACKET_DIR"
echo "Subject:    $SUBJECT_ID"
echo "Integrity:  $INTEGRITY"
echo "Admissible: $ADMISSIBLE"
echo "Verdict:    $VERDICT"

if [ "$ADMISSIBLE" = "True" ] && [ "$INTEGRITY" = "INTACT" ]; then
    echo "GATE: PASS"
    exit 0
else
    echo "GATE: BLOCKED" >&2
    if [ "$INTEGRITY" != "INTACT" ]; then
        echo "  Reason: integrity is $INTEGRITY (must be INTACT)" >&2
    fi
    if [ "$ADMISSIBLE" != "True" ]; then
        echo "  Reason: packet is not admissible" >&2
    fi
    exit 1
fi
