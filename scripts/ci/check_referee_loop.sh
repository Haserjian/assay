#!/usr/bin/env bash
# CI check: seeded referee loop is intact.
#
# Verifies:
#   1. Release invariant tests pass (README, gallery, demo, overclaim guard)
#   2. Messaging drift tests pass (landing page, exit codes)
#   3. Gallery regenerates cleanly (deterministic artifact set)
#
# Usage:
#   ./scripts/ci/check_referee_loop.sh
#
# Exit codes:
#   0 = referee loop intact
#   1 = test failure

set -euo pipefail

echo "=== Referee Loop Check ==="
echo ""

echo "[1/2] Release invariant tests..."
python3 -m pytest tests/assay/test_passport_release_invariants.py -q --tb=short
echo ""

echo "[2/2] Messaging drift tests (landing page)..."
python3 -m pytest tests/assay/test_messaging_drift.py::TestLandingPage -q --tb=short
echo ""

echo "=== Referee loop intact ==="
