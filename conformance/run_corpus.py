#!/usr/bin/env python3
"""
Assay Conformance Corpus Verifier.

Runs `assay verify-pack` against each corpus entry and asserts the exit code
matches expected_outcomes.json. This is the ABI test for the Assay verifier.

Usage:
    cd ~/assay
    python conformance/run_corpus.py

Exit codes:
    0  All corpus entries match expected outcomes
    1  One or more mismatches
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus_v1"
PACKS_DIR = CORPUS_DIR / "packs"
OUTCOMES_FILE = CORPUS_DIR / "expected_outcomes.json"


def run_corpus() -> int:
    """Verify all corpus packs and compare exit codes to expected outcomes."""
    if not OUTCOMES_FILE.exists():
        print(f"Error: {OUTCOMES_FILE} not found. Run generate_corpus.py first.")
        return 1

    outcomes = json.loads(OUTCOMES_FILE.read_text())
    entries = outcomes.get("entries", [])

    if not entries:
        print("Error: No entries in expected_outcomes.json")
        return 1

    print(f"Assay Conformance Corpus v{outcomes.get('corpus_version', '?')}")
    print(f"Generated: {outcomes.get('generated_at', '?')}")
    print(f"Entries:   {len(entries)}")
    print()

    passed = 0
    failed = 0
    errors: list[str] = []

    for entry in entries:
        name = entry["name"]
        expect_exit = entry["expect_exit"]
        require_claim = entry.get("require_claim_pass", False)
        pack_dir = PACKS_DIR / name

        if not pack_dir.exists():
            msg = f"  SKIP  {name:20s}  pack directory not found"
            print(msg)
            errors.append(msg)
            failed += 1
            continue

        cmd = [sys.executable, "-m", "assay.cli", "verify-pack", str(pack_dir)]
        if require_claim:
            cmd.append("--require-claim-pass")

        result = subprocess.run(cmd, capture_output=True, text=True)
        actual_exit = result.returncode

        if actual_exit == expect_exit:
            print(f"  PASS  {name:20s}  exit={actual_exit} (expected {expect_exit})")
            passed += 1
        else:
            msg = (
                f"  FAIL  {name:20s}  exit={actual_exit} (expected {expect_exit})"
            )
            print(msg)
            errors.append(msg)
            if result.stderr:
                for line in result.stderr.splitlines()[:3]:
                    errors.append(f"        stderr: {line}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed, {len(entries)} total")

    if errors:
        print()
        print("Failures:")
        for e in errors:
            print(e)
        return 1

    print("All corpus entries match expected outcomes.")
    return 0


if __name__ == "__main__":
    sys.exit(run_corpus())
