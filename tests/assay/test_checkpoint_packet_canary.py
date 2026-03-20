from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_checkpoint_packet_canary.py"


def test_checkpoint_packet_canary_script_builds_verified_packet(tmp_path: Path) -> None:
    out_dir = tmp_path / "checkpoint-canary"
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src if not current else f"{src}{os.pathsep}{current}"

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--out", str(out_dir)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    for rel_path in (
        "RUN_CONTEXT.json",
        "trace_id.txt",
        "decision_receipt.json",
        "proof_pack/receipt_pack.jsonl",
        "proof_pack/verify_report.json",
        "reviewer_packet/SETTLEMENT.json",
        "reviewer_verify.json",
    ):
        assert (out_dir / rel_path).exists(), rel_path

    run_context = json.loads((out_dir / "RUN_CONTEXT.json").read_text(encoding="utf-8"))
    reviewer_verify = json.loads((out_dir / "reviewer_verify.json").read_text(encoding="utf-8"))
    settlement = json.loads((out_dir / "reviewer_packet" / "SETTLEMENT.json").read_text(encoding="utf-8"))

    assert run_context["packet_profile"] == "checkpoint.outbound_action.send_email.v0.1"
    assert reviewer_verify["packet_verified"] is True
    assert reviewer_verify["settlement_state"] == "VERIFIED"
    assert reviewer_verify["coverage_summary"]["EVIDENCED"] == 4
    assert settlement["packet_profile"] == "checkpoint.outbound_action.send_email.v0.1"
