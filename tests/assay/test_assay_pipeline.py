"""
End-to-end assay demo → verify → pack pipeline test.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import typer
from typer.testing import CliRunner

from assay.store import AssayStore
import assay.store as store_mod
from assay.evidence_pack import create_evidence_pack
from assay import commands as assay_commands


def test_assay_demo_verify_pack_roundtrip(tmp_path: Path) -> None:
    """Runs demo, verifies trace, and builds an evidence pack."""
    store = AssayStore(base_dir=tmp_path)
    store_mod._default_store = store

    try:
        try:
            assay_commands.run_demo(scenario="all", persist=True, output_json=True)
        except typer.Exit as exc:
            assert exc.exit_code == 0

        trace_id = store.trace_id
        assert trace_id is not None

        try:
            assay_commands.verify_trace(
                trace_id,
                strict=False,
                policy_override=None,
                output_json=True,
            )
        except typer.Exit as exc:
            assert exc.exit_code == 0

        output_path = tmp_path / "evidence_pack.zip"
        pack_path = create_evidence_pack(
            trace_id=trace_id,
            output_path=output_path,
            preserve_raw=True,
        )
        assert pack_path.exists()

        with zipfile.ZipFile(pack_path, "r") as zf:
            names = zf.namelist()
            assert "trace.jsonl" in names
            assert "verify_report.json" in names
            assert "merkle_root.json" in names
            assert "claim_map.json" in names
            assert "build_metadata.json" in names
    finally:
        store_mod._default_store = None


def test_demo_pack_command_runs_and_exits_zero() -> None:
    """assay demo-pack produces output and exits 0."""
    runner = CliRunner()
    result = runner.invoke(assay_commands.assay_app, ["demo-pack"])
    assert result.exit_code == 0, f"demo-pack failed:\n{result.output}"
    assert "ASSAY DEMO PACK" in result.output
    assert "Integrity" in result.output
    assert "PASS" in result.output
    assert "FAIL" in result.output  # Pack B should show claim FAIL


def test_demo_pack_json_output() -> None:
    """assay demo-pack --json produces valid JSON."""
    import json

    runner = CliRunner()
    result = runner.invoke(assay_commands.assay_app, ["demo-pack", "--json"])
    assert result.exit_code == 0, f"demo-pack --json failed:\n{result.output}"
    data = json.loads(result.output)
    assert data["command"] == "demo-pack"
    assert data["pack_a"]["receipt_integrity"] == "PASS"
    assert data["pack_a"]["claim_check"] == "PASS"
    assert data["pack_b"]["receipt_integrity"] == "PASS"
    assert data["pack_b"]["claim_check"] == "FAIL"
