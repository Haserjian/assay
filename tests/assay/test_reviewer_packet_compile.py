from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.reviewer_packet_compile import compile_reviewer_packet
from assay.vendorq_models import load_json

runner = CliRunner()


def _fixture_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "reviewer_packet"


def test_compile_reviewer_packet_matches_golden_files(tmp_path: Path) -> None:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"

    result = compile_reviewer_packet(
        proof_pack_dir=fixtures / "sample_proof_pack",
        boundary_payload=load_json(fixtures / "sample_boundary.json"),
        mapping_payload=load_json(fixtures / "sample_mapping.json"),
        out_dir=out_dir,
    )

    assert result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert json.loads((out_dir / "SETTLEMENT.json").read_text()) == json.loads((fixtures / "expected_SETTLEMENT.json").read_text())
    assert json.loads((out_dir / "SCOPE_MANIFEST.json").read_text()) == json.loads((fixtures / "expected_SCOPE_MANIFEST.json").read_text())
    assert (out_dir / "COVERAGE_MATRIX.md").read_text() == (fixtures / "expected_COVERAGE_MATRIX.md").read_text()
    assert (out_dir / "proof_pack" / "verify_report.json").exists()


def test_vendorq_export_reviewer_cli(tmp_path: Path) -> None:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"

    result = runner.invoke(
        assay_app,
        [
            "vendorq",
            "export-reviewer",
            "--proof-pack",
            str(fixtures / "sample_proof_pack"),
            "--boundary",
            str(fixtures / "sample_boundary.json"),
            "--mapping",
            str(fixtures / "sample_mapping.json"),
            "--out",
            str(out_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["command"] == "vendorq export-reviewer"
    assert payload["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert payload["integrity_state"] == "PASS"
    assert payload["claim_state"] == "PASS"
    assert (out_dir / "REVIEWER_GUIDE.md").exists()
    assert (out_dir / "EXECUTIVE_SUMMARY.md").exists()
    assert (out_dir / "VERIFY.md").exists()
