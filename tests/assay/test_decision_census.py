from __future__ import annotations

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.reviewer_packet_compile import compile_reviewer_packet
from assay.reporting.decision_census import (
    build_decision_census_report,
    build_decision_gap_report,
    render_gap_markdown,
    render_markdown,
    write_report,
)
from assay.vendorq_models import load_json

runner = CliRunner()


def _fixture_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "reviewer_packet"


def _compile_sample_packet(tmp_path: Path) -> Path:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"
    compile_reviewer_packet(
        proof_pack_dir=fixtures / "sample_proof_pack",
        boundary_payload=load_json(fixtures / "sample_boundary.json"),
        mapping_payload=load_json(fixtures / "sample_mapping.json"),
        out_dir=out_dir,
    )
    return out_dir


def test_build_decision_census_report_from_compiled_packet(tmp_path: Path) -> None:
    packet_dir = _compile_sample_packet(tmp_path)

    report = build_decision_census_report(packet_dir)

    assert report["coverage_summary"]["expected_count"] == 2
    assert report["coverage_summary"]["observed_count"] == 2
    assert report["coverage_summary"]["missing_count"] == 0
    assert report["coverage_summary"]["coverage_state"] == "degraded"
    assert report["inventory"]["basis"] == "packet_inputs+coverage_rows"
    assert [row["status"] for row in report["decision_points"]] == ["emitted", "uncertain", "out_of_scope"]
    assert report["unsupported_surfaces"] == [
        "Row-level receipt IDs are not exposed by the current reviewer packet surfaces."
    ]

    gap_report = build_decision_gap_report(report)
    assert gap_report["gap_summary"]["gap_count"] == 1
    assert gap_report["gap_summary"]["missing_count"] == 0
    assert gap_report["gap_summary"]["uncertain_count"] == 1
    assert gap_report["gap_summary"]["excluded_out_of_scope_count"] == 1
    assert [row["observed_status"] for row in gap_report["gaps"]] == ["uncertain"]
    assert all(row["observed_status"] != "out_of_scope" for row in gap_report["gaps"])

    gap_markdown = render_gap_markdown(gap_report)
    assert "# Decision Gaps" in gap_markdown
    assert "Gap count: **1**" in gap_markdown

    markdown = render_markdown(report)
    assert "# Decision Census Report" in markdown
    assert "Unsupported Surfaces" in markdown
    assert "Coverage state: **degraded**" in markdown

    out_dir = tmp_path / "census_bundle"
    bundle = write_report(report, out_dir)
    assert bundle["coverage_state"] == "degraded"
    assert bundle["gap_count"] == 1
    assert (out_dir / "DECISION_CENSUS.json").exists()
    assert (out_dir / "DECISION_CENSUS.md").exists()
    assert (out_dir / "COVERAGE_MATRIX.md").exists()
    assert (out_dir / "DECISION_GAPS.json").exists()
    assert (out_dir / "DECISION_GAPS.md").exists()


def test_decision_census_runs_without_optional_packet_files(tmp_path: Path) -> None:
    packet_dir = _compile_sample_packet(tmp_path)
    stripped_dir = tmp_path / "reviewer_packet_stripped"
    shutil.copytree(packet_dir, stripped_dir)
    (stripped_dir / "PACKET_INPUTS.json").unlink()
    (stripped_dir / "PACKET_MANIFEST.json").unlink()

    report = build_decision_census_report(stripped_dir)

    assert report["coverage_summary"]["expected_count"] == 2
    assert report["coverage_summary"]["observed_count"] == 2
    assert report["coverage_summary"]["missing_count"] == 0
    assert report["coverage_summary"]["coverage_state"] == "degraded"
    assert report["inventory"]["basis"] == "coverage_rows_only"
    assert any("PACKET_INPUTS.json is absent" in item for item in report["unsupported_surfaces"])

    gap_report = build_decision_gap_report(report)
    assert gap_report["gap_summary"]["gap_count"] == 1
    assert gap_report["gap_summary"]["uncertain_count"] == 1
    assert any("coverage matrix alone" in item for item in report["unsupported_surfaces"])


def test_reviewer_census_cli_json_and_bundle(tmp_path: Path) -> None:
    packet_dir = _compile_sample_packet(tmp_path)
    out_dir = tmp_path / "decision_census"

    result = runner.invoke(
        assay_app,
        [
            "reviewer",
            "census",
            str(packet_dir),
            "--out",
            str(out_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["command"] == "reviewer census"
    assert payload["status"] == "ok"
    assert payload["coverage_summary"]["expected_count"] == 2
    assert payload["coverage_summary"]["observed_count"] == 2
    assert payload["coverage_summary"]["coverage_state"] == "degraded"
    assert payload["gap_count"] == 1
    assert payload["decision_point_count"] == 3
    assert payload["inventory"]["basis"] == "packet_inputs+coverage_rows"
    assert (out_dir / "DECISION_CENSUS.json").exists()
    assert (out_dir / "DECISION_CENSUS.md").exists()
    assert (out_dir / "COVERAGE_MATRIX.md").exists()
    assert (out_dir / "DECISION_GAPS.json").exists()
    assert (out_dir / "DECISION_GAPS.md").exists()
