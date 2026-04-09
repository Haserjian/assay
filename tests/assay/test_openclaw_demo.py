"""Tests for the deterministic OpenClaw demo and proof-pack projection."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.openclaw_demo import (
    project_bridge_receipt_for_proof_pack,
    run_openclaw_demo,
)
from assay.proof_pack import verify_proof_pack

runner = CliRunner()


def test_project_bridge_receipt_uses_namespaced_type() -> None:
    projected = project_bridge_receipt_for_proof_pack(
        {
            "receipt_type": "BridgeExecution",
            "receipt_id": "be_test",
            "timestamp": "2026-04-08T00:00:00Z",
            "schema_version": "3.0",
            "agent_id": "agent:test",
            "session_id": "sess",
            "tool_name": "web_fetch",
            "allowed": True,
            "outcome": "ok",
            "policy_hash": "abc",
            "arguments_sha256": "def",
        },
        run_id="openclaw_demo_v1",
        seq=0,
    )

    assert projected["type"] == "openclaw.bridge_execution/v1"
    assert projected["evidence_source"] == "membrane_execution"
    assert projected["source_receipt_type"] == "BridgeExecution"
    assert projected["run_id"] == "openclaw_demo_v1"


def test_run_openclaw_demo_builds_verifiable_pack(tmp_path: Path) -> None:
    result = run_openclaw_demo(tmp_path / "demo")

    assert result.verification_passed is True
    assert result.pack_dir.exists()
    assert result.session_log_path.exists()
    assert result.summary_path.exists()
    assert result.import_report.imported_count == 1
    assert result.import_report.skipped_count == 0

    manifest = json.loads(
        (result.pack_dir / "pack_manifest.json").read_text(encoding="utf-8")
    )
    verify_result = verify_proof_pack(manifest, result.pack_dir)
    assert verify_result.passed, [error.to_dict() for error in verify_result.errors]

    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert summary["verification"] == "PASS"
    assert summary["cases"]["membrane_denied"]["policy_ref"] == "POLICY_URL_002"
    assert summary["import_report"]["status"] == "clean"
    assert summary["import_report"]["imported_count"] == 1
    assert summary["import_report"]["skipped_count"] == 0
    assert summary["projected_evidence_sources"]["membrane_execution"] == 2
    assert summary["projected_evidence_sources"]["imported_session_log"] == 1
    assert summary["projected_evidence_sources"]["live_receipt_adapter"] == 1


def test_run_openclaw_demo_surfaces_partial_import_report(tmp_path: Path) -> None:
    result = run_openclaw_demo(
        tmp_path / "demo_partial",
        session_log_lines=[
            {
                "tool": "browser",
                "url": "https://github.com/anthropics/claude-code",
                "content_length": 1024,
            },
            {"tool": "shell_exec", "command": "whoami"},
            {"tool": "browser", "url": "https://evil.com/login"},
            {
                "tool": "browser",
                "url": "https://github.com/login",
                "sensitive_action_attempted": True,
            },
            "not-json",
            "",
        ],
    )

    assert result.verification_passed is True
    assert result.import_report.imported_count == 2
    assert result.import_report.skipped_count == 3
    assert result.import_report.blank_lines == 1
    assert result.import_report.completeness == "partial"

    imported_entries = {
        entry["source_line_number"]: entry
        for entry in result.projected_entries
        if entry["evidence_source"] == "imported_session_log"
    }
    assert imported_entries[1]["allowed"] is True
    assert imported_entries[3]["allowed"] is False
    assert imported_entries[3]["outcome"] == "blocked"

    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert summary["cases"]["session_log_import"]["status"] == "partial"
    assert summary["import_report"]["status"] == "partial"
    assert summary["import_report"]["skipped_count"] == 3
    assert summary["projected_evidence_sources"]["imported_session_log"] == 2
    assert [
        entry["reason"] for entry in summary["import_report"]["skipped_entries"]
    ] == [
        "unsupported_tool",
        "invalid_entry",
        "invalid_json",
    ]


def test_try_openclaw_cli_json(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo_cli"
    result = runner.invoke(
        assay_app, ["try-openclaw", "--output", str(output_dir), "--json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["verification"] == "PASS"
    assert payload["imported_events"] == 1
    assert payload["skipped_import_entries"] == 0
    assert payload["import_status"] == "clean"
    assert payload["import_total_lines"] == 1
    assert payload["import_blank_lines"] == 0
    assert Path(payload["pack_dir"]).exists()
