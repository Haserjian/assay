"""Tests for the `assay openclaw verify` command.

These exercise the read-only session-log verify path against the committed
OpenClaw fixtures and confirm the fail-closed contract for missing/empty input.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "openclaw"
LIVE_EXEC = (
    FIXTURES
    / "live_validation_home"
    / "agents"
    / "main"
    / "sessions"
    / "assay-openai-live-1.jsonl"
)
LIVE_WEB_FETCH = (
    FIXTURES
    / "live_validation_web_fetch_home"
    / "agents"
    / "main"
    / "sessions"
    / "assay-openai-live-2.jsonl"
)


def test_verify_reports_imported_rows_and_tools() -> None:
    result = runner.invoke(
        assay_app,
        ["openclaw", "verify", str(LIVE_EXEC), str(LIVE_WEB_FETCH)],
    )
    assert result.exit_code == 0, result.stdout
    assert "2 log(s), 16 imported row(s)" in result.stdout
    assert "exec=1" in result.stdout
    assert "web_fetch=1" in result.stdout
    # Scope discipline must be visible in the human output.
    assert "Not complete runtime capture" in result.stdout


def test_verify_json_surfaces_counts_and_tools() -> None:
    result = runner.invoke(
        assay_app,
        ["openclaw", "verify", "--json", str(LIVE_EXEC), str(LIVE_WEB_FETCH)],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["command"] == "openclaw verify"
    assert payload["status"] == "ok"
    assert payload["imported_count"] == 16
    assert payload["skipped_count"] == 0
    observed_tools: dict[str, int] = {}
    for log in payload["validated_logs"]:
        for tool, count in log["imported_tools"].items():
            observed_tools[tool] = observed_tools.get(tool, 0) + count
    assert observed_tools.get("exec") == 1
    assert observed_tools.get("web_fetch") == 1


def test_verify_fails_closed_on_missing_file() -> None:
    result = runner.invoke(
        assay_app,
        ["openclaw", "verify", "./definitely_not_here.jsonl"],
    )
    assert result.exit_code == 3, result.stdout
    assert "No readable session log" in result.stdout


def test_verify_json_blocked_on_missing_file() -> None:
    result = runner.invoke(
        assay_app,
        ["openclaw", "verify", "--json", "./definitely_not_here.jsonl"],
    )
    assert result.exit_code == 3, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["reason"] == "session_log_missing"


def test_verify_fails_closed_on_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    result = runner.invoke(assay_app, ["openclaw", "verify", str(empty)])
    assert result.exit_code == 1, result.stdout
    assert "Fail-closed" in result.stdout


def test_verify_reports_skipped_rows(tmp_path: Path) -> None:
    """A malformed row must be surfaced as skipped, not silently dropped."""
    log = tmp_path / "mixed.jsonl"
    log.write_text(
        "\n".join(
            [
                json.dumps({"type": "session"}),
                "{not valid json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = runner.invoke(assay_app, ["openclaw", "verify", "--json", str(log)])
    payload = json.loads(result.stdout)
    log_report = payload["validated_logs"][0]
    assert log_report["imported_count"] == 1
    assert log_report["skipped_count"] == 1
    assert log_report["completeness"] == "partial"
    assert "invalid_json" in log_report["skipped_reasons"]
