"""Tests for the real-log OpenClaw validation harness."""

from __future__ import annotations

from pathlib import Path

from assay.openclaw_validation import (
    discover_openclaw_session_logs,
    infer_openclaw_agent_name,
    render_openclaw_live_validation,
    validate_openclaw_session_logs,
)

FIXTURE_OPENCLAW_HOME = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "openclaw"
    / "live_validation_home"
)
FIXTURE_OPENCLAW_WEB_FETCH_HOME = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "openclaw"
    / "live_validation_web_fetch_home"
)


def test_discover_openclaw_session_logs_finds_agent_logs(tmp_path: Path) -> None:
    home = tmp_path / ".openclaw"
    first = home / "agents" / "main" / "sessions" / "sess-001.jsonl"
    second = home / "agents" / "research" / "sessions" / "sess-002.jsonl"
    ignored = home / "agents" / "main" / "sessions" / "sessions.json"
    first.parent.mkdir(parents=True, exist_ok=True)
    second.parent.mkdir(parents=True, exist_ok=True)
    first.write_text('{"tool":"web_fetch","url":"https://example.com"}\n')
    second.write_text('{"tool":"web_search","query":"python"}\n')
    ignored.write_text("{}\n")

    discovered = discover_openclaw_session_logs(home)

    assert discovered == [first.resolve(), second.resolve()]


def test_infer_openclaw_agent_name_uses_standard_path(tmp_path: Path) -> None:
    home = tmp_path / ".openclaw"
    log_path = home / "agents" / "main" / "sessions" / "sess-001.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("")

    assert infer_openclaw_agent_name(log_path, openclaw_home=home) == "main"


def test_validate_openclaw_session_logs_blocks_without_real_logs(
    tmp_path: Path,
) -> None:
    home = tmp_path / ".openclaw"
    (home / "identity").mkdir(parents=True, exist_ok=True)

    result = validate_openclaw_session_logs(openclaw_home=home)

    assert result.status == "blocked"
    assert result.reason == "no_session_logs"
    assert result.openclaw_home_exists is True
    assert result.top_level_entries == ["identity/"]
    text = render_openclaw_live_validation(result)
    assert "no_session_logs" in text
    assert "identity/" in text


def test_validate_openclaw_session_logs_reports_partial_fit(tmp_path: Path) -> None:
    home = tmp_path / ".openclaw"
    log_path = home / "agents" / "main" / "sessions" / "sess-001.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "\n".join(
            [
                '{"tool":"web_fetch","url":"https://docs.python.org/3/","content_length":1200}',
                '{"tool":"browser","url":"https://github.com/anthropics/claude-code","content_length":10}',
                '{"tool":"shell_exec","command":"whoami"}',
                "not-json",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = validate_openclaw_session_logs(openclaw_home=home)

    assert result.status == "ok"
    assert result.reason is None
    assert result.log_count == 1
    assert result.imported_count == 2
    assert result.skipped_count == 2
    assert result.partial_log_count == 1

    log = result.validated_logs[0]
    assert log.agent_name == "main"
    assert log.session_id == "sess-001"
    assert log.completeness == "partial"
    assert log.imported_tools == {"browser": 1, "web_fetch": 1}
    assert log.recognized_entry_types == {"legacy_tool": 2}
    assert log.message_roles == {}
    assert log.skipped_reasons == {"invalid_json": 1, "unsupported_tool": 1}
    assert len(log.skipped_entries_preview) == 2


def test_validate_openclaw_session_logs_supports_sanitized_live_fixture() -> None:
    result = validate_openclaw_session_logs(openclaw_home=FIXTURE_OPENCLAW_HOME)

    assert result.status == "ok"
    assert result.reason is None
    assert result.log_count == 1
    assert result.imported_count == 8
    assert result.skipped_count == 0
    assert result.partial_log_count == 0

    log = result.validated_logs[0]
    assert log.path.endswith("assay-openai-live-1.jsonl")
    assert log.agent_name == "main"
    assert log.session_id == "assay-openai-live-1"
    assert log.completeness == "clean"
    assert log.imported_tools == {"exec": 1}
    assert log.recognized_entry_types == {
        "custom": 1,
        "message": 4,
        "model_change": 1,
        "session": 1,
        "thinking_level_change": 1,
    }
    assert log.message_roles == {
        "assistant": 2,
        "toolResult": 1,
        "user": 1,
    }
    text = render_openclaw_live_validation(result)
    assert "Recognized entry types" in text
    assert "Observed tools: exec=1" in text


def test_validate_openclaw_session_logs_supports_web_fetch_live_fixture() -> None:
    result = validate_openclaw_session_logs(
        openclaw_home=FIXTURE_OPENCLAW_WEB_FETCH_HOME
    )

    assert result.status == "ok"
    assert result.reason is None
    assert result.log_count == 1
    assert result.imported_count == 8
    assert result.skipped_count == 0
    assert result.partial_log_count == 0

    log = result.validated_logs[0]
    assert log.path.endswith("assay-openai-live-2.jsonl")
    assert log.agent_name == "main"
    assert log.session_id == "assay-openai-live-2"
    assert log.completeness == "clean"
    assert log.imported_tools == {"web_fetch": 1}
    assert log.recognized_entry_types == {
        "custom": 1,
        "message": 4,
        "model_change": 1,
        "session": 1,
        "thinking_level_change": 1,
    }
    assert log.message_roles == {
        "assistant": 2,
        "toolResult": 1,
        "user": 1,
    }
    text = render_openclaw_live_validation(result)
    assert "Recognized entry types" in text
    assert "Observed tools: web_fetch=1" in text


def test_validate_openclaw_session_logs_blocks_when_home_missing(
    tmp_path: Path,
) -> None:
    missing_home = tmp_path / ".openclaw"

    result = validate_openclaw_session_logs(openclaw_home=missing_home)

    assert result.status == "blocked"
    assert result.reason == "openclaw_home_missing"
    assert result.openclaw_home_exists is False
