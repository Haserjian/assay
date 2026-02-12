"""CLI tests for assay scan JSON semantics and guidance."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app


def test_scan_json_non_ci_uses_ok_status_with_scan_status() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )
        result = runner.invoke(assay_app, ["scan", ".", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "ok"
        assert payload["scan_status"] == "fail"
        assert isinstance(payload["next_steps"], list)
        assert len(payload["next_steps"]) == 3


def test_scan_json_ci_uses_blocked_status_on_threshold_failure() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )
        result = runner.invoke(assay_app, ["scan", ".", "--json", "--ci", "--fail-on", "high"])
        assert result.exit_code == 1, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "blocked"
        assert payload["scan_status"] == "fail"


def test_scan_multi_framework_recommends_patch_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("app.py").write_text(
            "import openai\n"
            "import anthropic\n"
            "openai.OpenAI().chat.completions.create(model='gpt-4', messages=[])\n"
            "anthropic.Anthropic().messages.create(model='claude-3', messages=[])\n",
            encoding="utf-8",
        )
        result = runner.invoke(assay_app, ["scan", ".", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["next_steps"][0]["commands"] == ["assay patch ."]
        assert "assay patch ." in payload["next_command"]
