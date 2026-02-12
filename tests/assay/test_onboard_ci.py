"""Tests for onboarding and CI init CLI flows."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay import commands as assay_commands


def test_ci_init_github_writes_workflow() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            assay_commands.assay_app,
            [
                "ci",
                "init",
                "github",
                "--run-command",
                "python app.py",
            ],
        )
        assert result.exit_code == 0, result.output

        workflow = Path(".github/workflows/assay-verify.yml")
        assert workflow.exists()
        text = workflow.read_text(encoding="utf-8")
        assert "Haserjian/assay-verify-action@v1" in text
        assert "assay run -c receipt_completeness -c guardian_enforcement -- python app.py" in text


def test_ci_init_existing_without_force_fails() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        workflow = Path(".github/workflows/assay-verify.yml")
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("name: Existing\n", encoding="utf-8")

        result = runner.invoke(
            assay_commands.assay_app,
            ["ci", "init", "github"],
        )
        assert result.exit_code == 1
        assert "already exists" in result.output


def test_onboard_json_with_findings() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "resp = client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            assay_commands.assay_app,
            ["onboard", ".", "--skip-doctor", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["command"] == "onboard"
        assert payload["scan_summary"]["sites_total"] == 1
        assert "assay.integrations.openai" in (payload.get("patch_line") or "")
        assert payload["entrypoint"] == "app.py"
        assert len(payload["next_steps"]) >= 4


def test_scan_no_findings_shows_next_moves() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("empty.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(assay_commands.assay_app, ["scan", "."])
        assert result.exit_code == 0
        assert "Next steps" in result.output
        assert "--allow-empty" in result.output


def test_scan_findings_shows_next_moves() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "resp = client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )
        result = runner.invoke(assay_commands.assay_app, ["scan", "."])
        assert result.exit_code == 0
        assert "Next steps" in result.output
        assert "assay run -c receipt_completeness" in result.output
