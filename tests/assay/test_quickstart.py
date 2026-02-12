"""Tests for assay quickstart command."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app


runner = CliRunner()


class TestQuickstart:
    def test_creates_demo_packs(self, tmp_path):
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "challenge_pack" / "good").exists()
        assert (tmp_path / "challenge_pack" / "tampered").exists()

    def test_scans_project(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n"
        )
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "uninstrumented" in result.output

    def test_skip_demo(self, tmp_path):
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path), "--skip-demo"])
        assert result.exit_code == 0, result.output
        assert not (tmp_path / "challenge_pack").exists()
        assert "Skipped" in result.output

    def test_json_output(self, tmp_path):
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["command"] == "quickstart"
        assert payload["status"] == "ok"
        assert "steps" in payload
        assert "next_steps" in payload

    def test_empty_project(self, tmp_path):
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path), "--skip-demo"])
        assert result.exit_code == 0, result.output
        assert "0 call site" in result.output or "No AI call sites" in result.output or "0 uninstrumented" in result.output

    def test_generates_report(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n"
        )
        result = runner.invoke(assay_app, ["quickstart", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "assay_quickstart_report.html").exists()
