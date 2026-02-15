"""Tests for assay start guided entrypoints."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()


class TestStartHelp:
    def test_start_no_args_shows_help(self):
        """assay start with no subcommand shows help (exit 0 or 2)."""
        result = runner.invoke(assay_app, ["start"])
        assert result.exit_code in (0, 2)  # Typer no_args_is_help exits 2
        assert "demo" in result.output
        assert "ci" in result.output
        assert "mcp" in result.output

    def test_start_help_flag(self):
        """assay start --help shows all subcommands."""
        result = runner.invoke(assay_app, ["start", "--help"])
        assert result.exit_code == 0
        assert "Guided setup" in result.output


class TestStartDemo:
    def test_demo_runs(self, tmp_path, monkeypatch):
        """assay start demo runs without error."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["start", "demo"])
        # quickstart creates challenge_pack
        assert result.exit_code == 0 or result.exit_code is None

    def test_demo_json_output(self, tmp_path, monkeypatch):
        """assay start demo --json produces valid JSON."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["start", "demo", "--json"])
        assert result.exit_code == 0 or result.exit_code is None
        data = json.loads(result.output)
        assert data["command"] == "quickstart"
        assert "steps" in data


class TestStartCI:
    def test_ci_shows_steps(self):
        """assay start ci shows all 5 setup steps."""
        result = runner.invoke(assay_app, ["start", "ci"])
        assert result.exit_code == 0
        assert "Step 1" in result.output
        assert "Step 2" in result.output
        assert "Step 3" in result.output
        assert "Step 4" in result.output
        assert "Step 5" in result.output

    def test_ci_shows_key_commands(self):
        """CI path shows the essential commands."""
        result = runner.invoke(assay_app, ["start", "ci"])
        assert "assay patch" in result.output
        assert "assay run" in result.output
        assert "assay verify-pack" in result.output
        assert "assay lock write" in result.output
        assert "assay ci init" in result.output

    def test_ci_shows_daily_use(self):
        """CI path shows daily regression forensics command."""
        result = runner.invoke(assay_app, ["start", "ci"])
        assert "--against-previous" in result.output
        assert "--why" in result.output

    def test_ci_json_output(self):
        """assay start ci --json produces valid JSON with steps."""
        result = runner.invoke(assay_app, ["start", "ci", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "start ci"
        assert len(data["steps"]) == 5
        for step in data["steps"]:
            assert "step" in step
            assert "title" in step
            assert "commands" in step
            assert "note" in step

    def test_ci_step_order(self):
        """Steps are in correct order."""
        result = runner.invoke(assay_app, ["start", "ci", "--json"])
        data = json.loads(result.output)
        step_nums = [s["step"] for s in data["steps"]]
        assert step_nums == [1, 2, 3, 4, 5]


class TestStartMCP:
    def test_mcp_shows_steps(self):
        """assay start mcp shows all 4 setup steps."""
        result = runner.invoke(assay_app, ["start", "mcp"])
        assert result.exit_code == 0
        assert "Step 1" in result.output
        assert "Step 2" in result.output
        assert "Step 3" in result.output
        assert "Step 4" in result.output

    def test_mcp_shows_key_commands(self):
        """MCP path shows the proxy command."""
        result = runner.invoke(assay_app, ["start", "mcp"])
        assert "assay mcp-proxy" in result.output
        assert "--server-id" in result.output
        assert "--store-args" in result.output

    def test_mcp_shows_what_you_get(self):
        """MCP path explains the output."""
        result = runner.invoke(assay_app, ["start", "mcp"])
        assert "MCPToolCallReceipt" in result.output
        assert "session_complete" in result.output
        assert "privacy-by-default" in result.output.lower() or "Privacy-by-default" in result.output

    def test_mcp_json_output(self):
        """assay start mcp --json produces valid JSON with steps."""
        result = runner.invoke(assay_app, ["start", "mcp", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "start mcp"
        assert len(data["steps"]) == 4

    def test_mcp_step_order(self):
        """Steps are in correct order."""
        result = runner.invoke(assay_app, ["start", "mcp", "--json"])
        data = json.loads(result.output)
        step_nums = [s["step"] for s in data["steps"]]
        assert step_nums == [1, 2, 3, 4]
