"""Tests for assay flow command group."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.flow import (
    FlowDefinition,
    FlowStep,
    StepResult,
    run_flow,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Engine unit tests
# ---------------------------------------------------------------------------

class TestFlowEngine:
    def test_dry_run_returns_planned(self):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[FlowStep(number=1, title="Echo", command="echo hello")],
        )
        result = run_flow(flow, apply=False)
        assert result.status == "dry_run"
        assert result.steps[0].status == "planned"
        assert result.failed_step is None

    def test_apply_runs_command(self, tmp_path):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[FlowStep(number=1, title="Echo", command="echo hello")],
        )
        result = run_flow(flow, apply=True, cwd=tmp_path)
        assert result.status == "ok"
        assert result.steps[0].status == "ok"
        assert result.steps[0].exit_code == 0

    def test_fail_fast_on_error(self, tmp_path):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[
                FlowStep(number=1, title="Fail", command="exit 1"),
                FlowStep(number=2, title="Never", command="echo never"),
            ],
        )
        result = run_flow(flow, apply=True, cwd=tmp_path)
        assert result.status == "failed"
        assert result.failed_step == 1
        assert len(result.steps) == 1

    def test_skip_fn_skips(self, tmp_path):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[FlowStep(
                number=1, title="Skippable", command="echo hello",
                skip_fn=lambda cwd, r: (True, "always skip"),
            )],
        )
        result = run_flow(flow, apply=True, cwd=tmp_path)
        assert result.steps[0].status == "skipped"
        assert result.steps[0].skip_reason == "always skip"

    def test_expected_exit_codes(self, tmp_path):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[FlowStep(
                number=1, title="Expected exit 2", command="exit 2",
                expected_exit_codes=[0, 2],
            )],
        )
        result = run_flow(flow, apply=True, cwd=tmp_path)
        assert result.status == "ok"
        assert result.steps[0].status == "ok"
        assert result.steps[0].exit_code == 2

    def test_print_only_not_executed(self, tmp_path):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[FlowStep(
                number=1, title="Info", command="exit 99",
                print_only=True,
            )],
        )
        result = run_flow(flow, apply=True, cwd=tmp_path)
        assert result.steps[0].status == "print_only"
        assert result.steps[0].exit_code is None

    def test_command_fn_dynamic(self, tmp_path):
        flow = FlowDefinition(
            name="test", description="test",
            steps=[
                FlowStep(number=1, title="First", command="echo first"),
                FlowStep(
                    number=2, title="Dynamic",
                    command="echo fallback",
                    command_fn=lambda r: f"echo step1_was_{r[1].status}",
                ),
            ],
        )
        result = run_flow(flow, apply=True, cwd=tmp_path)
        assert result.status == "ok"
        assert "step1_was_ok" in result.steps[1].command

    def test_to_dict(self):
        result = run_flow(
            FlowDefinition(
                name="x", description="d",
                steps=[FlowStep(number=1, title="T", command="echo")],
            ),
            apply=False,
        )
        d = result.to_dict()
        assert d["flow"] == "x"
        assert d["status"] == "dry_run"
        assert len(d["steps"]) == 1
        assert d["steps"][0]["step"] == 1


# ---------------------------------------------------------------------------
# CLI tests -- help and dry-run (no side effects)
# ---------------------------------------------------------------------------

class TestFlowHelp:
    def test_flow_no_args_shows_help(self):
        result = runner.invoke(assay_app, ["flow"])
        assert result.exit_code in (0, 2)
        assert "try" in result.output
        assert "adopt" in result.output
        assert "ci" in result.output
        assert "mcp" in result.output
        assert "audit" in result.output


class TestFlowTryDryRun:
    def test_shows_steps(self):
        result = runner.invoke(assay_app, ["flow", "try"])
        assert result.exit_code == 0
        assert "Step 1" in result.output
        assert "Step 2" in result.output
        assert "Step 3" in result.output
        assert "demo-challenge" in result.output
        assert "Dry run" in result.output

    def test_json_output(self):
        result = runner.invoke(assay_app, ["flow", "try", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["flow"] == "try"
        assert data["status"] == "dry_run"
        assert len(data["steps"]) == 3


class TestFlowAdoptDryRun:
    def test_shows_five_steps(self):
        result = runner.invoke(assay_app, ["flow", "adopt"])
        assert result.exit_code == 0
        assert "Step 1" in result.output
        assert "Step 5" in result.output
        assert "assay scan" in result.output
        assert "assay run" in result.output

    def test_custom_run_command(self):
        result = runner.invoke(assay_app, [
            "flow", "adopt", "--run-command", "python my_agent.py",
        ])
        assert "python my_agent.py" in result.output

    def test_json_output(self):
        result = runner.invoke(assay_app, ["flow", "adopt", "--json"])
        data = json.loads(result.output)
        assert data["flow"] == "adopt"
        assert len(data["steps"]) == 5


class TestFlowCIDryRun:
    def test_shows_steps(self):
        result = runner.invoke(assay_app, ["flow", "ci"])
        assert result.exit_code == 0
        assert "assay lock init" in result.output
        assert "assay ci init" in result.output
        assert "assay baseline set" in result.output

    def test_json_output(self):
        result = runner.invoke(assay_app, ["flow", "ci", "--json"])
        data = json.loads(result.output)
        assert data["flow"] == "ci"
        assert len(data["steps"]) == 3


class TestFlowMCPDryRun:
    def test_shows_steps(self):
        result = runner.invoke(assay_app, ["flow", "mcp"])
        assert result.exit_code == 0
        assert "mcp policy init" in result.output
        assert "mcp-proxy" in result.output

    def test_server_command(self):
        result = runner.invoke(assay_app, [
            "flow", "mcp", "--server-command", "python my_server.py",
        ])
        assert "python my_server.py" in result.output

    def test_json_proxy_is_print_only(self):
        result = runner.invoke(assay_app, ["flow", "mcp", "--json"])
        data = json.loads(result.output)
        assert data["steps"][1]["status"] in ("planned", "print_only")


class TestFlowAuditDryRun:
    def test_shows_steps(self):
        result = runner.invoke(assay_app, ["flow", "audit"])
        assert result.exit_code == 0
        assert "verify-pack" in result.output
        assert "explain" in result.output

    def test_custom_pack_dir(self):
        result = runner.invoke(assay_app, ["flow", "audit", "./my_pack/"])
        assert "./my_pack/" in result.output

    def test_json_output(self):
        result = runner.invoke(assay_app, ["flow", "audit", "--json"])
        data = json.loads(result.output)
        assert data["flow"] == "audit"
        assert len(data["steps"]) == 3


# ---------------------------------------------------------------------------
# CLI tests -- apply mode
# ---------------------------------------------------------------------------

class TestFlowTryApply:
    def test_apply_creates_challenge_packs(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["flow", "try", "--apply"])
        # demo-challenge should create the packs
        assert (tmp_path / "challenge_pack" / "good").exists() or "PASS" in result.output or "FAIL" in result.output

    def test_apply_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["flow", "try", "--apply", "--json"])
        data = json.loads(result.output)
        assert data["flow"] == "try"
        assert data["status"] in ("ok", "failed")
        assert len(data["steps"]) >= 1


class TestFlowCIApply:
    def test_skip_lock_if_exists(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "assay.lock").write_text("{}")
        result = runner.invoke(assay_app, ["flow", "ci", "--apply", "--json"])
        data = json.loads(result.output)
        assert data["steps"][0]["status"] == "skipped"
        assert "already exists" in data["steps"][0]["skip_reason"]


class TestFlowMCPApply:
    def test_skip_policy_if_exists(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "assay.mcp-policy.yaml").write_text("server_id: test\n")
        result = runner.invoke(assay_app, ["flow", "mcp", "--apply", "--json"])
        data = json.loads(result.output)
        assert data["steps"][0]["status"] == "skipped"
