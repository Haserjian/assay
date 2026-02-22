"""Tests for template generators (Stage 1 PR4).

Tests:
  - assay mcp policy init (YAML generation)
  - assay ci init github (diff --report in workflow template)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()


class TestMCPPolicyInit:
    def test_creates_policy_file(self, tmp_path, monkeypatch):
        """assay mcp policy init creates a YAML file."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["mcp", "policy", "init"])
        assert result.exit_code == 0
        assert (tmp_path / "assay.mcp-policy.yaml").exists()

    def test_policy_file_content(self, tmp_path, monkeypatch):
        """Generated policy has expected keys."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(assay_app, ["mcp", "policy", "init"])
        content = (tmp_path / "assay.mcp-policy.yaml").read_text()
        assert "server_id:" in content
        assert "store_args: false" in content
        assert "store_results: false" in content
        assert "auto_pack: true" in content
        assert "audit_dir:" in content

    def test_policy_custom_server_id(self, tmp_path, monkeypatch):
        """--server-id pre-fills the server_id field."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(assay_app, ["mcp", "policy", "init", "--server-id", "test-srv"])
        content = (tmp_path / "assay.mcp-policy.yaml").read_text()
        assert '"test-srv"' in content

    def test_policy_custom_output(self, tmp_path, monkeypatch):
        """-o sets a custom output path."""
        monkeypatch.chdir(tmp_path)
        out = str(tmp_path / "custom.yaml")
        result = runner.invoke(assay_app, ["mcp", "policy", "init", "-o", out])
        assert result.exit_code == 0
        assert Path(out).exists()

    def test_policy_no_overwrite(self, tmp_path, monkeypatch):
        """Refuses to overwrite existing file without --force."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "assay.mcp-policy.yaml").write_text("existing")
        result = runner.invoke(assay_app, ["mcp", "policy", "init"])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_policy_force_overwrite(self, tmp_path, monkeypatch):
        """--force overwrites existing file."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "assay.mcp-policy.yaml").write_text("existing")
        result = runner.invoke(assay_app, ["mcp", "policy", "init", "--force"])
        assert result.exit_code == 0
        content = (tmp_path / "assay.mcp-policy.yaml").read_text()
        assert "server_id:" in content

    def test_policy_json_output(self, tmp_path, monkeypatch):
        """--json produces valid JSON."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["mcp", "policy", "init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "mcp policy init"
        assert data["status"] == "ok"
        assert "output" in data
        assert "server_id" in data

    def test_policy_json_error(self, tmp_path, monkeypatch):
        """--json error when file exists."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "assay.mcp-policy.yaml").write_text("existing")
        result = runner.invoke(assay_app, ["mcp", "policy", "init", "--json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"

    def test_policy_has_tool_restriction_comments(self, tmp_path, monkeypatch):
        """Policy template includes commented-out tool restriction examples."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(assay_app, ["mcp", "policy", "init"])
        content = (tmp_path / "assay.mcp-policy.yaml").read_text()
        assert "deny" in content
        assert "allow" in content
        assert "constraints" in content

    def test_policy_has_v1_fields(self, tmp_path, monkeypatch):
        """Policy template includes v1 schema fields."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(assay_app, ["mcp", "policy", "init"])
        content = (tmp_path / "assay.mcp-policy.yaml").read_text()
        assert 'version: "1"' in content
        assert "mode: audit" in content

    def test_generated_policy_validates(self, tmp_path, monkeypatch):
        """Generated policy file passes validate."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(assay_app, ["mcp", "policy", "init"])
        path = str(tmp_path / "assay.mcp-policy.yaml")
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", path])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()


class TestMCPPolicyValidate:
    def test_validate_valid_policy(self, tmp_path):
        """Validates a correct policy file."""
        p = tmp_path / "policy.yaml"
        p.write_text('version: "1"\nserver_id: test\nmode: enforce\n')
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(p)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()
        assert "enforce" in result.output

    def test_validate_missing_file(self, tmp_path):
        """Error for missing file."""
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    def test_validate_invalid_yaml(self, tmp_path):
        """Error for invalid YAML."""
        p = tmp_path / "bad.yaml"
        p.write_text("{{not: valid: yaml: [}")
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(p)])
        assert result.exit_code == 1

    def test_validate_invalid_mode(self, tmp_path):
        """Error for invalid mode."""
        p = tmp_path / "bad.yaml"
        p.write_text("mode: turbo\n")
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(p)])
        assert result.exit_code == 1

    def test_validate_json_output(self, tmp_path):
        """--json produces valid JSON summary."""
        p = tmp_path / "policy.yaml"
        p.write_text('version: "1"\nserver_id: json-test\nmode: audit\n')
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(p), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["mode"] == "audit"
        assert data["server_id"] == "json-test"
        assert data["hash"].startswith("sha256:")

    def test_validate_json_error(self, tmp_path):
        """--json error on bad file."""
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(tmp_path / "nope.yaml"), "--json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"

    def test_validate_shows_rule_counts(self, tmp_path):
        """Validate output shows deny/allow/constraint counts."""
        p = tmp_path / "policy.yaml"
        p.write_text(
            'version: "1"\nserver_id: test\nmode: enforce\n'
            "tools:\n  default: allow\n  deny:\n    - 'delete_*'\n    - 'drop_*'\n"
            "  allow:\n    - 'read_*'\n"
            "  constraints:\n    web_fetch:\n      max_calls: 5\n"
            "budget:\n  max_tool_calls: 20\n"
        )
        result = runner.invoke(assay_app, ["mcp", "policy", "validate", str(p)])
        assert result.exit_code == 0
        assert "2" in result.output  # 2 deny rules
        assert "20" in result.output  # budget


class TestMCPHelp:
    def test_mcp_no_args_shows_help(self):
        """assay mcp with no subcommand shows help."""
        result = runner.invoke(assay_app, ["mcp"])
        assert result.exit_code in (0, 2)
        assert "policy" in result.output

    def test_mcp_policy_no_args_shows_help(self):
        """assay mcp policy with no subcommand shows help."""
        result = runner.invoke(assay_app, ["mcp", "policy"])
        assert result.exit_code in (0, 2)
        assert "init" in result.output
        assert "validate" in result.output


class TestCIInitDiffReport:
    def test_ci_workflow_has_diff_comment(self, tmp_path, monkeypatch):
        """CI workflow template includes commented-out diff --report step."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, [
            "ci", "init", "github",
            "--run-command", "python app.py",
        ])
        assert result.exit_code == 0
        wf = (tmp_path / ".github" / "workflows" / "assay-verify.yml").read_text()
        assert "Regression Gate" in wf
        assert "assay diff" in wf
        assert "--report" in wf
        assert "Upload Diff Report" in wf
        assert "assay-diff-report" in wf
