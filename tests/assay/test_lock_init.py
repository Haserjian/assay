"""Tests for assay lock init command."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()


class TestLockInit:
    def test_creates_lockfile(self, tmp_path, monkeypatch):
        """assay lock init creates assay.lock with receipt_completeness."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["lock", "init"])
        assert result.exit_code == 0
        lock_path = tmp_path / "assay.lock"
        assert lock_path.exists()
        data = json.loads(lock_path.read_text())
        card_ids = [c["id"] for c in data["run_cards"]]
        assert "receipt_completeness" in card_ids

    def test_refuses_if_exists(self, tmp_path, monkeypatch):
        """assay lock init refuses to overwrite existing lockfile."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "assay.lock").write_text("{}")
        result = runner.invoke(assay_app, ["lock", "init"])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_custom_output_path(self, tmp_path, monkeypatch):
        """assay lock init -o custom.lock writes to custom path."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["lock", "init", "-o", "custom.lock"])
        assert result.exit_code == 0
        assert (tmp_path / "custom.lock").exists()

    def test_json_output(self, tmp_path, monkeypatch):
        """assay lock init --json produces valid JSON."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["lock", "init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "lock init"
        assert data["status"] == "ok"
        assert "receipt_completeness" in data["run_cards"]

    def test_next_hint_in_output(self, tmp_path, monkeypatch):
        """assay lock init shows Next: hint."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["lock", "init"])
        assert result.exit_code == 0
        assert "Next:" in result.output
        assert "ci init github" in result.output

    def test_lockfile_has_sane_defaults(self, tmp_path, monkeypatch):
        """Lockfile from init has expected structure."""
        monkeypatch.chdir(tmp_path)
        runner.invoke(assay_app, ["lock", "init"])
        data = json.loads((tmp_path / "assay.lock").read_text())
        assert "lock_version" in data
        assert "run_cards_composite_hash" in data
        assert "signer_policy" in data
        assert data["signer_policy"]["mode"] == "any"
