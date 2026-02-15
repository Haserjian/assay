"""Tests for assay status command."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from assay.cli import main as cli_main


# The CLI app is registered in assay.cli; use CliRunner to invoke.
# We need the Typer app object.
from assay.commands import assay_app

runner = CliRunner()


class TestStatusCommand:
    def test_status_runs(self, tmp_path, monkeypatch):
        """Status command exits 0 and shows key sections."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status"])
        assert result.exit_code == 0
        assert "assay status" in result.output
        assert "Version" in result.output
        assert "Signer" in result.output
        assert "Store" in result.output
        assert "Lockfile" in result.output
        assert "MCP proxy" in result.output

    def test_status_json_output(self, tmp_path, monkeypatch):
        """--json produces valid JSON with expected keys."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "status"
        assert "version" in data
        assert "key" in data
        assert "store" in data
        assert "lockfile" in data
        assert "latest_pack" in data
        assert "mcp_proxy" in data

    def test_status_shows_version(self, tmp_path, monkeypatch):
        """Version in status matches __version__."""
        monkeypatch.chdir(tmp_path)
        from assay import __version__
        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["version"] == __version__

    def test_status_key_info(self, tmp_path, monkeypatch):
        """Key section shows signer info."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        key = data["key"]
        assert "signer" in key
        assert "has_key" in key
        assert "fingerprint" in key
        assert "total_signers" in key
        assert isinstance(key["has_key"], bool)
        assert isinstance(key["total_signers"], int)

    def test_status_store_counts(self, tmp_path, monkeypatch):
        """Store section has receipt and trace counts."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        store = data["store"]
        assert "path" in store
        assert "traces" in store
        assert "receipts" in store
        assert isinstance(store["traces"], int)
        assert isinstance(store["receipts"], int)

    def test_status_no_lockfile(self, tmp_path, monkeypatch):
        """No lockfile in cwd shows present=false."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["lockfile"]["present"] is False

    def test_status_with_lockfile(self, tmp_path, monkeypatch):
        """Lockfile detected when present in cwd."""
        monkeypatch.chdir(tmp_path)
        lock = {
            "lock_version": 1,
            "run_cards": {"receipt_completeness": {}},
            "assay_version_min": "1.0.0",
        }
        (tmp_path / "assay.lock").write_text(json.dumps(lock))

        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["lockfile"]["present"] is True
        assert data["lockfile"]["lock_version"] == 1
        assert "receipt_completeness" in data["lockfile"]["cards"]

    def test_status_no_packs(self, tmp_path, monkeypatch):
        """No packs in cwd shows latest_pack=null."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["latest_pack"] is None

    def test_status_with_pack(self, tmp_path, monkeypatch):
        """Pack detected when proof_pack dir with manifest exists."""
        monkeypatch.chdir(tmp_path)
        pack_dir = tmp_path / "proof_pack_test_001"
        pack_dir.mkdir()
        manifest = {
            "pack_id": "pack_test_001",
            "receipt_count_expected": 5,
        }
        (pack_dir / "pack_manifest.json").write_text(json.dumps(manifest))

        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["latest_pack"] is not None
        assert data["latest_pack"]["pack_id"] == "pack_test_001"
        assert data["latest_pack"]["receipts"] == 5

    def test_status_mcp_proxy_ready(self, tmp_path, monkeypatch):
        """MCP proxy always shows available=true."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status", "--json"])
        data = json.loads(result.output)
        assert data["mcp_proxy"]["available"] is True

    def test_status_operational_with_key(self, tmp_path, monkeypatch):
        """Shows OPERATIONAL when key exists."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status"])
        # If we have a key (default dev environment), should show OPERATIONAL
        if "OPERATIONAL" not in result.output:
            assert "SETUP NEEDED" in result.output

    def test_status_text_no_crash_empty_dir(self, tmp_path, monkeypatch):
        """Status doesn't crash on empty directory with no packs/lockfile."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["status"])
        assert result.exit_code == 0
