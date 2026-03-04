"""Tests for assay lock init command."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


def _build_valid_pack(tmp_path: Path) -> Path:
    """Build a minimal valid proof pack for --from-pack tests."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test-signer")
    entries = [
        {
            "receipt_id": "r_lock_init_1",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 0,
        }
    ]
    pack = ProofPack(
        run_id="lock-init-test",
        entries=entries,
        signer_id="test-signer",
        claims=[],
        mode="shadow",
    )
    return pack.build(tmp_path / "proof_pack_from_pack", keystore=ks)


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

    def test_from_pack_imports_claim_set_hash(self, tmp_path, monkeypatch):
        """--from-pack should copy claim_set_hash from a verified source pack."""
        monkeypatch.chdir(tmp_path)
        pack_dir = _build_valid_pack(tmp_path)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        result = runner.invoke(
            assay_app,
            ["lock", "init", "--from-pack", str(pack_dir), "-o", "from_pack.lock"],
        )

        assert result.exit_code == 0
        data = json.loads((tmp_path / "from_pack.lock").read_text())
        assert data["claim_set_hash"] == manifest["claim_set_hash"]

    def test_from_pack_rejects_unverified_pack(self, tmp_path, monkeypatch):
        """--from-pack must fail closed if source pack integrity verification fails."""
        monkeypatch.chdir(tmp_path)
        pack_dir = _build_valid_pack(tmp_path)

        # Tamper after signing: detached signature no longer matches manifest bytes.
        with (pack_dir / "pack_signature.sig").open("ab") as f:
            f.write(b"x")

        result = runner.invoke(
            assay_app,
            ["lock", "init", "--from-pack", str(pack_dir), "-o", "should_not_exist.lock"],
        )

        assert result.exit_code == 1
        assert "Cannot import claim_set_hash from unverified pack" in result.output
        assert not (tmp_path / "should_not_exist.lock").exists()
