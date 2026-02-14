"""Tests for assay key management commands and active signer behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.lockfile import load_lockfile, write_lockfile

runner = CliRunner()


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    """Route ~/.assay to a temp dir and reset store globals."""
    import assay.store as store_mod

    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


class TestKeyStoreActiveSigner:
    def test_default_active_signer(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-local")
        assert ks.get_active_signer() == "assay-local"

    def test_set_active_signer(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-local")
        ks.generate_key("assay-next")
        ks.set_active_signer("assay-next")
        assert ks.get_active_signer() == "assay-next"


class TestKeyCLI:
    def test_key_list_json_empty(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "key list"
        assert data["status"] == "ok"
        assert data["signers"] == []

    def test_key_set_active_unknown(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "set-active", "missing"])
        assert result.exit_code == 3
        assert "Signer not found" in result.output

    def test_key_rotate_creates_new_signer_and_sets_active(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-local")

        result = runner.invoke(
            assay_app,
            ["key", "rotate", "--signer", "assay-local", "--new-signer", "assay-rot", "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["old_signer"] == "assay-local"
        assert data["new_signer"] == "assay-rot"
        assert data["active_signer"] == "assay-rot"
        assert data["lock_updated"] is False
        assert ks.has_key("assay-rot")

    def test_key_rotate_no_set_active(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-local")
        ks.set_active_signer("assay-local")

        result = runner.invoke(
            assay_app,
            [
                "key",
                "rotate",
                "--signer",
                "assay-local",
                "--new-signer",
                "assay-rot2",
                "--no-set-active",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["active_signer"] == "assay-local"
        assert ks.has_key("assay-rot2")

    def test_key_set_active_success(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-local")
        ks.generate_key("assay-next")

        result = runner.invoke(assay_app, ["key", "set-active", "assay-next", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["active_signer"] == "assay-next"
        assert ks.get_active_signer() == "assay-next"

    def test_key_rotate_updates_lock_allowlist(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-local")
        old_fp = ks.signer_fingerprint("assay-local")

        lock_path = tmp_path / "assay.lock"
        write_lockfile(
            ["receipt_completeness"],
            signer_fingerprints=[old_fp],
            output_path=lock_path,
        )

        result = runner.invoke(
            assay_app,
            [
                "key",
                "rotate",
                "--signer",
                "assay-local",
                "--new-signer",
                "assay-rot3",
                "--lock",
                str(lock_path),
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["lock_updated"] is True

        updated = load_lockfile(lock_path)
        new_fp = ks.signer_fingerprint("assay-rot3")
        assert updated["signer_policy"]["mode"] == "allowlist"
        assert old_fp in updated["signer_policy"]["allowed_fingerprints"]
        assert new_fp in updated["signer_policy"]["allowed_fingerprints"]

    def test_run_uses_active_signer(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("assay-signer-a")
        ks.set_active_signer("assay-signer-a")

        out = tmp_path / "proof_pack_run"
        result = runner.invoke(
            assay_app,
            [
                "run",
                "--allow-empty",
                "-o",
                str(out),
                "--",
                "python3",
                "-c",
                "print('ok')",
            ],
        )
        assert result.exit_code == 0
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["signer_id"] == "assay-signer-a"
