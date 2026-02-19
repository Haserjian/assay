"""Tests for key lifecycle UX commands: generate, info, export, import, revoke."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.lockfile import write_lockfile

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


# ---------------------------------------------------------------------------
# key generate
# ---------------------------------------------------------------------------

class TestKeyGenerate:
    def test_creates_key_and_sets_active(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "generate", "my-signer", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["signer_id"] == "my-signer"
        assert data["active_signer"] == "my-signer"
        assert len(data["fingerprint"]) == 64

    def test_default_signer_id(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "generate", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signer_id"] == "assay-local"

    def test_no_set_active(self, assay_home_tmp: Path) -> None:
        # Create a first key to have an active
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("existing")
        ks.set_active_signer("existing")

        result = runner.invoke(assay_app, ["key", "generate", "new-key", "--no-set-active", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["active_signer"] == "existing"

    def test_rejects_duplicate(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("taken")

        result = runner.invoke(assay_app, ["key", "generate", "taken", "--json"])
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "already exists" in data["error"]

    def test_human_output(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "generate", "test-key"])
        assert result.exit_code == 0
        assert "Key generated" in result.output
        assert "test-key" in result.output


# ---------------------------------------------------------------------------
# key info
# ---------------------------------------------------------------------------

class TestKeyInfo:
    def test_shows_info_json(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("info-test")
        ks.set_active_signer("info-test")

        result = runner.invoke(assay_app, ["key", "info", "info-test", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signer_id"] == "info-test"
        assert data["algorithm"] == "Ed25519"
        assert len(data["fingerprint"]) == 64
        assert data["pubkey_b64"]
        assert data["is_active"] is True

    def test_defaults_to_active(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("default-active")
        ks.set_active_signer("default-active")

        result = runner.invoke(assay_app, ["key", "info", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signer_id"] == "default-active"

    def test_not_found(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "info", "missing", "--json"])
        assert result.exit_code == 3

    def test_pubkey_is_valid_b64(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("b64-test")

        result = runner.invoke(assay_app, ["key", "info", "b64-test", "--json"])
        data = json.loads(result.output)
        decoded = base64.b64decode(data["pubkey_b64"])
        assert len(decoded) == 32  # Ed25519 public key = 32 bytes


# ---------------------------------------------------------------------------
# key export
# ---------------------------------------------------------------------------

class TestKeyExport:
    def test_exports_public_only(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("export-test")

        out_dir = tmp_path / "exported"
        result = runner.invoke(
            assay_app,
            ["key", "export", "export-test", "-o", str(out_dir), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["includes_private"] is False
        assert len(data["files"]) == 2

        pub_file = out_dir / "export-test.pub.b64"
        fp_file = out_dir / "export-test.fingerprint"
        assert pub_file.exists()
        assert fp_file.exists()
        assert len(base64.b64decode(pub_file.read_text().strip())) == 32

    def test_exports_with_private(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("priv-test")

        out_dir = tmp_path / "exported-priv"
        result = runner.invoke(
            assay_app,
            ["key", "export", "priv-test", "--private", "-o", str(out_dir), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["includes_private"] is True
        assert len(data["files"]) == 3

        key_file = out_dir / "priv-test.key.b64"
        assert key_file.exists()
        assert len(base64.b64decode(key_file.read_text().strip())) == 32

    def test_default_output_dir(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("default-dir")

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["key", "export", "default-dir", "--json"])
        assert result.exit_code == 0
        assert (tmp_path / "default-dir-export" / "default-dir.pub.b64").exists()

    def test_not_found(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "export", "missing", "--json"])
        assert result.exit_code == 3

    def test_defaults_to_active(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("act")
        ks.set_active_signer("act")

        out_dir = tmp_path / "exp-active"
        result = runner.invoke(assay_app, ["key", "export", "-o", str(out_dir), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signer_id"] == "act"


# ---------------------------------------------------------------------------
# key import
# ---------------------------------------------------------------------------

class TestKeyImport:
    def _export_key(self, ks: AssayKeyStore, signer_id: str, out_dir: Path, *, private: bool = True):
        """Helper to export a key for import testing."""
        pub_bytes = ks.get_verify_key(signer_id).encode()
        pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{signer_id}.pub.b64").write_text(pub_b64 + "\n")
        if private:
            key_bytes = ks.get_signing_key(signer_id).encode()
            key_b64 = base64.b64encode(key_bytes).decode("ascii")
            (out_dir / f"{signer_id}.key.b64").write_text(key_b64 + "\n")

    def test_import_public_only(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        # Generate a key, export it, delete it, then import
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("imp-pub")
        fp_before = ks.signer_fingerprint("imp-pub")
        export_dir = tmp_path / "export"
        self._export_key(ks, "imp-pub", export_dir, private=False)
        ks.delete_key("imp-pub")

        result = runner.invoke(
            assay_app,
            ["key", "import", str(export_dir / "imp-pub.pub.b64"), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signer_id"] == "imp-pub"
        assert data["has_private"] is False
        assert data["fingerprint"] == fp_before

    def test_import_with_private(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("imp-priv")
        fp_before = ks.signer_fingerprint("imp-priv")
        export_dir = tmp_path / "export"
        self._export_key(ks, "imp-priv", export_dir, private=True)
        ks.delete_key("imp-priv")

        result = runner.invoke(
            assay_app,
            [
                "key", "import",
                str(export_dir / "imp-priv.pub.b64"),
                "--private", str(export_dir / "imp-priv.key.b64"),
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["has_private"] is True
        assert data["fingerprint"] == fp_before

    def test_import_set_active(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("imp-act")
        export_dir = tmp_path / "export"
        self._export_key(ks, "imp-act", export_dir, private=True)
        ks.delete_key("imp-act")

        result = runner.invoke(
            assay_app,
            [
                "key", "import",
                str(export_dir / "imp-act.pub.b64"),
                "--private", str(export_dir / "imp-act.key.b64"),
                "--set-active",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["active_signer"] == "imp-act"

    def test_import_custom_signer_id(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("orig-name")
        export_dir = tmp_path / "export"
        self._export_key(ks, "orig-name", export_dir, private=False)
        ks.delete_key("orig-name")

        result = runner.invoke(
            assay_app,
            [
                "key", "import",
                str(export_dir / "orig-name.pub.b64"),
                "--signer", "new-name",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["signer_id"] == "new-name"

    def test_rejects_duplicate(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("dup-test")
        export_dir = tmp_path / "export"
        self._export_key(ks, "dup-test", export_dir, private=False)

        result = runner.invoke(
            assay_app,
            ["key", "import", str(export_dir / "dup-test.pub.b64"), "--json"],
        )
        assert result.exit_code == 3
        assert "already exists" in json.loads(result.output)["error"]

    def test_bad_pub_file(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.pub.b64"
        bad_file.write_text("not-valid-base64!!!\n")

        result = runner.invoke(assay_app, ["key", "import", str(bad_file), "--json"])
        assert result.exit_code == 3

    def test_missing_file(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "import", "/nonexistent.pub.b64", "--json"])
        assert result.exit_code == 3


# ---------------------------------------------------------------------------
# key revoke
# ---------------------------------------------------------------------------

class TestKeyRevoke:
    def test_revoke_removes_from_lockfile(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("revoke-test")
        fp = ks.signer_fingerprint("revoke-test")

        lock_path = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], signer_fingerprints=[fp], output_path=lock_path)

        result = runner.invoke(
            assay_app,
            ["key", "revoke", "revoke-test", "--lock", str(lock_path), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["removed_from_allowlist"] is True
        assert data["lock_updated"] is True
        assert data["key_deleted"] is False

        # Verify lockfile was actually updated
        from assay.lockfile import load_lockfile
        updated = load_lockfile(lock_path)
        assert fp not in updated["signer_policy"]["allowed_fingerprints"]

    def test_revoke_with_delete(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("del-test")

        result = runner.invoke(
            assay_app,
            ["key", "revoke", "del-test", "--delete", "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["key_deleted"] is True
        assert not ks.has_key("del-test")

    def test_revoke_not_found(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["key", "revoke", "missing", "--json"])
        assert result.exit_code == 3

    def test_revoke_without_lock(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("no-lock")

        result = runner.invoke(assay_app, ["key", "revoke", "no-lock", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["lock_updated"] is False
        assert data["removed_from_allowlist"] is False

    def test_revoke_fp_not_in_allowlist(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("not-in-list")

        lock_path = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], signer_fingerprints=["otherfp"], output_path=lock_path)

        result = runner.invoke(
            assay_app,
            ["key", "revoke", "not-in-list", "--lock", str(lock_path), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["removed_from_allowlist"] is False

    def test_revoke_clears_active_signer(self, assay_home_tmp: Path) -> None:
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("active-rev")
        ks.set_active_signer("active-rev")

        result = runner.invoke(
            assay_app,
            ["key", "revoke", "active-rev", "--delete", "--json"],
        )
        assert result.exit_code == 0
        # Active signer marker should be cleared
        marker = ks._active_signer_path()
        assert not marker.exists()


# ---------------------------------------------------------------------------
# Keystore delete_key method
# ---------------------------------------------------------------------------

class TestKeystoreDeleteKey:
    def test_delete_key(self, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        ks.generate_key("to-delete")
        assert ks.has_key("to-delete")
        assert ks.delete_key("to-delete") is True
        assert not ks.has_key("to-delete")

    def test_delete_nonexistent(self, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        assert ks.delete_key("missing") is False

    def test_delete_clears_active_marker(self, tmp_path: Path) -> None:
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        ks.generate_key("active-del")
        ks.set_active_signer("active-del")
        ks.delete_key("active-del")
        assert not ks._active_signer_path().exists()


# ---------------------------------------------------------------------------
# Round-trip: export -> delete -> import -> sign/verify
# ---------------------------------------------------------------------------

class TestKeyRoundTrip:
    def test_export_import_roundtrip(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        """Full round-trip: generate -> export -> delete -> import -> verify."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        ks.generate_key("roundtrip")
        fp_before = ks.signer_fingerprint("roundtrip")

        # Sign something with original key
        test_data = b"test data for signing"
        sig_b64 = ks.sign_b64(test_data, "roundtrip")

        # Export
        out_dir = tmp_path / "rt-export"
        result = runner.invoke(
            assay_app,
            ["key", "export", "roundtrip", "--private", "-o", str(out_dir), "--json"],
        )
        assert result.exit_code == 0

        # Delete
        result = runner.invoke(
            assay_app,
            ["key", "revoke", "roundtrip", "--delete", "--json"],
        )
        assert result.exit_code == 0
        assert not ks.has_key("roundtrip")

        # Import
        result = runner.invoke(
            assay_app,
            [
                "key", "import",
                str(out_dir / "roundtrip.pub.b64"),
                "--private", str(out_dir / "roundtrip.key.b64"),
                "--set-active",
                "--json",
            ],
        )
        assert result.exit_code == 0

        # Verify fingerprint matches
        fp_after = ks.signer_fingerprint("roundtrip")
        assert fp_after == fp_before

        # Verify original signature still works
        assert ks.verify_b64(test_data, sig_b64, "roundtrip")
