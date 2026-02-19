"""Tests for packs list, show, and pin-baseline commands."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

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


def _make_receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
        "provider": "openai",
        "model_id": "gpt-4",
        "input_tokens": 100,
        "output_tokens": 50,
    }
    base.update(overrides)
    return base


def _build_pack(
    base_dir: Path,
    pack_name: str,
    assay_home: Path,
    *,
    n_receipts: int = 3,
) -> Path:
    """Build a minimal proof pack directory for testing."""
    ks = AssayKeyStore(keys_dir=assay_home / "keys")
    ks.ensure_key("assay-local")

    receipts = [_make_receipt(seq=i) for i in range(n_receipts)]
    pack = ProofPack(
        run_id=f"test-run-{pack_name}",
        entries=receipts,
        signer_id="assay-local",
        mode="shadow",
    )
    out_dir = pack.build(base_dir / pack_name, keystore=ks)
    return out_dir


class TestPacksList:
    def test_list_empty(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "empty"
        work_dir.mkdir()
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 0
        assert data["packs"] == []

    def test_list_finds_packs(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        _build_pack(work_dir, "proof_pack_a", assay_home_tmp)
        _build_pack(work_dir, "proof_pack_b", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 2
        pack_ids = {p["pack_id"] for p in data["packs"]}
        assert len(pack_ids) == 2

    def test_list_with_directory_option(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        work_dir = tmp_path / "packs"
        work_dir.mkdir()
        _build_pack(work_dir, "proof_pack_x", assay_home_tmp)

        result = runner.invoke(assay_app, ["packs", "list", "-d", str(work_dir), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 1

    def test_list_shows_baseline_marker(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work_bl"
        work_dir.mkdir()
        pack_a = _build_pack(work_dir, "proof_pack_a", assay_home_tmp)
        _build_pack(work_dir, "proof_pack_b", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        # Pin baseline
        from assay.diff import save_baseline
        save_baseline(pack_a)

        result = runner.invoke(assay_app, ["packs", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        baselines = [p for p in data["packs"] if p["is_baseline"]]
        assert len(baselines) == 1

    def test_list_has_metadata_fields(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work_meta"
        work_dir.mkdir()
        _build_pack(work_dir, "proof_pack_m", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "list", "--json"])
        data = json.loads(result.output)
        pack = data["packs"][0]
        assert "pack_id" in pack
        assert "n_receipts" in pack
        assert "receipt_integrity" in pack
        assert "signer_id" in pack
        assert "timestamp" in pack

    def test_list_human_output(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work_human"
        work_dir.mkdir()
        _build_pack(work_dir, "proof_pack_h", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "list"])
        assert result.exit_code == 0
        assert "packs list" in result.output
        assert "PASS" in result.output

    def test_list_ignores_non_pack_dirs(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work_ignore"
        work_dir.mkdir()
        (work_dir / "not_a_pack").mkdir()
        (work_dir / "proof_pack_no_manifest").mkdir()  # missing manifest
        _build_pack(work_dir, "proof_pack_real", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "list", "--json"])
        data = json.loads(result.output)
        assert data["count"] == 1


class TestPacksShow:
    def test_show_json(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        pack = _build_pack(work_dir, "proof_pack_show", assay_home_tmp)

        result = runner.invoke(assay_app, ["packs", "show", str(pack), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["pack_id"]
        assert data["run_id"]
        assert data["n_receipts"] == 3
        assert data["actual_receipt_lines"] == 3
        assert data["receipt_integrity"] in ("PASS", "FAIL")
        assert data["signer_id"] == "assay-local"
        assert data["signature_alg"] == "ed25519"
        assert isinstance(data["files"], list)

    def test_show_not_a_dir(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["packs", "show", "/nonexistent", "--json"])
        assert result.exit_code == 3

    def test_show_no_manifest(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty_pack"
        empty_dir.mkdir()
        result = runner.invoke(assay_app, ["packs", "show", str(empty_dir), "--json"])
        assert result.exit_code == 3

    def test_show_human_output(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        work_dir = tmp_path / "work_h"
        work_dir.mkdir()
        pack = _build_pack(work_dir, "proof_pack_human", assay_home_tmp)

        result = runner.invoke(assay_app, ["packs", "show", str(pack)])
        assert result.exit_code == 0
        assert "Pack ID:" in result.output
        assert "Signer:" in result.output
        assert "Integrity:" in result.output

    def test_show_baseline_flag(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work_bl"
        work_dir.mkdir()
        pack = _build_pack(work_dir, "proof_pack_bl", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        from assay.diff import save_baseline
        save_baseline(pack)

        result = runner.invoke(assay_app, ["packs", "show", str(pack), "--json"])
        data = json.loads(result.output)
        assert data["is_baseline"] is True

    def test_show_files_inventory(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        work_dir = tmp_path / "work_files"
        work_dir.mkdir()
        pack = _build_pack(work_dir, "proof_pack_files", assay_home_tmp)

        result = runner.invoke(assay_app, ["packs", "show", str(pack), "--json"])
        data = json.loads(result.output)
        file_paths = [f["path"] for f in data["files"]]
        assert "receipt_pack.jsonl" in file_paths
        assert "verify_report.json" in file_paths


class TestPacksPinBaseline:
    def test_pin_baseline(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        pack = _build_pack(work_dir, "proof_pack_pin", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "pin-baseline", str(pack), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["pack_path"]
        assert data["baseline_file"]

        # Verify baseline was saved
        from assay.diff import load_baseline
        bl = load_baseline()
        assert bl is not None
        assert bl.resolve() == pack.resolve()

    def test_pin_not_a_dir(self, assay_home_tmp: Path) -> None:
        result = runner.invoke(assay_app, ["packs", "pin-baseline", "/nonexistent", "--json"])
        assert result.exit_code == 3

    def test_pin_no_manifest(self, assay_home_tmp: Path, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(assay_app, ["packs", "pin-baseline", str(empty), "--json"])
        assert result.exit_code == 3

    def test_pin_human_output(self, assay_home_tmp: Path, tmp_path: Path, monkeypatch) -> None:
        work_dir = tmp_path / "work_h"
        work_dir.mkdir()
        pack = _build_pack(work_dir, "proof_pack_hpin", assay_home_tmp)
        monkeypatch.chdir(work_dir)

        result = runner.invoke(assay_app, ["packs", "pin-baseline", str(pack)])
        assert result.exit_code == 0
        assert "Baseline pinned" in result.output
