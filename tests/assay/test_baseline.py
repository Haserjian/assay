"""Tests for assay baseline set/get and diff --against-previous integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.diff import load_baseline, save_baseline

runner = CliRunner()


def _make_pack(parent: Path, name: str = "proof_pack_001") -> Path:
    """Create a minimal valid pack directory."""
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "pack_manifest.json").write_text(json.dumps({
        "attestation": {"pack_id": name},
        "files": [],
    }))
    (d / "receipt_pack.jsonl").write_text("")
    return d


class TestSaveLoadBaseline:
    def test_save_and_load(self, tmp_path):
        pack = _make_pack(tmp_path)
        save_baseline(pack, project_dir=tmp_path)
        result = load_baseline(project_dir=tmp_path)
        assert result is not None
        assert result.resolve() == pack.resolve()

    def test_load_returns_none_when_no_file(self, tmp_path):
        assert load_baseline(project_dir=tmp_path) is None

    def test_load_returns_none_when_pack_deleted(self, tmp_path):
        pack = _make_pack(tmp_path)
        save_baseline(pack, project_dir=tmp_path)
        # Delete the pack
        import shutil
        shutil.rmtree(pack)
        assert load_baseline(project_dir=tmp_path) is None

    def test_save_stores_relative_path(self, tmp_path):
        pack = _make_pack(tmp_path)
        bf = save_baseline(pack, project_dir=tmp_path)
        data = json.loads(bf.read_text())
        # Should be relative, not absolute
        assert not Path(data["pack_path"]).is_absolute()

    def test_save_creates_assay_dir(self, tmp_path):
        pack = _make_pack(tmp_path)
        save_baseline(pack, project_dir=tmp_path)
        assert (tmp_path / ".assay").is_dir()
        assert (tmp_path / ".assay" / "baseline.json").exists()


class TestBaselineSetCmd:
    def test_set_creates_baseline(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pack = _make_pack(tmp_path)
        result = runner.invoke(assay_app, ["baseline", "set", str(pack)])
        assert result.exit_code == 0
        assert "Baseline set" in result.output

    def test_set_rejects_nondir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["baseline", "set", "nonexistent"])
        assert result.exit_code == 3

    def test_set_rejects_no_manifest(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        d = tmp_path / "empty_dir"
        d.mkdir()
        result = runner.invoke(assay_app, ["baseline", "set", str(d)])
        assert result.exit_code == 3
        assert "pack_manifest.json" in result.output

    def test_set_json_output(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pack = _make_pack(tmp_path)
        result = runner.invoke(assay_app, ["baseline", "set", str(pack), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "baseline set"
        assert data["status"] == "ok"

    def test_set_shows_next_hint(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pack = _make_pack(tmp_path)
        result = runner.invoke(assay_app, ["baseline", "set", str(pack)])
        assert "Next:" in result.output
        assert "--against-previous" in result.output


class TestBaselineGetCmd:
    def test_get_when_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["baseline", "get"])
        assert result.exit_code == 0
        assert "No baseline set" in result.output

    def test_get_after_set(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pack = _make_pack(tmp_path)
        runner.invoke(assay_app, ["baseline", "set", str(pack)])
        result = runner.invoke(assay_app, ["baseline", "get"])
        assert result.exit_code == 0
        assert "proof_pack_001" in result.output

    def test_get_json_when_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["baseline", "get", "--json"])
        data = json.loads(result.output)
        assert data["status"] == "none"
        assert data["pack_path"] is None

    def test_get_json_after_set(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pack = _make_pack(tmp_path)
        runner.invoke(assay_app, ["baseline", "set", str(pack)])
        result = runner.invoke(assay_app, ["baseline", "get", "--json"])
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert "proof_pack_001" in data["pack_path"]
