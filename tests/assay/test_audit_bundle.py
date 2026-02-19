"""Tests for assay audit bundle and assay verify-signer commands."""
from __future__ import annotations

import json
import tarfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


def _build_pack(tmp_path: Path, signer_id: str = "audit-test-signer"):
    """Build a valid signed proof pack for testing."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key(signer_id)
    receipts = [_make_receipt(seq=i) for i in range(3)]
    pack = ProofPack(
        run_id="audit-test-run",
        entries=receipts,
        signer_id=signer_id,
        mode="shadow",
    )
    out = pack.build(tmp_path / "pack", keystore=ks)
    return out, ks


# ---------------------------------------------------------------------------
# audit bundle tests
# ---------------------------------------------------------------------------

class TestAuditBundle:
    def test_creates_tarball(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "audit", "bundle", str(pack_dir),
            "-o", str(tmp_path / "bundle.tar.gz"),
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert (tmp_path / "bundle.tar.gz").exists()

    def test_tarball_contains_expected_files(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        out = tmp_path / "bundle.tar.gz"
        runner.invoke(assay_app, ["audit", "bundle", str(pack_dir), "-o", str(out)])
        with tarfile.open(str(out), "r:gz") as tar:
            names = tar.getnames()
            assert "pack_manifest.json" in names
            assert "receipt_pack.jsonl" in names
            assert "pack_signature.sig" in names
            assert "SIGNER_INFO.json" in names
            assert "VERIFY_INSTRUCTIONS.md" in names
            assert "VERIFY_RESULT.json" in names
            assert "PACK_SUMMARY.md" in names

    def test_signer_info_content(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        out = tmp_path / "bundle.tar.gz"
        runner.invoke(assay_app, ["audit", "bundle", str(pack_dir), "-o", str(out)])
        with tarfile.open(str(out), "r:gz") as tar:
            signer_info = json.loads(tar.extractfile("SIGNER_INFO.json").read())
            assert signer_info["signer_id"] == "audit-test-signer"
            assert signer_info["signer_pubkey"] is not None
            assert signer_info["signature_alg"] == "ed25519"

    def test_json_output(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "audit", "bundle", str(pack_dir),
            "-o", str(tmp_path / "bundle.tar.gz"),
            "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["verification_passed"] is True
        assert "bundle_path" in data

    def test_default_output_name(self, tmp_path, monkeypatch):
        pack_dir, _ks = _build_pack(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["audit", "bundle", str(pack_dir)])
        assert result.exit_code == 0
        bundles = list(tmp_path.glob("audit_bundle_*.tar.gz"))
        assert len(bundles) == 1

    def test_bad_input_not_a_directory(self, tmp_path):
        result = runner.invoke(assay_app, ["audit", "bundle", str(tmp_path / "nonexistent")])
        assert result.exit_code == 3

    def test_bad_input_no_manifest(self, tmp_path):
        (tmp_path / "empty_pack").mkdir()
        result = runner.invoke(assay_app, ["audit", "bundle", str(tmp_path / "empty_pack")])
        assert result.exit_code == 3

    def test_refuses_tampered_pack(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        receipt_file = pack_dir / "receipt_pack.jsonl"
        lines = receipt_file.read_text().strip().split("\n")
        if lines:
            obj = json.loads(lines[0])
            obj["receipt_id"] = "r_tampered_999"
            lines[0] = json.dumps(obj)
        receipt_file.write_text("\n".join(lines) + "\n")
        result = runner.invoke(assay_app, ["audit", "bundle", str(pack_dir)])
        assert result.exit_code == 3

    def test_refuses_tampered_pack_json(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        receipt_file = pack_dir / "receipt_pack.jsonl"
        lines = receipt_file.read_text().strip().split("\n")
        if lines:
            obj = json.loads(lines[0])
            obj["receipt_id"] = "r_tampered_999"
            lines[0] = json.dumps(obj)
        receipt_file.write_text("\n".join(lines) + "\n")
        result = runner.invoke(assay_app, ["audit", "bundle", str(pack_dir), "--json"])
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["error"] == "verification_failed"

    def test_verify_result_in_bundle(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        out = tmp_path / "bundle.tar.gz"
        runner.invoke(assay_app, ["audit", "bundle", str(pack_dir), "-o", str(out)])
        with tarfile.open(str(out), "r:gz") as tar:
            vr = json.loads(tar.extractfile("VERIFY_RESULT.json").read())
            assert vr["passed"] is True
            assert vr["verified_at_bundle_time"] is True


# ---------------------------------------------------------------------------
# verify-signer tests
# ---------------------------------------------------------------------------

class TestVerifySigner:
    def test_shows_signer_info(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["verify-signer", str(pack_dir)])
        assert result.exit_code == 0
        assert "audit-test-signer" in result.output

    def test_json_output(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["verify-signer", str(pack_dir), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["signer_id"] == "audit-test-signer"
        assert data["signer_pubkey_sha256"] is not None

    def test_expected_match(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "verify-signer", str(pack_dir), "--expected", "audit-test-signer",
        ])
        assert result.exit_code == 0

    def test_expected_mismatch(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "verify-signer", str(pack_dir), "--expected", "someone-else",
        ])
        assert result.exit_code == 1

    def test_expected_mismatch_json(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "verify-signer", str(pack_dir), "--expected", "someone-else", "--json",
        ])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "mismatch"
        assert "mismatch_reason" in data

    def test_fingerprint_match(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        fp = manifest["signer_pubkey_sha256"]
        result = runner.invoke(assay_app, [
            "verify-signer", str(pack_dir), "--fingerprint", fp[:16],
        ])
        assert result.exit_code == 0

    def test_fingerprint_mismatch(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "verify-signer", str(pack_dir), "--fingerprint", "deadbeef00000000",
        ])
        assert result.exit_code == 1

    def test_bad_input_not_a_directory(self, tmp_path):
        result = runner.invoke(assay_app, ["verify-signer", str(tmp_path / "nonexistent")])
        assert result.exit_code == 3

    def test_bad_input_no_manifest(self, tmp_path):
        (tmp_path / "empty_pack").mkdir()
        result = runner.invoke(assay_app, ["verify-signer", str(tmp_path / "empty_pack")])
        assert result.exit_code == 3

    def test_key_in_local_keystore_field(self, tmp_path):
        pack_dir, _ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["verify-signer", str(pack_dir), "--json"])
        data = json.loads(result.output)
        assert "key_in_local_keystore" in data
        assert isinstance(data["key_in_local_keystore"], bool)


# ---------------------------------------------------------------------------
# flow audit integration tests
# ---------------------------------------------------------------------------

class TestFlowAuditUpdated:
    def test_step_3_is_executable(self):
        from assay.flow import build_flow_audit
        flow = build_flow_audit()
        step3 = flow.steps[2]
        assert step3.print_only is False
        assert "assay audit bundle" in step3.command

    def test_step_4_is_signer_info(self):
        from assay.flow import build_flow_audit
        flow = build_flow_audit()
        assert len(flow.steps) == 4
        step4 = flow.steps[3]
        assert "verify-signer" in step4.command
        assert step4.print_only is True

    def test_dry_run_json_has_4_steps(self):
        result = runner.invoke(assay_app, ["flow", "audit", "--json"])
        data = json.loads(result.output)
        assert len(data["steps"]) == 4
