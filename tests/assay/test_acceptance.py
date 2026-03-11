"""Tests for acceptance receipt generation and verification.

Covers:
  - Generate from passing pack (exit 0)
  - Generate from failing-claims pack (exit 1)
  - Generate from integrity-fail pack (exit 2)
  - Verify valid receipt
  - Reject tampered receipt
  - Reject receipt with wrong pack reference
  - D12 invariant check
  - Schema version check
  - Round-trip: generate -> write -> read -> verify
  - CI binding passthrough
  - CLI lock enforcement path
"""

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay import __version__ as assay_version
from assay.acceptance import (
    SCHEMA_VERSION,
    generate_acceptance_receipt,
    verify_acceptance_receipt,
)
from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack


runner = CliRunner()


FAKE_SHA = "c" * 40

CI_BINDING = {
    "provider": "github_actions",
    "commit_sha": FAKE_SHA,
    "repo": "Haserjian/assay",
    "run_id": "99999",
}


@pytest.fixture
def keystore(tmp_path):
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test")
    return ks


@pytest.fixture
def pack_manifest(keystore, tmp_path, monkeypatch):
    """Build a minimal pack and return its manifest dict + pack_dir."""
    for key in (
        "GITHUB_ACTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_ACTOR",
    ):
        monkeypatch.delenv(key, raising=False)
    pp = ProofPack(run_id="accept-test", entries=[], signer_id="test")
    pack_dir = pp.build(tmp_path / "pack", keystore=keystore)
    manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
    return manifest, pack_dir


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Isolate default keystore under a temp HOME for CLI tests."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def cli_pack(tmp_path, isolated_home):
    """Build a minimal pack signed by the default CLI signer."""
    signer_id = "assay-local"
    keys_dir = isolated_home / ".assay" / "keys"
    ks = AssayKeyStore(keys_dir=keys_dir)
    ks.generate_key(signer_id)

    pack_dir = tmp_path / "proof_pack_cli"
    pp = ProofPack(run_id="accept-cli-test", entries=[], signer_id=signer_id)
    built = pp.build(pack_dir, keystore=ks)
    manifest = json.loads((built / "pack_manifest.json").read_text())
    return built, manifest


def _write_minimal_lock_for_manifest(lock_path: Path, manifest: dict) -> None:
    """Write a structurally valid lockfile that should pass for this manifest."""
    lock = {
        "lock_version": "1.0",
        "assay_version_min": assay_version,
        "pack_format_version": manifest["attestation"]["pack_format_version"],
        "receipt_schema_version": manifest["attestation"].get("receipt_schema_version", "3.0"),
        "run_cards": [],
        "run_cards_composite_hash": "0" * 64,
        "claim_set_hash": manifest["claim_set_hash"],
        "exit_contract": {
            "0": "integrity_pass AND claims_pass",
            "1": "integrity_pass AND claims_fail",
            "2": "integrity_fail",
        },
        "signer_policy": {"mode": "any", "allowed_fingerprints": []},
        "locked_at": "2026-03-04T00:00:00+00:00",
        "locked_by_assay_version": assay_version,
    }
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")


class TestGenerateAcceptanceReceipt:
    def test_passing_pack(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            claims_verdict="PASS",
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        assert receipt["schema_version"] == SCHEMA_VERSION
        assert receipt["verification"]["integrity"] == "PASS"
        assert receipt["verification"]["claims"] == "PASS"
        assert receipt["verification"]["exit_code"] == 0
        assert receipt["signer"]["signer_id"] == "test"
        assert receipt["signer"]["signature"] != ""
        assert receipt["pack_root_sha256"] == receipt["attestation_sha256"]

    def test_claims_fail_pack(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            claims_verdict="FAIL",
            exit_code=1,
            keystore=keystore,
            signer_id="test",
        )
        assert receipt["verification"]["integrity"] == "PASS"
        assert receipt["verification"]["claims"] == "FAIL"
        assert receipt["verification"]["exit_code"] == 1

    def test_integrity_fail_pack(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=False,
            claims_verdict="N/A",
            exit_code=2,
            keystore=keystore,
            signer_id="test",
        )
        assert receipt["verification"]["integrity"] == "FAIL"
        assert receipt["verification"]["exit_code"] == 2

    def test_writes_file(self, keystore, pack_manifest, tmp_path):
        manifest, _ = pack_manifest
        out = tmp_path / "receipt" / "ACCEPTANCE_RECEIPT.json"
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
            output_path=out,
        )
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["pack_id"] == receipt["pack_id"]
        assert loaded["signer"]["signature"] == receipt["signer"]["signature"]

    def test_ci_binding_passthrough(self, keystore, tmp_path):
        """CI binding from the pack attestation is passed through to the receipt."""
        pp = ProofPack(
            run_id="ci-accept-test",
            entries=[],
            signer_id="test",
            ci_binding=CI_BINDING,
        )
        pack_dir = pp.build(tmp_path / "ci_pack", keystore=keystore)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        assert receipt["ci_binding"] is not None
        assert receipt["ci_binding"]["provider"] == "github_actions"
        assert receipt["ci_binding"]["commit_sha"] == FAKE_SHA

    def test_no_ci_binding_is_null(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        assert receipt["ci_binding"] is None


class TestVerifyAcceptanceReceipt:
    def test_valid_receipt(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        result = verify_acceptance_receipt(receipt, keystore=keystore)
        assert result.passed
        assert result.errors == []

    def test_valid_receipt_without_keystore(self, keystore, pack_manifest):
        """Receipt remains verifiable without local signer key via embedded pubkey."""
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        result = verify_acceptance_receipt(receipt, keystore=None)
        assert result.passed
        assert result.errors == []

    def test_tampered_receipt_fails(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        receipt["verification"]["exit_code"] = 2
        result = verify_acceptance_receipt(receipt, keystore=keystore)
        assert not result.passed
        assert any("invalid signature" in e.lower() or "signature" in e.lower() for e in result.errors)

    def test_wrong_pack_reference(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        result = verify_acceptance_receipt(
            receipt,
            keystore=keystore,
            expected_pack_root="f" * 64,
        )
        assert not result.passed
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_matching_pack_reference(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        result = verify_acceptance_receipt(
            receipt,
            keystore=keystore,
            expected_pack_root=receipt["pack_root_sha256"],
        )
        assert result.passed

    def test_d12_invariant_violation(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        receipt_copy = copy.deepcopy(receipt)
        receipt_copy["attestation_sha256"] = "0" * 64
        result = verify_acceptance_receipt(receipt_copy, keystore=keystore)
        assert not result.passed
        assert any("D12" in e for e in result.errors)

    def test_wrong_schema_version(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        receipt_copy = copy.deepcopy(receipt)
        receipt_copy["schema_version"] = "99.0.0"
        result = verify_acceptance_receipt(receipt_copy, keystore=keystore)
        assert not result.passed
        assert any("schema_version" in e.lower() for e in result.errors)

    def test_missing_signature(self, keystore, pack_manifest):
        manifest, _ = pack_manifest
        receipt = generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
        )
        receipt["signer"]["signature"] = ""
        result = verify_acceptance_receipt(receipt, keystore=keystore)
        assert not result.passed


class TestRoundTrip:
    def test_write_read_verify(self, keystore, pack_manifest, tmp_path):
        manifest, _ = pack_manifest
        out = tmp_path / "ACCEPTANCE_RECEIPT.json"
        generate_acceptance_receipt(
            manifest,
            integrity_passed=True,
            exit_code=0,
            keystore=keystore,
            signer_id="test",
            output_path=out,
        )
        loaded = json.loads(out.read_text())
        result = verify_acceptance_receipt(loaded, keystore=keystore)
        assert result.passed


class TestAcceptCli:
    def test_accept_with_passing_lock_succeeds(self, cli_pack, tmp_path):
        pack_dir, manifest = cli_pack
        lock_path = tmp_path / "assay.lock"
        out_path = tmp_path / "ACCEPTANCE_RECEIPT.json"
        _write_minimal_lock_for_manifest(lock_path, manifest)

        result = runner.invoke(
            assay_app,
            ["accept", str(pack_dir), "--lock", str(lock_path), "--output", str(out_path)],
        )

        assert result.exit_code == 0, result.stdout
        assert out_path.exists()
