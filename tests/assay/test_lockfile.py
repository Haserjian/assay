"""Tests for the Assay verifier lockfile contract."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay.keystore import AssayKeyStore
from assay.lockfile import (
    LOCK_VERSION,
    check_lockfile,
    load_lockfile,
    validate_against_lock,
    write_lockfile,
)
from assay.proof_pack import ProofPack
from assay.run_cards import collect_claims_from_cards, get_builtin_card


def _make_receipt(seq: int = 0, **overrides) -> dict:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime(2026, 1, 15, 12, 0, seq, tzinfo=timezone.utc).isoformat(),
        "schema_version": "3.0",
        "seq": seq,
    }
    base.update(overrides)
    return base


@pytest.fixture
def tmp_keys(tmp_path):
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test-signer")
    return ks


def _build_pack(tmp_path, entries, claims, ks, name="test_pack"):
    pack = ProofPack(
        run_id=f"lock_test_{name}",
        entries=entries,
        signer_id="test-signer",
        claims=claims,
        mode="shadow",
    )
    return pack.build(tmp_path / name, keystore=ks)


class TestWriteLockfile:
    """Test lockfile generation."""

    def test_write_creates_file(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(
            ["receipt_completeness", "guardian_enforcement"],
            output_path=out,
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["lock_version"] == LOCK_VERSION
        assert len(data["run_cards"]) == 2
        assert data["exit_contract"]["0"] == "integrity_pass AND claims_pass"
        assert data["signer_policy"]["mode"] == "any"

    def test_write_with_signer_allowlist(self, tmp_path):
        out = tmp_path / "assay.lock"
        fp = "abc123" * 10 + "abcd"
        write_lockfile(
            ["receipt_completeness"],
            signer_fingerprints=[fp],
            output_path=out,
        )
        data = json.loads(out.read_text())
        assert data["signer_policy"]["mode"] == "allowlist"
        assert fp in data["signer_policy"]["allowed_fingerprints"]

    def test_write_unknown_card_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown RunCard"):
            write_lockfile(["nonexistent_card"], output_path=tmp_path / "x.lock")

    def test_card_hashes_are_deterministic(self, tmp_path):
        out1 = tmp_path / "lock1.json"
        out2 = tmp_path / "lock2.json"
        write_lockfile(["receipt_completeness"], output_path=out1)
        write_lockfile(["receipt_completeness"], output_path=out2)
        d1 = json.loads(out1.read_text())
        d2 = json.loads(out2.read_text())
        assert d1["run_cards"][0]["claim_set_hash"] == d2["run_cards"][0]["claim_set_hash"]
        assert d1["run_cards_composite_hash"] == d2["run_cards_composite_hash"]


class TestValidateAgainstLock:
    """Test pack-vs-lockfile validation."""

    def test_matching_pack_passes(self, tmp_path, tmp_keys):
        cards = [get_builtin_card("receipt_completeness"), get_builtin_card("guardian_enforcement")]
        claims = collect_claims_from_cards(cards)

        entries = [
            _make_receipt(0),
            {"receipt_id": f"g_{uuid.uuid4().hex[:8]}", "type": "guardian_verdict",
             "timestamp": datetime(2026, 1, 15, 12, 0, 1, tzinfo=timezone.utc).isoformat(),
             "schema_version": "3.0", "seq": 1, "verdict": "allow", "action": "test"},
        ]
        pack_dir = _build_pack(tmp_path, entries, claims, tmp_keys)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        lock_path = tmp_path / "assay.lock"
        write_lockfile(
            ["receipt_completeness", "guardian_enforcement"],
            output_path=lock_path,
        )
        lockfile = load_lockfile(lock_path)

        result = validate_against_lock(manifest, lockfile)
        assert result.passed
        assert len(result.errors) == 0

    def test_wrong_signer_fails(self, tmp_path, tmp_keys):
        cards = [get_builtin_card("receipt_completeness")]
        claims = collect_claims_from_cards(cards)
        entries = [_make_receipt(0)]
        pack_dir = _build_pack(tmp_path, entries, claims, tmp_keys)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        lock_path = tmp_path / "assay.lock"
        write_lockfile(
            ["receipt_completeness"],
            signer_fingerprints=["wrong_fingerprint_" + "0" * 48],
            output_path=lock_path,
        )
        lockfile = load_lockfile(lock_path)

        result = validate_against_lock(manifest, lockfile)
        assert not result.passed
        signer_errors = [e for e in result.errors if e.field == "signer_pubkey_sha256"]
        assert len(signer_errors) == 1


class TestCheckLockfile:
    """Test lockfile self-validation."""

    def test_valid_lockfile(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        issues = check_lockfile(out)
        assert issues == []

    def test_bad_version(self, tmp_path):
        out = tmp_path / "assay.lock"
        out.write_text(json.dumps({"lock_version": "99.0"}) + "\n")
        issues = check_lockfile(out)
        assert any("lock_version" in i for i in issues)

    def test_unknown_card(self, tmp_path):
        out = tmp_path / "assay.lock"
        data = {
            "lock_version": LOCK_VERSION,
            "run_cards": [{"id": "nonexistent", "claim_set_hash": "abc"}],
            "exit_contract": {"0": "ok", "1": "fail", "2": "fail"},
        }
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("nonexistent" in i for i in issues)

    def test_hash_drift_detected(self, tmp_path):
        out = tmp_path / "assay.lock"
        data = {
            "lock_version": LOCK_VERSION,
            "run_cards": [{"id": "receipt_completeness", "claim_set_hash": "wrong_hash"}],
            "exit_contract": {"0": "ok", "1": "fail", "2": "fail"},
        }
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("drift" in i for i in issues)

    def test_missing_exit_contract(self, tmp_path):
        out = tmp_path / "assay.lock"
        data = {
            "lock_version": LOCK_VERSION,
            "run_cards": [],
            "exit_contract": {"0": "ok"},
        }
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("exit_contract" in i for i in issues)


class TestLoadLockfileFailClosed:
    """Test that load_lockfile rejects structurally invalid lockfiles."""

    def test_missing_required_fields_raises(self, tmp_path):
        out = tmp_path / "assay.lock"
        data = {"lock_version": LOCK_VERSION}
        out.write_text(json.dumps(data) + "\n")
        with pytest.raises(ValueError, match="missing required fields"):
            load_lockfile(out)

    def test_bad_signer_mode_raises(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["signer_policy"]["mode"] = "yolo"
        out.write_text(json.dumps(data) + "\n")
        with pytest.raises(ValueError, match="Invalid signer_policy.mode"):
            load_lockfile(out)

    def test_allowlist_without_fingerprints_raises(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["signer_policy"] = {"mode": "allowlist", "allowed_fingerprints": "not-a-list"}
        out.write_text(json.dumps(data) + "\n")
        with pytest.raises(ValueError, match="allowed_fingerprints is not a list"):
            load_lockfile(out)

    def test_invalid_version_min_raises(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["assay_version_min"] = "not.a.version!!!"
        out.write_text(json.dumps(data) + "\n")
        with pytest.raises(ValueError, match="Invalid assay_version_min"):
            load_lockfile(out)


class TestValidateFailClosed:
    """Test that validate_against_lock treats missing fields as mismatches."""

    def test_missing_claim_set_hash_in_lockfile_fails(self):
        manifest = {"attestation": {"pack_format_version": "0.1.0"}, "claim_set_hash": "abc"}
        lockfile = {
            "pack_format_version": "0.1.0",
            "claim_set_hash": "",
            "signer_policy": {"mode": "any"},
            "assay_version_min": "",
        }
        result = validate_against_lock(manifest, lockfile)
        assert not result.passed
        assert any(e.field == "claim_set_hash" for e in result.errors)

    def test_missing_pack_format_in_lockfile_fails(self):
        manifest = {"attestation": {"pack_format_version": "0.1.0"}, "claim_set_hash": "abc"}
        lockfile = {
            "pack_format_version": "",
            "claim_set_hash": "abc",
            "signer_policy": {"mode": "any"},
            "assay_version_min": "",
        }
        result = validate_against_lock(manifest, lockfile)
        assert not result.passed
        assert any(e.field == "pack_format_version" for e in result.errors)

    def test_version_below_minimum_fails(self):
        manifest = {"attestation": {"pack_format_version": "0.1.0"}, "claim_set_hash": "abc"}
        lockfile = {
            "pack_format_version": "0.1.0",
            "claim_set_hash": "abc",
            "signer_policy": {"mode": "any"},
            "assay_version_min": "999.0.0",
        }
        result = validate_against_lock(manifest, lockfile)
        assert not result.passed
        assert any(e.field == "assay_version_min" for e in result.errors)

    def test_empty_allowlist_fails(self):
        manifest = {
            "attestation": {"pack_format_version": "0.1.0"},
            "claim_set_hash": "abc",
            "signer_pubkey_sha256": "somefp",
        }
        lockfile = {
            "pack_format_version": "0.1.0",
            "claim_set_hash": "abc",
            "signer_policy": {"mode": "allowlist", "allowed_fingerprints": []},
            "assay_version_min": "",
        }
        result = validate_against_lock(manifest, lockfile)
        assert not result.passed
        assert any(e.field == "signer_policy" for e in result.errors)


class TestCheckLockfileSemantic:
    """Test full semantic validation in check_lockfile."""

    def test_composite_hash_drift(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["run_cards_composite_hash"] = "tampered_hash"
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("run_cards_composite_hash" in i and "drift" in i for i in issues)

    def test_claim_set_hash_drift(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["claim_set_hash"] = "tampered_flat_hash"
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("claim_set_hash" in i and "drift" in i for i in issues)

    def test_version_below_min_detected(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["assay_version_min"] = "999.0.0"
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("below" in i for i in issues)

    def test_invalid_signer_mode_detected(self, tmp_path):
        out = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=out)
        data = json.loads(out.read_text())
        data["signer_policy"]["mode"] = "broken"
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("signer_policy.mode" in i for i in issues)

    def test_missing_required_fields_detected(self, tmp_path):
        out = tmp_path / "assay.lock"
        data = {
            "lock_version": LOCK_VERSION,
            "run_cards": [],
            "exit_contract": {"0": "ok", "1": "fail", "2": "fail"},
        }
        out.write_text(json.dumps(data) + "\n")
        issues = check_lockfile(out)
        assert any("Missing required fields" in i for i in issues)


class TestConformanceCorpus:
    """Test that the conformance corpus produces expected results."""

    def test_corpus_outcomes(self):
        """Run the corpus verifier as a test."""
        corpus_dir = Path(__file__).parent.parent.parent / "conformance" / "corpus_v1"
        outcomes_path = corpus_dir / "expected_outcomes.json"
        if not outcomes_path.exists():
            pytest.skip("Conformance corpus not generated")

        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent.parent.parent / "conformance" / "run_corpus.py")],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"Corpus verification failed:\n{result.stdout}\n{result.stderr}"
