"""Tests for passport minting from proof packs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.passport_mint import PassportMintError, mint_passport_draft


def _make_verify_report(**overrides) -> dict:
    base = {
        "attestation": {
            "pack_id": "pack_test_001",
            "receipt_integrity": "PASS",
            "claim_check": "PASS",
            "pack_root_sha256": "a" * 64,
            "timestamp_start": "2026-03-14T00:00:00+00:00",
            "timestamp_end": "2026-03-14T00:05:00+00:00",
        },
        "verified_at": "2026-03-14T00:05:00+00:00",
    }
    base.update(overrides)
    return base


def _make_manifest(**overrides) -> dict:
    base = {
        "attestation": {
            "pack_id": "pack_test_001",
            "pack_root_sha256": "a" * 64,
            "timestamp_start": "2026-03-14T00:00:00+00:00",
            "timestamp_end": "2026-03-14T00:05:00+00:00",
        },
    }
    base.update(overrides)
    return base


class TestMintDraft:
    def test_mint_minimal_without_pack(self) -> None:
        passport = mint_passport_draft(
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        assert passport["passport_version"] == "0.1"
        assert passport["subject"]["name"] == "TestApp"
        assert passport["subject"]["system_id"] == "test.v1"
        assert passport["subject"]["owner"] == "Test Inc."
        assert passport["claims"] == []
        assert "signature" not in passport
        assert "passport_id" not in passport

    def test_mint_with_valid_days(self) -> None:
        passport = mint_passport_draft(
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
            valid_days=60,
        )
        # valid_until should be 60 days from issued_at
        assert passport["valid_until"] is not None

    def test_mint_from_proof_pack(self, tmp_path: Path) -> None:
        # Set up proof pack directory
        report = _make_verify_report()
        manifest = _make_manifest()
        (tmp_path / "verify_report.json").write_text(json.dumps(report), encoding="utf-8")
        (tmp_path / "pack_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        passport = mint_passport_draft(
            proof_pack_dir=tmp_path,
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        assert len(passport["claims"]) >= 2  # At least integrity claims
        assert passport["relationships"]["proof_pack_ref"] == "sha256:" + "a" * 64

    def test_mint_extracts_integrity_claim(self, tmp_path: Path) -> None:
        report = _make_verify_report()
        (tmp_path / "verify_report.json").write_text(json.dumps(report), encoding="utf-8")

        passport = mint_passport_draft(
            proof_pack_dir=tmp_path,
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        integrity_claims = [c for c in passport["claims"] if c["claim_type"] == "integrity"]
        assert len(integrity_claims) >= 1
        assert all(c["result"] == "pass" for c in integrity_claims)

    def test_mint_failed_integrity(self, tmp_path: Path) -> None:
        report = _make_verify_report()
        report["attestation"]["receipt_integrity"] = "FAIL"
        (tmp_path / "verify_report.json").write_text(json.dumps(report), encoding="utf-8")

        passport = mint_passport_draft(
            proof_pack_dir=tmp_path,
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        integrity_claims = [c for c in passport["claims"] if c["claim_type"] == "integrity"]
        assert any(c["result"] == "fail" for c in integrity_claims)

    def test_mint_no_verify_report(self, tmp_path: Path) -> None:
        with pytest.raises(PassportMintError, match="verify_report.json not found"):
            mint_passport_draft(
                proof_pack_dir=tmp_path,
                subject_name="TestApp",
                subject_system_id="test.v1",
                subject_owner="Test Inc.",
            )

    def test_mint_includes_evidence_summary(self, tmp_path: Path) -> None:
        report = _make_verify_report()
        (tmp_path / "verify_report.json").write_text(json.dumps(report), encoding="utf-8")

        passport = mint_passport_draft(
            proof_pack_dir=tmp_path,
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        summary = passport["evidence_summary"]
        assert summary["total_claims"] > 0
        assert summary["machine_verified"] > 0

    def test_mint_reliance_class_without_signature(self, tmp_path: Path) -> None:
        report = _make_verify_report()
        (tmp_path / "verify_report.json").write_text(json.dumps(report), encoding="utf-8")

        passport = mint_passport_draft(
            proof_pack_dir=tmp_path,
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        # Unsigned draft → R0
        assert passport["reliance"]["class"] == "R0"

    def test_mint_includes_verification_instructions(self) -> None:
        passport = mint_passport_draft(
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        assert "assay passport verify" in passport["verification"]["how_to_verify"]
        assert "assay passport challenge" in passport["challenge"]["how_to_challenge"]

    def test_mint_claim_check_na(self, tmp_path: Path) -> None:
        report = _make_verify_report()
        report["attestation"]["claim_check"] = "N/A"
        (tmp_path / "verify_report.json").write_text(json.dumps(report), encoding="utf-8")

        passport = mint_passport_draft(
            proof_pack_dir=tmp_path,
            subject_name="TestApp",
            subject_system_id="test.v1",
            subject_owner="Test Inc.",
        )
        # Should have 2 claims (integrity only, no claim verification claim)
        assert len(passport["claims"]) == 2
