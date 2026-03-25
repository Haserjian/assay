"""Tests for signed lifecycle receipts."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from assay.keystore import AssayKeyStore
from assay.lifecycle_receipt import (
    LifecycleReceiptError,
    check_issuer_authority,
    create_signed_challenge_receipt,
    create_signed_revocation_receipt,
    create_signed_supersession_receipt,
    load_lifecycle_receipts,
    verify_lifecycle_receipt,
    write_lifecycle_receipt,
)


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    import assay.store as store_mod

    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


@pytest.fixture
def keystore(assay_home_tmp: Path) -> AssayKeyStore:
    ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
    ks.generate_key("test-signer")
    return ks


@pytest.fixture
def other_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(keys_dir=tmp_path / "other_keys")
    ks.generate_key("other-signer")
    return ks


@pytest.fixture
def sample_passport(keystore: AssayKeyStore) -> dict:
    """A minimal passport dict with signature for authority checks."""
    vk = keystore.get_verify_key("test-signer")
    fp = hashlib.sha256(vk.encode()).hexdigest()
    return {
        "passport_id": "sha256:" + "a" * 64,
        "subject": {"system_id": "test.v1"},
        "signature": {
            "key_id": "test-signer",
            "key_fingerprint": fp,
        },
        "chain": {
            "issuer": "test-signer",
            "issuer_fingerprint": fp,
        },
    }


# ---------------------------------------------------------------------------
# Golden cases: creation
# ---------------------------------------------------------------------------

class TestCreateSignedReceipts:
    def test_create_challenge(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="coverage_gap",
            reason_summary="Missing admin override",
            keystore=keystore,
            signer_id="test-signer",
        )
        assert receipt["event_type"] == "challenge"
        assert receipt["event_id"].startswith("sha256:")
        assert receipt["issuer"]["role"] == "challenger"
        assert receipt["issuer"]["pubkey"]  # embedded
        assert receipt["signature"]["algorithm"] == "Ed25519"
        assert receipt["target"]["passport_id"] == "sha256:" + "a" * 64

    def test_create_supersession(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_supersession_receipt(
            target_passport_id="sha256:" + "a" * 64,
            new_passport_id="sha256:" + "b" * 64,
            reason_code="remediation",
            reason_summary="Addressed coverage gap",
            keystore=keystore,
            signer_id="test-signer",
        )
        assert receipt["event_type"] == "supersession"
        assert receipt["issuer"]["role"] == "issuer"
        assert receipt["supersession"]["new_passport_id"] == "sha256:" + "b" * 64

    def test_create_revocation(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_revocation_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="key_compromise",
            reason_summary="Signing key exposed",
            keystore=keystore,
            signer_id="test-signer",
        )
        assert receipt["event_type"] == "revocation"
        assert receipt["issuer"]["role"] == "issuer"

    def test_self_supersession_rejected(self, keystore: AssayKeyStore) -> None:
        with pytest.raises(LifecycleReceiptError, match="cannot supersede itself"):
            create_signed_supersession_receipt(
                target_passport_id="sha256:" + "a" * 64,
                new_passport_id="sha256:" + "a" * 64,
                reason_code="remediation",
                reason_summary="test",
                keystore=keystore,
                signer_id="test-signer",
            )


# ---------------------------------------------------------------------------
# Golden cases: verification
# ---------------------------------------------------------------------------

class TestVerifyReceipts:
    def test_valid_challenge_verifies(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="coverage_gap",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is True
        assert vr["signature_valid"] is True
        assert vr["id_valid"] is True
        assert vr["error"] is None

    def test_valid_supersession_verifies(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_supersession_receipt(
            target_passport_id="sha256:" + "a" * 64,
            new_passport_id="sha256:" + "b" * 64,
            reason_code="remediation",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is True

    def test_valid_revocation_verifies(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_revocation_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="key_compromise",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is True

    def test_content_addressed_id(self, keystore: AssayKeyStore) -> None:
        """event_id is deterministic SHA-256 of JCS(body without id/sig)."""
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        from assay._receipts.jcs import canonicalize as jcs_canonicalize

        body = {k: v for k, v in receipt.items()
                if k not in ("event_id", "signature")}
        expected = "sha256:" + hashlib.sha256(jcs_canonicalize(body)).hexdigest()
        assert receipt["event_id"] == expected


# ---------------------------------------------------------------------------
# Adversarial / tampering cases
# ---------------------------------------------------------------------------

class TestTampering:
    def test_tampered_reason_fails(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="coverage_gap",
            reason_summary="original",
            keystore=keystore,
            signer_id="test-signer",
        )
        receipt["reason"]["summary"] = "tampered"
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is False
        assert vr["id_valid"] is False

    def test_forged_event_id_fails(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        receipt["event_id"] = "sha256:" + "f" * 64
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is False
        assert vr["id_valid"] is False

    def test_stripped_signature_fails(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        del receipt["signature"]
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is False

    def test_wrong_key_signature_fails(
        self, keystore: AssayKeyStore, other_keystore: AssayKeyStore
    ) -> None:
        """Sign with one key, re-sign event_id body with different key."""
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        # Replace signature with one from different key
        from assay._receipts.jcs import canonicalize as jcs_canonicalize

        sign_body = {k: v for k, v in receipt.items() if k != "signature"}
        fake_sig = other_keystore.sign_b64(jcs_canonicalize(sign_body), "other-signer")
        receipt["signature"]["signature"] = fake_sig
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is False

    def test_unknown_event_type(self, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        receipt["event_type"] = "freeze"
        vr = verify_lifecycle_receipt(receipt)
        assert vr["valid"] is False


# ---------------------------------------------------------------------------
# Authority checks
# ---------------------------------------------------------------------------

class TestAuthorityChecks:
    def test_challenger_always_authorized(
        self, keystore: AssayKeyStore, sample_passport: dict
    ) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id=sample_passport["passport_id"],
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        auth = check_issuer_authority(receipt, sample_passport)
        assert auth["authorized"] is True

    def test_supersession_by_issuer_authorized(
        self, keystore: AssayKeyStore, sample_passport: dict
    ) -> None:
        receipt = create_signed_supersession_receipt(
            target_passport_id=sample_passport["passport_id"],
            new_passport_id="sha256:" + "b" * 64,
            reason_code="remediation",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        auth = check_issuer_authority(receipt, sample_passport)
        assert auth["authorized"] is True

    def test_supersession_by_non_issuer_unauthorized(
        self, other_keystore: AssayKeyStore, sample_passport: dict
    ) -> None:
        receipt = create_signed_supersession_receipt(
            target_passport_id=sample_passport["passport_id"],
            new_passport_id="sha256:" + "b" * 64,
            reason_code="remediation",
            reason_summary="test",
            keystore=other_keystore,
            signer_id="other-signer",
        )
        auth = check_issuer_authority(receipt, sample_passport)
        assert auth["authorized"] is False

    def test_revocation_by_issuer_authorized(
        self, keystore: AssayKeyStore, sample_passport: dict
    ) -> None:
        receipt = create_signed_revocation_receipt(
            target_passport_id=sample_passport["passport_id"],
            reason_code="key_compromise",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        auth = check_issuer_authority(receipt, sample_passport)
        assert auth["authorized"] is True

    def test_revocation_by_non_issuer_unauthorized(
        self, other_keystore: AssayKeyStore, sample_passport: dict
    ) -> None:
        receipt = create_signed_revocation_receipt(
            target_passport_id=sample_passport["passport_id"],
            reason_code="key_compromise",
            reason_summary="test",
            keystore=other_keystore,
            signer_id="other-signer",
        )
        auth = check_issuer_authority(receipt, sample_passport)
        assert auth["authorized"] is False


# ---------------------------------------------------------------------------
# I/O and loading
# ---------------------------------------------------------------------------

class TestReceiptIO:
    def test_write_and_load(self, tmp_path: Path, keystore: AssayKeyStore) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="coverage_gap",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        path = write_lifecycle_receipt(receipt, tmp_path)
        assert path.exists()
        assert path.name.startswith("challenge_")

        loaded = load_lifecycle_receipts(tmp_path, verify=False)
        assert len(loaded) == 1
        assert loaded[0]["event_type"] == "challenge"

    def test_load_filters_by_passport_id(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        r1 = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="for A",
            keystore=keystore,
            signer_id="test-signer",
        )
        r2 = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "b" * 64,
            reason_code="other",
            reason_summary="for B",
            keystore=keystore,
            signer_id="test-signer",
        )
        write_lifecycle_receipt(r1, tmp_path)
        write_lifecycle_receipt(r2, tmp_path)

        loaded = load_lifecycle_receipts(
            tmp_path,
            target_passport_id="sha256:" + "a" * 64,
            verify=False,
        )
        assert len(loaded) == 1
        assert loaded[0]["target"]["passport_id"] == "sha256:" + "a" * 64

    def test_load_verifies_in_receipt_mode(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        write_lifecycle_receipt(receipt, tmp_path)

        loaded = load_lifecycle_receipts(tmp_path, verify=True)
        assert len(loaded) == 1
        assert loaded[0]["_verified"] is True

    def test_load_discards_tampered_in_receipt_mode(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        receipt["reason"]["summary"] = "tampered"
        write_lifecycle_receipt(receipt, tmp_path)

        loaded = load_lifecycle_receipts(tmp_path, verify=True)
        assert len(loaded) == 0  # tampered receipt discarded

    def test_load_accepts_unsigned_in_demo_mode(self, tmp_path: Path) -> None:
        """Old-format unsigned receipts work in demo mode."""
        old_receipt = {
            "type": "challenge",
            "passport_id": "sha256:" + "a" * 64,
            "reason": "test",
            "timestamp": "2026-03-14T00:00:00+00:00",
        }
        (tmp_path / "challenge_20260314T000000_abcd1234.json").write_text(
            json.dumps(old_receipt), encoding="utf-8"
        )
        loaded = load_lifecycle_receipts(tmp_path, verify=False)
        assert len(loaded) == 1

    def test_dedup_by_event_id(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        receipt = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other",
            reason_summary="test",
            keystore=keystore,
            signer_id="test-signer",
        )
        # Write same receipt twice with different filenames
        write_lifecycle_receipt(receipt, tmp_path)
        path2 = tmp_path / "challenge_duplicate.json"
        path2.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

        loaded = load_lifecycle_receipts(tmp_path, verify=False)
        assert len(loaded) == 1
