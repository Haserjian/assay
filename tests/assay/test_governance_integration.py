"""Integration tests: signed lifecycle receipts flow through CLI + verdict engine."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.lifecycle_receipt import (
    create_signed_challenge_receipt,
    create_signed_revocation_receipt,
    create_signed_supersession_receipt,
    derive_governance_dimensions,
    verify_lifecycle_receipt,
    write_lifecycle_receipt,
)

runner = CliRunner()


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
def signed_passport(tmp_path: Path, keystore: AssayKeyStore) -> Path:
    """A signed passport ready for lifecycle operations."""
    passport = {
        "passport_version": "0.1",
        "issued_at": "2026-03-14T00:00:00+00:00",
        "valid_until": "2027-03-14T00:00:00+00:00",
        "subject": {"name": "TestApp", "system_id": "test.v1", "owner": "Test Inc."},
        "claims": [{"claim_id": "C-001", "topic": "Integrity", "result": "pass"}],
        "status": {"state": "FRESH"},
        "reliance": {"class": "R1", "label": "Signed"},
        "relationships": {},
        "verification": {"how_to_verify": "assay passport verify"},
        "challenge": {"how_to_challenge": "assay passport challenge"},
    }
    path = tmp_path / "passport.json"
    path.write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")

    from assay.passport_sign import sign_passport
    sign_passport(path, keystore=keystore, signer_id="test-signer")
    return path


# ---------------------------------------------------------------------------
# derive_governance_dimensions
# ---------------------------------------------------------------------------

class TestDeriveGovernanceDimensions:
    def test_empty_dir(self, tmp_path: Path) -> None:
        gov = derive_governance_dimensions(tmp_path)
        assert gov["governance_status"] == "none"
        assert gov["event_integrity"] == "no_events"
        assert gov["receipts"] == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        gov = derive_governance_dimensions(tmp_path / "nope")
        assert gov["governance_status"] == "none"
        assert gov["event_integrity"] == "no_events"

    def test_signed_challenge_detected(
        self, tmp_path: Path, keystore: AssayKeyStore, signed_passport: Path
    ) -> None:
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        receipt = create_signed_challenge_receipt(
            target_passport_id=data["passport_id"],
            reason_code="coverage_gap",
            reason_summary="Missing coverage",
            keystore=keystore,
            signer_id="test-signer",
        )
        write_lifecycle_receipt(receipt, tmp_path)

        gov = derive_governance_dimensions(
            tmp_path, passport=data,
            target_passport_id=data["passport_id"],
        )
        assert gov["governance_status"] == "challenged"
        assert gov["event_integrity"] == "all_valid"
        assert gov["signed_total"] == 1
        assert gov["signed_valid"] == 1
        assert len(gov["receipts"]) == 1

    def test_signed_revocation_overrides_challenge(
        self, tmp_path: Path, keystore: AssayKeyStore, signed_passport: Path
    ) -> None:
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        pid = data["passport_id"]

        # Challenge + Revocation
        c = create_signed_challenge_receipt(
            target_passport_id=pid, reason_code="other",
            reason_summary="test", keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(c, tmp_path)

        r = create_signed_revocation_receipt(
            target_passport_id=pid, reason_code="key_compromise",
            reason_summary="test", keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(r, tmp_path)

        gov = derive_governance_dimensions(
            tmp_path, passport=data, target_passport_id=pid,
        )
        assert gov["governance_status"] == "revoked"
        assert gov["event_integrity"] == "all_valid"
        assert gov["signed_valid"] == 2

    def test_tampered_receipt_degrades_integrity(
        self, tmp_path: Path, keystore: AssayKeyStore, signed_passport: Path
    ) -> None:
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        pid = data["passport_id"]

        # Valid challenge
        c = create_signed_challenge_receipt(
            target_passport_id=pid, reason_code="other",
            reason_summary="valid", keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(c, tmp_path)

        # Tampered challenge
        c2 = create_signed_challenge_receipt(
            target_passport_id=pid, reason_code="other",
            reason_summary="will tamper", keystore=keystore, signer_id="test-signer",
        )
        c2["reason"]["summary"] = "tampered"
        write_lifecycle_receipt(c2, tmp_path)

        gov = derive_governance_dimensions(
            tmp_path, passport=data, target_passport_id=pid,
        )
        assert gov["event_integrity"] == "some_invalid"
        assert gov["signed_total"] == 2
        assert gov["signed_valid"] == 1

    def test_unsigned_demo_receipt_accepted(self, tmp_path: Path) -> None:
        """Old-format unsigned receipts are accepted, don't affect event_integrity."""
        receipt = {
            "type": "challenge",
            "passport_id": "sha256:" + "a" * 64,
            "reason": "demo",
            "timestamp": "2026-03-14T00:00:00+00:00",
        }
        (tmp_path / "challenge_20260314_demo.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )

        gov = derive_governance_dimensions(
            tmp_path, target_passport_id="sha256:" + "a" * 64,
        )
        assert gov["governance_status"] == "challenged"
        assert gov["event_integrity"] == "no_events"  # no signed receipts
        assert len(gov["receipts"]) == 1

    def test_supersession_priority(
        self, tmp_path: Path, keystore: AssayKeyStore, signed_passport: Path
    ) -> None:
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        pid = data["passport_id"]

        # Challenge + Supersession
        c = create_signed_challenge_receipt(
            target_passport_id=pid, reason_code="other",
            reason_summary="test", keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(c, tmp_path)

        s = create_signed_supersession_receipt(
            target_passport_id=pid,
            new_passport_id="sha256:" + "b" * 64,
            reason_code="remediation",
            reason_summary="test", keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(s, tmp_path)

        gov = derive_governance_dimensions(
            tmp_path, passport=data, target_passport_id=pid,
        )
        assert gov["governance_status"] == "superseded"

    def test_filter_by_target(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """Only receipts targeting the given passport_id are counted."""
        c1 = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "a" * 64,
            reason_code="other", reason_summary="for A",
            keystore=keystore, signer_id="test-signer",
        )
        c2 = create_signed_challenge_receipt(
            target_passport_id="sha256:" + "b" * 64,
            reason_code="other", reason_summary="for B",
            keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(c1, tmp_path)
        write_lifecycle_receipt(c2, tmp_path)

        gov = derive_governance_dimensions(
            tmp_path, target_passport_id="sha256:" + "a" * 64,
        )
        assert len(gov["receipts"]) == 1
        assert gov["governance_status"] == "challenged"


# ---------------------------------------------------------------------------
# CLI → signed receipt → verdict pipeline
# ---------------------------------------------------------------------------

class TestCLISignedPipeline:
    def test_challenge_creates_signed_receipt(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        """Default (no --demo) creates a signed receipt."""
        result = runner.invoke(assay_app, [
            "passport", "challenge", str(signed_passport),
            "--reason", "Missing admin override",
        ])
        assert result.exit_code == 0
        assert "signed" in result.output.lower()

        # Check receipt is signed
        receipts = list(signed_passport.parent.glob("challenge_*.json"))
        assert len(receipts) == 1
        data = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert "signature" in data
        assert "event_id" in data
        assert data["event_id"].startswith("sha256:")

        # Verify it
        vr = verify_lifecycle_receipt(data)
        assert vr["valid"] is True

    def test_challenge_demo_creates_unsigned(
        self, signed_passport: Path, assay_home_tmp: Path
    ) -> None:
        """--demo creates an old-format unsigned receipt."""
        result = runner.invoke(assay_app, [
            "passport", "challenge", str(signed_passport),
            "--reason", "demo test", "--demo",
        ])
        assert result.exit_code == 0
        assert "demo" in result.output.lower()

        receipts = list(signed_passport.parent.glob("challenge_*.json"))
        assert len(receipts) == 1
        data = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert "signature" not in data
        assert "event_id" not in data

    def test_supersede_creates_signed_receipt(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        from assay.passport_sign import sign_passport

        # Create two signed passports
        for name in ("old.json", "new.json"):
            p = {
                "passport_version": "0.1",
                "issued_at": "2026-03-14T00:00:00+00:00",
                "valid_until": "2027-03-14T00:00:00+00:00",
                "subject": {"name": name, "system_id": "x", "owner": "x"},
                "claims": [],
                "relationships": {},
            }
            path = tmp_path / name
            path.write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
            sign_passport(path, keystore=keystore, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "passport", "supersede",
            str(tmp_path / "old.json"), str(tmp_path / "new.json"),
            "--reason", "Coverage improvement",
        ])
        assert result.exit_code == 0

        receipts = list(tmp_path.glob("supersession_*.json"))
        assert len(receipts) == 1
        data = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert data["event_type"] == "supersession"
        assert "signature" in data
        vr = verify_lifecycle_receipt(data)
        assert vr["valid"] is True

    def test_revoke_creates_signed_receipt(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        result = runner.invoke(assay_app, [
            "passport", "revoke", str(signed_passport),
            "--reason", "Key compromised",
        ])
        assert result.exit_code == 0

        receipts = list(signed_passport.parent.glob("revocation_*.json"))
        assert len(receipts) == 1
        data = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert data["event_type"] == "revocation"
        assert "signature" in data
        vr = verify_lifecycle_receipt(data)
        assert vr["valid"] is True

    def test_status_detects_signed_challenge(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        """passport status consumes signed receipts via derive_governance_dimensions."""
        # Issue signed challenge
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        c = create_signed_challenge_receipt(
            target_passport_id=data["passport_id"],
            reason_code="coverage_gap",
            reason_summary="Test",
            keystore=keystore,
            signer_id="test-signer",
        )
        write_lifecycle_receipt(c, signed_passport.parent)

        # Check status in permissive mode (should WARN)
        result = runner.invoke(assay_app, [
            "passport", "status", str(signed_passport),
            "--mode", "permissive", "--json",
        ])
        assert result.exit_code == 1  # WARN
        out = json.loads(result.output)
        assert out["reliance_verdict"] == "WARN"
        assert out["dimensions"]["governance_status"] == "challenged"

    def test_status_detects_signed_revocation(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        r = create_signed_revocation_receipt(
            target_passport_id=data["passport_id"],
            reason_code="key_compromise",
            reason_summary="Test",
            keystore=keystore,
            signer_id="test-signer",
        )
        write_lifecycle_receipt(r, signed_passport.parent)

        result = runner.invoke(assay_app, [
            "passport", "status", str(signed_passport),
            "--mode", "permissive", "--json",
        ])
        assert result.exit_code == 2  # FAIL
        out = json.loads(result.output)
        assert out["reliance_verdict"] == "FAIL"
        assert out["dimensions"]["governance_status"] == "revoked"

        # Governance evidence must be present and inspectable
        ge = out["governance_evidence"]
        assert ge["source"] == "verified_lifecycle_receipts"
        assert ge["signed_total"] == 1
        assert ge["signed_valid"] == 1
        assert ge["unsigned_demo"] == 0
        assert "revocation" in ge["effective_events"]

    def test_status_event_integrity_with_tampered(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        """Tampered receipt degrades event_integrity to some_invalid."""
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        pid = data["passport_id"]

        # Valid challenge
        c = create_signed_challenge_receipt(
            target_passport_id=pid, reason_code="other",
            reason_summary="valid", keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(c, signed_passport.parent)

        # Tampered challenge
        c2 = create_signed_challenge_receipt(
            target_passport_id=pid, reason_code="other",
            reason_summary="will tamper", keystore=keystore, signer_id="test-signer",
        )
        c2["reason"]["summary"] = "tampered after signing"
        write_lifecycle_receipt(c2, signed_passport.parent)

        result = runner.invoke(assay_app, [
            "passport", "status", str(signed_passport),
            "--mode", "strict", "--json",
        ])
        out = json.loads(result.output)
        assert out["dimensions"]["event_integrity"] == "some_invalid"
        # In strict mode, some_invalid → FAIL
        assert out["reliance_verdict"] == "FAIL"

    def test_verify_detects_challenged_state(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        """verify command picks up signed challenges."""
        data = json.loads(signed_passport.read_text(encoding="utf-8"))
        c = create_signed_challenge_receipt(
            target_passport_id=data["passport_id"],
            reason_code="other", reason_summary="test",
            keystore=keystore, signer_id="test-signer",
        )
        write_lifecycle_receipt(c, signed_passport.parent)

        result = runner.invoke(assay_app, [
            "passport", "verify", str(signed_passport),
            "--require-fresh", "--json",
        ])
        assert result.exit_code == 1
        out = json.loads(result.output)
        assert out["state"]["state"] == "CHALLENGED"

    def test_full_lifecycle_signed(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """Full signed lifecycle: mint → sign → challenge → verify → supersede → status."""
        from assay.passport_sign import sign_passport

        # Mint + sign v1
        p1 = {
            "passport_version": "0.1",
            "issued_at": "2026-03-14T00:00:00+00:00",
            "valid_until": "2027-03-14T00:00:00+00:00",
            "subject": {"name": "App", "system_id": "app.v1", "owner": "Inc"},
            "claims": [{"claim_id": "C-001", "result": "pass"}],
            "relationships": {},
        }
        p1_path = tmp_path / "v1.json"
        p1_path.write_text(json.dumps(p1, indent=2) + "\n", encoding="utf-8")
        sign_passport(p1_path, keystore=keystore, signer_id="test-signer")

        p1_data = json.loads(p1_path.read_text(encoding="utf-8"))
        p1_id = p1_data["passport_id"]

        # Challenge
        result = runner.invoke(assay_app, [
            "passport", "challenge", str(p1_path),
            "--reason", "Gap found",
        ])
        assert result.exit_code == 0

        # Verify shows CHALLENGED
        result = runner.invoke(assay_app, [
            "passport", "verify", str(p1_path), "--json",
        ])
        out = json.loads(result.output)
        assert out["state"]["state"] == "CHALLENGED"

        # Mint + sign v2
        p2 = {
            "passport_version": "0.1",
            "issued_at": "2026-03-14T00:00:00+00:00",
            "valid_until": "2027-03-14T00:00:00+00:00",
            "subject": {"name": "App", "system_id": "app.v1", "owner": "Inc"},
            "claims": [{"claim_id": "C-001", "result": "pass"},
                        {"claim_id": "C-002", "result": "pass"}],
            "relationships": {},
        }
        p2_path = tmp_path / "v2.json"
        p2_path.write_text(json.dumps(p2, indent=2) + "\n", encoding="utf-8")
        sign_passport(p2_path, keystore=keystore, signer_id="test-signer")

        # Supersede v1 → v2
        result = runner.invoke(assay_app, [
            "passport", "supersede", str(p1_path), str(p2_path),
            "--reason", "Fixed gap",
        ])
        assert result.exit_code == 0

        # v1 status → SUPERSEDED (supersession receipt overrides challenge)
        result = runner.invoke(assay_app, [
            "passport", "status", str(p1_path), "--json",
        ])
        out = json.loads(result.output)
        # Should be superseded (superseded > challenged in governance priority)
        assert out["dimensions"]["governance_status"] == "superseded"

        # v2 is clean — supersede does not mutate signed passports,
        # so v2's signature remains valid and status should be PASS.
        result = runner.invoke(assay_app, [
            "passport", "status", str(p2_path), "--json",
        ])
        assert result.exit_code == 0
        out = json.loads(result.output)
        assert out["reliance_verdict"] == "PASS"
        assert out["dimensions"]["governance_status"] == "none"


# ---------------------------------------------------------------------------
# Signature preservation invariant
# ---------------------------------------------------------------------------

class TestSignaturePreservation:
    def test_supersede_preserves_signed_passport_signatures(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """Supersede must not mutate signed passports — signatures stay valid."""
        from assay.passport_sign import sign_passport, verify_passport_signature

        for name in ("old.json", "new.json"):
            p = {
                "passport_version": "0.1",
                "issued_at": "2026-03-14T00:00:00+00:00",
                "valid_until": "2027-03-14T00:00:00+00:00",
                "subject": {"name": name, "system_id": "x", "owner": "x"},
                "claims": [],
                "relationships": {},
            }
            path = tmp_path / name
            path.write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
            sign_passport(path, keystore=keystore, signer_id="test-signer")

        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"

        # Capture pre-supersede passport_ids
        old_id_before = json.loads(old_path.read_text(encoding="utf-8"))["passport_id"]
        new_id_before = json.loads(new_path.read_text(encoding="utf-8"))["passport_id"]

        # Supersede
        result = runner.invoke(assay_app, [
            "passport", "supersede", str(old_path), str(new_path),
            "--reason", "Test",
        ])
        assert result.exit_code == 0

        # Both passports must still verify — signatures not broken
        old_vr = verify_passport_signature(old_path, keystore=keystore)
        new_vr = verify_passport_signature(new_path, keystore=keystore)
        assert old_vr["signature_valid"] is True, "Old passport signature broken by supersede"
        assert new_vr["signature_valid"] is True, "New passport signature broken by supersede"

        # passport_ids unchanged
        old_id_after = json.loads(old_path.read_text(encoding="utf-8"))["passport_id"]
        new_id_after = json.loads(new_path.read_text(encoding="utf-8"))["passport_id"]
        assert old_id_before == old_id_after
        assert new_id_before == new_id_after

        # Relationship fields NOT written to signed passports
        old_data = json.loads(old_path.read_text(encoding="utf-8"))
        new_data = json.loads(new_path.read_text(encoding="utf-8"))
        assert old_data["relationships"].get("superseded_by") is None
        assert new_data["relationships"].get("supersedes") is None

        # But the receipt carries the full chain
        receipts = list(tmp_path.glob("supersession_*.json"))
        assert len(receipts) == 1
        r = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert r["target"]["passport_id"] == old_id_before
        assert r["supersession"]["new_passport_id"] == new_id_before

    def test_signed_passport_bytes_unchanged_after_supersede(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """CONSTITUTIONAL INVARIANT: signed passport file bytes must not change.

        If supersede mutates a signed passport, the content-addressed identity
        and Ed25519 signature become invalid. This test enforces byte-level
        immutability: the file on disk must be identical before and after.
        """
        from assay.passport_sign import sign_passport

        for name in ("a.json", "b.json"):
            p = {
                "passport_version": "0.1",
                "issued_at": "2026-03-14T00:00:00+00:00",
                "valid_until": "2027-03-14T00:00:00+00:00",
                "subject": {"name": name, "system_id": "x", "owner": "x"},
                "claims": [],
                "relationships": {},
            }
            path = tmp_path / name
            path.write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
            sign_passport(path, keystore=keystore, signer_id="test-signer")

        a_path = tmp_path / "a.json"
        b_path = tmp_path / "b.json"

        # Snapshot raw bytes before supersede
        a_bytes_before = a_path.read_bytes()
        b_bytes_before = b_path.read_bytes()

        runner.invoke(assay_app, [
            "passport", "supersede", str(a_path), str(b_path),
            "--reason", "Immutability test",
        ])

        # File bytes must be identical — zero mutation
        assert a_path.read_bytes() == a_bytes_before, \
            "INVARIANT VIOLATION: signed passport A was mutated by supersede"
        assert b_path.read_bytes() == b_bytes_before, \
            "INVARIANT VIOLATION: signed passport B was mutated by supersede"

    def test_supersede_mutates_unsigned_passports(
        self, tmp_path: Path, assay_home_tmp: Path
    ) -> None:
        """Unsigned passports still get relationship fields written."""
        p1 = {"passport_version": "0.1", "passport_id": "sha256:aaa",
               "subject": {"name": "v1"}, "relationships": {}}
        p2 = {"passport_version": "0.1", "passport_id": "sha256:bbb",
               "subject": {"name": "v2"}, "relationships": {}}
        p1_path = tmp_path / "v1.json"
        p2_path = tmp_path / "v2.json"
        p1_path.write_text(json.dumps(p1, indent=2), encoding="utf-8")
        p2_path.write_text(json.dumps(p2, indent=2), encoding="utf-8")

        result = runner.invoke(assay_app, [
            "passport", "supersede", str(p1_path), str(p2_path),
            "--reason", "test", "--demo",
        ])
        assert result.exit_code == 0

        # Unsigned passports DO get relationship fields
        p1_data = json.loads(p1_path.read_text(encoding="utf-8"))
        p2_data = json.loads(p2_path.read_text(encoding="utf-8"))
        assert p1_data["relationships"]["superseded_by"] == "sha256:bbb"
        assert p2_data["relationships"]["supersedes"] == "sha256:aaa"


# ---------------------------------------------------------------------------
# Demo receipt isolation
# ---------------------------------------------------------------------------

class TestDemoReceiptIsolation:
    def test_demo_receipt_has_no_signature(
        self, signed_passport: Path, assay_home_tmp: Path
    ) -> None:
        result = runner.invoke(assay_app, [
            "passport", "challenge", str(signed_passport),
            "--reason", "demo test", "--demo",
        ])
        assert result.exit_code == 0
        receipts = list(signed_passport.parent.glob("challenge_*.json"))
        data = json.loads(receipts[0].read_text(encoding="utf-8"))
        # Demo receipts must NOT have signature or event_id
        assert "signature" not in data
        assert "event_id" not in data
        # Demo receipts use old flat format
        assert data.get("type") == "challenge"

    def test_signed_receipt_has_full_envelope(
        self, signed_passport: Path, keystore: AssayKeyStore
    ) -> None:
        result = runner.invoke(assay_app, [
            "passport", "challenge", str(signed_passport),
            "--reason", "production test",
        ])
        assert result.exit_code == 0
        receipts = list(signed_passport.parent.glob("challenge_*.json"))
        data = json.loads(receipts[0].read_text(encoding="utf-8"))
        # Signed receipts have full envelope
        assert "signature" in data
        assert "event_id" in data
        assert data["event_id"].startswith("sha256:")
        assert data["event_type"] == "challenge"
        assert "issuer" in data
        assert "pubkey" in data["issuer"]
        assert data["receipt_version"] == "0.1"
