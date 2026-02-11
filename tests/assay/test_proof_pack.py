"""
Tests for Proof Pack v0: builder, integrity verifier, keystore.

Covers the 5-file kernel and end-to-end verification.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

import pytest

from assay.claim_verifier import (
    ClaimSpec,
    check_field_value_matches,
    check_no_receipt_type,
    check_receipt_count_ge,
    check_receipt_type_present,
    check_timestamps_monotonic,
    verify_claims,
)
from assay.integrity import (
    E_MANIFEST_TAMPER,
    E_PACK_OMISSION_DETECTED,
    E_PACK_SIG_INVALID,
    E_POLICY_MISSING,
    E_SCHEMA_UNKNOWN,
    E_SIG_MISSING,
    E_TIMESTAMP_INVALID,
    verify_pack_manifest,
    verify_receipt,
    verify_receipt_pack,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.run_cards import (
    BUILTIN_CARDS,
    RunCard,
    collect_claims_from_cards,
    get_all_builtin_cards,
    get_builtin_card,
    load_run_card,
)
from assay._receipts.canonicalize import to_jcs_bytes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_receipt(**overrides):
    """Create a minimal valid receipt dict."""
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


@pytest.fixture
def tmp_keys(tmp_path):
    """Create a temporary keystore."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test-signer")
    return ks


@pytest.fixture
def sample_receipts():
    """A list of 5 valid receipts."""
    return [_make_receipt(seq=i) for i in range(5)]


# ---------------------------------------------------------------------------
# Keystore tests
# ---------------------------------------------------------------------------

class TestKeyStore:
    def test_generate_and_verify(self, tmp_path):
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        ks.generate_key("test")

        data = b"hello world"
        sig = ks.sign(data, "test")
        assert ks.verify(data, sig, "test")

    def test_verify_bad_signature(self, tmp_path):
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        ks.generate_key("test")

        data = b"hello world"
        assert not ks.verify(data, b"bad-sig", "test")

    def test_sign_b64_roundtrip(self, tmp_path):
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        ks.generate_key("test")

        data = b"proof pack data"
        sig_b64 = ks.sign_b64(data, "test")
        assert ks.verify_b64(data, sig_b64, "test")

    def test_ensure_key_idempotent(self, tmp_path):
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        sk1 = ks.ensure_key("test")
        sk2 = ks.ensure_key("test")
        assert sk1.encode() == sk2.encode()


# ---------------------------------------------------------------------------
# JCS canonicalization tests
# ---------------------------------------------------------------------------

class TestCanonicalisation:
    def test_jcs_stability(self):
        """Same dict produces same bytes twice."""
        d = {"b": 2, "a": 1, "c": [3, 4]}
        b1 = to_jcs_bytes(d)
        b2 = to_jcs_bytes(d)
        assert b1 == b2

    def test_jcs_rejects_nan(self):
        """NaN float raises an error."""
        with pytest.raises((ValueError, TypeError, RuntimeError)):
            to_jcs_bytes({"value": float("nan")})

    def test_jcs_rejects_infinity(self):
        """Infinity float raises an error."""
        with pytest.raises((ValueError, TypeError, RuntimeError)):
            to_jcs_bytes({"value": float("inf")})

    def test_jcs_locked_vector(self):
        """Locked test vector: known input -> known canonical bytes -> known hash.

        Catches cross-implementation drift. If this test fails on a new
        platform or JCS library, the canonicalization is not compatible.
        """
        vector_input = {"b": 2, "a": 1, "c": [3, 4], "d": "hello"}
        # RFC 8785: keys sorted lexicographically, no whitespace
        expected_canonical = b'{"a":1,"b":2,"c":[3,4],"d":"hello"}'
        expected_sha256 = hashlib.sha256(expected_canonical).hexdigest()

        actual_canonical = to_jcs_bytes(vector_input)
        actual_sha256 = hashlib.sha256(actual_canonical).hexdigest()

        assert actual_canonical == expected_canonical, (
            f"JCS drift: expected {expected_canonical!r}, got {actual_canonical!r}"
        )
        assert actual_sha256 == expected_sha256


# ---------------------------------------------------------------------------
# Receipt-level verification
# ---------------------------------------------------------------------------

class TestVerifyReceipt:
    def test_valid_receipt(self):
        r = _make_receipt()
        errors = verify_receipt(r)
        assert errors == []

    def test_missing_receipt_id(self):
        r = _make_receipt()
        del r["receipt_id"]
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_SCHEMA_UNKNOWN and e.field == "receipt_id" for e in errors)

    def test_missing_type(self):
        r = _make_receipt()
        del r["type"]
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_SCHEMA_UNKNOWN and e.field == "type" for e in errors)

    def test_missing_timestamp(self):
        r = _make_receipt()
        del r["timestamp"]
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_SCHEMA_UNKNOWN and e.field == "timestamp" for e in errors)

    def test_invalid_timestamp(self):
        r = _make_receipt(timestamp="not-a-date")
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_TIMESTAMP_INVALID for e in errors)


# ---------------------------------------------------------------------------
# Receipt pack verification
# ---------------------------------------------------------------------------

class TestVerifyReceiptPack:
    def test_valid_pack(self, sample_receipts):
        result = verify_receipt_pack(sample_receipts)
        assert result.passed
        assert result.receipt_count == 5

    def test_duplicate_receipt_id(self):
        receipts = [_make_receipt(receipt_id="dup_id") for _ in range(2)]
        result = verify_receipt_pack(receipts)
        assert not result.passed
        assert any(e.code == "E_DUPLICATE_ID" for e in result.errors)

    def test_head_hash_computed(self, sample_receipts):
        result = verify_receipt_pack(sample_receipts)
        assert result.head_hash is not None
        assert len(result.head_hash) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# Proof Pack builder
# ---------------------------------------------------------------------------

class TestProofPackBuilder:
    def test_5_files_present(self, tmp_path, tmp_keys, sample_receipts):
        pack = ProofPack(
            trace_id="test_trace_001",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)

        kernel_files = {
            "receipt_pack.jsonl",
            "verify_report.json",
            "verify_transcript.md",
            "pack_manifest.json",
            "pack_signature.sig",
        }
        actual_files = {f.name for f in out.iterdir()}
        assert kernel_files.issubset(actual_files)
        # PACK_SUMMARY.md is a presentation extra, not part of the verification kernel
        assert actual_files - kernel_files <= {"PACK_SUMMARY.md"}

    def test_manifest_is_valid_json(self, tmp_path, tmp_keys, sample_receipts):
        pack = ProofPack(
            trace_id="test_trace_002",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["pack_version"] == "0.1.0"
        assert manifest["signature_alg"] == "ed25519"
        assert "signature" in manifest

    def test_attestation_sha256_matches(self, tmp_path, tmp_keys, sample_receipts):
        pack = ProofPack(
            trace_id="test_trace_003",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        att = manifest["attestation"]
        att_bytes = to_jcs_bytes(att)
        expected = hashlib.sha256(att_bytes).hexdigest()
        assert manifest["attestation_sha256"] == expected

    def test_receipt_count_matches(self, tmp_path, tmp_keys, sample_receipts):
        pack = ProofPack(
            trace_id="test_trace_004",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["receipt_count_expected"] == 5
        assert manifest["attestation"]["n_receipts"] == 5

    def test_end_to_end_verify(self, tmp_path, tmp_keys, sample_receipts):
        """Build pack then verify it — should pass."""
        pack = ProofPack(
            trace_id="test_trace_005",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert result.passed, f"Errors: {[e.to_dict() for e in result.errors]}"

    def test_end_to_end_verify_without_local_key(self, tmp_path, tmp_keys, sample_receipts):
        """Verifier should pass using embedded signer_pubkey even without local keys."""
        pack = ProofPack(
            trace_id="test_trace_005b",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        empty_keystore = AssayKeyStore(keys_dir=tmp_path / "empty_keys")
        result = verify_pack_manifest(manifest, out, empty_keystore)
        assert result.passed, f"Errors: {[e.to_dict() for e in result.errors]}"

    def test_verify_prefers_embedded_pubkey_over_wrong_local_key(
        self, tmp_path, tmp_keys, sample_receipts
    ):
        """Local keystore drift should warn, not fail, when embedded pubkey verifies."""
        pack = ProofPack(
            trace_id="test_trace_005c",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        wrong_keystore = AssayKeyStore(keys_dir=tmp_path / "wrong_keys")
        wrong_keystore.generate_key("test-signer")
        result = verify_pack_manifest(manifest, out, wrong_keystore)
        assert result.passed, f"Errors: {[e.to_dict() for e in result.errors]}"
        assert any(
            "fingerprint differs" in w for w in result.warnings
        )

    def test_manifest_tamper_detection(self, tmp_path, tmp_keys, sample_receipts):
        """Modify a file after packing — verification should fail."""
        pack = ProofPack(
            trace_id="test_trace_006",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)

        # Tamper with verify_report.json
        report_path = out / "verify_report.json"
        report_path.write_text(report_path.read_text() + "\n// tampered")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert not result.passed
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors)

    def test_signature_tamper_detection(self, tmp_path, tmp_keys, sample_receipts):
        """Modify manifest after signing — signature should fail."""
        pack = ProofPack(
            trace_id="test_trace_007",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)

        manifest = json.loads((out / "pack_manifest.json").read_text())
        manifest["receipt_count_expected"] = 999  # tamper

        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert not result.passed
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)

    def test_detached_signature_mismatch_detection(self, tmp_path, tmp_keys, sample_receipts):
        """Detached pack_signature.sig must match manifest signature bytes."""
        pack = ProofPack(
            trace_id="test_trace_007b",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)

        # Corrupt detached signature bytes
        sig_path = out / "pack_signature.sig"
        sig_path.write_bytes(b"corrupted-signature")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert not result.passed
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)

    def test_omission_detection(self, tmp_path, tmp_keys, sample_receipts):
        """Remove receipts from pack — count mismatch detected."""
        pack = ProofPack(
            trace_id="test_trace_008",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)

        # Remove 2 receipts from the file
        rp = out / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        rp.write_text("\n".join(lines[:3]) + "\n")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert not result.passed
        # Should detect both omission and file hash change
        codes = {e.code for e in result.errors}
        assert E_PACK_OMISSION_DETECTED in codes or E_MANIFEST_TAMPER in codes

    def test_transcript_contains_attestation(self, tmp_path, tmp_keys, sample_receipts):
        pack = ProofPack(
            trace_id="test_trace_009",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        transcript = (out / "verify_transcript.md").read_text()
        assert "Receipt Integrity" in transcript
        assert "PASS" in transcript
        assert "test_trace_009" in transcript

    def test_empty_trace(self, tmp_path, tmp_keys):
        """Empty trace should still produce a valid pack."""
        pack = ProofPack(
            trace_id="test_trace_empty",
            entries=[],
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["receipt_count_expected"] == 0

    def test_expected_files_in_manifest(self, tmp_path, tmp_keys, sample_receipts):
        """Manifest should list all 5 expected files."""
        pack = ProofPack(
            trace_id="test_trace_expected",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert "expected_files" in manifest
        expected = set(manifest["expected_files"])
        assert expected == {
            "receipt_pack.jsonl",
            "verify_report.json",
            "verify_transcript.md",
            "pack_manifest.json",
            "pack_signature.sig",
        }

    def test_missing_expected_file_detected(self, tmp_path, tmp_keys, sample_receipts):
        """Deleting an expected file that's not in hash-covered files list."""
        pack = ProofPack(
            trace_id="test_trace_missing_expected",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        # Delete pack_manifest.json from disk but pass manifest dict directly
        # This simulates someone who has the manifest data but the file is gone
        # Instead, delete pack_signature.sig which IS in expected_files
        # but NOT in the hash-covered files array
        (out / "pack_signature.sig").unlink()

        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert not result.passed
        codes = {e.code for e in result.errors}
        assert E_PACK_SIG_INVALID in codes or E_MANIFEST_TAMPER in codes


# ---------------------------------------------------------------------------
# Strict mode verification
# ---------------------------------------------------------------------------

class TestStrictMode:
    def test_permissive_passes_minimal_receipt(self):
        """Minimal receipt passes in default (permissive) mode."""
        r = _make_receipt()
        errors = verify_receipt(r)
        assert errors == []

    def test_strict_passes_complete_receipt(self):
        """Fully-qualified receipt passes strict mode."""
        r = _make_receipt(
            schema_version="3.0",
            policy_hash="abc123",
            payload_hash="sha256:deadbeef",
        )
        errors = verify_receipt(r, strict=True)
        assert errors == []

    def test_strict_missing_policy_hash(self):
        """Strict mode rejects receipt without policy_hash."""
        r = _make_receipt(
            schema_version="3.0",
            payload_hash="sha256:deadbeef",
        )
        errors = verify_receipt(r, strict=True)
        assert any(e.code == E_POLICY_MISSING for e in errors)

    def test_strict_governance_hash_accepted(self):
        """governance_hash is accepted as alternative to policy_hash."""
        r = _make_receipt(
            schema_version="3.0",
            governance_hash="abc123",
            payload_hash="sha256:deadbeef",
        )
        errors = verify_receipt(r, strict=True)
        assert not any(e.code == E_POLICY_MISSING for e in errors)

    def test_strict_missing_signature(self):
        """Strict mode rejects receipt without signature or payload_hash."""
        r = _make_receipt(
            schema_version="3.0",
            policy_hash="abc123",
        )
        errors = verify_receipt(r, strict=True)
        assert any(e.code == E_SIG_MISSING for e in errors)

    def test_strict_payload_hash_accepted(self):
        """payload_hash is accepted as alternative to signature."""
        r = _make_receipt(
            schema_version="3.0",
            policy_hash="abc123",
            payload_hash="sha256:deadbeef",
        )
        errors = verify_receipt(r, strict=True)
        assert not any(e.code == E_SIG_MISSING for e in errors)

    def test_strict_missing_schema_version(self):
        """Strict mode rejects receipt without schema_version."""
        r = _make_receipt()
        del r["schema_version"]
        errors = verify_receipt(r, strict=True)
        assert any(
            e.code == E_SCHEMA_UNKNOWN and e.field == "schema_version"
            for e in errors
        )

    def test_strict_pack_level(self):
        """strict=True propagates to verify_receipt_pack."""
        receipts = [_make_receipt() for _ in range(3)]
        # Permissive passes
        assert verify_receipt_pack(receipts).passed
        # Strict fails (no policy_hash, no signature)
        result = verify_receipt_pack(receipts, strict=True)
        assert not result.passed
        codes = {e.code for e in result.errors}
        assert E_POLICY_MISSING in codes
        assert E_SIG_MISSING in codes


# ---------------------------------------------------------------------------
# Audit-hardening fields (proof_tier, pubkey, pack_root, metadata)
# ---------------------------------------------------------------------------

class TestAuditHardeningFields:
    def test_proof_tier_in_attestation(self, tmp_path, tmp_keys, sample_receipts):
        """Attestation contains proof_tier = signed-pack."""
        pack = ProofPack(
            run_id="test_proof_tier",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["proof_tier"] == "signed-pack"

    def test_time_authority_in_attestation(self, tmp_path, tmp_keys, sample_receipts):
        """Attestation contains time_authority = local_clock."""
        pack = ProofPack(
            run_id="test_time_authority",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["time_authority"] == "local_clock"

    def test_head_hash_algorithm(self, tmp_path, tmp_keys, sample_receipts):
        """Attestation contains head_hash_algorithm."""
        pack = ProofPack(
            run_id="test_hha",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["head_hash_algorithm"] == "last-receipt-digest-v0"

    def test_canon_impl_fields(self, tmp_path, tmp_keys, sample_receipts):
        """Attestation records canon_impl and canon_impl_version."""
        pack = ProofPack(
            run_id="test_canon_impl",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        att = manifest["attestation"]
        assert att["canon_impl"] == "receipts.jcs"
        assert att["canon_impl_version"]  # non-empty

    def test_pubkey_fingerprint_in_manifest(self, tmp_path, tmp_keys, sample_receipts):
        """Manifest embeds signer pubkey and its SHA-256 fingerprint."""
        pack = ProofPack(
            run_id="test_pubkey_fp",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        assert "signer_pubkey" in manifest
        assert "signer_pubkey_sha256" in manifest

        # Verify fingerprint matches actual key
        import base64
        pubkey_bytes = base64.b64decode(manifest["signer_pubkey"])
        expected_fp = hashlib.sha256(pubkey_bytes).hexdigest()
        assert manifest["signer_pubkey_sha256"] == expected_fp

    def test_pubkey_matches_keystore(self, tmp_path, tmp_keys, sample_receipts):
        """Embedded pubkey matches the keystore's verify key."""
        pack = ProofPack(
            run_id="test_pubkey_ks",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        import base64
        embedded_key = base64.b64decode(manifest["signer_pubkey"])
        keystore_key = tmp_keys.get_verify_key("test-signer").encode()
        assert embedded_key == keystore_key

    def test_pack_root_sha256(self, tmp_path, tmp_keys, sample_receipts):
        """D12: pack_root_sha256 = attestation_sha256."""
        pack = ProofPack(
            run_id="test_pack_root",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        assert "pack_root_sha256" in manifest
        assert len(manifest["pack_root_sha256"]) == 64

        # D12: pack_root = attestation_sha256
        assert manifest["pack_root_sha256"] == manifest["attestation_sha256"]

        # Verify attestation_sha256 is correct
        att_bytes = to_jcs_bytes(manifest["attestation"])
        expected = hashlib.sha256(att_bytes).hexdigest()
        assert manifest["attestation_sha256"] == expected

    def test_pack_root_tamper_detected(self, tmp_path, tmp_keys, sample_receipts):
        """Tampering pack_root_sha256 is caught by verifier."""
        pack = ProofPack(
            run_id="test_pack_root_tamper",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        manifest["pack_root_sha256"] = "0" * 64  # tamper

        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert not result.passed
        # Should detect either root hash mismatch or signature failure
        codes = {e.code for e in result.errors}
        assert E_MANIFEST_TAMPER in codes or E_PACK_SIG_INVALID in codes

    def test_run_id_constructor(self, tmp_path, tmp_keys, sample_receipts):
        """ProofPack accepts run_id as canonical parameter."""
        pack = ProofPack(
            run_id="test_run_id_ctor",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["run_id"] == "test_run_id_ctor"

    def test_trace_id_alias(self, tmp_path, tmp_keys, sample_receipts):
        """ProofPack still accepts trace_id as backward-compat alias."""
        pack = ProofPack(
            trace_id="test_trace_alias",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        # trace_id is stored as run_id in attestation
        assert manifest["attestation"]["run_id"] == "test_trace_alias"

    def test_run_id_required(self):
        """ProofPack raises if neither run_id nor trace_id provided."""
        with pytest.raises(ValueError, match="run_id"):
            ProofPack(entries=[])


# ---------------------------------------------------------------------------
# Claim verifier tests
# ---------------------------------------------------------------------------

class TestCheckFunctions:
    """Test each built-in check function individually."""

    def test_receipt_type_present_found(self):
        receipts = [
            {"type": "model_call", "receipt_id": "r1"},
            {"type": "guardian_verdict", "receipt_id": "r2"},
        ]
        result = check_receipt_type_present(
            receipts, claim_id="test", receipt_type="guardian_verdict"
        )
        assert result.passed
        assert "r2" in result.evidence_receipt_ids

    def test_receipt_type_present_not_found(self):
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        result = check_receipt_type_present(
            receipts, claim_id="test", receipt_type="guardian_verdict"
        )
        assert not result.passed

    def test_no_receipt_type_pass(self):
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        result = check_no_receipt_type(
            receipts, claim_id="test", receipt_type="breakglass"
        )
        assert result.passed

    def test_no_receipt_type_fail(self):
        receipts = [{"type": "breakglass", "receipt_id": "r1"}]
        result = check_no_receipt_type(
            receipts, claim_id="test", receipt_type="breakglass"
        )
        assert not result.passed
        assert "r1" in result.evidence_receipt_ids

    def test_receipt_count_ge_pass(self):
        receipts = [{"receipt_id": f"r{i}"} for i in range(5)]
        result = check_receipt_count_ge(
            receipts, claim_id="test", min_count=3
        )
        assert result.passed

    def test_receipt_count_ge_fail(self):
        receipts = [{"receipt_id": "r1"}]
        result = check_receipt_count_ge(
            receipts, claim_id="test", min_count=5
        )
        assert not result.passed

    def test_timestamps_monotonic_pass(self):
        receipts = [
            {"timestamp": "2026-01-01T00:00:00Z", "receipt_id": "r1"},
            {"timestamp": "2026-01-01T00:01:00Z", "receipt_id": "r2"},
            {"timestamp": "2026-01-01T00:02:00Z", "receipt_id": "r3"},
        ]
        result = check_timestamps_monotonic(receipts, claim_id="test")
        assert result.passed

    def test_timestamps_monotonic_fail(self):
        receipts = [
            {"timestamp": "2026-01-01T00:02:00Z", "receipt_id": "r1"},
            {"timestamp": "2026-01-01T00:00:00Z", "receipt_id": "r2"},
        ]
        result = check_timestamps_monotonic(receipts, claim_id="test")
        assert not result.passed
        assert "r2" in result.evidence_receipt_ids

    def test_timestamps_monotonic_equal_ok(self):
        """Equal timestamps are non-decreasing (should pass)."""
        receipts = [
            {"timestamp": "2026-01-01T00:00:00Z", "receipt_id": "r1"},
            {"timestamp": "2026-01-01T00:00:00Z", "receipt_id": "r2"},
        ]
        result = check_timestamps_monotonic(receipts, claim_id="test")
        assert result.passed

    def test_field_value_matches_pass(self):
        receipts = [
            {"type": "model_call", "schema_version": "3.0", "receipt_id": "r1"},
            {"type": "model_call", "schema_version": "3.0", "receipt_id": "r2"},
        ]
        result = check_field_value_matches(
            receipts,
            claim_id="test",
            receipt_type="model_call",
            field_name="schema_version",
            expected_value="3.0",
        )
        assert result.passed

    def test_field_value_matches_mismatch(self):
        receipts = [
            {"type": "model_call", "schema_version": "3.0", "receipt_id": "r1"},
            {"type": "model_call", "schema_version": "2.0", "receipt_id": "r2"},
        ]
        result = check_field_value_matches(
            receipts,
            claim_id="test",
            receipt_type="model_call",
            field_name="schema_version",
            expected_value="3.0",
        )
        assert not result.passed
        assert "r2" in result.evidence_receipt_ids

    def test_field_value_matches_no_receipts_of_type(self):
        receipts = [{"type": "guardian_verdict", "receipt_id": "r1"}]
        result = check_field_value_matches(
            receipts,
            claim_id="test",
            receipt_type="model_call",
            field_name="schema_version",
            expected_value="3.0",
        )
        assert not result.passed
        assert "no receipts of that type" in result.actual


class TestVerifyClaims:
    """Test the verify_claims orchestrator."""

    def test_all_pass(self):
        receipts = [
            {"type": "model_call", "receipt_id": "r1",
             "timestamp": "2026-01-01T00:00:00Z"},
        ]
        claims = [
            ClaimSpec(
                claim_id="has_model_call",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        result = verify_claims(receipts, claims)
        assert result.passed
        assert result.n_claims == 1
        assert result.n_passed == 1
        assert result.n_failed == 0

    def test_critical_failure(self):
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="need_guardian",
                description="need guardian_verdict",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="critical",
            ),
        ]
        result = verify_claims(receipts, claims)
        assert not result.passed
        assert result.n_failed == 1

    def test_warning_does_not_fail_set(self):
        """Warnings are recorded but don't cause overall failure."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="soft_check",
                description="soft check",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="warning",
            ),
        ]
        result = verify_claims(receipts, claims)
        assert result.passed  # warning doesn't fail
        assert result.n_failed == 1  # still counted as failed

    def test_warning_severity_case_insensitive(self):
        """Severity labels are normalized so WARNING still behaves as warning."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="soft_check_case",
                description="soft check with uppercase severity",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="WARNING",
            ),
        ]
        result = verify_claims(receipts, claims)
        assert result.passed
        assert result.results[0].severity == "warning"

    def test_invalid_severity_fails_closed(self):
        """Unknown severities are rejected as critical failures."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="bad_severity",
                description="invalid severity should fail",
                check="receipt_count_ge",
                params={"min_count": 1},
                severity="advisory",
            ),
        ]
        result = verify_claims(receipts, claims)
        assert not result.passed
        assert result.results[0].severity == "critical"
        assert "invalid severity" in result.results[0].actual

    def test_unknown_check_fails(self):
        """Unknown check function name -> automatic fail."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="bad_check",
                description="bad check fn",
                check="nonexistent_check_fn",
            ),
        ]
        result = verify_claims(receipts, claims)
        assert not result.passed
        assert "unknown check function" in result.results[0].actual

    def test_discrepancy_fingerprint_deterministic(self):
        """Same inputs -> same fingerprint, different inputs -> different."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="check",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        r1 = verify_claims(receipts, claims)
        r2 = verify_claims(receipts, claims)
        assert r1.discrepancy_fingerprint == r2.discrepancy_fingerprint
        assert len(r1.discrepancy_fingerprint) == 64

        # Different claim -> different fingerprint
        claims2 = [
            ClaimSpec(
                claim_id="c2",
                description="different check",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        r3 = verify_claims(receipts, claims2)
        assert r3.discrepancy_fingerprint != r1.discrepancy_fingerprint

    def test_fingerprint_v1_policy_sensitivity(self):
        """Fingerprint v1: same results, different policy_hash -> different fingerprint."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="check",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        r_a = verify_claims(receipts, claims, policy_hash="aaa", suite_hash="xxx")
        r_b = verify_claims(receipts, claims, policy_hash="bbb", suite_hash="xxx")
        r_c = verify_claims(receipts, claims, policy_hash="aaa", suite_hash="yyy")
        # Same claim outcomes, but different context -> different fingerprints
        assert r_a.discrepancy_fingerprint != r_b.discrepancy_fingerprint
        assert r_a.discrepancy_fingerprint != r_c.discrepancy_fingerprint
        # Deterministic: same inputs -> same fingerprint
        r_a2 = verify_claims(receipts, claims, policy_hash="aaa", suite_hash="xxx")
        assert r_a.discrepancy_fingerprint == r_a2.discrepancy_fingerprint

    def test_mixed_critical_and_warning(self):
        """Critical pass + warning fail -> overall PASS."""
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="critical_ok",
                description="passes",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
                severity="critical",
            ),
            ClaimSpec(
                claim_id="warning_fail",
                description="fails as warning",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="warning",
            ),
        ]
        result = verify_claims(receipts, claims)
        assert result.passed  # critical passed
        assert result.n_passed == 1
        assert result.n_failed == 1

    def test_claim_set_result_to_dict(self):
        receipts = [{"type": "model_call", "receipt_id": "r1"}]
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="test",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        result = verify_claims(receipts, claims)
        d = result.to_dict()
        assert d["passed"] is True
        assert d["n_claims"] == 1
        assert len(d["results"]) == 1
        assert d["results"][0]["claim_id"] == "c1"


# ---------------------------------------------------------------------------
# RunCard tests
# ---------------------------------------------------------------------------

class TestRunCards:
    def test_builtin_cards_count(self):
        assert len(BUILTIN_CARDS) == 6

    def test_get_builtin_card(self):
        card = get_builtin_card("guardian_enforcement")
        assert card.card_id == "guardian_enforcement"
        assert len(card.claims) > 0

    def test_get_builtin_card_not_found(self):
        assert get_builtin_card("nonexistent_card") is None

    def test_get_all_builtin_cards(self):
        cards = get_all_builtin_cards()
        assert len(cards) == 6
        ids = {c.card_id for c in cards}
        assert "guardian_enforcement" in ids
        assert "receipt_completeness" in ids
        assert "no_breakglass" in ids
        assert "timestamp_ordering" in ids
        assert "schema_consistency" in ids

    def test_collect_claims_from_cards(self):
        cards = get_all_builtin_cards()
        claims = collect_claims_from_cards(cards)
        assert len(claims) >= 5  # at least one per card
        # All claims are ClaimSpec instances
        assert all(isinstance(c, ClaimSpec) for c in claims)

    def test_stochastic_trials_rejected(self):
        card = RunCard(
            card_id="stochastic_test",
            name="Stochastic",
            description="trials > 1",
            stochastic=True,
            trials=3,
        )
        with pytest.raises(NotImplementedError, match="Stochastic"):
            collect_claims_from_cards([card])

    def test_card_to_dict(self):
        card = get_builtin_card("receipt_completeness")
        d = card.to_dict()
        assert d["card_id"] == "receipt_completeness"
        assert isinstance(d["claims"], list)
        assert d["stochastic"] is False
        assert d["trials"] == 1

    def test_claim_set_hash_deterministic(self):
        card = get_builtin_card("receipt_completeness")
        h1 = card.claim_set_hash()
        h2 = card.claim_set_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_load_run_card_from_json(self, tmp_path):
        card_data = {
            "card_id": "custom_test",
            "name": "Custom Test Card",
            "description": "A test card loaded from JSON",
            "claims": [
                {
                    "claim_id": "custom_claim",
                    "description": "At least 1 receipt",
                    "check": "receipt_count_ge",
                    "params": {"min_count": 1},
                },
            ],
        }
        card_file = tmp_path / "custom_card.json"
        card_file.write_text(json.dumps(card_data))

        card = load_run_card(card_file)
        assert card.card_id == "custom_test"
        assert card.name == "Custom Test Card"
        assert len(card.claims) == 1
        assert card.claims[0].check == "receipt_count_ge"
        assert card.stochastic is False
        assert card.trials == 1


# ---------------------------------------------------------------------------
# Claim verification wiring into ProofPack
# ---------------------------------------------------------------------------

class TestClaimWiring:
    """Test that claim_check is wired into the ProofPack builder."""

    def test_no_claims_gives_na(self, tmp_path, tmp_keys, sample_receipts):
        """Without claims, claim_check = N/A."""
        pack = ProofPack(
            run_id="test_no_claims",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_check"] == "N/A"
        assert manifest["attestation"]["discrepancy_fingerprint"] is None

    def test_claims_pass(self, tmp_path, tmp_keys, sample_receipts):
        """Claims that pass set claim_check = PASS."""
        claims = [
            ClaimSpec(
                claim_id="has_receipts",
                description="at least 1 receipt",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
            ClaimSpec(
                claim_id="has_model_call",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        pack = ProofPack(
            run_id="test_claims_pass",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_check"] == "PASS"
        assert manifest["attestation"]["discrepancy_fingerprint"]
        assert len(manifest["attestation"]["discrepancy_fingerprint"]) == 64

    def test_claims_fail(self, tmp_path, tmp_keys, sample_receipts):
        """Claims that fail set claim_check = FAIL."""
        claims = [
            ClaimSpec(
                claim_id="need_guardian",
                description="guardian_verdict present",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="critical",
            ),
        ]
        pack = ProofPack(
            run_id="test_claims_fail",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_check"] == "FAIL"
        assert manifest["attestation"]["discrepancy_fingerprint"]

    def test_integrity_pass_claim_fail(self, tmp_path, tmp_keys, sample_receipts):
        """The critical demo: integrity PASS + claim FAIL without ambiguity."""
        claims = [
            ClaimSpec(
                claim_id="impossible_claim",
                description="need 1000 receipts",
                check="receipt_count_ge",
                params={"min_count": 1000},
                severity="critical",
            ),
        ]
        pack = ProofPack(
            run_id="test_dual_result",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        att = manifest["attestation"]

        # Both results visible, no ambiguity
        assert att["receipt_integrity"] == "PASS"
        assert att["claim_check"] == "FAIL"

    def test_claim_results_in_report(self, tmp_path, tmp_keys, sample_receipts):
        """verify_report.json contains claim_verification section."""
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="check",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        pack = ProofPack(
            run_id="test_report_claims",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        report = json.loads((out / "verify_report.json").read_text())

        assert "claim_verification" in report
        cv = report["claim_verification"]
        assert cv["passed"] is True
        assert cv["n_claims"] == 1
        assert cv["n_passed"] == 1
        assert len(cv["results"]) == 1
        assert cv["results"][0]["claim_id"] == "c1"

    def test_no_claim_results_in_report_without_claims(
        self, tmp_path, tmp_keys, sample_receipts
    ):
        """verify_report.json has no claim_verification when no claims."""
        pack = ProofPack(
            run_id="test_report_no_claims",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        report = json.loads((out / "verify_report.json").read_text())
        assert "claim_verification" not in report

    def test_claim_set_hash_auto_computed(self, tmp_path, tmp_keys, sample_receipts):
        """When claims are provided, claim_set_hash is computed from specs."""
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="check",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        pack = ProofPack(
            run_id="test_auto_hash",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        # claim_set_hash should be derived from the claims, not from "none"
        default_hash = hashlib.sha256(b"none").hexdigest()
        assert manifest["claim_set_hash"] != default_hash
        assert len(manifest["claim_set_hash"]) == 64

    def test_pack_with_claims_still_verifies(self, tmp_path, tmp_keys, sample_receipts):
        """Pack built with claims still passes pack_manifest verification."""
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="check",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        pack = ProofPack(
            run_id="test_verify_with_claims",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        result = verify_pack_manifest(manifest, out, tmp_keys)
        assert result.passed, f"Errors: {[e.to_dict() for e in result.errors]}"

    def test_discrepancy_fingerprint_in_attestation(
        self, tmp_path, tmp_keys, sample_receipts
    ):
        """discrepancy_fingerprint flows into attestation when claims exist."""
        claims = [
            ClaimSpec(
                claim_id="c1",
                description="check",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        pack = ProofPack(
            run_id="test_fp_attestation",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims,
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        fp = manifest["attestation"]["discrepancy_fingerprint"]
        assert fp is not None
        assert len(fp) == 64


# ---------------------------------------------------------------------------
# B4: Orthogonal axes demo (P1/P2 proof)
# ---------------------------------------------------------------------------


class TestOrthogonalAxes:
    """B4: Same receipts, different claim sets prove P1/P2 contract.

    This is the external proof that integrity and claims are orthogonal:
    - Pack A: integrity=PASS, claims=PASS (lenient claim set)
    - Pack B: integrity=PASS, claims=FAIL (strict claim set)
    Both built from identical receipts with identical integrity.
    """

    def test_same_integrity_different_claims(self, tmp_path, tmp_keys, sample_receipts):
        """Core P1 proof: identical receipts, opposite claim outcomes."""
        # Claim set A: passes (just needs >= 1 receipt)
        claims_pass = [
            ClaimSpec(
                claim_id="lenient",
                description="at least 1 receipt",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        # Claim set B: fails (demands guardian_verdict receipts that don't exist)
        claims_fail = [
            ClaimSpec(
                claim_id="strict",
                description="guardian_verdict required",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="critical",
            ),
        ]

        # Build both packs from identical receipts
        pack_a = ProofPack(
            run_id="test_ortho_a",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims_pass,
        )
        pack_b = ProofPack(
            run_id="test_ortho_b",
            entries=sample_receipts,
            signer_id="test-signer",
            claims=claims_fail,
        )

        out_a = pack_a.build(tmp_path / "pack_a", keystore=tmp_keys)
        out_b = pack_b.build(tmp_path / "pack_b", keystore=tmp_keys)

        manifest_a = json.loads((out_a / "pack_manifest.json").read_text())
        manifest_b = json.loads((out_b / "pack_manifest.json").read_text())

        att_a = manifest_a["attestation"]
        att_b = manifest_b["attestation"]

        # P1: Both have PASS integrity (same receipts)
        assert att_a["receipt_integrity"] == "PASS"
        assert att_b["receipt_integrity"] == "PASS"

        # P1: Different claim outcomes (different claim sets)
        assert att_a["claim_check"] == "PASS"
        assert att_b["claim_check"] == "FAIL"

        # P2: Claims cannot upgrade integrity -- even with claim_check=PASS,
        # integrity remains the same as claim_check=FAIL
        assert att_a["receipt_integrity"] == att_b["receipt_integrity"]

        # Fingerprints differ (different claim sets = different fingerprints)
        assert att_a["discrepancy_fingerprint"] != att_b["discrepancy_fingerprint"]

    def test_both_packs_verify_independently(self, tmp_path, tmp_keys, sample_receipts):
        """Both the pass and fail packs verify as structurally sound."""
        claims_pass = [
            ClaimSpec(
                claim_id="lenient",
                description="at least 1 receipt",
                check="receipt_count_ge",
                params={"min_count": 1},
            ),
        ]
        claims_fail = [
            ClaimSpec(
                claim_id="strict",
                description="need 1000",
                check="receipt_count_ge",
                params={"min_count": 1000},
                severity="critical",
            ),
        ]

        for label, claims in [("pass", claims_pass), ("fail", claims_fail)]:
            pack = ProofPack(
                run_id=f"test_verify_{label}",
                entries=sample_receipts,
                signer_id="test-signer",
                claims=claims,
            )
            out = pack.build(tmp_path / f"pack_{label}", keystore=tmp_keys)
            manifest = json.loads((out / "pack_manifest.json").read_text())
            result = verify_pack_manifest(manifest, out, tmp_keys)
            assert result.passed, (
                f"Pack {label} failed verification: "
                f"{[e.to_dict() for e in result.errors]}"
            )


# ---------------------------------------------------------------------------
# B14: Runtime schema enforcement
# ---------------------------------------------------------------------------


class TestSchemaEnforcement:
    """Manifest schema validation catches structural errors."""

    def test_valid_manifest_passes(self, tmp_path, tmp_keys, sample_receipts):
        """A properly built manifest passes schema validation."""
        from assay.manifest_schema import validate_manifest

        pack = ProofPack(
            run_id="test_schema_valid",
            entries=sample_receipts,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=tmp_keys)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        errors = validate_manifest(manifest)
        assert errors == [], f"Unexpected schema errors: {errors}"

    def test_missing_required_field_caught(self):
        """Missing required field is detected."""
        from assay.manifest_schema import validate_manifest

        # Minimal invalid manifest (missing almost everything)
        errors = validate_manifest({"pack_id": "test"})
        assert len(errors) > 0
        # Should flag multiple missing required fields
        assert any("required" in e.lower() for e in errors)

    def test_invalid_hash_pattern_caught(self):
        """Invalid hash format is detected."""
        from assay.manifest_schema import validate_attestation

        # attestation_sha256 with wrong length
        errors = validate_attestation({
            "pack_id": "test",
            "run_id": "test",
            "suite_id": "test",
            "suite_hash": "not-a-valid-hash",  # should be 64 hex chars
            "verifier_version": "0.1.0",
            "canon_version": "jcs-rfc8785",
            "canon_impl": "receipts.jcs",
            "canon_impl_version": "0.1.0",
            "policy_hash": "a" * 64,
            "claim_set_id": "none",
            "claim_set_hash": "b" * 64,
            "receipt_integrity": "PASS",
            "claim_check": "N/A",
            "assurance_level": "L0",
            "proof_tier": "signed-pack",
            "mode": "shadow",
            "head_hash": "c" * 64,
            "head_hash_algorithm": "last-receipt-digest-v0",
            "time_authority": "local_clock",
            "n_receipts": 0,
            "timestamp_start": "2026-01-01T00:00:00+00:00",
            "timestamp_end": "2026-01-01T00:00:00+00:00",
        })
        assert len(errors) > 0
        assert any("suite_hash" in e for e in errors)

    def test_invalid_enum_caught(self):
        """Invalid enum value (e.g., mode='invalid') is detected."""
        from assay.manifest_schema import validate_attestation

        errors = validate_attestation({
            "pack_id": "test",
            "run_id": "test",
            "suite_id": "test",
            "suite_hash": "a" * 64,
            "verifier_version": "0.1.0",
            "canon_version": "jcs-rfc8785",
            "canon_impl": "receipts.jcs",
            "canon_impl_version": "0.1.0",
            "policy_hash": "a" * 64,
            "claim_set_id": "none",
            "claim_set_hash": "b" * 64,
            "receipt_integrity": "PASS",
            "claim_check": "MAYBE",  # invalid enum
            "assurance_level": "L0",
            "proof_tier": "signed-pack",
            "mode": "yolo",  # invalid enum
            "head_hash": "c" * 64,
            "head_hash_algorithm": "last-receipt-digest-v0",
            "time_authority": "local_clock",
            "n_receipts": 0,
            "timestamp_start": "2026-01-01T00:00:00+00:00",
            "timestamp_end": "2026-01-01T00:00:00+00:00",
        })
        assert len(errors) >= 2
        assert any("claim_check" in e for e in errors)
        assert any("mode" in e for e in errors)

    def test_missing_schemas_raises(self, monkeypatch):
        """Validation fails closed when schema files are missing."""
        import assay.manifest_schema as ms
        from pathlib import Path

        # Point to a nonexistent directory
        monkeypatch.setattr(ms, "_SCHEMA_DIR", Path("/nonexistent/schemas"))
        # Clear cached validators so they're reloaded
        monkeypatch.setattr(ms, "_manifest_validator", None)
        monkeypatch.setattr(ms, "_attestation_validator", None)

        import pytest
        with pytest.raises(FileNotFoundError, match="Schema files not found"):
            ms.validate_manifest({"pack_id": "test"})

        with pytest.raises(FileNotFoundError, match="Schema files not found"):
            ms.validate_attestation({"pack_id": "test"})
