"""Tests for ReceiptV2 signing path — emit_v2_receipt(), default_v2_policy(),
build_v2_base_receipt().

Test categories:
  - Round-trip: emit then verify_v2 produces operational_valid=True
  - Tamper detection: mutating any attested field breaks digest
  - Digest determinism: same base + same key = same bundle_digest
  - Ed25519 signature determinism (algorithm-specific, not normative invariant)
  - Excluded-field non-attestation: excluded fields don't affect digest
  - Mint contract: hard reject on preexisting signatures[] / verification_bundle
  - Receipt structure: covers accuracy, bundle shape, sig entry fields
  - Helper functions: default_v2_policy(), build_v2_base_receipt()
  - Error cases: missing type, unknown projection_id
"""
from __future__ import annotations

import base64
import hashlib
import pytest

from assay._receipts.canonicalize import PROJECTION_DOCTRINE, PROJECTION_EXCLUSIONS
from assay._receipts.v2_sign import (
    emit_v2_receipt,
    default_v2_policy,
    build_v2_base_receipt,
)
from assay._receipts.v2_verify import verify_v2


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sk():
    """A deterministic Ed25519 signing key for tests."""
    from nacl.signing import SigningKey
    return SigningKey(b"\x01" * 32)   # 32-byte seed, deterministic


@pytest.fixture(scope="module")
def key_resolver(sk):
    """Key resolver that trusts only the test signing key."""
    pubkey = sk.verify_key.encode()
    def _resolver(_signer_id, pubkey_sha256):
        expected_fp = hashlib.sha256(pubkey).hexdigest()
        if pubkey_sha256 == expected_fp:
            return pubkey
        return None
    return _resolver


@pytest.fixture
def base_receipt():
    """Minimal valid base receipt for testing."""
    return {
        "receipt_id": "r-test-001",
        "type": "test_receipt",
        "timestamp": "2026-01-01T00:00:00Z",
        "payload": {"key": "value"},
        "verification_profile": "operational-v1",
        "verification_policy": default_v2_policy("operational-v1"),
    }


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_emit_then_verify_passes(self, sk, key_resolver, base_receipt):
        """Core round-trip: emit a signed receipt and verify it cleanly."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="test-signer", add_signed_at=False
        )
        result = verify_v2(receipt, key_resolver=key_resolver)

        assert result.digest_valid is True
        assert result.digest_status == "matched"
        assert result.operational_valid is True
        assert result.policy_satisfied is True
        assert len(result.signature_results) == 1
        assert result.signature_results[0].status == "valid"
        assert result.signature_results[0].cryptographically_valid is True
        assert result.signature_results[0].trusted_signer is True

    def test_archival_valid_is_none_for_operational_receipt(self, sk, key_resolver, base_receipt):
        """No PQ sig present → archival_valid=None (not assessed, not False)."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="test-signer", add_signed_at=False
        )
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.archival_valid is None

    def test_distinct_signer_ids_populated(self, sk, key_resolver, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="test-signer", add_signed_at=False
        )
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert "test-signer" in result.distinct_signer_ids

    def test_custom_payload_preserved(self, sk, key_resolver):
        base = build_v2_base_receipt(
            "custom_type",
            payload={"nested": {"deep": 42}, "list": [1, 2, 3]},
        )
        receipt = emit_v2_receipt(
            base, signing_key=sk, signer_id="test-signer", add_signed_at=False
        )
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True
        assert receipt["payload"] == {"nested": {"deep": 42}, "list": [1, 2, 3]}


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TestTamperDetection:
    """Mutating any attested field must break digest_valid."""

    def test_tamper_payload_breaks_digest(self, sk, key_resolver, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        tampered = dict(receipt)
        tampered["payload"] = {"key": "TAMPERED"}
        result = verify_v2(tampered, key_resolver=key_resolver)
        assert result.digest_valid is False
        assert result.digest_status == "mismatch"
        assert result.operational_valid is False

    def test_tamper_type_breaks_digest(self, sk, key_resolver, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        tampered = dict(receipt)
        tampered["type"] = "tampered_type"
        result = verify_v2(tampered, key_resolver=key_resolver)
        assert result.digest_valid is False

    def test_tamper_receipt_id_breaks_digest(self, sk, key_resolver, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        tampered = dict(receipt)
        tampered["receipt_id"] = "tampered-id"
        result = verify_v2(tampered, key_resolver=key_resolver)
        assert result.digest_valid is False

    def test_tamper_verification_profile_breaks_digest(self, sk, key_resolver, base_receipt):
        """verification_profile is attested — tampering it breaks digest."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        tampered = dict(receipt)
        tampered["verification_profile"] = "archival-v1"
        result = verify_v2(tampered, key_resolver=key_resolver)
        assert result.digest_valid is False

    def test_tamper_verification_policy_breaks_digest(self, sk, key_resolver, base_receipt):
        """verification_policy is attested — tampering it breaks digest."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        tampered = dict(receipt)
        tampered["verification_policy"] = {
            "schema_version": "1",
            "operational_requires": {"min_signatures": 99, "algorithms": ["ed25519"]},
        }
        result = verify_v2(tampered, key_resolver=key_resolver)
        assert result.digest_valid is False

    def test_tamper_bundle_digest_breaks_verification(self, sk, key_resolver, base_receipt):
        """Mutating stored bundle_digest is caught by recomputation."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        tampered = dict(receipt)
        tampered["verification_bundle"] = dict(receipt["verification_bundle"])
        tampered["verification_bundle"]["bundle_digest"] = "sha256:deadbeef"
        result = verify_v2(tampered, key_resolver=key_resolver)
        assert result.digest_valid is False
        assert result.digest_status == "mismatch"


# ---------------------------------------------------------------------------
# Digest determinism
# ---------------------------------------------------------------------------

class TestDigestDeterminism:
    """Normative invariant: same attested base + same projection = same digest."""

    def test_digest_is_deterministic(self, sk, base_receipt):
        r1 = emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r1["verification_bundle"]["bundle_digest"]
            == r2["verification_bundle"]["bundle_digest"]
        )

    def test_ed25519_signature_is_deterministic(self, sk, base_receipt):
        """Ed25519-specific: same key + same message = same signature bytes."""
        r1 = emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s", add_signed_at=False)
        assert r1["signatures"][0]["value"] == r2["signatures"][0]["value"]

    def test_different_payload_changes_digest(self, sk):
        b1 = build_v2_base_receipt("t", payload={"x": 1})
        b2 = build_v2_base_receipt("t", payload={"x": 2})
        # Pin receipt_id and timestamp so only payload differs
        b1["receipt_id"] = b2["receipt_id"] = "fixed-id"
        b1["timestamp"] = b2["timestamp"] = "2026-01-01T00:00:00Z"
        r1 = emit_v2_receipt(b1, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(b2, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r1["verification_bundle"]["bundle_digest"]
            != r2["verification_bundle"]["bundle_digest"]
        )


# ---------------------------------------------------------------------------
# Excluded-field non-attestation (constitutional boundary test)
# ---------------------------------------------------------------------------

class TestExcludedFieldNonAttestation:
    """Excluded fields must not affect bundle_digest — proving the spec boundary."""

    def test_adding_signatures_does_not_change_digest(self, sk, base_receipt):
        """signatures[] is excluded — adding it to base_receipt has no effect on digest."""
        with_sigs = dict(base_receipt)
        with_sigs["signatures"] = []   # stripped by projection
        r1 = emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s", add_signed_at=False)
        # Note: non-empty signatures[] triggers the mint-guard, so test with empty list
        r2 = emit_v2_receipt(with_sigs, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r1["verification_bundle"]["bundle_digest"]
            == r2["verification_bundle"]["bundle_digest"]
        )

    def test_adding_v1_flat_signer_id_does_not_change_digest(self, sk, base_receipt):
        """signer_id (deprecated v1 root field) is excluded — doesn't affect digest."""
        with_v1 = dict(base_receipt)
        with_v1["signer_id"] = "some-legacy-signer"
        with_v1["signer_pubkey_sha256"] = "some-legacy-fp"
        r_clean = emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s", add_signed_at=False)
        r_with_v1 = emit_v2_receipt(with_v1, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r_clean["verification_bundle"]["bundle_digest"]
            == r_with_v1["verification_bundle"]["bundle_digest"]
        )

    def test_adding_trust_anchors_does_not_change_digest(self, sk, key_resolver, base_receipt):
        """trust_anchors is excluded — two receipts with/without trust_anchors have same digest."""
        r_without = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        r_with = emit_v2_receipt(
            base_receipt,
            signing_key=sk,
            signer_id="s",
            trust_anchors=[{"id": "reg", "type": "registry"}],
            add_signed_at=False,
        )
        assert (
            r_without["verification_bundle"]["bundle_digest"]
            == r_with["verification_bundle"]["bundle_digest"]
        )
        # Both still verify
        assert verify_v2(r_without, key_resolver=key_resolver).operational_valid is True
        assert verify_v2(r_with, key_resolver=key_resolver).operational_valid is True

    def test_custom_attested_field_changes_digest(self, sk):
        """Custom non-excluded field IS attested — changing it changes digest."""
        b1 = build_v2_base_receipt("t", extra_field="value-A")
        b2 = build_v2_base_receipt("t", extra_field="value-B")
        b1["receipt_id"] = b2["receipt_id"] = "fixed-id"
        b1["timestamp"] = b2["timestamp"] = "2026-01-01T00:00:00Z"
        r1 = emit_v2_receipt(b1, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(b2, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r1["verification_bundle"]["bundle_digest"]
            != r2["verification_bundle"]["bundle_digest"]
        )

    def test_custom_attested_field_appears_in_covers(self, sk):
        """Custom non-excluded field appears in covers (the explanatory list)."""
        base = build_v2_base_receipt("t", extra_field="v")
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        assert "extra_field" in receipt["verification_bundle"]["covers"]


# ---------------------------------------------------------------------------
# Mint contract (hard reject)
# ---------------------------------------------------------------------------

class TestMintContract:
    def test_rejects_nonempty_signatures(self, sk, base_receipt):
        """emit_v2_receipt must reject base_receipt with existing signatures[]."""
        bad = dict(base_receipt)
        bad["signatures"] = [{"algorithm": "ed25519", "signer_id": "x", "value": "abc"}]
        with pytest.raises(ValueError, match="mint operation"):
            emit_v2_receipt(bad, signing_key=sk, signer_id="s")

    def test_rejects_existing_verification_bundle(self, sk, base_receipt):
        """emit_v2_receipt must reject base_receipt with existing verification_bundle."""
        bad = dict(base_receipt)
        bad["verification_bundle"] = {"bundle_digest": "sha256:abc", "bundle_algorithm": "sha256"}
        with pytest.raises(ValueError, match="mint operation"):
            emit_v2_receipt(bad, signing_key=sk, signer_id="s")

    def test_empty_signatures_list_is_allowed(self, sk, base_receipt):
        """Empty signatures=[] in base_receipt is allowed (treated as absent)."""
        with_empty = dict(base_receipt)
        with_empty["signatures"] = []
        # Should not raise
        receipt = emit_v2_receipt(with_empty, signing_key=sk, signer_id="s", add_signed_at=False)
        assert len(receipt["signatures"]) == 1

    def test_rejects_missing_type(self, sk):
        """base_receipt without 'type' must raise ValueError."""
        bad = {
            "receipt_id": "r1",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {},
        }
        with pytest.raises(ValueError, match='"type"'):
            emit_v2_receipt(bad, signing_key=sk, signer_id="s")

    def test_rejects_empty_type(self, sk):
        bad = {
            "receipt_id": "r1",
            "type": "",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {},
        }
        with pytest.raises(ValueError, match='"type"'):
            emit_v2_receipt(bad, signing_key=sk, signer_id="s")

    def test_rejects_unknown_projection_id(self, sk, base_receipt):
        with pytest.raises(ValueError, match="Unknown projection_id"):
            emit_v2_receipt(
                base_receipt, signing_key=sk, signer_id="s",
                projection_id="receipt-nonexistent-v99"
            )


# ---------------------------------------------------------------------------
# Receipt structure
# ---------------------------------------------------------------------------

class TestReceiptStructure:
    def test_verification_bundle_shape(self, sk, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        bundle = receipt["verification_bundle"]
        assert bundle["projection_id"] == "receipt-core-v2"
        assert bundle["bundle_digest"].startswith("sha256:")
        assert bundle["bundle_algorithm"] == "sha256"
        assert bundle["canonicalization"] == "jcs-rfc8785"
        assert isinstance(bundle["covers"], list)
        assert len(bundle["covers"]) > 0

    def test_covers_contains_attested_fields(self, sk, base_receipt):
        """covers must include all attested fields."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        covers = receipt["verification_bundle"]["covers"]
        for field in ["receipt_id", "type", "timestamp", "payload",
                      "verification_profile", "verification_policy"]:
            assert field in covers, f"Expected attested field {field!r} in covers"

    def test_covers_does_not_contain_excluded_fields(self, sk, base_receipt):
        """covers must not list excluded fields."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        covers = receipt["verification_bundle"]["covers"]
        excluded = [
            "verification_bundle", "signatures", "trust_anchors",
            "signature", "signer_pubkey_sha256",
        ]
        for field in excluded:
            assert field not in covers, f"Excluded field {field!r} must not be in covers"

    def test_sig_entry_shape(self, sk, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="test-signer", add_signed_at=False
        )
        sig = receipt["signatures"][0]
        assert sig["algorithm"] == "ed25519"
        assert sig["signer_id"] == "test-signer"
        assert isinstance(sig["signer_pubkey_sha256"], str) and len(sig["signer_pubkey_sha256"]) == 64
        # value is valid base64
        decoded = base64.b64decode(sig["value"])
        assert len(decoded) == 64   # Ed25519 signature is 64 bytes
        # signed_at absent when add_signed_at=False
        assert "signed_at" not in sig

    def test_sig_entry_has_signed_at_when_requested(self, sk, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=True
        )
        assert "signed_at" in receipt["signatures"][0]
        assert receipt["signatures"][0]["signed_at"].endswith("Z")

    def test_trust_anchors_attached_when_provided(self, sk, base_receipt):
        anchors = [{"id": "registry-1", "type": "registry", "registry_file": "signers.json"}]
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s",
            trust_anchors=anchors, add_signed_at=False,
        )
        assert receipt["trust_anchors"] == anchors

    def test_trust_anchors_absent_when_not_provided(self, sk, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        assert "trust_anchors" not in receipt

    def test_base_fields_preserved(self, sk, base_receipt):
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        for key in ["receipt_id", "type", "timestamp", "payload",
                    "verification_profile", "verification_policy"]:
            assert receipt[key] == base_receipt[key]

    def test_pubkey_fingerprint_matches_key(self, sk, base_receipt):
        """signer_pubkey_sha256 must be sha256 of the actual verify key bytes."""
        expected_fp = hashlib.sha256(sk.verify_key.encode()).hexdigest()
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        assert receipt["signatures"][0]["signer_pubkey_sha256"] == expected_fp


# ---------------------------------------------------------------------------
# default_v2_policy()
# ---------------------------------------------------------------------------

class TestDefaultV2Policy:
    def test_operational_v1_shape(self):
        p = default_v2_policy("operational-v1")
        assert p["schema_version"] == "1"
        assert p["operational_requires"]["min_signatures"] == 1
        assert "ed25519" in p["operational_requires"]["algorithms"]
        assert "archival_requires" not in p

    def test_archival_v1_shape(self):
        p = default_v2_policy("archival-v1")
        assert "operational_requires" in p
        assert "archival_requires" in p
        assert any(a.startswith("ml-dsa") for a in p["archival_requires"]["algorithms"])

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            default_v2_policy("nonexistent-profile")

    def test_default_matches_operational_v1(self):
        assert default_v2_policy() == default_v2_policy("operational-v1")


# ---------------------------------------------------------------------------
# build_v2_base_receipt()
# ---------------------------------------------------------------------------

class TestBuildV2BaseReceipt:
    def test_required_fields_present(self):
        base = build_v2_base_receipt("test_type")
        for f in ["receipt_id", "type", "timestamp", "payload",
                  "verification_profile", "verification_policy"]:
            assert f in base

    def test_type_set_correctly(self):
        base = build_v2_base_receipt("my_event")
        assert base["type"] == "my_event"

    def test_payload_defaults_to_empty_dict(self):
        base = build_v2_base_receipt("t")
        assert base["payload"] == {}

    def test_explicit_payload_preserved(self):
        base = build_v2_base_receipt("t", {"x": 1})
        assert base["payload"] == {"x": 1}

    def test_explicit_receipt_id_used(self):
        base = build_v2_base_receipt("t", receipt_id="fixed-r1")
        assert base["receipt_id"] == "fixed-r1"

    def test_auto_receipt_id_starts_with_prefix(self):
        base = build_v2_base_receipt("t")
        assert base["receipt_id"].startswith("rcpt-")

    def test_explicit_timestamp_used(self):
        base = build_v2_base_receipt("t", timestamp="2025-06-01T12:00:00Z")
        assert base["timestamp"] == "2025-06-01T12:00:00Z"

    def test_auto_timestamp_is_iso8601(self):
        import re
        base = build_v2_base_receipt("t")
        # Rough ISO 8601 UTC check
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", base["timestamp"])

    def test_default_profile_is_operational(self):
        base = build_v2_base_receipt("t")
        assert base["verification_profile"] == "operational-v1"

    def test_explicit_profile_used(self):
        base = build_v2_base_receipt("t", verification_profile="archival-v1")
        assert base["verification_profile"] == "archival-v1"

    def test_default_policy_derived_from_profile(self):
        base = build_v2_base_receipt("t")
        assert base["verification_policy"] == default_v2_policy("operational-v1")

    def test_explicit_policy_overrides_default(self):
        custom = {"schema_version": "1", "operational_requires": {"min_signatures": 2, "algorithms": ["ed25519"]}}
        base = build_v2_base_receipt("t", verification_policy=custom)
        assert base["verification_policy"] == custom

    def test_extra_attested_fields_included(self):
        base = build_v2_base_receipt("t", custom_field="hello", another=42)
        assert base["custom_field"] == "hello"
        assert base["another"] == 42

    def test_missing_type_raises(self):
        with pytest.raises((ValueError, TypeError)):
            build_v2_base_receipt("")

    def test_helper_produces_mintable_receipt(self, sk, key_resolver):
        """Round-trip: helper-built base → emit → verify passes."""
        base = build_v2_base_receipt(
            "helper_test",
            payload={"from": "helper"},
            receipt_id="helper-r1",
            timestamp="2026-01-01T00:00:00Z",
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True


# ---------------------------------------------------------------------------
# Projection Doctrine lock
# ---------------------------------------------------------------------------

class TestProjectionDoctrine:
    """PROJECTION_DOCTRINE is the machine-readable constitutional statement.
    These tests confirm the constant is present, structurally sound, and
    consistent with what the live code actually does.
    """

    def test_doctrine_exported(self):
        assert PROJECTION_DOCTRINE is not None
        assert isinstance(PROJECTION_DOCTRINE, dict)

    def test_doctrine_names_correct_projection(self):
        assert PROJECTION_DOCTRINE["projection_id"] == "receipt-core-v2"

    def test_doctrine_attested_fields_match_live_projection(self, sk):
        """Standard attested fields listed in PROJECTION_DOCTRINE must actually
        appear in the canonical projection of a standard receipt."""
        base = build_v2_base_receipt(
            "t", receipt_id="r1", timestamp="2026-01-01T00:00:00Z"
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        actual_covers = set(receipt["verification_bundle"]["covers"])
        for field in PROJECTION_DOCTRINE["attested"]["standard_fields"]:
            assert field in actual_covers, (
                f"PROJECTION_DOCTRINE lists {field!r} as attested, "
                f"but it is not in live covers: {actual_covers}"
            )

    def test_doctrine_excluded_fields_absent_from_live_projection(self, sk):
        """Every field listed in PROJECTION_DOCTRINE['excluded']['fields'] must
        NOT appear in covers, even if present in the base receipt."""
        base = build_v2_base_receipt("t", receipt_id="r1", timestamp="2026-01-01T00:00:00Z")
        # Inject excluded fields into base (they'll be stripped)
        for field in PROJECTION_DOCTRINE["excluded"]["fields"]:
            base[field] = "injected-value"
        # Remove signatures / verification_bundle injections to avoid mint guard
        base.pop("signatures", None)
        base.pop("verification_bundle", None)

        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        covers = set(receipt["verification_bundle"]["covers"])
        for field in PROJECTION_DOCTRINE["excluded"]["fields"]:
            assert field not in covers, (
                f"PROJECTION_DOCTRINE lists {field!r} as excluded, "
                f"but it appears in live covers: {covers}"
            )

    def test_doctrine_mint_rejection_rules_are_enforced(self, sk, base_receipt):
        """Spot-check: each mint rejection rule in PROJECTION_DOCTRINE is actually enforced."""
        # Rule 1: non-empty signatures[]
        bad1 = dict(base_receipt)
        bad1["signatures"] = [{"algorithm": "ed25519", "signer_id": "x", "value": "a"}]
        with pytest.raises(ValueError):
            emit_v2_receipt(bad1, signing_key=sk, signer_id="s")

        # Rule 2: existing verification_bundle
        bad2 = dict(base_receipt)
        bad2["verification_bundle"] = {"bundle_digest": "sha256:abc"}
        with pytest.raises(ValueError):
            emit_v2_receipt(bad2, signing_key=sk, signer_id="s")

        # Rule 3: missing type
        bad3 = {k: v for k, v in base_receipt.items() if k != "type"}
        with pytest.raises(ValueError):
            emit_v2_receipt(bad3, signing_key=sk, signer_id="s")

        # Rule 4: unknown projection_id
        with pytest.raises(ValueError):
            emit_v2_receipt(base_receipt, signing_key=sk, signer_id="s",
                            projection_id="fake-v99")

    def test_helper_status_labels_are_present(self):
        """Helper functions must be marked ERGONOMIC ONLY in the doctrine."""
        for fn in ["build_v2_base_receipt", "default_v2_policy"]:
            label = PROJECTION_DOCTRINE["helper_status"].get(fn, "")
            assert "ERGONOMIC" in label, (
                f"{fn} is missing ERGONOMIC ONLY label in PROJECTION_DOCTRINE"
            )

    def test_doctrine_lives_in_canonicalize(self):
        """PROJECTION_DOCTRINE must be importable from canonicalize — its
        authoritative home — not only from v2_sign. This ensures co-location
        with the projection code it describes."""
        from assay._receipts.canonicalize import PROJECTION_DOCTRINE as canon_doctrine
        from assay._receipts.v2_sign import PROJECTION_DOCTRINE as sign_doctrine
        assert canon_doctrine is sign_doctrine, (
            "PROJECTION_DOCTRINE in v2_sign must be the same object as in canonicalize. "
            "If they diverge, the re-export is broken."
        )

    # --- Completeness invariant ---

    def test_doctrine_excluded_fields_match_live_exclusion_set(self):
        """COMPLETENESS INVARIANT: the doctrine's excluded field list must
        exactly equal the live _V2_PROJECTION_EXCLUSIONS frozenset in code.

        If someone adds a field to the exclusion set without updating the
        doctrine (or vice versa), this test fails with a clear diff.
        This is the 'no silent category' guard.
        """
        code_exclusions = PROJECTION_EXCLUSIONS["receipt-core-v2"]
        doctrine_exclusions = set(PROJECTION_DOCTRINE["excluded"]["fields"])
        in_code_not_doctrine = code_exclusions - doctrine_exclusions
        in_doctrine_not_code = doctrine_exclusions - code_exclusions
        assert not in_code_not_doctrine and not in_doctrine_not_code, (
            f"Doctrine/code exclusion drift detected.\n"
            f"  In code but not doctrine: {sorted(in_code_not_doctrine)}\n"
            f"  In doctrine but not code: {sorted(in_doctrine_not_code)}\n"
            "Fix: update PROJECTION_DOCTRINE['excluded']['fields'] in canonicalize.py "
            "to match _V2_PROJECTION_EXCLUSIONS, or vice versa."
        )

    def test_no_field_in_both_attested_and_excluded(self):
        """No field may appear in both the standard attested list and the
        excluded list — that would be a doctrine contradiction."""
        attested = set(PROJECTION_DOCTRINE["attested"]["standard_fields"])
        excluded = set(PROJECTION_DOCTRINE["excluded"]["fields"])
        overlap = attested & excluded
        assert not overlap, (
            f"Fields appear in both attested and excluded: {sorted(overlap)}. "
            "A field cannot be both attested law and operational metadata."
        )

    # --- Covers ordering ---

    def test_covers_is_sorted_alphabetically(self, sk, base_receipt):
        """covers must be in sorted order — deterministic for human review
        and diff stability. Cryptographically irrelevant but operationally
        important for receipt readability."""
        receipt = emit_v2_receipt(
            base_receipt, signing_key=sk, signer_id="s", add_signed_at=False
        )
        covers = receipt["verification_bundle"]["covers"]
        assert covers == sorted(covers), (
            f"covers is not sorted. Got: {covers}, expected: {sorted(covers)}"
        )

    def test_covers_order_stable_regardless_of_base_dict_insertion_order(self, sk):
        """covers ordering must be deterministic regardless of base_receipt
        key insertion order — the sort happens on the projected keys, not
        on the input dict."""
        fields = {
            "receipt_id": "r1",
            "type": "t",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {},
            "verification_profile": "operational-v1",
            "verification_policy": default_v2_policy(),
        }
        forward = dict(fields)
        backward = {k: fields[k] for k in reversed(list(fields.keys()))}
        r_fwd = emit_v2_receipt(forward, signing_key=sk, signer_id="s", add_signed_at=False)
        r_bwd = emit_v2_receipt(backward, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r_fwd["verification_bundle"]["covers"]
            == r_bwd["verification_bundle"]["covers"]
        ), "covers must be in the same sorted order regardless of dict insertion order"

    def test_doctrine_covers_order_policy_is_documented(self):
        """PROJECTION_DOCTRINE must explicitly state the covers ordering policy."""
        policy = PROJECTION_DOCTRINE.get("covers_order", "")
        assert "sort" in policy.lower(), (
            "PROJECTION_DOCTRINE must document the covers ordering policy (sorted). "
            f"Got: {policy!r}"
        )


# ---------------------------------------------------------------------------
# Adversarial projection boundary tests
# ---------------------------------------------------------------------------

class TestAdversarialProjection:
    """Future-proof stress tests for the projection boundary.

    These tests probe edge cases that could silently corrupt the constitutional
    seam if the projection or canonicalization logic drifts:
      - Nested custom fields
      - Dict key ordering / insertion order noise
      - None vs absent semantics
      - Unicode and non-ASCII in values and keys
      - Duplicate semantic content in excluded vs included paths
      - Large / deeply nested payloads
    """

    # --- Nested custom fields ---

    def test_nested_custom_field_is_attested(self, sk, key_resolver):
        """Deeply nested custom fields are attested — changing them changes digest."""
        b1 = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
            meta={"source": {"system": "A", "version": 1}},
        )
        b2 = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
            meta={"source": {"system": "A", "version": 2}},   # version differs
        )
        r1 = emit_v2_receipt(b1, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(b2, signing_key=sk, signer_id="s", add_signed_at=False)
        assert r1["verification_bundle"]["bundle_digest"] != r2["verification_bundle"]["bundle_digest"]

    def test_nested_custom_field_round_trips(self, sk, key_resolver):
        """Nested custom field survives emit→verify."""
        base = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
            evidence={"items": [{"id": 1, "score": 0.9}, {"id": 2, "score": 0.5}]},
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True

    def test_array_in_payload_is_attested(self, sk):
        """Arrays in payload are attested — element order change changes digest."""
        b1 = build_v2_base_receipt("t",
            payload={"items": [1, 2, 3]},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        b2 = build_v2_base_receipt("t",
            payload={"items": [3, 2, 1]},   # order reversed
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        r1 = emit_v2_receipt(b1, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(b2, signing_key=sk, signer_id="s", add_signed_at=False)
        assert r1["verification_bundle"]["bundle_digest"] != r2["verification_bundle"]["bundle_digest"]

    # --- Key ordering / insertion order noise ---

    def test_digest_stable_across_dict_insertion_order(self, sk):
        """JCS canonicalization must produce the same bytes regardless of key
        insertion order in the base receipt dict."""
        fields = {
            "receipt_id": "r1",
            "type": "t",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {"z": 1, "a": 2},
            "verification_profile": "operational-v1",
            "verification_policy": default_v2_policy(),
        }
        # Build same receipt with different key insertion orders
        order1 = dict(fields)
        order2 = {k: fields[k] for k in reversed(list(fields.keys()))}
        r1 = emit_v2_receipt(order1, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(order2, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r1["verification_bundle"]["bundle_digest"]
            == r2["verification_bundle"]["bundle_digest"]
        ), "Digest must not depend on dict key insertion order"

    def test_payload_key_order_is_normalized(self, sk):
        """JCS sorts object keys — payload with different key orders must produce
        the same digest."""
        b1 = build_v2_base_receipt("t",
            payload={"b": 2, "a": 1},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        b2 = build_v2_base_receipt("t",
            payload={"a": 1, "b": 2},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        r1 = emit_v2_receipt(b1, signing_key=sk, signer_id="s", add_signed_at=False)
        r2 = emit_v2_receipt(b2, signing_key=sk, signer_id="s", add_signed_at=False)
        assert (
            r1["verification_bundle"]["bundle_digest"]
            == r2["verification_bundle"]["bundle_digest"]
        ), "JCS must normalize key order — digest must be same for reordered dicts"

    # --- None vs absent semantics ---

    def test_none_value_attested_differently_from_absent(self, sk):
        """A field present with value None is attested differently from absent.
        JCS serializes None as null; absent fields don't appear at all."""
        b_with_none = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
            optional_field=None,
        )
        b_without = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        r_none = emit_v2_receipt(b_with_none, signing_key=sk, signer_id="s", add_signed_at=False)
        r_absent = emit_v2_receipt(b_without, signing_key=sk, signer_id="s", add_signed_at=False)
        # None-valued field appears in covers; absent does not
        assert "optional_field" in r_none["verification_bundle"]["covers"]
        assert "optional_field" not in r_absent["verification_bundle"]["covers"]
        # Digests must differ
        assert (
            r_none["verification_bundle"]["bundle_digest"]
            != r_absent["verification_bundle"]["bundle_digest"]
        )

    def test_none_value_in_payload_preserved_and_attested(self, sk, key_resolver):
        """None values inside payload are serialized as JSON null and attested."""
        base = build_v2_base_receipt("t",
            payload={"present": "yes", "absent": None},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True
        assert receipt["payload"]["absent"] is None

    # --- Unicode and canonicalization ---

    def test_unicode_in_payload_values(self, sk, key_resolver):
        """Unicode strings in payload are attested and round-trip cleanly."""
        base = build_v2_base_receipt("t",
            payload={"greeting": "こんにちは", "emoji": "🔐", "arabic": "مرحبا"},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True

    def test_unicode_in_custom_field_key(self, sk, key_resolver):
        """Unicode field keys in the receipt are valid attested content."""
        base = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
            **{"résumé": "non-ascii key"},
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True
        assert "résumé" in receipt["verification_bundle"]["covers"]

    def test_unicode_normalization_stability(self, sk):
        """Same logical unicode string must produce the same digest regardless
        of NFC/NFD normalization form (JCS requires UTF-8, so the raw bytes
        matter — this test documents the behavior)."""
        import unicodedata
        original = "café"
        nfc = unicodedata.normalize("NFC", original)
        nfd = unicodedata.normalize("NFD", original)
        b_nfc = build_v2_base_receipt("t",
            payload={"word": nfc},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        b_nfd = build_v2_base_receipt("t",
            payload={"word": nfd},
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        r_nfc = emit_v2_receipt(b_nfc, signing_key=sk, signer_id="s", add_signed_at=False)
        r_nfd = emit_v2_receipt(b_nfd, signing_key=sk, signer_id="s", add_signed_at=False)
        # Document the behavior: NFC and NFD produce different byte sequences,
        # so they produce different digests. Callers must normalize before minting.
        if nfc != nfd:
            assert (
                r_nfc["verification_bundle"]["bundle_digest"]
                != r_nfd["verification_bundle"]["bundle_digest"]
            ), (
                "NFC and NFD forms have different byte sequences. "
                "If your digest is the same here, your JCS is silently normalizing — "
                "that is a canonicalization drift risk."
            )

    # --- Duplicate semantic content in excluded vs included paths ---

    def test_same_signer_id_in_excluded_and_signatures_not_double_attested(self, sk):
        """signer_id at receipt root (excluded) and in signatures[] (excluded)
        must not affect bundle_digest — neither path is attested."""
        base_clean = build_v2_base_receipt("t",
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        base_with_v1 = dict(base_clean)
        base_with_v1["signer_id"] = "ghost-signer"
        base_with_v1["signature"] = "ghost-sig"

        r_clean = emit_v2_receipt(base_clean, signing_key=sk, signer_id="real-signer", add_signed_at=False)
        r_ghost = emit_v2_receipt(base_with_v1, signing_key=sk, signer_id="real-signer", add_signed_at=False)

        assert (
            r_clean["verification_bundle"]["bundle_digest"]
            == r_ghost["verification_bundle"]["bundle_digest"]
        ), "Excluded v1 root fields must not affect digest even when present"

    def test_covers_does_not_list_v1_ghost_fields(self, sk):
        """v1 root signature fields injected into base_receipt must not appear in covers."""
        base = dict(build_v2_base_receipt("t", receipt_id="r1", timestamp="2026-01-01T00:00:00Z"))
        base["signer_id"] = "ghost"
        base["signature"] = "ghost-sig"
        base["signer_pubkey_sha256"] = "ghost-fp"
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        covers = receipt["verification_bundle"]["covers"]
        for ghost in ["signer_id", "signature", "signer_pubkey_sha256"]:
            assert ghost not in covers, f"Ghost field {ghost!r} must not appear in covers"

    def test_payload_with_verification_bundle_shaped_content_is_attested(self, sk, key_resolver):
        """A payload that contains a dict shaped like verification_bundle is attested
        normally — the exclusion is field-level, not content-level."""
        base = build_v2_base_receipt("t",
            payload={
                "looks_like_bundle": {
                    "bundle_digest": "sha256:fake",
                    "bundle_algorithm": "sha256",
                    "canonicalization": "jcs-rfc8785",
                }
            },
            receipt_id="r1", timestamp="2026-01-01T00:00:00Z",
        )
        receipt = emit_v2_receipt(base, signing_key=sk, signer_id="s", add_signed_at=False)
        result = verify_v2(receipt, key_resolver=key_resolver)
        assert result.operational_valid is True, (
            "Payload content shaped like excluded fields must still be attested"
        )
