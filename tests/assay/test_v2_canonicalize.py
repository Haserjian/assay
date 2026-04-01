"""Tests for v2 canonical projection and bundle digest.

Covers:
  - canonical_projection(): correct field inclusion/exclusion for receipt-core-v2
  - compute_bundle_digest(): prefixed hex format, stable across excluded-field changes
  - parse_ijson_receipt(): duplicate-key rejection at parse boundary
  - Golden vectors: locked hashes from receipt_projection_vectors.json (v2 section)
"""
from __future__ import annotations

import hashlib
import json
import pytest

from assay._receipts.canonicalize import (
    canonical_projection,
    compute_bundle_digest,
    parse_ijson_receipt,
)
from assay._receipts.jcs import canonicalize as jcs_canonicalize


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_ATTESTED_RECEIPT = {
    "receipt_id": "r1",
    "type": "test",
    "timestamp": "2026-01-01T00:00:00Z",
    "payload": {"value": 42},
    "verification_profile": "operational-v1",
    "verification_policy": {
        "operational_requires": {"min_signatures": 1, "algorithms": ["ed25519"]}
    },
}

_FULL_V2_RECEIPT = {
    **_ATTESTED_RECEIPT,
    # All excluded fields — none of these should appear in the projection
    "verification_bundle": {
        "bundle_digest": "sha256:deadbeef",
        "bundle_algorithm": "sha256",
        "canonicalization": "jcs-rfc8785",
    },
    "signatures": [{"algorithm": "ed25519", "signer_id": "assay-ci", "value": "abc123"}],
    "trust_anchors": [{"id": "test-registry", "type": "registry"}],
    "signature": "legacy-sig",
    "signer_id": "legacy-signer",
    "signer_pubkey_sha256": "legacy-fp",
    "cose_signature": "legacy-cose",
    "receipt_hash": "legacy-hash",
    "anchor": {"legacy": True},
}

# Golden values computed from the canonical implementation and locked here.
# If these change, the projection rule has drifted — investigate before updating.
_GOLDEN_CANONICAL_UTF8 = (
    '{"payload":{"value":42},"receipt_id":"r1","timestamp":"2026-01-01T00:00:00Z",'
    '"type":"test","verification_policy":{"operational_requires":{"algorithms":["ed25519"],'
    '"min_signatures":1}},"verification_profile":"operational-v1"}'
)
_GOLDEN_SHA256 = "7e8128ab202e95a59df9a2925790a66ae6677368e731db643d88cb9e3e769b57"
_GOLDEN_BUNDLE_DIGEST = f"sha256:{_GOLDEN_SHA256}"


# ---------------------------------------------------------------------------
# canonical_projection — attested field set
# ---------------------------------------------------------------------------

class TestCanonicalProjectionAttestedFields:
    """Verify that attested fields are included in the projection."""

    def test_receipt_id_included(self):
        proj = canonical_projection(_ATTESTED_RECEIPT)
        assert proj["receipt_id"] == "r1"

    def test_type_included(self):
        proj = canonical_projection(_ATTESTED_RECEIPT)
        assert proj["type"] == "test"

    def test_timestamp_included(self):
        proj = canonical_projection(_ATTESTED_RECEIPT)
        assert proj["timestamp"] == "2026-01-01T00:00:00Z"

    def test_payload_included(self):
        proj = canonical_projection(_ATTESTED_RECEIPT)
        assert proj["payload"] == {"value": 42}

    def test_verification_profile_included(self):
        proj = canonical_projection(_ATTESTED_RECEIPT)
        assert proj["verification_profile"] == "operational-v1"

    def test_verification_policy_included(self):
        proj = canonical_projection(_ATTESTED_RECEIPT)
        assert "verification_policy" in proj
        assert proj["verification_policy"]["operational_requires"]["min_signatures"] == 1


# ---------------------------------------------------------------------------
# canonical_projection — excluded field set (receipt-core-v2)
# ---------------------------------------------------------------------------

class TestCanonicalProjectionExcludedFields:
    """Verify that all spec-excluded fields are absent from the projection."""

    def test_verification_bundle_excluded(self):
        assert "verification_bundle" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_signatures_excluded(self):
        assert "signatures" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_trust_anchors_excluded(self):
        assert "trust_anchors" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_signature_v1_root_excluded(self):
        assert "signature" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_signer_id_v1_root_excluded(self):
        # signer_id was included in v0 hashing — v2 explicitly excludes it
        assert "signer_id" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_signer_pubkey_sha256_excluded(self):
        assert "signer_pubkey_sha256" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_cose_signature_excluded(self):
        assert "cose_signature" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_receipt_hash_excluded(self):
        assert "receipt_hash" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_anchor_excluded(self):
        assert "anchor" not in canonical_projection(_FULL_V2_RECEIPT)

    def test_only_attested_keys_remain(self):
        """Projection of _FULL_V2_RECEIPT has exactly the same keys as _ATTESTED_RECEIPT."""
        proj = canonical_projection(_FULL_V2_RECEIPT)
        assert set(proj.keys()) == set(_ATTESTED_RECEIPT.keys())


# ---------------------------------------------------------------------------
# canonical_projection — cross-version: signer_id excluded in v2, was in v0
# ---------------------------------------------------------------------------

class TestCanonicalProjectionCrossVersion:
    """Verify v2-specific exclusion behavior that differs from v0."""

    def test_signer_id_exclusion_does_not_affect_digest(self):
        """Adding v1-style signer_id to a receipt must not change the v2 projection hash."""
        receipt_with_signer = {**_ATTESTED_RECEIPT, "signer_id": "some-signer"}
        proj_with = canonical_projection(receipt_with_signer)
        proj_without = canonical_projection(_ATTESTED_RECEIPT)
        assert proj_with == proj_without

    def test_verification_bundle_exclusion_does_not_affect_digest(self):
        """Changing verification_bundle must not change the projection."""
        r1 = {**_ATTESTED_RECEIPT, "verification_bundle": {"bundle_digest": "sha256:aaa"}}
        r2 = {**_ATTESTED_RECEIPT, "verification_bundle": {"bundle_digest": "sha256:bbb"}}
        assert canonical_projection(r1) == canonical_projection(r2)

    def test_changing_attested_field_changes_projection(self):
        """Changing an attested field MUST change the projection."""
        r_a = {**_ATTESTED_RECEIPT, "receipt_id": "r-original"}
        r_b = {**_ATTESTED_RECEIPT, "receipt_id": "r-mutated"}
        assert canonical_projection(r_a) != canonical_projection(r_b)

    def test_changing_verification_profile_changes_projection(self):
        """verification_profile is attested — changing it changes the projection."""
        r_a = {**_ATTESTED_RECEIPT, "verification_profile": "operational-v1"}
        r_b = {**_ATTESTED_RECEIPT, "verification_profile": "archival-v1"}
        assert canonical_projection(r_a) != canonical_projection(r_b)

    def test_changing_verification_policy_changes_projection(self):
        """verification_policy is attested — changing it changes the projection."""
        r_a = dict(_ATTESTED_RECEIPT)
        r_b = {**_ATTESTED_RECEIPT, "verification_policy": {
            "operational_requires": {"min_signatures": 2, "algorithms": ["ml-dsa-65"]}
        }}
        assert canonical_projection(r_a) != canonical_projection(r_b)


# ---------------------------------------------------------------------------
# canonical_projection — error cases
# ---------------------------------------------------------------------------

class TestCanonicalProjectionErrors:
    def test_unknown_projection_id_raises(self):
        with pytest.raises(ValueError, match="Unknown projection_id"):
            canonical_projection(_ATTESTED_RECEIPT, projection_id="receipt-core-v9999")

    def test_unknown_projection_id_names_known_ids(self):
        with pytest.raises(ValueError, match="receipt-core-v2"):
            canonical_projection({}, projection_id="bad-id")

    def test_unsupported_type_raises(self):
        with pytest.raises(TypeError):
            canonical_projection(object())


# ---------------------------------------------------------------------------
# compute_bundle_digest
# ---------------------------------------------------------------------------

class TestComputeBundleDigest:
    def test_returns_prefixed_sha256(self):
        digest = compute_bundle_digest(_ATTESTED_RECEIPT)
        assert digest.startswith("sha256:")

    def test_hex_part_is_64_chars(self):
        digest = compute_bundle_digest(_ATTESTED_RECEIPT)
        _, hex_part = digest.split(":", 1)
        assert len(hex_part) == 64

    def test_excluded_fields_do_not_affect_digest(self):
        """Adding any excluded field must not change bundle_digest."""
        d1 = compute_bundle_digest(_ATTESTED_RECEIPT)
        d2 = compute_bundle_digest(_FULL_V2_RECEIPT)
        assert d1 == d2

    def test_attested_field_change_changes_digest(self):
        r = {**_ATTESTED_RECEIPT, "receipt_id": "r-mutated"}
        assert compute_bundle_digest(r) != compute_bundle_digest(_ATTESTED_RECEIPT)

    def test_sha3_256_prefix(self):
        digest = compute_bundle_digest(_ATTESTED_RECEIPT, algorithm="sha3-256")
        assert digest.startswith("sha3-256:")

    def test_sha3_256_differs_from_sha256(self):
        d_sha2 = compute_bundle_digest(_ATTESTED_RECEIPT, algorithm="sha256")
        d_sha3 = compute_bundle_digest(_ATTESTED_RECEIPT, algorithm="sha3-256")
        assert d_sha2 != d_sha3

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            compute_bundle_digest(_ATTESTED_RECEIPT, algorithm="md5")

    def test_unknown_projection_id_raises(self):
        with pytest.raises(ValueError, match="Unknown projection_id"):
            compute_bundle_digest(_ATTESTED_RECEIPT, projection_id="bad")

    def test_deterministic_repeated_calls(self):
        d1 = compute_bundle_digest(_ATTESTED_RECEIPT)
        d2 = compute_bundle_digest(_ATTESTED_RECEIPT)
        assert d1 == d2


# ---------------------------------------------------------------------------
# Golden vector tests — locked hashes
# ---------------------------------------------------------------------------

class TestGoldenVectors:
    """Locked hash values. If these fail, the projection rule has drifted."""

    def test_rc_v2_g01_canonical_utf8(self):
        """RC-V2-G01: attested-only receipt canonical form matches golden."""
        proj = canonical_projection(_ATTESTED_RECEIPT)
        canonical = jcs_canonicalize(proj).decode("utf-8")
        assert canonical == _GOLDEN_CANONICAL_UTF8

    def test_rc_v2_g01_sha256(self):
        """RC-V2-G01: attested-only receipt SHA256 matches golden."""
        proj = canonical_projection(_ATTESTED_RECEIPT)
        digest = hashlib.sha256(jcs_canonicalize(proj)).hexdigest()
        assert digest == _GOLDEN_SHA256

    def test_rc_v2_g02_sha256_equals_g01(self):
        """RC-V2-G02: receipt with all excluded fields → same hash as RC-V2-G01.

        The attested content is identical; excluded fields don't affect the digest.
        """
        proj = canonical_projection(_FULL_V2_RECEIPT)
        digest = hashlib.sha256(jcs_canonicalize(proj)).hexdigest()
        assert digest == _GOLDEN_SHA256

    def test_rc_v2_g02_bundle_digest_format(self):
        """RC-V2-G02: compute_bundle_digest returns correctly prefixed golden value."""
        assert compute_bundle_digest(_FULL_V2_RECEIPT) == _GOLDEN_BUNDLE_DIGEST

    def test_rc_v2_g03_signer_id_excluded_same_hash(self):
        """RC-V2-G03: v0-style signer_id in receipt → excluded → same hash as G01.

        Cross-version discriminator: signer_id was included in v0 hashing but
        is excluded in v2. This vector locks that behavior.
        """
        receipt_with_legacy = {**_ATTESTED_RECEIPT, "signer_id": "any-legacy-signer"}
        proj = canonical_projection(receipt_with_legacy)
        digest = hashlib.sha256(jcs_canonicalize(proj)).hexdigest()
        assert digest == _GOLDEN_SHA256


# ---------------------------------------------------------------------------
# parse_ijson_receipt — duplicate-key rejection
# ---------------------------------------------------------------------------

class TestParseIjsonReceipt:
    """Verify that duplicate keys are rejected before dict materialization.

    This is a mandatory acceptance criterion. Standard json.loads() silently
    overwrites earlier members; parse_ijson_receipt() must not.
    """

    def test_valid_json_parses_successfully(self):
        result = parse_ijson_receipt('{"receipt_id": "r1", "type": "test"}')
        assert result == {"receipt_id": "r1", "type": "test"}

    def test_nested_objects_parse_successfully(self):
        result = parse_ijson_receipt('{"payload": {"value": 42, "nested": {"a": 1}}}')
        assert result["payload"]["value"] == 42

    def test_duplicate_key_raises_value_error(self):
        """This is the mandatory I-JSON acceptance criterion.

        Standard json.loads() would silently return {"a": 2} here.
        parse_ijson_receipt() must reject.
        """
        with pytest.raises(ValueError, match="duplicate"):
            parse_ijson_receipt('{"a": 1, "a": 2}')

    def test_duplicate_key_names_the_offending_key(self):
        with pytest.raises(ValueError, match="receipt_id"):
            parse_ijson_receipt('{"receipt_id": "r1", "receipt_id": "r2", "type": "t"}')

    def test_duplicate_key_in_nested_object_raises(self):
        """Duplicate keys in nested objects must also be rejected."""
        with pytest.raises(ValueError, match="duplicate"):
            parse_ijson_receipt('{"payload": {"x": 1, "x": 2}}')

    def test_invalid_json_raises_json_decode_error(self):
        with pytest.raises(json.JSONDecodeError):
            parse_ijson_receipt("{not json}")

    def test_empty_object_parses_successfully(self):
        assert parse_ijson_receipt("{}") == {}

    def test_result_is_plain_dict(self):
        result = parse_ijson_receipt('{"a": 1}')
        assert type(result) is dict
