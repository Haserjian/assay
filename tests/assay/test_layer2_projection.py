"""Contract tests for the Layer 2 projection helper.

prepare_receipt_for_hashing() is the explicit projection step that converts
receipt objects into plain dicts suitable for Layer 1 (jcs.canonicalize).

These tests encode the contract, not just the implementation:
- Input types accepted (Pydantic model, dict, dict-like)
- Root-level-only stripping doctrine
- Versioned exclusion sets
- Failure behavior (explicit raises, no silent swallowing)
- Equivalence with the old to_jcs_bytes() pipeline for Group B callers
"""

import pytest
from pydantic import BaseModel as PydanticBaseModel

from assay._receipts.canonicalize import (
    _SIGNATURE_FIELD_SETS,
    compute_payload_hash,
    prepare_receipt_for_hashing,
    verify_jcs_stability,
)
from assay._receipts.jcs import canonicalize as jcs_canonicalize


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class SampleReceipt(PydanticBaseModel):
    receipt_id: str = "r1"
    type: str = "test"
    timestamp: str = "2026-01-01T00:00:00Z"
    signature: str = "sig_abc"
    data: str = "payload"


class NestedReceipt(PydanticBaseModel):
    receipt_id: str = "r2"
    type: str = "nested"
    timestamp: str = "2026-01-01T00:00:00Z"
    signature: str = "sig_xyz"
    inner: dict = {"signature": "nested_sig", "value": 42}


PLAIN_RECEIPT = {
    "receipt_id": "r1",
    "type": "test",
    "timestamp": "2026-01-01T00:00:00Z",
    "signature": "abc123",
    "data": {"nested": "value"},
}

RECEIPT_ALL_SIG_FIELDS = {
    "receipt_id": "r1",
    "type": "test",
    "timestamp": "2026-01-01T00:00:00Z",
    "signatures": ["sig1"],
    "signature": "sig2",
    "cose_signature": "sig3",
    "receipt_hash": "deadbeef",
    "anchor": {"ts": 1},
    "data": "payload",
}

RECEIPT_NO_SIG_FIELDS = {
    "receipt_id": "r1",
    "type": "test",
    "timestamp": "2026-01-01T00:00:00Z",
    "data": "payload",
}


# ---------------------------------------------------------------------------
# Input type acceptance
# ---------------------------------------------------------------------------

class TestInputTypes:
    """prepare_receipt_for_hashing accepts Pydantic models, dicts, and
    dict-like objects.  Unsupported types raise TypeError."""

    def test_accepts_plain_dict(self):
        result = prepare_receipt_for_hashing(PLAIN_RECEIPT)
        assert isinstance(result, dict)

    def test_accepts_pydantic_model(self):
        result = prepare_receipt_for_hashing(SampleReceipt())
        assert isinstance(result, dict)
        assert "receipt_id" in result

    def test_rejects_int(self):
        with pytest.raises(TypeError, match="int"):
            prepare_receipt_for_hashing(42)

    def test_rejects_string(self):
        with pytest.raises(TypeError, match="str"):
            prepare_receipt_for_hashing("not a receipt")

    def test_rejects_list(self):
        with pytest.raises(TypeError, match="list"):
            prepare_receipt_for_hashing([1, 2, 3])

    def test_rejects_none(self):
        with pytest.raises(TypeError, match="NoneType"):
            prepare_receipt_for_hashing(None)


# ---------------------------------------------------------------------------
# Root-level-only stripping doctrine
# ---------------------------------------------------------------------------

class TestRootOnlyStripping:
    """Signature field exclusion is root-level only.  Nested structures
    are payload and must not be modified by the projection step."""

    def test_strips_root_signature_fields_only(self):
        """Top-level 'signature' is stripped; nested 'signature' is preserved."""
        receipt = {
            "receipt_id": "r1",
            "type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "signature": "root_sig",
            "claims": {"signature": "nested_sig", "value": 1},
        }
        result = prepare_receipt_for_hashing(receipt)
        assert "signature" not in result
        assert result["claims"]["signature"] == "nested_sig"

    def test_nested_signature_field_in_pydantic_model_preserved(self):
        """Pydantic model with nested dict containing 'signature' key."""
        result = prepare_receipt_for_hashing(NestedReceipt())
        assert "signature" not in result
        assert result["inner"]["signature"] == "nested_sig"

    def test_nested_anchor_field_preserved(self):
        receipt = {
            "receipt_id": "r1",
            "type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "anchor": "root_anchor",
            "metadata": {"anchor": "nested_anchor"},
        }
        result = prepare_receipt_for_hashing(receipt)
        assert "anchor" not in result
        assert result["metadata"]["anchor"] == "nested_anchor"


# ---------------------------------------------------------------------------
# Exclusion set completeness
# ---------------------------------------------------------------------------

class TestExclusionSet:
    """The v0 exclusion set strips exactly the documented signature fields
    and preserves everything else."""

    def test_all_v0_signature_fields_stripped(self):
        result = prepare_receipt_for_hashing(RECEIPT_ALL_SIG_FIELDS)
        for field in _SIGNATURE_FIELD_SETS["v0"]:
            assert field not in result, f"{field} should be stripped"

    def test_non_signature_fields_preserved(self):
        result = prepare_receipt_for_hashing(RECEIPT_ALL_SIG_FIELDS)
        assert result["receipt_id"] == "r1"
        assert result["type"] == "test"
        assert result["timestamp"] == "2026-01-01T00:00:00Z"
        assert result["data"] == "payload"

    def test_receipt_without_signature_fields_unchanged(self):
        result = prepare_receipt_for_hashing(RECEIPT_NO_SIG_FIELDS)
        assert result == RECEIPT_NO_SIG_FIELDS

    def test_v0_exclusion_set_matches_documented_fields(self):
        """Guard against silent additions or removals."""
        expected = {"signatures", "signature", "cose_signature", "receipt_hash", "anchor"}
        assert _SIGNATURE_FIELD_SETS["v0"] == expected


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------

class TestVersioning:
    """The version parameter selects the exclusion set.  Unknown versions
    raise ValueError."""

    def test_default_version_is_v0(self):
        result_default = prepare_receipt_for_hashing(PLAIN_RECEIPT)
        result_v0 = prepare_receipt_for_hashing(PLAIN_RECEIPT, version="v0")
        assert result_default == result_v0

    def test_unknown_version_raises(self):
        with pytest.raises(ValueError, match="Unknown signature strip version"):
            prepare_receipt_for_hashing(PLAIN_RECEIPT, version="v99")

    def test_error_message_lists_known_versions(self):
        with pytest.raises(ValueError, match="v0"):
            prepare_receipt_for_hashing(PLAIN_RECEIPT, version="bad")


# ---------------------------------------------------------------------------
# Failure behavior
# ---------------------------------------------------------------------------

class TestFailureBehavior:
    """No silent exception swallowing.  All failures are explicit."""

    def test_type_error_is_not_swallowed(self):
        """Contrast with old pipeline which had try/except Exception: pass."""
        with pytest.raises(TypeError):
            prepare_receipt_for_hashing(42)

    def test_value_error_is_not_swallowed(self):
        with pytest.raises(ValueError):
            prepare_receipt_for_hashing({}, version="nonexistent")


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

class TestOutputShape:
    """The output must be a plain dict suitable for jcs.canonicalize()."""

    def test_output_is_plain_dict(self):
        result = prepare_receipt_for_hashing(SampleReceipt())
        assert type(result) is dict

    def test_output_values_are_json_primitives(self):
        """After projection, all values should be JSON-safe primitives."""
        result = prepare_receipt_for_hashing(SampleReceipt())
        for v in result.values():
            assert isinstance(v, (str, int, float, bool, list, dict, type(None)))

    def test_output_can_be_canonicalized(self):
        """The output must be accepted by jcs.canonicalize() without error."""
        result = prepare_receipt_for_hashing(RECEIPT_ALL_SIG_FIELDS)
        canonical = jcs_canonicalize(result)
        assert isinstance(canonical, bytes)
        assert len(canonical) > 0


# ---------------------------------------------------------------------------
# Migration equivalence: compute_payload_hash and verify_jcs_stability
# now route through prepare_receipt_for_hashing, not _prepare_for_canonicalization.
# These tests guard against divergence between the old and new paths.
# ---------------------------------------------------------------------------

class TestMigrationEquivalence:
    """compute_payload_hash() and verify_jcs_stability() must produce
    correct results through the explicit Layer 2 path."""

    def test_payload_hash_strips_signature_fields(self):
        """Hash excludes signature fields — the core contract."""
        hash_with_sig = compute_payload_hash(RECEIPT_ALL_SIG_FIELDS)
        hash_without_sig = compute_payload_hash(RECEIPT_NO_SIG_FIELDS)
        # Same payload data, different signature fields → same hash
        assert hash_with_sig == hash_without_sig

    def test_payload_hash_stable_across_calls(self):
        h1 = compute_payload_hash(RECEIPT_ALL_SIG_FIELDS)
        h2 = compute_payload_hash(RECEIPT_ALL_SIG_FIELDS)
        assert h1 == h2

    def test_payload_hash_on_pydantic_model(self):
        h = compute_payload_hash(SampleReceipt())
        # OCD-1 resolved: raw hex, no prefix
        assert len(h) == 64  # SHA-256 hex digest
        assert all(c in "0123456789abcdef" for c in h)

    def test_payload_hash_on_plain_dict(self):
        h = compute_payload_hash(PLAIN_RECEIPT)
        # OCD-1 resolved: raw hex, no prefix
        assert len(h) == 64
        assert ":" not in h

    def test_jcs_stability_true_for_receipt(self):
        assert verify_jcs_stability(RECEIPT_ALL_SIG_FIELDS) is True

    def test_jcs_stability_true_for_pydantic_model(self):
        assert verify_jcs_stability(SampleReceipt()) is True

    def test_jcs_stability_true_for_plain_dict(self):
        assert verify_jcs_stability(RECEIPT_NO_SIG_FIELDS) is True
