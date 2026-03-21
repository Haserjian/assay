"""Tests for the shared Decision Receipt trust evaluator.

Locks the 5-state trust model before signing lands.
Classification priority: MISSING → INVALID → UNVERIFIABLE → VERIFIED → UNSIGNED
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import pytest

from assay.decision_receipt_trust import (
    DecisionReceiptTrustState,
    TrustClassification,
    classify_trust,
    MISSING,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_RECEIPT = {
    "receipt_id": "trust-test-001",
    "receipt_type": "decision_v1",
    "receipt_version": "0.1.0",
    "ceid": None,
    "timestamp": "2026-03-21T12:00:00.000Z",
    "parent_receipt_id": None,
    "supersedes": None,
    "decision_type": "guardian_constitutional_refusal",
    "decision_subject": "test:subject",
    "verdict": "REFUSE",
    "verdict_reason": "Test refusal reason",
    "verdict_reason_codes": ["clarity_check_failed", "domain:epistemic"],
    "authority_id": "ccio:settlement:guardian_seat",
    "authority_class": "BINDING",
    "authority_scope": "constitutional_baseline",
    "delegated_from": None,
    "policy_id": "ccio.settlement.constitutional_baseline.v1",
    "policy_hash": "a" * 64,
    "episode_id": "ep-trust-001",
    "source_organ": "ccio",
    "disposition": "block",
    "disposition_target": None,
    "obligations_created": [],
    "evidence_refs": [],
    "evidence_sufficient": True,
    "evidence_gaps": [],
    "confidence": "high",
    "conflict_refs": [],
    "dissent": None,
    "abstention_reason": None,
    "unresolved_contradictions": [],
    "proof_tier_at_decision": None,
    "proof_tier_achieved": None,
    "proof_tier_minimum_required": None,
    "provenance_complete": True,
    "known_provenance_gaps": [],
    "content_hash": "f" * 64,
    "signature": None,
    "signer_pubkey_sha256": None,
}


@dataclass
class _MockValidationResult:
    valid: bool
    errors: List[Any] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


@dataclass
class _MockError:
    rule: str
    message: str


def _passing_validator(receipt: Dict[str, Any]) -> _MockValidationResult:
    return _MockValidationResult(valid=True)


def _failing_validator(receipt: Dict[str, Any]) -> _MockValidationResult:
    return _MockValidationResult(
        valid=False,
        errors=[_MockError(rule="R-TEST", message="Test validation failure")],
    )


def _true_verifier(receipt: Dict[str, Any]) -> bool:
    return True


def _false_verifier(receipt: Dict[str, Any]) -> bool:
    return False


def _exploding_verifier(receipt: Dict[str, Any]) -> bool:
    raise ValueError("Key material corrupted")


# ---------------------------------------------------------------------------
# MISSING
# ---------------------------------------------------------------------------

class TestMissing:

    def test_none_receipt_is_missing(self):
        result = classify_trust(None)
        assert result.state == DecisionReceiptTrustState.MISSING

    def test_missing_sentinel_matches(self):
        result = classify_trust(None)
        assert result == MISSING

    def test_missing_is_not_trustworthy(self):
        result = classify_trust(None)
        assert not result.is_trustworthy
        assert not result.is_structurally_sound


# ---------------------------------------------------------------------------
# UNSIGNED
# ---------------------------------------------------------------------------

class TestUnsigned:

    def test_no_signature_is_unsigned(self):
        result = classify_trust(_VALID_RECEIPT)
        assert result.state == DecisionReceiptTrustState.UNSIGNED

    def test_unsigned_with_content_hash(self):
        result = classify_trust(_VALID_RECEIPT)
        assert "structurally sound" in result.reason

    def test_unsigned_without_content_hash(self):
        receipt = {**_VALID_RECEIPT, "content_hash": None}
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.UNSIGNED
        assert "no content hash" in result.reason

    def test_unsigned_is_structurally_sound(self):
        result = classify_trust(_VALID_RECEIPT)
        assert result.is_structurally_sound
        assert not result.is_trustworthy

    def test_unsigned_with_validator_passing(self):
        result = classify_trust(_VALID_RECEIPT, validator=_passing_validator)
        assert result.state == DecisionReceiptTrustState.UNSIGNED


# ---------------------------------------------------------------------------
# INVALID
# ---------------------------------------------------------------------------

class TestInvalid:

    def test_schema_validation_failure_is_invalid(self):
        result = classify_trust(_VALID_RECEIPT, validator=_failing_validator)
        assert result.state == DecisionReceiptTrustState.INVALID

    def test_invalid_carries_errors(self):
        result = classify_trust(_VALID_RECEIPT, validator=_failing_validator)
        assert len(result.errors) > 0
        assert "R-TEST" in result.errors[0]

    def test_malformed_receipt_is_invalid(self):
        bad = {"receipt_id": "bad"}
        result = classify_trust(bad, validator=_failing_validator)
        assert result.state == DecisionReceiptTrustState.INVALID

    def test_invalid_is_not_structurally_sound(self):
        result = classify_trust(_VALID_RECEIPT, validator=_failing_validator)
        assert not result.is_structurally_sound
        assert not result.is_trustworthy

    def test_signature_mismatch_is_invalid(self):
        """Signed receipt where verification fails → INVALID, not unverifiable."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "bad_sig",
            "signer_pubkey_sha256": "some_key_hash",
        }
        result = classify_trust(receipt, verify_signature=_false_verifier)
        assert result.state == DecisionReceiptTrustState.INVALID
        assert "tampered" in result.errors[0].lower() or "mismatch" in result.reason.lower()

    def test_verification_exception_is_invalid(self):
        """Verifier raising exception → INVALID with error detail."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "some_sig",
            "signer_pubkey_sha256": "some_key",
        }
        result = classify_trust(receipt, verify_signature=_exploding_verifier)
        assert result.state == DecisionReceiptTrustState.INVALID
        assert "corrupted" in result.errors[0].lower()


# ---------------------------------------------------------------------------
# UNVERIFIABLE
# ---------------------------------------------------------------------------

class TestUnverifiable:

    def test_sig_present_no_key_is_unverifiable(self):
        receipt = {
            **_VALID_RECEIPT,
            "signature": "some_sig_base64",
            "signer_pubkey_sha256": None,
        }
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.UNVERIFIABLE

    def test_sig_present_no_verifier_is_unverifiable(self):
        """Signature + key present, but no verify function → unverifiable."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "some_sig",
            "signer_pubkey_sha256": "some_key_hash",
        }
        # No verify_signature callback provided
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.UNVERIFIABLE

    def test_unverifiable_reason_mentions_key(self):
        receipt = {
            **_VALID_RECEIPT,
            "signature": "sig",
            "signer_pubkey_sha256": None,
        }
        result = classify_trust(receipt)
        assert "key unavailable" in result.reason.lower()

    def test_unverifiable_is_not_invalid(self):
        """Critical boundary: unverifiable must NOT be collapsed into invalid."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "sig",
            "signer_pubkey_sha256": None,
        }
        result = classify_trust(receipt)
        assert result.state != DecisionReceiptTrustState.INVALID


# ---------------------------------------------------------------------------
# VERIFIED
# ---------------------------------------------------------------------------

class TestVerified:

    def test_sig_present_verification_passes(self):
        receipt = {
            **_VALID_RECEIPT,
            "signature": "valid_sig_base64",
            "signer_pubkey_sha256": "key_hash_abc123",
        }
        result = classify_trust(receipt, verify_signature=_true_verifier)
        assert result.state == DecisionReceiptTrustState.VERIFIED

    def test_verified_is_trustworthy(self):
        receipt = {
            **_VALID_RECEIPT,
            "signature": "valid_sig",
            "signer_pubkey_sha256": "key_hash",
        }
        result = classify_trust(receipt, verify_signature=_true_verifier)
        assert result.is_trustworthy
        assert result.is_structurally_sound

    def test_verified_with_validator_passing(self):
        receipt = {
            **_VALID_RECEIPT,
            "signature": "valid_sig",
            "signer_pubkey_sha256": "key_hash",
        }
        result = classify_trust(
            receipt,
            validator=_passing_validator,
            verify_signature=_true_verifier,
        )
        assert result.state == DecisionReceiptTrustState.VERIFIED


# ---------------------------------------------------------------------------
# Classification priority
# ---------------------------------------------------------------------------

class TestPriority:

    def test_unverifiable_beats_invalid(self):
        """Missing key takes priority over schema validation.

        The signature-present-key-absent pattern is UNVERIFIABLE, not INVALID,
        even if the validator would also flag I-7. This is because the receipt
        may be structurally fine — we just can't prove it with available keys.
        """
        receipt = {
            **_VALID_RECEIPT,
            "signature": "some_sig",
            "signer_pubkey_sha256": None,
        }
        result = classify_trust(receipt, validator=_failing_validator)
        assert result.state == DecisionReceiptTrustState.UNVERIFIABLE

    def test_invalid_beats_unsigned(self):
        result = classify_trust(_VALID_RECEIPT, validator=_failing_validator)
        assert result.state == DecisionReceiptTrustState.INVALID

    def test_missing_beats_everything(self):
        result = classify_trust(None, validator=_failing_validator)
        assert result.state == DecisionReceiptTrustState.MISSING


# ---------------------------------------------------------------------------
# Boundary: unverifiable vs invalid
# ---------------------------------------------------------------------------

class TestBoundary:
    """The distinction between unverifiable and invalid is constitutionally important."""

    def test_missing_key_is_unverifiable_not_invalid(self):
        """Key unavailable ≠ verification failed."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "sig",
            "signer_pubkey_sha256": None,
        }
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.UNVERIFIABLE
        assert result.state != DecisionReceiptTrustState.INVALID

    def test_bad_signature_is_invalid_not_unverifiable(self):
        """Verification attempted and failed ≠ verification impossible."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "bad_sig",
            "signer_pubkey_sha256": "key_hash",
        }
        result = classify_trust(receipt, verify_signature=_false_verifier)
        assert result.state == DecisionReceiptTrustState.INVALID
        assert result.state != DecisionReceiptTrustState.UNVERIFIABLE

    def test_malformed_signed_receipt_without_key_is_unverifiable(self):
        """Signed + key missing + structurally broken → UNVERIFIABLE wins.

        Policy choice: if key material is unavailable, we surface
        unverifiability even if validation would also fail. This is because
        the structural defect may be an artifact of incomplete transmission,
        and the dominant signal is "we cannot verify the signature."
        """
        broken_signed = {
            "receipt_id": "broken-signed-001",
            "signature": "some_sig",
            "signer_pubkey_sha256": None,
            # Missing most required fields — would fail validation
        }
        result = classify_trust(broken_signed, validator=_failing_validator)
        assert result.state == DecisionReceiptTrustState.UNVERIFIABLE


# ---------------------------------------------------------------------------
# Enum properties
# ---------------------------------------------------------------------------

class TestEmptySignature:
    """P1 fix: empty/whitespace signature is INVALID, not UNVERIFIABLE."""

    def test_empty_string_signature_is_invalid(self):
        receipt = {**_VALID_RECEIPT, "signature": ""}
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.INVALID
        assert "empty" in result.errors[0].lower()

    def test_whitespace_signature_is_invalid(self):
        receipt = {**_VALID_RECEIPT, "signature": "   "}
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.INVALID

    def test_none_signature_is_not_invalid(self):
        """None signature = unsigned, not invalid."""
        receipt = {**_VALID_RECEIPT, "signature": None}
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.UNSIGNED

    def test_real_signature_no_key_is_unverifiable(self):
        """Non-empty signature + no key = UNVERIFIABLE (not invalid)."""
        receipt = {
            **_VALID_RECEIPT,
            "signature": "abc123realbase64",
            "signer_pubkey_sha256": None,
        }
        result = classify_trust(receipt)
        assert result.state == DecisionReceiptTrustState.UNVERIFIABLE


class TestEnumContract:

    def test_all_five_states_exist(self):
        states = set(DecisionReceiptTrustState)
        assert len(states) == 5
        assert DecisionReceiptTrustState.VERIFIED in states
        assert DecisionReceiptTrustState.UNSIGNED in states
        assert DecisionReceiptTrustState.UNVERIFIABLE in states
        assert DecisionReceiptTrustState.INVALID in states
        assert DecisionReceiptTrustState.MISSING in states

    def test_states_are_lowercase_strings(self):
        for state in DecisionReceiptTrustState:
            assert state.value == state.value.lower()

    def test_trust_classification_is_frozen(self):
        tc = TrustClassification(state=DecisionReceiptTrustState.UNSIGNED)
        with pytest.raises(AttributeError):
            tc.state = DecisionReceiptTrustState.VERIFIED
