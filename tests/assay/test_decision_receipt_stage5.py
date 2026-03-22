"""Stage 5 authorization ancestry — assay-toolkit acceptance tests.

Tests the GovernanceEmissionError class and SUPPORTED_RECEIPT_VERSIONS
multi-version support from decision_receipt.py.

The guard itself lives in ccio/src/receipts/decision_receipts/build.py.
This file tests the shared exception type and version support.

Row 3 Stage 5.
"""
from __future__ import annotations

import pytest

from assay.decision_receipt import (
    GovernanceEmissionError,
    RECEIPT_VERSION,
    SUPPORTED_RECEIPT_VERSIONS,
    validate_shape,
)


# ---------------------------------------------------------------------------
# GovernanceEmissionError class
# ---------------------------------------------------------------------------


class TestGovernanceEmissionError:

    def test_is_subclass_of_value_error(self):
        assert issubclass(GovernanceEmissionError, ValueError)

    def test_is_not_runtime_error(self):
        assert not issubclass(GovernanceEmissionError, RuntimeError)

    def test_can_be_raised_and_caught_as_value_error(self):
        with pytest.raises(ValueError):
            raise GovernanceEmissionError("test message")

    def test_message_preserved(self):
        msg = "authority_class='BINDING' requires anchor"
        exc = GovernanceEmissionError(msg)
        assert msg in str(exc)

    def test_can_be_caught_specifically(self):
        with pytest.raises(GovernanceEmissionError):
            raise GovernanceEmissionError("test")


# ---------------------------------------------------------------------------
# RECEIPT_VERSION and SUPPORTED_RECEIPT_VERSIONS
# ---------------------------------------------------------------------------


class TestVersionConstants:

    def test_receipt_version_is_0_2_0(self):
        assert RECEIPT_VERSION == "0.2.0"

    def test_supported_versions_contains_0_1_0(self):
        """Legacy receipts (pre-Stage-5) must not be rejected."""
        assert "0.1.0" in SUPPORTED_RECEIPT_VERSIONS

    def test_supported_versions_contains_0_1_1(self):
        """v0.1.1 receipts (decision_basis) must not be rejected."""
        assert "0.1.1" in SUPPORTED_RECEIPT_VERSIONS

    def test_supported_versions_contains_0_2_0(self):
        assert "0.2.0" in SUPPORTED_RECEIPT_VERSIONS

    def test_supported_versions_is_frozenset(self):
        assert isinstance(SUPPORTED_RECEIPT_VERSIONS, frozenset)

    def test_receipt_version_is_in_supported_versions(self):
        """Current version must be a supported version."""
        assert RECEIPT_VERSION in SUPPORTED_RECEIPT_VERSIONS


# ---------------------------------------------------------------------------
# Validator accepts all supported versions
# ---------------------------------------------------------------------------


def _minimal_receipt(version: str) -> dict:
    """Return a minimal receipt dict with the given version."""
    return {
        "receipt_id": "11111111-1111-4111-8111-111111111111",
        "receipt_type": "decision_v1",
        "receipt_version": version,
        "timestamp": "2026-01-01T00:00:00.000Z",
        "decision_type": "gate_evaluation",
        "decision_subject": "test:subject",
        "verdict": "REFUSE",
        "authority_id": "ccio:test",
        "authority_class": "BINDING",
        "authority_scope": "test",
        "policy_id": "test.policy.v1",
        "policy_hash": "a" * 64,
        "episode_id": "ep-001",
        "disposition": "block",
        "evidence_sufficient": True,
        "provenance_complete": True,
    }


class TestValidatorAcceptsAllSupportedVersions:

    def test_v0_1_0_accepted_by_validator(self):
        receipt = _minimal_receipt("0.1.0")
        result = validate_shape(receipt)
        # receipt_version is valid — no version error
        version_errors = [e for e in result.errors if e.field == "receipt_version"]
        assert not version_errors, f"Unexpected version errors: {version_errors}"

    def test_v0_1_1_accepted_by_validator(self):
        receipt = _minimal_receipt("0.1.1")
        result = validate_shape(receipt)
        version_errors = [e for e in result.errors if e.field == "receipt_version"]
        assert not version_errors, f"Unexpected version errors: {version_errors}"

    def test_v0_2_0_accepted_by_validator(self):
        receipt = _minimal_receipt("0.2.0")
        result = validate_shape(receipt)
        version_errors = [e for e in result.errors if e.field == "receipt_version"]
        assert not version_errors, f"Unexpected version errors: {version_errors}"

    def test_unknown_version_rejected_by_validator(self):
        receipt = _minimal_receipt("9.9.9")
        result = validate_shape(receipt)
        assert not result.valid
        version_errors = [e for e in result.errors if e.field == "receipt_version"]
        assert version_errors, "Expected version error for unknown version"
