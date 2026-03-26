"""Stage 3b anchor resolution — assay-toolkit acceptance tests.
Stage 5 enforces that governance-class receipts declare an authorization
anchor. Stage 3b verifies that the declared anchor actually resolves to
an admissible artifact.

Declaration ≠ verification. This is the verification layer.

Row 3 Stage 3b.
"""
from __future__ import annotations

from __future__ import annotations

import pytest

from assay.decision_receipt import (
    LAYER_ANCHOR,
    validate_governance_anchors,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _governance_receipt(
    *,
    guardian_anchor: str | None = None,
    settlement_anchor: str | None = None,
    authority_class: str = "BINDING",
    version: str = "0.2.0",
) -> dict:
    """Minimal v0.2.0 governance receipt with configurable anchors."""
    r = {
        "receipt_id": "dr-001",
        "receipt_type": "decision_v1",
        "receipt_version": version,
        "timestamp": "2026-01-01T00:00:00.000Z",
        "decision_type": "gate_evaluation",
        "decision_subject": "test:subject",
        "verdict": "REFUSE",
        "authority_id": "ccio:test",
        "authority_class": authority_class,
        "authority_scope": "test",
        "policy_id": "test.policy.v1",
        "policy_hash": "a" * 64,
        "episode_id": "ep-001",
        "disposition": "block",
        "evidence_sufficient": True,
        "provenance_complete": True,
    }
    if guardian_anchor is not None:
        r["guardian_authorization_receipt_id"] = guardian_anchor
    if settlement_anchor is not None:
        r["settlement_outcome_id"] = settlement_anchor
    return r


def _guardian_artifact(receipt_id: str = "guardian-001") -> dict:
    """Minimal Guardian assessment artifact."""
    return {
        "receipt_id": receipt_id,
        "receipt_type": "guardian_assessment",
    }


def _settlement_artifact(receipt_id: str = "settlement-001") -> dict:
    """Minimal settlement outcome artifact."""
    return {
        "receipt_id": receipt_id,
        "receipt_type": "settlement_outcome",
    }


def _wrong_kind_artifact(receipt_id: str = "wrong-001") -> dict:
    """Artifact with a type not admissible for any anchor slot."""
    return {
        "receipt_id": receipt_id,
        "receipt_type": "observation_log",
    }


# ===================================================================
# 1. Anchor exists and is correct kind → PASS
# ===================================================================

class TestAnchorResolvesCorrectly:

    def test_guardian_anchor_resolves_to_assessment(self):
        """Guardian anchor pointing to guardian_assessment passes."""
        receipt = _governance_receipt(guardian_anchor="guardian-001")
        index = {"guardian-001": _guardian_artifact("guardian-001")}
        result = validate_governance_anchors(receipt, index)
        assert result.valid
        assert len(result.errors) == 0

    def test_settlement_anchor_resolves_to_outcome(self):
        """Settlement anchor pointing to settlement_outcome passes."""
        receipt = _governance_receipt(settlement_anchor="settlement-001")
        index = {"settlement-001": _settlement_artifact("settlement-001")}
        result = validate_governance_anchors(receipt, index)
        assert result.valid

    def test_both_anchors_resolve(self):
        """Both anchors present and both resolve correctly."""
        receipt = _governance_receipt(
            guardian_anchor="guardian-001",
            settlement_anchor="settlement-001",
        )
        index = {
            "guardian-001": _guardian_artifact("guardian-001"),
            "settlement-001": _settlement_artifact("settlement-001"),
        }
        result = validate_governance_anchors(receipt, index)
        assert result.valid


# ===================================================================
# 2. Anchor UUID missing from index → FAIL
# ===================================================================

class TestAnchorNotFound:

    def test_guardian_anchor_missing_from_index(self):
        """Guardian anchor ID not found in receipt index."""
        receipt = _governance_receipt(guardian_anchor="guardian-missing")
        index = {}  # empty index
        result = validate_governance_anchors(receipt, index)
        assert not result.valid
        assert len(result.errors) == 1
        assert result.errors[0].rule == "ANCHOR_NOT_FOUND"
        assert result.errors[0].field == "guardian_authorization_receipt_id"
        assert result.errors[0].layer == LAYER_ANCHOR

    def test_settlement_anchor_missing_from_index(self):
        """Settlement anchor ID not found in receipt index."""
        receipt = _governance_receipt(settlement_anchor="settlement-missing")
        index = {}
        result = validate_governance_anchors(receipt, index)
        assert not result.valid
        assert result.errors[0].rule == "ANCHOR_NOT_FOUND"
        assert result.errors[0].field == "settlement_outcome_id"

    def test_both_anchors_missing(self):
        """Both anchors declared but neither found — two errors."""
        receipt = _governance_receipt(
            guardian_anchor="g-missing",
            settlement_anchor="s-missing",
        )
        index = {}
        result = validate_governance_anchors(receipt, index)
        assert not result.valid
        assert len(result.errors) == 2
        fields = {e.field for e in result.errors}
        assert fields == {"guardian_authorization_receipt_id", "settlement_outcome_id"}


# ===================================================================
# 3. Anchor resolves to wrong artifact kind → FAIL
# ===================================================================

class TestAnchorWrongKind:

    def test_guardian_anchor_wrong_type(self):
        """Guardian anchor points to a non-Guardian artifact type."""
        receipt = _governance_receipt(guardian_anchor="wrong-001")
        index = {"wrong-001": _wrong_kind_artifact("wrong-001")}
        result = validate_governance_anchors(receipt, index)
        assert not result.valid
        assert result.errors[0].rule == "ANCHOR_WRONG_KIND"
        assert result.errors[0].field == "guardian_authorization_receipt_id"
        assert "observation_log" in result.errors[0].message

    def test_settlement_anchor_wrong_type(self):
        """Settlement anchor points to a non-settlement artifact type."""
        receipt = _governance_receipt(settlement_anchor="wrong-001")
        index = {"wrong-001": _wrong_kind_artifact("wrong-001")}
        result = validate_governance_anchors(receipt, index)
        assert not result.valid
        assert result.errors[0].rule == "ANCHOR_WRONG_KIND"
        assert result.errors[0].field == "settlement_outcome_id"

    def test_guardian_anchor_pointing_to_settlement_type(self):
        """Guardian anchor slot cannot hold a settlement artifact."""
        receipt = _governance_receipt(guardian_anchor="settlement-001")
        index = {"settlement-001": _settlement_artifact("settlement-001")}
        result = validate_governance_anchors(receipt, index)
        assert not result.valid
        assert result.errors[0].rule == "ANCHOR_WRONG_KIND"


# ===================================================================
# 4. Advisory receipt without anchor requirement → EXEMPT
# ===================================================================

class TestAdvisoryExempt:

    def test_advisory_receipt_no_anchors_passes(self):
        """ADVISORY receipts are exempt from anchor requirements."""
        receipt = _governance_receipt(authority_class="ADVISORY")
        result = validate_governance_anchors(receipt, {})
        assert result.valid

    def test_auditing_receipt_no_anchors_passes(self):
        """AUDITING receipts are exempt from anchor requirements."""
        receipt = _governance_receipt(authority_class="AUDITING")
        result = validate_governance_anchors(receipt, {})
        assert result.valid


# ===================================================================
# 5. Forensic compat — pre-v0.2.0 receipts exempt
# ===================================================================

class TestForensicCompat:

    def test_v0_1_0_receipt_exempt(self):
        """Pre-Stage-5 receipts have no anchor fields — exempt."""
        receipt = _governance_receipt(version="0.1.0")
        result = validate_governance_anchors(receipt, {})
        assert result.valid

    def test_v0_1_1_receipt_exempt(self):
        """v0.1.1 receipts predate anchor fields — exempt."""
        receipt = _governance_receipt(version="0.1.1")
        result = validate_governance_anchors(receipt, {})
        assert result.valid
