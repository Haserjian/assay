"""Posture-based claim eligibility — the doctrine that posture constrains
what status claims evidence may support.

Primary jurisdiction: Debt does not invalidate evidence; it constrains what
the evidence may assert about itself.

Secondary policy: Some workflows may additionally require clean posture for
promotion or admission — those are opt-in policy gates, not the doctrinal center.

A pack may remain valid evidence while being ineligible for some claims.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay.claim_verifier import (
    AUDIT_READY_CLAIM,
    GOVERNANCE_COMPLIANT_CLAIM,
    ClaimSpec,
    check_posture_eligible,
    verify_claims,
)
from assay.governance_posture import POSTURE_RECEIPT_TYPE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entries_with_posture(posture: str, **extra) -> list:
    """Build a minimal receipt list with a governance_posture_snapshot."""
    return [
        {"type": "model_call", "receipt_id": "r_model_1", "model": "test"},
        {
            "type": POSTURE_RECEIPT_TYPE,
            "receipt_id": "r_posture_1",
            "posture": posture,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "obligation_ids": extra.get("obligation_ids", []),
            "open_count": extra.get("open_count", 0),
            "overdue_count": extra.get("overdue_count", 0),
            "policy_version": "governance.obligation.v1",
            "derivation_scope": "local_obligation_store",
            "derivation_basis": "all open obligations at evaluation time",
        },
        {"type": "checkpoint.sealed", "receipt_id": "r_seal_1"},
    ]


def _entries_without_posture() -> list:
    """Build entries from a pack that predates posture embedding."""
    return [
        {"type": "model_call", "receipt_id": "r_model_1"},
        {"type": "checkpoint.sealed", "receipt_id": "r_seal_1"},
    ]


# ---------------------------------------------------------------------------
# Core eligibility check
# ---------------------------------------------------------------------------

class TestPostureEligibilityCheck:
    def test_clean_posture_passes_governance_compliant(self):
        entries = _entries_with_posture("CLEAN")
        result = check_posture_eligible(
            entries, claim_id="governance_compliant", required_posture="CLEAN"
        )
        assert result.passed
        assert "CLEAN" in result.actual

    def test_debt_outstanding_fails_governance_compliant(self):
        entries = _entries_with_posture(
            "DEBT_OUTSTANDING",
            obligation_ids=["OB-001"],
            open_count=1,
        )
        result = check_posture_eligible(
            entries, claim_id="governance_compliant", required_posture="CLEAN"
        )
        assert not result.passed
        assert "DEBT_OUTSTANDING" in result.actual

    def test_debt_overdue_fails_governance_compliant(self):
        entries = _entries_with_posture(
            "DEBT_OVERDUE",
            obligation_ids=["OB-001"],
            open_count=1,
            overdue_count=1,
        )
        result = check_posture_eligible(
            entries, claim_id="governance_compliant", required_posture="CLEAN"
        )
        assert not result.passed
        assert "DEBT_OVERDUE" in result.actual

    def test_debt_outstanding_passes_with_relaxed_threshold(self):
        """DEBT_OUTSTANDING meets a DEBT_OUTSTANDING requirement (not overdue)."""
        entries = _entries_with_posture(
            "DEBT_OUTSTANDING",
            obligation_ids=["OB-001"],
            open_count=1,
        )
        result = check_posture_eligible(
            entries, claim_id="no_overdue_debt",
            required_posture="DEBT_OUTSTANDING",
        )
        assert result.passed

    def test_debt_overdue_fails_even_relaxed_threshold(self):
        entries = _entries_with_posture(
            "DEBT_OVERDUE",
            obligation_ids=["OB-001"],
            open_count=1,
            overdue_count=1,
        )
        result = check_posture_eligible(
            entries, claim_id="no_overdue_debt",
            required_posture="DEBT_OUTSTANDING",
        )
        assert not result.passed

    def test_no_posture_receipt_fails(self):
        """Pack predating posture embedding cannot claim governance standing."""
        entries = _entries_without_posture()
        result = check_posture_eligible(
            entries, claim_id="governance_compliant", required_posture="CLEAN"
        )
        assert not result.passed
        assert "predates" in result.actual.lower()

    def test_unknown_posture_fails(self):
        entries = _entries_with_posture("UNKNOWN")
        result = check_posture_eligible(
            entries, claim_id="governance_compliant", required_posture="CLEAN"
        )
        assert not result.passed

    def test_evidence_receipt_id_included(self):
        entries = _entries_with_posture("CLEAN")
        result = check_posture_eligible(
            entries, claim_id="test", required_posture="CLEAN"
        )
        assert "r_posture_1" in result.evidence_receipt_ids


# ---------------------------------------------------------------------------
# Predefined claim specs
# ---------------------------------------------------------------------------

class TestPredefinedClaims:
    def test_governance_compliant_claim_spec(self):
        assert GOVERNANCE_COMPLIANT_CLAIM.claim_id == "governance_compliant"
        assert GOVERNANCE_COMPLIANT_CLAIM.check == "posture_eligible"
        assert GOVERNANCE_COMPLIANT_CLAIM.params["required_posture"] == "CLEAN"
        assert GOVERNANCE_COMPLIANT_CLAIM.severity == "critical"

    def test_audit_ready_claim_spec(self):
        assert AUDIT_READY_CLAIM.claim_id == "audit_ready"
        assert AUDIT_READY_CLAIM.check == "posture_eligible"
        assert AUDIT_READY_CLAIM.params["required_posture"] == "CLEAN"
        assert AUDIT_READY_CLAIM.severity == "critical"


# ---------------------------------------------------------------------------
# Integration with verify_claims
# ---------------------------------------------------------------------------

class TestClaimVerificationIntegration:
    def test_governance_compliant_passes_with_clean_posture(self):
        entries = _entries_with_posture("CLEAN")
        result = verify_claims(entries, [GOVERNANCE_COMPLIANT_CLAIM])
        assert result.passed
        assert result.n_passed == 1
        assert result.n_failed == 0

    def test_governance_compliant_fails_with_debt(self):
        entries = _entries_with_posture(
            "DEBT_OUTSTANDING",
            obligation_ids=["OB-001"],
            open_count=1,
        )
        result = verify_claims(entries, [GOVERNANCE_COMPLIANT_CLAIM])
        assert not result.passed
        assert result.n_failed == 1

    def test_mixed_claims_partial_failure(self):
        """Evidence integrity claim passes, governance claim fails.

        This proves the core doctrine: a pack may remain valid evidence
        while being ineligible for governance-standing claims.
        """
        entries = _entries_with_posture(
            "DEBT_OVERDUE",
            obligation_ids=["OB-001"],
            open_count=1,
            overdue_count=1,
        )

        integrity_claim = ClaimSpec(
            claim_id="has_model_call",
            description="At least one model call receipt exists",
            check="receipt_type_present",
            params={"receipt_type": "model_call"},
        )

        result = verify_claims(
            entries, [integrity_claim, GOVERNANCE_COMPLIANT_CLAIM]
        )

        # Overall: FAIL (governance claim is critical and failed)
        assert not result.passed

        # But the integrity claim passed
        by_id = {r.claim_id: r for r in result.results}
        assert by_id["has_model_call"].passed
        assert not by_id["governance_compliant"].passed

        # Evidence is valid; governance standing is not
        assert by_id["has_model_call"].actual == "found 1"
        assert "DEBT_OVERDUE" in by_id["governance_compliant"].actual

    def test_both_governance_and_audit_ready_fail_together(self):
        entries = _entries_with_posture("DEBT_OUTSTANDING", open_count=1)
        result = verify_claims(
            entries, [GOVERNANCE_COMPLIANT_CLAIM, AUDIT_READY_CLAIM]
        )
        assert not result.passed
        assert result.n_failed == 2

    def test_governance_claims_with_no_posture_receipt(self):
        """Old packs that predate posture embedding fail governance claims."""
        entries = _entries_without_posture()
        result = verify_claims(entries, [GOVERNANCE_COMPLIANT_CLAIM])
        assert not result.passed
        by_id = {r.claim_id: r for r in result.results}
        assert "predates" in by_id["governance_compliant"].actual.lower()


# ---------------------------------------------------------------------------
# The doctrine test: evidence validity is independent of claim eligibility
# ---------------------------------------------------------------------------

class TestDoctrineIndependence:
    def test_evidence_valid_but_claim_ineligible(self):
        """The core constitutional doctrine: debt does not invalidate evidence,
        it constrains what status claims the evidence may support.

        A pack with DEBT_OVERDUE posture:
          - Integrity: PASS (receipts are authentic)
          - Evidence claims: PASS (model calls present, timestamps ordered)
          - Governance claims: FAIL (posture does not support assertion)

        The pack is still valid evidence. It just cannot claim governance standing.
        """
        entries = _entries_with_posture(
            "DEBT_OVERDUE",
            obligation_ids=["OB-overdue"],
            open_count=1,
            overdue_count=1,
        )

        evidence_claims = [
            ClaimSpec(
                claim_id="has_model_call",
                description="Model call exists",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
            ClaimSpec(
                claim_id="has_checkpoint",
                description="Checkpoint sealed",
                check="receipt_type_present",
                params={"receipt_type": "checkpoint.sealed"},
            ),
        ]
        governance_claims = [GOVERNANCE_COMPLIANT_CLAIM, AUDIT_READY_CLAIM]

        # Evidence claims pass independently
        ev_result = verify_claims(entries, evidence_claims)
        assert ev_result.passed, "Evidence validity must be independent of posture"

        # Governance claims fail independently
        gov_result = verify_claims(entries, governance_claims)
        assert not gov_result.passed, "Governance standing is constrained by posture"

        # Combined: evidence passes, governance fails
        combined = verify_claims(entries, evidence_claims + governance_claims)
        assert not combined.passed  # critical governance claims failed
        by_id = {r.claim_id: r for r in combined.results}
        assert by_id["has_model_call"].passed
        assert by_id["has_checkpoint"].passed
        assert not by_id["governance_compliant"].passed
        assert not by_id["audit_ready"].passed
