"""Tests for falsifier, residual risk, and proof debt primitives.

These three primitives form a constitutional triad:
  - Falsifiers: what would cheaply disprove this claim?
  - Residual risk: what remains unresolved but tolerated?
  - Proof debt: what is still owed?
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.claim_verifier import (
    ALLOWED_SEVERITIES,
    ClaimResult,
    ClaimSetResult,
    ClaimSpec,
    FalsifierSpec,
    TIER_CAP_TABLE,
    verify_claims,
)
from assay.residual_risk import (
    ResidualRiskItem,
    ResidualRiskLedger,
    build_residual_risk_from_claims,
)
from assay.proof_debt import (
    ProofDebtItem,
    ProofDebtLedger,
    compute_proof_debt,
    DEBT_SOURCES,
)
from assay.proof_posture import (
    ProofPosture,
    build_proof_posture,
    compute_disposition,
    render_proof_posture_text,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RECEIPTS = [
    {"receipt_id": "r1", "type": "model_call", "timestamp": "2026-03-14T00:00:00Z"},
    {"receipt_id": "r2", "type": "model_call", "timestamp": "2026-03-14T00:00:01Z"},
    {"receipt_id": "r3", "type": "tool_use", "timestamp": "2026-03-14T00:00:02Z"},
]

FALSIFIER_AUTH = FalsifierSpec(
    description="Run login/logout/session-expiry matrix against changed endpoints",
    test_command="pytest tests/auth/ -k session_matrix",
    evaluation_surface="auth endpoints",
)

FALSIFIER_AUTH_EXECUTED = FalsifierSpec(
    description="Run login/logout/session-expiry matrix against changed endpoints",
    test_command="pytest tests/auth/ -k session_matrix",
    evaluation_surface="auth endpoints",
    executed=True,
)

CLAIM_WITH_FALSIFIER = ClaimSpec(
    claim_id="has_model_calls",
    description="At least one model call receipt exists",
    check="receipt_type_present",
    params={"receipt_type": "model_call"},
    severity="critical",
    falsifier=FALSIFIER_AUTH_EXECUTED,
)

CLAIM_WITHOUT_FALSIFIER = ClaimSpec(
    claim_id="has_tool_use",
    description="At least one tool_use receipt exists",
    check="receipt_type_present",
    params={"receipt_type": "tool_use"},
    severity="critical",
)

CLAIM_WARNING = ClaimSpec(
    claim_id="many_receipts",
    description="At least 10 receipts",
    check="receipt_count_ge",
    params={"min_count": 10},
    severity="warning",
)


# ===========================================================================
# FALSIFIER TESTS
# ===========================================================================

class TestFalsifierSpec:
    def test_to_dict_minimal(self):
        f = FalsifierSpec(description="Check ECE on held-out data")
        d = f.to_dict()
        assert d == {"description": "Check ECE on held-out data"}
        assert "test_command" not in d
        assert "evaluation_surface" not in d

    def test_to_dict_full(self):
        d = FALSIFIER_AUTH.to_dict()
        assert d["description"] == "Run login/logout/session-expiry matrix against changed endpoints"
        assert d["test_command"] == "pytest tests/auth/ -k session_matrix"
        assert d["evaluation_surface"] == "auth endpoints"


class TestClaimSpecWithFalsifier:
    def test_to_dict_includes_falsifier(self):
        d = CLAIM_WITH_FALSIFIER.to_dict()
        assert "falsifier" in d
        assert d["falsifier"]["description"] == FALSIFIER_AUTH_EXECUTED.description

    def test_to_dict_omits_falsifier_when_none(self):
        d = CLAIM_WITHOUT_FALSIFIER.to_dict()
        assert "falsifier" not in d


class TestVerifyClaimsWithFalsifiers:
    def test_no_enforcement_by_default(self):
        result = verify_claims(SAMPLE_RECEIPTS, [CLAIM_WITHOUT_FALSIFIER])
        assert result.passed is True
        assert result.n_capped == 0
        cr = result.results[0]
        assert cr.falsifier_status == "not_required"
        assert cr.tier_cap is None

    def test_enforcement_caps_missing_falsifier(self):
        result = verify_claims(
            SAMPLE_RECEIPTS, [CLAIM_WITHOUT_FALSIFIER], require_falsifiers=True,
        )
        assert result.passed is True
        assert result.n_capped == 1
        cr = result.results[0]
        assert cr.falsifier_status == "absent"
        assert cr.tier_cap is not None
        assert "falsifier" in cr.tier_cap.lower()

    def test_enforcement_no_cap_when_falsifier_executed(self):
        result = verify_claims(
            SAMPLE_RECEIPTS, [CLAIM_WITH_FALSIFIER], require_falsifiers=True,
        )
        assert result.passed is True
        assert result.n_capped == 0
        cr = result.results[0]
        assert cr.falsifier_status == "executed_passed"
        assert cr.tier_cap is None

    def test_warning_severity_never_capped(self):
        result = verify_claims(
            SAMPLE_RECEIPTS, [CLAIM_WARNING], require_falsifiers=True,
        )
        assert result.passed is True
        cr = result.results[0]
        assert cr.falsifier_status == "not_required"
        assert cr.tier_cap is None

    def test_falsifier_summary_counts(self):
        result = verify_claims(
            SAMPLE_RECEIPTS,
            [CLAIM_WITH_FALSIFIER, CLAIM_WITHOUT_FALSIFIER, CLAIM_WARNING],
            require_falsifiers=True,
        )
        s = result.falsifier_summary
        assert s.get("executed_passed", 0) == 1
        assert s.get("absent", 0) == 1
        assert s.get("not_required", 0) == 1

    def test_cap_does_not_cause_failure(self):
        result = verify_claims(
            SAMPLE_RECEIPTS, [CLAIM_WITHOUT_FALSIFIER], require_falsifiers=True,
        )
        assert result.passed is True
        assert result.results[0].passed is True
        assert result.results[0].tier_cap is not None

    def test_to_dict_includes_cap(self):
        result = verify_claims(
            SAMPLE_RECEIPTS, [CLAIM_WITHOUT_FALSIFIER], require_falsifiers=True,
        )
        d = result.results[0].to_dict()
        assert "tier_cap" in d
        assert "falsifier_status" in d
        assert d["falsifier_status"] == "absent"

    def test_to_dict_omits_cap_when_none(self):
        result = verify_claims(SAMPLE_RECEIPTS, [CLAIM_WITH_FALSIFIER], require_falsifiers=True)
        d = result.results[0].to_dict()
        assert "tier_cap" not in d

    def test_claim_set_to_dict_includes_cap_summary(self):
        result = verify_claims(
            SAMPLE_RECEIPTS, [CLAIM_WITHOUT_FALSIFIER], require_falsifiers=True,
        )
        d = result.to_dict()
        assert d["n_capped"] == 1
        assert "falsifier_summary" in d

    def test_claim_set_to_dict_omits_cap_when_zero(self):
        result = verify_claims(SAMPLE_RECEIPTS, [CLAIM_WITH_FALSIFIER])
        d = result.to_dict()
        assert "n_capped" not in d
        assert "falsifier_summary" not in d

    def test_backward_compat_no_falsifiers(self):
        claim = ClaimSpec(
            claim_id="basic", description="Basic check",
            check="receipt_count_ge", params={"min_count": 1},
        )
        result = verify_claims(SAMPLE_RECEIPTS, [claim])
        assert result.passed is True
        assert result.n_capped == 0
        d = result.to_dict()
        assert "passed" in d
        assert "n_claims" in d


# ===========================================================================
# RESIDUAL RISK TESTS
# ===========================================================================

class TestResidualRiskItem:
    def test_to_dict(self):
        item = ResidualRiskItem(
            claim_id="auth_preserves_behavior",
            risk_statement="Auth behavior unverified under session expiry",
            why_tolerated="No auth changes in this PR",
            owner="security-team",
            expiry_condition="Next auth-touching PR",
            next_cheapest_evidence="Run session matrix test",
        )
        d = item.to_dict()
        assert d["claim_id"] == "auth_preserves_behavior"
        assert d["blocking_on_merge"] is False
        assert d["next_cheapest_evidence"] == "Run session matrix test"


class TestResidualRiskLedger:
    def test_empty_ledger(self):
        ledger = ResidualRiskLedger()
        assert ledger.n_items == 0
        assert ledger.n_blocking == 0
        assert ledger.n_unowned == 0

    def test_add_items(self):
        ledger = ResidualRiskLedger()
        ledger.add(ResidualRiskItem(
            claim_id="c1", risk_statement="risk", why_tolerated="ok",
            owner="team", expiry_condition="never", next_cheapest_evidence="test",
        ))
        ledger.add(ResidualRiskItem(
            claim_id="c2", risk_statement="risk", why_tolerated="ok",
            owner="", expiry_condition="", next_cheapest_evidence="test",
            blocking_on_merge=True,
        ))
        assert ledger.n_items == 2
        assert ledger.n_blocking == 1
        assert ledger.n_unowned == 1

    def test_fingerprint_deterministic(self):
        ledger1 = ResidualRiskLedger()
        ledger2 = ResidualRiskLedger()
        item = ResidualRiskItem(
            claim_id="c1", risk_statement="r", why_tolerated="ok",
            owner="o", expiry_condition="e", next_cheapest_evidence="n",
        )
        ledger1.add(item)
        ledger2.add(item)
        assert ledger1.fingerprint() == ledger2.fingerprint()

    def test_to_dict(self):
        ledger = ResidualRiskLedger()
        ledger.add(ResidualRiskItem(
            claim_id="c1", risk_statement="r", why_tolerated="ok",
            owner="o", expiry_condition="e", next_cheapest_evidence="n",
        ))
        d = ledger.to_dict()
        assert d["n_items"] == 1
        assert d["n_blocking"] == 0
        assert d["n_unowned"] == 0
        assert len(d["items"]) == 1


class TestBuildResidualRiskFromClaims:
    def test_capped_claim_creates_risk(self):
        claims = [
            {"claim_id": "c1", "passed": True, "tier_cap": "capped: no named falsifier",
             "severity": "critical"},
        ]
        ledger = build_residual_risk_from_claims(claims)
        assert ledger.n_items == 1
        assert "capped" in ledger.items[0].risk_statement.lower()

    def test_warning_failure_creates_risk(self):
        claims = [
            {"claim_id": "c1", "passed": False, "severity": "warning",
             "expected": ">= 10", "actual": "3"},
        ]
        ledger = build_residual_risk_from_claims(claims)
        assert ledger.n_items == 1
        assert "warning" in ledger.items[0].risk_statement.lower()

    def test_critical_failure_not_residual(self):
        claims = [{"claim_id": "c1", "passed": False, "severity": "critical"}]
        ledger = build_residual_risk_from_claims(claims)
        assert ledger.n_items == 0

    def test_clean_pass_no_risk(self):
        claims = [{"claim_id": "c1", "passed": True, "severity": "critical"}]
        ledger = build_residual_risk_from_claims(claims)
        assert ledger.n_items == 0

    def test_annotations_override_defaults(self):
        claims = [
            {"claim_id": "c1", "passed": True, "tier_cap": "capped", "severity": "critical"},
        ]
        annotations = {
            "c1": {
                "why_tolerated": "PR has no auth changes",
                "owner": "security-team",
                "expiry_condition": "Next auth PR",
                "next_cheapest_evidence": "Run session matrix",
            }
        }
        ledger = build_residual_risk_from_claims(claims, risk_annotations=annotations)
        item = ledger.items[0]
        assert item.owner == "security-team"
        assert item.next_cheapest_evidence == "Run session matrix"


# ===========================================================================
# PROOF DEBT TESTS
# ===========================================================================

class TestProofDebtItem:
    def test_valid_sources(self):
        for source in DEBT_SOURCES:
            item = ProofDebtItem(claim_id="c1", source=source, description="d", repayment_action="a")
            assert item.source == source

    def test_invalid_source_raises(self):
        with pytest.raises(ValueError, match="Invalid debt source"):
            ProofDebtItem(claim_id="c1", source="vibes", description="d", repayment_action="a")

    def test_to_dict(self):
        item = ProofDebtItem(
            claim_id="c1", source="missing_falsifier",
            description="No kill test", repayment_action="Name one", severity="moderate",
        )
        d = item.to_dict()
        assert d["source"] == "missing_falsifier"
        assert d["severity"] == "moderate"


class TestProofDebtLedger:
    def test_empty(self):
        ledger = ProofDebtLedger()
        assert ledger.n_items == 0
        assert ledger.by_source == {}
        assert ledger.by_severity == {}

    def test_by_source(self):
        ledger = ProofDebtLedger()
        ledger.add(ProofDebtItem("c1", "missing_evidence", "d", "a"))
        ledger.add(ProofDebtItem("c2", "missing_falsifier", "d", "a"))
        ledger.add(ProofDebtItem("c3", "missing_falsifier", "d", "a"))
        assert ledger.by_source == {"missing_evidence": 1, "missing_falsifier": 2}

    def test_to_dict(self):
        ledger = ProofDebtLedger()
        ledger.add(ProofDebtItem("c1", "missing_evidence", "d", "a", "severe"))
        d = ledger.to_dict()
        assert d["n_items"] == 1
        assert d["by_source"] == {"missing_evidence": 1}
        assert d["by_severity"] == {"severe": 1}


class TestComputeProofDebt:
    def test_critical_failure_creates_missing_evidence_debt(self):
        claims = [{"claim_id": "c1", "passed": False, "severity": "critical", "expected": ">= 5 receipts"}]
        ledger = compute_proof_debt(claims)
        assert ledger.n_items == 1
        assert ledger.items[0].source == "missing_evidence"
        assert ledger.items[0].severity == "severe"

    def test_warning_failure_no_debt(self):
        claims = [{"claim_id": "c1", "passed": False, "severity": "warning"}]
        ledger = compute_proof_debt(claims)
        assert ledger.n_items == 0

    def test_absent_falsifier_creates_debt(self):
        claims = [
            {"claim_id": "c1", "passed": True, "severity": "critical",
             "falsifier_status": "absent", "tier_cap": "capped: no named falsifier"},
        ]
        ledger = compute_proof_debt(claims)
        assert ledger.n_items == 1
        assert ledger.items[0].source == "missing_falsifier"
        assert "disprove" in ledger.items[0].repayment_action.lower()

    def test_named_falsifier_no_debt(self):
        claims = [{"claim_id": "c1", "passed": True, "severity": "critical", "falsifier_status": "named"}]
        ledger = compute_proof_debt(claims)
        assert ledger.n_items == 0

    def test_unowned_residual_risk_creates_debt(self):
        risks = [{"claim_id": "c1", "owner": "", "expiry_condition": ""}]
        ledger = compute_proof_debt([], residual_risk_items=risks)
        assert ledger.n_items == 1
        assert ledger.items[0].source == "unowned_risk"
        assert ledger.items[0].severity == "severe"

    def test_owned_risk_without_expiry_creates_moderate_debt(self):
        risks = [{"claim_id": "c1", "owner": "team", "expiry_condition": ""}]
        ledger = compute_proof_debt([], residual_risk_items=risks)
        assert ledger.n_items == 1
        assert ledger.items[0].severity == "moderate"

    def test_fully_owned_risk_no_debt(self):
        risks = [{"claim_id": "c1", "owner": "team", "expiry_condition": "next sprint"}]
        ledger = compute_proof_debt([], residual_risk_items=risks)
        assert ledger.n_items == 0

    def test_full_triad_integration(self):
        result = verify_claims(
            SAMPLE_RECEIPTS,
            [CLAIM_WITH_FALSIFIER, CLAIM_WITHOUT_FALSIFIER, CLAIM_WARNING],
            require_falsifiers=True,
        )
        claim_dicts = [r.to_dict() for r in result.results]
        risk_ledger = build_residual_risk_from_claims(claim_dicts)
        debt_ledger = compute_proof_debt(
            claim_dicts, residual_risk_items=[r.to_dict() for r in risk_ledger.items],
        )
        assert result.passed is True
        assert result.n_capped == 1
        assert risk_ledger.n_items == 2
        assert debt_ledger.n_items >= 1
        sources = {item.source for item in debt_ledger.items}
        assert "missing_falsifier" in sources


# ===========================================================================
# TIER CAP DECISION TABLE TESTS
# ===========================================================================

class TestTierCapDecisionTable:
    def test_warning_never_capped(self):
        for (sev, fs), (cap, _) in TIER_CAP_TABLE.items():
            if sev == "warning":
                assert cap is False, f"warning/{fs} should not be capped"

    def test_critical_absent_capped(self):
        cap, reason = TIER_CAP_TABLE[("critical", "absent")]
        assert cap is True
        assert "falsifier" in reason.lower()

    def test_critical_named_capped(self):
        cap, reason = TIER_CAP_TABLE[("critical", "named")]
        assert cap is True
        assert "not executed" in reason.lower()

    def test_critical_executed_passed_uncapped(self):
        cap, reason = TIER_CAP_TABLE[("critical", "executed_passed")]
        assert cap is False
        assert reason is None

    def test_critical_executed_failed_capped(self):
        cap, reason = TIER_CAP_TABLE[("critical", "executed_failed")]
        assert cap is True
        assert "disproved" in reason.lower()

    def test_critical_not_required_uncapped(self):
        cap, reason = TIER_CAP_TABLE[("critical", "not_required")]
        assert cap is False

    def test_table_covers_all_status_severity_pairs(self):
        from assay.claim_verifier import FALSIFIER_STATUSES
        for sev in ALLOWED_SEVERITIES:
            for fs in FALSIFIER_STATUSES:
                assert (sev, fs) in TIER_CAP_TABLE, f"Missing: ({sev}, {fs})"


class TestFalsifierExecution:
    def test_executed_passed_uncapped(self):
        claim = ClaimSpec(
            claim_id="auth_safe", description="Auth behavior preserved",
            check="receipt_type_present", params={"receipt_type": "model_call"},
            severity="critical",
            falsifier=FalsifierSpec(description="Run session matrix", executed=True),
        )
        result = verify_claims(SAMPLE_RECEIPTS, [claim], require_falsifiers=True)
        cr = result.results[0]
        assert cr.falsifier_status == "executed_passed"
        assert cr.tier_cap is None
        assert result.n_capped == 0

    def test_executed_failed_capped(self):
        claim = ClaimSpec(
            claim_id="auth_safe", description="Auth behavior preserved",
            check="receipt_type_present", params={"receipt_type": "model_call"},
            severity="critical",
            falsifier=FalsifierSpec(description="Run session matrix", executed=False),
        )
        result = verify_claims(SAMPLE_RECEIPTS, [claim], require_falsifiers=True)
        cr = result.results[0]
        assert cr.falsifier_status == "executed_failed"
        assert cr.tier_cap is not None
        assert "disproved" in cr.tier_cap.lower()

    def test_named_not_executed_capped(self):
        claim = ClaimSpec(
            claim_id="auth_safe", description="Auth behavior preserved",
            check="receipt_type_present", params={"receipt_type": "model_call"},
            severity="critical",
            falsifier=FalsifierSpec(description="Run session matrix"),
        )
        result = verify_claims(SAMPLE_RECEIPTS, [claim], require_falsifiers=True)
        cr = result.results[0]
        assert cr.falsifier_status == "named"
        assert cr.tier_cap is not None
        assert "not executed" in cr.tier_cap.lower()

    def test_falsifier_recorded_even_without_enforcement(self):
        claim = ClaimSpec(
            claim_id="c1", description="test",
            check="receipt_type_present", params={"receipt_type": "model_call"},
            severity="critical",
            falsifier=FalsifierSpec(description="test", executed=True),
        )
        result = verify_claims(SAMPLE_RECEIPTS, [claim], require_falsifiers=False)
        cr = result.results[0]
        assert cr.falsifier_status == "executed_passed"
        assert cr.tier_cap is None


# ===========================================================================
# RESIDUAL RISK HARDENING TESTS
# ===========================================================================

class TestResidualRiskConstitutional:
    def test_owner_missing_is_unowned(self):
        ledger = ResidualRiskLedger()
        ledger.add(ResidualRiskItem(
            claim_id="c1", risk_statement="r", why_tolerated="ok",
            owner="", expiry_condition="e", next_cheapest_evidence="n",
        ))
        assert ledger.n_unowned == 1

    def test_expiry_missing(self):
        item = ResidualRiskItem(
            claim_id="c1", risk_statement="r", why_tolerated="ok",
            owner="team", expiry_condition="", next_cheapest_evidence="n",
        )
        d = item.to_dict()
        assert d["expiry_condition"] == ""

    def test_next_cheapest_evidence_missing(self):
        item = ResidualRiskItem(
            claim_id="c1", risk_statement="r", why_tolerated="ok",
            owner="team", expiry_condition="e", next_cheapest_evidence="",
        )
        d = item.to_dict()
        assert d["next_cheapest_evidence"] == ""

    def test_blocking_risk_counted(self):
        ledger = ResidualRiskLedger()
        ledger.add(ResidualRiskItem(
            claim_id="c1", risk_statement="r", why_tolerated="ok",
            owner="team", expiry_condition="e", next_cheapest_evidence="n",
            blocking_on_merge=True,
        ))
        ledger.add(ResidualRiskItem(
            claim_id="c2", risk_statement="r", why_tolerated="ok",
            owner="team", expiry_condition="e", next_cheapest_evidence="n",
            blocking_on_merge=False,
        ))
        assert ledger.n_blocking == 1

    def test_critical_failure_never_becomes_residual_risk(self):
        claims = [{"claim_id": "c1", "passed": False, "severity": "critical", "expected": "thing", "actual": "nope"}]
        ledger = build_residual_risk_from_claims(claims)
        assert ledger.n_items == 0


# ===========================================================================
# PROOF POSTURE TESTS
# ===========================================================================

class TestComputeDisposition:
    def test_verified(self):
        assert compute_disposition(n_failed=0, n_capped=0, n_risks_blocking=0, n_debt_severe=0) == "verified"

    def test_capped(self):
        assert compute_disposition(n_failed=0, n_capped=1, n_risks_blocking=0, n_debt_severe=0) == "supported_but_capped"

    def test_incomplete_from_failure(self):
        assert compute_disposition(n_failed=1, n_capped=0, n_risks_blocking=0, n_debt_severe=0) == "incomplete"

    def test_incomplete_from_severe_debt(self):
        assert compute_disposition(n_failed=0, n_capped=0, n_risks_blocking=0, n_debt_severe=2) == "incomplete"

    def test_blocked(self):
        assert compute_disposition(n_failed=0, n_capped=0, n_risks_blocking=1, n_debt_severe=0) == "blocked"

    def test_blocked_overrides_incomplete(self):
        assert compute_disposition(n_failed=1, n_capped=1, n_risks_blocking=1, n_debt_severe=1) == "blocked"


class TestBuildProofPosture:
    def test_empty_posture(self):
        posture = build_proof_posture()
        assert posture.disposition == "verified"
        assert posture.n_claims == 0

    def test_from_dicts(self):
        posture = build_proof_posture(
            claim_set_result={"n_claims": 3, "n_passed": 2, "n_failed": 1, "results": []},
            residual_risk_ledger={"n_items": 1, "n_blocking": 0, "n_unowned": 1, "items": []},
            proof_debt_ledger={"n_items": 2, "by_source": {"missing_falsifier": 2}, "by_severity": {"moderate": 2}, "items": []},
        )
        assert posture.disposition == "incomplete"
        assert posture.n_claims == 3

    def test_to_dict_structure(self):
        posture = build_proof_posture()
        d = posture.to_dict()
        assert "disposition" in d
        assert "claims" in d
        assert "residual_risk" in d
        assert "proof_debt" in d


class TestRenderProofPostureText:
    def test_verified_output(self):
        posture = ProofPosture(n_claims=3, n_passed=3, disposition="verified")
        text = render_proof_posture_text(posture)
        assert "VERIFIED" in text
        assert "3 verified" in text

    def test_capped_output(self):
        posture = ProofPosture(
            n_claims=2, n_passed=2, n_capped=1,
            disposition="supported_but_capped",
            capped_claims=[{"claim_id": "auth", "tier_cap": "capped: no named falsifier", "falsifier_status": "absent"}],
        )
        text = render_proof_posture_text(posture)
        assert "SUPPORTED (capped)" in text
        assert "auth" in text
        assert "falsifier" in text

    def test_debt_output(self):
        posture = ProofPosture(
            n_claims=1, n_passed=1, n_debt_items=1,
            disposition="verified",
            debt_items=[{"claim_id": "c1", "source": "missing_falsifier", "repayment_action": "Name a kill test"}],
        )
        text = render_proof_posture_text(posture)
        assert "1 items owed" in text
        assert "kill test" in text


# ===========================================================================
# CANONICAL SPECIMEN
# ===========================================================================

class TestCanonicalSpecimen:
    def test_canonical_triad_specimen(self):
        claims = [
            ClaimSpec('model_calls_present', 'Model call receipts exist', 'receipt_type_present',
                      {'receipt_type': 'model_call'}, 'critical',
                      FalsifierSpec('Remove all model_call receipts and verify failure', executed=True)),
            ClaimSpec('auth_behavior_preserved', 'Auth behavior is unchanged', 'receipt_type_present',
                      {'receipt_type': 'tool_use'}, 'critical'),
            ClaimSpec('high_receipt_count', 'At least 10 receipts for statistical confidence',
                      'receipt_count_ge', {'min_count': 10}, 'warning'),
            ClaimSpec('timestamps_valid', 'Timestamps are monotonically increasing',
                      'timestamps_monotonic', severity='critical',
                      falsifier=FalsifierSpec('Insert out-of-order timestamp')),
        ]
        result = verify_claims(SAMPLE_RECEIPTS, claims, require_falsifiers=True)
        assert result.passed is True
        assert result.n_capped == 2

        by_id = {r.claim_id: r for r in result.results}
        assert by_id["model_calls_present"].falsifier_status == "executed_passed"
        assert by_id["model_calls_present"].tier_cap is None
        assert by_id["auth_behavior_preserved"].falsifier_status == "absent"
        assert by_id["auth_behavior_preserved"].tier_cap is not None
        assert by_id["high_receipt_count"].falsifier_status == "not_required"
        assert by_id["timestamps_valid"].falsifier_status == "named"
        assert by_id["timestamps_valid"].tier_cap is not None

        claim_dicts = [r.to_dict() for r in result.results]
        risk_annotations = {
            'auth_behavior_preserved': {
                'why_tolerated': 'No auth code changed in this PR',
                'owner': 'security-team',
                'expiry_condition': 'Next PR touching auth/',
                'next_cheapest_evidence': 'Run session expiry matrix',
            },
        }
        risk_ledger = build_residual_risk_from_claims(claim_dicts, risk_annotations=risk_annotations)
        assert risk_ledger.n_items == 3

        debt_ledger = compute_proof_debt(claim_dicts, residual_risk_items=[r.to_dict() for r in risk_ledger.items])
        assert debt_ledger.n_items >= 1
        sources = {item.source for item in debt_ledger.items}
        assert "missing_falsifier" in sources

        posture = build_proof_posture(
            claim_set_result=result.to_dict(),
            residual_risk_ledger=risk_ledger.to_dict(),
            proof_debt_ledger=debt_ledger.to_dict(),
        )
        assert posture.disposition == "incomplete"
        assert posture.n_capped == 2
        assert posture.n_residual_risks == 3
        assert posture.n_debt_items >= 1

        text = render_proof_posture_text(posture)
        assert "INCOMPLETE" in text
        assert "auth_behavior_preserved" in text
        assert len(text.splitlines()) > 3

    def test_golden_fixture_regression(self):
        fixture_path = Path(__file__).parent / "fixtures" / "proof_posture" / "canonical_specimen.json"
        if not fixture_path.exists():
            pytest.skip("Golden fixture not found")
        expected = json.loads(fixture_path.read_text())

        claims = [
            ClaimSpec('model_calls_present', 'Model call receipts exist', 'receipt_type_present',
                      {'receipt_type': 'model_call'}, 'critical',
                      FalsifierSpec('Remove all model_call receipts and verify failure', executed=True)),
            ClaimSpec('auth_behavior_preserved', 'Auth behavior is unchanged', 'receipt_type_present',
                      {'receipt_type': 'tool_use'}, 'critical'),
            ClaimSpec('high_receipt_count', 'At least 10 receipts for statistical confidence',
                      'receipt_count_ge', {'min_count': 10}, 'warning'),
            ClaimSpec('timestamps_valid', 'Timestamps are monotonically increasing',
                      'timestamps_monotonic', severity='critical',
                      falsifier=FalsifierSpec('Insert out-of-order timestamp')),
        ]
        result = verify_claims(SAMPLE_RECEIPTS, claims, require_falsifiers=True)
        claim_dicts = [r.to_dict() for r in result.results]
        risk_annotations = {
            'auth_behavior_preserved': {
                'why_tolerated': 'No auth code changed in this PR',
                'owner': 'security-team',
                'expiry_condition': 'Next PR touching auth/',
                'next_cheapest_evidence': 'Run session expiry matrix',
            },
        }
        risk_ledger = build_residual_risk_from_claims(claim_dicts, risk_annotations=risk_annotations)
        debt_ledger = compute_proof_debt(claim_dicts, residual_risk_items=[r.to_dict() for r in risk_ledger.items])
        posture = build_proof_posture(
            claim_set_result=result.to_dict(),
            residual_risk_ledger=risk_ledger.to_dict(),
            proof_debt_ledger=debt_ledger.to_dict(),
        )
        actual = posture.to_dict()
        assert actual == expected, (
            f"Golden fixture mismatch.\n"
            f"Expected disposition: {expected['disposition']}\n"
            f"Actual disposition: {actual['disposition']}\n"
            f"Diff in claims: {expected['claims']} vs {actual['claims']}"
        )
