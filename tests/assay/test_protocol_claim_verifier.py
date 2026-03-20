"""Tests for protocol claim & contradiction verifiers.

Tests shape validation, lifecycle legality, append-only rules,
backward reference rules, and cross-artifact consistency.
Includes golden fixture tests for JSON-level verification.
"""
import json
import uuid
from pathlib import Path

import pytest

from assay.protocol_claim_verifier import (
    ALLOWED_TRANSITIONS,
    CAT_CONSISTENCY,
    CAT_DEDUP,
    CAT_REFERENCE,
    CAT_SHAPE,
    CAT_TEMPORAL,
    CAT_TRANSITION,
    GENESIS_POSTURE,
    INVARIANT_BY_CODE,
    INVARIANT_CATEGORIES,
    INVARIANT_REGISTRY,
    ChainVerificationResult,
    InvariantEntry,
    invariants_by_category,
    invariants_by_severity,
    invariants_for_artifact,
    verify_claim_assertion,
    verify_claim_chain,
    verify_claim_support_change,
    verify_contradiction_registration,
    verify_contradiction_resolution,
)

GOLDEN_FIXTURES_PATH = Path(__file__).parent / "fixtures" / "protocol_claim_golden.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _claim_id() -> str:
    return f"clm_{uuid.uuid4().hex[:12]}"


def _change_id() -> str:
    return f"csc_{uuid.uuid4().hex[:12]}"


def _contradiction_id() -> str:
    return f"ctr_{uuid.uuid4().hex[:12]}"


def _resolution_id() -> str:
    return f"crr_{uuid.uuid4().hex[:12]}"


def _ts(n: int = 0) -> str:
    return f"2026-03-19T12:{n:02d}:00Z"


def _make_assertion(
    claim_id: str | None = None,
    timestamp: str | None = None,
    **overrides,
) -> dict:
    cid = claim_id or _claim_id()
    return {
        "claim_id": cid,
        "artifact_type": "claim_assertion",
        "schema_version": "0.1.0",
        "timestamp": timestamp or _ts(0),
        "episode_id": "ep-001",
        "claim_text": "Redis is the bottleneck",
        "claim_type": "FACTUAL",
        "checkable": True,
        "basis": {
            "basis_type": "extracted",
            "basis_refs": [{"ref_type": "receipt", "ref_id": "r_abc", "ref_role": "supporting"}],
            "proof_tier_at_assertion": "CHECKED",
        },
        **overrides,
    }


def _make_support_change(
    claim_id: str,
    prior: str,
    new: str,
    change_type: str = "evidence_added",
    timestamp: str | None = None,
    **overrides,
) -> dict:
    return {
        "change_id": _change_id(),
        "artifact_type": "claim_support_change",
        "schema_version": "0.1.0",
        "timestamp": timestamp or _ts(1),
        "claim_id": claim_id,
        "episode_id": "ep-001",
        "prior_support_status": prior,
        "new_support_status": new,
        "change_type": change_type,
        "evidence_refs": [{"ref_type": "receipt", "ref_id": "r_xyz", "ref_role": "supporting"}],
        **overrides,
    }


def _make_contradiction(
    claim_a_id: str,
    claim_b_id: str,
    contradiction_id: str | None = None,
    timestamp: str | None = None,
    **overrides,
) -> dict:
    # Enforce lexicographic ordering
    a, b = sorted([claim_a_id, claim_b_id])
    return {
        "contradiction_id": contradiction_id or _contradiction_id(),
        "artifact_type": "contradiction_registration",
        "schema_version": "0.1.0",
        "timestamp": timestamp or _ts(2),
        "episode_id": "ep-001",
        "claim_a_id": a,
        "claim_b_id": b,
        "conflict_type": "direct_negation",
        "severity": "high",
        "detection": {
            "detection_method": "automated_verification",
            "detection_confidence": 0.9,
            "detector_id": "test",
            "detection_evidence_refs": [
                {"ref_type": "receipt", "ref_id": "r_det", "ref_role": "supporting"}
            ],
        },
        **overrides,
    }


def _make_resolution(
    contradiction_id: str,
    outcome: str = "claim_a_prevails",
    timestamp: str | None = None,
    **overrides,
) -> dict:
    return {
        "resolution_id": _resolution_id(),
        "artifact_type": "contradiction_resolution",
        "schema_version": "0.1.0",
        "timestamp": timestamp or _ts(3),
        "contradiction_id": contradiction_id,
        "episode_id": "ep-001",
        "resolution_outcome": outcome,
        "resolution_basis": {
            "authority_type": "automated_verification",
            "decision_receipt_id": None,
            "evidence_refs": [
                {"ref_type": "receipt", "ref_id": "r_res", "ref_role": "supporting"}
            ],
            "prevailing_proof_tier": "TOOL_VERIFIED",
        },
        **overrides,
    }


# ===================================================================
# CLAIM ASSERTION SHAPE TESTS
# ===================================================================


class TestClaimAssertionShape:
    def test_valid_assertion(self):
        results = verify_claim_assertion(_make_assertion())
        assert all(r.passed for r in results), [r.message for r in results if not r.passed]

    def test_missing_required_fields(self):
        results = verify_claim_assertion({"claim_id": _claim_id()})
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 5  # many missing fields

    def test_bad_claim_id_format(self):
        results = verify_claim_assertion(_make_assertion(claim_id="bad_id"))
        failed = [r for r in results if not r.passed and "id_format" in r.check_name]
        assert len(failed) == 1

    def test_bad_claim_type(self):
        a = _make_assertion()
        a["claim_type"] = "INVALID"
        results = verify_claim_assertion(a)
        failed = [r for r in results if not r.passed and "claim_type" in r.check_name]
        assert len(failed) == 1

    def test_text_too_long(self):
        a = _make_assertion()
        a["claim_text"] = "x" * 501
        results = verify_claim_assertion(a)
        failed = [r for r in results if not r.passed and "text_length" in r.check_name]
        assert len(failed) == 1

    def test_empty_basis_refs(self):
        a = _make_assertion()
        a["basis"]["basis_refs"] = []
        results = verify_claim_assertion(a)
        failed = [r for r in results if not r.passed and "basis_refs" in r.check_name]
        assert len(failed) == 1

    def test_bad_proof_tier(self):
        a = _make_assertion()
        a["basis"]["proof_tier_at_assertion"] = "MEGA"
        results = verify_claim_assertion(a)
        failed = [r for r in results if not r.passed and "proof_tier" in r.check_name]
        assert len(failed) == 1

    def test_parent_claim_id_format(self):
        a = _make_assertion(parent_claim_id="not_a_claim_id")
        # Manually set since helper doesn't include optional fields
        a["parent_claim_id"] = "not_a_claim_id"
        results = verify_claim_assertion(a)
        failed = [r for r in results if not r.passed and "parent_format" in r.check_name]
        assert len(failed) == 1


# ===================================================================
# CLAIM SUPPORT CHANGE SHAPE TESTS
# ===================================================================


class TestSupportChangeShape:
    def test_valid_change(self):
        cid = _claim_id()
        results = verify_claim_support_change(
            _make_support_change(cid, "ASSERTED", "SUPPORTED")
        )
        assert all(r.passed for r in results), [r.message for r in results if not r.passed]

    def test_missing_required_fields(self):
        results = verify_claim_support_change({"change_id": _change_id()})
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 5

    def test_bad_change_id_format(self):
        sc = _make_support_change(_claim_id(), "ASSERTED", "SUPPORTED")
        sc["change_id"] = "bad"
        results = verify_claim_support_change(sc)
        failed = [r for r in results if not r.passed and "id_format" in r.check_name]
        assert len(failed) == 1

    def test_forbidden_transition_from_retracted(self):
        sc = _make_support_change(_claim_id(), "RETRACTED", "SUPPORTED")
        results = verify_claim_support_change(sc)
        failed = [r for r in results if not r.passed and "transition" in r.check_name]
        assert len(failed) == 1

    def test_all_allowed_transitions_pass(self):
        for prior, new in ALLOWED_TRANSITIONS:
            sc = _make_support_change(_claim_id(), prior, new)
            if new == "SUPPORTED":
                sc["evidence_refs"] = [{"ref_type": "receipt", "ref_id": "r", "ref_role": "supporting"}]
            if prior == "CONTRADICTED" and new in ("SUPPORTED", "WEAKENED"):
                sc["change_type"] = "contradiction_resolved"
                sc["contradiction_id"] = _contradiction_id()
            results = verify_claim_support_change(sc)
            transition_fails = [r for r in results if not r.passed and "transition" in r.check_name]
            assert len(transition_fails) == 0, f"{prior}->{new} should be allowed"

    def test_contradiction_change_requires_contradiction_id(self):
        sc = _make_support_change(
            _claim_id(), "ASSERTED", "CONTRADICTED",
            change_type="contradiction_registered",
        )
        sc.pop("contradiction_id", None)
        results = verify_claim_support_change(sc)
        failed = [r for r in results if not r.passed and "contradiction_ref" in r.check_name]
        assert len(failed) == 1

    def test_governance_change_requires_decision_receipt_id(self):
        sc = _make_support_change(
            _claim_id(), "ASSERTED", "RETRACTED",
            change_type="governance_decision",
        )
        results = verify_claim_support_change(sc)
        failed = [r for r in results if not r.passed and "decision_ref" in r.check_name]
        assert len(failed) == 1

    def test_supported_requires_evidence(self):
        sc = _make_support_change(_claim_id(), "ASSERTED", "SUPPORTED")
        sc["evidence_refs"] = []
        results = verify_claim_support_change(sc)
        failed = [r for r in results if not r.passed and "supported_evidence" in r.check_name]
        assert len(failed) == 1

    def test_support_change_timestamp_must_be_iso8601(self):
        sc = _make_support_change(_claim_id(), "ASSERTED", "SUPPORTED")
        sc["timestamp"] = "not-a-timestamp"
        results = verify_claim_support_change(sc)
        failed = [r for r in results if not r.passed and "timestamp" in r.check_name]
        assert len(failed) == 1


# ===================================================================
# CONTRADICTION REGISTRATION SHAPE TESTS
# ===================================================================


class TestContradictionRegistrationShape:
    def test_valid_registration(self):
        a, b = sorted([_claim_id(), _claim_id()])
        results = verify_contradiction_registration(_make_contradiction(a, b))
        assert all(r.passed for r in results), [r.message for r in results if not r.passed]

    def test_self_contradiction_rejected(self):
        cid = _claim_id()
        c = _make_contradiction(cid, cid)
        # Override the sorted enforcement in helper
        c["claim_a_id"] = cid
        c["claim_b_id"] = cid
        results = verify_contradiction_registration(c)
        failed = [r for r in results if not r.passed and "self" in r.check_name]
        assert len(failed) == 1

    def test_lexicographic_ordering_enforced(self):
        a, b = _claim_id(), _claim_id()
        if a < b:
            a, b = b, a  # swap to violate ordering
        c = _make_contradiction(a, b)
        c["claim_a_id"] = a
        c["claim_b_id"] = b
        results = verify_contradiction_registration(c)
        failed = [r for r in results if not r.passed and "ordering" in r.check_name]
        assert len(failed) == 1

    def test_missing_detection_evidence(self):
        a, b = sorted([_claim_id(), _claim_id()])
        c = _make_contradiction(a, b)
        c["detection"]["detection_evidence_refs"] = []
        results = verify_contradiction_registration(c)
        failed = [r for r in results if not r.passed and "detection_evidence" in r.check_name]
        assert len(failed) == 1

    def test_bad_severity(self):
        a, b = sorted([_claim_id(), _claim_id()])
        c = _make_contradiction(a, b)
        c["severity"] = "mega"
        results = verify_contradiction_registration(c)
        failed = [r for r in results if not r.passed and "severity" in r.check_name]
        assert len(failed) == 1

    def test_confidence_out_of_range(self):
        a, b = sorted([_claim_id(), _claim_id()])
        c = _make_contradiction(a, b)
        c["detection"]["detection_confidence"] = 1.5
        results = verify_contradiction_registration(c)
        failed = [r for r in results if not r.passed and "confidence" in r.check_name]
        assert len(failed) == 1


# ===================================================================
# CONTRADICTION RESOLUTION SHAPE TESTS
# ===================================================================


class TestContradictionResolutionShape:
    def test_valid_resolution(self):
        results = verify_contradiction_resolution(
            _make_resolution(_contradiction_id())
        )
        assert all(r.passed for r in results), [r.message for r in results if not r.passed]

    def test_reconciled_requires_superseding_claim(self):
        r = _make_resolution(_contradiction_id(), outcome="reconciled")
        results = verify_contradiction_resolution(r)
        failed = [v for v in results if not v.passed and "reconciled_claim" in v.check_name]
        assert len(failed) == 1

    def test_prevails_requires_evidence(self):
        r = _make_resolution(_contradiction_id(), outcome="claim_a_prevails")
        r["resolution_basis"]["evidence_refs"] = []
        results = verify_contradiction_resolution(r)
        failed = [v for v in results if not v.passed and "prevails_evidence" in v.check_name]
        assert len(failed) == 1

    def test_bad_outcome(self):
        r = _make_resolution(_contradiction_id(), outcome="everybody_wins")
        results = verify_contradiction_resolution(r)
        failed = [v for v in results if not v.passed and "outcome" in v.check_name]
        assert len(failed) == 1


# ===================================================================
# CHAIN VERIFICATION TESTS
# ===================================================================


class TestChainVerification:
    """Tests for cross-artifact lifecycle legality."""

    def test_happy_path_full_chain(self):
        """Complete lifecycle: assert -> support -> contradict -> resolve."""
        cid_a = _claim_id()
        cid_b = _claim_id()
        a_id, b_id = sorted([cid_a, cid_b])

        ctrid = _contradiction_id()

        assertions = [
            _make_assertion(claim_id=cid_a, timestamp=_ts(0)),
            _make_assertion(claim_id=cid_b, timestamp=_ts(0)),
        ]
        support_changes = [
            _make_support_change(cid_a, "ASSERTED", "SUPPORTED", timestamp=_ts(1)),
            _make_support_change(cid_b, "ASSERTED", "SUPPORTED", timestamp=_ts(1)),
            _make_support_change(
                cid_a, "SUPPORTED", "CONTRADICTED",
                change_type="contradiction_registered",
                contradiction_id=ctrid,
                timestamp=_ts(3),
            ),
            _make_support_change(
                cid_b, "SUPPORTED", "CONTRADICTED",
                change_type="contradiction_registered",
                contradiction_id=ctrid,
                timestamp=_ts(3),
            ),
        ]
        contradictions = [
            _make_contradiction(a_id, b_id, contradiction_id=ctrid, timestamp=_ts(2)),
        ]
        resolutions = [
            _make_resolution(ctrid, outcome="claim_a_prevails", timestamp=_ts(4)),
        ]

        result = verify_claim_chain(assertions, support_changes, contradictions, resolutions)
        errors = [r for r in result.results if not r.passed and r.severity == "error"]
        assert result.passed, [r.message for r in errors]

    def test_support_change_without_claim(self):
        """Support change referencing nonexistent claim."""
        sc = _make_support_change("clm_000000000000", "ASSERTED", "SUPPORTED")
        result = verify_claim_chain([], [sc], [], [])
        assert not result.passed
        assert any("claim_exists" in r.check_name for r in result.results if not r.passed)

    def test_retracted_is_terminal(self):
        """No support changes after RETRACTED."""
        cid = _claim_id()
        assertions = [_make_assertion(claim_id=cid, timestamp=_ts(0))]
        changes = [
            _make_support_change(cid, "ASSERTED", "RETRACTED",
                                 change_type="retraction", timestamp=_ts(1)),
            _make_support_change(cid, "RETRACTED", "SUPPORTED", timestamp=_ts(2)),
        ]
        result = verify_claim_chain(assertions, changes, [], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "terminal" in r.check_name]
        assert len(errors) >= 1

    def test_prior_status_chain_consistency(self):
        """Each change's prior must match previous change's new."""
        cid = _claim_id()
        assertions = [_make_assertion(claim_id=cid, timestamp=_ts(0))]
        changes = [
            _make_support_change(cid, "ASSERTED", "SUPPORTED", timestamp=_ts(1)),
            # Bug: prior says ASSERTED but should be SUPPORTED
            _make_support_change(cid, "ASSERTED", "WEAKENED", timestamp=_ts(2)),
        ]
        result = verify_claim_chain(assertions, changes, [], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "prior_mismatch" in r.check_name]
        assert len(errors) >= 1

    def test_support_change_cannot_precede_claim_assertion(self):
        """Support changes must not predate the assertion they modify."""
        cid = _claim_id()
        assertions = [_make_assertion(claim_id=cid, timestamp=_ts(2))]
        changes = [
            _make_support_change(cid, "ASSERTED", "SUPPORTED", timestamp=_ts(1)),
        ]
        result = verify_claim_chain(assertions, changes, [], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "after_assertion" in r.check_name]
        assert len(errors) == 1

    def test_contradiction_claims_must_exist(self):
        """Contradiction referencing nonexistent claims."""
        c = _make_contradiction("clm_000000000000", "clm_111111111111")
        result = verify_claim_chain([], [], [c], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "claim_a_exists" in r.check_name or "claim_b_exists" in r.check_name]
        assert len(errors) >= 1

    def test_resolution_must_reference_existing_contradiction(self):
        """Resolution referencing nonexistent contradiction."""
        r = _make_resolution("ctr_000000000000")
        result = verify_claim_chain([], [], [], [r])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "contradiction_exists" in r.check_name]
        assert len(errors) >= 1

    def test_resolution_must_be_after_registration(self):
        """Resolution timestamp before contradiction registration."""
        cid_a, cid_b = sorted([_claim_id(), _claim_id()])
        ctrid = _contradiction_id()
        assertions = [
            _make_assertion(claim_id=cid_a, timestamp=_ts(0)),
            _make_assertion(claim_id=cid_b, timestamp=_ts(0)),
        ]
        contradictions = [_make_contradiction(cid_a, cid_b, contradiction_id=ctrid, timestamp=_ts(5))]
        resolutions = [_make_resolution(ctrid, timestamp=_ts(3))]  # before registration

        result = verify_claim_chain(assertions, [], contradictions, resolutions)
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "after_registration" in r.check_name]
        assert len(errors) == 1

    def test_duplicate_claim_id_rejected(self):
        """Two assertions with same claim_id."""
        cid = _claim_id()
        assertions = [
            _make_assertion(claim_id=cid, timestamp=_ts(0)),
            _make_assertion(claim_id=cid, timestamp=_ts(1)),
        ]
        result = verify_claim_chain(assertions, [], [], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "duplicate_claim" in r.check_name]
        assert len(errors) >= 1

    def test_duplicate_unresolved_contradiction_rejected(self):
        """Two unresolved contradictions for same claim pair."""
        cid_a, cid_b = sorted([_claim_id(), _claim_id()])
        assertions = [
            _make_assertion(claim_id=cid_a, timestamp=_ts(0)),
            _make_assertion(claim_id=cid_b, timestamp=_ts(0)),
        ]
        contradictions = [
            _make_contradiction(cid_a, cid_b, timestamp=_ts(1)),
            _make_contradiction(cid_a, cid_b, timestamp=_ts(2)),
        ]
        result = verify_claim_chain(assertions, [], contradictions, [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "dedup" in r.check_name]
        assert len(errors) >= 1

    def test_re_registration_after_resolution_allowed(self):
        """Re-registering a contradiction after resolution is legal."""
        cid_a, cid_b = sorted([_claim_id(), _claim_id()])
        ctrid1 = _contradiction_id()
        ctrid2 = _contradiction_id()

        assertions = [
            _make_assertion(claim_id=cid_a, timestamp=_ts(0)),
            _make_assertion(claim_id=cid_b, timestamp=_ts(0)),
        ]
        contradictions = [
            _make_contradiction(cid_a, cid_b, contradiction_id=ctrid1, timestamp=_ts(1)),
            _make_contradiction(cid_a, cid_b, contradiction_id=ctrid2, timestamp=_ts(4)),
        ]
        resolutions = [
            _make_resolution(ctrid1, outcome="claim_a_prevails", timestamp=_ts(3)),
        ]

        result = verify_claim_chain(assertions, [], contradictions, resolutions)
        # ctrid1 is resolved, ctrid2 is new — should be fine
        dedup_errors = [r for r in result.results if not r.passed and "dedup" in r.check_name]
        assert len(dedup_errors) == 0

    def test_backward_reference_violation(self):
        """Contradiction timestamp before its claims."""
        cid_a, cid_b = sorted([_claim_id(), _claim_id()])
        assertions = [
            _make_assertion(claim_id=cid_a, timestamp=_ts(5)),
            _make_assertion(claim_id=cid_b, timestamp=_ts(5)),
        ]
        contradictions = [
            _make_contradiction(cid_a, cid_b, timestamp=_ts(1)),  # before claims
        ]
        result = verify_claim_chain(assertions, [], contradictions, [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "backward" in r.check_name]
        assert len(errors) >= 1

    def test_resolution_consistency_warning(self):
        """Resolution with prevails but no corresponding support change."""
        cid_a, cid_b = sorted([_claim_id(), _claim_id()])
        ctrid = _contradiction_id()

        assertions = [
            _make_assertion(claim_id=cid_a, timestamp=_ts(0)),
            _make_assertion(claim_id=cid_b, timestamp=_ts(0)),
        ]
        contradictions = [_make_contradiction(cid_a, cid_b, contradiction_id=ctrid, timestamp=_ts(1))]
        resolutions = [_make_resolution(ctrid, outcome="claim_a_prevails", timestamp=_ts(2))]

        result = verify_claim_chain(assertions, [], contradictions, resolutions)
        # Should pass (no errors) but have a warning
        warnings = [r for r in result.results if r.severity == "warning"]
        assert len(warnings) >= 1
        assert result.passed  # warnings don't fail verification

    def test_parent_claim_backward_reference(self):
        """Parent claim must have earlier timestamp."""
        parent_id = _claim_id()
        child_id = _claim_id()
        assertions = [
            _make_assertion(claim_id=parent_id, timestamp=_ts(5)),
            {**_make_assertion(claim_id=child_id, timestamp=_ts(1)), "parent_claim_id": parent_id},
        ]
        result = verify_claim_chain(assertions, [], [], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "parent_backward" in r.check_name]
        assert len(errors) >= 1

    def test_genesis_posture_is_asserted(self):
        """First support change must have prior_support_status=ASSERTED (genesis invariant)."""
        cid = _claim_id()
        assertions = [_make_assertion(claim_id=cid, timestamp=_ts(0))]
        # First change claims prior is SUPPORTED, but genesis is ASSERTED
        changes = [
            _make_support_change(cid, "SUPPORTED", "WEAKENED", timestamp=_ts(1)),
        ]
        result = verify_claim_chain(assertions, changes, [], [])
        assert not result.passed
        errors = [r for r in result.results if not r.passed and "prior_mismatch" in r.check_name]
        assert len(errors) >= 1


# ===================================================================
# GOLDEN FIXTURE TESTS
# ===================================================================


class TestGoldenFixtures:
    """Tests verifiers against JSON golden fixtures."""

    @pytest.fixture
    def golden(self):
        with open(GOLDEN_FIXTURES_PATH) as f:
            return json.load(f)

    def test_valid_claim_assertion(self, golden):
        fixture = golden["valid_claim_assertion"]
        artifact = {k: v for k, v in fixture.items() if k != "expected_result"}
        results = verify_claim_assertion(artifact)
        failed = [r for r in results if not r.passed]
        assert len(failed) == 0, [r.message for r in failed]

    def test_valid_support_chain(self, golden):
        fixture = golden["valid_support_chain"]
        result = verify_claim_chain(
            [fixture["assertion"]],
            fixture["changes"],
            [], [],
        )
        assert result.passed, [r.message for r in result.results if not r.passed]

    def test_valid_contradiction_registration(self, golden):
        fixture = golden["valid_contradiction_registration"]
        artifact = {k: v for k, v in fixture.items() if k != "expected_result"}
        results = verify_contradiction_registration(artifact)
        failed = [r for r in results if not r.passed]
        assert len(failed) == 0, [r.message for r in failed]

    def test_valid_contradiction_resolution(self, golden):
        fixture = golden["valid_contradiction_resolution"]
        artifact = {k: v for k, v in fixture.items() if k != "expected_result"}
        results = verify_contradiction_resolution(artifact)
        failed = [r for r in results if not r.passed]
        assert len(failed) == 0, [r.message for r in failed]

    def test_invalid_retracted_terminal(self, golden):
        fixture = golden["invalid_retracted_terminal"]
        result = verify_claim_chain(
            [fixture["assertion"]],
            fixture["changes"],
            [], [],
        )
        assert not result.passed
        assert any(
            fixture["expected_invariant"] in r.check_name
            for r in result.results if not r.passed
        )

    def test_invalid_self_contradiction(self, golden):
        fixture = golden["invalid_self_contradiction"]
        artifact = {k: v for k, v in fixture.items()
                    if k not in ("expected_result", "expected_invariant", "_description")}
        results = verify_contradiction_registration(artifact)
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 1
        assert any(fixture["expected_invariant"] in r.check_name for r in failed)

    def test_invalid_backward_ref_violation(self, golden):
        fixture = golden["invalid_backward_ref_violation"]
        result = verify_claim_chain(
            fixture["claims"],
            [],
            [fixture["contradiction"]],
            [],
        )
        assert not result.passed
        assert any(
            fixture["expected_invariant"] in r.check_name
            for r in result.results if not r.passed
        )


# ===================================================================
# INVARIANT REGISTRY TESTS
# ===================================================================


class TestInvariantRegistry:
    """Tests for the constitutional invariant registry."""

    def test_registry_is_nonempty(self):
        assert len(INVARIANT_REGISTRY) > 0

    def test_all_entries_are_frozen(self):
        for entry in INVARIANT_REGISTRY:
            assert isinstance(entry, InvariantEntry)

    def test_no_duplicate_codes(self):
        codes = [entry.code for entry in INVARIANT_REGISTRY]
        assert len(codes) == len(set(codes)), f"Duplicate codes: {[c for c in codes if codes.count(c) > 1]}"

    def test_lookup_by_code_covers_all_entries(self):
        assert len(INVARIANT_BY_CODE) == len(INVARIANT_REGISTRY)
        for entry in INVARIANT_REGISTRY:
            assert entry.code in INVARIANT_BY_CODE
            assert INVARIANT_BY_CODE[entry.code] is entry

    def test_all_severities_are_valid(self):
        for entry in INVARIANT_REGISTRY:
            assert entry.severity in ("error", "warning"), f"{entry.code} has invalid severity: {entry.severity}"

    def test_all_categories_are_valid(self):
        for entry in INVARIANT_REGISTRY:
            assert entry.category in INVARIANT_CATEGORIES, f"{entry.code} has invalid category: {entry.category}"

    def test_all_categories_have_at_least_one_entry(self):
        for cat in INVARIANT_CATEGORIES:
            entries = invariants_by_category(cat)
            assert len(entries) > 0, f"Category '{cat}' has no entries"

    def test_all_artifact_classes_are_known(self):
        known = {"claim_assertion", "claim_support_change", "contradiction_registration", "contradiction_resolution"}
        for entry in INVARIANT_REGISTRY:
            for art in entry.artifacts:
                assert art in known, f"{entry.code} references unknown artifact class: {art}"

    def test_all_meanings_are_nonempty(self):
        for entry in INVARIANT_REGISTRY:
            assert entry.meaning.strip(), f"{entry.code} has empty meaning"

    def test_genesis_posture_is_asserted(self):
        """GENESIS_POSTURE constant matches the documented constitutional default."""
        assert GENESIS_POSTURE == "ASSERTED"

    def test_only_one_warning_invariant(self):
        """Only resolution/support consistency is a warning; everything else is error."""
        warnings = invariants_by_severity("warning")
        assert len(warnings) == 1
        assert warnings[0].code == "chain_resolution_support_consistency"
        assert warnings[0].category == CAT_CONSISTENCY

    def test_invariants_for_artifact_filters_correctly(self):
        claim_invs = invariants_for_artifact("claim_assertion")
        assert len(claim_invs) > 0
        for entry in claim_invs:
            assert "claim_assertion" in entry.artifacts

    def test_invariants_by_category_filters_correctly(self):
        temporal = invariants_by_category(CAT_TEMPORAL)
        assert len(temporal) > 0
        for entry in temporal:
            assert entry.category == CAT_TEMPORAL

    def test_every_artifact_type_has_invariants(self):
        """Every known artifact class has at least one applicable invariant."""
        known = {"claim_assertion", "claim_support_change", "contradiction_registration", "contradiction_resolution"}
        for art in known:
            invs = invariants_for_artifact(art)
            assert len(invs) > 0, f"No invariants for artifact type '{art}'"

    def test_unknown_artifact_returns_empty(self):
        """Typo'd artifact type returns empty tuple, not error."""
        assert invariants_for_artifact("claim_assertons") == ()

    def test_warning_invariants_are_intentionally_sparse(self):
        """Warnings should be rare and explicit — most invariants are errors."""
        warnings = invariants_by_severity("warning")
        errors = invariants_by_severity("error")
        assert len(warnings) < len(errors), "Warnings should be much rarer than errors"
