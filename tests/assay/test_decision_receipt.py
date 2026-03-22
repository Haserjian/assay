"""Decision Receipt v0.1.0 — conformance and invariant tests.

Uses the 6 golden fixtures from the spec as positive tests,
plus one negative test per forbidden state and invariant.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from assay.decision_receipt import (
    AUTHORITY_LAYER_RANK,
    LAYER_FORBIDDEN,
    LAYER_INVARIANTS,
    LAYER_SHAPE,
    PROOF_TIER_RANK,
    TierEscalationError,
    assert_tier_monotonic,
    validate_decision_receipt,
    validate_invariants,
    validate_shape,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "decision_receipt"


def _load(name: str) -> dict:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text())


# ---------------------------------------------------------------------------
# Golden fixtures: all 6 must pass full validation
# ---------------------------------------------------------------------------

class TestGoldenFixtures:

    @pytest.mark.parametrize("name", [
        "approve", "abstain", "defer", "rollback", "conflict", "refuse",
    ])
    def test_golden_fixture_validates(self, name):
        receipt = _load(name)
        result = validate_decision_receipt(receipt)
        assert result.valid, (
            f"Golden fixture '{name}' failed validation:\n"
            + "\n".join(f"  [{e.rule}] {e.message}" for e in result.errors)
        )

    def test_all_fixtures_have_decision_subject(self):
        for name in ("approve", "abstain", "defer", "rollback", "conflict", "refuse"):
            receipt = _load(name)
            assert "decision_subject" in receipt, f"{name} missing decision_subject"
            assert receipt["decision_subject"], f"{name} has empty decision_subject"

    def test_all_fixtures_have_authority_scope(self):
        for name in ("approve", "abstain", "defer", "rollback", "conflict", "refuse"):
            receipt = _load(name)
            assert "authority_scope" in receipt, f"{name} missing authority_scope"

    def test_conflict_fixture_has_conflict_refs(self):
        receipt = _load("conflict")
        assert receipt.get("conflict_refs"), "conflict fixture should have conflict_refs"


# ---------------------------------------------------------------------------
# Shape validation
# ---------------------------------------------------------------------------

class TestShapeValidation:

    def test_missing_required_field_fails(self):
        receipt = _load("approve")
        del receipt["verdict"]
        result = validate_shape(receipt)
        assert not result.valid
        assert any(e.field == "verdict" for e in result.errors)

    def test_wrong_receipt_type_fails(self):
        receipt = _load("approve")
        receipt["receipt_type"] = "execution_v1"
        result = validate_shape(receipt)
        assert not result.valid

    def test_wrong_receipt_version_fails(self):
        receipt = _load("approve")
        receipt["receipt_version"] = "0.2.0"
        result = validate_shape(receipt)
        assert not result.valid

    def test_invalid_verdict_fails(self):
        receipt = _load("approve")
        receipt["verdict"] = "MAYBE"
        result = validate_shape(receipt)
        assert not result.valid

    def test_invalid_disposition_fails(self):
        receipt = _load("approve")
        receipt["disposition"] = "yolo"
        result = validate_shape(receipt)
        assert not result.valid

    def test_invalid_source_organ_fails(self):
        receipt = _load("approve")
        receipt["source_organ"] = "unknown_system"
        result = validate_shape(receipt)
        assert not result.valid
        assert any(e.field == "source_organ" for e in result.errors)

    def test_invalid_proof_tier_at_decision_fails(self):
        receipt = _load("approve")
        receipt["proof_tier_at_decision"] = "MEGA_VERIFIED"
        result = validate_shape(receipt)
        assert not result.valid
        assert any(e.field == "proof_tier_at_decision" for e in result.errors)

    def test_invalid_dissent_severity_fails(self):
        receipt = _load("conflict")
        receipt["dissent"]["dissent_severity"] = "rage"
        result = validate_shape(receipt)
        assert not result.valid
        assert any("dissent_severity" in (e.field or "") for e in result.errors)

    def test_invalid_ref_role_fails(self):
        receipt = _load("approve")
        receipt["evidence_refs"] = [{
            "ref_type": "receipt", "ref_id": "x", "ref_role": "context",
        }]
        result = validate_shape(receipt)
        assert not result.valid
        assert any("ref_role" in (e.field or "") for e in result.errors)

    def test_evidence_ref_missing_required_field_fails(self):
        receipt = _load("approve")
        receipt["evidence_refs"] = [{"ref_type": "receipt"}]
        result = validate_shape(receipt)
        assert not result.valid


# ---------------------------------------------------------------------------
# I-1: Verdict-disposition coherence
# ---------------------------------------------------------------------------

class TestI1VerdictDisposition:

    def test_approve_block_rejected(self):
        r = _load("approve")
        r["disposition"] = "block"
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-1" in e.rule for e in result.errors)

    def test_refuse_execute_rejected(self):
        r = _load("refuse")
        r["disposition"] = "execute"
        result = validate_invariants(r)
        assert not result.valid

    def test_abstain_without_reason_rejected(self):
        r = _load("abstain")
        r["abstention_reason"] = None
        result = validate_invariants(r)
        assert not result.valid
        assert any("abstention_reason" in (e.field or "") for e in result.errors)

    def test_rollback_without_supersedes_rejected(self):
        r = _load("rollback")
        r["supersedes"] = None
        result = validate_invariants(r)
        assert not result.valid

    def test_conflict_without_refs_or_dissent_rejected(self):
        r = _load("conflict")
        r["conflict_refs"] = []
        r["dissent"] = None
        result = validate_invariants(r)
        assert not result.valid

    def test_defer_with_obligation_needs_obligations(self):
        r = _load("defer")
        r["disposition"] = "defer_with_obligation"
        r["obligations_created"] = []
        result = validate_invariants(r)
        assert not result.valid


# ---------------------------------------------------------------------------
# I-2: Authority-class constraints
# ---------------------------------------------------------------------------

class TestI2AuthorityClass:

    def test_advisory_cannot_rollback(self):
        r = _load("rollback")
        r["authority_class"] = "ADVISORY"
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-2" in e.rule or "ADVISORY" in e.message for e in result.errors)

    def test_advisory_cannot_conflict(self):
        r = _load("conflict")
        r["authority_class"] = "ADVISORY"
        result = validate_invariants(r)
        assert not result.valid

    def test_advisory_can_defer(self):
        r = _load("defer")
        r["authority_class"] = "ADVISORY"
        result = validate_invariants(r)
        i2_errors = [e for e in result.errors if "I-2" in e.rule]
        assert len(i2_errors) == 0

    def test_overriding_needs_delegation(self):
        r = _load("approve")
        r["authority_class"] = "OVERRIDING"
        r["delegated_from"] = None
        result = validate_invariants(r)
        assert not result.valid
        assert any("delegated_from" in (e.field or "") for e in result.errors)


# ---------------------------------------------------------------------------
# I-3: Evidence sufficiency
# ---------------------------------------------------------------------------

class TestI3EvidenceSufficiency:

    def test_approve_with_insufficient_evidence_rejected(self):
        r = _load("approve")
        r["evidence_sufficient"] = False
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-3" in e.rule for e in result.errors)

    def test_refuse_insufficient_needs_gaps(self):
        r = _load("refuse")
        r["evidence_sufficient"] = False
        r["evidence_gaps"] = []
        result = validate_invariants(r)
        assert not result.valid


# ---------------------------------------------------------------------------
# I-4: Proof tier monotonicity
# ---------------------------------------------------------------------------

class TestI4ProofTier:

    def test_achieved_below_minimum_with_approve_rejected(self):
        r = _load("approve")
        r["proof_tier_achieved"] = "DRAFT"
        r["proof_tier_minimum_required"] = "TOOL_VERIFIED"
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-4" in e.rule for e in result.errors)

    def test_achieved_below_minimum_with_refuse_allowed(self):
        r = _load("refuse")
        r["proof_tier_achieved"] = "DRAFT"
        r["proof_tier_minimum_required"] = "CHECKED"
        result = validate_invariants(r)
        i4_errors = [e for e in result.errors if "I-4" in e.rule]
        assert len(i4_errors) == 0

    def test_rank_order_is_correct(self):
        assert PROOF_TIER_RANK["DRAFT"] < PROOF_TIER_RANK["CHECKED"]
        assert PROOF_TIER_RANK["CHECKED"] < PROOF_TIER_RANK["TOOL_VERIFIED"]
        assert PROOF_TIER_RANK["TOOL_VERIFIED"] < PROOF_TIER_RANK["ADVERSARIAL"]
        assert PROOF_TIER_RANK["ADVERSARIAL"] < PROOF_TIER_RANK["CONSTITUTIONAL"]


# ---------------------------------------------------------------------------
# I-5: Supersession integrity
# ---------------------------------------------------------------------------

class TestI5Supersession:

    def test_self_supersession_rejected(self):
        r = _load("rollback")
        r["supersedes"] = r["receipt_id"]
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-5" in e.rule for e in result.errors)


# ---------------------------------------------------------------------------
# I-6: Provenance self-consistency
# ---------------------------------------------------------------------------

class TestI6Provenance:

    def test_complete_with_gaps_rejected(self):
        r = _load("approve")
        r["provenance_complete"] = True
        r["known_provenance_gaps"] = ["missing_witness"]
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-6" in e.rule for e in result.errors)

    def test_incomplete_without_gaps_rejected(self):
        r = _load("approve")
        r["provenance_complete"] = False
        r["known_provenance_gaps"] = []
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-6" in e.rule for e in result.errors)


# ---------------------------------------------------------------------------
# I-7: Signature scope
# ---------------------------------------------------------------------------

class TestI7Signature:

    def test_signature_without_pubkey_rejected(self):
        r = _load("approve")
        r["signature"] = "base64signaturedata"
        r["signer_pubkey_sha256"] = None
        result = validate_invariants(r)
        assert not result.valid
        assert any("I-7" in e.rule for e in result.errors)


# ---------------------------------------------------------------------------
# Forbidden states
# ---------------------------------------------------------------------------

class TestForbiddenStates:

    def test_high_confidence_insufficient_evidence(self):
        r = _load("refuse")
        r["confidence"] = "high"
        r["evidence_sufficient"] = False
        result = validate_invariants(r)
        assert not result.valid
        assert any("epistemic fraud" in e.message for e in result.errors)

    def test_approve_block_incoherent(self):
        r = _load("approve")
        r["disposition"] = "block"
        result = validate_invariants(r)
        assert not result.valid

    def test_refuse_execute_violates_separation(self):
        r = _load("refuse")
        r["disposition"] = "execute"
        result = validate_invariants(r)
        assert not result.valid

    def test_advisory_rollback_forbidden(self):
        r = _load("rollback")
        r["authority_class"] = "ADVISORY"
        result = validate_invariants(r)
        assert not result.valid


# ---------------------------------------------------------------------------
# Diagnostic contract: layer tagging and structured output
# ---------------------------------------------------------------------------

class TestDiagnosticContract:
    """Pin the structured error format so downstream consumers can rely on it."""

    def test_shape_error_has_shape_layer(self):
        r = _load("approve")
        del r["verdict"]
        result = validate_shape(r)
        assert not result.valid
        for e in result.errors:
            assert e.layer == LAYER_SHAPE

    def test_invariant_error_has_invariants_layer(self):
        r = _load("approve")
        r["evidence_sufficient"] = False
        result = validate_invariants(r)
        i3 = [e for e in result.errors if e.rule == "I-3"]
        assert len(i3) > 0
        assert all(e.layer == LAYER_INVARIANTS for e in i3)

    def test_forbidden_error_has_forbidden_layer(self):
        r = _load("refuse")
        r["confidence"] = "high"
        r["evidence_sufficient"] = False
        result = validate_invariants(r)
        forbidden = [e for e in result.errors if e.rule == "forbidden"]
        assert len(forbidden) > 0
        assert all(e.layer == LAYER_FORBIDDEN for e in forbidden)

    def test_to_dict_shape_is_stable(self):
        r = _load("approve")
        del r["verdict"]
        result = validate_shape(r)
        d = result.to_dict()
        assert d["valid"] is False
        assert len(d["errors"]) > 0
        err = d["errors"][0]
        assert set(err.keys()) == {"rule", "message", "layer", "severity", "field"}
        assert err["layer"] == LAYER_SHAPE
        assert err["severity"] == "error"

    def test_to_dict_invariant_is_stable(self):
        r = _load("approve")
        r["disposition"] = "block"
        result = validate_invariants(r)
        d = result.to_dict()
        assert d["valid"] is False
        err = d["errors"][0]
        assert err["layer"] == LAYER_INVARIANTS
        assert err["rule"] == "I-1"
        assert "field" in err

    def test_golden_fixture_to_dict_is_clean(self):
        r = _load("approve")
        result = validate_decision_receipt(r)
        d = result.to_dict()
        assert d == {"valid": True, "errors": []}

    def test_error_ordering_is_deterministic(self):
        """Errors appear in code order, not sorted or grouped."""
        r = _load("approve")
        r["evidence_sufficient"] = False  # I-3
        r["confidence"] = "high"  # forbidden
        r["disposition"] = "block"  # I-1
        result = validate_invariants(r)
        rules = [e.rule for e in result.errors]
        # I-1 comes before I-3 in code order
        assert rules.index("I-1") < rules.index("I-3")


# ---------------------------------------------------------------------------
# Tier monotonicity guard (Row 3, Stage 2)
# ---------------------------------------------------------------------------

class TestAuthorityLayerRank:
    """AUTHORITY_LAYER_RANK ordinal table is present and correct."""

    def test_evidence_is_lowest(self):
        assert AUTHORITY_LAYER_RANK["EVIDENCE"] < AUTHORITY_LAYER_RANK["CONTINUITY"]

    def test_continuity_is_middle(self):
        assert AUTHORITY_LAYER_RANK["CONTINUITY"] < AUTHORITY_LAYER_RANK["GOVERNANCE"]

    def test_all_three_layers_present(self):
        assert set(AUTHORITY_LAYER_RANK.keys()) == {"EVIDENCE", "CONTINUITY", "GOVERNANCE"}


class TestTierEscalationError:
    """TierEscalationError is a named, non-generic ValueError."""

    def test_is_value_error(self):
        err = TierEscalationError("test")
        assert isinstance(err, ValueError)

    def test_message_preserved(self):
        err = TierEscalationError("aggregation does not create authority")
        assert "aggregation does not create authority" in str(err)

    def test_distinct_from_bare_value_error(self):
        assert TierEscalationError is not ValueError


class TestAssertTierMonotonic:
    """assert_tier_monotonic enforces: GOVERNANCE cannot be emitted from EVIDENCE-only chain."""

    # Rejection cases — evidence-only inputs without authorized path
    def test_evidence_only_raises(self):
        with pytest.raises(TierEscalationError):
            assert_tier_monotonic(["EVIDENCE"])

    def test_multiple_evidence_inputs_raises(self):
        with pytest.raises(TierEscalationError):
            assert_tier_monotonic(["EVIDENCE", "EVIDENCE", "EVIDENCE"])

    def test_continuity_only_raises(self):
        with pytest.raises(TierEscalationError):
            assert_tier_monotonic(["CONTINUITY"])

    def test_evidence_and_continuity_raises(self):
        with pytest.raises(TierEscalationError):
            assert_tier_monotonic(["EVIDENCE", "CONTINUITY", "EVIDENCE"])

    # Pass cases — governance predecessor present
    def test_governance_predecessor_passes(self):
        assert_tier_monotonic(["GOVERNANCE"])  # must not raise

    def test_mixed_with_governance_passes(self):
        assert_tier_monotonic(["EVIDENCE", "GOVERNANCE"])  # must not raise

    def test_all_three_layers_passes(self):
        assert_tier_monotonic(["EVIDENCE", "CONTINUITY", "GOVERNANCE"])  # must not raise

    # Pass cases — authorized judgment path declared
    def test_evidence_with_authorized_path_passes(self):
        assert_tier_monotonic(["EVIDENCE"], authorized_judgment_path=True)  # must not raise

    def test_continuity_with_authorized_path_passes(self):
        assert_tier_monotonic(["CONTINUITY"], authorized_judgment_path=True)  # must not raise

    def test_empty_list_passes(self):
        """Empty predecessor list is unchecked — no assertion possible."""
        assert_tier_monotonic([])  # must not raise

    # Error message quality
    def test_error_message_names_received_layers(self):
        with pytest.raises(TierEscalationError, match="EVIDENCE"):
            assert_tier_monotonic(["EVIDENCE"])

    def test_error_message_cites_invariant(self):
        with pytest.raises(TierEscalationError, match="aggregation does not create authority"):
            assert_tier_monotonic(["EVIDENCE"])

    def test_error_message_names_governance(self):
        with pytest.raises(TierEscalationError, match="GOVERNANCE"):
            assert_tier_monotonic(["EVIDENCE"])
