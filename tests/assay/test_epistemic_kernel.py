"""Tests for canonical kernel claim and denial artifacts."""
from __future__ import annotations

import copy
import json
from importlib import resources

import pytest
from jsonschema import Draft202012Validator

from assay import (
    BELIEF_UPDATE_RECEIPT_TYPE,
    CONTRADICTION_REGISTRATION_RECEIPT_TYPE,
    CONTRADICTION_RESOLUTION_RECEIPT_TYPE,
    PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE,
    adapt_contradiction_receipt_to_registration,
    adapt_ccio_refusalstone_to_denial_record,
    adapt_checkpoint_decision_to_claim_assertion,
    adapt_checkpoint_decision_to_proof_budget_snapshot,
    adapt_checkpoint_evaluation_to_contradiction_grounded_claims,
    adapt_checkpoint_evaluation_to_contradiction_registrations,
    adapt_checkpoint_resolution_to_denial_record,
    emit_belief_update,
    emit_claim_assertion,
    emit_claim_support_change,
    emit_contradiction_registration,
    emit_contradiction_resolution,
    emit_proof_budget_snapshot,
    open_episode,
    verify_belief_update,
    verify_claim_artifact_set,
    verify_claim_support_chain,
    verify_contradiction_registration_artifact,
    verify_contradiction_resolution_artifact,
    verify_denial_record,
    verify_proof_budget_snapshot,
)
from assay._receipts.domains.blockages import create_contradiction_receipt
from assay.epistemic_kernel import KernelValidationError
from assay.store import AssayStore


def _load_schema(name: str) -> dict:
    schema_path = resources.files("assay").joinpath(f"schemas/{name}")
    return json.loads(schema_path.read_text())


def _typed_ref(ref_id: str, *, ref_role: str = "supporting") -> dict:
    return {
        "ref_type": "external",
        "ref_id": ref_id,
        "ref_uri": None,
        "ref_hash": None,
        "ref_role": ref_role,
    }


def _checkpoint_examples_root() -> str:
    return "/Users/timmybhaserjian/assay/docs/examples/checkpoints"


def _load_example(name: str) -> dict:
    with open(f"{_checkpoint_examples_root()}/{name}", "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_kernel_schemas_validate_as_draft_2020_12() -> None:
    for schema_name in (
        "claim_assertion.v0.1.schema.json",
        "claim_support_change.v0.1.schema.json",
        "denial_record.v0.1.schema.json",
        "proof_budget_snapshot.v0.1.schema.json",
        "belief_update.v0.1.schema.json",
        "contradiction_registration.v0.1.schema.json",
        "contradiction_resolution.v0.1.schema.json",
    ):
        Draft202012Validator.check_schema(_load_schema(schema_name))


def test_claim_assertion_and_support_change_emit_and_verify(tmp_path) -> None:
    store = AssayStore(base_dir=tmp_path / "assay_store")

    with open_episode(store=store) as episode:
        assertion = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:00Z",
            claim_id="clm_a1b2c3d4e5f6",
            claim_text="Recipient verification is sufficient for outbound email release.",
            claim_type="POLICY",
            checkable=True,
            basis={
                "basis_type": "policy_declared",
                "basis_refs": [_typed_ref("policy://outbound_email.default")],
                "proof_tier_at_assertion": "CHECKED",
            },
            claim_scope="outbound_action.send_email",
            source_organ="assay-toolkit",
        )
        support_change = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:02:00Z",
            change_id="csc_a1b2c3d4e5f6",
            claim_id=assertion.claim_id,
            prior_support_status="ASSERTED",
            new_support_status="SUPPORTED",
            change_type="verification_passed",
            evidence_refs=[_typed_ref("checkpoint_evaluation:cke_01HQXEVAL")],
            proof_tier_at_change="TOOL_VERIFIED",
            reason="Checkpoint evidence bundle satisfied the verification policy.",
        )

    chain_result = verify_claim_support_chain(assertion, [support_change])
    assert chain_result.passed is True
    assert chain_result.current_support_status == "SUPPORTED"

    set_result = verify_claim_artifact_set([assertion], [support_change])
    assert set_result.passed is True
    assert set_result.errors == []


def test_claim_support_change_cannot_transition_after_retraction(tmp_path) -> None:
    store = AssayStore(base_dir=tmp_path / "assay_store")

    with open_episode(store=store) as episode:
        assertion = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:00Z",
            claim_id="clm_deadbeefcafe",
            claim_text="This claim will be withdrawn.",
            claim_type="SYNTHESIS",
            checkable=False,
            basis={
                "basis_type": "human_asserted",
                "basis_refs": [_typed_ref("note://human-review")],
                "proof_tier_at_assertion": "DRAFT",
            },
        )
        retracted = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:01:00Z",
            change_id="csc_deadbeef0001",
            claim_id=assertion.claim_id,
            prior_support_status="ASSERTED",
            new_support_status="RETRACTED",
            change_type="retraction",
            evidence_refs=[],
            reason="Operator withdrew the assertion.",
        )
        invalid_followup = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:02:00Z",
            change_id="csc_deadbeef0002",
            claim_id=assertion.claim_id,
            prior_support_status="RETRACTED",
            new_support_status="SUPPORTED",
            change_type="evidence_added",
            evidence_refs=[_typed_ref("evidence://reopened")],
        )

    result = verify_claim_support_chain(assertion, [retracted, invalid_followup])
    assert result.passed is False
    assert "retracted_claim_cannot_transition" in result.errors
    assert "forbidden_support_transition" in result.errors
    assert "chain_retracted_terminal" in result.error_codes
    assert "support_change_transition" in result.error_codes


def test_claim_support_chain_orders_equal_timestamps_by_change_id(tmp_path) -> None:
    store = AssayStore(base_dir=tmp_path / "assay_store")

    with open_episode(store=store) as episode:
        assertion = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:00Z",
            claim_id="clm_111111111111",
            claim_text="A deterministic total order exists for support changes.",
            claim_type="FACTUAL",
            checkable=True,
            basis={
                "basis_type": "extracted",
                "basis_refs": [_typed_ref("receipt://claim_basis")],
                "proof_tier_at_assertion": "CHECKED",
            },
        )
        weakened = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:01:00Z",
            change_id="csc_000000000002",
            claim_id=assertion.claim_id,
            prior_support_status="SUPPORTED",
            new_support_status="WEAKENED",
            change_type="verification_inconclusive",
            evidence_refs=[_typed_ref("receipt://verification_inconclusive")],
        )
        supported = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:01:00Z",
            change_id="csc_000000000001",
            claim_id=assertion.claim_id,
            prior_support_status="ASSERTED",
            new_support_status="SUPPORTED",
            change_type="verification_passed",
            evidence_refs=[_typed_ref("receipt://verification_passed")],
        )

    result = verify_claim_support_chain(assertion, [weakened, supported])
    assert result.passed is True
    assert result.errors == []
    assert result.current_support_status == "WEAKENED"


def test_claim_support_change_requires_existing_claim_assertion() -> None:
    support_change = {
        "schema_version": "0.1.0",
        "artifact_type": "claim_support_change",
        "change_id": "csc_feedfacec001",
        "timestamp": "2026-03-19T12:05:00Z",
        "claim_id": "clm_feedfacec001",
        "episode_id": "ep_claimless",
        "prior_support_status": "ASSERTED",
        "new_support_status": "SUPPORTED",
        "change_type": "verification_passed",
        "evidence_refs": [_typed_ref("checkpoint_evaluation:cke_claimless")],
        "proof_tier_at_change": "CHECKED",
        "reason": "Synthetic verifier passed.",
    }

    result = verify_claim_artifact_set([], [support_change])
    assert result.passed is False
    assert result.errors == ["unknown_claim_assertion:clm_feedfacec001"]
    assert "chain_support_change_claim_exists" in result.error_codes


def test_denial_record_adapts_checkpoint_negative_resolution_and_verifies() -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = _load_example("outbound_action.send_email.blocked.v0.1.json")
    resolution = _load_example("outbound_action.send_email.resolution.blocked.v0.1.json")

    denial = adapt_checkpoint_resolution_to_denial_record(request, evaluation, resolution)
    result = verify_denial_record(
        denial,
        known_refs={
            "request_id": [request["request_id"]],
            "evaluation_id": [evaluation["evaluation_id"]],
            "resolution_id": [resolution["resolution_id"]],
            "decision_receipt_ids": resolution["decision_receipt_ids"],
        },
        source_timestamps={
            request["request_id"]: request["requested_at"],
            evaluation["evaluation_id"]: evaluation["validity"]["evaluated_at"],
            resolution["resolution_id"]: resolution["resolved_at"],
            resolution["decision_receipt_ids"][0]: "2026-03-19T12:15:02Z",
        },
    )

    assert result.passed is True
    assert result.errors == []
    assert denial.denial_outcome == "blocked"
    assert denial.backward_refs["resolution_id"] == resolution["resolution_id"]
    assert "recipient_verified" in denial.missing_evidence


def test_checkpoint_decision_adapts_to_claim_and_proof_budget_snapshot(tmp_path) -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = _load_example("outbound_action.send_email.blocked.v0.1.json")
    decision_receipt = {
        "receipt_id": "decision_kernel_001",
        "timestamp": "2026-03-19T12:15:02Z",
        "proof_tier_at_decision": "CHECKED",
        "proof_tier_minimum_required": "TOOL_VERIFIED",
        "evidence_gaps": ["recipient_verified", "fresh_context_snapshot"],
        "verdict": "REFUSE",
    }

    claim = adapt_checkpoint_decision_to_claim_assertion(request, evaluation, decision_receipt)
    snapshot = adapt_checkpoint_decision_to_proof_budget_snapshot(
        request,
        evaluation,
        decision_receipt,
        claim_ids=[claim.claim_id],
    )

    assert claim.claim_scope == "outbound_action.send_email"
    assert snapshot.boundary_kind == "checkpoint_decision"
    assert snapshot.boundary_refs["decision_receipt_id"] == decision_receipt["receipt_id"]
    assert snapshot.claim_ids == [claim.claim_id]

    claim_result = verify_claim_artifact_set([claim], [])
    snapshot_result = verify_proof_budget_snapshot(snapshot, known_claim_ids=[claim.claim_id])
    assert claim_result.passed is True
    assert snapshot_result.passed is True

    store = AssayStore(base_dir=tmp_path / "assay_store")
    with open_episode(store=store) as episode:
        emit_claim_assertion(
            episode,
            claim_text=claim.claim_text,
            claim_type=claim.claim_type,
            checkable=claim.checkable,
            basis=claim.basis,
            claim_id=claim.claim_id,
            timestamp=claim.timestamp,
            claim_scope=claim.claim_scope,
            source_organ=claim.source_organ,
        )
        emit_proof_budget_snapshot(
            episode,
            snapshot,
        )

    entries = store.read_trace(episode.trace_id)
    assert any(entry["type"] == PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE for entry in entries)


def test_checkpoint_evaluation_adapts_to_contradiction_registration(tmp_path) -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = _load_example("outbound_action.send_email.blocked.v0.1.json")
    evaluation["evidence_bundle"]["contradictions"] = [
        {
            "lhs_ref": "ev_21",
            "rhs_ref": "ev_22",
            "reason_code": "context_policy_conflict",
            "severity": "blocking",
        }
    ]
    decision_receipt = {
        "receipt_id": "decision_contradiction_001",
        "timestamp": "2026-03-19T12:15:02Z",
    }

    contradictions = adapt_checkpoint_evaluation_to_contradiction_registrations(
        request,
        evaluation,
        decision_receipt,
    )

    assert len(contradictions) == 1
    contradiction = contradictions[0]
    assert contradiction.status == "open"
    assert contradiction.boundary_refs["decision_receipt_id"] == "decision_contradiction_001"

    result = verify_contradiction_registration_artifact(contradiction)
    assert result.passed is True

    store = AssayStore(base_dir=tmp_path / "assay_store")
    with open_episode(store=store) as episode:
        emit_contradiction_registration(episode, contradiction)

    entries = store.read_trace(episode.trace_id)
    assert any(entry["type"] == CONTRADICTION_REGISTRATION_RECEIPT_TYPE for entry in entries)


def test_checkpoint_evaluation_adapts_to_grounded_contradiction_claims() -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = _load_example("outbound_action.send_email.blocked.v0.1.json")
    evaluation["evidence_bundle"]["contradictions"] = [
        {
            "lhs_ref": "ev_21",
            "rhs_ref": "ev_22",
            "reason_code": "context_policy_conflict",
            "severity": "blocking",
        }
    ]
    decision_receipt = {
        "receipt_id": "decision_contradiction_001",
        "timestamp": "2026-03-19T12:15:02Z",
    }

    claims = adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
        request,
        evaluation,
        decision_receipt,
    )
    repeat_claims = adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
        request,
        evaluation,
        decision_receipt,
    )
    contradictions = adapt_checkpoint_evaluation_to_contradiction_registrations(
        request,
        evaluation,
        decision_receipt,
    )

    assert len(claims) == 2
    assert [claim.claim_id for claim in claims] == [claim.claim_id for claim in repeat_claims]
    assert [claim.claim_id for claim in claims] == sorted(claim.claim_id for claim in claims)
    assert {claim.claim_id for claim in claims} == {contradictions[0].claim_a_id, contradictions[0].claim_b_id}

    evidence_index = {
        item["evidence_id"]: item
        for item in evaluation["evidence_bundle"]["items"]
    }
    by_evidence_id = {claim.basis["basis_refs"][0]["ref_id"]: claim for claim in claims}
    assert set(by_evidence_id) == {"ev_21", "ev_22"}
    for evidence_id, claim in by_evidence_id.items():
        evidence_item = evidence_index[evidence_id]
        basis_ref = claim.basis["basis_refs"][0]
        assert claim.claim_type == "FACTUAL"
        assert claim.checkable is True
        assert claim.basis["basis_type"] == "extracted"
        assert claim.basis["proof_tier_at_assertion"] == "CHECKED"
        assert claim.claim_scope == "outbound_action.send_email"
        assert claim.source_organ == "assay-toolkit"
        assert basis_ref["ref_type"] == "external"
        assert basis_ref["ref_id"] == evidence_id
        assert basis_ref["ref_uri"] == evidence_item["uri"]
        assert basis_ref["ref_hash"] == evidence_item["hash"]
        assert basis_ref["ref_role"] == "supporting"
        assert evidence_id in claim.claim_text


def test_checkpoint_evaluation_grounded_contradiction_claims_dedupe_shared_evidence() -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
    evaluation["evidence_bundle"]["contradictions"] = [
        {
            "lhs_ref": "ev_1",
            "rhs_ref": "ev_2",
            "reason_code": "scope_overlap",
            "severity": "warning",
        },
        {
            "lhs_ref": "ev_1",
            "rhs_ref": "ev_3",
            "reason_code": "freshness_conflict",
            "severity": "warning",
        },
    ]
    decision_receipt = {
        "receipt_id": "decision_contradiction_dedupe_001",
        "timestamp": "2026-03-19T12:15:02Z",
    }

    claims = adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
        request,
        evaluation,
        decision_receipt,
    )
    repeat_claims = adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
        request,
        evaluation,
        decision_receipt,
    )

    assert len(claims) == 3
    assert [claim.claim_id for claim in claims] == [claim.claim_id for claim in repeat_claims]

    refs = [claim.basis["basis_refs"][0]["ref_id"] for claim in claims]
    assert refs.count("ev_1") == 1
    assert set(refs) == {"ev_1", "ev_2", "ev_3"}
    assert [claim.claim_id for claim in claims] == sorted(claim.claim_id for claim in claims)


@pytest.mark.parametrize(
    "mutator, expected_error",
    [
        (
            "missing_ref",
            "does not resolve to a known evidence item",
        ),
        (
            "duplicate_item",
            "duplicate checkpoint contradiction evidence_id",
        ),
    ],
)
def test_checkpoint_evaluation_grounded_contradiction_claims_fail_closed(
    mutator: str,
    expected_error: str,
) -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = copy.deepcopy(_load_example("outbound_action.send_email.blocked.v0.1.json"))
    evaluation["evidence_bundle"]["contradictions"] = [
        {
            "lhs_ref": "ev_21",
            "rhs_ref": "ev_22",
            "reason_code": "context_policy_conflict",
            "severity": "blocking",
        }
    ]
    if mutator == "missing_ref":
        evaluation["evidence_bundle"]["contradictions"][0]["rhs_ref"] = "ev_missing"
    elif mutator == "duplicate_item":
        evaluation["evidence_bundle"]["items"].append(copy.deepcopy(evaluation["evidence_bundle"]["items"][0]))

    decision_receipt = {
        "receipt_id": "decision_contradiction_fail_closed_001",
        "timestamp": "2026-03-19T12:15:02Z",
    }

    with pytest.raises(KernelValidationError, match=expected_error):
        adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
            request,
            evaluation,
            decision_receipt,
        )


def test_contradiction_receipt_adapts_to_registration_and_verifies(tmp_path) -> None:
    store = AssayStore(base_dir=tmp_path / "assay_store")

    with open_episode(store=store) as episode:
        claim_a = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:00Z",
            claim_id="clm_1234567890ab",
            claim_text="The recipient domain is authorized for outbound billing follow-up.",
            claim_type="FACTUAL",
            checkable=True,
            basis={
                "basis_type": "extracted",
                "basis_refs": [_typed_ref("crm://contact:17")],
                "proof_tier_at_assertion": "CHECKED",
            },
        )
        claim_b = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:05Z",
            claim_id="clm_1234567890ac",
            claim_text="The recipient domain is currently blocked by policy.",
            claim_type="POLICY",
            checkable=True,
            basis={
                "basis_type": "policy_declared",
                "basis_refs": [_typed_ref("policy://outbound_email.domain_block")],
                "proof_tier_at_assertion": "CHECKED",
            },
        )
        contradiction_receipt = create_contradiction_receipt(
            claim_a=claim_a.claim_text,
            claim_a_confidence=0.86,
            claim_b=claim_b.claim_text,
            claim_b_confidence=0.91,
            impacted_invariants=["policy_compliance"],
            resolution_attempted=True,
            resolution_result="Deferred to human review",
        )
        contradiction = adapt_contradiction_receipt_to_registration(
            contradiction_receipt,
            episode_id=episode.episode_id,
            claim_a_id=claim_a.claim_id,
            claim_b_id=claim_b.claim_id,
            timestamp="2026-03-19T12:00:30Z",
            scope="outbound_action.send_email",
        )
        emit_contradiction_registration(episode, contradiction)

    result = verify_contradiction_registration_artifact(contradiction)
    assert result.passed is True
    chain_result = verify_claim_artifact_set([claim_a, claim_b], [], contradictions=[contradiction])
    assert chain_result.passed is True

    entries = store.read_trace(episode.trace_id)
    assert any(entry["type"] == CONTRADICTION_REGISTRATION_RECEIPT_TYPE for entry in entries)


def test_contradiction_resolution_emits_and_closes_chain(tmp_path) -> None:
    store = AssayStore(base_dir=tmp_path / "assay_store")

    with open_episode(store=store) as episode:
        claim_a = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:00Z",
            claim_id="clm_abcdef123456",
            claim_text="Customer follow-up is allowed for this ticket.",
            claim_type="FACTUAL",
            checkable=True,
            basis={
                "basis_type": "extracted",
                "basis_refs": [_typed_ref("ticket://case-44")],
                "proof_tier_at_assertion": "CHECKED",
            },
        )
        claim_b = emit_claim_assertion(
            episode,
            timestamp="2026-03-19T12:00:10Z",
            claim_id="clm_abcdef123457",
            claim_text="Customer follow-up is blocked by current policy.",
            claim_type="POLICY",
            checkable=True,
            basis={
                "basis_type": "policy_declared",
                "basis_refs": [_typed_ref("policy://follow_up.default")],
                "proof_tier_at_assertion": "CHECKED",
            },
        )
        contradiction_receipt = create_contradiction_receipt(
            claim_a=claim_a.claim_text,
            claim_a_confidence=0.75,
            claim_b=claim_b.claim_text,
            claim_b_confidence=0.89,
            impacted_invariants=["customer_safety", "policy_compliance"],
        )
        contradiction = adapt_contradiction_receipt_to_registration(
            contradiction_receipt,
            episode_id=episode.episode_id,
            claim_a_id=claim_a.claim_id,
            claim_b_id=claim_b.claim_id,
            timestamp="2026-03-19T12:01:00Z",
        )
        emit_contradiction_registration(episode, contradiction)
        contradicting_change = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:01:10Z",
            change_id="csc_abcdef123456",
            claim_id=claim_b.claim_id,
            prior_support_status="ASSERTED",
            new_support_status="CONTRADICTED",
            change_type="contradiction_registered",
            evidence_refs=[_typed_ref(contradiction.contradiction_id, ref_role="contradicting")],
            contradiction_id=contradiction.contradiction_id,
        )
        contradiction_resolution = {
            "resolution_id": "crr_abcdef123456",
            "artifact_type": "contradiction_resolution",
            "schema_version": "0.1.0",
            "timestamp": "2026-03-19T12:02:00Z",
            "contradiction_id": contradiction.contradiction_id,
            "episode_id": episode.episode_id,
            "resolution_outcome": "claim_a_prevails",
            "resolution_basis": {
                "authority_type": "automated_verification",
                "decision_receipt_id": None,
                "evidence_refs": [_typed_ref("receipt://verification_pass")],
                "prevailing_proof_tier": "TOOL_VERIFIED"
            },
            "notes": "Independent verifier confirmed the blocking policy was stale."
        }
        emit_contradiction_resolution(episode, contradiction_resolution)
        resolved_change = emit_claim_support_change(
            episode,
            timestamp="2026-03-19T12:02:10Z",
            change_id="csc_abcdef123457",
            claim_id=claim_b.claim_id,
            prior_support_status="CONTRADICTED",
            new_support_status="RETRACTED",
            change_type="contradiction_resolved",
            evidence_refs=[_typed_ref("crr_abcdef123456")],
            contradiction_id=contradiction.contradiction_id,
            reason="Losing claim was retracted after contradiction resolution.",
        )

    resolution_result = verify_contradiction_resolution_artifact(contradiction_resolution)
    assert resolution_result.passed is True
    chain_result = verify_claim_artifact_set(
        [claim_a, claim_b],
        [contradicting_change, resolved_change],
        contradictions=[contradiction],
        resolutions=[contradiction_resolution],
    )
    assert chain_result.passed is True

    entries = store.read_trace(episode.trace_id)
    assert any(entry["type"] == CONTRADICTION_RESOLUTION_RECEIPT_TYPE for entry in entries)


def test_belief_update_emits_and_verifies(tmp_path) -> None:
    store = AssayStore(base_dir=tmp_path / "assay_store")
    belief_update = {
        "update_id": "blu_a1b2c3d4e5f6",
        "timestamp": "2026-03-19T12:20:00Z",
        "episode_id": "ep_kernel_001",
        "claim_id": "clm_a1b2c3d4e5f6",
        "prior_state": {"status": "ASSERTED"},
        "new_state": {"status": "SUPPORTED"},
        "settlement_status": "settled",
        "durability_class": "durable",
        "trigger_refs": [_typed_ref("decision://kernel_gate")],
        "rationale": "Promotion moved from asserted to supported after settlement.",
        "lineage_refs": [_typed_ref("claim://clm_a1b2c3d4e5f6", ref_role="contextual")],
    }

    with open_episode(store=store) as episode:
        emit_belief_update(episode, belief_update)

    result = verify_belief_update(belief_update, known_claim_ids=["clm_a1b2c3d4e5f6"])
    assert result.passed is True
    entries = store.read_trace(episode.trace_id)
    assert any(entry["type"] == BELIEF_UPDATE_RECEIPT_TYPE for entry in entries)


def test_denial_record_rejects_unknown_and_forward_refs() -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation = _load_example("outbound_action.send_email.blocked.v0.1.json")
    resolution = _load_example("outbound_action.send_email.resolution.blocked.v0.1.json")
    denial = adapt_checkpoint_resolution_to_denial_record(request, evaluation, resolution)

    result = verify_denial_record(
        denial,
        known_refs={
            "request_id": [request["request_id"]],
            "evaluation_id": ["cke_other"],
            "resolution_id": [resolution["resolution_id"]],
            "decision_receipt_ids": [],
        },
        source_timestamps={
            request["request_id"]: request["requested_at"],
            evaluation["evaluation_id"]: "2026-03-19T12:20:00Z",
            resolution["resolution_id"]: resolution["resolved_at"],
        },
    )

    assert result.passed is False
    assert f"unknown_backward_ref:evaluation_id:{evaluation['evaluation_id']}" in result.errors
    assert f"forward_ref_timestamp:evaluation_id:{evaluation['evaluation_id']}" in result.errors


def test_ccio_refusalstone_fixture_maps_to_canonical_denial() -> None:
    refusal_fixture = {
        "receipt_id": "REF_UNIT",
        "reason": "Feature drift blocked adjudication until missing labs are supplied.",
        "domain": "ncaab",
        "asset_id": "asset-123",
        "reasons": ["FeatureDrift:MissingLabs"],
        "metrics": {
            "refusal_type": "data_insufficient",
            "recourse_kind": "collect_more_data",
            "admissibility_consequence": "retryable",
        },
        "details": {
            "subject_type": "claim_case",
            "subject_id": "case-123",
            "attempted_action": {
                "action_type": "adjudication",
                "action_name": "approve_claim",
                "action_target": "prior_auth:case-123",
                "argument_hash": "sha256:abc123"
            },
            "missing_evidence": ["clinical_labs", "updated_documentation"],
            "policy_ref": "guardian:medical_review",
            "policy_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "upgrade_conditions": ["provide:clinical_labs", "provide:updated_documentation"],
            "safer_lawful_alternative": "Route the case to manual review without automated approval.",
            "cheaper_next_move": "Collect the missing clinical lab records.",
            "request_id": "req_medical_001",
            "evaluation_id": "cke_medical_001",
            "resolution_id": "ckr_medical_001",
            "decision_receipt_ids": ["decision_medical_001"]
        },
        "timestamp": "2026-03-19T12:00:00Z",
    }

    denial = adapt_ccio_refusalstone_to_denial_record(refusal_fixture)
    assert denial.source_surface == "ccio.refusalstone"
    assert denial.subject["subject_id"] == "case-123"
    assert denial.attempted_action["action_name"] == "approve_claim"
    assert denial.missing_evidence == ["clinical_labs", "updated_documentation"]
    assert denial.cheaper_next_move == "Collect the missing clinical lab records."
    assert denial.backward_refs["source_receipt_id"] == "REF_UNIT"


def test_checkpoint_resolution_adapts_to_contradiction_resolutions() -> None:
    from assay.epistemic_kernel import (
        ContradictionRegistrationArtifact,
        adapt_checkpoint_resolution_to_contradiction_resolutions,
    )

    request = _load_example("outbound_action.send_email.request.v0.1.json")
    resolution = _load_example("outbound_action.send_email.resolution.blocked.v0.1.json")
    registered = ContradictionRegistrationArtifact(
        contradiction_id="ctr_aabbccddeeff",
        timestamp="2026-03-19T12:15:02Z",
        episode_id=request["subject"]["episode_id"],
        claim_a_id="clm_aabbccddeeff",
        claim_b_id="clm_ffeeddccbbaa",
        conflict_type="inconsistent_evidence",
        severity="high",
        detection={
            "detection_method": "automated_verification",
            "detection_confidence": 1.0,
            "detector_id": "test",
            "detection_evidence_refs": [_typed_ref("ev_test")],
        },
        status="open",
        boundary_refs={
            "checkpoint_id": request["checkpoint_id"],
            "request_id": request["request_id"],
            "evaluation_id": "cke_test",
            "decision_receipt_id": resolution["decision_receipt_ids"][0],
        },
    )

    resolutions = adapt_checkpoint_resolution_to_contradiction_resolutions(
        request,
        resolution,
        [registered],
        decision_receipt_ids=resolution["decision_receipt_ids"],
    )
    assert len(resolutions) == 1
    ctr_res = resolutions[0]
    assert ctr_res.contradiction_id == "ctr_aabbccddeeff"
    assert ctr_res.resolution_outcome == "claim_a_prevails"  # negative resolution
    assert ctr_res.resolution_basis["authority_type"] == "governance_decision"
    assert ctr_res.resolution_basis["decision_receipt_id"] == resolution["decision_receipt_ids"][0]


def test_positive_checkpoint_resolution_produces_out_of_scope_contradiction_resolution() -> None:
    from assay.epistemic_kernel import (
        ContradictionRegistrationArtifact,
        adapt_checkpoint_resolution_to_contradiction_resolutions,
    )

    request = _load_example("outbound_action.send_email.request.v0.1.json")
    resolution = {
        "resolution_id": "ckr_positive_test",
        "checkpoint_id": request["checkpoint_id"],
        "request_id": request["request_id"],
        "evaluation_id": "cke_test",
        "final_evaluation_id": "cke_test",
        "resolution_outcome": "released",
        "reason_codes": ["human_approval_granted"],
        "resolved_at": "2026-03-19T12:05:01Z",
        "decision_receipt_ids": ["decision_happy_01"],
    }
    registered = ContradictionRegistrationArtifact(
        contradiction_id="ctr_aabbccddeeff",
        timestamp="2026-03-19T12:04:00Z",
        episode_id=request["subject"]["episode_id"],
        claim_a_id="clm_aabbccddeeff",
        claim_b_id="clm_ffeeddccbbaa",
        conflict_type="scope_overlap",
        severity="medium",
        detection={
            "detection_method": "automated_verification",
            "detection_confidence": 0.8,
            "detector_id": "test",
            "detection_evidence_refs": [_typed_ref("ev_test")],
        },
        status="contained",
        boundary_refs={
            "checkpoint_id": request["checkpoint_id"],
            "request_id": request["request_id"],
            "evaluation_id": "cke_test",
            "decision_receipt_id": "decision_happy_01",
        },
    )

    resolutions = adapt_checkpoint_resolution_to_contradiction_resolutions(
        request,
        resolution,
        [registered],
    )
    assert len(resolutions) == 1
    assert resolutions[0].resolution_outcome == "out_of_scope"
