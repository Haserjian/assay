"""Tests for counterparty-facing checkpoint attempt views."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay import open_episode
from assay.checkpoint_views import (
    build_outbound_email_checkpoint_attempt_view_from_trace,
    load_outbound_email_checkpoint_attempt_view,
)
from assay.checkpoints import OutboundEmailCheckpointFlow
from assay.epistemic_kernel import (
    CLAIM_ASSERTION_RECEIPT_TYPE,
    PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE,
)
from assay.store import AssayStore


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = ROOT / "docs" / "examples" / "checkpoints"


@pytest.fixture
def tmp_store(tmp_path):
    return AssayStore(base_dir=tmp_path / "assay_store")


def _load_example(name: str) -> dict:
    return json.loads((EXAMPLES_DIR / name).read_text())


def _emit_request_and_evaluation(flow: OutboundEmailCheckpointFlow, template: dict) -> None:
    flow.create_request(
        subject=template["subject"],
        attempt=template["attempt"],
        relying_party=template["relying_party"],
        requested_at=template["requested_at"],
        request_id=template["request_id"],
    )
    flow.evaluate(
        shadow=template["shadow"],
        evidence_bundle=template["evidence_bundle"],
        verifiers=template["verifiers"],
        uncertainty=template["uncertainty"],
        policy=template["policy"],
        evaluation_outcome=template["evaluation_outcome"],
        validity=template["validity"],
        audit=template["audit"],
        evaluation_id=template["evaluation_id"],
    )


def _trace_entry(entry_type: str, timestamp: str, payload: dict, *, trace_id: str = "trace_view") -> dict:
    return {
        **payload,
        "receipt_id": f"r_{entry_type.replace('.', '_')}_{timestamp[-3:-1]}",
        "type": entry_type,
        "timestamp": timestamp,
        "schema_version": "3.0",
        "episode_id": payload.get("subject", {}).get("episode_id", "ep_123"),
        "_trace_id": trace_id,
        "_stored_at": timestamp,
    }


def test_counterparty_view_answers_four_checkpoint_questions(tmp_store) -> None:
    template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

    with open_episode(store=tmp_store) as episode:
        flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
        _emit_request_and_evaluation(flow, template)
        decision = flow.decide(
            authority_id="assay:checkpoint:human_review",
            authority_scope="outbound_action.send_email",
            timestamp="2026-03-19T12:05:00Z",
            verdict="APPROVE",
            verdict_reason="Human reviewer approved the outbound send after checking recipient and context.",
            verdict_reason_codes=["human_approval_granted"],
            confidence="high",
        )
        flow.resolve(
            resolution_outcome="released",
            reason_codes=["human_approval_granted"],
            release_revalidation_performed=True,
            evaluation_valid_at_resolution=True,
            resolved_at="2026-03-19T12:05:01Z",
            human_approval={
                "approver_id": "user://ops_manager_17",
                "decision": "approved",
                "decided_at": "2026-03-19T12:05:00Z",
            },
            dispatch_attempted_at="2026-03-19T12:05:01Z",
        )

    view = load_outbound_email_checkpoint_attempt_view(
        tmp_store,
        episode.trace_id,
        checkpoint_attempt_id=template["checkpoint_id"],
        decision_receipts=[decision],
    )

    assert view.checkpoint_attempt_id == template["checkpoint_id"]
    assert view.attempted_crossing["request_id"] == template["request_id"]
    assert view.attempted_crossing["attempt"]["action_target"]["system"] == "gmail"
    assert view.last_eligible_posture["route"] == "allow_if_approved"
    assert view.authority_decisions[0]["detail_source"] == "decision_receipt"
    assert view.authority_decisions[0]["verdict"] == "APPROVE"
    assert view.actual_outcome["resolution_outcome"] == "released"
    assert view.actual_outcome["final_evaluation_id"] == template["evaluation_id"]
    assert view.current_state == "released"
    assert view.verification["status"] == "passed"
    assert view.verification["errors"] == []
    assert view.limitations == []


def test_counterparty_view_degrades_honestly_without_decision_receipts(tmp_store) -> None:
    template = _load_example("outbound_action.send_email.blocked.v0.1.json")

    with open_episode(store=tmp_store) as episode:
        flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
        _emit_request_and_evaluation(flow, template)
        flow.decide(
            authority_id="assay:checkpoint:outbound_email_policy",
            authority_scope="outbound_action.send_email",
            timestamp="2026-03-19T12:15:02Z",
            verdict="REFUSE",
            verdict_reason="Recipient verification and freshness requirements were not satisfied.",
            verdict_reason_codes=["missing_recipient_verification", "stale_context"],
            evidence_sufficient=False,
            evidence_gaps=["recipient_verified", "fresh_context_snapshot"],
            confidence="moderate",
        )
        flow.resolve(
            resolution_outcome="blocked",
            reason_codes=["missing_recipient_verification", "stale_context"],
            release_revalidation_performed=False,
            evaluation_valid_at_resolution=False,
            resolved_at="2026-03-19T12:15:03Z",
        )

    trace_entries = tmp_store.read_trace(episode.trace_id)
    view = build_outbound_email_checkpoint_attempt_view_from_trace(
        trace_entries,
        checkpoint_attempt_id=template["checkpoint_id"],
    )

    assert view.authority_decisions[0]["detail_source"] == "trace_wrapper"
    assert view.authority_decisions[0]["verdict"] == "REFUSE"
    assert view.actual_outcome["resolution_outcome"] == "blocked"
    assert view.verification["status"] == "degraded"
    assert view.verification["errors"] == ["decision_receipts_required_for_full_authority_verification"]
    assert "canonical_decision_receipts_not_supplied" in view.limitations
    assert "authority_layer_only_proven_by_trace_wrappers" in view.limitations


def test_multiple_decisions_chain_linearly_in_trace_and_view(tmp_store) -> None:
    template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

    with open_episode(store=tmp_store) as episode:
        flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
        _emit_request_and_evaluation(flow, template)
        decision_defer = flow.decide(
            authority_id="assay:checkpoint:preflight_guardian",
            authority_scope="outbound_action.send_email",
            timestamp="2026-03-19T12:00:10Z",
            verdict_reason="Initial posture requires human review before release.",
            verdict_reason_codes=["human_approval_required"],
            confidence="moderate",
        )
        decision_approve = flow.decide(
            authority_id="assay:checkpoint:human_review",
            authority_scope="outbound_action.send_email",
            timestamp="2026-03-19T12:05:00Z",
            verdict="APPROVE",
            verdict_reason="Human reviewer approved the outbound send after checking recipient and context.",
            verdict_reason_codes=["human_approval_granted"],
            confidence="high",
        )
        flow.resolve(
            resolution_outcome="released",
            reason_codes=["human_approval_granted"],
            release_revalidation_performed=True,
            evaluation_valid_at_resolution=True,
            resolved_at="2026-03-19T12:05:01Z",
            human_approval={
                "approver_id": "user://ops_manager_17",
                "decision": "approved",
                "decided_at": "2026-03-19T12:05:00Z",
            },
            dispatch_attempted_at="2026-03-19T12:05:01Z",
        )

    assert decision_approve["parent_receipt_id"] == decision_defer["receipt_id"]

    trace_entries = tmp_store.read_trace(episode.trace_id)
    claim_entries = [entry for entry in trace_entries if entry["type"] == CLAIM_ASSERTION_RECEIPT_TYPE]
    snapshot_entries = [entry for entry in trace_entries if entry["type"] == PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE]
    decision_trace_entries = [entry for entry in trace_entries if entry["type"] == "checkpoint.decision_recorded"]
    assert len(claim_entries) == 2
    assert len(snapshot_entries) == 2
    assert len(decision_trace_entries) == 2
    assert decision_trace_entries[0]["parent_receipt_id"] != decision_trace_entries[1]["parent_receipt_id"]
    assert claim_entries[1]["parent_receipt_id"] == decision_trace_entries[0]["receipt_id"]
    assert snapshot_entries[1]["parent_receipt_id"] == claim_entries[1]["receipt_id"]
    assert decision_trace_entries[1]["parent_receipt_id"] == snapshot_entries[1]["receipt_id"]

    view = build_outbound_email_checkpoint_attempt_view_from_trace(
        trace_entries,
        checkpoint_attempt_id=template["checkpoint_id"],
        decision_receipts=[decision_defer, decision_approve],
    )

    assert [decision["verdict"] for decision in view.authority_decisions] == ["DEFER", "APPROVE"]
    assert view.authority_decisions[0]["disposition"] == "defer_with_obligation"
    assert view.authority_decisions[1]["disposition"] == "execute"
    assert view.verification["status"] == "passed"


def test_resolved_view_uses_resolution_evaluation_not_latest_timestamp() -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation_primary = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
    evaluation_later = _load_example("outbound_action.send_email.blocked.v0.1.json")

    evaluation_primary["checkpoint_id"] = request["checkpoint_id"]
    evaluation_primary["request_id"] = request["request_id"]
    evaluation_primary["evaluation_id"] = "cke_primary"
    evaluation_primary["validity"]["evaluated_at"] = "2026-03-19T12:00:02Z"

    evaluation_later["checkpoint_id"] = request["checkpoint_id"]
    evaluation_later["request_id"] = request["request_id"]
    evaluation_later["subject"] = request["subject"]
    evaluation_later["attempt"] = request["attempt"]
    evaluation_later["relying_party"] = request["relying_party"]
    evaluation_later["evaluation_id"] = "cke_later"
    evaluation_later["validity"]["evaluated_at"] = "2026-03-19T12:10:02Z"

    resolution = {
        **_load_example("outbound_action.send_email.resolution.released.v0.1.json"),
        "request_id": request["request_id"],
        "checkpoint_id": request["checkpoint_id"],
        "evaluation_id": "cke_primary",
        "final_evaluation_id": "cke_primary",
        "resolution_id": "ckr_expired",
        "resolution_outcome": "expired",
        "reason_codes": ["evaluation_freshness_window_elapsed"],
        "release_revalidation_performed": True,
        "evaluation_valid_at_resolution": False,
        "decision_receipt_ids": [],
        "human_approval": None,
        "dispatch_attempted_at": None,
        "effect_observed_at": None,
        "resolved_at": "2026-03-19T13:05:00Z",
    }

    trace_entries = [
        _trace_entry("checkpoint.requested", "2026-03-19T12:00:00Z", request),
        _trace_entry("checkpoint.evaluated", "2026-03-19T12:00:02Z", evaluation_primary),
        _trace_entry("checkpoint.evaluated", "2026-03-19T12:10:02Z", evaluation_later),
        _trace_entry("checkpoint.resolved", "2026-03-19T13:05:00Z", resolution),
    ]

    view = build_outbound_email_checkpoint_attempt_view_from_trace(
        trace_entries,
        checkpoint_attempt_id=request["checkpoint_id"],
    )

    assert view.current_state == "expired"
    assert view.last_eligible_posture["evaluation_id"] == "cke_primary"
    assert view.last_eligible_posture["route"] == "allow_if_approved"
    assert view.actual_outcome["final_evaluation_id"] == "cke_primary"


def test_unresolved_view_uses_latest_evaluation_by_timestamp() -> None:
    request = _load_example("outbound_action.send_email.request.v0.1.json")
    evaluation_primary = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
    evaluation_later = _load_example("outbound_action.send_email.blocked.v0.1.json")

    evaluation_primary["checkpoint_id"] = request["checkpoint_id"]
    evaluation_primary["request_id"] = request["request_id"]
    evaluation_primary["evaluation_id"] = "cke_primary"
    evaluation_primary["validity"]["evaluated_at"] = "2026-03-19T12:00:02Z"

    evaluation_later["checkpoint_id"] = request["checkpoint_id"]
    evaluation_later["request_id"] = request["request_id"]
    evaluation_later["subject"] = request["subject"]
    evaluation_later["attempt"] = request["attempt"]
    evaluation_later["relying_party"] = request["relying_party"]
    evaluation_later["evaluation_id"] = "cke_later"
    evaluation_later["validity"]["evaluated_at"] = "2026-03-19T12:10:02Z"

    trace_entries = [
        _trace_entry("checkpoint.requested", "2026-03-19T12:00:00Z", request),
        _trace_entry("checkpoint.evaluated", "2026-03-19T12:00:02Z", evaluation_primary),
        _trace_entry("checkpoint.evaluated", "2026-03-19T12:10:02Z", evaluation_later),
    ]

    view = build_outbound_email_checkpoint_attempt_view_from_trace(
        trace_entries,
        checkpoint_attempt_id=request["checkpoint_id"],
    )

    assert view.current_state == "block"
    assert view.last_eligible_posture["evaluation_id"] == "cke_later"
    assert view.last_eligible_posture["route"] == "block"
    assert view.actual_outcome["final_evaluation_id"] is None
