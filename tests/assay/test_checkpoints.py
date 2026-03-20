"""Golden tests for outbound email checkpoint lifecycle emission."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from assay import open_episode
from assay.checkpoints import (
    CheckpointResolutionArtifact,
    CheckpointValidationError,
    verify_outbound_email_kernel_bundle,
    OutboundEmailCheckpointFlow,
    verify_outbound_email_lifecycle,
)
from assay.epistemic_kernel import (
    CLAIM_ASSERTION_RECEIPT_TYPE,
    CONTRADICTION_REGISTRATION_RECEIPT_TYPE,
    DENIAL_RECORD_RECEIPT_TYPE,
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


class TestOutboundEmailCheckpointFlow:
    def test_blocked_flow_emits_contradiction_bundle_when_evaluation_has_contradictions(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.blocked.v0.1.json")
        template["evidence_bundle"]["contradictions"] = [
            {
                "lhs_ref": "ev_21",
                "rhs_ref": "ev_22",
                "reason_code": "context_policy_conflict",
                "severity": "blocking",
            }
        ]

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:outbound_email_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="REFUSE",
                verdict_reason="Contradictory evidence and freshness failures blocked release.",
                verdict_reason_codes=["context_policy_conflict", "stale_context"],
                evidence_sufficient=False,
                evidence_gaps=["recipient_verified", "fresh_context_snapshot"],
                confidence="moderate",
                proof_tier_at_decision="CHECKED",
                proof_tier_minimum_required="TOOL_VERIFIED",
            )
            resolution = flow.resolve(
                resolution_outcome="blocked",
                reason_codes=["context_policy_conflict", "stale_context"],
                release_revalidation_performed=False,
                evaluation_valid_at_resolution=False,
                resolved_at="2026-03-19T12:15:03Z",
            )

        assert len(flow.kernel_contradictions) == 1
        assert decision["unresolved_contradictions"] == [flow.kernel_contradictions[0].contradiction_id]
        entries = tmp_store.read_trace(episode.trace_id)
        claims = [e for e in entries if e["type"] == CLAIM_ASSERTION_RECEIPT_TYPE]
        contradictions = [e for e in entries if e["type"] == CONTRADICTION_REGISTRATION_RECEIPT_TYPE]
        snapshots = [e for e in entries if e["type"] == PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE]
        denials = [e for e in entries if e["type"] == DENIAL_RECORD_RECEIPT_TYPE]
        recorded = [e for e in entries if e["type"] == "checkpoint.decision_recorded"][0]
        evaluated = [e for e in entries if e["type"] == "checkpoint.evaluated"][0]
        assert len(flow.kernel_claims) == 3
        assert len(claims) == 3
        assert len(contradictions) == 1
        assert len(snapshots) == 1
        assert len(denials) == 1
        assert claims[0]["parent_receipt_id"] == evaluated["receipt_id"]
        assert claims[1]["parent_receipt_id"] == claims[0]["receipt_id"]
        assert claims[2]["parent_receipt_id"] == claims[1]["receipt_id"]
        assert contradictions[0]["parent_receipt_id"] == claims[2]["receipt_id"]
        assert snapshots[0]["parent_receipt_id"] == contradictions[0]["receipt_id"]
        assert snapshots[0]["contradiction_ids"] == [contradictions[0]["contradiction_id"]]
        assert snapshots[0]["claim_ids"] == [claim["claim_id"] for claim in claims]
        assert denials[0]["contradiction_ids"] == [contradictions[0]["contradiction_id"]]
        assert denials[0]["related_claim_ids"] == [claim["claim_id"] for claim in claims]
        assert recorded["kernel_claim_ids"] == [claim["claim_id"] for claim in claims]
        assert resolution.decision_receipt_ids == [decision["receipt_id"]]

        # Contradiction resolution should be emitted after checkpoint resolution
        ctr_resolutions = [e for e in entries if e["type"] == "contradiction.resolved"]
        assert len(ctr_resolutions) == 1
        assert ctr_resolutions[0]["contradiction_id"] == contradictions[0]["contradiction_id"]
        assert ctr_resolutions[0]["resolution_outcome"] == "claim_a_prevails"
        assert len(flow.kernel_contradiction_resolutions) == 1

    def test_released_flow_with_contradictions_emits_out_of_scope_resolutions(self, tmp_store) -> None:
        """Positive resolution should settle contradictions as out_of_scope."""
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
        template["evidence_bundle"]["contradictions"] = [
            {
                "lhs_ref": "ev_1",
                "rhs_ref": "ev_2",
                "reason_code": "scope_overlap",
                "severity": "warning",
            }
        ]

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:human_review",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:05:00Z",
                verdict="APPROVE",
                verdict_reason="Human reviewer approved despite minor contradiction.",
                verdict_reason_codes=["human_approval_granted"],
                confidence="high",
            )
            resolution = flow.resolve(
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

        entries = tmp_store.read_trace(episode.trace_id)
        ctr_registrations = [e for e in entries if e["type"] == "contradiction.registered"]
        ctr_resolutions = [e for e in entries if e["type"] == "contradiction.resolved"]
        assert len(ctr_registrations) == 1
        assert len(ctr_resolutions) == 1
        assert ctr_resolutions[0]["contradiction_id"] == ctr_registrations[0]["contradiction_id"]
        assert ctr_resolutions[0]["resolution_outcome"] == "out_of_scope"
        assert len(flow.kernel_contradiction_resolutions) == 1

    def test_blocked_flow_emits_request_evaluation_and_resolution(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.blocked.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
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
            resolution = flow.resolve(
                resolution_outcome="blocked",
                reason_codes=["missing_recipient_verification", "stale_context"],
                release_revalidation_performed=False,
                evaluation_valid_at_resolution=False,
                resolved_at="2026-03-19T12:15:03Z",
            )

        assert resolution.resolution_outcome == "blocked"
        assert resolution.decision_receipt_ids == [decision["receipt_id"]]
        entries = tmp_store.read_trace(episode.trace_id)
        requested = [e for e in entries if e["type"] == "checkpoint.requested"][0]
        evaluated = [e for e in entries if e["type"] == "checkpoint.evaluated"][0]
        recorded = [e for e in entries if e["type"] == "checkpoint.decision_recorded"][0]
        resolved = [e for e in entries if e["type"] == "checkpoint.resolved"][0]
        denial = [e for e in entries if e["type"] == DENIAL_RECORD_RECEIPT_TYPE][0]
        claims = [e for e in entries if e["type"] == CLAIM_ASSERTION_RECEIPT_TYPE]
        snapshots = [e for e in entries if e["type"] == PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE]
        assert evaluated["parent_receipt_id"] == requested["receipt_id"]
        assert len(claims) == 1
        assert len(snapshots) == 1
        assert claims[0]["parent_receipt_id"] == evaluated["receipt_id"]
        assert snapshots[0]["parent_receipt_id"] == claims[0]["receipt_id"]
        assert recorded["parent_receipt_id"] == snapshots[0]["receipt_id"]
        assert resolved["parent_receipt_id"] == recorded["receipt_id"]
        assert denial["parent_receipt_id"] == resolved["receipt_id"]
        assert denial["denial_outcome"] == "blocked"
        assert denial["backward_refs"]["resolution_id"] == resolution.resolution_id
        assert denial["proof_budget_snapshot_id"] == snapshots[0]["snapshot_id"]
        assert denial["related_claim_ids"] == [claims[0]["claim_id"]]
        assert recorded["proof_budget_snapshot_id"] == snapshots[0]["snapshot_id"]
        assert recorded["kernel_claim_ids"] == [claims[0]["claim_id"]]
        assert resolved["resolution_outcome"] == "blocked"

    def test_review_gated_flow_releases_after_human_approval(self, tmp_store) -> None:
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
                evidence_refs=[
                    {
                        "ref_type": "external",
                        "ref_id": "approval://ops_manager_17",
                        "ref_uri": "approval://ops_manager_17",
                        "ref_hash": None,
                        "ref_role": "supporting",
                    }
                ],
                confidence="high",
            )
            resolution = flow.resolve(
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
                appended_evidence_refs=["approval://ops_manager_17"],
            )

        assert resolution.resolution_outcome == "released"
        assert resolution.decision_receipt_ids == [decision["receipt_id"]]
        assert resolution.human_approval["decision"] == "approved"
        entries = tmp_store.read_trace(episode.trace_id)
        resolved = [e for e in entries if e["type"] == "checkpoint.resolved"][0]
        denials = [e for e in entries if e["type"] == DENIAL_RECORD_RECEIPT_TYPE]
        snapshots = [e for e in entries if e["type"] == PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE]
        assert resolved["release_revalidation_performed"] is True
        assert resolved["evaluation_valid_at_resolution"] is True
        assert len(snapshots) == 1
        assert denials == []

    def test_dispatch_failed_is_distinct_from_release(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:human_review",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:05:00Z",
                verdict="APPROVE",
                verdict_reason="Human reviewer approved the outbound send before dispatch.",
                verdict_reason_codes=["human_approval_granted"],
                confidence="high",
            )
            resolution = flow.resolve(
                resolution_outcome="dispatch_failed",
                reason_codes=["smtp_timeout"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=True,
                resolved_at="2026-03-19T12:05:02Z",
                human_approval={
                    "approver_id": "user://ops_manager_17",
                    "decision": "approved",
                    "decided_at": "2026-03-19T12:05:00Z",
                },
                dispatch_attempted_at="2026-03-19T12:05:01Z",
            )

        assert resolution.resolution_outcome == "dispatch_failed"
        assert resolution.decision_receipt_ids == [decision["receipt_id"]]
        assert resolution.dispatch_attempted_at == "2026-03-19T12:05:01Z"

    def test_stale_evaluation_cannot_release_and_expires_instead(self, tmp_store) -> None:
        template = copy.deepcopy(_load_example("outbound_action.send_email.allow_if_approved.v0.1.json"))
        template["validity"]["evidence_valid_until"] = "2026-03-19T12:01:00Z"

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            resolution = flow.resolve(
                resolution_outcome="expired",
                reason_codes=["evaluation_freshness_window_elapsed"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=False,
                resolved_at="2026-03-19T12:05:02Z",
            )

        assert resolution.resolution_outcome == "expired"
        assert resolution.evaluation_valid_at_resolution is False

    def test_review_gated_release_without_approval_is_rejected(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            flow.decide(
                authority_id="assay:checkpoint:human_review",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:05:00Z",
                verdict="APPROVE",
                verdict_reason="Authority approved, but caller failed to provide approval evidence to resolution.",
                verdict_reason_codes=["human_approval_granted"],
                confidence="high",
            )
            with pytest.raises(CheckpointValidationError, match="human_approval"):
                flow.resolve(
                    resolution_outcome="released",
                    reason_codes=["attempted_release_without_review"],
                    release_revalidation_performed=True,
                    evaluation_valid_at_resolution=True,
                    resolved_at="2026-03-19T12:05:01Z",
                )

    def test_reevaluation_flow_emits_linear_runtime_chain(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
        reevaluation_template = copy.deepcopy(template)
        reevaluation_template["evaluation_id"] = "cke_01HQXREEVAL"
        reevaluation_template["evaluation_outcome"] = {
            "route": "allow_immediately",
            "reason_codes": ["fresh_context_revalidated"],
            "human_review_required": False,
            "release_conditions": [],
        }
        reevaluation_template["validity"]["evaluated_at"] = "2026-03-19T12:04:00Z"
        reevaluation_template["validity"]["evidence_valid_until"] = "2026-03-19T13:04:00Z"
        reevaluation_template["audit"]["created_at"] = "2026-03-19T12:04:00Z"

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            request = flow.create_request(
                subject=template["subject"],
                attempt=template["attempt"],
                relying_party=template["relying_party"],
                requested_at=template["requested_at"],
                request_id=template["request_id"],
            )
            evaluation_1 = flow.evaluate(
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
            decision_1 = flow.decide(
                authority_id="assay:checkpoint:human_review",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:03:00Z",
                verdict="DEFER",
                verdict_reason="Human review is still required before release.",
                verdict_reason_codes=["human_approval_required"],
                confidence="moderate",
            )
            evaluation_2 = flow.evaluate(
                shadow=reevaluation_template["shadow"],
                evidence_bundle=reevaluation_template["evidence_bundle"],
                verifiers=reevaluation_template["verifiers"],
                uncertainty=reevaluation_template["uncertainty"],
                policy=reevaluation_template["policy"],
                evaluation_outcome=reevaluation_template["evaluation_outcome"],
                validity=reevaluation_template["validity"],
                audit=reevaluation_template["audit"],
                evaluation_id=reevaluation_template["evaluation_id"],
            )
            decision_2 = flow.decide(
                authority_id="assay:checkpoint:outbound_email_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:05:00Z",
                verdict="APPROVE",
                verdict_reason="Fresh context revalidation removed the human review requirement.",
                verdict_reason_codes=["fresh_context_revalidated"],
                confidence="high",
            )
            resolution = flow.resolve(
                resolution_outcome="released",
                reason_codes=["fresh_context_revalidated"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=True,
                resolved_at="2026-03-19T12:05:01Z",
                dispatch_attempted_at="2026-03-19T12:05:01Z",
            )

        assert [evaluation.evaluation_id for evaluation in flow.evaluations] == [
            evaluation_1.evaluation_id,
            evaluation_2.evaluation_id,
        ]
        assert evaluation_2.supersedes_evaluation_id == evaluation_1.evaluation_id
        assert resolution.final_evaluation_id == evaluation_2.evaluation_id

        entries = tmp_store.read_trace(episode.trace_id)
        requested = [entry for entry in entries if entry["type"] == "checkpoint.requested"][0]
        evaluated = [entry for entry in entries if entry["type"] == "checkpoint.evaluated"]
        claims = [entry for entry in entries if entry["type"] == CLAIM_ASSERTION_RECEIPT_TYPE]
        snapshots = [entry for entry in entries if entry["type"] == PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE]
        recorded = [entry for entry in entries if entry["type"] == "checkpoint.decision_recorded"]
        resolved = [entry for entry in entries if entry["type"] == "checkpoint.resolved"][0]
        assert len(evaluated) == 2
        assert len(claims) == 2
        assert len(snapshots) == 2
        assert len(recorded) == 2
        assert evaluated[0]["parent_receipt_id"] == requested["receipt_id"]
        assert claims[0]["parent_receipt_id"] == evaluated[0]["receipt_id"]
        assert snapshots[0]["parent_receipt_id"] == claims[0]["receipt_id"]
        assert recorded[0]["parent_receipt_id"] == snapshots[0]["receipt_id"]
        assert evaluated[1]["parent_receipt_id"] == recorded[0]["receipt_id"]
        assert claims[1]["parent_receipt_id"] == evaluated[1]["receipt_id"]
        assert snapshots[1]["parent_receipt_id"] == claims[1]["receipt_id"]
        assert recorded[1]["parent_receipt_id"] == snapshots[1]["receipt_id"]
        assert resolved["parent_receipt_id"] == recorded[1]["receipt_id"]

        result = verify_outbound_email_lifecycle(
            request,
            [evaluation_1, evaluation_2],
            resolution,
            decision_receipts=[decision_1, decision_2],
        )
        assert result.passed is True
        assert result.errors == []

    def test_resolution_cannot_bind_to_superseded_evaluation(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
        reevaluation_template = copy.deepcopy(template)
        reevaluation_template["evaluation_id"] = "cke_01HQXREEVAL"
        reevaluation_template["validity"]["evaluated_at"] = "2026-03-19T12:04:00Z"
        reevaluation_template["audit"]["created_at"] = "2026-03-19T12:04:00Z"

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            flow.evaluate(
                shadow=reevaluation_template["shadow"],
                evidence_bundle=reevaluation_template["evidence_bundle"],
                verifiers=reevaluation_template["verifiers"],
                uncertainty=reevaluation_template["uncertainty"],
                policy=reevaluation_template["policy"],
                evaluation_outcome=reevaluation_template["evaluation_outcome"],
                validity=reevaluation_template["validity"],
                audit=reevaluation_template["audit"],
                evaluation_id=reevaluation_template["evaluation_id"],
            )

            with pytest.raises(CheckpointValidationError, match="current evaluation"):
                flow.resolve(
                    resolution_outcome="expired",
                    reason_codes=["evaluation_freshness_window_elapsed"],
                    release_revalidation_performed=True,
                    evaluation_valid_at_resolution=False,
                    resolved_at="2026-03-19T12:05:02Z",
                    final_evaluation_id=template["evaluation_id"],
                )


class TestOutboundEmailLifecycleVerifier:
    def test_verifier_accepts_consistent_lifecycle(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            request = flow.create_request(
                subject=template["subject"],
                attempt=template["attempt"],
                relying_party=template["relying_party"],
                requested_at=template["requested_at"],
                request_id=template["request_id"],
            )
            evaluation = flow.evaluate(
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
            decision = flow.decide(
                authority_id="assay:checkpoint:human_review",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:05:00Z",
                verdict="APPROVE",
                verdict_reason="Human reviewer approved the outbound send after evaluating the evidence bundle.",
                verdict_reason_codes=["human_approval_granted"],
                confidence="high",
            )
            resolution = flow.resolve(
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

        result = verify_outbound_email_lifecycle(request, evaluation, resolution, decision_receipts=[decision])
        assert result.passed is True
        assert result.errors == []

    def test_verifier_can_require_denial_for_negative_resolution(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.blocked.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            request = flow.create_request(
                subject=template["subject"],
                attempt=template["attempt"],
                relying_party=template["relying_party"],
                requested_at=template["requested_at"],
                request_id=template["request_id"],
            )
            evaluation = flow.evaluate(
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
            decision = flow.decide(
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
            resolution = flow.resolve(
                resolution_outcome="blocked",
                reason_codes=["missing_recipient_verification", "stale_context"],
                release_revalidation_performed=False,
                evaluation_valid_at_resolution=False,
                resolved_at="2026-03-19T12:15:03Z",
            )

        trace_entries = tmp_store.read_trace(episode.trace_id)
        denials = [entry for entry in trace_entries if entry["type"] == DENIAL_RECORD_RECEIPT_TYPE]
        result = verify_outbound_email_lifecycle(
            request,
            evaluation,
            resolution,
            decision_receipts=[decision],
            denial_records=denials,
            require_denial_for_negative_resolution=True,
        )
        assert result.passed is True
        assert result.errors == []

        missing_result = verify_outbound_email_lifecycle(
            request,
            evaluation,
            resolution,
            decision_receipts=[decision],
            denial_records=[],
            require_denial_for_negative_resolution=True,
        )
        assert missing_result.passed is False
        assert "denial_missing_for_negative_resolution" in missing_result.errors

    def test_kernel_bundle_verifier_accepts_checkpoint_bundle(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.blocked.v0.1.json")
        template["evidence_bundle"]["contradictions"] = [
            {
                "lhs_ref": "ev_21",
                "rhs_ref": "ev_22",
                "reason_code": "context_policy_conflict",
                "severity": "blocking",
            }
        ]

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            request = flow.create_request(
                subject=template["subject"],
                attempt=template["attempt"],
                relying_party=template["relying_party"],
                requested_at=template["requested_at"],
                request_id=template["request_id"],
            )
            evaluation = flow.evaluate(
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
            decision = flow.decide(
                authority_id="assay:checkpoint:outbound_email_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="REFUSE",
                verdict_reason="Recipient verification and freshness requirements were not satisfied.",
                verdict_reason_codes=["missing_recipient_verification", "stale_context"],
                evidence_sufficient=False,
                evidence_gaps=["recipient_verified", "fresh_context_snapshot"],
                confidence="moderate",
                proof_tier_at_decision="CHECKED",
                proof_tier_minimum_required="TOOL_VERIFIED",
            )
            resolution = flow.resolve(
                resolution_outcome="blocked",
                reason_codes=["missing_recipient_verification", "stale_context"],
                release_revalidation_performed=False,
                evaluation_valid_at_resolution=False,
                resolved_at="2026-03-19T12:15:03Z",
            )

        result = verify_outbound_email_kernel_bundle(
            request,
            evaluation,
            resolution,
            decision_receipts=[decision],
            claim_assertions=flow.kernel_claims,
            contradictions=flow.kernel_contradictions,
            proof_budget_snapshots=flow.proof_budget_snapshots,
            denial_records=flow.denial_records,
        )
        assert result.passed is True
        assert result.errors == []

    def test_kernel_bundle_verifier_rejects_superseded_contradiction_without_resolution(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.blocked.v0.1.json")
        template["evidence_bundle"]["contradictions"] = [
            {
                "lhs_ref": "ev_21",
                "rhs_ref": "ev_22",
                "reason_code": "context_policy_conflict",
                "severity": "blocking",
            }
        ]

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            request = flow.create_request(
                subject=template["subject"],
                attempt=template["attempt"],
                relying_party=template["relying_party"],
                requested_at=template["requested_at"],
                request_id=template["request_id"],
            )
            evaluation = flow.evaluate(
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
            decision = flow.decide(
                authority_id="assay:checkpoint:outbound_email_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="REFUSE",
                verdict_reason="Contradictory evidence blocked release.",
                verdict_reason_codes=["context_policy_conflict"],
                evidence_sufficient=False,
                evidence_gaps=["recipient_verified", "fresh_context_snapshot"],
                confidence="moderate",
            )
            resolution = flow.resolve(
                resolution_outcome="blocked",
                reason_codes=["context_policy_conflict"],
                release_revalidation_performed=False,
                evaluation_valid_at_resolution=False,
                resolved_at="2026-03-19T12:15:03Z",
            )

        contradiction = flow.kernel_contradictions[0]
        contradiction.status = "superseded"
        result = verify_outbound_email_kernel_bundle(
            request,
            evaluation,
            resolution,
            decision_receipts=[decision],
            claim_assertions=flow.kernel_claims,
            contradictions=[contradiction],
            proof_budget_snapshots=flow.proof_budget_snapshots,
            denial_records=flow.denial_records,
        )
        assert result.passed is False
        assert any("contradiction_terminal_status_requires_resolution" in error for error in result.errors)

    def test_verifier_detects_cross_artifact_mismatch(self) -> None:
        request = _load_example("outbound_action.send_email.request.v0.1.json")
        evaluation = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
        resolution = _load_example("outbound_action.send_email.resolution.released.v0.1.json")
        bad_resolution = CheckpointResolutionArtifact(**{**resolution, "request_id": "req_mismatch"})
        decision = {
            "receipt_id": "9b2ef8da-b2df-467a-ac9e-14f861380a4c",
            "receipt_type": "decision_v1",
            "receipt_version": "0.1.0",
            "ceid": None,
            "timestamp": "2026-03-19T12:05:00Z",
            "parent_receipt_id": None,
            "supersedes": None,
            "decision_type": "checkpoint_authorization",
            "decision_subject": "checkpoint_attempt:chk_01HQXCHK",
            "verdict": "APPROVE",
            "verdict_reason": "Approved by human reviewer.",
            "verdict_reason_codes": ["human_approval_granted"],
            "authority_id": "assay:checkpoint:human_review",
            "authority_class": "BINDING",
            "authority_scope": "outbound_action.send_email",
            "delegated_from": None,
            "policy_id": evaluation["policy"]["policy_id"],
            "policy_hash": evaluation["policy"]["policy_hash"],
            "policy_version": evaluation["policy"]["policy_version"],
            "episode_id": request["subject"]["episode_id"],
            "session_state_hash": None,
            "proof_tier_at_decision": None,
            "runtime_condition_vector": None,
            "evidence_refs": [
                {
                    "ref_type": "external",
                    "ref_id": evaluation["evaluation_id"],
                    "ref_uri": "checkpoint_evaluation:cke_01HQXEVAL",
                    "ref_hash": None,
                    "ref_role": "supporting",
                }
            ],
            "evidence_sufficient": True,
            "evidence_gaps": [],
            "confidence": "high",
            "dissent": None,
            "abstention_reason": None,
            "unresolved_contradictions": [],
            "disposition": "execute",
            "disposition_target": None,
            "obligations_created": [],
            "proof_tier_achieved": None,
            "proof_tier_minimum_required": None,
            "provenance_complete": True,
            "known_provenance_gaps": [],
            "source_organ": "assay-toolkit",
            "content_hash": None,
            "signature": None,
            "signer_pubkey_sha256": None,
        }

        result = verify_outbound_email_lifecycle(
            request,
            evaluation,
            bad_resolution,
            decision_receipts=[decision],
        )
        assert result.passed is False
        assert "request_id_mismatch_between_request_and_resolution" in result.errors
