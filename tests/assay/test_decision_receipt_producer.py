"""Tests for the first Decision Receipt producer: checkpoint lifecycle.

Contract: when a checkpoint flow calls decide(), a decision_v1 receipt
is emitted into the episode trace. This means it survives into
receipt_pack.jsonl and is available for downstream posture evaluation.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from assay import open_episode
from assay.checkpoints import OutboundEmailCheckpointFlow
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


class TestDecisionReceiptInTrace:
    """Decision receipts must appear in the episode trace as decision_v1 receipts."""

    def test_decide_emits_decision_v1_into_trace(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:outbound_email_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="APPROVE",
                verdict_reason="Human reviewer approved the outbound send.",
                verdict_reason_codes=["human_approval_granted"],
                confidence="high",
            )
            flow.resolve(
                resolution_outcome="released",
                reason_codes=["policy_pass"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=True,
                resolved_at="2026-03-19T12:15:03Z",
                decision_receipt_ids=[decision["receipt_id"]],
                human_approval={
                    "approver_id": "user://ops_manager",
                    "decision": "approved",
                    "decided_at": "2026-03-19T12:15:01Z",
                },
            )

        entries = tmp_store.read_trace(episode.trace_id)
        decision_receipts = [e for e in entries if e["type"] == "decision_v1"]

        assert len(decision_receipts) == 1, \
            f"Expected 1 decision_v1 receipt in trace, found {len(decision_receipts)}"

    def test_decision_v1_has_required_fields(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:test_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="APPROVE",
                verdict_reason="All checks passed.",
                verdict_reason_codes=["policy_pass"],
                confidence="high",
            )
            flow.resolve(
                resolution_outcome="released",
                reason_codes=["policy_pass"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=True,
                resolved_at="2026-03-19T12:15:03Z",
                decision_receipt_ids=[decision["receipt_id"]],
                human_approval={
                    "approver_id": "user://reviewer",
                    "decision": "approved",
                    "decided_at": "2026-03-19T12:15:01Z",
                },
            )

        entries = tmp_store.read_trace(episode.trace_id)
        dr = [e for e in entries if e["type"] == "decision_v1"][0]

        assert dr["receipt_type"] == "decision_v1"
        assert dr["verdict"] == "APPROVE"
        assert dr["disposition"] == "execute"
        assert dr["authority_id"] == "assay:checkpoint:test_policy"
        assert dr["authority_class"] == "BINDING"
        assert "policy_id" in dr
        assert "episode_id" in dr
        assert "evidence_sufficient" in dr
        assert "provenance_complete" in dr

    def test_blocked_decision_has_refuse_verdict(self, tmp_store) -> None:
        template = _load_example("outbound_action.send_email.blocked.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:test_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="REFUSE",
                verdict_reason="Policy violation detected.",
                verdict_reason_codes=["stale_context"],
                evidence_sufficient=False,
                evidence_gaps=["fresh_context_snapshot"],
                confidence="moderate",
                proof_tier_at_decision="CHECKED",
                proof_tier_minimum_required="TOOL_VERIFIED",
            )
            flow.resolve(
                resolution_outcome="blocked",
                reason_codes=["stale_context"],
                release_revalidation_performed=False,
                evaluation_valid_at_resolution=False,
            )

        entries = tmp_store.read_trace(episode.trace_id)
        dr = [e for e in entries if e["type"] == "decision_v1"][0]

        assert dr["verdict"] == "REFUSE"
        assert dr["disposition"] == "block"
        assert dr["evidence_sufficient"] is False

    def test_decision_receipt_identity_preserved(self, tmp_store) -> None:
        """The original decision receipt ID must be preserved as decision_receipt_id
        since the episode envelope assigns its own receipt_id."""
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)
            decision = flow.decide(
                authority_id="assay:checkpoint:test_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:15:02Z",
                verdict="APPROVE",
                verdict_reason="Approved.",
                verdict_reason_codes=["policy_pass"],
                confidence="high",
            )
            flow.resolve(
                resolution_outcome="released",
                reason_codes=["policy_pass"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=True,
                resolved_at="2026-03-19T12:15:03Z",
                decision_receipt_ids=[decision["receipt_id"]],
                human_approval={
                    "approver_id": "user://reviewer",
                    "decision": "approved",
                    "decided_at": "2026-03-19T12:15:01Z",
                },
            )

        entries = tmp_store.read_trace(episode.trace_id)
        dr = [e for e in entries if e["type"] == "decision_v1"][0]

        # Envelope gets its own receipt_id (r_<hex>)
        assert dr["receipt_id"].startswith("r_")
        # Original decision receipt ID preserved under decision_receipt_id
        assert dr["decision_receipt_id"] == decision["receipt_id"]
        # Content fields survive
        assert dr["verdict"] == decision["verdict"]
        assert dr["decision_subject"] == decision["decision_subject"]
        assert dr["authority_id"] == decision["authority_id"]

    def test_multiple_decisions_all_emitted(self, tmp_store) -> None:
        """Reevaluation flow: multiple decisions should all appear in trace."""
        template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
        reeval_template = copy.deepcopy(template)
        reeval_template["evaluation_id"] = "cke_REEVAL_01"
        reeval_template["evaluation_outcome"] = {
            "route": "allow_immediately",
            "reason_codes": ["fresh_context_revalidated"],
            "human_review_required": False,
            "release_conditions": [],
        }
        reeval_template["validity"]["evaluated_at"] = "2026-03-19T12:04:00Z"
        reeval_template["validity"]["evidence_valid_until"] = "2026-03-19T13:04:00Z"
        reeval_template["audit"]["created_at"] = "2026-03-19T12:04:00Z"

        with open_episode(store=tmp_store) as episode:
            flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
            _emit_request_and_evaluation(flow, template)

            # First decision: DEFER
            d1 = flow.decide(
                authority_id="assay:checkpoint:test_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:03:00Z",
                verdict="DEFER",
                verdict_reason="Requires human approval.",
                verdict_reason_codes=["human_review_required"],
                confidence="moderate",
            )

            # Reevaluate with fresh evidence
            flow.evaluate(
                shadow=reeval_template["shadow"],
                evidence_bundle=reeval_template["evidence_bundle"],
                verifiers=reeval_template["verifiers"],
                uncertainty=reeval_template["uncertainty"],
                policy=reeval_template["policy"],
                evaluation_outcome=reeval_template["evaluation_outcome"],
                validity=reeval_template["validity"],
                audit=reeval_template["audit"],
                evaluation_id=reeval_template["evaluation_id"],
            )

            # Second decision: APPROVE
            d2 = flow.decide(
                authority_id="assay:checkpoint:test_policy",
                authority_scope="outbound_action.send_email",
                timestamp="2026-03-19T12:05:00Z",
                verdict="APPROVE",
                verdict_reason="Approved after reevaluation.",
                verdict_reason_codes=["reevaluation_pass"],
                confidence="high",
            )

            flow.resolve(
                resolution_outcome="released",
                reason_codes=["policy_pass"],
                release_revalidation_performed=True,
                evaluation_valid_at_resolution=True,
                resolved_at="2026-03-19T12:05:01Z",
                decision_receipt_ids=[d1["receipt_id"], d2["receipt_id"]],
            )

        entries = tmp_store.read_trace(episode.trace_id)
        decision_receipts = [e for e in entries if e["type"] == "decision_v1"]

        assert len(decision_receipts) == 2
        verdicts = [dr["verdict"] for dr in decision_receipts]
        assert "DEFER" in verdicts
        assert "APPROVE" in verdicts
