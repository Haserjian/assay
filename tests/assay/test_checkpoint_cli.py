"""CLI tests for checkpoint attempt views."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay import open_episode
from assay.checkpoints import OutboundEmailCheckpointFlow
from assay.commands import assay_app
from assay.store import AssayStore


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = ROOT / "docs" / "examples" / "checkpoints"
runner = CliRunner()


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


def test_checkpoint_view_cli_json_with_decision_receipt(tmp_store, tmp_path: Path) -> None:
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

    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")

    result = runner.invoke(
        assay_app,
        [
            "checkpoint",
            "view",
            template["checkpoint_id"],
            "--trace",
            episode.trace_id,
            "--store-dir",
            str(tmp_store.base_dir),
            "--decision-receipt",
            str(decision_path),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["command"] == "checkpoint view"
    assert payload["checkpoint_attempt_id"] == template["checkpoint_id"]
    assert payload["current_state"] == "released"
    assert payload["verification"]["status"] == "passed"
    assert payload["authority_decisions"][0]["detail_source"] == "decision_receipt"
    assert payload["actual_outcome"]["resolution_outcome"] == "released"


def test_checkpoint_view_cli_json_degrades_without_decision_receipt(tmp_store) -> None:
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

    result = runner.invoke(
        assay_app,
        [
            "checkpoint",
            "view",
            template["checkpoint_id"],
            "--trace",
            episode.trace_id,
            "--store-dir",
            str(tmp_store.base_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["verification"]["status"] == "degraded"
    assert payload["authority_decisions"][0]["detail_source"] == "trace_wrapper"
    assert payload["actual_outcome"]["resolution_outcome"] == "blocked"
    assert "canonical_decision_receipts_not_supplied" in payload["limitations"]


def test_checkpoint_view_cli_human_output(tmp_store, tmp_path: Path) -> None:
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

    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")

    result = runner.invoke(
        assay_app,
        [
            "checkpoint",
            "view",
            template["checkpoint_id"],
            "--trace",
            episode.trace_id,
            "--store-dir",
            str(tmp_store.base_dir),
            "--decision-receipt",
            str(decision_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "assay checkpoint view" in result.stdout
    assert "Attempted Crossing" in result.stdout
    assert "Last Eligible Posture" in result.stdout
    assert "Actual Outcome" in result.stdout
