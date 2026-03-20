"""Counterparty-facing checkpoint attempt views.

Builds a read model over checkpoint lifecycle artifacts for one
`checkpoint_attempt_id` without inventing new lifecycle semantics.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Union

from assay.checkpoints import (
    CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
    CheckpointEvaluationArtifact,
    CheckpointRequestArtifact,
    CheckpointResolutionArtifact,
    CheckpointValidationError,
    verify_outbound_email_lifecycle,
)
from assay.store import AssayStore


TRACE_ENVELOPE_FIELDS = {
    "receipt_id",
    "type",
    "timestamp",
    "episode_id",
    "schema_version",
    "_trace_id",
    "_stored_at",
    "parent_receipt_id",
    "seq",
    "canonical_hash",
}


def _normalize_artifact_dict(
    artifact: Union[
        CheckpointRequestArtifact,
        CheckpointEvaluationArtifact,
        CheckpointResolutionArtifact,
        Dict[str, Any],
    ]
) -> Dict[str, Any]:
    if hasattr(artifact, "to_dict"):
        return artifact.to_dict()  # type: ignore[return-value]
    return dict(artifact)


def _parse_iso8601(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _sort_timestamped(items: Sequence[Dict[str, Any]], timestamp_field: str) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda item: _parse_iso8601(str(item[timestamp_field])))


def _strip_trace_envelope(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in entry.items()
        if key not in TRACE_ENVELOPE_FIELDS
    }


def _select_evaluation_for_attempt_view(
    evaluations: Sequence[Dict[str, Any]],
    resolution: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not evaluations:
        raise CheckpointValidationError("checkpoint attempt view requires at least one evaluation")

    if resolution is None:
        return evaluations[-1]

    selected_evaluation_id = (
        resolution.get("final_evaluation_id")
        or resolution.get("evaluation_id")
    )
    for evaluation in evaluations:
        if evaluation.get("evaluation_id") == selected_evaluation_id:
            return evaluation

    raise CheckpointValidationError(
        f"checkpoint resolution references unknown evaluation_id={selected_evaluation_id!r}"
    )


@dataclass
class CheckpointAttemptArtifactSet:
    checkpoint_attempt_id: str
    checkpoint_type: str
    trace_id: Optional[str]
    request: Dict[str, Any]
    evaluations: List[Dict[str, Any]]
    decision_trace_entries: List[Dict[str, Any]]
    resolution: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CheckpointAttemptView:
    checkpoint_attempt_id: str
    checkpoint_type: str
    trace_id: Optional[str]
    current_state: str
    attempted_crossing: Dict[str, Any]
    last_eligible_posture: Dict[str, Any]
    authority_decisions: List[Dict[str, Any]]
    actual_outcome: Dict[str, Any]
    verification: Dict[str, Any]
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_outbound_email_checkpoint_attempt_artifacts(
    trace_entries: Sequence[Dict[str, Any]],
    *,
    checkpoint_attempt_id: str,
) -> CheckpointAttemptArtifactSet:
    """Extract one outbound email checkpoint attempt from a trace."""
    matching_entries = [
        entry for entry in trace_entries
        if entry.get("checkpoint_id") == checkpoint_attempt_id
    ]
    if not matching_entries:
        raise CheckpointValidationError(
            f"no checkpoint lifecycle artifacts found for checkpoint_attempt_id={checkpoint_attempt_id!r}"
        )

    request_entries = [
        entry for entry in matching_entries
        if entry.get("type") == "checkpoint.requested"
    ]
    evaluation_entries = [
        entry for entry in matching_entries
        if entry.get("type") == "checkpoint.evaluated"
    ]
    decision_trace_entries = [
        entry for entry in matching_entries
        if entry.get("type") == "checkpoint.decision_recorded"
    ]
    resolution_entries = [
        entry for entry in matching_entries
        if entry.get("type") == "checkpoint.resolved"
    ]

    if len(request_entries) != 1:
        raise CheckpointValidationError(
            f"checkpoint_attempt_id={checkpoint_attempt_id!r} must have exactly one checkpoint.requested entry"
        )
    if not evaluation_entries:
        raise CheckpointValidationError(
            f"checkpoint_attempt_id={checkpoint_attempt_id!r} must have at least one checkpoint.evaluated entry"
        )
    if len(resolution_entries) > 1:
        raise CheckpointValidationError(
            f"checkpoint_attempt_id={checkpoint_attempt_id!r} must not have more than one checkpoint.resolved entry"
        )

    checkpoint_types = {entry.get("checkpoint_type") for entry in matching_entries}
    if checkpoint_types != {CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL}:
        raise CheckpointValidationError(
            f"checkpoint_attempt_id={checkpoint_attempt_id!r} has unsupported or mixed checkpoint types: {sorted(checkpoint_types)}"
        )

    trace_ids = {entry.get("_trace_id") for entry in matching_entries if entry.get("_trace_id")}
    trace_id = sorted(trace_ids)[-1] if trace_ids else None

    return CheckpointAttemptArtifactSet(
        checkpoint_attempt_id=checkpoint_attempt_id,
        checkpoint_type=CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
        trace_id=trace_id,
        request=_strip_trace_envelope(request_entries[0]),
        evaluations=[
            _strip_trace_envelope(entry)
            for entry in _sort_timestamped(evaluation_entries, "timestamp")
        ],
        decision_trace_entries=_sort_timestamped(decision_trace_entries, "timestamp"),
        resolution=_strip_trace_envelope(resolution_entries[0]) if resolution_entries else None,
    )


def build_outbound_email_checkpoint_attempt_view(
    request: Union[CheckpointRequestArtifact, Dict[str, Any]],
    evaluation: Union[CheckpointEvaluationArtifact, Dict[str, Any]],
    resolution: Optional[Union[CheckpointResolutionArtifact, Dict[str, Any]]] = None,
    *,
    evaluations: Optional[
        Sequence[Union[CheckpointEvaluationArtifact, Dict[str, Any]]]
    ] = None,
    decision_receipts: Optional[Sequence[Dict[str, Any]]] = None,
    decision_trace_entries: Optional[Sequence[Dict[str, Any]]] = None,
    trace_id: Optional[str] = None,
) -> CheckpointAttemptView:
    """Build a counterparty-facing view for one outbound email checkpoint attempt."""
    request_dict = _normalize_artifact_dict(request)
    evaluation_dict = _normalize_artifact_dict(evaluation)
    resolution_dict = _normalize_artifact_dict(resolution) if resolution is not None else None
    normalized_evaluations = [
        _normalize_artifact_dict(item)
        for item in (evaluations if evaluations is not None else [evaluation_dict])
    ]
    sorted_decisions = _sort_timestamped(
        [dict(decision) for decision in (decision_receipts or [])],
        "timestamp",
    )
    sorted_decision_trace_entries = _sort_timestamped(
        [dict(entry) for entry in (decision_trace_entries or [])],
        "timestamp",
    )

    attempted_crossing = {
        "request_id": request_dict["request_id"],
        "requested_at": request_dict["requested_at"],
        "subject": request_dict["subject"],
        "attempt": request_dict["attempt"],
        "relying_party": request_dict["relying_party"],
    }

    last_eligible_posture = {
        "evaluation_id": evaluation_dict["evaluation_id"],
        "evaluated_at": evaluation_dict["validity"]["evaluated_at"],
        "route": evaluation_dict["evaluation_outcome"]["route"],
        "reason_codes": evaluation_dict["evaluation_outcome"]["reason_codes"],
        "human_review_required": evaluation_dict["evaluation_outcome"]["human_review_required"],
        "release_conditions": evaluation_dict["evaluation_outcome"]["release_conditions"],
        "policy": {
            "policy_id": evaluation_dict["policy"]["policy_id"],
            "policy_version": evaluation_dict["policy"]["policy_version"],
            "policy_hash": evaluation_dict["policy"]["policy_hash"],
            "decision_rule": evaluation_dict["policy"]["decision_rule"],
            "thresholds": evaluation_dict["policy"]["thresholds"],
        },
        "uncertainty": evaluation_dict["uncertainty"],
        "evidence_summary": {
            "bundle_id": evaluation_dict["evidence_bundle"]["bundle_id"],
            "item_count": len(evaluation_dict["evidence_bundle"]["items"]),
            "gap_count": len(evaluation_dict["evidence_bundle"].get("gaps", [])),
            "contradiction_count": len(evaluation_dict["evidence_bundle"].get("contradictions", [])),
            "gaps": evaluation_dict["evidence_bundle"].get("gaps", []),
            "contradictions": evaluation_dict["evidence_bundle"].get("contradictions", []),
        },
        "validity": evaluation_dict["validity"],
    }

    authority_decisions: List[Dict[str, Any]] = []
    limitations: List[str] = []
    if sorted_decisions:
        for decision in sorted_decisions:
            authority_decisions.append({
                "detail_source": "decision_receipt",
                "decision_receipt_id": decision["receipt_id"],
                "timestamp": decision["timestamp"],
                "authority_id": decision["authority_id"],
                "authority_scope": decision["authority_scope"],
                "verdict": decision["verdict"],
                "disposition": decision["disposition"],
                "verdict_reason_codes": decision.get("verdict_reason_codes") or [],
                "evidence_sufficient": decision.get("evidence_sufficient"),
                "evidence_gaps": decision.get("evidence_gaps") or [],
                "obligations_created": decision.get("obligations_created") or [],
            })
    else:
        if sorted_decision_trace_entries:
            limitations.append("canonical_decision_receipts_not_supplied")
        for entry in sorted_decision_trace_entries:
            authority_decisions.append({
                "detail_source": "trace_wrapper",
                "decision_receipt_id": entry.get("decision_receipt_id"),
                "timestamp": entry.get("timestamp"),
                "authority_id": entry.get("authority_id"),
                "authority_scope": None,
                "verdict": entry.get("decision_verdict"),
                "disposition": entry.get("decision_disposition"),
                "verdict_reason_codes": [],
                "evidence_sufficient": None,
                "evidence_gaps": [],
                "obligations_created": [],
            })

    if resolution_dict is None:
        actual_outcome = {
            "status": "pending",
            "resolution_outcome": None,
            "resolved_at": None,
            "final_evaluation_id": None,
            "reason_codes": [],
            "human_approval": None,
            "dispatch_attempted_at": None,
            "effect_observed_at": None,
            "decision_receipt_ids": [],
        }
        current_state = evaluation_dict["evaluation_outcome"]["route"]
    else:
        actual_outcome = {
            "status": "resolved",
            "resolution_id": resolution_dict["resolution_id"],
            "resolution_outcome": resolution_dict["resolution_outcome"],
            "resolved_at": resolution_dict["resolved_at"],
            "final_evaluation_id": (
                resolution_dict.get("final_evaluation_id")
                or resolution_dict["evaluation_id"]
            ),
            "reason_codes": resolution_dict["reason_codes"],
            "human_approval": resolution_dict.get("human_approval"),
            "dispatch_attempted_at": resolution_dict.get("dispatch_attempted_at"),
            "effect_observed_at": resolution_dict.get("effect_observed_at"),
            "decision_receipt_ids": resolution_dict.get("decision_receipt_ids") or [],
            "release_revalidation_performed": resolution_dict["release_revalidation_performed"],
            "evaluation_valid_at_resolution": resolution_dict["evaluation_valid_at_resolution"],
        }
        current_state = resolution_dict["resolution_outcome"]

    verification_status = "not_run"
    verification_errors: List[str] = []
    if resolution_dict is not None:
        if sorted_decisions:
            verification_result = verify_outbound_email_lifecycle(
                request_dict,
                normalized_evaluations,
                resolution_dict,
                decision_receipts=sorted_decisions,
            )
            verification_status = "passed" if verification_result.passed else "failed"
            verification_errors = verification_result.errors
        elif actual_outcome["decision_receipt_ids"]:
            verification_status = "degraded"
            verification_errors = ["decision_receipts_required_for_full_authority_verification"]
            limitations.append("authority_layer_only_proven_by_trace_wrappers")
        else:
            verification_result = verify_outbound_email_lifecycle(
                request_dict,
                normalized_evaluations,
                resolution_dict,
            )
            verification_status = "passed" if verification_result.passed else "failed"
            verification_errors = verification_result.errors

    return CheckpointAttemptView(
        checkpoint_attempt_id=request_dict["checkpoint_id"],
        checkpoint_type=request_dict["checkpoint_type"],
        trace_id=trace_id,
        current_state=current_state,
        attempted_crossing=attempted_crossing,
        last_eligible_posture=last_eligible_posture,
        authority_decisions=authority_decisions,
        actual_outcome=actual_outcome,
        verification={
            "status": verification_status,
            "errors": verification_errors,
        },
        limitations=sorted(set(limitations)),
    )


def build_outbound_email_checkpoint_attempt_view_from_trace(
    trace_entries: Sequence[Dict[str, Any]],
    *,
    checkpoint_attempt_id: str,
    decision_receipts: Optional[Sequence[Dict[str, Any]]] = None,
) -> CheckpointAttemptView:
    """Build a counterparty-facing view for one attempt directly from a trace."""
    artifact_set = load_outbound_email_checkpoint_attempt_artifacts(
        trace_entries,
        checkpoint_attempt_id=checkpoint_attempt_id,
    )
    selected_evaluation = _select_evaluation_for_attempt_view(
        artifact_set.evaluations,
        artifact_set.resolution,
    )
    return build_outbound_email_checkpoint_attempt_view(
        artifact_set.request,
        selected_evaluation,
        artifact_set.resolution,
        evaluations=artifact_set.evaluations,
        decision_receipts=decision_receipts,
        decision_trace_entries=artifact_set.decision_trace_entries,
        trace_id=artifact_set.trace_id,
    )


def load_outbound_email_checkpoint_attempt_view(
    store: AssayStore,
    trace_id: str,
    *,
    checkpoint_attempt_id: str,
    decision_receipts: Optional[Sequence[Dict[str, Any]]] = None,
) -> CheckpointAttemptView:
    """Load a checkpoint attempt view from persisted trace storage."""
    trace_entries = store.read_trace(trace_id)
    return build_outbound_email_checkpoint_attempt_view_from_trace(
        trace_entries,
        checkpoint_attempt_id=checkpoint_attempt_id,
        decision_receipts=decision_receipts,
    )


__all__ = [
    "CheckpointAttemptArtifactSet",
    "CheckpointAttemptView",
    "build_outbound_email_checkpoint_attempt_view",
    "build_outbound_email_checkpoint_attempt_view_from_trace",
    "load_outbound_email_checkpoint_attempt_artifacts",
    "load_outbound_email_checkpoint_attempt_view",
]
