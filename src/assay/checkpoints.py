"""Checkpoint artifact models, emitters, and lifecycle verification.

Implements a narrow, explicit checkpoint lifecycle for one real path:
`outbound_action.send_email`.

Design goals:
  - Keep request, evaluation, and resolution as separate artifacts.
  - Reuse Episode receipt emission rather than inventing new storage.
  - Validate request, evaluation, and resolution artifacts against normative JSON Schema.
  - Keep v0 narrow enough to harden with tests before expanding.
"""
from __future__ import annotations

import copy
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Dict, List, Optional, Union

from jsonschema import Draft202012Validator

from assay.decision_receipt import validate_decision_receipt
from assay.epistemic_kernel import (
    CLAIM_ASSERTION_RECEIPT_TYPE,
    CONTRADICTION_REGISTRATION_RECEIPT_TYPE,
    CONTRADICTION_RESOLUTION_RECEIPT_TYPE,
    NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES,
    PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE,
    ArtifactVerificationResult,
    ClaimAssertionArtifact,
    ContradictionRegistrationArtifact,
    DenialRecordArtifact,
    ProofBudgetSnapshotArtifact,
    adapt_checkpoint_decision_to_claim_assertion,
    adapt_checkpoint_decision_to_proof_budget_snapshot,
    adapt_checkpoint_evaluation_to_contradiction_grounded_claims,
    adapt_checkpoint_evaluation_to_contradiction_registrations,
    adapt_checkpoint_resolution_to_contradiction_resolutions,
    adapt_checkpoint_resolution_to_denial_record,
    emit_denial_record_to_episode,
    verify_contradiction_registration_artifact,
    verify_contradiction_resolution_artifact,
    verify_claim_artifact_set,
    verify_denial_record,
    verify_proof_budget_snapshot,
)
from assay.episode import Episode


SCHEMA_VERSION = "0.1.0"
CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL = "outbound_action.send_email"

REQUEST_RECEIPT_TYPE = "checkpoint.requested"
EVALUATION_RECEIPT_TYPE = "checkpoint.evaluated"
RESOLUTION_RECEIPT_TYPE = "checkpoint.resolved"

VALID_ACTOR_TYPES = {"agent", "service", "human", "workflow"}
TRACE_ENVELOPE_FIELDS = {
    "receipt_id",
    "type",
    "episode_id",
    "schema_version",
    "_trace_id",
    "_stored_at",
    "_store_seq",
    "parent_receipt_id",
    "seq",
    "canonical_hash",
}
VALID_RESOLUTION_OUTCOMES = {
    "released",
    "blocked",
    "refused",
    "expired",
    "dispatch_failed",
    "review_rejected",
    "escalated",
    "abandoned",
}

DECISION_REQUIRED_OUTCOMES = {
    "released",
    "dispatch_failed",
    "blocked",
    "refused",
}

ROUTE_TO_ALLOWED_RESOLUTIONS = {
    "allow_immediately": {"released", "dispatch_failed", "expired", "abandoned"},
    "allow_if_approved": {"released", "dispatch_failed", "review_rejected", "expired", "abandoned"},
    "block": {"blocked"},
    "refuse": {"refused"},
    "escalate": {"escalated", "abandoned"},
}

ROUTE_TO_DEFAULT_DECISION = {
    "allow_immediately": ("APPROVE", "execute"),
    "allow_if_approved": ("DEFER", "defer_with_obligation"),
    "block": ("REFUSE", "block"),
    "refuse": ("REFUSE", "block"),
    "escalate": ("ABSTAIN", "escalate"),
}

VERDICT_TO_DEFAULT_DISPOSITION = {
    "APPROVE": "execute",
    "REFUSE": "block",
    "DEFER": "defer_with_obligation",
    "ABSTAIN": "escalate",
    "ROLLBACK": "compensate",
    "CONFLICT": "escalate",
}


class CheckpointValidationError(ValueError):
    """Raised when a checkpoint artifact is invalid."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _parse_iso8601(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _require_fields(obj: Dict[str, Any], required: List[str], *, where: str) -> None:
    for field_name in required:
        if field_name not in obj:
            raise CheckpointValidationError(f"{where} missing required field: {field_name}")


_SCHEMA_VALIDATORS: Dict[str, Draft202012Validator] = {}


def _get_schema_validator(schema_name: str) -> Draft202012Validator:
    validator = _SCHEMA_VALIDATORS.get(schema_name)
    if validator is None:
        schema_path = resources.files("assay").joinpath(f"schemas/{schema_name}")
        schema = json.loads(schema_path.read_text())
        validator = Draft202012Validator(schema)
        _SCHEMA_VALIDATORS[schema_name] = validator
    return validator


def _get_outbound_email_request_validator() -> Draft202012Validator:
    return _get_schema_validator("checkpoint_request.outbound_action.send_email.v0.1.schema.json")


def _get_outbound_email_evaluation_validator() -> Draft202012Validator:
    return _get_schema_validator("checkpoint_evaluation.outbound_action.send_email.v0.1.schema.json")


def _get_outbound_email_resolution_validator() -> Draft202012Validator:
    return _get_schema_validator("checkpoint_resolution.outbound_action.send_email.v0.1.schema.json")


def _normalize_artifact(
    artifact: Union[
        "CheckpointRequestArtifact",
        "CheckpointEvaluationArtifact",
        "CheckpointResolutionArtifact",
        Dict[str, Any],
    ]
) -> Dict[str, Any]:
    if hasattr(artifact, "to_dict"):
        return artifact.to_dict()  # type: ignore[return-value]
    return dict(artifact)


def _strip_trace_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in TRACE_ENVELOPE_FIELDS
    }


@dataclass
class CheckpointRequestArtifact:
    request_id: str
    checkpoint_id: str
    checkpoint_type: str
    requested_at: str
    subject: Dict[str, Any]
    attempt: Dict[str, Any]
    relying_party: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "checkpoint_request"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        validator = _get_outbound_email_request_validator()
        validator.validate(self.to_dict())


@dataclass
class CheckpointEvaluationArtifact:
    request_id: str
    checkpoint_id: str
    evaluation_id: str
    checkpoint_type: str
    requested_at: str
    subject: Dict[str, Any]
    attempt: Dict[str, Any]
    relying_party: Dict[str, Any]
    shadow: Dict[str, Any]
    evidence_bundle: Dict[str, Any]
    verifiers: List[Dict[str, Any]]
    uncertainty: Dict[str, Any]
    policy: Dict[str, Any]
    evaluation_outcome: Dict[str, Any]
    validity: Dict[str, Any]
    audit: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "checkpoint_evaluation"
    supersedes_evaluation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        validator = _get_outbound_email_evaluation_validator()
        validator.validate(self.to_dict())


@dataclass
class CheckpointResolutionArtifact:
    request_id: str
    checkpoint_id: str
    evaluation_id: str
    resolution_id: str
    checkpoint_type: str
    resolved_at: str
    resolution_outcome: str
    reason_codes: List[str]
    release_revalidation_performed: bool
    evaluation_valid_at_resolution: bool
    final_evaluation_id: Optional[str] = None
    decision_receipt_ids: List[str] = field(default_factory=list)
    appended_evidence_refs: List[str] = field(default_factory=list)
    human_approval: Optional[Dict[str, Any]] = None
    dispatch_attempted_at: Optional[str] = None
    effect_observed_at: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "checkpoint_resolution"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate_against(self, evaluation: CheckpointEvaluationArtifact) -> None:
        payload = self.to_dict()
        if payload.get("final_evaluation_id") is None:
            payload.pop("final_evaluation_id", None)
        _get_outbound_email_resolution_validator().validate(payload)
        if payload["resolution_outcome"] not in VALID_RESOLUTION_OUTCOMES:
            raise CheckpointValidationError(f"Unknown checkpoint resolution outcome: {payload['resolution_outcome']!r}")
        if not payload["reason_codes"]:
            raise CheckpointValidationError("checkpoint_resolution requires at least one reason code")
        if payload.get("final_evaluation_id") and payload["final_evaluation_id"] != payload["evaluation_id"]:
            raise CheckpointValidationError(
                "final_evaluation_id must match evaluation_id in checkpoint_resolution v0.1"
            )

        evaluation_dict = evaluation.to_dict()
        route = evaluation_dict["evaluation_outcome"]["route"]
        allowed = ROUTE_TO_ALLOWED_RESOLUTIONS.get(route, set())
        if payload["resolution_outcome"] not in allowed:
            raise CheckpointValidationError(
                f"resolution_outcome={payload['resolution_outcome']!r} is not allowed for evaluation route={route!r}"
            )

        resolved_at = _parse_iso8601(payload["resolved_at"])
        valid_until = evaluation_dict["validity"].get("evidence_valid_until")
        if valid_until is not None:
            expiry = _parse_iso8601(valid_until)
            if payload["evaluation_valid_at_resolution"] and resolved_at > expiry:
                raise CheckpointValidationError(
                    "evaluation_valid_at_resolution cannot be true after evidence_valid_until has passed"
                )
            if payload["resolution_outcome"] == "expired" and resolved_at <= expiry:
                raise CheckpointValidationError(
                    "resolution_outcome=expired requires resolved_at after evidence_valid_until"
                )

        release_required = bool(evaluation_dict["validity"]["release_revalidation_required"])
        is_release_like = payload["resolution_outcome"] in {"released", "dispatch_failed"}
        if is_release_like and release_required and not payload["release_revalidation_performed"]:
            raise CheckpointValidationError(
                "release-like resolutions require release_revalidation_performed when evaluation requires it"
            )
        if is_release_like and not payload["evaluation_valid_at_resolution"]:
            raise CheckpointValidationError(
                "release-like resolutions require evaluation_valid_at_resolution=true"
            )

        if payload["resolution_outcome"] == "dispatch_failed" and not payload["dispatch_attempted_at"]:
            raise CheckpointValidationError(
                "dispatch_failed requires dispatch_attempted_at"
            )
        if payload["resolution_outcome"] == "expired" and payload["evaluation_valid_at_resolution"]:
            raise CheckpointValidationError(
                "expired resolutions require evaluation_valid_at_resolution=false"
            )

        approval = payload.get("human_approval")
        if route == "allow_if_approved" and payload["resolution_outcome"] in {"released", "dispatch_failed"}:
            if not approval:
                raise CheckpointValidationError("allow_if_approved release requires human_approval")
            if approval.get("decision") != "approved":
                raise CheckpointValidationError("allow_if_approved release requires human_approval.decision='approved'")
            _require_fields(approval, ["approver_id", "decision", "decided_at"], where="human_approval")
            _parse_iso8601(str(approval["decided_at"]))

        if payload["resolution_outcome"] == "review_rejected":
            if not approval:
                raise CheckpointValidationError("review_rejected requires human_approval")
            if approval.get("decision") != "rejected":
                raise CheckpointValidationError("review_rejected requires human_approval.decision='rejected'")
        if payload["resolution_outcome"] in DECISION_REQUIRED_OUTCOMES and not payload["decision_receipt_ids"]:
            raise CheckpointValidationError(
                "resolution outcomes that finalize authority action require decision_receipt_ids"
            )


@dataclass
class LifecycleVerificationResult:
    passed: bool
    errors: List[str] = field(default_factory=list)


@dataclass
class KernelBundleVerificationResult:
    passed: bool
    errors: List[str] = field(default_factory=list)


def _validate_decision_receipt_or_raise(receipt: Dict[str, Any]) -> None:
    result = validate_decision_receipt(receipt)
    if not result.valid:
        lines = "; ".join(f"{err.rule}:{err.message}" for err in result.errors)
        raise CheckpointValidationError(f"decision_receipt invalid: {lines}")


def _decision_subject(checkpoint_id: str) -> str:
    return f"checkpoint_attempt:{checkpoint_id}"


def _normalize_evaluation_inputs(
    evaluation: Union[
        CheckpointEvaluationArtifact,
        Dict[str, Any],
        List[Union["CheckpointEvaluationArtifact", Dict[str, Any]]],
    ]
) -> List[CheckpointEvaluationArtifact]:
    if isinstance(evaluation, list):
        items = list(evaluation)
    else:
        items = [evaluation]

    normalized: List[CheckpointEvaluationArtifact] = []
    for item in items:
        eval_art = (
            item if isinstance(item, CheckpointEvaluationArtifact)
            else CheckpointEvaluationArtifact(**_normalize_artifact(item))
        )
        eval_art.validate()
        normalized.append(eval_art)
    return normalized


def _evaluation_ref_ids_for_decision(
    decision: Dict[str, Any],
    evaluation_ids: set[str],
) -> List[str]:
    return [
        ref["ref_id"]
        for ref in decision.get("evidence_refs") or []
        if ref.get("ref_id") in evaluation_ids
    ]


def verify_outbound_email_lifecycle(
    request: Union[CheckpointRequestArtifact, Dict[str, Any]],
    evaluation: Union[
        CheckpointEvaluationArtifact,
        Dict[str, Any],
        List[Union[CheckpointEvaluationArtifact, Dict[str, Any]]],
    ],
    resolution: Union[CheckpointResolutionArtifact, Dict[str, Any]],
    decision_receipts: Optional[List[Dict[str, Any]]] = None,
    denial_records: Optional[List[Union[DenialRecordArtifact, Dict[str, Any]]]] = None,
    *,
    require_denial_for_negative_resolution: bool = False,
) -> LifecycleVerificationResult:
    """Verify lifecycle consistency across checkpoint request/evaluation/resolution."""
    errors: List[str] = []

    try:
        req = request if isinstance(request, CheckpointRequestArtifact) else CheckpointRequestArtifact(**_normalize_artifact(request))
        req.validate()
    except Exception as exc:
        errors.append(f"request_invalid: {exc}")
        req = None  # type: ignore[assignment]

    try:
        eval_arts = _normalize_evaluation_inputs(evaluation)
    except Exception as exc:
        errors.append(f"evaluation_invalid: {exc}")
        eval_arts = []

    try:
        res = (
            resolution if isinstance(resolution, CheckpointResolutionArtifact)
            else CheckpointResolutionArtifact(**_normalize_artifact(resolution))
        )
        if eval_arts:
            final_evaluation_id = res.final_evaluation_id or res.evaluation_id
            final_eval_art = next(
                (eval_art for eval_art in eval_arts if eval_art.evaluation_id == final_evaluation_id),
                None,
            )
            if final_eval_art is None:
                raise CheckpointValidationError(
                    f"resolution references unknown evaluation_id={final_evaluation_id!r}"
                )
            res.validate_against(final_eval_art)
        else:
            _get_outbound_email_resolution_validator().validate(res.to_dict())
    except Exception as exc:
        errors.append(f"resolution_invalid: {exc}")
        res = None  # type: ignore[assignment]

    normalized_decisions: List[Dict[str, Any]] = []
    for idx, decision in enumerate(decision_receipts or []):
        try:
            decision_dict = _normalize_artifact(decision)
            _validate_decision_receipt_or_raise(decision_dict)
            normalized_decisions.append(decision_dict)
        except Exception as exc:
            errors.append(f"decision_invalid[{idx}]: {exc}")

    normalized_denials: List[DenialRecordArtifact] = []
    for idx, denial in enumerate(denial_records or []):
        try:
            denial_art = (
                denial
                if isinstance(denial, DenialRecordArtifact)
                else DenialRecordArtifact(
                    **{
                        key: value
                        for key, value in dict(denial).items()
                        if key not in TRACE_ENVELOPE_FIELDS
                    }
                )
            )
            normalized_denials.append(denial_art)
        except Exception as exc:
            errors.append(f"denial_invalid[{idx}]: {exc}")

    if req is None or not eval_arts or res is None:
        return LifecycleVerificationResult(passed=False, errors=errors)

    eval_arts = sorted(
        eval_arts,
        key=lambda eval_art: _parse_iso8601(str(eval_art.validity["evaluated_at"])),
    )
    evaluation_ids = [eval_art.evaluation_id for eval_art in eval_arts]
    if len(set(evaluation_ids)) != len(evaluation_ids):
        errors.append("duplicate_evaluation_id")
    eval_by_id = {eval_art.evaluation_id: eval_art for eval_art in eval_arts}
    evaluation_id_set = set(evaluation_ids)
    final_evaluation_id = res.final_evaluation_id or res.evaluation_id
    final_eval_art = eval_by_id[final_evaluation_id]
    request_time = _parse_iso8601(req.requested_at)

    if len(eval_arts) > 1:
        if eval_arts[0].supersedes_evaluation_id is not None:
            errors.append("initial_evaluation_must_not_supersede")
        for previous_eval, current_eval in zip(eval_arts, eval_arts[1:]):
            if current_eval.supersedes_evaluation_id != previous_eval.evaluation_id:
                errors.append("evaluation_supersession_chain_invalid")
        if eval_arts[-1].evaluation_id != final_eval_art.evaluation_id:
            errors.append("resolution_uses_superseded_evaluation")

    for eval_art in eval_arts:
        if req.request_id != eval_art.request_id:
            errors.append("request_id_mismatch_between_request_and_evaluation")
        if req.checkpoint_id != eval_art.checkpoint_id:
            errors.append("checkpoint_id_mismatch_between_request_and_evaluation")
        if req.checkpoint_type != eval_art.checkpoint_type:
            errors.append("checkpoint_type_mismatch_between_request_and_evaluation")
        if req.subject != eval_art.subject:
            errors.append("subject_mismatch_between_request_and_evaluation")
        if req.attempt != eval_art.attempt:
            errors.append("attempt_mismatch_between_request_and_evaluation")
        if req.relying_party != eval_art.relying_party:
            errors.append("relying_party_mismatch_between_request_and_evaluation")

    if req.request_id != res.request_id:
        errors.append("request_id_mismatch_between_request_and_resolution")
    if req.checkpoint_id != res.checkpoint_id:
        errors.append("checkpoint_id_mismatch_between_request_and_resolution")
    if final_eval_art.evaluation_id != res.evaluation_id:
        errors.append("evaluation_id_mismatch_between_evaluation_and_resolution")
    if final_eval_art.checkpoint_type != res.checkpoint_type:
        errors.append("checkpoint_type_mismatch_between_evaluation_and_resolution")

    evaluated_time = _parse_iso8601(str(final_eval_art.validity["evaluated_at"]))
    resolved_time = _parse_iso8601(res.resolved_at)

    for eval_art in eval_arts:
        if _parse_iso8601(str(eval_art.validity["evaluated_at"])) < request_time:
            errors.append("evaluation_precedes_request")
    if resolved_time < evaluated_time:
        errors.append("resolution_precedes_evaluation")

    approval = res.human_approval
    if approval:
        approval_time = _parse_iso8601(str(approval["decided_at"]))
        if approval_time < request_time:
            errors.append("approval_precedes_request")
        if approval_time > resolved_time:
            errors.append("approval_after_resolution")

    if res.resolution_outcome in DECISION_REQUIRED_OUTCOMES and not normalized_decisions:
        errors.append("decision_missing_for_terminal_outcome")

    decision_ids = [decision["receipt_id"] for decision in normalized_decisions]
    for expected_id in res.decision_receipt_ids:
        if expected_id not in decision_ids:
            errors.append(f"resolution_references_unknown_decision:{expected_id}")

    normalized_decisions.sort(key=lambda decision: _parse_iso8601(str(decision["timestamp"])))
    last_decision_bound_evaluation_id: Optional[str] = None
    for decision in normalized_decisions:
        if decision["episode_id"] != req.subject["episode_id"]:
            errors.append("decision_episode_id_mismatch")
        if decision["decision_subject"] != _decision_subject(req.checkpoint_id):
            errors.append("decision_subject_mismatch")
        decision_time = _parse_iso8601(str(decision["timestamp"]))
        if decision_time < request_time:
            errors.append("decision_precedes_request")
        if decision_time > resolved_time:
            errors.append("decision_after_resolution")
        bound_evaluation_ids = _evaluation_ref_ids_for_decision(decision, evaluation_id_set)
        if not bound_evaluation_ids:
            errors.append("decision_missing_evaluation_ref")
            continue
        if len(bound_evaluation_ids) > 1:
            errors.append("decision_references_multiple_evaluations")
            continue

        bound_evaluation_id = bound_evaluation_ids[0]
        bound_eval_art = eval_by_id[bound_evaluation_id]
        last_decision_bound_evaluation_id = bound_evaluation_id
        bound_evaluated_time = _parse_iso8601(str(bound_eval_art.validity["evaluated_at"]))

        if decision["policy_id"] != bound_eval_art.policy["policy_id"]:
            errors.append("decision_policy_id_mismatch")
        if decision["policy_hash"] != bound_eval_art.policy["policy_hash"]:
            errors.append("decision_policy_hash_mismatch")
        if decision_time < bound_evaluated_time:
            errors.append("decision_precedes_evaluation")
        effective_evaluations = [
            eval_art
            for eval_art in eval_arts
            if _parse_iso8601(str(eval_art.validity["evaluated_at"])) <= decision_time
        ]
        if effective_evaluations and effective_evaluations[-1].evaluation_id != bound_evaluation_id:
            errors.append("decision_uses_superseded_evaluation")

    if normalized_decisions:
        last_decision = normalized_decisions[-1]
        if last_decision_bound_evaluation_id != final_eval_art.evaluation_id:
            errors.append("final_decision_not_bound_to_final_evaluation")
        if res.resolution_outcome in {"released", "dispatch_failed"}:
            if last_decision["verdict"] != "APPROVE" or last_decision["disposition"] != "execute":
                errors.append("release_like_resolution_requires_approve_execute_decision")
        if res.resolution_outcome == "blocked":
            if last_decision["verdict"] != "REFUSE" or last_decision["disposition"] != "block":
                errors.append("blocked_resolution_requires_refuse_block_decision")
        if res.resolution_outcome == "refused":
            if last_decision["verdict"] != "REFUSE":
                errors.append("refused_resolution_requires_refuse_decision")

    if res.resolution_outcome in NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES:
        known_refs = {
            "request_id": [req.request_id],
            "evaluation_id": list(evaluation_id_set),
            "resolution_id": [res.resolution_id],
            "decision_receipt_ids": decision_ids,
        }
        source_timestamps = {
            req.request_id: req.requested_at,
            res.resolution_id: res.resolved_at,
        }
        for eval_art in eval_arts:
            source_timestamps[eval_art.evaluation_id] = str(eval_art.validity["evaluated_at"])
        for decision in normalized_decisions:
            source_timestamps[decision["receipt_id"]] = str(decision["timestamp"])

        linked_denials = [
            denial
            for denial in normalized_denials
            if denial.backward_refs.get("resolution_id") == res.resolution_id
        ]
        if require_denial_for_negative_resolution and not linked_denials:
            errors.append("denial_missing_for_negative_resolution")
        for denial in linked_denials:
            denial_result = verify_denial_record(
                denial,
                known_refs=known_refs,
                source_timestamps=source_timestamps,
            )
            errors.extend(denial_result.errors)
            if denial.subject.get("subject_id") != req.checkpoint_id:
                errors.append("denial_subject_checkpoint_id_mismatch")
            if denial.denial_outcome != res.resolution_outcome:
                errors.append("denial_outcome_mismatch_with_resolution")

    return LifecycleVerificationResult(passed=not errors, errors=errors)


class OutboundEmailCheckpointFlow:
    """Explicit request -> evaluation -> resolution emitter for outbound email sends."""

    def __init__(self, episode: Episode, *, checkpoint_id: Optional[str] = None) -> None:
        self._episode = episode
        self.checkpoint_id = checkpoint_id or _new_id("chk")
        self.request: Optional[CheckpointRequestArtifact] = None
        self.evaluation: Optional[CheckpointEvaluationArtifact] = None
        self.evaluations: List[CheckpointEvaluationArtifact] = []
        self.decision_receipts: List[Dict[str, Any]] = []
        self.resolution: Optional[CheckpointResolutionArtifact] = None
        self.request_receipt_id: Optional[str] = None
        self.evaluation_receipt_id: Optional[str] = None
        self.evaluation_receipt_ids_by_id: Dict[str, str] = {}
        self.current_evaluation_id: Optional[str] = None
        self.decision_trace_receipt_ids: List[str] = []
        self.resolution_receipt_id: Optional[str] = None
        self.denial_records: List[DenialRecordArtifact] = []
        self.denial_record_receipt_ids: List[str] = []
        self.kernel_claims: List[ClaimAssertionArtifact] = []
        self.kernel_claim_receipt_ids: List[str] = []
        self.kernel_claim_ids_by_decision_receipt_id: Dict[str, List[str]] = {}
        self.kernel_contradictions: List[ContradictionRegistrationArtifact] = []
        self.kernel_contradiction_receipt_ids: List[str] = []
        self.kernel_contradiction_ids_by_decision_receipt_id: Dict[str, List[str]] = {}
        self.kernel_contradiction_resolutions: List[Any] = []
        self.kernel_contradiction_resolution_receipt_ids: List[str] = []
        self.proof_budget_snapshots: List[ProofBudgetSnapshotArtifact] = []
        self.proof_budget_snapshot_receipt_ids: List[str] = []
        self.proof_budget_snapshot_ids_by_decision_receipt_id: Dict[str, str] = {}
        self.last_trace_receipt_id: Optional[str] = None

    def _get_evaluation(self, evaluation_id: str) -> CheckpointEvaluationArtifact:
        for evaluation in self.evaluations:
            if evaluation.evaluation_id == evaluation_id:
                return evaluation
        raise CheckpointValidationError(f"unknown checkpoint evaluation: {evaluation_id!r}")

    def _select_action_evaluation(
        self,
        evaluation_id: Optional[str],
        *,
        action_name: str,
    ) -> CheckpointEvaluationArtifact:
        target_id = evaluation_id or self.current_evaluation_id
        if target_id is None:
            raise CheckpointValidationError(
                f"{action_name} requires an existing checkpoint_evaluation"
            )
        evaluation = self._get_evaluation(target_id)
        if self.current_evaluation_id is not None and evaluation.evaluation_id != self.current_evaluation_id:
            raise CheckpointValidationError(
                f"{action_name} must use the current evaluation; {evaluation.evaluation_id!r} has been superseded"
            )
        return evaluation

    def create_request(
        self,
        *,
        subject: Dict[str, Any],
        attempt: Dict[str, Any],
        relying_party: Dict[str, Any],
        requested_at: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> CheckpointRequestArtifact:
        if self.request is not None:
            raise CheckpointValidationError("checkpoint_request already emitted for this flow")
        request = CheckpointRequestArtifact(
            request_id=request_id or _new_id("req"),
            checkpoint_id=self.checkpoint_id,
            checkpoint_type=CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
            requested_at=requested_at or _now_iso(),
            subject=copy.deepcopy(subject),
            attempt=copy.deepcopy(attempt),
            relying_party=copy.deepcopy(relying_party),
        )
        request.validate()
        self.request = request
        self.request_receipt_id = self._episode.emit(REQUEST_RECEIPT_TYPE, request.to_dict())
        self.last_trace_receipt_id = self.request_receipt_id
        return request

    def evaluate(
        self,
        *,
        shadow: Dict[str, Any],
        evidence_bundle: Dict[str, Any],
        verifiers: List[Dict[str, Any]],
        uncertainty: Dict[str, Any],
        policy: Dict[str, Any],
        evaluation_outcome: Dict[str, Any],
        validity: Dict[str, Any],
        audit: Dict[str, Any],
        evaluation_id: Optional[str] = None,
        supersedes_evaluation_id: Optional[str] = None,
    ) -> CheckpointEvaluationArtifact:
        if self.request is None:
            raise CheckpointValidationError("checkpoint_evaluation requires an existing checkpoint_request")
        if self.resolution is not None:
            raise CheckpointValidationError("checkpoint_evaluation cannot be emitted after checkpoint_resolution")
        current_evaluation = self.evaluation
        if current_evaluation is None and supersedes_evaluation_id is not None:
            raise CheckpointValidationError(
                "initial checkpoint_evaluation cannot supersede a prior evaluation"
            )
        if current_evaluation is not None:
            expected_supersedes = current_evaluation.evaluation_id
            if supersedes_evaluation_id is None:
                supersedes_evaluation_id = expected_supersedes
            elif supersedes_evaluation_id != expected_supersedes:
                raise CheckpointValidationError(
                    "reevaluation must supersede the current evaluation"
                )
        evaluation = CheckpointEvaluationArtifact(
            request_id=self.request.request_id,
            checkpoint_id=self.checkpoint_id,
            evaluation_id=evaluation_id or _new_id("cke"),
            checkpoint_type=CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
            requested_at=self.request.requested_at,
            subject=copy.deepcopy(self.request.subject),
            attempt=copy.deepcopy(self.request.attempt),
            relying_party=copy.deepcopy(self.request.relying_party),
            shadow=copy.deepcopy(shadow),
            evidence_bundle=copy.deepcopy(evidence_bundle),
            verifiers=copy.deepcopy(verifiers),
            uncertainty=copy.deepcopy(uncertainty),
            policy=copy.deepcopy(policy),
            evaluation_outcome=copy.deepcopy(evaluation_outcome),
            validity=copy.deepcopy(validity),
            audit=copy.deepcopy(audit),
            supersedes_evaluation_id=supersedes_evaluation_id,
        )
        evaluation.validate()
        evaluated_time = _parse_iso8601(str(evaluation.validity["evaluated_at"]))
        if evaluated_time < _parse_iso8601(self.request.requested_at):
            raise CheckpointValidationError("checkpoint_evaluation cannot precede checkpoint_request")
        if current_evaluation is not None:
            current_time = _parse_iso8601(str(current_evaluation.validity["evaluated_at"]))
            if evaluated_time < current_time:
                raise CheckpointValidationError(
                    "reevaluation must not precede the evaluation it supersedes"
                )
        self.evaluations.append(evaluation)
        self.evaluation = evaluation
        self.current_evaluation_id = evaluation.evaluation_id
        self.evaluation_receipt_id = self._episode.emit(
            EVALUATION_RECEIPT_TYPE,
            evaluation.to_dict(),
            parent_receipt_id=self.last_trace_receipt_id,
        )
        self.evaluation_receipt_ids_by_id[evaluation.evaluation_id] = self.evaluation_receipt_id
        self.last_trace_receipt_id = self.evaluation_receipt_id
        return evaluation

    def decide(
        self,
        *,
        authority_id: str,
        authority_scope: str,
        verdict_reason: str,
        verdict_reason_codes: List[str],
        authority_class: str = "BINDING",
        verdict: Optional[str] = None,
        disposition: Optional[str] = None,
        timestamp: Optional[str] = None,
        decision_type: str = "checkpoint_authorization",
        decision_subject: Optional[str] = None,
        delegated_from: Optional[str] = None,
        evidence_refs: Optional[List[Dict[str, Any]]] = None,
        evidence_sufficient: Optional[bool] = None,
        evidence_gaps: Optional[List[str]] = None,
        confidence: Optional[str] = None,
        disposition_target: Optional[str] = None,
        obligations_created: Optional[List[str]] = None,
        abstention_reason: Optional[str] = None,
        proof_tier_at_decision: Optional[str] = None,
        proof_tier_minimum_required: Optional[str] = None,
        known_provenance_gaps: Optional[List[str]] = None,
        provenance_complete: bool = True,
        source_organ: str = "assay-toolkit",
        evaluation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.request is None or not self.evaluations:
            raise CheckpointValidationError(
                "decision emission requires existing checkpoint_request and checkpoint_evaluation"
            )
        if self.resolution is not None:
            raise CheckpointValidationError("decision emission cannot occur after checkpoint_resolution")
        evaluation = self._select_action_evaluation(evaluation_id, action_name="decision emission")

        route = evaluation.evaluation_outcome["route"]
        default_verdict, default_disposition = ROUTE_TO_DEFAULT_DECISION[route]
        final_verdict = verdict or default_verdict
        final_disposition = disposition or (
            default_disposition
            if verdict is None
            else VERDICT_TO_DEFAULT_DISPOSITION.get(final_verdict, default_disposition)
        )
        decision_timestamp = timestamp or _now_iso()

        evaluation_ref = {
            "ref_type": "external",
            "ref_id": evaluation.evaluation_id,
            "ref_uri": f"checkpoint_evaluation:{evaluation.evaluation_id}",
            "ref_hash": None,
            "ref_role": "supporting",
        }
        request_ref = {
            "ref_type": "external",
            "ref_id": self.request.request_id,
            "ref_uri": f"checkpoint_request:{self.request.request_id}",
            "ref_hash": None,
            "ref_role": "contextual",
        }
        merged_evidence_refs = [evaluation_ref, request_ref]
        if evidence_refs:
            merged_evidence_refs.extend(copy.deepcopy(evidence_refs))

        default_gaps = list(evidence_gaps or [])
        if final_verdict == "DEFER" and not default_gaps:
            default_gaps = ["human_approval"]

        if evidence_sufficient is None:
            if final_verdict == "APPROVE":
                final_evidence_sufficient = True
            elif final_verdict == "DEFER":
                final_evidence_sufficient = False
            else:
                final_evidence_sufficient = not bool(evaluation.evidence_bundle.get("gaps"))
        else:
            final_evidence_sufficient = evidence_sufficient

        normalized_obligations = list(obligations_created or [])
        if final_verdict == "DEFER" and final_disposition == "defer_with_obligation" and not normalized_obligations:
            normalized_obligations = ["obtain_human_approval_before_release"]

        final_abstention_reason = abstention_reason
        if final_verdict == "ABSTAIN" and not final_abstention_reason:
            final_abstention_reason = "Escalation required under checkpoint policy."

        kernel_contradictions = adapt_checkpoint_evaluation_to_contradiction_registrations(
            self.request,
            evaluation,
            {"receipt_id": "pending", "timestamp": decision_timestamp},
            timestamp=decision_timestamp,
        )
        contradiction_ids = [artifact.contradiction_id for artifact in kernel_contradictions]
        decision_receipt: Dict[str, Any] = {
            "receipt_id": str(uuid.uuid4()),
            "receipt_type": "decision_v1",
            "receipt_version": "0.1.0",
            "ceid": None,
            "timestamp": decision_timestamp,
            "parent_receipt_id": (
                self.decision_receipts[-1]["receipt_id"]
                if self.decision_receipts
                else None
            ),
            "supersedes": None,
            "decision_type": decision_type,
            "decision_subject": decision_subject or _decision_subject(self.checkpoint_id),
            "verdict": final_verdict,
            "verdict_reason": verdict_reason,
            "verdict_reason_codes": list(verdict_reason_codes),
            "authority_id": authority_id,
            "authority_class": authority_class,
            "authority_scope": authority_scope,
            "delegated_from": delegated_from,
            "policy_id": evaluation.policy["policy_id"],
            "policy_hash": evaluation.policy["policy_hash"],
            "policy_version": evaluation.policy["policy_version"],
            "episode_id": self.request.subject["episode_id"],
            "session_state_hash": None,
            "proof_tier_at_decision": proof_tier_at_decision,
            "runtime_condition_vector": None,
            "evidence_refs": merged_evidence_refs,
            "evidence_sufficient": final_evidence_sufficient,
            "evidence_gaps": default_gaps,
            "confidence": confidence,
            "dissent": None,
            "abstention_reason": final_abstention_reason,
            "unresolved_contradictions": contradiction_ids,
            "disposition": final_disposition,
            "disposition_target": disposition_target,
            "obligations_created": normalized_obligations,
            "proof_tier_achieved": None,
            "proof_tier_minimum_required": proof_tier_minimum_required,
            "provenance_complete": provenance_complete,
            "known_provenance_gaps": list(known_provenance_gaps or []),
            "source_organ": source_organ,
            "content_hash": None,
            "signature": None,
            "signer_pubkey_sha256": None,
        }

        _validate_decision_receipt_or_raise(decision_receipt)
        grounded_claims = adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
            self.request,
            evaluation,
            {"receipt_id": decision_receipt["receipt_id"], "timestamp": decision_timestamp},
            timestamp=decision_timestamp,
        )
        self.decision_receipts.append(decision_receipt)
        kernel_claim = adapt_checkpoint_decision_to_claim_assertion(
            self.request,
            evaluation,
            decision_receipt,
        )
        kernel_claim.validate()
        kernel_claim_receipt_id = self._episode.emit(
            CLAIM_ASSERTION_RECEIPT_TYPE,
            kernel_claim.to_dict(),
            parent_receipt_id=self.last_trace_receipt_id,
        )
        self.kernel_claims.append(kernel_claim)
        self.kernel_claim_receipt_ids.append(kernel_claim_receipt_id)
        decision_claim_ids = [kernel_claim.claim_id]
        contradiction_parent_receipt_id = kernel_claim_receipt_id
        for grounded_claim in grounded_claims:
            grounded_claim.validate()
            grounded_claim_receipt_id = self._episode.emit(
                CLAIM_ASSERTION_RECEIPT_TYPE,
                grounded_claim.to_dict(),
                parent_receipt_id=contradiction_parent_receipt_id,
            )
            self.kernel_claims.append(grounded_claim)
            self.kernel_claim_receipt_ids.append(grounded_claim_receipt_id)
            decision_claim_ids.append(grounded_claim.claim_id)
            contradiction_parent_receipt_id = grounded_claim_receipt_id
        for contradiction in kernel_contradictions:
            contradiction.boundary_refs["decision_receipt_id"] = decision_receipt["receipt_id"]
            contradiction.validate()
            contradiction_receipt_id = self._episode.emit(
                CONTRADICTION_REGISTRATION_RECEIPT_TYPE,
                contradiction.to_dict(),
                parent_receipt_id=contradiction_parent_receipt_id,
            )
            self.kernel_contradictions.append(contradiction)
            self.kernel_contradiction_receipt_ids.append(contradiction_receipt_id)
            contradiction_parent_receipt_id = contradiction_receipt_id
        proof_budget_snapshot = adapt_checkpoint_decision_to_proof_budget_snapshot(
            self.request,
            evaluation,
            decision_receipt,
            claim_ids=decision_claim_ids,
            contradiction_ids=contradiction_ids,
        )
        proof_budget_snapshot.validate()
        proof_budget_snapshot_receipt_id = self._episode.emit(
            PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE,
            proof_budget_snapshot.to_dict(),
            parent_receipt_id=contradiction_parent_receipt_id,
        )
        self.proof_budget_snapshots.append(proof_budget_snapshot)
        self.proof_budget_snapshot_receipt_ids.append(proof_budget_snapshot_receipt_id)
        self.kernel_claim_ids_by_decision_receipt_id[decision_receipt["receipt_id"]] = decision_claim_ids
        self.kernel_contradiction_ids_by_decision_receipt_id[decision_receipt["receipt_id"]] = contradiction_ids
        self.proof_budget_snapshot_ids_by_decision_receipt_id[decision_receipt["receipt_id"]] = (
            proof_budget_snapshot.snapshot_id
        )
        decision_trace_receipt_id = self._episode.emit(
            "checkpoint.decision_recorded",
            {
                "checkpoint_id": self.checkpoint_id,
                "checkpoint_type": CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
                "request_id": self.request.request_id,
                "evaluation_id": evaluation.evaluation_id,
                "decision_receipt_id": decision_receipt["receipt_id"],
                "decision_verdict": decision_receipt["verdict"],
                "decision_disposition": decision_receipt["disposition"],
                "authority_id": authority_id,
                "decision_subject": decision_receipt["decision_subject"],
                "kernel_claim_ids": decision_claim_ids,
                "contradiction_ids": contradiction_ids,
                "proof_budget_snapshot_id": proof_budget_snapshot.snapshot_id,
            },
            parent_receipt_id=proof_budget_snapshot_receipt_id,
        )
        self.decision_trace_receipt_ids.append(decision_trace_receipt_id)
        self.last_trace_receipt_id = decision_trace_receipt_id
        return decision_receipt

    def resolve(
        self,
        *,
        resolution_outcome: str,
        reason_codes: List[str],
        release_revalidation_performed: bool,
        evaluation_valid_at_resolution: bool,
        resolved_at: Optional[str] = None,
        resolution_id: Optional[str] = None,
        decision_receipt_ids: Optional[List[str]] = None,
        appended_evidence_refs: Optional[List[str]] = None,
        human_approval: Optional[Dict[str, Any]] = None,
        dispatch_attempted_at: Optional[str] = None,
        effect_observed_at: Optional[str] = None,
        final_evaluation_id: Optional[str] = None,
    ) -> CheckpointResolutionArtifact:
        if self.request is None or not self.evaluations:
            raise CheckpointValidationError(
                "checkpoint_resolution requires existing checkpoint_request and checkpoint_evaluation"
            )
        if self.resolution is not None:
            raise CheckpointValidationError("checkpoint_resolution already emitted for this flow")
        evaluation = self._select_action_evaluation(final_evaluation_id, action_name="checkpoint_resolution")
        resolution = CheckpointResolutionArtifact(
            request_id=self.request.request_id,
            checkpoint_id=self.checkpoint_id,
            evaluation_id=evaluation.evaluation_id,
            resolution_id=resolution_id or _new_id("ckr"),
            final_evaluation_id=evaluation.evaluation_id,
            checkpoint_type=CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
            resolved_at=resolved_at or _now_iso(),
            resolution_outcome=resolution_outcome,
            reason_codes=list(reason_codes),
            release_revalidation_performed=release_revalidation_performed,
            evaluation_valid_at_resolution=evaluation_valid_at_resolution,
            decision_receipt_ids=list(
                decision_receipt_ids
                if decision_receipt_ids is not None
                else [decision["receipt_id"] for decision in self.decision_receipts]
            ),
            appended_evidence_refs=list(appended_evidence_refs or []),
            human_approval=copy.deepcopy(human_approval),
            dispatch_attempted_at=dispatch_attempted_at,
            effect_observed_at=effect_observed_at,
        )
        resolution.validate_against(evaluation)
        self.resolution = resolution
        self.resolution_receipt_id = self._episode.emit(
            RESOLUTION_RECEIPT_TYPE,
            resolution.to_dict(),
            parent_receipt_id=self.last_trace_receipt_id,
        )
        self.last_trace_receipt_id = self.resolution_receipt_id
        if resolution_outcome in NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES:
            related_claim_ids: List[str] = []
            proof_budget_snapshot_id: Optional[str] = None
            contradiction_ids: List[str] = []
            for decision_receipt_id in resolution.decision_receipt_ids:
                related_claim_ids.extend(
                    self.kernel_claim_ids_by_decision_receipt_id.get(decision_receipt_id, [])
                )
                contradiction_ids.extend(
                    self.kernel_contradiction_ids_by_decision_receipt_id.get(decision_receipt_id, [])
                )
                snapshot_id = self.proof_budget_snapshot_ids_by_decision_receipt_id.get(decision_receipt_id)
                if snapshot_id:
                    proof_budget_snapshot_id = snapshot_id
            denial_record = adapt_checkpoint_resolution_to_denial_record(
                self.request,
                evaluation,
                resolution,
                related_claim_ids=related_claim_ids,
                proof_budget_snapshot_id=proof_budget_snapshot_id,
                contradiction_ids=contradiction_ids,
            )
            denial_receipt_id = emit_denial_record_to_episode(
                self._episode,
                denial_record,
                parent_receipt_id=self.resolution_receipt_id,
            )
            self.denial_records.append(denial_record)
            self.denial_record_receipt_ids.append(denial_receipt_id)
            self.last_trace_receipt_id = denial_receipt_id

        # Emit contradiction resolutions for any registered contradictions
        if self.kernel_contradictions:
            contradiction_resolution_artifacts = adapt_checkpoint_resolution_to_contradiction_resolutions(
                self.request,
                resolution,
                self.kernel_contradictions,
                decision_receipt_ids=resolution.decision_receipt_ids,
            )
            for ctr_resolution in contradiction_resolution_artifacts:
                ctr_resolution.validate()
                ctr_receipt_id = self._episode.emit(
                    CONTRADICTION_RESOLUTION_RECEIPT_TYPE,
                    ctr_resolution.to_dict(),
                    parent_receipt_id=self.last_trace_receipt_id,
                )
                self.kernel_contradiction_resolutions.append(ctr_resolution)
                self.kernel_contradiction_resolution_receipt_ids.append(ctr_receipt_id)
                self.last_trace_receipt_id = ctr_receipt_id

        return resolution


def verify_outbound_email_kernel_bundle(
    request: Union[CheckpointRequestArtifact, Dict[str, Any]],
    evaluation: Union[
        CheckpointEvaluationArtifact,
        Dict[str, Any],
        List[Union[CheckpointEvaluationArtifact, Dict[str, Any]]],
    ],
    resolution: Union[CheckpointResolutionArtifact, Dict[str, Any]],
    *,
    decision_receipts: Optional[List[Dict[str, Any]]] = None,
    claim_assertions: Optional[List[Union[ClaimAssertionArtifact, Dict[str, Any]]]] = None,
    contradictions: Optional[List[Union[ContradictionRegistrationArtifact, Dict[str, Any]]]] = None,
    contradiction_resolutions: Optional[List[Dict[str, Any]]] = None,
    proof_budget_snapshots: Optional[List[Union[ProofBudgetSnapshotArtifact, Dict[str, Any]]]] = None,
    denial_records: Optional[List[Union[DenialRecordArtifact, Dict[str, Any]]]] = None,
) -> KernelBundleVerificationResult:
    errors: List[str] = []
    lifecycle_result = verify_outbound_email_lifecycle(
        request,
        evaluation,
        resolution,
        decision_receipts=decision_receipts,
        denial_records=denial_records,
        require_denial_for_negative_resolution=_normalize_artifact(resolution).get("resolution_outcome") in NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES,
    )
    errors.extend(lifecycle_result.errors)

    normalized_claims = [
        item
        if isinstance(item, ClaimAssertionArtifact)
        else ClaimAssertionArtifact(**_strip_trace_fields(_normalize_artifact(item)))
        for item in (claim_assertions or [])
    ]
    claim_result = verify_claim_artifact_set(normalized_claims, [])
    errors.extend(claim_result.errors)
    claim_ids = {claim.claim_id for claim in normalized_claims}

    normalized_contradictions: List[ContradictionRegistrationArtifact] = []
    contradiction_ids: set[str] = set()
    contradictions_by_decision: Dict[str, List[ContradictionRegistrationArtifact]] = {}
    for idx, item in enumerate(contradictions or []):
        contradiction = (
            item
            if isinstance(item, ContradictionRegistrationArtifact)
            else ContradictionRegistrationArtifact(**_strip_trace_fields(_normalize_artifact(item)))
        )
        contradiction_result = verify_contradiction_registration_artifact(contradiction)
        normalized_contradictions.append(contradiction)
        contradiction_ids.add(contradiction.contradiction_id)
        contradictions_by_decision.setdefault(
            contradiction.boundary_refs.get("decision_receipt_id", ""),
            [],
        ).append(contradiction)
        for error in contradiction_result.errors:
            errors.append(f"contradiction[{idx}]:{error}")

    resolution_by_contradiction_id: Dict[str, Dict[str, Any]] = {}
    for idx, resolution_item in enumerate(contradiction_resolutions or []):
        resolution_result = verify_contradiction_resolution_artifact(resolution_item)
        resolution_id = str(resolution_item.get("resolution_id") or f"<resolution:{idx}>")
        resolution_by_contradiction_id[str(resolution_item.get("contradiction_id") or "")] = dict(resolution_item)
        for error in resolution_result.errors:
            errors.append(f"contradiction_resolution[{resolution_id}]:{error}")

    for contradiction in normalized_contradictions:
        status = contradiction.status
        resolution = resolution_by_contradiction_id.get(contradiction.contradiction_id)
        if status in {"settled", "superseded"} and resolution is None:
            errors.append(f"contradiction_terminal_status_requires_resolution:{contradiction.contradiction_id}:{status}")
        if status in {"open", "contained"} and resolution is not None:
            errors.append(f"contradiction_open_status_conflicts_with_resolution:{contradiction.contradiction_id}:{status}")
        if status == "superseded" and resolution is not None and resolution.get("resolution_outcome") != "reconciled":
            errors.append(f"contradiction_superseded_requires_reconciled_resolution:{contradiction.contradiction_id}")
        if status == "settled" and resolution is not None and resolution.get("resolution_outcome") == "reconciled":
            errors.append(f"contradiction_settled_cannot_use_reconciled_resolution:{contradiction.contradiction_id}")

    normalized_snapshots: List[ProofBudgetSnapshotArtifact] = []
    for idx, item in enumerate(proof_budget_snapshots or []):
        snapshot = (
            item
            if isinstance(item, ProofBudgetSnapshotArtifact)
            else ProofBudgetSnapshotArtifact(**_strip_trace_fields(_normalize_artifact(item)))
        )
        snapshot_result: ArtifactVerificationResult = verify_proof_budget_snapshot(
            snapshot,
            known_claim_ids=claim_ids,
            known_contradiction_ids=contradiction_ids,
        )
        normalized_snapshots.append(snapshot)
        for error in snapshot_result.errors:
            errors.append(f"proof_budget_snapshot[{idx}]:{error}")

    decision_ids = {decision["receipt_id"] for decision in (decision_receipts or [])}
    snapshot_ids = {snapshot.snapshot_id for snapshot in normalized_snapshots}
    snapshots_by_decision = {
        snapshot.boundary_refs.get("decision_receipt_id"): snapshot
        for snapshot in normalized_snapshots
    }
    for decision_id in decision_ids:
        if decision_id not in snapshots_by_decision:
            errors.append(f"missing_proof_budget_snapshot_for_decision:{decision_id}")
        expected_contradiction_ids = {
            contradiction.contradiction_id
            for contradiction in contradictions_by_decision.get(decision_id, [])
        }
        decision = next((item for item in (decision_receipts or []) if item["receipt_id"] == decision_id), None)
        if decision is not None:
            actual_contradiction_ids = set(decision.get("unresolved_contradictions") or [])
            if actual_contradiction_ids != expected_contradiction_ids:
                errors.append(f"decision_contradiction_mismatch:{decision_id}")

    for snapshot in normalized_snapshots:
        boundary_refs = snapshot.boundary_refs
        if boundary_refs.get("decision_receipt_id") not in decision_ids:
            errors.append(
                f"proof_budget_snapshot_unknown_decision:{snapshot.snapshot_id}:{boundary_refs.get('decision_receipt_id')}"
            )
        if snapshot.boundary_kind != "checkpoint_decision":
            errors.append(f"proof_budget_snapshot_wrong_boundary_kind:{snapshot.snapshot_id}:{snapshot.boundary_kind}")

    for idx, denial in enumerate(denial_records or []):
        denial_result = verify_denial_record(
            denial,
            known_refs={
                "proof_budget_snapshot_ids": list(snapshot_ids),
                "claim_ids": list(claim_ids),
                "contradiction_ids": list(contradiction_ids),
            },
        )
        for error in denial_result.errors:
            errors.append(f"denial[{idx}]:{error}")

    return KernelBundleVerificationResult(passed=not errors, errors=errors)


__all__ = [
    "CheckpointEvaluationArtifact",
    "CheckpointRequestArtifact",
    "CheckpointResolutionArtifact",
    "CheckpointValidationError",
    "KernelBundleVerificationResult",
    "LifecycleVerificationResult",
    "OutboundEmailCheckpointFlow",
    "verify_outbound_email_kernel_bundle",
    "verify_outbound_email_lifecycle",
]
