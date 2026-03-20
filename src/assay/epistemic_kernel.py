"""Canonical kernel artifacts for claims, contradictions, and denials.

This module is intentionally narrow. It provides the first enforced kernel
artifacts needed for convergence work in Assay:

- ``claim_assertion``
- ``claim_support_change``
- ``contradiction_registration``
- ``contradiction_resolution``
- ``denial_record``

The artifacts are append-only and schema-backed. Runtime-specific receipts
such as ``BridgeDenial`` or checkpoint resolutions can be adapted into the
canonical kernel noun without replacing those runtime surfaces.
"""
from __future__ import annotations

import copy
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Collection, Dict, List, Mapping, Optional, Sequence, Union

from jsonschema import Draft202012Validator

from assay.episode import Episode
from assay.protocol_claim_verifier import (
    verify_claim_assertion as verify_protocol_claim_assertion,
    verify_claim_chain as verify_protocol_claim_chain,
    verify_claim_support_change as verify_protocol_claim_support_change,
    verify_contradiction_registration as verify_protocol_contradiction_registration,
    verify_contradiction_resolution as verify_protocol_contradiction_resolution,
)
from assay.store import emit_receipt


SCHEMA_VERSION = "0.1.0"
TRACE_ENVELOPE_FIELDS = {
    "receipt_id",
    "type",
    "_trace_id",
    "_stored_at",
    "parent_receipt_id",
    "seq",
    "canonical_hash",
}

CLAIM_ASSERTION_RECEIPT_TYPE = "claim.asserted"
CLAIM_SUPPORT_CHANGE_RECEIPT_TYPE = "claim.support_changed"
DENIAL_RECORD_RECEIPT_TYPE = "denial.recorded"
PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE = "proof_budget.snapshotted"
BELIEF_UPDATE_RECEIPT_TYPE = "belief.updated"
CONTRADICTION_REGISTRATION_RECEIPT_TYPE = "contradiction.registered"
CONTRADICTION_RESOLUTION_RECEIPT_TYPE = "contradiction.resolved"

CLAIM_SUPPORT_STATUSES = {
    "ASSERTED",
    "SUPPORTED",
    "WEAKENED",
    "CONTRADICTED",
    "RETRACTED",
}

PROOF_TIERS = {
    "DRAFT",
    "CHECKED",
    "TOOL_VERIFIED",
    "ADVERSARIAL",
    "CONSTITUTIONAL",
}

PROOF_TIER_RANK = {
    "DRAFT": 0,
    "CHECKED": 1,
    "TOOL_VERIFIED": 2,
    "ADVERSARIAL": 3,
    "CONSTITUTIONAL": 4,
}

PROOF_BUDGET_BOUNDARY_KINDS = {
    "checkpoint_decision",
    "guardian_decision",
    "memory_promotion",
    "policy_mutation",
}

PROOF_BUDGET_ESCALATION_POSTURES = {
    "sufficient",
    "review_required",
    "blocked",
    "escalate",
}

BELIEF_UPDATE_SETTLEMENT_STATUSES = {
    "proposed",
    "settled",
    "superseded",
}

BELIEF_UPDATE_DURABILITY_CLASSES = {
    "working",
    "durable",
    "archival",
}

CONTRADICTION_STATUSES = {
    "open",
    "contained",
    "settled",
    "superseded",
}

CLAIM_ALLOWED_TRANSITIONS = {
    "ASSERTED": {"SUPPORTED", "WEAKENED", "CONTRADICTED", "RETRACTED"},
    "SUPPORTED": {"WEAKENED", "CONTRADICTED", "RETRACTED"},
    "WEAKENED": {"SUPPORTED", "CONTRADICTED", "RETRACTED"},
    "CONTRADICTED": {"SUPPORTED", "WEAKENED", "RETRACTED"},
    "RETRACTED": set(),
}

NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES = {
    "blocked",
    "refused",
    "review_rejected",
    "escalated",
}

_SCHEMA_VALIDATORS: Dict[str, Draft202012Validator] = {}


class KernelValidationError(ValueError):
    """Raised when a kernel artifact is invalid."""


@dataclass
class ArtifactVerificationResult:
    passed: bool
    errors: List[str] = field(default_factory=list)
    error_codes: List[str] = field(default_factory=list)


@dataclass
class ClaimChainVerificationResult:
    passed: bool
    current_support_status: str
    errors: List[str] = field(default_factory=list)
    error_codes: List[str] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _parse_iso8601(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _normalize_artifact(artifact: Any) -> Dict[str, Any]:
    if hasattr(artifact, "to_dict"):
        return artifact.to_dict()  # type: ignore[return-value]
    return {
        key: value
        for key, value in dict(artifact).items()
        if key not in TRACE_ENVELOPE_FIELDS
    }


def _get_schema_validator(schema_name: str) -> Draft202012Validator:
    validator = _SCHEMA_VALIDATORS.get(schema_name)
    if validator is None:
        schema_path = resources.files("assay").joinpath(f"schemas/{schema_name}")
        schema = json.loads(schema_path.read_text())
        validator = Draft202012Validator(schema)
        _SCHEMA_VALIDATORS[schema_name] = validator
    return validator


def _typed_ref(ref_id: str, *, ref_type: str = "external", ref_role: str = "supporting") -> Dict[str, Any]:
    return {
        "ref_type": ref_type,
        "ref_id": ref_id,
        "ref_uri": None,
        "ref_hash": None,
        "ref_role": ref_role,
    }


def _stable_prefixed_id(prefix: str, *parts: Optional[str]) -> str:
    seed = "|".join(part or "" for part in parts)
    digest = uuid.uuid5(uuid.NAMESPACE_URL, seed).hex[:12]
    return f"{prefix}_{digest}"


def _checkpoint_contradiction_claim_id(
    checkpoint_id: str,
    evaluation_id: str,
    evidence_ref: str,
) -> str:
    return _stable_prefixed_id("clm", checkpoint_id, evaluation_id, evidence_ref)


def _checkpoint_contradiction_evidence_index(
    evaluation_dict: Mapping[str, Any],
) -> Dict[str, Dict[str, Any]]:
    evidence_index: Dict[str, Dict[str, Any]] = {}
    evidence_items = list(evaluation_dict.get("evidence_bundle", {}).get("items", []))
    for raw_item in evidence_items:
        try:
            item = dict(raw_item)
        except Exception as exc:  # pragma: no cover - defensive fail-closed path
            raise KernelValidationError("checkpoint contradiction evidence item must be an object") from exc
        evidence_id = str(item.get("evidence_id") or "").strip()
        if not evidence_id:
            raise KernelValidationError("checkpoint contradiction evidence item missing evidence_id")
        if evidence_id in evidence_index:
            raise KernelValidationError(f"duplicate checkpoint contradiction evidence_id: {evidence_id}")
        evidence_index[evidence_id] = item
    return evidence_index


def _checkpoint_contradiction_grounded_claim_basis_ref(evidence_item: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "ref_type": "external",
        "ref_id": str(evidence_item.get("evidence_id") or ""),
        "ref_uri": evidence_item.get("uri"),
        "ref_hash": evidence_item.get("hash"),
        "ref_role": "supporting",
    }


def _checkpoint_contradiction_grounded_claim_text(
    checkpoint_id: str,
    evidence_item: Mapping[str, Any],
) -> str:
    evidence_id = str(evidence_item.get("evidence_id") or "unknown_evidence")
    kind = str(evidence_item.get("kind") or "evidence")
    authority_level = str(evidence_item.get("authority_level") or "unknown")
    return (
        f"Checkpoint {checkpoint_id} evidence item {evidence_id} ({kind}) "
        f"with authority level {authority_level} is present in the evidence bundle"
    )


def _checkpoint_contradiction_id(
    checkpoint_id: str,
    evaluation_id: str,
    lhs_ref: str,
    rhs_ref: str,
    reason_code: str,
) -> str:
    ordered = sorted([lhs_ref, rhs_ref])
    return _stable_prefixed_id("ctr", checkpoint_id, evaluation_id, ordered[0], ordered[1], reason_code)


def _contradiction_conflict_type(reason_code: str) -> str:
    lowered = reason_code.lower()
    if any(token in lowered for token in ("policy", "authority", "permission")):
        return "policy_conflict"
    if any(token in lowered for token in ("fresh", "stale", "temporal", "window", "time")):
        return "temporal_inconsistency"
    if any(token in lowered for token in ("scope", "recipient", "audience")):
        return "scope_overlap"
    return "inconsistent_evidence"


_PROTOCOL_CHECK_TO_KERNEL_ERROR = {
    "chain_support_prior_mismatch": "prior_support_status_mismatch",
    "chain_support_change_after_assertion": "support_change_precedes_claim_assertion",
    "chain_retracted_terminal": "retracted_claim_cannot_transition",
    "support_change_transition": "forbidden_support_transition",
    "support_change_contradiction_ref": "contradiction_change_missing_contradiction_id",
    "support_change_decision_ref": "governance_change_missing_decision_receipt_id",
    "support_change_supported_evidence": "supported_status_requires_evidence_refs",
    "chain_duplicate_claim_id": "duplicate_claim_assertion",
}


def _append_unique(values: List[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _contradiction_registration_protocol_payload(
    artifact: ContradictionRegistrationArtifact,
) -> Dict[str, Any]:
    protocol_payload = artifact.to_dict()
    protocol_payload.pop("status", None)
    protocol_payload.pop("scope", None)
    protocol_payload.pop("lhs_ref", None)
    protocol_payload.pop("rhs_ref", None)
    protocol_payload.pop("replay_refs", None)
    protocol_payload.pop("boundary_refs", None)
    return protocol_payload


def _is_contradiction_protocol_check(check_name: str) -> bool:
    return "contradiction" in check_name or check_name.startswith("chain_resolution_")


def _derive_claim_support_status(
    support_changes: Sequence[ClaimSupportChangeArtifact],
) -> str:
    if not support_changes:
        return "ASSERTED"
    ordered = sorted(
        support_changes,
        key=lambda item: (_parse_iso8601(item.timestamp), item.change_id),
    )
    return ordered[-1].new_support_status


def _protocol_failures_to_kernel_errors(protocol_failures: Sequence[Any]) -> tuple[List[str], List[str]]:
    errors: List[str] = []
    error_codes: List[str] = []
    for failure in protocol_failures:
        if getattr(failure, "passed", True):
            continue
        check_name = str(getattr(failure, "check_name", "unknown"))
        _append_unique(error_codes, check_name)
        mapped_error = _PROTOCOL_CHECK_TO_KERNEL_ERROR.get(check_name)
        if mapped_error:
            _append_unique(errors, mapped_error)
    return errors, error_codes


@dataclass
class ClaimAssertionArtifact:
    claim_id: str
    timestamp: str
    episode_id: str
    claim_text: str
    claim_type: str
    checkable: bool
    basis: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "claim_assertion"
    claim_scope: Optional[str] = None
    parent_claim_id: Optional[str] = None
    source_organ: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("claim_assertion.v0.1.schema.json").validate(self.to_dict())


@dataclass
class ClaimSupportChangeArtifact:
    change_id: str
    timestamp: str
    claim_id: str
    episode_id: str
    prior_support_status: str
    new_support_status: str
    change_type: str
    evidence_refs: List[Dict[str, Any]]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "claim_support_change"
    contradiction_id: Optional[str] = None
    decision_receipt_id: Optional[str] = None
    proof_tier_at_change: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("claim_support_change.v0.1.schema.json").validate(self.to_dict())


@dataclass
class ContradictionRegistrationArtifact:
    contradiction_id: str
    timestamp: str
    episode_id: str
    claim_a_id: str
    claim_b_id: str
    conflict_type: str
    severity: str
    detection: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "contradiction_registration"
    status: str = "open"
    scope: Optional[str] = None
    lhs_ref: Optional[str] = None
    rhs_ref: Optional[str] = None
    replay_refs: List[str] = field(default_factory=list)
    boundary_refs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("contradiction_registration.v0.1.schema.json").validate(self.to_dict())


@dataclass
class ContradictionResolutionArtifact:
    resolution_id: str
    timestamp: str
    contradiction_id: str
    episode_id: str
    resolution_outcome: str
    resolution_basis: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "contradiction_resolution"
    superseding_claim_id: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("contradiction_resolution.v0.1.schema.json").validate(self.to_dict())


@dataclass
class DenialRecordArtifact:
    denial_id: str
    timestamp: str
    denial_outcome: str
    source_surface: str
    subject: Dict[str, Any]
    attempted_action: Dict[str, Any]
    blocking_basis: Dict[str, Any]
    missing_evidence: List[str]
    upgrade_conditions: List[str]
    backward_refs: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "denial_record"
    cheaper_next_move: Optional[str] = None
    safer_lawful_alternative: Optional[str] = None
    related_claim_ids: List[str] = field(default_factory=list)
    proof_budget_snapshot_id: Optional[str] = None
    contradiction_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("denial_record.v0.1.schema.json").validate(self.to_dict())


@dataclass
class ProofBudgetSnapshotArtifact:
    snapshot_id: str
    timestamp: str
    episode_id: str
    boundary_kind: str
    boundary_refs: Dict[str, Any]
    required_tier: str
    current_tier: str
    deficit: Dict[str, Any]
    next_evidence_move: Optional[str]
    escalation_posture: str
    claim_ids: List[str]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "proof_budget_snapshot"
    contradiction_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("proof_budget_snapshot.v0.1.schema.json").validate(self.to_dict())


@dataclass
class BeliefUpdateArtifact:
    update_id: str
    timestamp: str
    episode_id: str
    claim_id: str
    prior_state: Dict[str, Any]
    new_state: Dict[str, Any]
    settlement_status: str
    durability_class: str
    trigger_refs: List[Dict[str, Any]]
    rationale: str
    lineage_refs: List[Dict[str, Any]]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "belief_update"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_schema_validator("belief_update.v0.1.schema.json").validate(self.to_dict())


def emit_claim_assertion(
    episode: Episode,
    *,
    claim_text: str,
    claim_type: str,
    checkable: bool,
    basis: Dict[str, Any],
    claim_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    claim_scope: Optional[str] = None,
    parent_claim_id: Optional[str] = None,
    source_organ: Optional[str] = None,
    parent_receipt_id: Optional[str] = None,
) -> ClaimAssertionArtifact:
    artifact = ClaimAssertionArtifact(
        claim_id=claim_id or _new_id("clm"),
        timestamp=timestamp or _now_iso(),
        episode_id=episode.episode_id,
        claim_text=claim_text,
        claim_type=claim_type,
        checkable=checkable,
        basis=copy.deepcopy(basis),
        claim_scope=claim_scope,
        parent_claim_id=parent_claim_id,
        source_organ=source_organ,
    )
    artifact.validate()
    episode.emit(
        CLAIM_ASSERTION_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_claim_support_change(
    episode: Episode,
    *,
    claim_id: str,
    prior_support_status: str,
    new_support_status: str,
    change_type: str,
    evidence_refs: List[Dict[str, Any]],
    change_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    contradiction_id: Optional[str] = None,
    decision_receipt_id: Optional[str] = None,
    proof_tier_at_change: Optional[str] = None,
    reason: Optional[str] = None,
    parent_receipt_id: Optional[str] = None,
) -> ClaimSupportChangeArtifact:
    artifact = ClaimSupportChangeArtifact(
        change_id=change_id or _new_id("csc"),
        timestamp=timestamp or _now_iso(),
        claim_id=claim_id,
        episode_id=episode.episode_id,
        prior_support_status=prior_support_status,
        new_support_status=new_support_status,
        change_type=change_type,
        evidence_refs=copy.deepcopy(evidence_refs),
        contradiction_id=contradiction_id,
        decision_receipt_id=decision_receipt_id,
        proof_tier_at_change=proof_tier_at_change,
        reason=reason,
    )
    artifact.validate()
    episode.emit(
        CLAIM_SUPPORT_CHANGE_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_denial_record_to_episode(
    episode: Episode,
    denial_record: Union[DenialRecordArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> str:
    artifact = (
        denial_record
        if isinstance(denial_record, DenialRecordArtifact)
        else DenialRecordArtifact(**_normalize_artifact(denial_record))
    )
    artifact.validate()
    return episode.emit(
        DENIAL_RECORD_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )


def emit_denial_record_to_trace(
    denial_record: Union[DenialRecordArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> Dict[str, Any]:
    artifact = (
        denial_record
        if isinstance(denial_record, DenialRecordArtifact)
        else DenialRecordArtifact(**_normalize_artifact(denial_record))
    )
    artifact.validate()
    return emit_receipt(
        DENIAL_RECORD_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )


def emit_contradiction_registration(
    episode: Episode,
    contradiction_registration: Union[ContradictionRegistrationArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> ContradictionRegistrationArtifact:
    artifact = (
        contradiction_registration
        if isinstance(contradiction_registration, ContradictionRegistrationArtifact)
        else ContradictionRegistrationArtifact(**_normalize_artifact(contradiction_registration))
    )
    artifact.validate()
    episode.emit(
        CONTRADICTION_REGISTRATION_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_contradiction_resolution(
    episode: Episode,
    contradiction_resolution: Union[ContradictionResolutionArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> ContradictionResolutionArtifact:
    artifact = (
        contradiction_resolution
        if isinstance(contradiction_resolution, ContradictionResolutionArtifact)
        else ContradictionResolutionArtifact(**_normalize_artifact(contradiction_resolution))
    )
    artifact.validate()
    episode.emit(
        CONTRADICTION_RESOLUTION_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_proof_budget_snapshot(
    episode: Episode,
    proof_budget_snapshot: Union[ProofBudgetSnapshotArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> ProofBudgetSnapshotArtifact:
    artifact = (
        proof_budget_snapshot
        if isinstance(proof_budget_snapshot, ProofBudgetSnapshotArtifact)
        else ProofBudgetSnapshotArtifact(**_normalize_artifact(proof_budget_snapshot))
    )
    artifact.validate()
    episode.emit(
        PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_belief_update(
    episode: Episode,
    belief_update: Union[BeliefUpdateArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> BeliefUpdateArtifact:
    artifact = (
        belief_update
        if isinstance(belief_update, BeliefUpdateArtifact)
        else BeliefUpdateArtifact(**_normalize_artifact(belief_update))
    )
    artifact.validate()
    episode.emit(
        BELIEF_UPDATE_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def verify_claim_support_chain(
    assertion: Union[ClaimAssertionArtifact, Dict[str, Any]],
    support_changes: Sequence[Union[ClaimSupportChangeArtifact, Dict[str, Any]]],
) -> ClaimChainVerificationResult:
    errors: List[str] = []
    error_codes: List[str] = []

    try:
        claim_art = (
            assertion
            if isinstance(assertion, ClaimAssertionArtifact)
            else ClaimAssertionArtifact(**_normalize_artifact(assertion))
        )
        claim_art.validate()
    except Exception as exc:
        return ClaimChainVerificationResult(
            passed=False,
            current_support_status="ASSERTED",
            errors=[f"claim_assertion_invalid: {exc}"],
            error_codes=["claim_assertion_invalid"],
        )

    normalized_changes: List[ClaimSupportChangeArtifact] = []
    for idx, item in enumerate(support_changes):
        try:
            change = (
                item
                if isinstance(item, ClaimSupportChangeArtifact)
                else ClaimSupportChangeArtifact(**_normalize_artifact(item))
            )
            change.validate()
            normalized_changes.append(change)
        except Exception as exc:
            errors.append(f"claim_support_change_invalid[{idx}]: {exc}")
            _append_unique(error_codes, "claim_support_change_invalid")

    if errors:
        return ClaimChainVerificationResult(
            passed=False,
            current_support_status="ASSERTED",
            errors=errors,
            error_codes=error_codes,
        )

    for change in normalized_changes:
        if change.claim_id != claim_art.claim_id:
            _append_unique(errors, "claim_id_mismatch")
            _append_unique(error_codes, "claim_id_mismatch")

    assertion_dict = claim_art.to_dict()
    support_change_dicts = [change.to_dict() for change in normalized_changes]
    protocol_failures = list(verify_protocol_claim_assertion(assertion_dict))
    for change_dict in support_change_dicts:
        protocol_failures.extend(verify_protocol_claim_support_change(change_dict))
    chain_result = verify_protocol_claim_chain(
        [assertion_dict],
        support_change_dicts,
        [],
        [],
    )
    protocol_failures.extend(chain_result.results)
    mapped_errors, mapped_codes = _protocol_failures_to_kernel_errors(protocol_failures)
    for error in mapped_errors:
        _append_unique(errors, error)
    for code in mapped_codes:
        _append_unique(error_codes, code)

    return ClaimChainVerificationResult(
        passed=not errors,
        current_support_status=_derive_claim_support_status(
            [change for change in normalized_changes if change.claim_id == claim_art.claim_id]
        ),
        errors=errors,
        error_codes=error_codes,
    )


def verify_claim_artifact_set(
    assertions: Sequence[Union[ClaimAssertionArtifact, Dict[str, Any]]],
    support_changes: Sequence[Union[ClaimSupportChangeArtifact, Dict[str, Any]]],
    contradictions: Optional[Sequence[Union[ContradictionRegistrationArtifact, Dict[str, Any]]]] = None,
    resolutions: Optional[Sequence[Union[ContradictionResolutionArtifact, Dict[str, Any]]]] = None,
) -> ArtifactVerificationResult:
    errors: List[str] = []
    error_codes: List[str] = []
    normalized_assertions: Dict[str, ClaimAssertionArtifact] = {}

    for idx, item in enumerate(assertions):
        try:
            assertion = (
                item
                if isinstance(item, ClaimAssertionArtifact)
                else ClaimAssertionArtifact(**_normalize_artifact(item))
            )
            assertion.validate()
        except Exception as exc:
            errors.append(f"claim_assertion_invalid[{idx}]: {exc}")
            _append_unique(error_codes, "claim_assertion_invalid")
            continue
        if assertion.claim_id in normalized_assertions:
            errors.append(f"duplicate_claim_assertion:{assertion.claim_id}")
            _append_unique(error_codes, "chain_duplicate_claim_id")
            continue
        normalized_assertions[assertion.claim_id] = assertion

    grouped_changes: Dict[str, List[ClaimSupportChangeArtifact]] = {}
    for idx, item in enumerate(support_changes):
        try:
            change = (
                item
                if isinstance(item, ClaimSupportChangeArtifact)
                else ClaimSupportChangeArtifact(**_normalize_artifact(item))
            )
            change.validate()
        except Exception as exc:
            errors.append(f"claim_support_change_invalid[{idx}]: {exc}")
            _append_unique(error_codes, "claim_support_change_invalid")
            continue
        grouped_changes.setdefault(change.claim_id, []).append(change)

    normalized_contradictions: List[ContradictionRegistrationArtifact] = []
    for idx, item in enumerate(contradictions or []):
        try:
            contradiction = (
                item
                if isinstance(item, ContradictionRegistrationArtifact)
                else ContradictionRegistrationArtifact(**_normalize_artifact(item))
            )
            contradiction.validate()
        except Exception as exc:
            errors.append(f"contradiction_registration_invalid[{idx}]: {exc}")
            _append_unique(error_codes, "contradiction_registration_invalid")
            continue
        result = verify_contradiction_registration_artifact(contradiction)
        for error in result.errors:
            _append_unique(errors, error)
        for code in result.error_codes:
            _append_unique(error_codes, code)
        normalized_contradictions.append(contradiction)

    normalized_resolutions: List[ContradictionResolutionArtifact] = []
    for idx, item in enumerate(resolutions or []):
        try:
            resolution = (
                item
                if isinstance(item, ContradictionResolutionArtifact)
                else ContradictionResolutionArtifact(**_normalize_artifact(item))
            )
            resolution.validate()
        except Exception as exc:
            errors.append(f"contradiction_resolution_invalid[{idx}]: {exc}")
            _append_unique(error_codes, "contradiction_resolution_invalid")
            continue
        result = verify_contradiction_resolution_artifact(resolution)
        for error in result.errors:
            _append_unique(errors, error)
        for code in result.error_codes:
            _append_unique(error_codes, code)
        normalized_resolutions.append(resolution)

    assertion_dicts = [artifact.to_dict() for artifact in normalized_assertions.values()]
    support_change_dicts = [
        change.to_dict()
        for changes in grouped_changes.values()
        for change in changes
    ]
    contradiction_dicts = [artifact.to_dict() for artifact in normalized_contradictions]
    resolution_dicts = [artifact.to_dict() for artifact in normalized_resolutions]
    protocol_result = verify_protocol_claim_chain(
        assertion_dicts,
        support_change_dicts,
        contradiction_dicts,
        resolution_dicts,
    )
    mapped_errors, mapped_codes = _protocol_failures_to_kernel_errors(protocol_result.results)
    for error in mapped_errors:
        _append_unique(errors, error)
    for code in mapped_codes:
        _append_unique(error_codes, code)
    if normalized_contradictions or normalized_resolutions:
        for failure in protocol_result.results:
            if getattr(failure, "passed", True):
                continue
            check_name = str(getattr(failure, "check_name", "unknown"))
            if not _is_contradiction_protocol_check(check_name):
                continue
            _append_unique(
                errors,
                str(getattr(failure, "message", "contradiction chain invariant failed")),
            )
            _append_unique(error_codes, check_name)

    for claim_id, changes in grouped_changes.items():
        assertion = normalized_assertions.get(claim_id)
        if assertion is None:
            _append_unique(errors, f"unknown_claim_assertion:{claim_id}")
            _append_unique(error_codes, "chain_support_change_claim_exists")
            continue
        result = verify_claim_support_chain(assertion, changes)
        for error in result.errors:
            _append_unique(errors, error)
        for code in result.error_codes:
            _append_unique(error_codes, code)

    return ArtifactVerificationResult(passed=not errors, errors=errors, error_codes=error_codes)


def verify_denial_record(
    denial_record: Union[DenialRecordArtifact, Dict[str, Any]],
    *,
    known_refs: Optional[Mapping[str, Collection[str]]] = None,
    source_timestamps: Optional[Mapping[str, str]] = None,
) -> ArtifactVerificationResult:
    errors: List[str] = []

    try:
        denial = (
            denial_record
            if isinstance(denial_record, DenialRecordArtifact)
            else DenialRecordArtifact(**_normalize_artifact(denial_record))
        )
        denial.validate()
    except Exception as exc:
        return ArtifactVerificationResult(passed=False, errors=[f"denial_record_invalid: {exc}"])

    refs = denial.backward_refs
    known = known_refs or {}
    for key in ("source_receipt_id", "request_id", "evaluation_id", "resolution_id"):
        ref_id = refs.get(key)
        if ref_id:
            valid = set(known.get(key, []))
            if valid and ref_id not in valid:
                errors.append(f"unknown_backward_ref:{key}:{ref_id}")
    decision_ids = list(refs.get("decision_receipt_ids") or [])
    known_decisions = set(known.get("decision_receipt_ids", []))
    for decision_id in decision_ids:
        if known_decisions and decision_id not in known_decisions:
            errors.append(f"unknown_backward_ref:decision_receipt_ids:{decision_id}")
    proof_budget_snapshot_id = denial.proof_budget_snapshot_id
    known_snapshots = set(known.get("proof_budget_snapshot_ids", []))
    if proof_budget_snapshot_id and known_snapshots and proof_budget_snapshot_id not in known_snapshots:
        errors.append(f"unknown_backward_ref:proof_budget_snapshot_id:{proof_budget_snapshot_id}")
    known_claim_ids = set(known.get("claim_ids", []))
    for claim_id in denial.related_claim_ids:
        if known_claim_ids and claim_id not in known_claim_ids:
            errors.append(f"unknown_backward_ref:related_claim_ids:{claim_id}")
    known_contradictions = set(known.get("contradiction_ids", []))
    for contradiction_id in denial.contradiction_ids:
        if known_contradictions and contradiction_id not in known_contradictions:
            errors.append(f"unknown_backward_ref:contradiction_ids:{contradiction_id}")

    if source_timestamps:
        denial_time = _parse_iso8601(denial.timestamp)
        for key in ("source_receipt_id", "request_id", "evaluation_id", "resolution_id"):
            ref_id = refs.get(key)
            if ref_id and ref_id in source_timestamps:
                if _parse_iso8601(source_timestamps[ref_id]) > denial_time:
                    errors.append(f"forward_ref_timestamp:{key}:{ref_id}")
        for decision_id in decision_ids:
            if decision_id in source_timestamps and _parse_iso8601(source_timestamps[decision_id]) > denial_time:
                errors.append(f"forward_ref_timestamp:decision_receipt_ids:{decision_id}")

    return ArtifactVerificationResult(passed=not errors, errors=errors)


def verify_proof_budget_snapshot(
    proof_budget_snapshot: Union[ProofBudgetSnapshotArtifact, Dict[str, Any]],
    *,
    known_claim_ids: Optional[Collection[str]] = None,
    known_contradiction_ids: Optional[Collection[str]] = None,
) -> ArtifactVerificationResult:
    errors: List[str] = []
    try:
        snapshot = (
            proof_budget_snapshot
            if isinstance(proof_budget_snapshot, ProofBudgetSnapshotArtifact)
            else ProofBudgetSnapshotArtifact(**_normalize_artifact(proof_budget_snapshot))
        )
        snapshot.validate()
    except Exception as exc:
        return ArtifactVerificationResult(
            passed=False,
            errors=[f"proof_budget_snapshot_invalid: {exc}"],
        )

    if snapshot.boundary_kind not in PROOF_BUDGET_BOUNDARY_KINDS:
        errors.append(f"invalid_boundary_kind:{snapshot.boundary_kind}")
    if snapshot.required_tier not in PROOF_TIERS:
        errors.append(f"invalid_required_tier:{snapshot.required_tier}")
    if snapshot.current_tier not in PROOF_TIERS:
        errors.append(f"invalid_current_tier:{snapshot.current_tier}")
    if (
        snapshot.required_tier in PROOF_TIER_RANK
        and snapshot.current_tier in PROOF_TIER_RANK
    ):
        meets_minimum = bool(snapshot.deficit.get("meets_minimum"))
        current_rank = PROOF_TIER_RANK[snapshot.current_tier]
        required_rank = PROOF_TIER_RANK[snapshot.required_tier]
        if meets_minimum != (current_rank >= required_rank):
            errors.append("proof_budget_meets_minimum_mismatch")
    if snapshot.escalation_posture not in PROOF_BUDGET_ESCALATION_POSTURES:
        errors.append(f"invalid_escalation_posture:{snapshot.escalation_posture}")
    if known_claim_ids is not None:
        known = set(known_claim_ids)
        for claim_id in snapshot.claim_ids:
            if claim_id not in known:
                errors.append(f"unknown_claim_ref:{claim_id}")
    if known_contradiction_ids is not None:
        known = set(known_contradiction_ids)
        for contradiction_id in snapshot.contradiction_ids:
            if contradiction_id not in known:
                errors.append(f"unknown_contradiction_ref:{contradiction_id}")

    return ArtifactVerificationResult(passed=not errors, errors=errors)


def verify_belief_update(
    belief_update: Union[BeliefUpdateArtifact, Dict[str, Any]],
    *,
    known_claim_ids: Optional[Collection[str]] = None,
) -> ArtifactVerificationResult:
    errors: List[str] = []
    try:
        update = (
            belief_update
            if isinstance(belief_update, BeliefUpdateArtifact)
            else BeliefUpdateArtifact(**_normalize_artifact(belief_update))
        )
        update.validate()
    except Exception as exc:
        return ArtifactVerificationResult(
            passed=False,
            errors=[f"belief_update_invalid: {exc}"],
        )

    if update.settlement_status not in BELIEF_UPDATE_SETTLEMENT_STATUSES:
        errors.append(f"invalid_settlement_status:{update.settlement_status}")
    if update.durability_class not in BELIEF_UPDATE_DURABILITY_CLASSES:
        errors.append(f"invalid_durability_class:{update.durability_class}")
    if known_claim_ids is not None and update.claim_id not in set(known_claim_ids):
        errors.append(f"unknown_claim_ref:{update.claim_id}")

    return ArtifactVerificationResult(passed=not errors, errors=errors)


def verify_contradiction_registration_artifact(
    contradiction_registration: Union[ContradictionRegistrationArtifact, Dict[str, Any]],
) -> ArtifactVerificationResult:
    errors: List[str] = []
    error_codes: List[str] = []
    try:
        artifact = (
            contradiction_registration
            if isinstance(contradiction_registration, ContradictionRegistrationArtifact)
            else ContradictionRegistrationArtifact(**_normalize_artifact(contradiction_registration))
        )
        artifact.validate()
    except Exception as exc:
        return ArtifactVerificationResult(
            passed=False,
            errors=[f"contradiction_registration_invalid: {exc}"],
            error_codes=["contradiction_registration_invalid"],
        )

    if artifact.status not in CONTRADICTION_STATUSES:
        _append_unique(errors, f"invalid_contradiction_status:{artifact.status}")
        _append_unique(error_codes, "contradiction_registration_status")
    protocol_payload = _contradiction_registration_protocol_payload(artifact)
    protocol_failures = verify_protocol_contradiction_registration(protocol_payload)
    mapped_errors, mapped_codes = _protocol_failures_to_kernel_errors(protocol_failures)
    for error in mapped_errors:
        _append_unique(errors, error)
    for error_code in mapped_codes:
        _append_unique(error_codes, error_code)
    for failure in protocol_failures:
        if getattr(failure, "passed", True):
            continue
        message = str(getattr(failure, "message", "protocol contradiction invariant failed"))
        _append_unique(errors, message)
        _append_unique(error_codes, str(getattr(failure, "check_name", "unknown")))

    return ArtifactVerificationResult(passed=not errors, errors=errors, error_codes=error_codes)


def verify_contradiction_resolution_artifact(
    contradiction_resolution: Union[ContradictionResolutionArtifact, Dict[str, Any]],
) -> ArtifactVerificationResult:
    try:
        artifact = (
            contradiction_resolution
            if isinstance(contradiction_resolution, ContradictionResolutionArtifact)
            else ContradictionResolutionArtifact(**_normalize_artifact(contradiction_resolution))
        )
        artifact.validate()
    except Exception as exc:
        return ArtifactVerificationResult(
            passed=False,
            errors=[f"contradiction_resolution_invalid: {exc}"],
            error_codes=["contradiction_resolution_invalid"],
        )
    protocol_payload = artifact.to_dict()
    protocol_payload.pop("notes", None)
    protocol_failures = verify_protocol_contradiction_resolution(protocol_payload)
    errors: List[str] = []
    error_codes: List[str] = []
    for failure in protocol_failures:
        if getattr(failure, "passed", True):
            continue
        _append_unique(errors, str(getattr(failure, "message", "protocol contradiction resolution invariant failed")))
        _append_unique(error_codes, str(getattr(failure, "check_name", "unknown")))
    return ArtifactVerificationResult(passed=not errors, errors=errors, error_codes=error_codes)


def adapt_contradiction_receipt_to_registration(
    contradiction_receipt: Any,
    *,
    episode_id: str,
    claim_a_id: str,
    claim_b_id: str,
    timestamp: Optional[str] = None,
    contradiction_id: Optional[str] = None,
    conflict_type: Optional[str] = None,
    severity: Optional[str] = None,
    detection_method: str = "automated_verification",
    detector_id: Optional[str] = None,
    scope: Optional[str] = None,
    status: Optional[str] = None,
    replay_refs: Optional[Sequence[str]] = None,
    boundary_refs: Optional[Mapping[str, Any]] = None,
) -> ContradictionRegistrationArtifact:
    receipt_dict = _normalize_artifact(contradiction_receipt)
    ordered_claims = sorted(
        [
            (claim_a_id, str(receipt_dict.get("claim_a") or "")),
            (claim_b_id, str(receipt_dict.get("claim_b") or "")),
        ],
        key=lambda item: item[0],
    )
    ordered_claim_a_id, lhs_ref = ordered_claims[0]
    ordered_claim_b_id, rhs_ref = ordered_claims[1]
    source_receipt_id = str(receipt_dict.get("receipt_id") or "")
    source_timestamp = str(
        timestamp
        or receipt_dict.get("detected_at")
        or receipt_dict.get("timestamp")
        or _now_iso()
    )
    if contradiction_id is None:
        contradiction_id = _stable_prefixed_id(
            "ctr",
            ordered_claim_a_id,
            ordered_claim_b_id,
            source_receipt_id,
            source_timestamp,
        )

    receipt_summary = " ".join(
        [
            str(receipt_dict.get("resolution_result") or ""),
            *[str(item) for item in receipt_dict.get("impacted_invariants") or []],
        ]
    )
    derived_conflict_type = conflict_type or _contradiction_conflict_type(receipt_summary)
    confidence_values = [
        float(receipt_dict.get("claim_a_confidence") or 0.0),
        float(receipt_dict.get("claim_b_confidence") or 0.0),
    ]
    detection_confidence = max(confidence_values) if confidence_values else 0.0
    impacted_invariants = list(receipt_dict.get("impacted_invariants") or [])
    if severity is None:
        if detection_confidence >= 0.95 or len(impacted_invariants) >= 3:
            severity = "critical"
        elif detection_confidence >= 0.85 or impacted_invariants:
            severity = "high"
        elif detection_confidence >= 0.60:
            severity = "medium"
        else:
            severity = "low"

    artifact = ContradictionRegistrationArtifact(
        contradiction_id=contradiction_id,
        timestamp=source_timestamp,
        episode_id=episode_id,
        claim_a_id=ordered_claim_a_id,
        claim_b_id=ordered_claim_b_id,
        conflict_type=derived_conflict_type,
        severity=severity,
        detection={
            "detection_method": detection_method,
            "detection_confidence": detection_confidence,
            "detector_id": detector_id or "assay.blockages.contradiction_receipt",
            "detection_evidence_refs": (
                [_typed_ref(source_receipt_id, ref_type="receipt", ref_role="supporting")]
                if source_receipt_id
                else [_typed_ref(contradiction_id, ref_type="external", ref_role="contextual")]
            ),
        },
        status=status or ("contained" if receipt_dict.get("resolution_attempted") else "open"),
        scope=scope,
        lhs_ref=lhs_ref or None,
        rhs_ref=rhs_ref or None,
        replay_refs=list(replay_refs or ([source_receipt_id] if source_receipt_id else [])),
        boundary_refs={
            "source_receipt_id": source_receipt_id or None,
            "source_receipt_type": receipt_dict.get("receipt_type"),
            "resolution_attempted": bool(receipt_dict.get("resolution_attempted")),
            "resolution_result": receipt_dict.get("resolution_result"),
            **dict(boundary_refs or {}),
        },
    )
    artifact.validate()
    return artifact


def adapt_bridge_denial_to_denial_record(
    bridge_denial: Mapping[str, Any],
    *,
    denial_id: Optional[str] = None,
) -> DenialRecordArtifact:
    policy_ref = str(bridge_denial.get("policy_ref") or "")
    denial_reason = str(bridge_denial.get("denial_reason") or "Bridge policy denied the requested tool.")
    tool_name = str(bridge_denial.get("tool_name") or "unknown_tool")

    if policy_ref in {"POLICY_URL_001", "POLICY_URL_002"}:
        cheaper_next_move = "Use a public http(s) URL that satisfies the bridge safety policy."
        safer_alternative = "Keep the network call blocked and use an allowlisted public web tool."
        upgrade_conditions = ["public_http_url", "bridge_policy_match"]
    else:
        cheaper_next_move = "Use an allowlisted safe tool or update the bridge policy before retrying."
        safer_alternative = "Avoid the blocked tool and route through a safe web tool or human operator."
        upgrade_conditions = [policy_ref] if policy_ref else ["bridge_policy_match"]

    artifact = DenialRecordArtifact(
        denial_id=denial_id or _new_id("den"),
        timestamp=str(bridge_denial.get("timestamp") or _now_iso()),
        denial_outcome="policy_denied",
        source_surface="assay.bridge",
        subject={
            "subject_type": "session",
            "subject_id": str(bridge_denial.get("session_id") or "unknown_session"),
        },
        attempted_action={
            "action_type": "tool_invocation",
            "action_name": tool_name,
            "action_target": tool_name,
            "argument_hash": bridge_denial.get("arguments_sha256"),
        },
        blocking_basis={
            "basis_type": "policy_check",
            "summary": denial_reason,
            "reason_codes": [policy_ref] if policy_ref else ["policy_denied"],
            "policy_ref": policy_ref or None,
            "policy_hash": bridge_denial.get("policy_hash"),
        },
        missing_evidence=[],
        cheaper_next_move=cheaper_next_move,
        safer_lawful_alternative=safer_alternative,
        upgrade_conditions=upgrade_conditions,
        backward_refs={
            "source_receipt_id": bridge_denial.get("receipt_id"),
            "request_id": None,
            "evaluation_id": None,
            "resolution_id": None,
            "decision_receipt_ids": [],
        },
    )
    artifact.validate()
    return artifact


def _default_next_evidence_move(
    evaluation_dict: Mapping[str, Any],
    *,
    outcome: Optional[str] = None,
) -> Optional[str]:
    blocking_gaps = [
        str(gap.get("kind"))
        for gap in evaluation_dict.get("evidence_bundle", {}).get("gaps", [])
        if gap.get("blocking")
    ]
    if blocking_gaps:
        return "Provide the first blocking evidence gap: " + ", ".join(blocking_gaps)
    if evaluation_dict.get("evaluation_outcome", {}).get("human_review_required"):
        return "Obtain a human approval bound to the current evaluation."
    if outcome == "escalated":
        return "Escalate the attempt to a higher-authority reviewer with the current evidence bundle."
    return None


def adapt_checkpoint_decision_to_claim_assertion(
    request: Any,
    evaluation: Any,
    decision_receipt: Mapping[str, Any],
    *,
    claim_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ClaimAssertionArtifact:
    request_dict = _normalize_artifact(request)
    evaluation_dict = _normalize_artifact(evaluation)
    route = str(evaluation_dict.get("evaluation_outcome", {}).get("route") or "unknown")
    reason_codes = list(evaluation_dict.get("evaluation_outcome", {}).get("reason_codes") or [])
    claim_text = (
        f"Checkpoint {request_dict['checkpoint_id']} for {request_dict['checkpoint_type']} "
        f"evaluated to route {route}"
    )
    if reason_codes:
        claim_text += f" because {', '.join(reason_codes)}"

    proof_tier = str(
        decision_receipt.get("proof_tier_at_decision")
        or decision_receipt.get("proof_tier_minimum_required")
        or "CHECKED"
    )
    if proof_tier not in PROOF_TIERS:
        proof_tier = "CHECKED"

    artifact = ClaimAssertionArtifact(
        claim_id=claim_id or _new_id("clm"),
        timestamp=timestamp or str(decision_receipt.get("timestamp") or _now_iso()),
        episode_id=str(request_dict["subject"]["episode_id"]),
        claim_text=claim_text,
        claim_type="POLICY",
        checkable=True,
        basis={
            "basis_type": "governance_inferred",
            "basis_refs": [
                _typed_ref(str(request_dict["request_id"]), ref_role="contextual"),
                _typed_ref(str(evaluation_dict["evaluation_id"]), ref_role="supporting"),
                _typed_ref(str(decision_receipt["receipt_id"]), ref_role="supporting"),
            ],
            "proof_tier_at_assertion": proof_tier,
        },
        claim_scope=str(request_dict["checkpoint_type"]),
        source_organ="assay-toolkit",
    )
    artifact.validate()
    return artifact


def adapt_checkpoint_decision_to_proof_budget_snapshot(
    request: Any,
    evaluation: Any,
    decision_receipt: Mapping[str, Any],
    *,
    claim_ids: Sequence[str],
    contradiction_ids: Optional[Sequence[str]] = None,
    snapshot_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ProofBudgetSnapshotArtifact:
    request_dict = _normalize_artifact(request)
    evaluation_dict = _normalize_artifact(evaluation)
    required_tier = str(decision_receipt.get("proof_tier_minimum_required") or "CHECKED")
    current_tier = str(decision_receipt.get("proof_tier_at_decision") or required_tier or "CHECKED")
    if required_tier not in PROOF_TIERS:
        required_tier = "CHECKED"
    if current_tier not in PROOF_TIERS:
        current_tier = required_tier

    evidence_gaps = list(decision_receipt.get("evidence_gaps") or [])
    blocking_reason_codes = list(evaluation_dict.get("evaluation_outcome", {}).get("reason_codes") or [])
    meets_minimum = PROOF_TIER_RANK[current_tier] >= PROOF_TIER_RANK[required_tier]
    route = str(evaluation_dict.get("evaluation_outcome", {}).get("route") or "")
    if route == "escalate" or decision_receipt.get("verdict") == "ABSTAIN":
        escalation_posture = "escalate"
    elif evaluation_dict.get("evaluation_outcome", {}).get("human_review_required") or decision_receipt.get("verdict") == "DEFER":
        escalation_posture = "review_required"
    elif evidence_gaps or blocking_reason_codes or not meets_minimum:
        escalation_posture = "blocked"
    else:
        escalation_posture = "sufficient"

    contradictions = list(contradiction_ids or [])
    artifact = ProofBudgetSnapshotArtifact(
        snapshot_id=snapshot_id or _new_id("pbs"),
        timestamp=timestamp or str(decision_receipt.get("timestamp") or _now_iso()),
        episode_id=str(request_dict["subject"]["episode_id"]),
        boundary_kind="checkpoint_decision",
        boundary_refs={
            "checkpoint_id": request_dict["checkpoint_id"],
            "request_id": request_dict["request_id"],
            "evaluation_id": evaluation_dict["evaluation_id"],
            "decision_receipt_id": decision_receipt["receipt_id"],
        },
        required_tier=required_tier,
        current_tier=current_tier,
        deficit={
            "meets_minimum": meets_minimum,
            "gap_refs": evidence_gaps,
            "blocking_reason_codes": blocking_reason_codes,
        },
        next_evidence_move=_default_next_evidence_move(evaluation_dict),
        escalation_posture=escalation_posture,
        claim_ids=list(claim_ids),
        contradiction_ids=contradictions,
    )
    artifact.validate()
    return artifact


def adapt_checkpoint_evaluation_to_contradiction_grounded_claims(
    request: Any,
    evaluation: Any,
    decision_receipt: Mapping[str, Any],
    *,
    timestamp: Optional[str] = None,
) -> List[ClaimAssertionArtifact]:
    request_dict = _normalize_artifact(request)
    evaluation_dict = _normalize_artifact(evaluation)
    evidence_index = _checkpoint_contradiction_evidence_index(evaluation_dict)
    contradiction_items = list(evaluation_dict.get("evidence_bundle", {}).get("contradictions", []))

    referenced_evidence_ids: List[str] = []
    for item in contradiction_items:
        lhs_ref = str(item.get("lhs_ref") or "").strip()
        rhs_ref = str(item.get("rhs_ref") or "").strip()
        if not lhs_ref or not rhs_ref:
            raise KernelValidationError("checkpoint contradiction requires both lhs_ref and rhs_ref")
        if lhs_ref == rhs_ref:
            raise KernelValidationError(
                f"checkpoint contradiction cannot reference the same evidence item twice: {lhs_ref}"
            )
        for ref in (lhs_ref, rhs_ref):
            if ref not in evidence_index:
                raise KernelValidationError(
                    f"checkpoint contradiction reference {ref!r} does not resolve to a known evidence item"
                )
            referenced_evidence_ids.append(ref)

    claim_timestamp = timestamp or str(decision_receipt.get("timestamp") or _now_iso())
    checkpoint_id = str(request_dict["checkpoint_id"])
    checkpoint_type = str(request_dict["checkpoint_type"])
    evaluation_id = str(evaluation_dict["evaluation_id"])
    episode_id = str(request_dict["subject"]["episode_id"])

    artifacts: List[ClaimAssertionArtifact] = []
    for evidence_id in sorted(set(referenced_evidence_ids)):
        evidence_item = evidence_index[evidence_id]
        artifact = ClaimAssertionArtifact(
            claim_id=_checkpoint_contradiction_claim_id(checkpoint_id, evaluation_id, evidence_id),
            timestamp=claim_timestamp,
            episode_id=episode_id,
            claim_text=_checkpoint_contradiction_grounded_claim_text(checkpoint_id, evidence_item),
            claim_type="FACTUAL",
            checkable=True,
            basis={
                "basis_type": "extracted",
                "basis_refs": [_checkpoint_contradiction_grounded_claim_basis_ref(evidence_item)],
                "proof_tier_at_assertion": "CHECKED",
            },
            claim_scope=checkpoint_type,
            source_organ="assay-toolkit",
        )
        artifact.validate()
        artifacts.append(artifact)

    artifacts.sort(key=lambda artifact: artifact.claim_id)
    return artifacts


def adapt_checkpoint_evaluation_to_contradiction_registrations(
    request: Any,
    evaluation: Any,
    decision_receipt: Mapping[str, Any],
    *,
    timestamp: Optional[str] = None,
) -> List[ContradictionRegistrationArtifact]:
    request_dict = _normalize_artifact(request)
    evaluation_dict = _normalize_artifact(evaluation)
    contradiction_items = list(evaluation_dict.get("evidence_bundle", {}).get("contradictions", []))
    artifacts: List[ContradictionRegistrationArtifact] = []
    for item in contradiction_items:
        lhs_ref = str(item.get("lhs_ref") or "")
        rhs_ref = str(item.get("rhs_ref") or "")
        reason_code = str(item.get("reason_code") or "inconsistent_evidence")
        severity = str(item.get("severity") or "warning")
        ordered_refs = sorted([lhs_ref, rhs_ref])
        claim_pairs = sorted(
            [
                (
                    _checkpoint_contradiction_claim_id(
                        str(request_dict["checkpoint_id"]),
                        str(evaluation_dict["evaluation_id"]),
                        ordered_refs[0],
                    ),
                    ordered_refs[0],
                ),
                (
                    _checkpoint_contradiction_claim_id(
                        str(request_dict["checkpoint_id"]),
                        str(evaluation_dict["evaluation_id"]),
                        ordered_refs[1],
                    ),
                    ordered_refs[1],
                ),
            ],
            key=lambda item_pair: item_pair[0],
        )
        status = "open" if severity == "blocking" else "contained"
        artifact = ContradictionRegistrationArtifact(
            contradiction_id=_checkpoint_contradiction_id(
                str(request_dict["checkpoint_id"]),
                str(evaluation_dict["evaluation_id"]),
                ordered_refs[0],
                ordered_refs[1],
                reason_code,
            ),
            timestamp=timestamp or str(decision_receipt.get("timestamp") or _now_iso()),
            episode_id=str(request_dict["subject"]["episode_id"]),
            claim_a_id=claim_pairs[0][0],
            claim_b_id=claim_pairs[1][0],
            conflict_type=_contradiction_conflict_type(reason_code),
            severity="high" if severity == "blocking" else "medium",
            detection={
                "detection_method": "automated_verification",
                "detection_confidence": 1.0 if severity == "blocking" else 0.8,
                "detector_id": "assay.checkpoint.evidence_bundle",
                "detection_evidence_refs": [
                    _typed_ref(str(evaluation_dict["evaluation_id"]), ref_role="contextual"),
                    _typed_ref(claim_pairs[0][1]),
                    _typed_ref(claim_pairs[1][1]),
                ],
            },
            status=status,
            scope=str(request_dict["checkpoint_type"]),
            lhs_ref=claim_pairs[0][1],
            rhs_ref=claim_pairs[1][1],
            replay_refs=[str(evaluation_dict["evaluation_id"])],
            boundary_refs={
                "checkpoint_id": str(request_dict["checkpoint_id"]),
                "request_id": str(request_dict["request_id"]),
                "evaluation_id": str(evaluation_dict["evaluation_id"]),
                "decision_receipt_id": str(decision_receipt["receipt_id"]),
            },
        )
        artifact.validate()
        artifacts.append(artifact)
    return artifacts


def adapt_checkpoint_resolution_to_contradiction_resolutions(
    request: Any,
    resolution: Any,
    registered_contradictions: Sequence[ContradictionRegistrationArtifact],
    *,
    decision_receipt_ids: Optional[Sequence[str]] = None,
    proof_tier: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> List[ContradictionResolutionArtifact]:
    """Derive contradiction resolutions from a checkpoint resolution.

    Positive resolutions (released) settle contradictions as out_of_scope
    (the action succeeded despite the contradiction).
    Negative resolutions settle contradictions as the blocking claim prevailing.
    """
    request_dict = _normalize_artifact(request)
    resolution_dict = _normalize_artifact(resolution)
    resolution_outcome = str(resolution_dict["resolution_outcome"])
    resolved_at = timestamp or str(resolution_dict.get("resolved_at") or _now_iso())
    episode_id = str(request_dict["subject"]["episode_id"])
    receipt_ids = list(decision_receipt_ids or resolution_dict.get("decision_receipt_ids") or [])
    effective_tier = proof_tier or "CHECKED"
    if effective_tier not in PROOF_TIERS:
        effective_tier = "CHECKED"

    artifacts: List[ContradictionResolutionArtifact] = []
    for contradiction in registered_contradictions:
        if resolution_outcome in NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES:
            # Negative: the contradiction's blocking side prevailed
            ctr_resolution_outcome = "claim_a_prevails"
        elif resolution_outcome == "released":
            # Positive: contradiction was not blocking, treat as out_of_scope
            ctr_resolution_outcome = "out_of_scope"
        else:
            ctr_resolution_outcome = "deferred"

        evidence_refs = [
            _typed_ref(str(resolution_dict["resolution_id"]), ref_role="supporting"),
        ]
        for receipt_id in receipt_ids:
            evidence_refs.append(_typed_ref(receipt_id, ref_role="supporting"))

        artifact = ContradictionResolutionArtifact(
            resolution_id=_new_id("crr"),
            timestamp=resolved_at,
            contradiction_id=contradiction.contradiction_id,
            episode_id=episode_id,
            resolution_outcome=ctr_resolution_outcome,
            resolution_basis={
                "authority_type": "governance_decision",
                "decision_receipt_id": receipt_ids[0] if receipt_ids else None,
                "evidence_refs": evidence_refs,
                "prevailing_proof_tier": effective_tier,
                "rationale": (
                    f"Contradiction settled by checkpoint resolution "
                    f"{resolution_dict['resolution_id']} with outcome {resolution_outcome}."
                ),
            },
        )
        artifact.validate()
        artifacts.append(artifact)
    return artifacts


def adapt_checkpoint_resolution_to_denial_record(
    request: Any,
    evaluation: Any,
    resolution: Any,
    *,
    denial_id: Optional[str] = None,
    related_claim_ids: Optional[Sequence[str]] = None,
    proof_budget_snapshot_id: Optional[str] = None,
    contradiction_ids: Optional[Sequence[str]] = None,
) -> DenialRecordArtifact:
    request_dict = _normalize_artifact(request)
    evaluation_dict = _normalize_artifact(evaluation)
    resolution_dict = _normalize_artifact(resolution)

    outcome = str(resolution_dict["resolution_outcome"])
    if outcome not in NEGATIVE_CHECKPOINT_RESOLUTION_OUTCOMES:
        raise KernelValidationError(
            f"checkpoint resolution outcome {outcome!r} does not require a canonical denial"
        )

    blocking_gaps = [
        str(gap.get("kind"))
        for gap in evaluation_dict.get("evidence_bundle", {}).get("gaps", [])
        if gap.get("blocking")
    ]
    action_target = request_dict.get("attempt", {}).get("action_target", {})
    target_summary = None
    if action_target:
        target_summary = f"{action_target.get('system', 'unknown')}:{action_target.get('operation', 'unknown')}"

    if outcome == "review_rejected":
        cheaper_next_move = "Revise the outbound action and obtain a fresh human approval."
    else:
        cheaper_next_move = _default_next_evidence_move(evaluation_dict, outcome=outcome)
    if cheaper_next_move is None:
        cheaper_next_move = "Gather stronger supporting evidence or change the requested action before retrying."

    if request_dict["checkpoint_type"] == "outbound_action.send_email":
        safer_lawful_alternative = "Keep the message unsent and hand off to a human operator."
    else:
        safer_lawful_alternative = "Do not execute the requested action until policy conditions are satisfied."

    upgrade_conditions = [f"provide:{gap}" for gap in blocking_gaps]
    if evaluation_dict.get("evaluation_outcome", {}).get("human_review_required"):
        upgrade_conditions.append("human_approval")
    if outcome == "review_rejected":
        upgrade_conditions.append("new_human_approval")
    if outcome == "escalated":
        upgrade_conditions.append("higher_authority_review")
    if not upgrade_conditions:
        upgrade_conditions.append("policy_conditions_satisfied")

    artifact = DenialRecordArtifact(
        denial_id=denial_id or _new_id("den"),
        timestamp=str(resolution_dict.get("resolved_at") or _now_iso()),
        denial_outcome=outcome,
        source_surface=f"assay.checkpoint.{request_dict['checkpoint_type']}",
        subject={
            "subject_type": "checkpoint_attempt",
            "subject_id": request_dict["checkpoint_id"],
        },
        attempted_action={
            "action_type": request_dict["checkpoint_type"],
            "action_name": action_target.get("operation", request_dict["checkpoint_type"]),
            "action_target": target_summary,
            "argument_hash": request_dict.get("attempt", {}).get("intent_hash"),
        },
        blocking_basis={
            "basis_type": "checkpoint_resolution",
            "summary": (
                f"Checkpoint ended with {outcome}: "
                + ", ".join(resolution_dict.get("reason_codes") or [])
            ),
            "reason_codes": list(resolution_dict.get("reason_codes") or []),
            "policy_ref": evaluation_dict.get("policy", {}).get("policy_id"),
            "policy_hash": evaluation_dict.get("policy", {}).get("policy_hash"),
        },
        missing_evidence=blocking_gaps,
        cheaper_next_move=cheaper_next_move,
        safer_lawful_alternative=safer_lawful_alternative,
        upgrade_conditions=upgrade_conditions,
        related_claim_ids=list(related_claim_ids or []),
        proof_budget_snapshot_id=proof_budget_snapshot_id,
        contradiction_ids=list(contradiction_ids or []),
        backward_refs={
            "source_receipt_id": None,
            "request_id": request_dict["request_id"],
            "evaluation_id": resolution_dict.get("final_evaluation_id") or resolution_dict["evaluation_id"],
            "resolution_id": resolution_dict["resolution_id"],
            "decision_receipt_ids": list(resolution_dict.get("decision_receipt_ids") or []),
        },
    )
    artifact.validate()
    return artifact


def adapt_ccio_refusalstone_to_denial_record(
    refusal_stone: Mapping[str, Any],
    *,
    denial_id: Optional[str] = None,
) -> DenialRecordArtifact:
    details = copy.deepcopy(refusal_stone.get("details") or {})
    reason = str(refusal_stone.get("reason") or "Guardian refusal")
    reason_codes = list(refusal_stone.get("reasons") or [])
    if not reason_codes:
        reason_codes = [reason]

    attempted_action = copy.deepcopy(details.get("attempted_action") or {})
    if not attempted_action:
        attempted_action = {
            "action_type": str(details.get("action_type") or "governed_action"),
            "action_name": str(details.get("action_name") or reason),
            "action_target": details.get("action_target"),
            "argument_hash": details.get("argument_hash"),
        }

    subject_id = (
        details.get("subject_id")
        or refusal_stone.get("asset_id")
        or refusal_stone.get("domain")
        or "unknown_subject"
    )
    subject_type = details.get("subject_type") or ("asset" if refusal_stone.get("asset_id") else "domain")

    artifact = DenialRecordArtifact(
        denial_id=denial_id or _new_id("den"),
        timestamp=str(refusal_stone.get("timestamp") or _now_iso()),
        denial_outcome=str(details.get("denial_outcome") or "refused"),
        source_surface="ccio.refusalstone",
        subject={
            "subject_type": str(subject_type),
            "subject_id": str(subject_id),
        },
        attempted_action=attempted_action,
        blocking_basis={
            "basis_type": "guardian_refusal",
            "summary": reason,
            "reason_codes": reason_codes,
            "policy_ref": details.get("policy_ref"),
            "policy_hash": details.get("policy_hash"),
        },
        missing_evidence=list(details.get("missing_evidence") or []),
        cheaper_next_move=details.get("cheaper_next_move") or details.get("recourse_kind"),
        safer_lawful_alternative=details.get("safer_lawful_alternative"),
        upgrade_conditions=list(details.get("upgrade_conditions") or []),
        related_claim_ids=list(details.get("related_claim_ids") or []),
        proof_budget_snapshot_id=details.get("proof_budget_snapshot_id"),
        contradiction_ids=list(details.get("contradiction_ids") or []),
        backward_refs={
            "source_receipt_id": refusal_stone.get("receipt_id"),
            "request_id": details.get("request_id"),
            "evaluation_id": details.get("evaluation_id"),
            "resolution_id": details.get("resolution_id"),
            "decision_receipt_ids": list(details.get("decision_receipt_ids") or []),
        },
    )
    artifact.validate()
    return artifact


__all__ = [
    "SCHEMA_VERSION",
    "CLAIM_ASSERTION_RECEIPT_TYPE",
    "CLAIM_SUPPORT_CHANGE_RECEIPT_TYPE",
    "DENIAL_RECORD_RECEIPT_TYPE",
    "PROOF_BUDGET_SNAPSHOT_RECEIPT_TYPE",
    "BELIEF_UPDATE_RECEIPT_TYPE",
    "CONTRADICTION_REGISTRATION_RECEIPT_TYPE",
    "CONTRADICTION_RESOLUTION_RECEIPT_TYPE",
    "KernelValidationError",
    "ArtifactVerificationResult",
    "ClaimChainVerificationResult",
    "ClaimAssertionArtifact",
    "ClaimSupportChangeArtifact",
    "ContradictionRegistrationArtifact",
    "ContradictionResolutionArtifact",
    "DenialRecordArtifact",
    "ProofBudgetSnapshotArtifact",
    "BeliefUpdateArtifact",
    "emit_claim_assertion",
    "emit_claim_support_change",
    "emit_contradiction_registration",
    "emit_contradiction_resolution",
    "emit_denial_record_to_episode",
    "emit_denial_record_to_trace",
    "emit_proof_budget_snapshot",
    "emit_belief_update",
    "verify_claim_artifact_set",
    "verify_claim_support_chain",
    "verify_contradiction_registration_artifact",
    "verify_contradiction_resolution_artifact",
    "verify_denial_record",
    "verify_proof_budget_snapshot",
    "verify_belief_update",
    "adapt_bridge_denial_to_denial_record",
    "adapt_contradiction_receipt_to_registration",
    "adapt_checkpoint_decision_to_claim_assertion",
    "adapt_checkpoint_decision_to_proof_budget_snapshot",
    "adapt_checkpoint_evaluation_to_contradiction_grounded_claims",
    "adapt_checkpoint_evaluation_to_contradiction_registrations",
    "adapt_checkpoint_resolution_to_denial_record",
    "adapt_ccio_refusalstone_to_denial_record",
]
