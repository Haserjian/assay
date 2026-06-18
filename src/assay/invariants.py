"""Invariant accounting primitives for Assay.

This module is intentionally small. It gives Assay a first-class accounting
surface for evaluating whether declared invariants survived an episode without
changing existing Guardian behavior or proof-tier semantics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Mapping, Optional, Tuple


ProofTierName = str

PROOF_TIER_VALUES: Tuple[ProofTierName, ...] = (
    "DRAFT",
    "CHECKED",
    "TOOL_VERIFIED",
    "ADVERSARIAL",
    "CONSTITUTIONAL",
)


class InvariantStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class InvariantSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    BLOCKING = "BLOCKING"


@dataclass(frozen=True)
class EvidenceRef:
    ref_id: str
    ref_type: str = "receipt"
    ref_role: str = "supporting"


@dataclass(frozen=True)
class InvariantSpec:
    invariant_id: str
    claim: str
    measurement: Mapping[str, Any]
    tolerance: Mapping[str, Any]
    severity: InvariantSeverity = InvariantSeverity.BLOCKING
    proof_tier_required: ProofTierName = "CHECKED"
    scope: Mapping[str, Any] = field(default_factory=dict)
    model_regime: Mapping[str, Any] = field(default_factory=dict)
    break_conditions: List[str] = field(default_factory=list)
    on_violation: Mapping[str, Any] = field(default_factory=dict)
    compression_warning: Mapping[str, List[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class InvariantEvaluation:
    invariant_id: str
    status: InvariantStatus
    severity: InvariantSeverity
    observed_value: Optional[Mapping[str, Any]]
    expected_value: Optional[Mapping[str, Any]]
    proof_tier_observed: ProofTierName
    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    uncertainty: List[str] = field(default_factory=list)
    compression_loss_observed: List[str] = field(default_factory=list)
    guardian_action: Optional[str] = None
    episode_id: Optional[str] = None
    reason: Optional[str] = None


def evaluate_latency_budget(
    spec: InvariantSpec,
    receipt: Optional[Mapping[str, Any]],
) -> InvariantEvaluation:
    """Evaluate a wall-clock latency budget invariant.

    Expected spec shape:
        measurement.metric == "wall_clock_ms"
        tolerance.max_ms is numeric

    Expected receipt shape:
        receipt_id: optional evidence reference
        episode_id: optional episode reference
        wall_clock_ms: numeric observed latency
    """
    evidence_refs = _evidence_refs_from_receipt(receipt)
    episode_id = _episode_id_from_receipt(receipt)
    compression_loss = list(spec.compression_warning.get("lost_distinctions", []))
    guardian_action = _guardian_action(spec)
    metric = spec.measurement.get("metric")
    max_ms = spec.tolerance.get("max_ms")

    if metric is None:
        return _evaluation(
            spec,
            InvariantStatus.UNKNOWN,
            evidence_refs=evidence_refs,
            episode_id=episode_id,
            expected_value={"metric": "wall_clock_ms"},
            uncertainty=["Latency invariant missing measurement.metric."],
            compression_loss_observed=compression_loss,
            guardian_action=guardian_action,
            reason="missing_metric",
        )

    if metric != "wall_clock_ms":
        return _evaluation(
            spec,
            InvariantStatus.UNKNOWN,
            evidence_refs=evidence_refs,
            episode_id=episode_id,
            expected_value={"metric": "wall_clock_ms"},
            uncertainty=["Latency evaluator only applies to measurement.metric == 'wall_clock_ms'."],
            compression_loss_observed=compression_loss,
            guardian_action=guardian_action,
            reason="unsupported_metric",
        )

    if not _is_number(max_ms):
        return _evaluation(
            spec,
            InvariantStatus.UNKNOWN,
            evidence_refs=evidence_refs,
            episode_id=episode_id,
            expected_value={"max_ms": max_ms},
            uncertainty=["Latency invariant missing numeric tolerance.max_ms."],
            compression_loss_observed=compression_loss,
            guardian_action=guardian_action,
            reason="invalid_max_ms",
        )

    if receipt is None:
        return _evaluation(
            spec,
            InvariantStatus.UNKNOWN,
            evidence_refs=evidence_refs,
            episode_id=episode_id,
            expected_value={"max_ms": max_ms},
            uncertainty=["Latency receipt is missing."],
            compression_loss_observed=compression_loss,
            guardian_action=guardian_action,
            reason="missing_receipt",
        )

    observed_ms = receipt.get("wall_clock_ms")
    if "wall_clock_ms" not in receipt:
        return _evaluation(
            spec,
            InvariantStatus.UNKNOWN,
            evidence_refs=evidence_refs,
            episode_id=episode_id,
            expected_value={"max_ms": max_ms},
            uncertainty=["Latency receipt missing wall_clock_ms."],
            compression_loss_observed=compression_loss,
            guardian_action=guardian_action,
            reason="missing_wall_clock_ms",
        )

    if not _is_number(observed_ms):
        return _evaluation(
            spec,
            InvariantStatus.UNKNOWN,
            evidence_refs=evidence_refs,
            episode_id=episode_id,
            observed_value={"wall_clock_ms": observed_ms},
            expected_value={"max_ms": max_ms},
            uncertainty=["wall_clock_ms must be numeric."],
            compression_loss_observed=compression_loss,
            guardian_action=guardian_action,
            reason="invalid_wall_clock_ms",
        )

    status = InvariantStatus.PASS if observed_ms <= max_ms else InvariantStatus.FAIL
    return _evaluation(
        spec,
        status,
        evidence_refs=evidence_refs,
        episode_id=episode_id,
        observed_value={"wall_clock_ms": observed_ms},
        expected_value={"max_ms": max_ms},
        compression_loss_observed=compression_loss,
        guardian_action=None if status is InvariantStatus.PASS else guardian_action,
        reason="latency_budget_passed" if status is InvariantStatus.PASS else "latency_budget_exceeded",
    )


def _evaluation(
    spec: InvariantSpec,
    status: InvariantStatus,
    *,
    evidence_refs: List[EvidenceRef],
    episode_id: Optional[str],
    observed_value: Optional[Mapping[str, Any]] = None,
    expected_value: Optional[Mapping[str, Any]] = None,
    uncertainty: Optional[List[str]] = None,
    compression_loss_observed: Optional[List[str]] = None,
    guardian_action: Optional[str] = None,
    reason: Optional[str] = None,
) -> InvariantEvaluation:
    return InvariantEvaluation(
        invariant_id=spec.invariant_id,
        status=status,
        severity=spec.severity,
        observed_value=observed_value,
        expected_value=expected_value,
        proof_tier_observed=spec.proof_tier_required,
        evidence_refs=evidence_refs,
        uncertainty=uncertainty or [],
        compression_loss_observed=compression_loss_observed or [],
        guardian_action=guardian_action,
        episode_id=episode_id,
        reason=reason,
    )


def _evidence_refs_from_receipt(receipt: Optional[Mapping[str, Any]]) -> List[EvidenceRef]:
    if receipt is None:
        return []
    receipt_id = receipt.get("receipt_id")
    if not receipt_id:
        return []
    return [EvidenceRef(ref_id=str(receipt_id))]


def _episode_id_from_receipt(receipt: Optional[Mapping[str, Any]]) -> Optional[str]:
    if receipt is None:
        return None
    episode_id = receipt.get("episode_id")
    return str(episode_id) if episode_id else None


def _guardian_action(spec: InvariantSpec) -> Optional[str]:
    action = spec.on_violation.get("guardian_action")
    return str(action) if action else None


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


__all__ = [
    "EvidenceRef",
    "InvariantEvaluation",
    "InvariantSeverity",
    "InvariantSpec",
    "InvariantStatus",
    "PROOF_TIER_VALUES",
    "ProofTierName",
    "evaluate_latency_budget",
]
