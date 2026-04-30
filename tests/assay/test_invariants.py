"""Tests for invariant accounting primitives."""
from __future__ import annotations

from assay.invariants import (
    EvidenceRef,
    InvariantSeverity,
    InvariantSpec,
    InvariantStatus,
    PROOF_TIER_VALUES,
    evaluate_latency_budget,
)


def _latency_spec(**overrides) -> InvariantSpec:
    payload = {
        "invariant_id": "invariant.latency_budget.v0",
        "claim": "Episode execution stays within the configured latency budget.",
        "measurement": {"metric": "wall_clock_ms"},
        "tolerance": {"max_ms": 1000},
        "severity": InvariantSeverity.BLOCKING,
        "proof_tier_required": "CHECKED",
        "on_violation": {"guardian_action": "degrade_or_reroute"},
        "compression_warning": {
            "lost_distinctions": [
                "System-measured latency may differ from user-perceived latency.",
            ],
        },
    }
    payload.update(overrides)
    return InvariantSpec(**payload)


def test_uses_existing_proof_tier_vocabulary() -> None:
    assert PROOF_TIER_VALUES == (
        "DRAFT",
        "CHECKED",
        "TOOL_VERIFIED",
        "ADVERSARIAL",
        "CONSTITUTIONAL",
    )


def test_latency_missing_receipt_returns_unknown() -> None:
    result = evaluate_latency_budget(_latency_spec(), None)

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "missing_receipt"
    assert result.guardian_action == "degrade_or_reroute"
    assert result.evidence_refs == []


def test_latency_missing_metric_name_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(measurement={}),
        {"receipt_id": "r-001", "wall_clock_ms": 100},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "missing_metric"
    assert result.evidence_refs == [EvidenceRef(ref_id="r-001")]


def test_latency_unsupported_metric_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(measurement={"metric": "tokens"}),
        {"receipt_id": "r-001", "wall_clock_ms": 100},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "unsupported_metric"


def test_latency_missing_max_ms_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(tolerance={}),
        {"receipt_id": "r-001", "wall_clock_ms": 100},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "invalid_max_ms"


def test_latency_nonnumeric_max_ms_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(tolerance={"max_ms": "fast"}),
        {"receipt_id": "r-001", "wall_clock_ms": 100},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "invalid_max_ms"


def test_latency_missing_wall_clock_ms_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(),
        {"receipt_id": "r-001", "episode_id": "ep-001"},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "missing_wall_clock_ms"
    assert result.episode_id == "ep-001"
    assert result.evidence_refs == [EvidenceRef(ref_id="r-001")]


def test_latency_nonnumeric_wall_clock_ms_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(),
        {"receipt_id": "r-001", "wall_clock_ms": "slow"},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "invalid_wall_clock_ms"
    assert result.observed_value == {"wall_clock_ms": "slow"}


def test_latency_bool_wall_clock_ms_returns_unknown() -> None:
    result = evaluate_latency_budget(
        _latency_spec(),
        {"receipt_id": "r-001", "wall_clock_ms": True},
    )

    assert result.status is InvariantStatus.UNKNOWN
    assert result.reason == "invalid_wall_clock_ms"


def test_latency_under_budget_passes() -> None:
    result = evaluate_latency_budget(
        _latency_spec(),
        {"receipt_id": "r-001", "episode_id": "ep-001", "wall_clock_ms": 1000},
    )

    assert result.status is InvariantStatus.PASS
    assert result.reason == "latency_budget_passed"
    assert result.guardian_action is None
    assert result.observed_value == {"wall_clock_ms": 1000}
    assert result.expected_value == {"max_ms": 1000}


def test_latency_over_budget_fails() -> None:
    result = evaluate_latency_budget(
        _latency_spec(),
        {"receipt_id": "r-001", "episode_id": "ep-001", "wall_clock_ms": 1001},
    )

    assert result.status is InvariantStatus.FAIL
    assert result.reason == "latency_budget_exceeded"
    assert result.guardian_action == "degrade_or_reroute"


def test_latency_evaluation_preserves_compression_warnings() -> None:
    result = evaluate_latency_budget(
        _latency_spec(),
        {"receipt_id": "r-001", "wall_clock_ms": 100},
    )

    assert result.compression_loss_observed == [
        "System-measured latency may differ from user-perceived latency.",
    ]
