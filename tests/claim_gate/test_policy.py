from __future__ import annotations

from assay.claim_gate.models import ClaimBoundaryTransition, TextSpan
from assay.claim_gate.policy import apply_policy, parse_policy


def _transition(transition_class: str) -> ClaimBoundaryTransition:
    span_before = TextSpan(
        file="README.md",
        start_line=1,
        end_line=1,
        text="This experimental prototype may help.",
    )
    span_after = TextSpan(
        file="README.md",
        start_line=1,
        end_line=1,
        text="This production-ready framework guarantees outcomes.",
    )
    return ClaimBoundaryTransition(
        transition_class=transition_class,
        file="README.md",
        before_span=span_before,
        after_span=span_after,
    )


def test_blocked_transition_blocks_when_required_evidence_missing() -> None:
    policy = parse_policy(
        {
            "schema_version": "assay.claim_policy.v0",
            "default_verdict": "NEEDS_REVIEW",
            "blocked_transitions": {
                "prototype_to_production": {
                    "severity": "high",
                    "requires": ["production_deployment_receipt"],
                }
            },
        }
    )

    [evaluated] = apply_policy([_transition("prototype_to_production")], policy, {})

    assert evaluated.verdict == "BLOCK"
    assert evaluated.severity == "high"
    assert evaluated.evidence_required == ["production_deployment_receipt"]
    assert evaluated.evidence_found == []


def test_blocked_transition_passes_when_required_evidence_is_found() -> None:
    policy = parse_policy(
        {
            "schema_version": "assay.claim_policy.v0",
            "default_verdict": "NEEDS_REVIEW",
            "blocked_transitions": {
                "prototype_to_production": {
                    "severity": "high",
                    "requires": ["production_deployment_receipt"],
                }
            },
        }
    )

    [evaluated] = apply_policy(
        [_transition("prototype_to_production")],
        policy,
        {
            "production_deployment_receipt": [
                "receipts/production_deployment_receipt.json"
            ]
        },
    )

    assert evaluated.verdict == "PASS"
    assert evaluated.evidence_found == [
        "production_deployment_receipt:receipts/production_deployment_receipt.json"
    ]


def test_review_transition_defaults_to_needs_review_when_evidence_missing() -> None:
    policy = parse_policy(
        {
            "schema_version": "assay.claim_policy.v0",
            "default_verdict": "NEEDS_REVIEW",
            "review_transitions": {
                "local_to_general": {
                    "severity": "medium",
                    "requires": ["scope_evidence"],
                }
            },
        }
    )

    [evaluated] = apply_policy([_transition("local_to_general")], policy, {})

    assert evaluated.verdict == "NEEDS_REVIEW"
    assert evaluated.evidence_required == ["scope_evidence"]
