from __future__ import annotations

from assay.claim_gate.models import BLOCK, NEEDS_REVIEW, ClaimBoundaryTransition, TextSpan
from assay.claim_gate.report import build_report, exit_code_for_verdict, report_json


def _transition(verdict: str) -> ClaimBoundaryTransition:
    before = TextSpan("README.md", 3, 3, "This experimental prototype may help.")
    after = TextSpan("README.md", 3, 3, "This production-ready framework guarantees safety.")
    return ClaimBoundaryTransition(
        transition_class="prototype_to_production",
        file="README.md",
        before_span=before,
        after_span=after,
        severity="high",
        evidence_required=["production_deployment_receipt"],
        verdict=verdict,
    )


def test_report_assigns_ids_and_blocks_on_blocking_transition() -> None:
    report = build_report(
        base="main",
        head="HEAD",
        policy_path="assay.claims.yml",
        files_scanned=1,
        transitions=[_transition(BLOCK)],
        non_claims=[],
    )

    assert report["verdict"] == "BLOCK"
    assert report["summary"]["blocking_transitions"] == 1
    assert report["transitions"][0]["id"] == "cgt_001"
    assert "does not determine truth" in report_json(report)


def test_exit_codes_keep_needs_review_advisory_by_default() -> None:
    assert exit_code_for_verdict("PASS") == 0
    assert exit_code_for_verdict(NEEDS_REVIEW) == 0
    assert exit_code_for_verdict(NEEDS_REVIEW, fail_on_review=True) == 1
    assert exit_code_for_verdict(BLOCK) == 2
