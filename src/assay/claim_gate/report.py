"""JSON report rendering for Assay Claim Gate."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from assay.claim_gate.models import (
    BLOCK,
    NEEDS_REVIEW,
    PASS,
    ClaimBoundaryTransition,
    NonClaim,
)


SCHEMA_VERSION = "assay.claim_gate_report.v0"


def build_report(
    *,
    base: str,
    head: str,
    policy_path: str,
    files_scanned: int,
    transitions: List[ClaimBoundaryTransition],
    non_claims: List[NonClaim],
) -> Dict[str, Any]:
    """Build a deterministic Claim Gate report dict."""
    ordered = _with_ids(_sort_transitions(transitions))
    verdict = overall_verdict(ordered)
    return {
        "schema_version": SCHEMA_VERSION,
        "command": "assay claim-gate diff",
        "verdict": verdict,
        "subject": {
            "base": base,
            "head": head,
            "policy": policy_path,
        },
        "summary": {
            "files_scanned": files_scanned,
            "transitions_detected": len(ordered),
            "blocking_transitions": sum(1 for item in ordered if item.verdict == BLOCK),
            "needs_review": sum(1 for item in ordered if item.verdict == NEEDS_REVIEW),
            "non_claims": len(non_claims),
        },
        "transitions": [item.to_dict() for item in ordered],
        "non_claims": [
            item.to_dict()
            for item in sorted(
                non_claims,
                key=lambda n: (n.file, n.span.start_line, n.reason),
            )
        ],
        "non_claims_global": [
            "This report does not determine truth.",
            "This report does not certify legal compliance.",
            "This report does not approve production deployment.",
            "This report only gates configured claim-boundary transitions.",
        ],
    }


def write_report(report: Dict[str, Any], path: Path) -> None:
    """Write a deterministic JSON report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_json(report) + "\n", encoding="utf-8")


def report_json(report: Dict[str, Any]) -> str:
    """Return canonical-ish JSON for stable snapshots and PR artifacts."""
    return json.dumps(report, indent=2, sort_keys=True)


def overall_verdict(transitions: List[ClaimBoundaryTransition]) -> str:
    if any(item.verdict == BLOCK for item in transitions):
        return BLOCK
    if any(item.verdict == NEEDS_REVIEW for item in transitions):
        return NEEDS_REVIEW
    return PASS


def exit_code_for_verdict(verdict: str, *, fail_on_review: bool = False) -> int:
    if verdict == BLOCK:
        return 2
    if verdict == NEEDS_REVIEW and fail_on_review:
        return 1
    return 0


def _sort_transitions(
    transitions: List[ClaimBoundaryTransition],
) -> List[ClaimBoundaryTransition]:
    return sorted(
        transitions,
        key=lambda item: (
            item.file,
            item.after_span.start_line,
            item.transition_class,
            item.after_span.text,
        ),
    )


def _with_ids(
    transitions: List[ClaimBoundaryTransition],
) -> List[ClaimBoundaryTransition]:
    return [
        transition.with_id(f"cgt_{index:03d}")
        for index, transition in enumerate(transitions, 1)
    ]
