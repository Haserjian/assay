"""CLI helpers for Assay Claim Gate."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

from assay.claim_gate.detectors import detect_collection
from assay.claim_gate.diff_source import DiffSourceError, collect_diff
from assay.claim_gate.evidence import build_evidence_index
from assay.claim_gate.policy import ClaimGatePolicyError, apply_policy, load_policy
from assay.claim_gate.report import build_report, exit_code_for_verdict, write_report


class ClaimGateError(ValueError):
    """Raised when Claim Gate cannot produce a report."""


def run_claim_gate_diff(
    *,
    repo_root: Path,
    base: str,
    head: str,
    policy_path: Path,
    out_path: Optional[Path] = None,
    fail_on_review: bool = False,
    paths: Optional[Sequence[str]] = None,
) -> Tuple[Dict[str, object], int]:
    """Run Claim Gate over a Git diff and optionally write the report."""
    try:
        repo_root = repo_root.resolve()
        policy_path = policy_path.resolve()
        policy = load_policy(policy_path)
        diff = collect_diff(repo_root=repo_root, base=base, head=head, paths=paths)
        transitions, non_claims = detect_collection(
            diff.pairs,
            allow_markers=policy.allow_markers,
        )
        requirements = [
            requirement
            for transition in transitions
            for requirement in policy.rule_for(transition.transition_class).requires
        ]
        evidence_index = build_evidence_index(
            repo_root=repo_root,
            head=head,
            requirements=requirements,
            policy=policy,
        )
        evaluated = apply_policy(transitions, policy, evidence_index)
        report = build_report(
            base=base,
            head=head,
            policy_path=_report_path(policy_path, repo_root),
            files_scanned=diff.files_scanned,
            transitions=evaluated,
            non_claims=non_claims,
        )
        if out_path is not None:
            write_report(report, out_path)
        return report, exit_code_for_verdict(
            str(report["verdict"]),
            fail_on_review=fail_on_review,
        )
    except (ClaimGatePolicyError, DiffSourceError, OSError) as exc:
        raise ClaimGateError(str(exc)) from exc


def _report_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())
