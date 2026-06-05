"""Render PR Gate Verification Reports as pull request comments."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from assay.pr_gate.packet import DO_NOT_INFER, VERIFY_REPORT_SCHEMA_VERSION


class CommentRenderError(ValueError):
    """Raised when a PR Gate comment cannot be rendered safely."""


def render_pr_gate_comment(
    *,
    report: Mapping[str, Any],
    pack_manifest: Mapping[str, Any],
    evidence: Optional[Mapping[str, Any]] = None,
) -> str:
    """Render a stable Markdown PR Gate comment."""
    _validate_report(report)
    _validate_manifest(pack_manifest)
    _validate_report_manifest_binding(report=report, pack_manifest=pack_manifest)
    subject = _mapping(report.get("subject"), "report.subject")
    channels = _mapping(report.get("channels"), "report.channels")
    decision = _string(report.get("overall_decision"), "report.overall_decision")
    recommended_action = _string(
        report.get("recommended_action"), "report.recommended_action"
    )
    reasons = _reasons(report)
    evidence = evidence or {}

    lines = [
        f"Assay PR Gate: {_decision_label(decision)}",
        "",
        f"Recommended action: {recommended_action}",
        f"Reason: {_reason_summary(reasons)}",
        "",
        "Subject:",
        f"- repo: {subject.get('repo')}",
        f"- PR: #{subject.get('pr_number')}",
        f"- head commit: {subject.get('head_sha')}",
        f"- diff hash: {subject.get('diff_sha256')}",
        "",
        "Verdict channels:",
        f"- Integrity: {channels.get('integrity')}",
        f"- Claim: {_claim_line(report=report, evidence=evidence)}",
        f"- Replay: {channels.get('replay')}",
        f"- Trust policy: {_trust_policy_line(report=report)}",
        "",
        "Evidence:",
        f"- Evidence Box: {_evidence_ref(report, 'Evidence Box', 'proof-pack/pack_manifest.json')}",
        f"- Verification Report: {_evidence_ref(report, 'Verification Report', 'signed-report/verify_report.json')}",
        f"- Signature Proof: {_evidence_ref(report, 'Signature Proof', 'signed-report/verify_report.sigstore.json')}",
        "",
        "Do not infer:",
    ]
    lines.extend(f"- {item}" for item in _do_not_infer(report))
    lines.extend(
        [
            "",
            "Signed by expected workflow:",
            _expected_identity(report),
            "",
            "How to verify:",
            "- Download `assay-pr-gate-report`, then run `assay pr-gate verify` against `proof-pack/` and `signed-report/`.",
            "",
            "How to challenge:",
            "- Comment with missing evidence, stale policy, signer trust, replay divergence, overbroad claim, or contradictory evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_pr_gate_comment_files(
    *,
    report_path: Path,
    pack_manifest_path: Path,
    out_path: Optional[Path] = None,
) -> str:
    """Load a PR Gate report and manifest, render a comment, and optionally write it."""
    report = _load_json_object(report_path, "Verification Report")
    pack_manifest = _load_json_object(pack_manifest_path, "pack manifest")
    evidence = _load_optional_evidence(pack_manifest_path)
    comment = render_pr_gate_comment(
        report=report,
        pack_manifest=pack_manifest,
        evidence=evidence,
    )
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(comment, encoding="utf-8")
    return comment


def _validate_report(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != VERIFY_REPORT_SCHEMA_VERSION:
        raise CommentRenderError("report schema_version is not PR Gate v0.1")
    for key in (
        "subject",
        "overall_decision",
        "recommended_action",
        "channels",
        "signature_policy",
    ):
        if key not in report:
            raise CommentRenderError(f"report missing {key}")


def _validate_manifest(pack_manifest: Mapping[str, Any]) -> None:
    for key in ("pack_root_sha256", "subject", "decision_ref"):
        if key not in pack_manifest:
            raise CommentRenderError(f"pack manifest missing {key}")


def _validate_report_manifest_binding(
    *, report: Mapping[str, Any], pack_manifest: Mapping[str, Any]
) -> None:
    if report.get("pack_root_sha256") != pack_manifest.get("pack_root_sha256"):
        raise CommentRenderError("report pack_root_sha256 does not match pack manifest")
    if report.get("subject") != pack_manifest.get("subject"):
        raise CommentRenderError("report subject does not match pack manifest")
    if report.get("policy") != pack_manifest.get("policy"):
        raise CommentRenderError("report policy does not match pack manifest")

    decision_ref = _mapping(
        pack_manifest.get("decision_ref"), "pack_manifest.decision_ref"
    )
    for field in ("overall_decision", "recommended_action", "channels"):
        if report.get(field) != decision_ref.get(field):
            raise CommentRenderError(
                f"report {field} does not match pack manifest decision_ref"
            )


def _decision_label(decision: str) -> str:
    if decision == "PASS":
        return "PASS - proceed to normal review"
    return decision


def _reason_summary(reasons: List[Mapping[str, Any]]) -> str:
    if not reasons:
        return "none"
    reason = reasons[0]
    rule = reason.get("rule")
    if rule == "risk_path_touched":
        pattern = reason.get("matched_pattern")
        return f"touched risk path {pattern}" if pattern else "touched risk path"
    if rule == "required_check_missing":
        return _missing_check_summary(reason)
    if rule == "required_check_failed":
        return f"required check \"{reason.get('check')}\" failed"
    if rule == "integrity_failed":
        return "integrity failed"
    if rule == "untrusted_signer":
        return "untrusted signer"
    return json.dumps(reason, sort_keys=True)


def _claim_line(*, report: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    channels = _mapping(report.get("channels"), "report.channels")
    claim = channels.get("claim")
    if claim != "PASS":
        return _non_pass_claim_line(report=report, claim=str(claim))
    claim_gate = evidence.get("claim_gate_report")
    if isinstance(claim_gate, Mapping) and claim_gate.get("verdict") == "PASS":
        return "PASS - claim_gate report verdict PASS"
    subject = _mapping(report.get("subject"), "report.subject")
    head_sha = subject.get("head_sha")
    checks = evidence.get("observed_checks") or []
    if isinstance(checks, list):
        for check in checks:
            if not isinstance(check, Mapping):
                continue
            name = check.get("name")
            conclusion = check.get("conclusion")
            check_sha = check.get("head_sha")
            if name and conclusion and check_sha == head_sha:
                return (
                    f"{claim} - observed check \"{name}\" concluded "
                    f"{conclusion} for commit {head_sha}"
                )
    return str(claim)


def _non_pass_claim_line(*, report: Mapping[str, Any], claim: str) -> str:
    claim_gate_reasons = [
        reason
        for reason in _reasons(report)
        if reason.get("rule") in {"claim_gate_block", "claim_gate_needs_review"}
    ]
    if claim_gate_reasons:
        verdict = str(claim_gate_reasons[0].get("claim_gate_verdict") or "UNKNOWN")
        classes = sorted(
            {
                str(reason.get("transition_class"))
                for reason in claim_gate_reasons
                if reason.get("transition_class")
            }
        )
        suffix = f": {', '.join(classes)}" if classes else ""
        if verdict == "NEEDS_REVIEW":
            return f"{claim} - claim_gate NEEDS_REVIEW{suffix}; claim evidence requires human review"
        return f"{claim} - claim_gate {verdict}{suffix}"
    return claim


def _trust_policy_line(*, report: Mapping[str, Any]) -> str:
    channels = _mapping(report.get("channels"), "report.channels")
    trust_policy = channels.get("trust_policy")
    for reason in _reasons(report):
        rule = reason.get("rule")
        if rule == "risk_path_touched" and reason.get("path"):
            return f"{trust_policy} - touched {reason.get('path')}"
        if rule == "untrusted_signer":
            return f"{trust_policy} - untrusted signer"
        if rule == "required_check_failed":
            return f"{trust_policy} - required check \"{reason.get('check')}\" failed"
        if rule == "required_check_missing":
            return f"{trust_policy} - {_missing_check_summary(reason)}"
        if rule == "integrity_failed":
            return f"{trust_policy} - integrity failed"
    return str(trust_policy)


def _missing_check_summary(reason: Mapping[str, Any]) -> str:
    check = reason.get("check")
    status = reason.get("observation_status")
    if status == "OBSERVED_PENDING":
        return f"required check \"{check}\" is still pending"
    if status == "NAME_MISMATCH_POSSIBLE":
        observed = reason.get("observed_check_names")
        if isinstance(observed, list) and observed:
            names = ", ".join(f'"{name}"' for name in observed if isinstance(name, str))
            if names:
                return (
                    f"required check \"{check}\" was not observed; "
                    f"observed checks used other names: {names}"
                )
        return (
            f"required check \"{check}\" was not observed; "
            "observed checks used other names"
        )
    return f"required check \"{check}\" was not observed yet"


def _evidence_ref(report: Mapping[str, Any], kind: str, default: str) -> str:
    refs = report.get("evidence_refs") or []
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, Mapping) and ref.get("kind") == kind:
                path = ref.get("path")
                if isinstance(path, str) and path:
                    return path
    return default


def _do_not_infer(report: Mapping[str, Any]) -> List[str]:
    raw = report.get("do_not_infer")
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return list(raw)
    return list(DO_NOT_INFER)


def _expected_identity(report: Mapping[str, Any]) -> str:
    signature_policy = _mapping(
        report.get("signature_policy"), "report.signature_policy"
    )
    return _string(
        signature_policy.get("expected_certificate_identity"),
        "report.signature_policy.expected_certificate_identity",
    )


def _reasons(report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    raw = report.get("reasons") or []
    if not isinstance(raw, list):
        raise CommentRenderError("report.reasons must be a list")
    reasons: List[Mapping[str, Any]] = []
    for index, reason in enumerate(raw):
        if not isinstance(reason, Mapping):
            raise CommentRenderError(f"report.reasons[{index}] must be a mapping")
        reasons.append(reason)
    return reasons


def _load_optional_evidence(pack_manifest_path: Path) -> Dict[str, Any]:
    evidence_path = pack_manifest_path.parent / "pr_gate_evidence.json"
    if not evidence_path.exists():
        return {}
    return _load_json_object(evidence_path, "PR Gate evidence")


def _load_json_object(path: Path, label: str) -> Dict[str, Any]:
    if not path.exists():
        raise CommentRenderError(f"{label} not found: {path}")
    if not path.is_file():
        raise CommentRenderError(f"{label} path is not a file: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CommentRenderError(f"failed to parse {label} JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CommentRenderError(f"{label} must be a JSON object")
    return raw


def _mapping(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise CommentRenderError(f"{label} must be a mapping")
    return raw


def _string(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise CommentRenderError(f"{label} must be a non-empty string")
    return raw


__all__ = [
    "CommentRenderError",
    "render_pr_gate_comment",
    "render_pr_gate_comment_files",
]
