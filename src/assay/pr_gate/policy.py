"""Deterministic policy evaluator for Assay PR Gate v0."""
from __future__ import annotations

import fnmatch
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from assay._receipts.jcs import canonicalize as jcs_canonicalize

DECISIONS = frozenset({"PASS", "NEEDS_REVIEW", "BLOCK", "ERROR"})
RECOMMENDED_ACTIONS = frozenset(
    {
        "proceed",
        "require_human_approval",
        "request_codeowner_review",
        "rerun_required_check",
        "block_missing_evidence",
        "block_required_check_failed",
        "block_integrity_failed",
        "block_untrusted_signer",
        "manual_triage",
    }
)
CHECK_OBSERVATION_STATUSES = frozenset(
    {
        "OBSERVED_PASS",
        "OBSERVED_FAIL",
        "OBSERVED_PENDING",
        "NOT_OBSERVED_YET",
        "NAME_MISMATCH_POSSIBLE",
    }
)
CLAIM_GATE_REPORT_SCHEMA_VERSION = "assay.claim_gate_report.v0"
CLAIM_GATE_REPORT_COMMAND = "assay claim-gate diff"
CLAIM_GATE_VERDICTS = frozenset({"PASS", "NEEDS_REVIEW", "BLOCK"})

RULE_ORDER = (
    "integrity_failed",
    "untrusted_signer",
    "required_check_failed",
    "required_check_missing",
    "risk_path_touched",
)

SUCCESSFUL_CHECK_CONCLUSIONS = frozenset({"success"})


class PolicyEvaluationError(ValueError):
    """Raised when PR Gate evidence or policy cannot be evaluated safely."""


def load_policy(path: Path) -> Dict[str, Any]:
    """Load a PR Gate policy YAML file as a mapping."""
    try:
        import yaml
    except ImportError as exc:
        raise PolicyEvaluationError(
            "PyYAML is required to load PR Gate policy files"
        ) from exc

    if not path.exists():
        raise PolicyEvaluationError(f"Policy file not found: {path}")
    if not path.is_file():
        raise PolicyEvaluationError(f"Policy path is not a file: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyEvaluationError(f"Failed to parse policy file: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyEvaluationError(
            f"Policy file must be a YAML mapping, got {type(raw).__name__}"
        )
    validate_policy(raw)
    return raw


def load_evidence(path: Path) -> Dict[str, Any]:
    """Load a PR Gate evidence JSON file as a mapping."""
    if not path.exists():
        raise PolicyEvaluationError(f"Evidence file not found: {path}")
    if not path.is_file():
        raise PolicyEvaluationError(f"Evidence path is not a file: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyEvaluationError(f"Failed to parse evidence JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyEvaluationError(
            f"Evidence file must be a JSON object, got {type(raw).__name__}"
        )
    return raw


def compute_policy_sha256(policy: Mapping[str, Any]) -> str:
    """Return the PR Gate policy hash as sha256:<hex> over JCS canonical JSON."""
    return "sha256:" + hashlib.sha256(jcs_canonicalize(policy)).hexdigest()


def validate_policy(policy: Mapping[str, Any]) -> None:
    """Validate the v0 policy profile and fixed enum surface."""
    profile = policy.get("profile")
    if profile != "coding_pr_v0":
        raise PolicyEvaluationError(
            f"Unsupported PR Gate policy profile: {profile!r}"
        )

    _string_list(policy, "risk_paths")
    _string_list(policy, "required_checks")

    rules = _mapping(policy.get("rules"), "rules")
    for rule in RULE_ORDER:
        if rule not in rules:
            raise PolicyEvaluationError(f"Policy missing rule: {rule}")
        _validate_decision_spec(rules[rule], f"rules.{rule}")

    _validate_decision_spec(policy.get("default"), "default")


def evaluate_policy(
    evidence: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    integrity_status: Optional[str] = None,
    signer_trusted: Optional[bool] = None,
) -> Dict[str, Any]:
    """Evaluate PR evidence against a PR Gate policy.

    The result shape matches the v0 product contract:
    overall decision, stable recommended action, deterministic reasons, and
    verdict channels.
    """
    validate_policy(policy)

    changed_files = _changed_file_paths(evidence)
    observed_checks = _observed_checks(evidence)
    required_checks = _string_list(policy, "required_checks")
    risk_paths = _string_list(policy, "risk_paths")
    head_sha = _subject_head_sha(evidence)
    rules = _mapping(policy["rules"], "rules")

    reasons_by_rule: Dict[str, List[Dict[str, Any]]] = {
        rule: [] for rule in RULE_ORDER
    }

    integrity = _resolve_integrity_status(evidence, integrity_status)
    if integrity != "PASS":
        reasons_by_rule["integrity_failed"].append(
            {"rule": "integrity_failed", "integrity": integrity}
        )

    trusted = _resolve_signer_trusted(evidence, signer_trusted)
    if trusted is False:
        reasons_by_rule["untrusted_signer"].append(
            {"rule": "untrusted_signer"}
        )

    check_outcomes = _required_check_outcomes(
        required_checks=required_checks,
        observed_checks=observed_checks,
        head_sha=head_sha,
    )
    claim_gate_report = _claim_gate_report(evidence)
    claim_gate_verdict = _claim_gate_verdict(claim_gate_report)
    claim_gate_reasons = _claim_gate_reasons(claim_gate_report)
    for outcome in check_outcomes:
        status = str(outcome["status"])
        if status == "OBSERVED_FAIL":
            reasons_by_rule["required_check_failed"].append(
                _required_check_failed_reason(outcome, head_sha)
            )
        elif status in {
            "OBSERVED_PENDING",
            "NOT_OBSERVED_YET",
            "NAME_MISMATCH_POSSIBLE",
        }:
            reason: Dict[str, Any] = {
                "rule": "required_check_missing",
                "check": outcome["name"],
                "observation_status": status,
            }
            if head_sha:
                reason["head_sha"] = head_sha
            observed_names = outcome.get("observed_check_names")
            if observed_names:
                reason["observed_check_names"] = observed_names
            reasons_by_rule["required_check_missing"].append(reason)

    for path, matched_pattern in _risk_path_matches(changed_files, risk_paths):
        reasons_by_rule["risk_path_touched"].append(
            {
                "rule": "risk_path_touched",
                "path": path,
                "matched_pattern": matched_pattern,
            }
        )

    reasons = _ordered_reasons(reasons_by_rule, claim_gate_reasons)
    selected_rule = _selected_rule(reasons_by_rule)

    # Rule-based outcomes take priority: they cover every BLOCK case and the
    # existing NEEDS_REVIEW cases. A claim_gate FAIL only escalates the
    # top-level decision when no rule already fired, so the gate never
    # recommends "proceed" while the Claim channel reads FAIL.
    #
    # v0 escalation: claim_gate BLOCK and NEEDS_REVIEW both route to
    # NEEDS_REVIEW (human review), not a hard merge block. Whether claim_gate
    # BLOCK should hard-BLOCK is a separate, later decision.
    if selected_rule is not None:
        spec = _mapping(rules[selected_rule], f"rules.{selected_rule}")
        overall_decision = str(spec["decision"])
        recommended_action = str(spec["recommended_action"])
    elif claim_gate_verdict in {"BLOCK", "NEEDS_REVIEW"}:
        overall_decision = "NEEDS_REVIEW"
        recommended_action = "require_human_approval"
    else:
        default = _mapping(policy["default"], "default")
        overall_decision = str(default["decision"])
        recommended_action = str(default["recommended_action"])

    return {
        "overall_decision": overall_decision,
        "recommended_action": recommended_action,
        "reasons": reasons,
        "check_observations": check_outcomes,
        "channels": {
            "integrity": "PASS" if integrity == "PASS" else "FAIL",
            "claim": _claim_channel(claim_gate_verdict),
            "replay": "NOT_RUN",
            "trust_policy": _trust_policy_channel(reasons_by_rule),
        },
    }


def evaluate_policy_files(
    evidence_path: Path,
    policy_path: Path,
    *,
    out_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Evaluate evidence and policy files, optionally writing decision JSON."""
    decision = evaluate_policy(load_evidence(evidence_path), load_policy(policy_path))
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(decision, indent=2) + "\n",
            encoding="utf-8",
        )
    return decision


def _validate_decision_spec(raw: Any, label: str) -> None:
    spec = _mapping(raw, label)
    decision = spec.get("decision")
    action = spec.get("recommended_action")
    if decision not in DECISIONS:
        raise PolicyEvaluationError(
            f"{label}.decision must be one of {sorted(DECISIONS)}, got {decision!r}"
        )
    if action not in RECOMMENDED_ACTIONS:
        raise PolicyEvaluationError(
            f"{label}.recommended_action must be one of "
            f"{sorted(RECOMMENDED_ACTIONS)}, got {action!r}"
        )


def _mapping(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise PolicyEvaluationError(
            f"{label} must be a mapping, got {type(raw).__name__}"
        )
    return raw


def _string_list(mapping: Mapping[str, Any], key: str) -> List[str]:
    raw = mapping.get(key)
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PolicyEvaluationError(f"{key} must be a list of strings")
    return list(raw)


def _changed_file_paths(evidence: Mapping[str, Any]) -> List[str]:
    raw_files = evidence.get("changed_files") or []
    if not isinstance(raw_files, list):
        raise PolicyEvaluationError("changed_files must be a list")

    paths: List[str] = []
    for index, entry in enumerate(raw_files):
        if isinstance(entry, str):
            path = entry
        elif isinstance(entry, Mapping):
            raw_path = entry.get("path")
            if not isinstance(raw_path, str):
                raise PolicyEvaluationError(
                    f"changed_files[{index}].path must be a string"
                )
            path = raw_path
        else:
            raise PolicyEvaluationError(
                f"changed_files[{index}] must be a string or mapping"
            )
        paths.append(path)
    return sorted(paths)


def _observed_checks(evidence: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    raw_checks = evidence.get("observed_checks") or []
    if not isinstance(raw_checks, list):
        raise PolicyEvaluationError("observed_checks must be a list")

    checks: List[Mapping[str, Any]] = []
    for index, check in enumerate(raw_checks):
        if not isinstance(check, Mapping):
            raise PolicyEvaluationError(
                f"observed_checks[{index}] must be a mapping"
            )
        if not isinstance(check.get("name"), str):
            raise PolicyEvaluationError(
                f"observed_checks[{index}].name must be a string"
            )
        checks.append(check)
    return checks


def _subject_head_sha(evidence: Mapping[str, Any]) -> Optional[str]:
    subject = evidence.get("subject")
    if isinstance(subject, Mapping):
        head_sha = subject.get("head_sha")
        if isinstance(head_sha, str) and head_sha:
            return head_sha
    head_sha = evidence.get("head_sha")
    if isinstance(head_sha, str) and head_sha:
        return head_sha
    return None


def _resolve_integrity_status(
    evidence: Mapping[str, Any], override: Optional[str]
) -> str:
    raw: Any = override
    if raw is None:
        raw = evidence.get("integrity_status")
    if raw is None and isinstance(evidence.get("integrity"), Mapping):
        raw = evidence["integrity"].get("status")  # type: ignore[index]
    if raw is None and isinstance(evidence.get("channels"), Mapping):
        raw = evidence["channels"].get("integrity")  # type: ignore[index]
    if raw is None:
        return "PASS"
    if raw is True:
        return "PASS"
    if raw is False:
        return "FAIL"
    text = str(raw).upper()
    if text in {"PASS", "PASSED", "OK", "VALID", "INTACT"}:
        return "PASS"
    return text or "FAIL"


def _resolve_signer_trusted(
    evidence: Mapping[str, Any], override: Optional[bool]
) -> Optional[bool]:
    if override is not None:
        return override

    raw: Any = evidence.get("signer_trusted")
    if raw is None and isinstance(evidence.get("signer"), Mapping):
        raw = evidence["signer"].get("trusted")  # type: ignore[index]
    if raw is None and isinstance(evidence.get("trust"), Mapping):
        raw = evidence["trust"].get("signer_trusted")  # type: ignore[index]
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in {"true", "yes", "trusted", "pass"}:
            return True
        if normalized in {"false", "no", "untrusted", "block", "fail"}:
            return False
    raise PolicyEvaluationError("signer_trusted must be a boolean")


def _required_check_outcomes(
    *,
    required_checks: Iterable[str],
    observed_checks: List[Mapping[str, Any]],
    head_sha: Optional[str],
) -> List[Dict[str, Any]]:
    outcomes: List[Dict[str, Any]] = []
    observed_names = _observed_check_names(observed_checks, head_sha)
    for check_name in sorted(required_checks):
        candidates = _matching_checks(check_name, observed_checks, head_sha)
        if not candidates:
            status = (
                "NAME_MISMATCH_POSSIBLE"
                if observed_names
                else "NOT_OBSERVED_YET"
            )
            outcome: Dict[str, Any] = {"name": check_name, "status": status}
            if head_sha:
                outcome["head_sha"] = head_sha
            if observed_names:
                outcome["observed_check_names"] = observed_names
            outcomes.append(outcome)
            continue

        concluded = [
            check
            for check in candidates
            if isinstance(check.get("conclusion"), str) and check.get("conclusion")
        ]
        if not concluded:
            check = _sort_checks(candidates)[0]
            outcome = {"name": check_name, "status": "OBSERVED_PENDING"}
            if head_sha:
                outcome["head_sha"] = head_sha
            observed_at = check.get("observed_at")
            if isinstance(observed_at, str) and observed_at:
                outcome["observed_at"] = observed_at
            outcomes.append(outcome)
            continue

        failed = [
            check
            for check in concluded
            if str(check["conclusion"]).lower() not in SUCCESSFUL_CHECK_CONCLUSIONS
        ]
        if failed:
            outcomes.append(
                _check_observation(
                    check_name,
                    "OBSERVED_FAIL",
                    _sort_checks(failed)[0],
                    head_sha,
                )
            )
        else:
            outcomes.append(
                _check_observation(
                    check_name,
                    "OBSERVED_PASS",
                    _sort_checks(concluded)[0],
                    head_sha,
                )
            )
    return outcomes


def _observed_check_names(
    observed_checks: List[Mapping[str, Any]], head_sha: Optional[str]
) -> List[str]:
    names = set()
    for check in observed_checks:
        check_head = check.get("head_sha")
        if head_sha and check_head != head_sha:
            continue
        name = check.get("name")
        if isinstance(name, str) and name:
            names.add(name)
    return sorted(names)


def _check_observation(
    check_name: str,
    status: str,
    check: Mapping[str, Any],
    head_sha: Optional[str],
) -> Dict[str, Any]:
    observation: Dict[str, Any] = {"name": check_name, "status": status}
    check_head = check.get("head_sha")
    if isinstance(check_head, str) and check_head:
        observation["head_sha"] = check_head
    elif head_sha:
        observation["head_sha"] = head_sha
    conclusion = check.get("conclusion")
    if isinstance(conclusion, str) and conclusion:
        observation["conclusion"] = conclusion
    observed_at = check.get("observed_at")
    if isinstance(observed_at, str) and observed_at:
        observation["observed_at"] = observed_at
    return observation


def _matching_checks(
    check_name: str,
    observed_checks: List[Mapping[str, Any]],
    head_sha: Optional[str],
) -> List[Mapping[str, Any]]:
    matches: List[Mapping[str, Any]] = []
    for check in observed_checks:
        if check.get("name") != check_name:
            continue
        check_head = check.get("head_sha")
        if head_sha and check_head != head_sha:
            continue
        matches.append(check)
    return _sort_checks(matches)


def _sort_checks(checks: List[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    return sorted(
        checks,
        key=lambda check: (
            str(check.get("observed_at") or ""),
            str(check.get("name") or ""),
            str(check.get("head_sha") or ""),
            str(check.get("conclusion") or ""),
        ),
    )


def _required_check_failed_reason(
    outcome: Mapping[str, Any],
    head_sha: Optional[str],
) -> Dict[str, Any]:
    reason: Dict[str, Any] = {
        "rule": "required_check_failed",
        "check": outcome["name"],
        "conclusion": str(outcome.get("conclusion") or "unknown"),
        "observation_status": str(outcome.get("status") or "OBSERVED_FAIL"),
    }
    check_head = outcome.get("head_sha")
    if isinstance(check_head, str) and check_head:
        reason["head_sha"] = check_head
    elif head_sha:
        reason["head_sha"] = head_sha
    return reason


def _risk_path_matches(
    changed_files: List[str], risk_paths: List[str]
) -> List[Tuple[str, str]]:
    matches: List[Tuple[str, str]] = []
    for path in changed_files:
        for pattern in risk_paths:
            if fnmatch.fnmatchcase(path, pattern):
                matches.append((path, pattern))
                break
    return matches


def _ordered_reasons(
    reasons_by_rule: Mapping[str, List[Dict[str, Any]]],
    claim_gate_reasons: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    reasons: List[Dict[str, Any]] = []
    for rule in RULE_ORDER:
        reasons.extend(reasons_by_rule[rule])
        if rule == "required_check_failed":
            reasons.extend(claim_gate_reasons or [])
    return reasons


def _selected_rule(
    reasons_by_rule: Mapping[str, List[Dict[str, Any]]]
) -> Optional[str]:
    for rule in RULE_ORDER:
        if reasons_by_rule[rule]:
            return rule
    return None


def _claim_gate_report(evidence: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    raw = evidence.get("claim_gate_report")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise PolicyEvaluationError("claim_gate_report must be a mapping")
    if raw.get("schema_version") != CLAIM_GATE_REPORT_SCHEMA_VERSION:
        raise PolicyEvaluationError(
            "claim_gate_report schema_version is not assay.claim_gate_report.v0"
        )
    if raw.get("command") != CLAIM_GATE_REPORT_COMMAND:
        raise PolicyEvaluationError(
            "claim_gate_report command is not assay claim-gate diff"
        )
    return raw


def _claim_gate_verdict(report: Optional[Mapping[str, Any]]) -> Optional[str]:
    if report is None:
        return None
    verdict = report.get("verdict")
    if verdict not in CLAIM_GATE_VERDICTS:
        raise PolicyEvaluationError(
            f"claim_gate_report.verdict must be one of "
            f"{sorted(CLAIM_GATE_VERDICTS)}, got {verdict!r}"
        )
    return str(verdict)


def _claim_gate_reasons(
    report: Optional[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    verdict = _claim_gate_verdict(report)
    if report is None or verdict == "PASS":
        return []
    transitions = report.get("transitions")
    if transitions is None:
        transitions = []
    if not isinstance(transitions, list):
        raise PolicyEvaluationError("claim_gate_report.transitions must be a list")

    reasons: List[Dict[str, Any]] = []
    included_verdicts = {"BLOCK"} if verdict == "BLOCK" else {"NEEDS_REVIEW"}
    for transition in transitions:
        if not isinstance(transition, Mapping):
            raise PolicyEvaluationError(
                "claim_gate_report.transitions entries must be mappings"
            )
        transition_verdict = transition.get("verdict")
        if transition_verdict not in included_verdicts:
            continue
        evidence_required = _string_list_value(
            transition.get("evidence_required"), "claim_gate_report.evidence_required"
        )
        evidence_found = _string_list_value(
            transition.get("evidence_found", []), "claim_gate_report.evidence_found"
        )
        missing_evidence = [
            item for item in evidence_required if item not in set(evidence_found)
        ]
        rule = (
            "claim_gate_block"
            if transition_verdict == "BLOCK"
            else "claim_gate_needs_review"
        )
        reason: Dict[str, Any] = {
            "rule": rule,
            "claim_gate_verdict": verdict,
            "transition_verdict": str(transition_verdict),
            "transition_class": str(transition.get("transition_class") or "unknown"),
            "missing_evidence": missing_evidence,
        }
        for key in ("id", "file", "severity"):
            value = transition.get(key)
            if isinstance(value, str) and value:
                reason[key] = value
        reasons.append(reason)

    if reasons:
        return reasons

    return [
        {
            "rule": "claim_gate_block"
            if verdict == "BLOCK"
            else "claim_gate_needs_review",
            "claim_gate_verdict": verdict,
        }
    ]


def _string_list_value(raw: Any, label: str) -> List[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PolicyEvaluationError(f"{label} must be a list of strings")
    return list(raw)


def _claim_channel(claim_gate_verdict: Optional[str]) -> str:
    if claim_gate_verdict == "PASS":
        return "PASS"
    if claim_gate_verdict in {"NEEDS_REVIEW", "BLOCK"}:
        return "FAIL"
    return "NOT_EVALUATED"


def _trust_policy_channel(
    reasons_by_rule: Mapping[str, List[Dict[str, Any]]]
) -> str:
    if (
        reasons_by_rule["integrity_failed"]
        or reasons_by_rule["untrusted_signer"]
        or reasons_by_rule["required_check_failed"]
    ):
        return "BLOCK"
    if reasons_by_rule["required_check_missing"] or reasons_by_rule["risk_path_touched"]:
        return "NEEDS_REVIEW"
    return "PASS"


__all__ = [
    "DECISIONS",
    "CHECK_OBSERVATION_STATUSES",
    "CLAIM_GATE_REPORT_COMMAND",
    "CLAIM_GATE_REPORT_SCHEMA_VERSION",
    "CLAIM_GATE_VERDICTS",
    "RECOMMENDED_ACTIONS",
    "RULE_ORDER",
    "PolicyEvaluationError",
    "compute_policy_sha256",
    "evaluate_policy",
    "evaluate_policy_files",
    "load_evidence",
    "load_policy",
    "validate_policy",
]
