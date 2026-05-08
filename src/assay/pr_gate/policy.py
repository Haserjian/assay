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
    for check_name, outcome, check in check_outcomes:
        if outcome == "failed":
            reasons_by_rule["required_check_failed"].append(
                _required_check_failed_reason(check_name, check, head_sha)
            )
        elif outcome == "missing":
            reason: Dict[str, Any] = {
                "rule": "required_check_missing",
                "check": check_name,
            }
            if head_sha:
                reason["head_sha"] = head_sha
            reasons_by_rule["required_check_missing"].append(reason)

    for path, matched_pattern in _risk_path_matches(changed_files, risk_paths):
        reasons_by_rule["risk_path_touched"].append(
            {
                "rule": "risk_path_touched",
                "path": path,
                "matched_pattern": matched_pattern,
            }
        )

    reasons = _ordered_reasons(reasons_by_rule)
    selected_rule = _selected_rule(reasons_by_rule)

    if selected_rule is None:
        default = _mapping(policy["default"], "default")
        overall_decision = str(default["decision"])
        recommended_action = str(default["recommended_action"])
    else:
        spec = _mapping(rules[selected_rule], f"rules.{selected_rule}")
        overall_decision = str(spec["decision"])
        recommended_action = str(spec["recommended_action"])

    return {
        "overall_decision": overall_decision,
        "recommended_action": recommended_action,
        "reasons": reasons,
        "channels": {
            "integrity": "PASS" if integrity == "PASS" else "FAIL",
            "claim": _claim_channel(check_outcomes),
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
) -> List[Tuple[str, str, Optional[Mapping[str, Any]]]]:
    outcomes: List[Tuple[str, str, Optional[Mapping[str, Any]]]] = []
    for check_name in sorted(required_checks):
        candidates = _matching_checks(check_name, observed_checks, head_sha)
        if not candidates:
            outcomes.append((check_name, "missing", None))
            continue

        concluded = [
            check
            for check in candidates
            if isinstance(check.get("conclusion"), str) and check.get("conclusion")
        ]
        if not concluded:
            outcomes.append((check_name, "missing", None))
            continue

        failed = [
            check
            for check in concluded
            if str(check["conclusion"]).lower() not in SUCCESSFUL_CHECK_CONCLUSIONS
        ]
        if failed:
            outcomes.append((check_name, "failed", _sort_checks(failed)[0]))
        else:
            outcomes.append((check_name, "passed", _sort_checks(concluded)[0]))
    return outcomes


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
    check_name: str,
    check: Optional[Mapping[str, Any]],
    head_sha: Optional[str],
) -> Dict[str, Any]:
    reason: Dict[str, Any] = {
        "rule": "required_check_failed",
        "check": check_name,
        "conclusion": str((check or {}).get("conclusion") or "unknown"),
    }
    check_head = (check or {}).get("head_sha")
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
    reasons_by_rule: Mapping[str, List[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    reasons: List[Dict[str, Any]] = []
    for rule in RULE_ORDER:
        reasons.extend(reasons_by_rule[rule])
    return reasons


def _selected_rule(
    reasons_by_rule: Mapping[str, List[Dict[str, Any]]]
) -> Optional[str]:
    for rule in RULE_ORDER:
        if reasons_by_rule[rule]:
            return rule
    return None


def _claim_channel(
    check_outcomes: List[Tuple[str, str, Optional[Mapping[str, Any]]]]
) -> str:
    outcomes = {outcome for _, outcome, _ in check_outcomes}
    if "failed" in outcomes:
        return "FAIL"
    if "missing" in outcomes:
        return "NOT_EVALUATED"
    if "passed" in outcomes:
        return "PASS"
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
