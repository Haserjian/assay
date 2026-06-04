"""Policy loading and evaluation for Assay Claim Gate."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping

from assay.claim_gate.detectors import DEFAULT_ALLOW_MARKERS
from assay.claim_gate.models import (
    BLOCK,
    NEEDS_REVIEW,
    PASS,
    VERDICTS,
    ClaimBoundaryTransition,
)


SCHEMA_VERSION = "assay.claim_policy.v0"


class ClaimGatePolicyError(ValueError):
    """Raised when a Claim Gate policy is malformed."""


@dataclass(frozen=True)
class PolicyRule:
    transition_class: str
    verdict: str
    severity: str = "medium"
    requires: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ClaimGatePolicy:
    schema_version: str
    default_verdict: str
    blocked_transitions: Dict[str, PolicyRule]
    review_transitions: Dict[str, PolicyRule]
    allow_markers: List[str]
    evidence_paths: Dict[str, List[str]]

    def rule_for(self, transition_class: str) -> PolicyRule:
        if transition_class in self.blocked_transitions:
            return self.blocked_transitions[transition_class]
        if transition_class in self.review_transitions:
            return self.review_transitions[transition_class]
        return PolicyRule(
            transition_class=transition_class,
            verdict=self.default_verdict,
            severity="medium",
            requires=[],
        )


def load_policy(path: Path) -> ClaimGatePolicy:
    """Load an assay.claims.yml policy file."""
    try:
        import yaml
    except ImportError as exc:
        raise ClaimGatePolicyError("PyYAML is required to load Claim Gate policy") from exc

    if not path.exists():
        raise ClaimGatePolicyError(f"Policy file not found: {path}")
    if not path.is_file():
        raise ClaimGatePolicyError(f"Policy path is not a file: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ClaimGatePolicyError(f"Failed to parse policy file: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ClaimGatePolicyError("Policy file must be a YAML mapping")
    return parse_policy(raw)


def parse_policy(raw: Mapping[str, Any]) -> ClaimGatePolicy:
    """Parse and validate a Claim Gate policy mapping."""
    schema_version = str(raw.get("schema_version", ""))
    if schema_version != SCHEMA_VERSION:
        raise ClaimGatePolicyError(
            f"Unsupported Claim Gate policy schema_version: {schema_version!r}"
        )

    default_verdict = str(raw.get("default_verdict", NEEDS_REVIEW))
    _validate_verdict(default_verdict, "default_verdict")

    blocked = _parse_rules(raw.get("blocked_transitions") or {}, BLOCK)
    review = _parse_rules(raw.get("review_transitions") or {}, NEEDS_REVIEW)
    allow_markers = _string_list(
        raw.get("allow_markers") or list(DEFAULT_ALLOW_MARKERS),
        "allow_markers",
    )
    evidence_paths = _parse_evidence_paths(raw.get("evidence_paths") or {})

    return ClaimGatePolicy(
        schema_version=schema_version,
        default_verdict=default_verdict,
        blocked_transitions=blocked,
        review_transitions=review,
        allow_markers=allow_markers,
        evidence_paths=evidence_paths,
    )


def apply_policy(
    transitions: List[ClaimBoundaryTransition],
    policy: ClaimGatePolicy,
    evidence_index: Mapping[str, List[str]],
) -> List[ClaimBoundaryTransition]:
    """Attach policy verdicts and evidence findings to detected transitions."""
    evaluated: List[ClaimBoundaryTransition] = []
    for transition in transitions:
        rule = policy.rule_for(transition.transition_class)
        evidence_required = list(rule.requires)
        evidence_found = _evidence_found_for(evidence_required, evidence_index)
        verdict = _verdict_for(rule, evidence_required, evidence_found)
        evaluated.append(
            transition.with_policy(
                evidence_required=evidence_required,
                evidence_found=evidence_found,
                verdict=verdict,
                severity=rule.severity or transition.severity,
            )
        )
    return evaluated


def _verdict_for(
    rule: PolicyRule, evidence_required: List[str], evidence_found: List[str]
) -> str:
    if not evidence_required:
        return rule.verdict
    found_requirements = {
        item.split(":", 1)[0] for item in evidence_found if ":" in item
    }
    missing = [req for req in evidence_required if req not in found_requirements]
    if missing:
        return rule.verdict
    return PASS


def _evidence_found_for(
    evidence_required: List[str], evidence_index: Mapping[str, List[str]]
) -> List[str]:
    found: List[str] = []
    for requirement in evidence_required:
        for path in evidence_index.get(requirement, []):
            found.append(f"{requirement}:{path}")
    return sorted(dict.fromkeys(found))


def _parse_rules(raw: Any, default_verdict: str) -> Dict[str, PolicyRule]:
    if not isinstance(raw, Mapping):
        raise ClaimGatePolicyError("transition rules must be a mapping")
    parsed: Dict[str, PolicyRule] = {}
    for transition_class, spec in raw.items():
        if not isinstance(transition_class, str) or not transition_class:
            raise ClaimGatePolicyError("transition class names must be non-empty strings")
        if not isinstance(spec, Mapping):
            raise ClaimGatePolicyError(f"{transition_class} must be a mapping")
        verdict = str(spec.get("verdict", default_verdict))
        _validate_verdict(verdict, f"{transition_class}.verdict")
        severity = str(spec.get("severity", "medium"))
        requires = _string_list(
            spec.get("requires") or [],
            f"{transition_class}.requires",
        )
        parsed[transition_class] = PolicyRule(
            transition_class=transition_class,
            verdict=verdict,
            severity=severity,
            requires=requires,
        )
    return parsed


def _parse_evidence_paths(raw: Any) -> Dict[str, List[str]]:
    if not isinstance(raw, Mapping):
        raise ClaimGatePolicyError("evidence_paths must be a mapping")
    parsed: Dict[str, List[str]] = {}
    for requirement, patterns in raw.items():
        if not isinstance(requirement, str) or not requirement:
            raise ClaimGatePolicyError("evidence requirement names must be strings")
        if isinstance(patterns, str):
            parsed[requirement] = [patterns]
        else:
            parsed[requirement] = _string_list(
                patterns,
                f"evidence_paths.{requirement}",
            )
    return parsed


def _validate_verdict(value: str, label: str) -> None:
    if value not in VERDICTS:
        raise ClaimGatePolicyError(
            f"{label} must be one of {sorted(VERDICTS)}, got {value!r}"
        )


def _string_list(raw: Any, label: str) -> List[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ClaimGatePolicyError(f"{label} must be a list of strings")
    return list(raw)
