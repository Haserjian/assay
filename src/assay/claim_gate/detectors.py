"""Rule-based claim-boundary transition detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from assay.claim_gate.models import (
    ClaimBoundaryTransition,
    DiffPair,
    NonClaim,
    TextSpan,
)

DEFAULT_ALLOW_MARKERS = (
    "draft",
    "future work",
    "future goal",
    "goal:",
    "hypothesis",
    "roadmap",
    "exploring",
    "proposal",
    "aspiration",
)


GENERIC_BOUNDARY_MARKERS = {"prototype", "experimental"}

HARD_CLAIM_TERMS = (
    "approved",
    "guarantee",
    "guarantees",
    "guaranteed",
    "must",
    "policy",
    "production-ready",
    "production ready",
    "proven",
    "proves",
    "safe",
    "validated",
    "verified",
)


@dataclass(frozen=True)
class DetectorSpec:
    transition_class: str
    before_terms: Tuple[str, ...]
    after_terms: Tuple[str, ...]
    severity: str
    confidence: float
    rationale: str
    suggested_rewrite: str


DETECTOR_SPECS: Tuple[DetectorSpec, ...] = (
    DetectorSpec(
        "prototype_to_production",
        ("prototype", "experimental", "draft", "demo"),
        (
            "production-ready",
            "production ready",
            "production-grade",
            "production grade",
        ),
        "high",
        0.93,
        "The text moves from prototype or experimental language to production readiness.",
        "Frame this as a prototype or production-oriented exploration until deployment evidence is present.",
    ),
    DetectorSpec(
        "experimental_to_reliable",
        ("experimental", "prototype", "early"),
        ("reliable", "robust", "stable", "dependable"),
        "medium",
        0.82,
        "The text moves from experimental posture to reliability language.",
        "Keep reliability claims scoped to the evidence actually present.",
    ),
    DetectorSpec(
        "possible_to_guaranteed",
        ("possible", "may", "might", "could", "potentially"),
        ("guarantee", "guarantees", "guaranteed", "ensures", "always"),
        "high",
        0.9,
        "The text moves from possibility language to a guarantee.",
        "Use possibility language unless direct evidence supports the guarantee.",
    ),
    DetectorSpec(
        "may_might_could_to_does_will",
        ("may", "might", "could"),
        ("does", "will", "is now", "now provides"),
        "medium",
        0.76,
        "The text upgrades a conditional claim into an asserted behavior.",
        "Keep the behavior conditional or cite evidence for the stronger assertion.",
    ),
    DetectorSpec(
        "local_to_general",
        ("local", "locally", "single", "one configured", "one test"),
        ("all", "every", "general", "generally", "always", "any environment", "across"),
        "medium",
        0.82,
        "The text generalizes a local observation beyond its observed scope.",
        "State the local scope unless broader reproducibility evidence is present.",
    ),
    DetectorSpec(
        "demo_to_enterprise",
        ("demo", "sample", "toy"),
        ("enterprise", "organization-wide", "company-wide", "production"),
        "medium",
        0.8,
        "The text upgrades a demo or sample into enterprise or production scope.",
        "Keep the claim in demo scope until deployment evidence exists.",
    ),
    DetectorSpec(
        "suggestion_to_recommendation",
        ("suggestion", "suggested", "idea", "option"),
        ("recommend", "recommends", "recommendation", "should"),
        "medium",
        0.78,
        "The text upgrades an idea or suggestion into a recommendation.",
        "Keep the suggestion advisory unless review evidence supports recommending it.",
    ),
    DetectorSpec(
        "recommendation_to_policy",
        ("recommend", "recommendation", "guidance", "should"),
        ("policy", "must", "required", "approved"),
        "high",
        0.86,
        "The text upgrades guidance into policy or approval language.",
        "Keep policy language out unless a policy review or human acceptance is present.",
    ),
    DetectorSpec(
        "partial_support_to_proven",
        ("partial", "limited", "supports", "some evidence", "early evidence"),
        ("proves", "proven", "validated", "verified", "confirms"),
        "high",
        0.86,
        "The text upgrades partial support into proof or validation.",
        "Use bounded support language unless proof evidence is present.",
    ),
    DetectorSpec(
        "risk_reduced_to_safe",
        ("risk reduced", "reduced risk", "reduces risk", "safer", "mitigates"),
        ("safe", "safety guarantee", "hazard-free", "risk-free"),
        "high",
        0.9,
        "The text upgrades risk reduction into safety.",
        "Say risk was reduced or mitigated, not that the system is safe.",
    ),
    DetectorSpec(
        "observed_to_causal",
        ("observed", "correlated", "appeared", "associated"),
        ("caused", "causes", "because", "led to"),
        "medium",
        0.78,
        "The text upgrades observation or correlation into causality.",
        "Keep the observation descriptive unless causal evidence is present.",
    ),
)


def detect_transitions(
    pair: DiffPair, *, allow_markers: Sequence[str] = DEFAULT_ALLOW_MARKERS
) -> Tuple[List[ClaimBoundaryTransition], List[NonClaim]]:
    """Detect claim-boundary transitions for one before/after pair."""
    before = pair.before_span.text
    after = pair.after_span.text
    if not after.strip():
        return [], []

    transitions: List[ClaimBoundaryTransition] = []
    non_claims: List[NonClaim] = []

    for after_line in _line_spans(pair.after_span):
        non_claim = _non_claim(after_line, allow_markers)
        if non_claim is not None:
            non_claims.append(non_claim)
            continue
        for spec in DETECTOR_SPECS:
            if _has_any(before, spec.before_terms) and _has_any(
                after_line.text, spec.after_terms
            ):
                transitions.append(
                    ClaimBoundaryTransition(
                        transition_class=spec.transition_class,
                        file=pair.file,
                        before_span=pair.before_span,
                        after_span=after_line,
                        severity=spec.severity,
                        confidence=spec.confidence,
                        rationale=spec.rationale,
                        suggested_rewrite=spec.suggested_rewrite,
                    )
                )
    return _dedupe_transitions(transitions), _dedupe_non_claims(non_claims)


def detect_collection(
    pairs: Iterable[DiffPair], *, allow_markers: Sequence[str] = DEFAULT_ALLOW_MARKERS
) -> Tuple[List[ClaimBoundaryTransition], List[NonClaim]]:
    """Run every detector over a collection of changed text pairs."""
    transitions: List[ClaimBoundaryTransition] = []
    non_claims: List[NonClaim] = []
    for pair in pairs:
        pair_transitions, pair_non_claims = detect_transitions(
            pair, allow_markers=allow_markers
        )
        transitions.extend(pair_transitions)
        non_claims.extend(pair_non_claims)
    return transitions, _dedupe_non_claims(non_claims)


def _non_claim(span: TextSpan, allow_markers: Sequence[str]) -> Optional[NonClaim]:
    after = _normalize(span.text)
    for marker in allow_markers:
        normalized_marker = _normalize(marker)
        if normalized_marker in after:
            if normalized_marker in GENERIC_BOUNDARY_MARKERS and _has_any(
                span.text, HARD_CLAIM_TERMS
            ):
                continue
            return NonClaim(
                file=span.file,
                span=span,
                reason=f"bounded_or_aspirational_marker:{marker}",
            )
    return None


def _line_spans(span: TextSpan) -> List[TextSpan]:
    lines = span.text.splitlines()
    return [
        TextSpan(
            file=span.file,
            start_line=span.start_line + index,
            end_line=span.start_line + index,
            text=line,
        )
        for index, line in enumerate(lines)
        if line.strip()
    ]


def _has_any(text: str, terms: Sequence[str]) -> bool:
    normalized = _normalize(text)
    return any(_contains_term(normalized, _normalize(term)) for term in terms)


def _contains_term(text: str, term: str) -> bool:
    if " " in term or "-" in term:
        return term in text
    return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None


def _normalize(text: str) -> str:
    return " ".join(text.lower().replace("_", " ").split())


def _dedupe_transitions(
    transitions: List[ClaimBoundaryTransition],
) -> List[ClaimBoundaryTransition]:
    seen = set()
    out: List[ClaimBoundaryTransition] = []
    for transition in transitions:
        key = (
            transition.file,
            transition.before_span.start_line,
            transition.after_span.start_line,
            transition.transition_class,
        )
        if key not in seen:
            seen.add(key)
            out.append(transition)
    return out


def _dedupe_non_claims(non_claims: List[NonClaim]) -> List[NonClaim]:
    seen = set()
    out: List[NonClaim] = []
    for non_claim in non_claims:
        key = (
            non_claim.file,
            non_claim.span.start_line,
            non_claim.span.end_line,
            non_claim.reason,
        )
        if key not in seen:
            seen.add(key)
            out.append(non_claim)
    return out
