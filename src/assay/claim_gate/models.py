"""Data models for Assay Claim Gate."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


PASS = "PASS"
NEEDS_REVIEW = "NEEDS_REVIEW"
BLOCK = "BLOCK"
VERDICTS = {PASS, NEEDS_REVIEW, BLOCK}


@dataclass(frozen=True)
class TextSpan:
    """A file-local text span used in claim drift reports."""

    file: str
    start_line: int
    end_line: int
    text: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_line": self.start_line,
            "end_line": self.end_line,
            "text": self.text,
        }


@dataclass(frozen=True)
class DiffPair:
    """One before/after text pair from a repository diff."""

    file: str
    before_span: TextSpan
    after_span: TextSpan


@dataclass(frozen=True)
class DiffCollection:
    """Changed text spans plus metadata about the diff source."""

    base: str
    head: str
    changed_paths: List[str]
    pairs: List[DiffPair]
    files_scanned: int


@dataclass(frozen=True)
class NonClaim:
    """A changed text span that is explicitly bounded or aspirational."""

    file: str
    span: TextSpan
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "span": self.span.to_dict(),
            "text": self.span.text,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ClaimBoundaryTransition:
    """A detected claim-boundary transition."""

    transition_class: str
    file: str
    before_span: TextSpan
    after_span: TextSpan
    risk_class: str = "unsupported_claim_escalation"
    severity: str = "medium"
    confidence: float = 0.75
    rationale: str = ""
    evidence_required: List[str] = field(default_factory=list)
    evidence_found: List[str] = field(default_factory=list)
    verdict: str = NEEDS_REVIEW
    suggested_rewrite: str = ""
    transition_id: str = ""

    def with_policy(
        self,
        *,
        evidence_required: List[str],
        evidence_found: List[str],
        verdict: str,
        severity: str,
    ) -> "ClaimBoundaryTransition":
        return ClaimBoundaryTransition(
            transition_id=self.transition_id,
            transition_class=self.transition_class,
            file=self.file,
            before_span=self.before_span,
            after_span=self.after_span,
            risk_class=self.risk_class,
            severity=severity,
            confidence=self.confidence,
            rationale=self.rationale,
            evidence_required=evidence_required,
            evidence_found=evidence_found,
            verdict=verdict,
            suggested_rewrite=self.suggested_rewrite,
        )

    def with_id(self, transition_id: str) -> "ClaimBoundaryTransition":
        return ClaimBoundaryTransition(
            transition_id=transition_id,
            transition_class=self.transition_class,
            file=self.file,
            before_span=self.before_span,
            after_span=self.after_span,
            risk_class=self.risk_class,
            severity=self.severity,
            confidence=self.confidence,
            rationale=self.rationale,
            evidence_required=list(self.evidence_required),
            evidence_found=list(self.evidence_found),
            verdict=self.verdict,
            suggested_rewrite=self.suggested_rewrite,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.transition_id,
            "file": self.file,
            "before_span": self.before_span.to_dict(),
            "after_span": self.after_span.to_dict(),
            "transition_class": self.transition_class,
            "risk_class": self.risk_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_required": list(self.evidence_required),
            "evidence_found": list(self.evidence_found),
            "verdict": self.verdict,
            "rationale": self.rationale,
            "suggested_rewrite": self.suggested_rewrite,
        }
