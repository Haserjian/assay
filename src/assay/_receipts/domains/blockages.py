"""
Blockage Receipts: Structured proof of what can't be decided and why.

Most audit systems log what happened. These receipts log what *couldn't be resolved*
and why — enabling debugging of AI decision-making at the limits of knowledge.

Three types with escalating severity:
- IncompletenessReceipt: Missing evidence prevents decision
- ContradictionReceipt: Two claims can't both be true
- ParadoxReceipt: Contradiction requires frame change to resolve

Schema: blockages.v1
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Literal, Optional
import uuid

from assay._receipts.compat.pyd import BaseModel, Field, model_validator
from assay._receipts.base import BaseReceipt, Domain, _normalise_utc_millis


# Type aliases for clarity
Impact = Literal["low", "medium", "high", "critical"]
RecommendedAction = Literal["gather_evidence", "defer", "escalate"]
EscalationPath = Literal["council", "human", "defer"]


class IncompletenessReceipt(BaseReceipt):
    """
    What can't be decided and why.

    Emitted when the system cannot proceed due to missing information.
    Unlike a crash or error, this is a *structured acknowledgment* of
    the limits of current knowledge.

    Resolution protocol: gather_evidence → retry
    """

    receipt_type: str = Field(default="IncompletenessReceipt")
    domain: str = Field(default=Domain.GOVERNANCE.value)

    # What couldn't be decided
    undecidable_claim: str = Field(
        description="The claim or decision that cannot be made"
    )

    # Why it couldn't be decided
    missing_evidence: List[str] = Field(
        default_factory=list,
        description="List of evidence types that would resolve the incompleteness"
    )

    # Severity assessment
    impact_if_wrong: Impact = Field(
        default="medium",
        description="Impact if we guessed wrong: low, medium, high, critical"
    )

    # What to do next
    recommended_action: RecommendedAction = Field(
        default="gather_evidence",
        description="Recommended next action: gather_evidence, defer, escalate"
    )

    # When this was detected
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the incompleteness was detected (normalized to UTC)"
    )

    @model_validator(mode="after")
    def _normalise_timestamps(self) -> "IncompletenessReceipt":
        """Normalize detected_at to UTC with millisecond precision."""
        object.__setattr__(self, "detected_at", _normalise_utc_millis(self.detected_at))
        return self


class ContradictionReceipt(BaseReceipt):
    """
    Two claims that can't both be true.

    Emitted when the system detects logical inconsistency between
    two assertions. This is more severe than incompleteness because
    we have information — it just contradicts.

    Resolution protocol: attempt local resolution → if fails, escalate to paradox
    """

    receipt_type: str = Field(default="ContradictionReceipt")
    domain: str = Field(default=Domain.GOVERNANCE.value)

    # The contradicting claims
    claim_a: str = Field(description="First claim")
    claim_a_confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in claim A (0.0-1.0)"
    )

    claim_b: str = Field(description="Second claim (contradicts claim A)")
    claim_b_confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in claim B (0.0-1.0)"
    )

    # What's affected
    impacted_invariants: List[str] = Field(
        default_factory=list,
        description="System invariants affected by this contradiction"
    )

    # Resolution attempt
    resolution_attempted: bool = Field(
        default=False,
        description="Whether automatic resolution was attempted"
    )
    resolution_result: Optional[str] = Field(
        default=None,
        description="Result of resolution attempt, if any"
    )

    # When detected
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the contradiction was detected (normalized to UTC)"
    )

    @model_validator(mode="after")
    def _normalise_timestamps(self) -> "ContradictionReceipt":
        """Normalize detected_at to UTC with millisecond precision."""
        object.__setattr__(self, "detected_at", _normalise_utc_millis(self.detected_at))
        return self


class ParadoxReceipt(BaseReceipt):
    """
    Contradiction that requires frame change to resolve.

    This is the most severe blockage: a contradiction that cannot be
    resolved within the current conceptual framework. The system must
    either escalate to a higher authority or refuse to proceed.

    Resolution protocol: escalate to council/human or refuse action
    """

    receipt_type: str = Field(default="ParadoxReceipt")
    domain: str = Field(default=Domain.GOVERNANCE.value)

    # Link to underlying contradiction
    contradiction_id: str = Field(
        description="Receipt ID of the ContradictionReceipt that escalated to paradox"
    )

    # Why it's a paradox (not just a contradiction)
    why_frame_change_required: str = Field(
        description="Explanation of why local resolution is impossible"
    )

    # Possible reframes
    candidate_reframes: List[str] = Field(
        default_factory=list,
        description="Candidate conceptual reframes that might resolve the paradox"
    )

    # Escalation
    escalation_path: EscalationPath = Field(
        default="council",
        description="Where to escalate: council, human, defer"
    )

    # Risk assessment
    dignity_risk: float = Field(
        ge=0.0, le=1.0,
        description="Risk to dignity if we proceed without resolution (0.0-1.0)"
    )

    # When detected
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the paradox was identified (normalized to UTC)"
    )

    @model_validator(mode="after")
    def _normalise_timestamps(self) -> "ParadoxReceipt":
        """Normalize detected_at to UTC with millisecond precision."""
        object.__setattr__(self, "detected_at", _normalise_utc_millis(self.detected_at))
        return self


# Factory functions

def create_incompleteness_receipt(
    undecidable_claim: str,
    missing_evidence: List[str],
    impact_if_wrong: Impact = "medium",
    recommended_action: RecommendedAction = "gather_evidence",
) -> IncompletenessReceipt:
    """Create an IncompletenessReceipt with auto-generated ID."""
    return IncompletenessReceipt(
        receipt_id=f"inc_{uuid.uuid4().hex[:16]}",
        undecidable_claim=undecidable_claim,
        missing_evidence=missing_evidence,
        impact_if_wrong=impact_if_wrong,
        recommended_action=recommended_action,
    )


def create_contradiction_receipt(
    claim_a: str,
    claim_a_confidence: float,
    claim_b: str,
    claim_b_confidence: float,
    impacted_invariants: Optional[List[str]] = None,
    resolution_attempted: bool = False,
    resolution_result: Optional[str] = None,
) -> ContradictionReceipt:
    """Create a ContradictionReceipt with auto-generated ID."""
    return ContradictionReceipt(
        receipt_id=f"con_{uuid.uuid4().hex[:16]}",
        claim_a=claim_a,
        claim_a_confidence=claim_a_confidence,
        claim_b=claim_b,
        claim_b_confidence=claim_b_confidence,
        impacted_invariants=impacted_invariants or [],
        resolution_attempted=resolution_attempted,
        resolution_result=resolution_result,
    )


def create_paradox_receipt(
    contradiction_id: str,
    why_frame_change_required: str,
    candidate_reframes: Optional[List[str]] = None,
    escalation_path: EscalationPath = "council",
    dignity_risk: float = 0.5,
) -> ParadoxReceipt:
    """Create a ParadoxReceipt with auto-generated ID."""
    return ParadoxReceipt(
        receipt_id=f"par_{uuid.uuid4().hex[:16]}",
        contradiction_id=contradiction_id,
        why_frame_change_required=why_frame_change_required,
        candidate_reframes=candidate_reframes or [],
        escalation_path=escalation_path,
        dignity_risk=dignity_risk,
    )


__all__ = [
    "Impact",
    "RecommendedAction",
    "EscalationPath",
    "IncompletenessReceipt",
    "ContradictionReceipt",
    "ParadoxReceipt",
    "create_incompleteness_receipt",
    "create_contradiction_receipt",
    "create_paradox_receipt",
]
