"""Types for the comparability engine.

All types are plain dataclasses with to_dict() for serialization.
No Pydantic dependency — keeps the module lightweight and testable.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Mismatch severity. Determines effect on verdict."""
    INVALIDATING = "INVALIDATING"   # Forces DENIED
    DEGRADING = "DEGRADING"         # Pushes toward DOWNGRADED
    INFORMATIONAL = "INFORMATIONAL" # No effect on verdict


class Verdict(str, Enum):
    """Comparability verdict."""
    SATISFIED = "SATISFIED"         # All parity fields match
    DOWNGRADED = "DOWNGRADED"       # Degrading mismatches only
    DENIED = "DENIED"               # At least one invalidating mismatch
    UNDETERMINED = "UNDETERMINED"   # Required fields missing, can't evaluate


class ClaimStatus(str, Enum):
    """What the verdict means for the claim."""
    ADMISSIBLE = "ADMISSIBLE"
    ADMISSIBLE_WITH_CAVEAT = "ADMISSIBLE_WITH_CAVEAT"
    INADMISSIBLE = "INADMISSIBLE"
    PENDING_REVIEW = "PENDING_REVIEW"


class ParityFieldGroup(str, Enum):
    """Logical grouping of parity fields."""
    INSTRUMENT_IDENTITY = "instrument_identity"
    EXECUTION_PARAMS = "execution_params"
    EVAL_SURFACE = "eval_surface"


class InstrumentContinuity(str, Enum):
    """Whether the measurement instrument is the same across both bundles."""
    PRESERVED = "PRESERVED"
    BROKEN = "BROKEN"
    UNKNOWN = "UNKNOWN"


class FieldRequirement(str, Enum):
    """Whether a field is required for contract evaluation."""
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    DERIVED = "DERIVED"


# ---------------------------------------------------------------------------
# Field-level types
# ---------------------------------------------------------------------------

@dataclass
class FieldSource:
    """Where a field value came from (provenance)."""
    field: str
    source: str  # e.g. "env:OPENAI_MODEL", "file:prompts/v2.txt", "config:judge.yaml"
    method: str = "declared"  # "declared", "inferred", "default"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "source": self.source,
            "method": self.method,
        }


@dataclass
class Mismatch:
    """A single parity field that failed matching."""
    field: str
    baseline_value: Any
    candidate_value: Any
    severity: Severity
    rule: str  # match rule name: "exact", "content_hash", etc.
    group: ParityFieldGroup
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "baseline_value": self.baseline_value,
            "candidate_value": self.candidate_value,
            "severity": self.severity.value,
            "rule": self.rule,
            "group": self.group.value,
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# Bundle completeness
# ---------------------------------------------------------------------------

@dataclass
class BundleCompleteness:
    """Whether evidence bundles have all required fields."""
    status: Literal["COMPLETE", "INCOMPLETE"]
    missing_fields: List[str] = field(default_factory=list)
    present_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "status": self.status,
            "present_count": len(self.present_fields),
        }
        if self.missing_fields:
            d["missing_fields"] = self.missing_fields
        return d


# ---------------------------------------------------------------------------
# Claim under test
# ---------------------------------------------------------------------------

@dataclass
class ClaimUnderTest:
    """The claim being evaluated for admissibility."""
    claim_type: str  # "improvement", "regression", "equivalence", "ranking_change"
    summary: str
    metric: str = ""
    delta: Optional[float] = None
    direction: str = "higher_is_better"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": self.claim_type,
            "summary": self.summary,
        }
        if self.metric:
            d["metric"] = self.metric
        if self.delta is not None:
            d["delta"] = self.delta
        if self.direction:
            d["direction"] = self.direction
        return d


# ---------------------------------------------------------------------------
# Consequence
# ---------------------------------------------------------------------------

@dataclass
class Consequence:
    """What follows from the verdict."""
    claim_status: ClaimStatus
    blocked_actions: List[str] = field(default_factory=list)
    required_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "claim_status": self.claim_status.value,
        }
        if self.blocked_actions:
            d["blocked_actions"] = self.blocked_actions
        if self.required_actions:
            d["required_actions"] = self.required_actions
        return d


# ---------------------------------------------------------------------------
# Constitutional Diff — the core product object
# ---------------------------------------------------------------------------

@dataclass
class ConstitutionalDiff:
    """The constitutional diff: verdict + mismatches + consequence.

    This is the product object. It answers five questions:
      1. What changed? (claim)
      2. Is the comparison valid? (verdict)
      3. What broke it? (mismatches)
      4. What follows? (consequence)
      5. What do you do now? (required_actions in consequence)
    """
    # Identity
    diff_id: str = field(default_factory=lambda: f"cd-{uuid.uuid4().hex[:12]}")
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # What is being compared
    baseline_ref: str = ""
    candidate_ref: str = ""
    baseline_label: str = ""
    candidate_label: str = ""

    # The claim under test
    claim: Optional[ClaimUnderTest] = None

    # The verdict
    verdict: Verdict = Verdict.UNDETERMINED
    mismatches: List[Mismatch] = field(default_factory=list)
    satisfied_fields: List[str] = field(default_factory=list)

    # Instrument continuity
    instrument_continuity: InstrumentContinuity = InstrumentContinuity.UNKNOWN

    # Bundle completeness
    baseline_completeness: Optional[BundleCompleteness] = None
    candidate_completeness: Optional[BundleCompleteness] = None

    # Consequence
    consequence: Optional[Consequence] = None

    # Lineage
    contract_id: str = ""
    contract_version: str = ""
    contract_hash: str = ""
    prior_diff_ids: List[str] = field(default_factory=list)
    supersedes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "constitutional_diff": {
                "version": "0.1.0",
                "artifact_class": "diagnostic_diff",
                "evidence_status": "not_signed_not_authoritative",
                "authority_source_type": "comparability_verdict_receipt",
                "authority_container": "proof_pack",
                "diff_id": self.diff_id,
                "created_at": self.created_at,
                "entities": {
                    "baseline": {
                        "ref": self.baseline_ref,
                        "label": self.baseline_label,
                    },
                    "candidate": {
                        "ref": self.candidate_ref,
                        "label": self.candidate_label,
                    },
                },
                "comparability": {
                    "verdict": self.verdict.value,
                    "instrument_continuity": self.instrument_continuity.value,
                    "mismatches": [m.to_dict() for m in self.mismatches],
                    "satisfied_fields": self.satisfied_fields,
                },
                "lineage": {
                    "contract_id": self.contract_id,
                    "contract_version": self.contract_version,
                    "contract_hash": self.contract_hash,
                },
            }
        }
        if self.claim:
            d["constitutional_diff"]["claim"] = self.claim.to_dict()
        if self.consequence:
            d["constitutional_diff"]["consequence"] = self.consequence.to_dict()
        if self.baseline_completeness:
            d["constitutional_diff"]["baseline_completeness"] = (
                self.baseline_completeness.to_dict()
            )
        if self.candidate_completeness:
            d["constitutional_diff"]["candidate_completeness"] = (
                self.candidate_completeness.to_dict()
            )
        if self.prior_diff_ids:
            d["constitutional_diff"]["lineage"]["prior_diffs"] = self.prior_diff_ids
        if self.supersedes:
            d["constitutional_diff"]["lineage"]["supersedes"] = self.supersedes
        return d

    @property
    def exit_code(self) -> int:
        """0=SATISFIED, 1=DENIED/DOWNGRADED, 2=UNDETERMINED."""
        if self.verdict == Verdict.SATISFIED:
            return 0
        if self.verdict == Verdict.UNDETERMINED:
            return 2
        return 1
