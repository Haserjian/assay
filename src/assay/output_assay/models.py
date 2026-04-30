"""Strict local draft and stamped-run models for Output Assay."""

from __future__ import annotations

from enum import Enum

from assay._receipts.compat.pyd import BaseModel, ConfigDictLike, Field, model_validator


class IntentClass(str, Enum):
    ARGUMENT = "argument"
    PLAN = "plan"
    TECHNICAL_ANSWER = "technical_answer"
    DECISION_MEMO = "decision_memo"
    STATUS_UPDATE = "status_update"
    CREATIVE = "creative"
    EMOTIONAL_SUPPORT = "emotional_support"
    BRAINSTORM = "brainstorm"
    SALES_PITCH = "sales_pitch"
    RESEARCH_SUMMARY = "research_summary"


class UnitType(str, Enum):
    CLAIM = "claim"
    CONSTRAINT = "constraint"
    ACTION = "action"
    QUESTION = "question"
    DECISION = "decision"
    RISK = "risk"
    EMOTION = "emotion"
    INSIGHT = "insight"
    COMMITMENT = "commitment"
    INSTRUCTION = "instruction"


class SourceRole(str, Enum):
    EVIDENCE = "evidence"
    ASSERTION = "assertion"
    INSTRUCTION = "instruction"
    CONTEXT = "context"
    EXAMPLE = "example"
    UNKNOWN = "unknown"


class ObserverKind(str, Enum):
    LLM = "llm"
    HUMAN = "human"
    TOOL = "tool"


class ObservationStatus(str, Enum):
    DRAFT = "draft"
    GUARDIAN_PASSED = "guardian_passed"
    GUARDIAN_WARNED = "guardian_warned"
    GUARDIAN_BLOCKED = "guardian_blocked"


class PromotionEligibilityStatus(str, Enum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"


class RunDisposition(str, Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


class ArtifactSpanDraft(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    text: str
    start_char: int
    end_char: int

    @model_validator(mode="after")
    def _validate_span(self) -> "ArtifactSpanDraft":
        if not self.text:
            raise ValueError("artifact_span.text must be non-empty")
        if self.start_char < 0:
            raise ValueError("artifact_span.start_char must be >= 0")
        if self.end_char < self.start_char:
            raise ValueError(
                "artifact_span.end_char must be >= artifact_span.start_char"
            )
        return self


class OutputAssayObservedUnitDraft(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    unit_type: UnitType
    source_role: SourceRole
    artifact_span: ArtifactSpanDraft
    normalized_text: str
    observation_confidence: float = Field(ge=0.0, le=1.0)
    notes: str

    @model_validator(mode="after")
    def _validate_text_fields(self) -> "OutputAssayObservedUnitDraft":
        if not self.normalized_text:
            raise ValueError("normalized_text must be non-empty")
        if not self.notes:
            raise ValueError("notes must be non-empty")
        return self


class OutputAssayAnalysisDraft(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    intent_class: IntentClass
    summary: str
    observed_units: list[OutputAssayObservedUnitDraft]

    @model_validator(mode="after")
    def _validate_observed_units(self) -> "OutputAssayAnalysisDraft":
        if not self.summary:
            raise ValueError("summary must be non-empty")
        if not self.observed_units:
            raise ValueError("observed_units must not be empty")
        return self


class OutputAssayObserver(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    kind: ObserverKind
    provider: str
    model: str

    @model_validator(mode="after")
    def _validate_observer_fields(self) -> "OutputAssayObserver":
        if not self.provider:
            raise ValueError("observer.provider must be non-empty")
        if not self.model:
            raise ValueError("observer.model must be non-empty")
        return self


class OutputAssayPromotionEligibility(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    status: PromotionEligibilityStatus
    reason: str
    reasons: list[str] | None = None

    @model_validator(mode="after")
    def _validate_reason_fields(self) -> "OutputAssayPromotionEligibility":
        if not self.reason:
            raise ValueError("promotion_eligibility.reason must be non-empty")
        if (
            self.status == PromotionEligibilityStatus.ELIGIBLE
            and self.reasons is not None
        ):
            raise ValueError("eligible promotion_eligibility must not include reasons")
        return self


class OutputAssayGuardianVerdict(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    run_status: RunDisposition
    observation_counts: dict[str, int]
    failure_modes: list[str]
    warnings: list[str]
    block_reasons: list[str]

    @model_validator(mode="after")
    def _validate_observation_counts(self) -> "OutputAssayGuardianVerdict":
        expected_keys = {
            ObservationStatus.GUARDIAN_PASSED.value,
            ObservationStatus.GUARDIAN_WARNED.value,
            ObservationStatus.GUARDIAN_BLOCKED.value,
        }
        if set(self.observation_counts) != expected_keys:
            raise ValueError(
                "guardian_verdict.observation_counts must track passed, warned, and blocked observations"
            )
        if any(count < 0 for count in self.observation_counts.values()):
            raise ValueError("guardian_verdict.observation_counts values must be >= 0")
        return self


class OutputAssayObservedUnit(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    receipt_type: str = Field(default="artifact.unit_observed")
    unit_id: str
    unit_type: UnitType
    source_role: SourceRole
    artifact_hash: str
    artifact_span: ArtifactSpanDraft
    normalized_text: str
    observer: OutputAssayObserver
    observation_confidence: float = Field(ge=0.0, le=1.0)
    observation_status: ObservationStatus
    promotion_eligibility: OutputAssayPromotionEligibility
    notes: str

    @model_validator(mode="after")
    def _validate_stamped_unit(self) -> "OutputAssayObservedUnit":
        if self.receipt_type != "artifact.unit_observed":
            raise ValueError("receipt_type must be artifact.unit_observed")
        if not self.unit_id:
            raise ValueError("unit_id must be non-empty")
        if not self.artifact_hash.startswith("sha256:"):
            raise ValueError("artifact_hash must start with sha256:")
        if not self.normalized_text:
            raise ValueError("normalized_text must be non-empty")
        if not self.notes:
            raise ValueError("notes must be non-empty")
        return self


class OutputAssayRunEnvelope(BaseModel):
    model_config = ConfigDictLike(extra="forbid", protected_namespaces=())

    receipt_type: str = Field(default="output_assay.run")
    run_id: str
    artifact_hash: str
    intent_class: IntentClass
    summary: str
    observed_units: list[OutputAssayObservedUnit]
    guardian_verdict: OutputAssayGuardianVerdict | None = None

    @model_validator(mode="after")
    def _validate_run_envelope(self) -> "OutputAssayRunEnvelope":
        if self.receipt_type != "output_assay.run":
            raise ValueError("receipt_type must be output_assay.run")
        if not self.run_id:
            raise ValueError("run_id must be non-empty")
        if not self.artifact_hash.startswith("sha256:"):
            raise ValueError("artifact_hash must start with sha256:")
        if not self.summary:
            raise ValueError("summary must be non-empty")
        if not self.observed_units:
            raise ValueError("observed_units must not be empty")
        for observed_unit in self.observed_units:
            if observed_unit.artifact_hash != self.artifact_hash:
                raise ValueError(
                    "observed_units artifact_hash must match run artifact_hash"
                )
        if self.guardian_verdict is not None:
            status_counts = {
                ObservationStatus.GUARDIAN_PASSED.value: 0,
                ObservationStatus.GUARDIAN_WARNED.value: 0,
                ObservationStatus.GUARDIAN_BLOCKED.value: 0,
            }
            for observed_unit in self.observed_units:
                if observed_unit.observation_status == ObservationStatus.DRAFT:
                    continue
                status_counts[observed_unit.observation_status.value] += 1

            if self.guardian_verdict.observation_counts != status_counts:
                raise ValueError(
                    "guardian_verdict.observation_counts must match observed unit statuses"
                )

            expected_run_status = RunDisposition.PASS
            if status_counts[ObservationStatus.GUARDIAN_BLOCKED.value] > 0:
                expected_run_status = RunDisposition.BLOCK
            elif status_counts[ObservationStatus.GUARDIAN_WARNED.value] > 0:
                expected_run_status = RunDisposition.WARN

            if self.guardian_verdict.run_status != expected_run_status:
                raise ValueError(
                    "guardian_verdict.run_status must match observed unit statuses"
                )

            if self.guardian_verdict.run_status == RunDisposition.BLOCK:
                if any(
                    observed_unit.promotion_eligibility.status
                    == PromotionEligibilityStatus.ELIGIBLE
                    for observed_unit in self.observed_units
                ):
                    raise ValueError(
                        "blocked runs must not contain promotion-eligible observations"
                    )
        return self


__all__ = [
    "ArtifactSpanDraft",
    "IntentClass",
    "ObservationStatus",
    "OutputAssayAnalysisDraft",
    "OutputAssayGuardianVerdict",
    "OutputAssayObservedUnit",
    "OutputAssayObservedUnitDraft",
    "OutputAssayObserver",
    "OutputAssayPromotionEligibility",
    "OutputAssayRunEnvelope",
    "ObserverKind",
    "PromotionEligibilityStatus",
    "RunDisposition",
    "SourceRole",
    "UnitType",
]
