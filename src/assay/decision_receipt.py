"""Decision Receipt v0.1.0 — validator and invariant checker.

Reference implementation for the Decision Receipt constitutional artifact.

Normative contract: src/assay/schemas/decision_receipt_v0.1.0.schema.json
This module is a convenience/runtime enforcement layer. When the schema
and this code disagree, the JSON Schema file is authoritative.

Three validation layers:
  1. Shape — required fields, types, enum constraints
  2. Invariants — semantic rules I-1 through I-7 + forbidden states
  3. Reference integrity — optional, environment-aware (not in v0)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Current canonical receipt version (emitted by build.py)
RECEIPT_VERSION = "0.2.0"

# All versions this validator accepts. Stage 3b reads receipt_version per-receipt
# to select forensic vs strict mode — the validator must not reject historical receipts.
SUPPORTED_RECEIPT_VERSIONS = frozenset({"0.1.0", "0.1.1", "0.2.0"})

# Validation layers — used in ValidationError.layer
LAYER_SHAPE = "shape"
LAYER_INVARIANTS = "invariants"
LAYER_FORBIDDEN = "forbidden"

# Severity — currently only "error". Warning/fatal reserved for future use.
SEVERITY_ERROR = "error"

# Proof tier ordinal ranking — validators MUST use this, not string comparison
PROOF_TIER_RANK: Dict[str, int] = {
    "DRAFT": 0,
    "CHECKED": 1,
    "TOOL_VERIFIED": 2,
    "ADVERSARIAL": 3,
    "CONSTITUTIONAL": 4,
}

VALID_VERDICTS = {"APPROVE", "REFUSE", "DEFER", "ABSTAIN", "ROLLBACK", "CONFLICT"}

VALID_DISPOSITIONS = {
    "execute", "block", "defer_with_obligation",
    "escalate", "compensate", "no_action",
}

VALID_AUTHORITY_CLASSES = {
    "ADVISORY", "AUDITING", "BINDING", "MUTATING", "OVERRIDING",
}

VALID_CONFIDENCE = {"high", "moderate", "low", "minimal", None}

VALID_REF_ROLES = {"supporting", "contradicting", "contextual", "superseded"}

VALID_REF_TYPES = {
    "receipt", "claim", "attestation", "witness_bundle", "metric", "external",
}

VALID_SOURCE_ORGANS = {
    "ccio", "loom", "agentmesh", "assay-toolkit", "assay-ledger", "puppetlabs",
}

VALID_PROOF_TIERS = set(PROOF_TIER_RANK.keys()) | {None}

VALID_DISSENT_SEVERITY = {"note", "concern", "objection", "block"}

# Authority layer ordinal ranking — used by assert_tier_monotonic
# These map the three-layer receipt authority model to comparable ordinal values.
# Law: a Decision Receipt (GOVERNANCE) cannot be produced from EVIDENCE-only inputs
# without an authorized judgment path. See RECEIPT_AUTHORITY_LADDER.md.
AUTHORITY_LAYER_RANK: Dict[str, int] = {
    "EVIDENCE": 0,
    "CONTINUITY": 1,
    "GOVERNANCE": 2,
}

# Verdict -> allowed dispositions (I-1)
VERDICT_DISPOSITION_MAP: Dict[str, set] = {
    "APPROVE": {"execute"},
    "REFUSE": {"block", "escalate"},
    "DEFER": {"defer_with_obligation", "escalate"},
    "ABSTAIN": {"escalate", "no_action"},
    "ROLLBACK": {"compensate", "execute"},
    "CONFLICT": {"escalate"},
}

# Advisory cannot ROLLBACK or produce CONFLICT (I-2)
ADVISORY_ALLOWED_VERDICTS = {"APPROVE", "REFUSE", "DEFER", "ABSTAIN"}

REQUIRED_FIELDS = [
    "receipt_id", "receipt_type", "receipt_version", "timestamp",
    "decision_type", "decision_subject", "verdict",
    "authority_id", "authority_class", "authority_scope",
    "policy_id", "policy_hash", "episode_id",
    "disposition", "evidence_sufficient", "provenance_complete",
]


class TierEscalationError(ValueError):
    """Raised when a Decision Receipt (GOVERNANCE layer) is emitted from
    only EVIDENCE or CONTINUITY predecessors without an authorized judgment path.

    Core invariant: aggregation does not create authority.
    See RECEIPT_AUTHORITY_LADDER.md, propagation law.

    Do not catch this as a bare ValueError — handle it explicitly or let it
    propagate to the caller as a programming error.
    """


class GovernanceEmissionError(ValueError):
    """Raised when a Decision Receipt is emitted without a declared authorization anchor.

    Governance-class receipts (authority_class in {BINDING, MUTATING, OVERRIDING}) must
    declare explicit authorization ancestry at emission time. At least one of the following
    must be non-null:
      - guardian_authorization_receipt_id — Guardian-path authorization artifact
      - settlement_outcome_id             — settlement state-machine closure path

    Both anchors may be present; at least one must be non-null.

    Stage 5 enforces declaration only. Resolution and constitutional sufficiency
    are validated by Stage 3b strict mode.

    ADVISORY and AUDITING class receipts do not require an authorization anchor —
    they do not impose governance acts.

    Row 3 Stage 5. Follows TierEscalationError(ValueError) naming pattern (Stage 2).
    Distinct from TierEscalationError: that error guards proof-tier ancestry;
    this error guards explicit authorization ancestry.
    """


@dataclass(frozen=True)
class JudgmentPathDeclaration:
    """Typed declaration that an authorized judgment path was on the predecessor chain.

    Use this instead of a bare boolean to make authority provenance explicit and
    auditable. Passing this to assert_tier_monotonic means the caller is making a
    constitutional declaration: governance was reached through authorized judgment,
    not through composition of evidence receipts alone.

    This is an assertion, not a receipt. It does not replace proper lineage
    tracking but makes the declaration legible in operator context.

    Fields:
        reason: Non-empty description of why governance authority is declared.
            Must be substantive — empty or whitespace-only strings are rejected.
        authority_ref: Optional reference to the authorizing receipt ID, Guardian
            judgment ID, or policy reference that grounds this declaration.
        declared_by: Optional identifier of the subsystem or agent making this
            declaration (e.g. "ccio:guardian:settlement_seat").

    Future hardening (not enforced now):
        - reason length / substantiveness check (reject "x", "override", etc.)
        - authority_ref presence required for OVERRIDING authority class
        - serialization of declaration context into the Decision Receipt payload
    """
    reason: str
    authority_ref: Optional[str] = None
    declared_by: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError(
                "JudgmentPathDeclaration.reason must be non-empty. "
                "Provide a substantive description of why governance authority "
                "is declared on this path."
            )


def assert_tier_monotonic(
    predecessor_authority_layers: List[str],
    *,
    authorized_judgment_path: Optional[JudgmentPathDeclaration] = None,
) -> None:
    """Assert that a Decision Receipt (GOVERNANCE tier) may be emitted from
    the given predecessor authority layers.

    A Decision Receipt is a GOVERNANCE-layer artifact. It cannot be produced
    from only EVIDENCE or CONTINUITY predecessors without an authorized
    judgment path.

    Args:
        predecessor_authority_layers: Authority layer of each predecessor
            receipt in the chain. Values: "EVIDENCE", "CONTINUITY",
            "GOVERNANCE". An empty list is treated as unchecked (no-op).

            Note: [] (empty) is currently conflated with "lineage unknown",
            "lineage complete but empty", and "lineage redacted". These are
            distinct organism states. See predecessor_completeness planning note
            in ROW3_RECEIPT_COMPOSITION_DRAFT.md.

        authorized_judgment_path: A JudgmentPathDeclaration when an authorized
            judgment (Guardian, settlement) was on the path — even if not
            reflected as a GOVERNANCE predecessor in the layer list. Requires
            a non-empty reason. This is a typed declaration by the caller,
            not a silent boolean bypass.

    Raises:
        TierEscalationError: if no predecessor is GOVERNANCE-tier and
            authorized_judgment_path is None.
    """
    if not predecessor_authority_layers:
        return  # No predecessors provided — no assertion possible

    if authorized_judgment_path is not None:
        return  # Caller provided a typed JudgmentPathDeclaration

    governance_rank = AUTHORITY_LAYER_RANK["GOVERNANCE"]
    has_governance_predecessor = any(
        AUTHORITY_LAYER_RANK.get(layer, 0) >= governance_rank
        for layer in predecessor_authority_layers
    )

    if not has_governance_predecessor:
        received = sorted(set(predecessor_authority_layers))
        raise TierEscalationError(
            f"Decision Receipt (GOVERNANCE layer) cannot be emitted from "
            f"{received!r} predecessors without an authorized judgment path. "
            f"Include a GOVERNANCE-layer predecessor (e.g. Guardian judgment receipt) "
            f"or set authorized_judgment_path=True to declare one. "
            f"Core invariant: aggregation does not create authority. "
            f"See RECEIPT_AUTHORITY_LADDER.md."
        )


@dataclass(frozen=True)
class ValidationError:
    """A single structured validation failure."""
    rule: str
    message: str
    field: Optional[str] = None
    layer: str = LAYER_SHAPE
    severity: str = SEVERITY_ERROR

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"rule": self.rule, "message": self.message,
                              "layer": self.layer, "severity": self.severity}
        if self.field is not None:
            d["field"] = self.field
        return d


@dataclass
class ValidationResult:
    """Aggregate validation result."""
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)

    def add(self, rule: str, message: str, *, field: Optional[str] = None,
            layer: str = LAYER_SHAPE, severity: str = SEVERITY_ERROR):
        self.errors.append(ValidationError(rule=rule, message=message, field=field,
                                            layer=layer, severity=severity))
        self.valid = False

    def to_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "errors": [e.to_dict() for e in self.errors]}


def validate_shape(receipt: Dict[str, Any]) -> ValidationResult:
    """Layer 1: Check required fields, types, and enum constraints."""
    result = ValidationResult(valid=True)

    for f in REQUIRED_FIELDS:
        if f not in receipt:
            result.add("shape", f"Missing required field: {f}", field=f)

    if receipt.get("receipt_type") != "decision_v1":
        result.add("shape", f"receipt_type must be 'decision_v1', got {receipt.get('receipt_type')!r}", field="receipt_type")

    if receipt.get("receipt_version") not in SUPPORTED_RECEIPT_VERSIONS:
        result.add("shape",
                   f"receipt_version must be one of {sorted(SUPPORTED_RECEIPT_VERSIONS)}, "
                   f"got {receipt.get('receipt_version')!r}",
                   field="receipt_version")

    verdict = receipt.get("verdict")
    if verdict and verdict not in VALID_VERDICTS:
        result.add("shape", f"Unknown verdict: {verdict!r}", field="verdict")

    disposition = receipt.get("disposition")
    if disposition and disposition not in VALID_DISPOSITIONS:
        result.add("shape", f"Unknown disposition: {disposition!r}", field="disposition")

    ac = receipt.get("authority_class")
    if ac and ac not in VALID_AUTHORITY_CLASSES:
        result.add("shape", f"Unknown authority_class: {ac!r}", field="authority_class")

    conf = receipt.get("confidence")
    if conf is not None and conf not in VALID_CONFIDENCE:
        result.add("shape", f"Unknown confidence band: {conf!r}", field="confidence")

    so = receipt.get("source_organ")
    if so is not None and so not in VALID_SOURCE_ORGANS:
        result.add("shape", f"Unknown source_organ: {so!r}", field="source_organ")

    pt = receipt.get("proof_tier_at_decision")
    if pt is not None and pt not in VALID_PROOF_TIERS:
        result.add("shape", f"Unknown proof_tier_at_decision: {pt!r}", field="proof_tier_at_decision")

    dissent = receipt.get("dissent")
    if isinstance(dissent, dict):
        ds = dissent.get("dissent_severity")
        if ds is not None and ds not in VALID_DISSENT_SEVERITY:
            result.add("shape", f"Unknown dissent_severity: {ds!r}", field="dissent.dissent_severity")

    for i, ref in enumerate(receipt.get("evidence_refs") or []):
        if not isinstance(ref, dict):
            result.add("shape", f"evidence_refs[{i}] is not an object", field="evidence_refs")
            continue
        for req in ("ref_type", "ref_id", "ref_role"):
            if req not in ref:
                result.add("shape", f"evidence_refs[{i}] missing {req}", field=f"evidence_refs[{i}].{req}")
        rt = ref.get("ref_type")
        if rt and rt not in VALID_REF_TYPES:
            result.add("shape", f"evidence_refs[{i}] unknown ref_type: {rt!r}", field=f"evidence_refs[{i}].ref_type")
        rr = ref.get("ref_role")
        if rr and rr not in VALID_REF_ROLES:
            result.add("shape", f"evidence_refs[{i}] unknown ref_role: {rr!r}", field=f"evidence_refs[{i}].ref_role")

    return result


def validate_invariants(receipt: Dict[str, Any]) -> ValidationResult:
    """Layer 2: Check semantic invariants I-1 through I-7 and forbidden states."""
    result = ValidationResult(valid=True)
    verdict = receipt.get("verdict")
    disposition = receipt.get("disposition")
    ac = receipt.get("authority_class")
    ev_suff = receipt.get("evidence_sufficient")
    prov = receipt.get("provenance_complete")
    confidence = receipt.get("confidence")
    L = LAYER_INVARIANTS

    # I-1: Verdict-disposition coherence
    if verdict in VERDICT_DISPOSITION_MAP and disposition:
        allowed = VERDICT_DISPOSITION_MAP[verdict]
        if disposition not in allowed:
            result.add("I-1", f"verdict={verdict} does not allow disposition={disposition} (allowed: {allowed})",
                        field="disposition", layer=L)

    # I-1 conditional requirements
    if verdict == "ABSTAIN" and not receipt.get("abstention_reason"):
        result.add("I-1", "verdict=ABSTAIN requires abstention_reason", field="abstention_reason", layer=L)

    if verdict == "ROLLBACK" and not receipt.get("supersedes"):
        result.add("I-1", "verdict=ROLLBACK requires supersedes", field="supersedes", layer=L)

    if verdict == "CONFLICT":
        has_conflict_refs = bool(receipt.get("conflict_refs"))
        has_dissent = receipt.get("dissent") is not None
        if not has_conflict_refs and not has_dissent:
            result.add("I-1", "verdict=CONFLICT requires conflict_refs non-empty or dissent non-null",
                        field="conflict_refs", layer=L)

    if disposition == "defer_with_obligation":
        if not receipt.get("obligations_created"):
            result.add("I-1", "disposition=defer_with_obligation requires non-empty obligations_created",
                        field="obligations_created", layer=L)

    # I-2: Authority-class constraints
    if ac == "ADVISORY" and verdict and verdict not in ADVISORY_ALLOWED_VERDICTS:
        result.add("I-2", f"authority_class=ADVISORY cannot produce verdict={verdict}", field="verdict", layer=L)

    if ac == "OVERRIDING" and not receipt.get("delegated_from"):
        result.add("I-2", "authority_class=OVERRIDING requires delegated_from", field="delegated_from", layer=L)

    # I-3: Evidence sufficiency coherence
    if ev_suff is False and verdict == "APPROVE":
        result.add("I-3", "Cannot APPROVE with evidence_sufficient=false", field="evidence_sufficient", layer=L)

    if ev_suff is False and verdict == "REFUSE":
        if not receipt.get("evidence_gaps"):
            result.add("I-3", "REFUSE with evidence_sufficient=false requires non-empty evidence_gaps",
                        field="evidence_gaps", layer=L)

    # I-4: Proof tier monotonicity (comparison by ordinal rank, not lexicographic)
    achieved = receipt.get("proof_tier_achieved")
    minimum = receipt.get("proof_tier_minimum_required")
    if achieved and minimum and verdict == "APPROVE":
        a_rank = PROOF_TIER_RANK.get(achieved, -1)
        m_rank = PROOF_TIER_RANK.get(minimum, -1)
        if a_rank < m_rank:
            result.add("I-4", f"proof_tier_achieved={achieved} (rank {a_rank}) < "
                        f"proof_tier_minimum_required={minimum} (rank {m_rank}) with APPROVE verdict",
                        field="proof_tier_achieved", layer=L)

    # I-5: Supersession integrity
    supersedes = receipt.get("supersedes")
    receipt_id = receipt.get("receipt_id")
    if supersedes and supersedes == receipt_id:
        result.add("I-5", "receipt cannot supersede itself", field="supersedes", layer=L)

    # I-6: Provenance self-consistency
    gaps = receipt.get("known_provenance_gaps") or []
    if prov is True and len(gaps) > 0:
        result.add("I-6", "provenance_complete=true but known_provenance_gaps is non-empty",
                    field="provenance_complete", layer=L)
    if prov is False and len(gaps) == 0:
        result.add("I-6", "provenance_complete=false but known_provenance_gaps is empty",
                    field="known_provenance_gaps", layer=L)

    # I-7: Signature scope
    sig = receipt.get("signature")
    spk = receipt.get("signer_pubkey_sha256")
    if sig and not spk:
        result.add("I-7", "signature present but signer_pubkey_sha256 is null",
                    field="signer_pubkey_sha256", layer=L)

    # Forbidden states
    F = LAYER_FORBIDDEN
    if confidence == "high" and ev_suff is False:
        result.add("forbidden", "confidence=high with evidence_sufficient=false is epistemic fraud",
                    field="confidence", layer=F)

    if verdict == "APPROVE" and disposition == "block":
        result.add("forbidden", "APPROVE + block is incoherent", field="disposition", layer=F)

    if verdict == "REFUSE" and disposition == "execute":
        result.add("forbidden", "REFUSE + execute violates decision/execution separation",
                    field="disposition", layer=F)

    if ac == "ADVISORY" and verdict == "ROLLBACK":
        result.add("forbidden", "ADVISORY cannot ROLLBACK", field="verdict", layer=F)

    return result


def validate_decision_receipt(receipt: Dict[str, Any]) -> ValidationResult:
    """Full validation: shape + invariants."""
    shape_result = validate_shape(receipt)
    if not shape_result.valid:
        return shape_result

    inv_result = validate_invariants(receipt)
    combined = ValidationResult(valid=shape_result.valid and inv_result.valid)
    combined.errors = shape_result.errors + inv_result.errors
    return combined


def load_and_validate(path: Path) -> ValidationResult:
    """Load a decision receipt from JSON file and validate it."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return validate_decision_receipt(data)


__all__ = [
    "RECEIPT_VERSION",
    "SUPPORTED_RECEIPT_VERSIONS",
    "LAYER_SHAPE",
    "LAYER_INVARIANTS",
    "LAYER_FORBIDDEN",
    "SEVERITY_ERROR",
    "PROOF_TIER_RANK",
    "AUTHORITY_LAYER_RANK",
    "TierEscalationError",
    "GovernanceEmissionError",
    "JudgmentPathDeclaration",
    "assert_tier_monotonic",
    "ValidationError",
    "ValidationResult",
    "validate_shape",
    "validate_invariants",
    "validate_decision_receipt",
    "load_and_validate",
]
