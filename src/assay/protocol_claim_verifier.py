"""
Protocol Claim & Contradiction Verifier for Assay.

Verifies protocol-level claim_assertion, claim_support_change,
contradiction_registration, and contradiction_resolution artifacts
against constitutional invariants.

This verifier checks SHAPE + LIFECYCLE LEGALITY + APPEND-ONLY RULES.
It does NOT check content truthfulness — that is a runtime concern.

Relationship to epistemic_kernel.py:
  - epistemic_kernel.py owns claim/denial dataclasses, emission, and
    single-chain verification (verify_claim_support_chain).
  - This module adds contradiction verification and multi-artifact
    cross-chain lifecycle checks that epistemic_kernel does not cover.

Design goals:
  - Pure functions over artifact chains. No side effects.
  - Every check returns a named VerificationResult with a stable
    invariant name (INV_*) for analytics and policy experiments.
  - Fail-closed: missing fields or broken invariants produce FAIL, not WARN.
  - Separate from claim_verifier.py (which checks receipt pack policy claims).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Stable Invariant Names
# ---------------------------------------------------------------------------
# These constants are the canonical identifiers for constitutional violations.
# Use them in check_name fields for analytics, dashboards, and Quintet policy.

INV_CLAIM_REQUIRED_FIELD = "claim_assertion_required_field"
INV_CLAIM_TYPE = "claim_assertion_type"
INV_CLAIM_ID_FORMAT = "claim_assertion_id_format"
INV_CLAIM_CLAIM_TYPE = "claim_assertion_claim_type"
INV_CLAIM_TEXT_LENGTH = "claim_assertion_text_length"
INV_CLAIM_BASIS_TYPE = "claim_assertion_basis_type"
INV_CLAIM_PROOF_TIER = "claim_assertion_proof_tier"
INV_CLAIM_BASIS_REFS = "claim_assertion_basis_refs"
INV_CLAIM_PARENT_FORMAT = "claim_assertion_parent_format"
INV_CLAIM_TIMESTAMP = "claim_assertion_timestamp"

INV_CHANGE_REQUIRED_FIELD = "support_change_required_field"
INV_CHANGE_TYPE = "support_change_type"
INV_CHANGE_ID_FORMAT = "support_change_id_format"
INV_CHANGE_CLAIM_ID = "support_change_claim_id"
INV_CHANGE_PRIOR_STATUS = "support_change_prior_status"
INV_CHANGE_NEW_STATUS = "support_change_new_status"
INV_CHANGE_TRANSITION = "support_change_transition"
INV_CHANGE_CHANGE_TYPE = "support_change_change_type"
INV_CHANGE_CONTRADICTION_REF = "support_change_contradiction_ref"
INV_CHANGE_DECISION_REF = "support_change_decision_ref"
INV_CHANGE_SUPPORTED_EVIDENCE = "support_change_supported_evidence"

INV_CTR_REG_REQUIRED_FIELD = "contradiction_reg_required_field"
INV_CTR_REG_TYPE = "contradiction_reg_type"
INV_CTR_REG_ID_FORMAT = "contradiction_reg_id_format"
INV_CTR_REG_CLAIM_FORMAT = "contradiction_reg_claim_format"
INV_CTR_REG_SELF = "contradiction_reg_self"
INV_CTR_REG_ORDERING = "contradiction_reg_ordering"
INV_CTR_REG_CONFLICT_TYPE = "contradiction_reg_conflict_type"
INV_CTR_REG_SEVERITY = "contradiction_reg_severity"
INV_CTR_REG_DETECTION_METHOD = "contradiction_reg_detection_method"
INV_CTR_REG_DETECTION_CONFIDENCE = "contradiction_reg_detection_confidence"
INV_CTR_REG_DETECTION_EVIDENCE = "contradiction_reg_detection_evidence"

INV_CTR_RES_REQUIRED_FIELD = "contradiction_res_required_field"
INV_CTR_RES_TYPE = "contradiction_res_type"
INV_CTR_RES_ID_FORMAT = "contradiction_res_id_format"
INV_CTR_RES_CONTRADICTION_REF = "contradiction_res_contradiction_ref"
INV_CTR_RES_OUTCOME = "contradiction_res_outcome"
INV_CTR_RES_RECONCILED_CLAIM = "contradiction_res_reconciled_claim"
INV_CTR_RES_PREVAILS_EVIDENCE = "contradiction_res_prevails_evidence"
INV_CTR_RES_AUTHORITY_TYPE = "contradiction_res_authority_type"

INV_CHAIN_DUPLICATE_CLAIM = "chain_duplicate_claim_id"
INV_CHAIN_PARENT_EXISTS = "chain_parent_claim_exists"
INV_CHAIN_PARENT_BACKWARD = "chain_parent_backward_ref"
INV_CHAIN_CHANGE_CLAIM_EXISTS = "chain_support_change_claim_exists"
INV_CHAIN_PRIOR_MISMATCH = "chain_support_prior_mismatch"
INV_CHAIN_RETRACTED_TERMINAL = "chain_retracted_terminal"
INV_CHAIN_CONTRADICTION_REF_EXISTS = "chain_contradiction_ref_exists"
INV_CHAIN_CTR_CLAIM_EXISTS = "chain_contradiction_claim_exists"
INV_CHAIN_CTR_BACKWARD = "chain_contradiction_backward_ref"
INV_CHAIN_CTR_DEDUP = "chain_contradiction_dedup"
INV_CHAIN_DUPLICATE_CTR = "chain_duplicate_contradiction_id"
INV_CHAIN_RES_CTR_EXISTS = "chain_resolution_contradiction_exists"
INV_CHAIN_RES_AFTER_REG = "chain_resolution_after_registration"
INV_CHAIN_RES_SUPERSEDING = "chain_resolution_superseding_claim"
INV_CHAIN_RES_CONSISTENCY = "chain_resolution_support_consistency"


# ---------------------------------------------------------------------------
# Additional invariants from live verifier checks
# ---------------------------------------------------------------------------

INV_CHANGE_TIMESTAMP = "support_change_timestamp"
INV_CHAIN_CHANGE_AFTER_ASSERTION = "chain_support_change_after_assertion"


# ---------------------------------------------------------------------------
# Invariant Categories
# ---------------------------------------------------------------------------

CAT_SHAPE = "shape"
CAT_REFERENCE = "reference_integrity"
CAT_TEMPORAL = "temporal_integrity"
CAT_TRANSITION = "state_transition"
CAT_DEDUP = "dedup"
CAT_CONSISTENCY = "consistency"

INVARIANT_CATEGORIES = {
    CAT_SHAPE, CAT_REFERENCE, CAT_TEMPORAL,
    CAT_TRANSITION, CAT_DEDUP, CAT_CONSISTENCY,
}

# Type aliases for stricter signatures
Severity = Literal["error", "warning"]
Category = Literal["shape", "reference_integrity", "temporal_integrity", "state_transition", "dedup", "consistency"]
ArtifactType = Literal["claim_assertion", "claim_support_change", "contradiction_registration", "contradiction_resolution"]

ARTIFACT_TYPES: Set[str] = {"claim_assertion", "claim_support_change", "contradiction_registration", "contradiction_resolution"}


# ---------------------------------------------------------------------------
# Invariant Registry
# ---------------------------------------------------------------------------
# Single constitutional index for Assay receipt rendering, Guardian policy
# tuning, Quintet experiments, and docs generation. Each entry:
#   code: stable string identifier (used in check_name)
#   severity: default severity level
#   category: invariant taxonomy class
#   meaning: one-line constitutional meaning
#   artifacts: which artifact classes this invariant applies to

@dataclass(frozen=True)
class InvariantEntry:
    """One constitutional invariant in the registry."""
    code: str
    severity: Severity
    category: Category
    meaning: str
    artifacts: Tuple[ArtifactType, ...]


INVARIANT_REGISTRY: Tuple[InvariantEntry, ...] = (
    # --- Claim assertion shape ---
    InvariantEntry(INV_CLAIM_REQUIRED_FIELD, "error", CAT_SHAPE, "Required field missing from claim_assertion", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_TYPE, "error", CAT_SHAPE, "artifact_type is not 'claim_assertion'", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_ID_FORMAT, "error", CAT_SHAPE, "claim_id does not match canonical pattern clm_[0-9a-f]{12}", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_CLAIM_TYPE, "error", CAT_SHAPE, "claim_type not in allowed enum", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_TEXT_LENGTH, "error", CAT_SHAPE, "claim_text exceeds 500 character maximum", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_BASIS_TYPE, "error", CAT_SHAPE, "basis_type not in allowed enum", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_PROOF_TIER, "error", CAT_SHAPE, "proof_tier_at_assertion not in allowed enum", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_BASIS_REFS, "error", CAT_SHAPE, "basis_refs is empty (promotion contract requires evidence)", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_PARENT_FORMAT, "error", CAT_SHAPE, "parent_claim_id does not match claim_id pattern", ("claim_assertion",)),
    InvariantEntry(INV_CLAIM_TIMESTAMP, "error", CAT_SHAPE, "timestamp is not valid ISO-8601", ("claim_assertion",)),

    # --- Support change shape ---
    InvariantEntry(INV_CHANGE_REQUIRED_FIELD, "error", CAT_SHAPE, "Required field missing from claim_support_change", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_TYPE, "error", CAT_SHAPE, "artifact_type is not 'claim_support_change'", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_ID_FORMAT, "error", CAT_SHAPE, "change_id does not match canonical pattern csc_[0-9a-f]{12}", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_CLAIM_ID, "error", CAT_REFERENCE, "claim_id reference does not match canonical pattern", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_PRIOR_STATUS, "error", CAT_SHAPE, "prior_support_status not in allowed enum", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_NEW_STATUS, "error", CAT_SHAPE, "new_support_status not in allowed enum", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_TRANSITION, "error", CAT_TRANSITION, "Support status transition is forbidden by constitutional law", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_CHANGE_TYPE, "error", CAT_SHAPE, "change_type not in allowed enum", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_CONTRADICTION_REF, "error", CAT_REFERENCE, "contradiction_id required when change_type is contradiction_registered or contradiction_resolved", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_DECISION_REF, "error", CAT_REFERENCE, "decision_receipt_id required when change_type is governance_decision", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_SUPPORTED_EVIDENCE, "error", CAT_SHAPE, "evidence_refs must be non-empty when transitioning to SUPPORTED", ("claim_support_change",)),
    InvariantEntry(INV_CHANGE_TIMESTAMP, "error", CAT_SHAPE, "timestamp is not valid ISO-8601", ("claim_support_change",)),

    # --- Contradiction registration shape ---
    InvariantEntry(INV_CTR_REG_REQUIRED_FIELD, "error", CAT_SHAPE, "Required field missing from contradiction_registration", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_TYPE, "error", CAT_SHAPE, "artifact_type is not 'contradiction_registration'", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_ID_FORMAT, "error", CAT_SHAPE, "contradiction_id does not match canonical pattern ctr_[0-9a-f]{12}", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_CLAIM_FORMAT, "error", CAT_SHAPE, "claim_a_id or claim_b_id does not match claim_id pattern", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_SELF, "error", CAT_REFERENCE, "A claim cannot contradict itself (claim_a_id == claim_b_id)", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_ORDERING, "error", CAT_DEDUP, "claim_a_id must be lexicographically <= claim_b_id (prevents duplicate registrations)", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_CONFLICT_TYPE, "error", CAT_SHAPE, "conflict_type not in allowed enum", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_SEVERITY, "error", CAT_SHAPE, "severity not in allowed enum", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_DETECTION_METHOD, "error", CAT_SHAPE, "detection_method not in allowed enum", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_DETECTION_CONFIDENCE, "error", CAT_SHAPE, "detection_confidence not in [0.0, 1.0]", ("contradiction_registration",)),
    InvariantEntry(INV_CTR_REG_DETECTION_EVIDENCE, "error", CAT_SHAPE, "detection_evidence_refs must be non-empty", ("contradiction_registration",)),

    # --- Contradiction resolution shape ---
    InvariantEntry(INV_CTR_RES_REQUIRED_FIELD, "error", CAT_SHAPE, "Required field missing from contradiction_resolution", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_TYPE, "error", CAT_SHAPE, "artifact_type is not 'contradiction_resolution'", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_ID_FORMAT, "error", CAT_SHAPE, "resolution_id does not match canonical pattern crr_[0-9a-f]{12}", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_CONTRADICTION_REF, "error", CAT_REFERENCE, "contradiction_id reference does not match canonical pattern", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_OUTCOME, "error", CAT_SHAPE, "resolution_outcome not in allowed enum", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_RECONCILED_CLAIM, "error", CAT_REFERENCE, "superseding_claim_id required when resolution_outcome is 'reconciled'", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_PREVAILS_EVIDENCE, "error", CAT_SHAPE, "evidence_refs required when resolution_outcome is claim_a/b_prevails", ("contradiction_resolution",)),
    InvariantEntry(INV_CTR_RES_AUTHORITY_TYPE, "error", CAT_SHAPE, "authority_type not in allowed enum", ("contradiction_resolution",)),

    # --- Chain / lifecycle legality ---
    InvariantEntry(INV_CHAIN_DUPLICATE_CLAIM, "error", CAT_DEDUP, "Two claim_assertion artifacts share the same claim_id", ("claim_assertion",)),
    InvariantEntry(INV_CHAIN_PARENT_EXISTS, "error", CAT_REFERENCE, "parent_claim_id does not resolve to a known claim_assertion", ("claim_assertion",)),
    InvariantEntry(INV_CHAIN_PARENT_BACKWARD, "error", CAT_TEMPORAL, "Child claim has earlier timestamp than its parent (backward reference violation)", ("claim_assertion",)),
    InvariantEntry(INV_CHAIN_CHANGE_CLAIM_EXISTS, "error", CAT_REFERENCE, "claim_support_change references a claim_id with no claim_assertion", ("claim_support_change",)),
    InvariantEntry(INV_CHAIN_CHANGE_AFTER_ASSERTION, "error", CAT_TEMPORAL, "claim_support_change timestamp precedes claim_assertion timestamp", ("claim_support_change",)),
    InvariantEntry(INV_CHAIN_PRIOR_MISMATCH, "error", CAT_TRANSITION, "prior_support_status does not match expected posture from chain (genesis is ASSERTED)", ("claim_support_change",)),
    InvariantEntry(INV_CHAIN_RETRACTED_TERMINAL, "error", CAT_TRANSITION, "Support change follows RETRACTED state (RETRACTED is terminal)", ("claim_support_change",)),
    InvariantEntry(INV_CHAIN_CONTRADICTION_REF_EXISTS, "error", CAT_REFERENCE, "claim_support_change references a contradiction_id with no contradiction_registration", ("claim_support_change",)),
    InvariantEntry(INV_CHAIN_CTR_CLAIM_EXISTS, "error", CAT_REFERENCE, "contradiction_registration references a claim_id with no claim_assertion", ("contradiction_registration",)),
    InvariantEntry(INV_CHAIN_CTR_BACKWARD, "error", CAT_TEMPORAL, "contradiction_registration timestamp precedes referenced claim timestamp", ("contradiction_registration",)),
    InvariantEntry(INV_CHAIN_CTR_DEDUP, "error", CAT_DEDUP, "Duplicate unresolved contradiction for same claim pair", ("contradiction_registration",)),
    InvariantEntry(INV_CHAIN_DUPLICATE_CTR, "error", CAT_DEDUP, "Two contradiction_registration artifacts share the same contradiction_id", ("contradiction_registration",)),
    InvariantEntry(INV_CHAIN_RES_CTR_EXISTS, "error", CAT_REFERENCE, "contradiction_resolution references a contradiction_id with no contradiction_registration", ("contradiction_resolution",)),
    InvariantEntry(INV_CHAIN_RES_AFTER_REG, "error", CAT_TEMPORAL, "contradiction_resolution timestamp precedes contradiction_registration timestamp", ("contradiction_resolution",)),
    InvariantEntry(INV_CHAIN_RES_SUPERSEDING, "error", CAT_REFERENCE, "superseding_claim_id does not resolve to a known claim_assertion", ("contradiction_resolution",)),
    InvariantEntry(INV_CHAIN_RES_CONSISTENCY, "warning", CAT_CONSISTENCY, "Resolution prevails but no corresponding claim_support_change found for losing claim", ("contradiction_resolution", "claim_support_change")),
)

# Lookup by code for programmatic access
INVARIANT_BY_CODE: Dict[str, InvariantEntry] = {
    entry.code: entry for entry in INVARIANT_REGISTRY
}


def invariants_for_artifact(artifact_type: str) -> Tuple[InvariantEntry, ...]:
    """Return all invariants that apply to a given artifact type.

    Tolerant query API: returns empty tuple for unknown artifact types.
    This is intentional — the registry is queried by dashboards, adapters,
    CLI tools, and exploratory code that should not crash on typos.
    """
    return tuple(e for e in INVARIANT_REGISTRY if artifact_type in e.artifacts)


def invariants_by_severity(severity: Severity) -> Tuple[InvariantEntry, ...]:
    """Return all invariants with the given severity."""
    return tuple(e for e in INVARIANT_REGISTRY if e.severity == severity)


def invariants_by_category(category: Category) -> Tuple[InvariantEntry, ...]:
    """Return all invariants in the given category."""
    return tuple(e for e in INVARIANT_REGISTRY if e.category == category)


# ---------------------------------------------------------------------------
# Genesis Posture Invariant
# ---------------------------------------------------------------------------
# A claim_assertion implicitly starts at ASSERTED posture. This is not stored
# inside the assertion — it is a constitutional default. The first
# claim_support_change for a claim_id must have prior_support_status=ASSERTED.
# This invariant is checked in verify_claim_chain.

GENESIS_POSTURE = "ASSERTED"


# ---------------------------------------------------------------------------
# ID Format & Canonical Serialization
# ---------------------------------------------------------------------------
# All IDs participating in lexicographic tiebreaks MUST use canonical textual
# form: lowercase hex, no hyphens, fixed length. The patterns below enforce
# this. Emitters MUST NOT emit uppercase, hyphenated, or variable-length IDs
# for claim/change/contradiction/resolution identifiers.

CLAIM_ID_PATTERN = re.compile(r"^clm_[0-9a-f]{12}$")
CHANGE_ID_PATTERN = re.compile(r"^csc_[0-9a-f]{12}$")
CONTRADICTION_ID_PATTERN = re.compile(r"^ctr_[0-9a-f]{12}$")
RESOLUTION_ID_PATTERN = re.compile(r"^crr_[0-9a-f]{12}$")

CLAIM_TYPES = {"FACTUAL", "CODE_OUTPUT", "CONSTRAINT", "POLICY", "SYNTHESIS"}
BASIS_TYPES = {"extracted", "policy_declared", "governance_inferred", "human_asserted"}
PROOF_TIERS = {"DRAFT", "CHECKED", "TOOL_VERIFIED", "ADVERSARIAL", "CONSTITUTIONAL"}

SUPPORT_STATUSES = {"ASSERTED", "SUPPORTED", "WEAKENED", "CONTRADICTED", "RETRACTED"}

CHANGE_TYPES = {
    "evidence_added",
    "evidence_removed",
    "verification_passed",
    "verification_failed",
    "verification_inconclusive",
    "contradiction_registered",
    "contradiction_resolved",
    "governance_decision",
    "retraction",
}

CONFLICT_TYPES = {
    "direct_negation",
    "inconsistent_evidence",
    "policy_conflict",
    "temporal_inconsistency",
    "scope_overlap",
}

SEVERITIES = {"critical", "high", "medium", "low"}

DETECTION_METHODS = {
    "automated_verification",
    "semantic_similarity",
    "opa_policy",
    "human_identified",
    "cross_episode",
}

RESOLUTION_OUTCOMES = {
    "claim_a_prevails",
    "claim_b_prevails",
    "both_retracted",
    "reconciled",
    "out_of_scope",
    "deferred",
}

AUTHORITY_TYPES = {
    "automated_verification",
    "governance_decision",
    "human_judgment",
    "new_evidence",
    "policy_update",
}

# Allowed support status transitions: {(from, to)}
ALLOWED_TRANSITIONS: Set[Tuple[str, str]] = {
    ("ASSERTED", "SUPPORTED"),
    ("ASSERTED", "WEAKENED"),
    ("ASSERTED", "CONTRADICTED"),
    ("ASSERTED", "RETRACTED"),
    ("SUPPORTED", "WEAKENED"),
    ("SUPPORTED", "CONTRADICTED"),
    ("SUPPORTED", "RETRACTED"),
    ("WEAKENED", "SUPPORTED"),
    ("WEAKENED", "CONTRADICTED"),
    ("WEAKENED", "RETRACTED"),
    ("CONTRADICTED", "SUPPORTED"),
    ("CONTRADICTED", "WEAKENED"),
    ("CONTRADICTED", "RETRACTED"),
}
# RETRACTED is terminal: no transitions from RETRACTED.


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of a single verification check."""
    check_name: str
    passed: bool
    message: str
    severity: str = "error"  # "error" or "warning"
    artifact_id: Optional[str] = None


@dataclass
class ChainVerificationResult:
    """Result of verifying an entire artifact chain."""
    passed: bool
    results: List[VerificationResult] = field(default_factory=list)
    error_count: int = 0
    warning_count: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso(ts: str) -> datetime:
    """Parse ISO-8601 timestamp."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _get(obj: Dict[str, Any], key: str) -> Any:
    """Get a field, return None if missing."""
    return obj.get(key)


def _require(
    obj: Dict[str, Any],
    keys: List[str],
    artifact_type: str,
    artifact_id: str,
) -> List[VerificationResult]:
    """Check required fields are present and non-null."""
    results = []
    for key in keys:
        val = obj.get(key)
        if val is None:
            results.append(VerificationResult(
                check_name=f"{artifact_type}_required_field",
                passed=False,
                message=f"Missing required field '{key}'",
                artifact_id=artifact_id,
            ))
    return results


# ---------------------------------------------------------------------------
# Claim Assertion Verifier
# ---------------------------------------------------------------------------

def verify_claim_assertion(artifact: Dict[str, Any]) -> List[VerificationResult]:
    """Verify a single claim_assertion artifact for shape validity."""
    results: List[VerificationResult] = []
    aid = artifact.get("claim_id", "<unknown>")

    # Required fields
    results.extend(_require(artifact, [
        "claim_id", "artifact_type", "schema_version", "timestamp",
        "episode_id", "claim_text", "claim_type", "checkable", "basis",
    ], "claim_assertion", aid))

    # Artifact type
    if artifact.get("artifact_type") != "claim_assertion":
        results.append(VerificationResult(
            "claim_assertion_type", False,
            f"artifact_type must be 'claim_assertion', got '{artifact.get('artifact_type')}'",
            artifact_id=aid,
        ))

    # ID format
    claim_id = artifact.get("claim_id", "")
    if not CLAIM_ID_PATTERN.match(claim_id):
        results.append(VerificationResult(
            "claim_assertion_id_format", False,
            f"claim_id '{claim_id}' does not match pattern clm_[0-9a-f]{{12}}",
            artifact_id=aid,
        ))

    # Claim type
    ct = artifact.get("claim_type")
    if ct and ct not in CLAIM_TYPES:
        results.append(VerificationResult(
            "claim_assertion_claim_type", False,
            f"claim_type '{ct}' not in {CLAIM_TYPES}",
            artifact_id=aid,
        ))

    # Claim text length
    text = artifact.get("claim_text", "")
    if isinstance(text, str) and len(text) > 500:
        results.append(VerificationResult(
            "claim_assertion_text_length", False,
            f"claim_text exceeds 500 chars ({len(text)})",
            artifact_id=aid,
        ))

    # Basis
    basis = artifact.get("basis")
    if isinstance(basis, dict):
        bt = basis.get("basis_type")
        if bt and bt not in BASIS_TYPES:
            results.append(VerificationResult(
                "claim_assertion_basis_type", False,
                f"basis_type '{bt}' not in {BASIS_TYPES}",
                artifact_id=aid,
            ))
        pt = basis.get("proof_tier_at_assertion")
        if pt and pt not in PROOF_TIERS:
            results.append(VerificationResult(
                "claim_assertion_proof_tier", False,
                f"proof_tier_at_assertion '{pt}' not in {PROOF_TIERS}",
                artifact_id=aid,
            ))
        refs = basis.get("basis_refs")
        if not refs or not isinstance(refs, list) or len(refs) == 0:
            results.append(VerificationResult(
                "claim_assertion_basis_refs", False,
                "basis_refs must be non-empty (promotion contract)",
                artifact_id=aid,
            ))

    # Parent claim backward reference (if present)
    parent = artifact.get("parent_claim_id")
    if parent is not None and not CLAIM_ID_PATTERN.match(parent):
        results.append(VerificationResult(
            "claim_assertion_parent_format", False,
            f"parent_claim_id '{parent}' does not match claim_id pattern",
            artifact_id=aid,
        ))

    # Timestamp parseable
    ts = artifact.get("timestamp")
    if ts:
        try:
            _parse_iso(ts)
        except (ValueError, TypeError):
            results.append(VerificationResult(
                "claim_assertion_timestamp", False,
                f"timestamp '{ts}' is not valid ISO-8601",
                artifact_id=aid,
            ))

    return results


# ---------------------------------------------------------------------------
# Claim Support Change Verifier
# ---------------------------------------------------------------------------

def verify_claim_support_change(artifact: Dict[str, Any]) -> List[VerificationResult]:
    """Verify a single claim_support_change artifact for shape validity."""
    results: List[VerificationResult] = []
    aid = artifact.get("change_id", "<unknown>")

    # Required fields
    results.extend(_require(artifact, [
        "change_id", "artifact_type", "schema_version", "timestamp",
        "claim_id", "episode_id", "prior_support_status",
        "new_support_status", "change_type", "evidence_refs",
    ], "claim_support_change", aid))

    # Artifact type
    if artifact.get("artifact_type") != "claim_support_change":
        results.append(VerificationResult(
            "support_change_type", False,
            f"artifact_type must be 'claim_support_change', got '{artifact.get('artifact_type')}'",
            artifact_id=aid,
        ))

    # ID format
    change_id = artifact.get("change_id", "")
    if not CHANGE_ID_PATTERN.match(change_id):
        results.append(VerificationResult(
            "support_change_id_format", False,
            f"change_id '{change_id}' does not match pattern csc_[0-9a-f]{{12}}",
            artifact_id=aid,
        ))

    # Claim ID format
    cid = artifact.get("claim_id", "")
    if cid and not CLAIM_ID_PATTERN.match(cid):
        results.append(VerificationResult(
            "support_change_claim_id", False,
            f"claim_id '{cid}' does not match claim_id pattern",
            artifact_id=aid,
        ))

    # Status enums
    prior = artifact.get("prior_support_status")
    new = artifact.get("new_support_status")
    if prior and prior not in SUPPORT_STATUSES:
        results.append(VerificationResult(
            "support_change_prior_status", False,
            f"prior_support_status '{prior}' not in {SUPPORT_STATUSES}",
            artifact_id=aid,
        ))
    if new and new not in SUPPORT_STATUSES:
        results.append(VerificationResult(
            "support_change_new_status", False,
            f"new_support_status '{new}' not in {SUPPORT_STATUSES}",
            artifact_id=aid,
        ))

    # Transition legality
    if prior and new and prior in SUPPORT_STATUSES and new in SUPPORT_STATUSES:
        if (prior, new) not in ALLOWED_TRANSITIONS:
            results.append(VerificationResult(
                "support_change_transition", False,
                f"Transition {prior} -> {new} is forbidden",
                artifact_id=aid,
            ))

    # Change type
    ct = artifact.get("change_type")
    if ct and ct not in CHANGE_TYPES:
        results.append(VerificationResult(
            "support_change_change_type", False,
            f"change_type '{ct}' not in {CHANGE_TYPES}",
            artifact_id=aid,
        ))

    # Contradiction ID required for contradiction change types
    if ct in ("contradiction_registered", "contradiction_resolved"):
        if not artifact.get("contradiction_id"):
            results.append(VerificationResult(
                "support_change_contradiction_ref", False,
                f"contradiction_id required when change_type is '{ct}'",
                artifact_id=aid,
            ))

    # Decision receipt ID required for governance_decision
    if ct == "governance_decision":
        if not artifact.get("decision_receipt_id"):
            results.append(VerificationResult(
                "support_change_decision_ref", False,
                "decision_receipt_id required when change_type is 'governance_decision'",
                artifact_id=aid,
            ))

    # Evidence refs required for SUPPORTED transitions
    if new == "SUPPORTED":
        refs = artifact.get("evidence_refs")
        if not refs or not isinstance(refs, list) or len(refs) == 0:
            results.append(VerificationResult(
                "support_change_supported_evidence", False,
                "evidence_refs must be non-empty when new_support_status is SUPPORTED",
                artifact_id=aid,
            ))

    # Timestamp parseable
    ts = artifact.get("timestamp")
    if ts:
        try:
            _parse_iso(ts)
        except (ValueError, TypeError):
            results.append(VerificationResult(
                "support_change_timestamp", False,
                f"timestamp '{ts}' is not valid ISO-8601",
                artifact_id=aid,
            ))

    return results


# ---------------------------------------------------------------------------
# Contradiction Registration Verifier
# ---------------------------------------------------------------------------

def verify_contradiction_registration(
    artifact: Dict[str, Any],
) -> List[VerificationResult]:
    """Verify a single contradiction_registration for shape validity."""
    results: List[VerificationResult] = []
    aid = artifact.get("contradiction_id", "<unknown>")

    # Required fields
    results.extend(_require(artifact, [
        "contradiction_id", "artifact_type", "schema_version", "timestamp",
        "episode_id", "claim_a_id", "claim_b_id", "conflict_type",
        "severity", "detection",
    ], "contradiction_registration", aid))

    # Artifact type
    if artifact.get("artifact_type") != "contradiction_registration":
        results.append(VerificationResult(
            "contradiction_reg_type", False,
            f"artifact_type must be 'contradiction_registration', got '{artifact.get('artifact_type')}'",
            artifact_id=aid,
        ))

    # ID format
    ctr_id = artifact.get("contradiction_id", "")
    if not CONTRADICTION_ID_PATTERN.match(ctr_id):
        results.append(VerificationResult(
            "contradiction_reg_id_format", False,
            f"contradiction_id '{ctr_id}' does not match pattern ctr_[0-9a-f]{{12}}",
            artifact_id=aid,
        ))

    # Claim ID formats
    a_id = artifact.get("claim_a_id", "")
    b_id = artifact.get("claim_b_id", "")
    if a_id and not CLAIM_ID_PATTERN.match(a_id):
        results.append(VerificationResult(
            "contradiction_reg_claim_a_format", False,
            f"claim_a_id '{a_id}' does not match claim_id pattern",
            artifact_id=aid,
        ))
    if b_id and not CLAIM_ID_PATTERN.match(b_id):
        results.append(VerificationResult(
            "contradiction_reg_claim_b_format", False,
            f"claim_b_id '{b_id}' does not match claim_id pattern",
            artifact_id=aid,
        ))

    # No self-contradiction
    if a_id and b_id and a_id == b_id:
        results.append(VerificationResult(
            "contradiction_reg_self", False,
            f"claim_a_id and claim_b_id are identical: '{a_id}'",
            artifact_id=aid,
        ))

    # Lexicographic ordering
    if a_id and b_id and a_id > b_id:
        results.append(VerificationResult(
            "contradiction_reg_ordering", False,
            f"claim_a_id must be <= claim_b_id (lexicographic). Got a='{a_id}', b='{b_id}'",
            artifact_id=aid,
        ))

    # Conflict type
    ct = artifact.get("conflict_type")
    if ct and ct not in CONFLICT_TYPES:
        results.append(VerificationResult(
            "contradiction_reg_conflict_type", False,
            f"conflict_type '{ct}' not in {CONFLICT_TYPES}",
            artifact_id=aid,
        ))

    # Severity
    sev = artifact.get("severity")
    if sev and sev not in SEVERITIES:
        results.append(VerificationResult(
            "contradiction_reg_severity", False,
            f"severity '{sev}' not in {SEVERITIES}",
            artifact_id=aid,
        ))

    # Detection object
    det = artifact.get("detection")
    if isinstance(det, dict):
        dm = det.get("detection_method")
        if dm and dm not in DETECTION_METHODS:
            results.append(VerificationResult(
                "contradiction_reg_detection_method", False,
                f"detection_method '{dm}' not in {DETECTION_METHODS}",
                artifact_id=aid,
            ))
        dc = det.get("detection_confidence")
        if dc is not None and (not isinstance(dc, (int, float)) or dc < 0.0 or dc > 1.0):
            results.append(VerificationResult(
                "contradiction_reg_detection_confidence", False,
                f"detection_confidence must be in [0.0, 1.0], got {dc}",
                artifact_id=aid,
            ))
        refs = det.get("detection_evidence_refs")
        if not refs or not isinstance(refs, list) or len(refs) == 0:
            results.append(VerificationResult(
                "contradiction_reg_detection_evidence", False,
                "detection.detection_evidence_refs must be non-empty",
                artifact_id=aid,
            ))

    return results


# ---------------------------------------------------------------------------
# Contradiction Resolution Verifier
# ---------------------------------------------------------------------------

def verify_contradiction_resolution(
    artifact: Dict[str, Any],
) -> List[VerificationResult]:
    """Verify a single contradiction_resolution for shape validity."""
    results: List[VerificationResult] = []
    aid = artifact.get("resolution_id", "<unknown>")

    # Required fields
    results.extend(_require(artifact, [
        "resolution_id", "artifact_type", "schema_version", "timestamp",
        "contradiction_id", "episode_id", "resolution_outcome",
        "resolution_basis",
    ], "contradiction_resolution", aid))

    # Artifact type
    if artifact.get("artifact_type") != "contradiction_resolution":
        results.append(VerificationResult(
            "contradiction_res_type", False,
            f"artifact_type must be 'contradiction_resolution', got '{artifact.get('artifact_type')}'",
            artifact_id=aid,
        ))

    # ID formats
    res_id = artifact.get("resolution_id", "")
    if not RESOLUTION_ID_PATTERN.match(res_id):
        results.append(VerificationResult(
            "contradiction_res_id_format", False,
            f"resolution_id '{res_id}' does not match pattern crr_[0-9a-f]{{12}}",
            artifact_id=aid,
        ))

    ctr_id = artifact.get("contradiction_id", "")
    if ctr_id and not CONTRADICTION_ID_PATTERN.match(ctr_id):
        results.append(VerificationResult(
            "contradiction_res_contradiction_ref", False,
            f"contradiction_id '{ctr_id}' does not match pattern",
            artifact_id=aid,
        ))

    # Resolution outcome
    outcome = artifact.get("resolution_outcome")
    if outcome and outcome not in RESOLUTION_OUTCOMES:
        results.append(VerificationResult(
            "contradiction_res_outcome", False,
            f"resolution_outcome '{outcome}' not in {RESOLUTION_OUTCOMES}",
            artifact_id=aid,
        ))

    # Reconciled requires superseding_claim_id
    if outcome == "reconciled" and not artifact.get("superseding_claim_id"):
        results.append(VerificationResult(
            "contradiction_res_reconciled_claim", False,
            "superseding_claim_id required when resolution_outcome is 'reconciled'",
            artifact_id=aid,
        ))

    # Prevails requires evidence
    if outcome in ("claim_a_prevails", "claim_b_prevails"):
        basis = artifact.get("resolution_basis")
        if isinstance(basis, dict):
            refs = basis.get("evidence_refs")
            if not refs or not isinstance(refs, list) or len(refs) == 0:
                results.append(VerificationResult(
                    "contradiction_res_prevails_evidence", False,
                    f"evidence_refs required when resolution_outcome is '{outcome}'",
                    artifact_id=aid,
                ))

    # Resolution basis
    basis = artifact.get("resolution_basis")
    if isinstance(basis, dict):
        at = basis.get("authority_type")
        if at and at not in AUTHORITY_TYPES:
            results.append(VerificationResult(
                "contradiction_res_authority_type", False,
                f"authority_type '{at}' not in {AUTHORITY_TYPES}",
                artifact_id=aid,
            ))

    return results


# ---------------------------------------------------------------------------
# Chain Verifier (lifecycle legality across artifact sequence)
# ---------------------------------------------------------------------------

def verify_claim_chain(
    assertions: List[Dict[str, Any]],
    support_changes: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    resolutions: List[Dict[str, Any]],
) -> ChainVerificationResult:
    """Verify lifecycle legality across a chain of protocol claim artifacts.

    This is the key verifier: it checks cross-artifact invariants that
    individual artifact shape checks cannot catch.

    Args:
        assertions: List of claim_assertion artifacts.
        support_changes: List of claim_support_change artifacts.
        contradictions: List of contradiction_registration artifacts.
        resolutions: List of contradiction_resolution artifacts.

    Returns:
        ChainVerificationResult with all checks.
    """
    results: List[VerificationResult] = []

    # Build indexes
    known_claims: Dict[str, Dict[str, Any]] = {}
    for a in assertions:
        cid = a.get("claim_id", "")
        if cid in known_claims:
            results.append(VerificationResult(
                "chain_duplicate_claim_id", False,
                f"Duplicate claim_id: '{cid}'",
                artifact_id=cid,
            ))
        known_claims[cid] = a

    known_contradictions: Dict[str, Dict[str, Any]] = {}
    for c in contradictions:
        ctrid = c.get("contradiction_id", "")
        if ctrid in known_contradictions:
            results.append(VerificationResult(
                "chain_duplicate_contradiction_id", False,
                f"Duplicate contradiction_id: '{ctrid}'",
                artifact_id=ctrid,
            ))
        known_contradictions[ctrid] = c

    # --- Claim assertion checks ---

    # Parent claim references must resolve
    for a in assertions:
        parent = a.get("parent_claim_id")
        if parent and parent not in known_claims:
            results.append(VerificationResult(
                "chain_parent_claim_exists", False,
                f"parent_claim_id '{parent}' does not resolve to a known claim_assertion",
                artifact_id=a.get("claim_id"),
            ))
        # Parent must have earlier timestamp (backward reference)
        if parent and parent in known_claims:
            parent_ts = known_claims[parent].get("timestamp", "")
            child_ts = a.get("timestamp", "")
            if parent_ts and child_ts:
                try:
                    if _parse_iso(child_ts) < _parse_iso(parent_ts):
                        results.append(VerificationResult(
                            "chain_parent_backward_ref", False,
                            f"claim '{a.get('claim_id')}' has parent '{parent}' with later timestamp",
                            artifact_id=a.get("claim_id"),
                        ))
                except (ValueError, TypeError):
                    pass

    # --- Support change chain checks ---

    # Group changes by claim_id, sort by (timestamp, change_id)
    changes_by_claim: Dict[str, List[Dict[str, Any]]] = {}
    for sc in support_changes:
        cid = sc.get("claim_id", "")
        changes_by_claim.setdefault(cid, []).append(sc)

    for cid, changes in changes_by_claim.items():
        # Claim must exist
        if cid not in known_claims:
            results.append(VerificationResult(
                "chain_support_change_claim_exists", False,
                f"claim_support_change references claim_id '{cid}' which has no claim_assertion",
                artifact_id=changes[0].get("change_id"),
            ))

        # Sort by (timestamp, change_id) for total order
        def sort_key(sc: Dict[str, Any]) -> Tuple[str, str]:
            return (sc.get("timestamp", ""), sc.get("change_id", ""))

        sorted_changes = sorted(changes, key=sort_key)

        # Walk the chain
        expected_prior = GENESIS_POSTURE
        claim_ts = known_claims.get(cid, {}).get("timestamp", "")
        for sc in sorted_changes:
            prior = sc.get("prior_support_status")
            new = sc.get("new_support_status")
            scid = sc.get("change_id", "<unknown>")

            if claim_ts and sc.get("timestamp"):
                try:
                    if _parse_iso(sc["timestamp"]) < _parse_iso(claim_ts):
                        results.append(VerificationResult(
                            "chain_support_change_after_assertion", False,
                            f"change '{scid}' has timestamp before claim_assertion '{cid}'",
                            artifact_id=scid,
                        ))
                except (ValueError, TypeError):
                    pass

            # Prior must match expected
            if prior != expected_prior:
                results.append(VerificationResult(
                    "chain_support_prior_mismatch", False,
                    f"change '{scid}' has prior_support_status='{prior}' "
                    f"but expected '{expected_prior}' based on chain",
                    artifact_id=scid,
                ))

            # Terminality: no changes after RETRACTED
            if expected_prior == "RETRACTED":
                results.append(VerificationResult(
                    "chain_retracted_terminal", False,
                    f"change '{scid}' follows RETRACTED state for claim '{cid}' — RETRACTED is terminal",
                    artifact_id=scid,
                ))

            expected_prior = new if new else expected_prior

        # Contradiction references must resolve
        for sc in sorted_changes:
            ct = sc.get("change_type")
            if ct in ("contradiction_registered", "contradiction_resolved"):
                ctrid = sc.get("contradiction_id")
                if ctrid and ctrid not in known_contradictions:
                    results.append(VerificationResult(
                        "chain_contradiction_ref_exists", False,
                        f"change '{sc.get('change_id')}' references contradiction_id "
                        f"'{ctrid}' which has no contradiction_registration",
                        artifact_id=sc.get("change_id"),
                    ))

    # --- Contradiction registration checks ---

    for c in contradictions:
        ctrid = c.get("contradiction_id", "<unknown>")
        a_id = c.get("claim_a_id", "")
        b_id = c.get("claim_b_id", "")

        # Both claims must exist
        if a_id not in known_claims:
            results.append(VerificationResult(
                "chain_contradiction_claim_a_exists", False,
                f"contradiction '{ctrid}' references claim_a_id '{a_id}' "
                f"which has no claim_assertion",
                artifact_id=ctrid,
            ))
        if b_id not in known_claims:
            results.append(VerificationResult(
                "chain_contradiction_claim_b_exists", False,
                f"contradiction '{ctrid}' references claim_b_id '{b_id}' "
                f"which has no claim_assertion",
                artifact_id=ctrid,
            ))

        # Claims must have earlier timestamps (backward reference)
        c_ts = c.get("timestamp", "")
        for ref_id, label in [(a_id, "claim_a"), (b_id, "claim_b")]:
            if ref_id in known_claims:
                ref_ts = known_claims[ref_id].get("timestamp", "")
                if c_ts and ref_ts:
                    try:
                        if _parse_iso(c_ts) < _parse_iso(ref_ts):
                            results.append(VerificationResult(
                                f"chain_contradiction_{label}_backward", False,
                                f"contradiction '{ctrid}' has timestamp before "
                                f"{label}_id '{ref_id}'",
                                artifact_id=ctrid,
                            ))
                    except (ValueError, TypeError):
                        pass

    # Dedup: no two unresolved contradictions for same claim pair
    # Build resolution index first
    resolved_contradictions: Set[str] = set()
    terminal_outcomes = {"claim_a_prevails", "claim_b_prevails", "both_retracted", "reconciled", "out_of_scope"}
    for r in resolutions:
        ctrid = r.get("contradiction_id", "")
        outcome = r.get("resolution_outcome", "")
        if outcome in terminal_outcomes:
            resolved_contradictions.add(ctrid)

    active_pairs: Dict[Tuple[str, str], str] = {}
    for c in contradictions:
        ctrid = c.get("contradiction_id", "")
        pair = (c.get("claim_a_id", ""), c.get("claim_b_id", ""))
        if pair[0] and pair[1]:
            if ctrid not in resolved_contradictions:
                if pair in active_pairs:
                    results.append(VerificationResult(
                        "chain_contradiction_dedup", False,
                        f"Duplicate unresolved contradiction for pair {pair}: "
                        f"'{active_pairs[pair]}' and '{ctrid}'",
                        artifact_id=ctrid,
                    ))
                else:
                    active_pairs[pair] = ctrid

    # --- Contradiction resolution checks ---

    for r in resolutions:
        rid = r.get("resolution_id", "<unknown>")
        ctrid = r.get("contradiction_id", "")

        # Must reference existing contradiction
        if ctrid not in known_contradictions:
            results.append(VerificationResult(
                "chain_resolution_contradiction_exists", False,
                f"resolution '{rid}' references contradiction_id '{ctrid}' "
                f"which has no contradiction_registration",
                artifact_id=rid,
            ))

        # Resolution must have later timestamp than registration
        if ctrid in known_contradictions:
            reg_ts = known_contradictions[ctrid].get("timestamp", "")
            res_ts = r.get("timestamp", "")
            if reg_ts and res_ts:
                try:
                    if _parse_iso(res_ts) < _parse_iso(reg_ts):
                        results.append(VerificationResult(
                            "chain_resolution_after_registration", False,
                            f"resolution '{rid}' has timestamp before "
                            f"contradiction '{ctrid}'",
                            artifact_id=rid,
                        ))
                except (ValueError, TypeError):
                    pass

        # Reconciled: superseding_claim_id must resolve
        outcome = r.get("resolution_outcome")
        if outcome == "reconciled":
            sup_id = r.get("superseding_claim_id")
            if sup_id and sup_id not in known_claims:
                results.append(VerificationResult(
                    "chain_resolution_superseding_claim", False,
                    f"resolution '{rid}' references superseding_claim_id '{sup_id}' "
                    f"which has no claim_assertion",
                    artifact_id=rid,
                ))

    # --- Cross-artifact consistency warnings ---
    #
    # Why warnings instead of errors for resolution/support-change consistency:
    #
    # 1. The contradiction_resolution artifact is constitutionally valid on
    #    its own — it records an authority act with evidence basis.
    # 2. Corresponding claim_support_changes are RECOMMENDED side effects,
    #    not fused into the resolution artifact. Resolution and posture
    #    updates may be emitted in different episodes or at different times.
    # 3. Missing support changes weaken governance clarity but do not
    #    invalidate the resolution itself.
    # 4. Temporary incompleteness is expected. Long-lived inconsistency
    #    (e.g., after episode finalization) is a Guardian/policy concern,
    #    not a protocol verifier concern at v0.
    #
    # If a contradiction is resolved with claim_a/b_prevails,
    # check that corresponding claim_support_change exists (warning, not error)
    for r in resolutions:
        rid = r.get("resolution_id", "<unknown>")
        ctrid = r.get("contradiction_id", "")
        outcome = r.get("resolution_outcome", "")

        if outcome in ("claim_a_prevails", "claim_b_prevails") and ctrid in known_contradictions:
            reg = known_contradictions[ctrid]
            losing_id = reg.get("claim_b_id") if outcome == "claim_a_prevails" else reg.get("claim_a_id")

            # Check if a support change exists for the losing claim
            # with contradiction_resolved change_type
            losing_changes = changes_by_claim.get(losing_id, [])
            has_resolution_change = any(
                sc.get("change_type") == "contradiction_resolved"
                and sc.get("contradiction_id") == ctrid
                for sc in losing_changes
            )
            if not has_resolution_change:
                results.append(VerificationResult(
                    "chain_resolution_support_consistency", True,
                    f"resolution '{rid}' resolves '{outcome}' but no "
                    f"claim_support_change with contradiction_resolved found "
                    f"for losing claim '{losing_id}' — this is a warning, "
                    f"not an error (side effects are RECOMMENDED, not required)",
                    severity="warning",
                    artifact_id=rid,
                ))

    # Compute totals
    error_count = sum(1 for r in results if not r.passed and r.severity == "error")
    warning_count = sum(1 for r in results if r.severity == "warning")
    passed = error_count == 0

    return ChainVerificationResult(
        passed=passed,
        results=results,
        error_count=error_count,
        warning_count=warning_count,
    )
