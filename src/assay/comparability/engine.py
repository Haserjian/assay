"""Denial engine: evaluates a contract against two evidence bundles.

This is the core of the comparability subsystem. It produces a
ConstitutionalDiff — the product artifact with teeth.

Algorithm:
  1. Check each parity field in the contract
  2. Collect mismatches with severity
  3. Determine verdict:
     - Any INVALIDATING mismatch → DENIED (even if fields are missing)
     - Only missing fields, no mismatches → UNDETERMINED
     - Only DEGRADING mismatches → DOWNGRADED
     - All matched → SATISFIED
  4. Compute instrument continuity
  5. Compute bundle completeness
  6. Derive consequence from verdict
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from assay.comparability.bundle import EvidenceBundle
from assay.comparability.contract import ComparabilityContract, ParityField
from assay.comparability.match_rules import apply_rule
from assay.comparability.types import (
    FieldRequirement,
    BundleCompleteness,
    ClaimStatus,
    ClaimUnderTest,
    Consequence,
    ConstitutionalDiff,
    InstrumentContinuity,
    Mismatch,
    ParityFieldGroup,
    Severity,
    Verdict,
)


# ---------------------------------------------------------------------------
# Consequence derivation
# ---------------------------------------------------------------------------

_CONSEQUENCE_MAP: Dict[Verdict, Consequence] = {
    Verdict.SATISFIED: Consequence(
        claim_status=ClaimStatus.ADMISSIBLE,
    ),
    Verdict.DOWNGRADED: Consequence(
        claim_status=ClaimStatus.ADMISSIBLE_WITH_CAVEAT,
        blocked_actions=["report_without_caveat"],
        required_actions=["attach_mismatch_disclosure"],
    ),
    Verdict.DENIED: Consequence(
        claim_status=ClaimStatus.INADMISSIBLE,
        blocked_actions=[
            "promotion",
            "leaderboard_entry",
            "benchmark_claim",
            "budget_movement",
        ],
        required_actions=["rerun_under_pinned_config"],
    ),
    Verdict.UNDETERMINED: Consequence(
        claim_status=ClaimStatus.PENDING_REVIEW,
        blocked_actions=["all_automated_actions"],
        required_actions=["complete_evidence_bundle"],
    ),
}


def _derive_consequence(verdict: Verdict) -> Consequence:
    """Map verdict to consequence. Returns a copy."""
    template = _CONSEQUENCE_MAP[verdict]
    return Consequence(
        claim_status=template.claim_status,
        blocked_actions=list(template.blocked_actions),
        required_actions=list(template.required_actions),
    )


# ---------------------------------------------------------------------------
# Instrument continuity
# ---------------------------------------------------------------------------

def _compute_instrument_continuity(
    mismatches: List[Mismatch],
    missing_instrument_fields: List[str],
) -> InstrumentContinuity:
    """Determine whether the measurement instrument is the same.

    Broken if any instrument_identity field has an INVALIDATING mismatch.
    Unknown if instrument_identity fields are missing.
    Preserved otherwise.
    """
    instrument_mismatches = [
        m for m in mismatches
        if m.group == ParityFieldGroup.INSTRUMENT_IDENTITY
        and m.severity == Severity.INVALIDATING
    ]
    if instrument_mismatches:
        return InstrumentContinuity.BROKEN
    if missing_instrument_fields:
        return InstrumentContinuity.UNKNOWN
    return InstrumentContinuity.PRESERVED


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

def evaluate(
    contract: ComparabilityContract,
    baseline: EvidenceBundle,
    candidate: EvidenceBundle,
    *,
    claim: Optional[ClaimUnderTest] = None,
) -> ConstitutionalDiff:
    """Evaluate a comparability contract against two evidence bundles.

    This is the denial engine. It produces a ConstitutionalDiff with:
      - verdict
      - mismatches (with severity and grouping)
      - instrument continuity
      - bundle completeness
      - consequence

    Args:
        contract: The comparability contract to evaluate.
        baseline: Evidence bundle from the baseline run.
        candidate: Evidence bundle from the candidate run.
        claim: Optional claim under test (for labeling the diff).

    Returns:
        ConstitutionalDiff with full evaluation results.
    """
    mismatches: List[Mismatch] = []
    satisfied: List[str] = []
    missing_fields: List[str] = []
    missing_instrument_fields: List[str] = []

    for pf in contract.parity_fields:
        baseline_val = baseline.get(pf.field)
        candidate_val = candidate.get(pf.field)

        # Missing field handling
        baseline_missing = not baseline.has(pf.field)
        candidate_missing = not candidate.has(pf.field)

        if baseline_missing or candidate_missing:
            # OPTIONAL fields that are absent should not drive UNDETERMINED.
            # Only REQUIRED fields count as "missing" for verdict purposes.
            if pf.requirement == FieldRequirement.REQUIRED:
                missing_fields.append(pf.field)
                if pf.group == ParityFieldGroup.INSTRUMENT_IDENTITY:
                    missing_instrument_fields.append(pf.field)
            continue

        # Apply match rule
        matched = apply_rule(
            pf.match_rule,
            baseline_val,
            candidate_val,
            **pf.rule_params,
        )

        if matched:
            satisfied.append(pf.field)
        else:
            mismatches.append(Mismatch(
                field=pf.field,
                baseline_value=baseline_val,
                candidate_value=candidate_val,
                severity=pf.severity,
                rule=pf.match_rule,
                group=pf.group,
                explanation=pf.rationale,
            ))

    # --- Verdict determination ---
    # Rule: INVALIDATING mismatch → DENIED, even if other fields are missing.
    has_invalidating = any(
        m.severity == Severity.INVALIDATING for m in mismatches
    )
    has_degrading = any(
        m.severity == Severity.DEGRADING for m in mismatches
    )

    if has_invalidating:
        verdict = Verdict.DENIED
    elif has_degrading and not missing_fields:
        verdict = Verdict.DOWNGRADED
    elif missing_fields and not has_degrading:
        verdict = Verdict.UNDETERMINED
    elif missing_fields and has_degrading:
        # Missing fields + degrading = still undetermined.
        # Can't be confident in DOWNGRADED when we don't have full picture.
        verdict = Verdict.UNDETERMINED
    else:
        verdict = Verdict.SATISFIED

    # --- Compute completeness ---
    required = contract.required_field_names()
    baseline_completeness = baseline.completeness(required)
    candidate_completeness = candidate.completeness(required)

    # --- Instrument continuity ---
    instrument_continuity = _compute_instrument_continuity(
        mismatches, missing_instrument_fields
    )

    # --- Consequence ---
    consequence = _derive_consequence(verdict)

    # --- Build the diff ---
    diff = ConstitutionalDiff(
        baseline_ref=baseline.ref,
        candidate_ref=candidate.ref,
        baseline_label=baseline.label,
        candidate_label=candidate.label,
        claim=claim,
        verdict=verdict,
        mismatches=mismatches,
        satisfied_fields=satisfied,
        instrument_continuity=instrument_continuity,
        baseline_completeness=baseline_completeness,
        candidate_completeness=candidate_completeness,
        consequence=consequence,
        contract_id=contract.contract_id,
        contract_version=contract.version,
        contract_hash=contract.content_hash(),
    )

    return diff
