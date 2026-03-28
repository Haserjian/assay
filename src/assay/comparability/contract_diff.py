"""Contract diff: replay evidence bundles under two contracts, diff verdicts.

Given two contract versions and a corpus of evidence bundle pairs,
this module:
  1. Evaluates each pair under both contracts
  2. Identifies verdict flips (e.g., DENIED -> DOWNGRADED)
  3. Emits clause-level reasons for each flip

This is the replay engine. It is deterministic: same inputs produce
the same diff report every time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from assay.comparability.bundle import EvidenceBundle
from assay.comparability.contract import ComparabilityContract, ParityField
from assay.comparability.engine import evaluate
from assay.comparability.types import Severity, Verdict


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class ClauseChange:
    """A single field whose contract rule changed between versions."""
    field: str
    old_severity: Severity
    new_severity: Severity
    old_match_rule: str
    new_match_rule: str
    change_type: str  # "severity_relaxed", "severity_tightened", "rule_changed", "field_added", "field_removed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "old_severity": self.old_severity.value,
            "new_severity": self.new_severity.value,
            "old_match_rule": self.old_match_rule,
            "new_match_rule": self.new_match_rule,
            "change_type": self.change_type,
        }


@dataclass
class VerdictFlip:
    """A single bundle pair whose verdict changed between contract versions."""
    bundle_ref: str
    old_verdict: Verdict
    new_verdict: Verdict
    triggering_clauses: List[ClauseChange]
    triggering_field: str  # The specific field mismatch that caused the flip
    reason: str  # Human-readable explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_ref": self.bundle_ref,
            "old_verdict": self.old_verdict.value,
            "new_verdict": self.new_verdict.value,
            "triggering_clauses": [c.to_dict() for c in self.triggering_clauses],
            "triggering_field": self.triggering_field,
            "reason": self.reason,
        }


@dataclass
class ContractDiffReport:
    """Full report comparing two contract versions over a bundle corpus."""
    old_contract_id: str
    old_contract_version: str
    old_contract_hash: str
    new_contract_id: str
    new_contract_version: str
    new_contract_hash: str
    clause_changes: List[ClauseChange]
    flips: List[VerdictFlip]
    total_pairs: int
    stable_count: int  # pairs with no verdict change

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_diff": {
                "old": {
                    "id": self.old_contract_id,
                    "version": self.old_contract_version,
                    "hash": self.old_contract_hash,
                },
                "new": {
                    "id": self.new_contract_id,
                    "version": self.new_contract_version,
                    "hash": self.new_contract_hash,
                },
                "clause_changes": [c.to_dict() for c in self.clause_changes],
                "summary": {
                    "total_pairs": self.total_pairs,
                    "flips": len(self.flips),
                    "stable": self.stable_count,
                },
                "flips": [f.to_dict() for f in self.flips],
            }
        }


# ---------------------------------------------------------------------------
# Contract comparison (structural)
# ---------------------------------------------------------------------------

def diff_contracts(
    old: ComparabilityContract,
    new: ComparabilityContract,
) -> List[ClauseChange]:
    """Find structural differences between two contract versions.

    Returns a list of clause changes (field-level diffs).
    """
    old_fields = {pf.field: pf for pf in old.parity_fields}
    new_fields = {pf.field: pf for pf in new.parity_fields}

    changes: List[ClauseChange] = []

    # Fields in both contracts
    for field_name in sorted(set(old_fields) & set(new_fields)):
        old_pf = old_fields[field_name]
        new_pf = new_fields[field_name]

        severity_changed = old_pf.severity != new_pf.severity
        rule_changed = old_pf.match_rule != new_pf.match_rule

        if severity_changed or rule_changed:
            if severity_changed and not rule_changed:
                # Determine direction
                severity_order = {
                    Severity.INFORMATIONAL: 0,
                    Severity.DEGRADING: 1,
                    Severity.INVALIDATING: 2,
                }
                if severity_order[new_pf.severity] < severity_order[old_pf.severity]:
                    change_type = "severity_relaxed"
                else:
                    change_type = "severity_tightened"
            elif rule_changed:
                change_type = "rule_changed"
            else:
                change_type = "severity_relaxed"  # both changed

            changes.append(ClauseChange(
                field=field_name,
                old_severity=old_pf.severity,
                new_severity=new_pf.severity,
                old_match_rule=old_pf.match_rule,
                new_match_rule=new_pf.match_rule,
                change_type=change_type,
            ))

    # Fields only in old (removed)
    for field_name in sorted(set(old_fields) - set(new_fields)):
        old_pf = old_fields[field_name]
        changes.append(ClauseChange(
            field=field_name,
            old_severity=old_pf.severity,
            new_severity=Severity.INFORMATIONAL,  # effectively removed
            old_match_rule=old_pf.match_rule,
            new_match_rule="",
            change_type="field_removed",
        ))

    # Fields only in new (added)
    for field_name in sorted(set(new_fields) - set(old_fields)):
        new_pf = new_fields[field_name]
        changes.append(ClauseChange(
            field=field_name,
            old_severity=Severity.INFORMATIONAL,  # effectively absent
            new_severity=new_pf.severity,
            old_match_rule="",
            new_match_rule=new_pf.match_rule,
            change_type="field_added",
        ))

    return changes


# ---------------------------------------------------------------------------
# Verdict replay
# ---------------------------------------------------------------------------

def _find_triggering_field(
    old_diff,
    new_diff,
    clause_changes: List[ClauseChange],
) -> tuple[str, str]:
    """Identify which field mismatch caused the verdict flip.

    Returns (field_name, reason_string).
    """
    changed_fields = {c.field for c in clause_changes}

    # Find mismatches that exist in old but changed severity in new
    old_mismatches = {m.field: m for m in old_diff.mismatches}
    new_mismatches = {m.field: m for m in new_diff.mismatches}

    for cc in clause_changes:
        if cc.field in old_mismatches:
            old_m = old_mismatches[cc.field]
            new_m = new_mismatches.get(cc.field)

            if cc.change_type == "severity_relaxed":
                reason = (
                    f"{cc.field}: severity relaxed from {cc.old_severity.value} "
                    f"to {cc.new_severity.value}"
                )
                return cc.field, reason
            elif cc.change_type == "severity_tightened":
                reason = (
                    f"{cc.field}: severity tightened from {cc.old_severity.value} "
                    f"to {cc.new_severity.value}"
                )
                return cc.field, reason
            elif cc.change_type == "field_removed":
                reason = f"{cc.field}: field removed from contract"
                return cc.field, reason

    # Check for newly added fields that caused mismatches
    for cc in clause_changes:
        if cc.change_type == "field_added" and cc.field in new_mismatches:
            reason = f"{cc.field}: new required field added to contract"
            return cc.field, reason

    return "unknown", "verdict flip cause could not be determined"


def replay(
    old_contract: ComparabilityContract,
    new_contract: ComparabilityContract,
    bundle_pairs: List[tuple[EvidenceBundle, EvidenceBundle]],
) -> ContractDiffReport:
    """Replay bundle pairs under both contracts, report verdict flips.

    This is the core contract diff operation. It is deterministic.

    Args:
        old_contract: The baseline contract version.
        new_contract: The amended contract version.
        bundle_pairs: List of (baseline_bundle, candidate_bundle) tuples.

    Returns:
        ContractDiffReport with structural changes and verdict flips.
    """
    clause_changes = diff_contracts(old_contract, new_contract)
    flips: List[VerdictFlip] = []

    for baseline, candidate in bundle_pairs:
        old_diff = evaluate(old_contract, baseline, candidate)
        new_diff = evaluate(new_contract, baseline, candidate)

        if old_diff.verdict != new_diff.verdict:
            triggering_field, reason = _find_triggering_field(
                old_diff, new_diff, clause_changes
            )

            # Filter to clause changes that affected this specific pair
            relevant_clauses = [
                cc for cc in clause_changes
                if cc.field in {m.field for m in old_diff.mismatches}
                or cc.field in {m.field for m in new_diff.mismatches}
            ]

            flips.append(VerdictFlip(
                bundle_ref=f"{baseline.ref} vs {candidate.ref}",
                old_verdict=old_diff.verdict,
                new_verdict=new_diff.verdict,
                triggering_clauses=relevant_clauses,
                triggering_field=triggering_field,
                reason=reason,
            ))

    return ContractDiffReport(
        old_contract_id=old_contract.contract_id,
        old_contract_version=old_contract.version,
        old_contract_hash=old_contract.content_hash(),
        new_contract_id=new_contract.contract_id,
        new_contract_version=new_contract.version,
        new_contract_hash=new_contract.content_hash(),
        clause_changes=clause_changes,
        flips=flips,
        total_pairs=len(bundle_pairs),
        stable_count=len(bundle_pairs) - len(flips),
    )
