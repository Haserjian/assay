"""
Proof Debt Ledger for Assay Proof Packs.

Proof debt transforms weak evidence from a passive label into an
active liability.  Debt accrues from exactly three sources:

  1. missing_evidence   — required evidence not present
  2. missing_falsifier  — critical claim without a named kill test
  3. unowned_risk       — residual risk carried without owner or expiry

Debt is NOT:
  - generic unease
  - low confidence vibes
  - broad quality concerns

Those belong elsewhere.  If proof debt gets too broad, it stops being
a constitutional primitive and becomes emotional bookkeeping.

Each debt item suggests a repayment action so the system feels like
guidance, not judgment theater.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


DEBT_SOURCES = {"missing_evidence", "missing_falsifier", "unowned_risk"}


@dataclass
class ProofDebtItem:
    """A single unit of epistemic debt."""

    claim_id: str
    source: str  # one of DEBT_SOURCES
    description: str
    repayment_action: str
    severity: str = "moderate"  # low | moderate | severe

    def __post_init__(self) -> None:
        if self.source not in DEBT_SOURCES:
            raise ValueError(
                f"Invalid debt source '{self.source}'; "
                f"must be one of {sorted(DEBT_SOURCES)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "source": self.source,
            "description": self.description,
            "repayment_action": self.repayment_action,
            "severity": self.severity,
        }


@dataclass
class ProofDebtLedger:
    """Collection of proof debt items for an episode or packet."""

    items: List[ProofDebtItem] = field(default_factory=list)

    @property
    def n_items(self) -> int:
        return len(self.items)

    @property
    def by_source(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in self.items:
            counts[item.source] = counts.get(item.source, 0) + 1
        return counts

    @property
    def by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in self.items:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n_items": self.n_items,
            "by_source": self.by_source,
            "by_severity": self.by_severity,
            "items": [item.to_dict() for item in self.items],
        }

    def add(self, item: ProofDebtItem) -> None:
        self.items.append(item)


def compute_proof_debt(
    claim_results: List[Dict[str, Any]],
    *,
    residual_risk_items: Optional[List[Dict[str, Any]]] = None,
) -> ProofDebtLedger:
    """Compute proof debt from claim results and residual risk.

    Debt accrues from exactly three sources:
      1. Critical claim failed (missing_evidence)
      2. Critical claim has no falsifier (missing_falsifier)
      3. Residual risk item has no owner or no expiry (unowned_risk)
    """
    ledger = ProofDebtLedger()

    for cr in claim_results:
        claim_id = cr.get("claim_id", "")
        severity = cr.get("severity", "critical")
        passed = cr.get("passed", False)
        falsifier_status = cr.get("falsifier_status", "not_required")
        tier_cap = cr.get("tier_cap")

        # Source 1: missing evidence (critical claim failed)
        if not passed and severity == "critical":
            expected = cr.get("expected", "?")
            ledger.add(ProofDebtItem(
                claim_id=claim_id,
                source="missing_evidence",
                description=f"Critical claim failed: expected {expected}",
                repayment_action=f"Attach evidence satisfying: {expected}",
                severity="severe",
            ))

        # Source 2: missing falsifier (critical claim without kill test)
        if falsifier_status == "absent" or (
            severity == "critical" and tier_cap and "falsifier" in (tier_cap or "")
        ):
            ledger.add(ProofDebtItem(
                claim_id=claim_id,
                source="missing_falsifier",
                description="Critical claim has no named kill test",
                repayment_action="Name the cheapest test that would disprove this claim",
                severity="moderate",
            ))

    # Source 3: unowned residual risk
    for rr in (residual_risk_items or []):
        claim_id = rr.get("claim_id", "")
        owner = rr.get("owner", "")
        expiry = rr.get("expiry_condition", "")

        if not owner or not expiry:
            missing = []
            if not owner:
                missing.append("owner")
            if not expiry:
                missing.append("expiry_condition")
            ledger.add(ProofDebtItem(
                claim_id=claim_id,
                source="unowned_risk",
                description=f"Residual risk missing: {', '.join(missing)}",
                repayment_action=f"Assign {' and '.join(missing)} to this residual risk",
                severity="moderate" if owner else "severe",
            ))

    return ledger


__all__ = [
    "ProofDebtItem",
    "ProofDebtLedger",
    "compute_proof_debt",
    "DEBT_SOURCES",
]
