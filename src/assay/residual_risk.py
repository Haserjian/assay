"""
Residual Risk Ledger for Assay Proof Packs.

Residual risk tracks what remains unresolved but tolerated after
verification.  Each item is aggressively structured — not prose.

Distinct from failure:
  - failed     = claim did not pass verification
  - unproven   = insufficient evidence to evaluate
  - tolerated  = risk acknowledged, owner assigned, expiry set

The key field is next_cheapest_evidence: it turns uncertainty into
a navigable frontier instead of a fog bank.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from assay._receipts.canonicalize import to_jcs_bytes


@dataclass
class ResidualRiskItem:
    """A single unresolved risk carried forward with explicit tolerance."""

    claim_id: str
    risk_statement: str
    why_tolerated: str
    owner: str
    expiry_condition: str
    next_cheapest_evidence: str
    blocking_on_merge: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "risk_statement": self.risk_statement,
            "why_tolerated": self.why_tolerated,
            "owner": self.owner,
            "expiry_condition": self.expiry_condition,
            "next_cheapest_evidence": self.next_cheapest_evidence,
            "blocking_on_merge": self.blocking_on_merge,
        }


@dataclass
class ResidualRiskLedger:
    """Collection of residual risks for an episode or packet."""

    items: List[ResidualRiskItem] = field(default_factory=list)

    @property
    def n_items(self) -> int:
        return len(self.items)

    @property
    def n_blocking(self) -> int:
        return sum(1 for item in self.items if item.blocking_on_merge)

    @property
    def n_unowned(self) -> int:
        return sum(1 for item in self.items if not item.owner)

    def fingerprint(self) -> str:
        """Deterministic hash of the ledger contents."""
        canonical = [item.to_dict() for item in sorted(self.items, key=lambda i: i.claim_id)]
        return hashlib.sha256(to_jcs_bytes(canonical)).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n_items": self.n_items,
            "n_blocking": self.n_blocking,
            "n_unowned": self.n_unowned,
            "fingerprint": self.fingerprint(),
            "items": [item.to_dict() for item in self.items],
        }

    def add(self, item: ResidualRiskItem) -> None:
        self.items.append(item)


def build_residual_risk_from_claims(
    claim_results: List[Dict[str, Any]],
    *,
    risk_annotations: Optional[Dict[str, Dict[str, str]]] = None,
) -> ResidualRiskLedger:
    """Build a residual risk ledger from claim verification results.

    Any claim that passed but has a tier_cap, or failed with warning
    severity, becomes a candidate residual risk.  The risk_annotations
    dict maps claim_id to override fields (why_tolerated, owner,
    expiry_condition, next_cheapest_evidence).
    """
    annotations = risk_annotations or {}
    ledger = ResidualRiskLedger()

    for cr in claim_results:
        claim_id = cr.get("claim_id", "")
        tier_cap = cr.get("tier_cap")
        severity = cr.get("severity", "critical")
        passed = cr.get("passed", False)

        # Capped claims: passed but with limited proof strength
        if passed and tier_cap:
            ann = annotations.get(claim_id, {})
            ledger.add(ResidualRiskItem(
                claim_id=claim_id,
                risk_statement=f"Claim passed but capped: {tier_cap}",
                why_tolerated=ann.get("why_tolerated", "no rationale provided"),
                owner=ann.get("owner", ""),
                expiry_condition=ann.get("expiry_condition", ""),
                next_cheapest_evidence=ann.get(
                    "next_cheapest_evidence",
                    "name a falsifier for this claim",
                ),
                blocking_on_merge=False,
            ))

        # Warning-severity failures: tolerated but noted
        if not passed and severity == "warning":
            ann = annotations.get(claim_id, {})
            ledger.add(ResidualRiskItem(
                claim_id=claim_id,
                risk_statement=f"Warning claim failed: expected {cr.get('expected', '?')}, actual {cr.get('actual', '?')}",
                why_tolerated=ann.get("why_tolerated", "warning severity — not blocking"),
                owner=ann.get("owner", ""),
                expiry_condition=ann.get("expiry_condition", ""),
                next_cheapest_evidence=ann.get("next_cheapest_evidence", ""),
                blocking_on_merge=False,
            ))

    return ledger


__all__ = [
    "ResidualRiskItem",
    "ResidualRiskLedger",
    "build_residual_risk_from_claims",
]
