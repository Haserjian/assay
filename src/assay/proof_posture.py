"""
Proof Posture: unified summary of claim verification + residual risk + proof debt.

A proof posture answers four questions:
  - what is proven?
  - what is supported but capped?
  - what remains unresolved but tolerated?
  - what is still owed?

Most verification systems know only pass/fail/warning.
Proof posture adds a richer epistemic grammar.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProofPosture:
    """Structured summary of the epistemic state of a claim set."""

    # From claim verification
    n_claims: int = 0
    n_passed: int = 0
    n_failed: int = 0
    n_capped: int = 0

    # From residual risk
    n_residual_risks: int = 0
    n_risks_blocking: int = 0
    n_risks_unowned: int = 0

    # From proof debt
    n_debt_items: int = 0
    debt_by_source: Dict[str, int] = field(default_factory=dict)
    debt_by_severity: Dict[str, int] = field(default_factory=dict)

    # Disposition
    disposition: str = "unknown"  # verified | supported_but_capped | incomplete | blocked

    # Detail lists for rendering
    capped_claims: List[Dict[str, str]] = field(default_factory=list)
    residual_risks: List[Dict[str, str]] = field(default_factory=list)
    debt_items: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "disposition": self.disposition,
            "claims": {
                "total": self.n_claims,
                "passed": self.n_passed,
                "failed": self.n_failed,
                "capped": self.n_capped,
            },
            "residual_risk": {
                "total": self.n_residual_risks,
                "blocking": self.n_risks_blocking,
                "unowned": self.n_risks_unowned,
            },
            "proof_debt": {
                "total": self.n_debt_items,
                "by_source": self.debt_by_source,
                "by_severity": self.debt_by_severity,
            },
            "capped_claims": self.capped_claims,
            "residual_risks": self.residual_risks,
            "debt_items": self.debt_items,
        }


def compute_disposition(
    *,
    n_failed: int,
    n_capped: int,
    n_risks_blocking: int,
    n_debt_severe: int,
) -> str:
    """Derive disposition from posture components.

    Disposition values:
      - verified:              all claims pass, no caps, no blocking risk
      - supported_but_capped:  all claims pass but some are tier-capped
      - incomplete:            critical claims failed or severe debt exists
      - blocked:               blocking residual risk prevents promotion
    """
    if n_risks_blocking > 0:
        return "blocked"
    if n_failed > 0:
        return "incomplete"
    if n_debt_severe > 0:
        return "incomplete"
    if n_capped > 0:
        return "supported_but_capped"
    return "verified"


def build_proof_posture(
    *,
    claim_set_result: Optional[Dict[str, Any]] = None,
    residual_risk_ledger: Optional[Dict[str, Any]] = None,
    proof_debt_ledger: Optional[Dict[str, Any]] = None,
) -> ProofPosture:
    """Build a ProofPosture from the outputs of the three primitives."""
    posture = ProofPosture()

    # Claims
    if claim_set_result:
        posture.n_claims = claim_set_result.get("n_claims", 0)
        posture.n_passed = claim_set_result.get("n_passed", 0)
        posture.n_failed = claim_set_result.get("n_failed", 0)
        posture.n_capped = claim_set_result.get("n_capped", 0)
        for r in claim_set_result.get("results", []):
            if r.get("tier_cap"):
                posture.capped_claims.append({
                    "claim_id": r.get("claim_id", ""),
                    "tier_cap": r["tier_cap"],
                    "falsifier_status": r.get("falsifier_status", ""),
                })

    # Residual risk
    if residual_risk_ledger:
        posture.n_residual_risks = residual_risk_ledger.get("n_items", 0)
        posture.n_risks_blocking = residual_risk_ledger.get("n_blocking", 0)
        posture.n_risks_unowned = residual_risk_ledger.get("n_unowned", 0)
        for item in residual_risk_ledger.get("items", []):
            posture.residual_risks.append({
                "claim_id": item.get("claim_id", ""),
                "risk_statement": item.get("risk_statement", ""),
                "owner": item.get("owner", ""),
                "next_cheapest_evidence": item.get("next_cheapest_evidence", ""),
            })

    # Proof debt
    if proof_debt_ledger:
        posture.n_debt_items = proof_debt_ledger.get("n_items", 0)
        posture.debt_by_source = proof_debt_ledger.get("by_source", {})
        posture.debt_by_severity = proof_debt_ledger.get("by_severity", {})
        for item in proof_debt_ledger.get("items", []):
            posture.debt_items.append({
                "claim_id": item.get("claim_id", ""),
                "source": item.get("source", ""),
                "repayment_action": item.get("repayment_action", ""),
            })

    # Disposition
    posture.disposition = compute_disposition(
        n_failed=posture.n_failed,
        n_capped=posture.n_capped,
        n_risks_blocking=posture.n_risks_blocking,
        n_debt_severe=posture.debt_by_severity.get("severe", 0),
    )

    return posture


def render_proof_posture_text(posture: ProofPosture) -> str:
    """Render a compact human-readable proof posture summary.

    Designed for PR comments and terminal output.
    Tiny top section, details below.
    """
    lines: List[str] = []

    # Header
    disp_label = {
        "verified": "VERIFIED",
        "supported_but_capped": "SUPPORTED (capped)",
        "incomplete": "INCOMPLETE",
        "blocked": "BLOCKED",
        "unknown": "UNKNOWN",
    }
    lines.append(f"Proof Posture: {disp_label.get(posture.disposition, posture.disposition)}")
    lines.append("")

    # Claims summary
    lines.append(f"Claims: {posture.n_passed} verified, {posture.n_failed} failed, {posture.n_capped} capped")

    # Capped claims
    if posture.capped_claims:
        for cc in posture.capped_claims:
            lines.append(f"  - {cc['claim_id']}: {cc['tier_cap']}")

    # Residual risks
    if posture.n_residual_risks > 0:
        lines.append(f"Residual risks: {posture.n_residual_risks} ({posture.n_risks_unowned} unowned)")
        for rr in posture.residual_risks:
            owner = rr.get("owner") or "unowned"
            lines.append(f"  - {rr['claim_id']}: {rr['risk_statement']} [{owner}]")
            nce = rr.get("next_cheapest_evidence")
            if nce:
                lines.append(f"    next evidence: {nce}")

    # Proof debt
    if posture.n_debt_items > 0:
        lines.append(f"Proof debt: {posture.n_debt_items} items owed")
        for di in posture.debt_items:
            lines.append(f"  - {di['claim_id']} ({di['source']}): {di['repayment_action']}")

    return "\n".join(lines)


__all__ = [
    "ProofPosture",
    "build_proof_posture",
    "compute_disposition",
    "render_proof_posture_text",
]
