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


@dataclass
class PackPostureResult:
    """Result of computing posture from a proof pack directory.

    Includes the posture itself plus structured warnings about input
    quality so callers can make honest decisions under damaged evidence.
    """

    posture: ProofPosture
    pack_dir: str
    warnings: List[str] = field(default_factory=list)
    receipts_loaded: int = 0
    claims_loaded: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pack_dir": self.pack_dir,
            "warnings": self.warnings,
            "receipts_loaded": self.receipts_loaded,
            "claims_loaded": self.claims_loaded,
            **self.posture.to_dict(),
        }


def posture_from_pack(
    pack_dir: str,
    *,
    require_falsifiers: bool = False,
) -> PackPostureResult:
    """Compute proof posture from a proof pack directory.

    This is the single canonical path for posture computation.
    Both ``assay posture`` and ``assay gate check --posture-pack``
    call this function.

    Incomplete-input law:
      If the pack is missing, unreadable, or structurally damaged,
      the posture degrades honestly — it does not silently produce
      ``verified``.  Warnings are always surfaced, never swallowed.

    Degradation rules:
      - missing pack_manifest.json → no claims → verified (with warning)
      - malformed receipt lines      → skipped with per-line warning count
      - unreadable manifest          → no claims → verified (with warning)
      - no receipt_pack.jsonl        → zero receipts (with warning)
    """
    import json as _json
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec, verify_claims
    from assay.proof_debt import compute_proof_debt
    from assay.residual_risk import build_residual_risk_from_claims

    root = Path(pack_dir).resolve()
    warnings: List[str] = []

    # Load receipts
    receipts: List[Dict[str, Any]] = []
    receipt_path = root / "receipt_pack.jsonl"
    decode_errors = 0
    if receipt_path.exists():
        for line in receipt_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                receipts.append(_json.loads(line))
            except _json.JSONDecodeError:
                decode_errors += 1
        if decode_errors:
            warnings.append(f"{decode_errors} malformed receipt line(s) skipped")
    else:
        warnings.append("receipt_pack.jsonl not found")

    # Load claims from manifest
    claims: List[ClaimSpec] = []
    manifest_path = root / "pack_manifest.json"
    if manifest_path.exists():
        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
            for c in manifest.get("claims", []):
                claims.append(ClaimSpec(
                    claim_id=c.get("claim_id", c.get("id", "")),
                    description=c.get("description", ""),
                    check=c.get("check", "receipt_type_present"),
                    params=c.get("params", {}),
                    severity=c.get("severity", "critical"),
                ))
        except (_json.JSONDecodeError, OSError) as exc:
            warnings.append(f"pack_manifest.json unreadable: {exc}")
        if not claims:
            warnings.append("pack_manifest.json has no claims — posture has nothing to verify")
    else:
        warnings.append("pack_manifest.json not found — no claims to verify")

    # Verify claims
    claim_set_result: Dict[str, Any] = {
        "n_claims": 0, "n_passed": 0, "n_failed": 0, "n_capped": 0, "results": [],
    }
    claim_results_list: List[Dict[str, Any]] = []

    if claims:
        claim_set = verify_claims(receipts, claims)
        claim_results_list = [r.to_dict() for r in claim_set.results]

        n_capped = 0
        enriched: List[Dict[str, Any]] = []
        for r in claim_results_list:
            tier_cap = ""
            if require_falsifiers and r.get("severity") == "critical":
                fstatus = r.get("falsifier_status", "")
                if fstatus in ("absent", ""):
                    tier_cap = "no falsifier named"
                    n_capped += 1
            enriched.append({**r, "tier_cap": tier_cap})

        claim_set_result = {
            "n_claims": claim_set.n_claims,
            "n_passed": claim_set.n_passed,
            "n_failed": claim_set.n_failed,
            "n_capped": n_capped,
            "results": enriched,
        }
        claim_results_list = enriched

    # Build posture primitives
    residual_risk_ledger = build_residual_risk_from_claims(claim_results_list)
    proof_debt_ledger = compute_proof_debt(
        claim_results_list,
        residual_risk_items=residual_risk_ledger.to_dict().get("items", []),
    )

    posture = build_proof_posture(
        claim_set_result=claim_set_result,
        residual_risk_ledger=residual_risk_ledger.to_dict(),
        proof_debt_ledger=proof_debt_ledger.to_dict(),
    )

    return PackPostureResult(
        posture=posture,
        pack_dir=str(root),
        warnings=warnings,
        receipts_loaded=len(receipts),
        claims_loaded=len(claims),
    )


__all__ = [
    "ProofPosture",
    "PackPostureResult",
    "build_proof_posture",
    "compute_disposition",
    "posture_from_pack",
    "render_proof_posture_text",
]
