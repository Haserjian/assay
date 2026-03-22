"""Constitutional interrogation: `assay why <receipt-id>`.

Answers the question: "Why was this decision made, under what authority,
and what obligations remain?"

This is a read-side constitutional explanation surface. It does not mutate
state — only traces existing receipts and obligations.

Two explanation layers:
  - execution_why: what immediate rule/path fired (stack trace equivalent)
  - constitutional_why: what prior receipts, judgments, and obligations
    made this permissible or impermissible (constitutional trace)

Edge semantics are preserved during traversal:
  - supersedes = override/succession (constitutional relation)
  - parent_receipt_id = lineage/derivation (causal chain)
These are distinct constitutional meanings, not interchangeable backward links.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from assay.obligation import Obligation, ObligationStore
from assay.store import AssayStore


@dataclass
class ReceiptSummary:
    """Minimal receipt projection for explanation purposes."""

    receipt_id: str
    verdict: str
    disposition: str
    authority_class: str
    authority_id: str
    decision_type: str
    verdict_reason: Optional[str] = None
    verdict_reason_codes: Optional[List[str]] = None
    timestamp: Optional[str] = None
    delegated_from: Optional[str] = None
    decision_subject: Optional[str] = None

    @classmethod
    def from_receipt(cls, receipt: Dict[str, Any]) -> "ReceiptSummary":
        return cls(
            receipt_id=receipt.get("receipt_id", "unknown"),
            verdict=receipt.get("verdict", "unknown"),
            disposition=receipt.get("disposition", "unknown"),
            authority_class=receipt.get("authority_class", "unknown"),
            authority_id=receipt.get("authority_id", "unknown"),
            decision_type=receipt.get("decision_type", "unknown"),
            verdict_reason=receipt.get("verdict_reason"),
            verdict_reason_codes=receipt.get("verdict_reason_codes"),
            timestamp=receipt.get("timestamp"),
            delegated_from=receipt.get("delegated_from"),
            decision_subject=receipt.get("decision_subject"),
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class SupersessionEdge:
    """A supersedes relation between two receipts (override semantics)."""

    from_receipt_id: str
    to_receipt_id: str  # the superseded receipt
    relation: str = "supersedes"  # always "supersedes" for now


@dataclass
class ParentEdge:
    """A parent_receipt_id relation (causal derivation semantics)."""

    from_receipt_id: str
    to_receipt_id: str
    relation: str = "derived_from"


@dataclass
class ObligationSummary:
    """Obligation projection for explanation output."""

    obligation_id: str
    status: str
    severity: str
    obligation_type: str
    due_at: str
    owner: str
    discharge_receipt_id: Optional[str] = None
    status_reason: Optional[str] = None

    @classmethod
    def from_obligation(cls, ob: Obligation) -> "ObligationSummary":
        return cls(
            obligation_id=ob.obligation_id,
            status=ob.status,
            severity=ob.severity,
            obligation_type=ob.obligation_type,
            due_at=ob.due_at,
            owner=ob.owner,
            discharge_receipt_id=ob.discharge_receipt_id,
            status_reason=ob.status_reason,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class MissingLink:
    """Records a referenced artifact that could not be found.

    The system must be honest about broken links rather than producing
    fake coherence through silent omission.
    """

    referenced_id: str
    referenced_from: str
    relation: str  # "supersedes", "obligation", "parent"
    message: str


@dataclass
class WhyResult:
    """Complete explanation of a decision receipt."""

    receipt: ReceiptSummary
    execution_why: str  # immediate rule/path that fired
    constitutional_why: Optional[Dict[str, Any]] = None  # prior chain
    superseded_receipt: Optional[ReceiptSummary] = None
    supersession_edge: Optional[SupersessionEdge] = None
    obligations: List[ObligationSummary] = field(default_factory=list)
    parent_chain: List[ReceiptSummary] = field(default_factory=list)
    parent_edges: List[ParentEdge] = field(default_factory=list)
    missing_links: List[MissingLink] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "receipt_id": self.receipt.receipt_id,
            "verdict": self.receipt.verdict,
            "disposition": self.receipt.disposition,
            "authority_class": self.receipt.authority_class,
            "authority_id": self.receipt.authority_id,
            "decision_type": self.receipt.decision_type,
            "execution_why": self.execution_why,
        }
        if self.receipt.timestamp:
            d["timestamp"] = self.receipt.timestamp
        if self.receipt.decision_subject:
            d["decision_subject"] = self.receipt.decision_subject

        if self.superseded_receipt:
            d["supersedes"] = {
                "receipt_id": self.superseded_receipt.receipt_id,
                "relation": "supersedes",
                "verdict": self.superseded_receipt.verdict,
                "disposition": self.superseded_receipt.disposition,
                "authority_class": self.superseded_receipt.authority_class,
                "verdict_reason": self.superseded_receipt.verdict_reason,
                "verdict_reason_codes": self.superseded_receipt.verdict_reason_codes,
            }

        if self.constitutional_why:
            d["constitutional_why"] = self.constitutional_why

        if self.obligations:
            d["obligations"] = [ob.to_dict() for ob in self.obligations]

        if self.parent_chain:
            d["parent_chain"] = [
                {**r.to_dict(), "relation": "derived_from"}
                for r in self.parent_chain
            ]

        if self.missing_links:
            d["missing_links"] = [
                {"referenced_id": ml.referenced_id, "relation": ml.relation,
                 "message": ml.message}
                for ml in self.missing_links
            ]

        return d


class ReceiptIndex:
    """Thin index over receipt traces for interrogation.

    Loads receipts from AssayStore traces into a dict keyed by receipt_id.
    Only indexes decision_v1 receipts by default, but falls back to any
    receipt with a matching receipt_id.
    """

    def __init__(self, store: Optional[AssayStore] = None):
        self._store = store or AssayStore()
        self._index: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        # Load all traces
        for trace_info in self._store.list_traces(limit=100):
            trace_id = trace_info["trace_id"]
            entries = self._store.read_trace(trace_id)
            for entry in entries:
                rid = entry.get("receipt_id")
                if rid:
                    self._index[rid] = entry
        self._loaded = True

    def get(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_loaded()
        return self._index.get(receipt_id)

    def add(self, receipt: Dict[str, Any]) -> None:
        """Add a receipt to the in-memory index (for testing)."""
        rid = receipt.get("receipt_id")
        if rid:
            self._index[rid] = receipt
            self._loaded = True  # Mark as loaded to prevent re-scan


def explain_why(
    receipt_id: str,
    *,
    receipt_index: Optional[ReceiptIndex] = None,
    obligation_store: Optional[ObligationStore] = None,
    trace_depth: int = 1,
) -> WhyResult:
    """Explain why a decision was made.

    Args:
        receipt_id: The receipt to explain.
        receipt_index: Index to look up receipts. Uses default store if None.
        obligation_store: Store to look up obligations. Uses default if None.
        trace_depth: How many parent_receipt_id links to follow (default 1).
            Supersedes links are always followed (they are constitutional, not just causal).

    Returns:
        WhyResult with execution_why, constitutional_why, and linked artifacts.
    """
    if receipt_index is None:
        receipt_index = ReceiptIndex()
    if obligation_store is None:
        obligation_store = ObligationStore()

    receipt = receipt_index.get(receipt_id)
    if receipt is None:
        return WhyResult(
            receipt=ReceiptSummary(
                receipt_id=receipt_id,
                verdict="unknown",
                disposition="unknown",
                authority_class="unknown",
                authority_id="unknown",
                decision_type="unknown",
            ),
            execution_why=f"Receipt {receipt_id} not found in store",
            missing_links=[MissingLink(
                referenced_id=receipt_id,
                referenced_from="query",
                relation="target",
                message=f"Target receipt {receipt_id} not found",
            )],
        )

    summary = ReceiptSummary.from_receipt(receipt)

    # --- Execution why ---
    execution_why = _build_execution_why(receipt)

    # --- Constitutional why (supersedes chain) ---
    superseded_receipt = None
    supersession_edge = None
    constitutional_why = None
    missing_links: List[MissingLink] = []

    supersedes_id = receipt.get("supersedes")
    if supersedes_id:
        superseded_raw = receipt_index.get(supersedes_id)
        if superseded_raw:
            superseded_receipt = ReceiptSummary.from_receipt(superseded_raw)
            supersession_edge = SupersessionEdge(
                from_receipt_id=receipt_id,
                to_receipt_id=supersedes_id,
            )
            constitutional_why = {
                "prior_decision_id": supersedes_id,
                "prior_outcome": superseded_raw.get("verdict"),
                "prior_disposition": superseded_raw.get("disposition"),
                "prior_authority": superseded_raw.get("authority_id"),
                "override_authority": receipt.get("authority_id"),
                "delegated_from": receipt.get("delegated_from"),
            }
        else:
            missing_links.append(MissingLink(
                referenced_id=supersedes_id,
                referenced_from=receipt_id,
                relation="supersedes",
                message=f"Superseded receipt {supersedes_id} not found in store",
            ))

    # --- Obligations ---
    obligation_summaries: List[ObligationSummary] = []
    obligation_ids = receipt.get("obligations_created") or []
    for ob_id in obligation_ids:
        ob = obligation_store.get(ob_id)
        if ob:
            obligation_summaries.append(ObligationSummary.from_obligation(ob))
        else:
            missing_links.append(MissingLink(
                referenced_id=ob_id,
                referenced_from=receipt_id,
                relation="obligation",
                message=f"Obligation {ob_id} referenced in receipt but not found in store",
            ))

    # Also check for obligations linked to this receipt as source
    linked_obligations = obligation_store.find_by_receipt(receipt_id)
    for ob in linked_obligations:
        if ob.obligation_id not in [o.obligation_id for o in obligation_summaries]:
            obligation_summaries.append(ObligationSummary.from_obligation(ob))

    # --- Parent chain (causal, not constitutional) ---
    parent_chain: List[ReceiptSummary] = []
    parent_edges: List[ParentEdge] = []
    visited: Set[str] = {receipt_id}  # cycle detection
    current_id = receipt.get("parent_receipt_id")
    depth = 0
    while current_id and depth < trace_depth:
        if current_id in visited:
            missing_links.append(MissingLink(
                referenced_id=current_id,
                referenced_from=receipt_id,
                relation="parent",
                message=f"Cycle detected: {current_id} already visited in chain",
            ))
            break
        visited.add(current_id)
        parent_raw = receipt_index.get(current_id)
        if parent_raw:
            parent_chain.append(ReceiptSummary.from_receipt(parent_raw))
            prev_id = parent_chain[-2].receipt_id if len(parent_chain) > 1 else receipt_id
            parent_edges.append(ParentEdge(
                from_receipt_id=prev_id,
                to_receipt_id=current_id,
            ))
            current_id = parent_raw.get("parent_receipt_id")
        else:
            missing_links.append(MissingLink(
                referenced_id=current_id,
                referenced_from=receipt_id,
                relation="parent",
                message=f"Parent receipt {current_id} not found in store",
            ))
            break
        depth += 1

    return WhyResult(
        receipt=summary,
        execution_why=execution_why,
        constitutional_why=constitutional_why,
        superseded_receipt=superseded_receipt,
        supersession_edge=supersession_edge,
        obligations=obligation_summaries,
        parent_chain=parent_chain,
        parent_edges=parent_edges,
        missing_links=missing_links,
    )


def _build_execution_why(receipt: Dict[str, Any]) -> str:
    """Build a human-readable execution-why string from receipt fields."""
    verdict = receipt.get("verdict", "unknown")
    disposition = receipt.get("disposition", "unknown")
    decision_type = receipt.get("decision_type", "unknown")
    authority = receipt.get("authority_id", "unknown")
    authority_class = receipt.get("authority_class", "unknown")
    reason = receipt.get("verdict_reason", "")

    parts = [f"{verdict} ({disposition})"]
    parts.append(f"by {authority} [{authority_class}]")

    if decision_type == "human_authority_override":
        delegated = receipt.get("delegated_from", "unknown")
        parts.append(f"overriding {delegated}")

    if decision_type == "guardian_constitutional_refusal":
        parts.append("via Guardian constitutional assessment")

    if reason:
        parts.append(f"— {reason[:200]}")

    return " ".join(parts)


def render_text(result: WhyResult) -> str:
    """Render WhyResult as human-readable tree text."""
    lines: List[str] = []
    r = result.receipt

    lines.append(f"Decision {r.receipt_id}")
    lines.append(f"  Outcome: {r.verdict} ({r.disposition})")
    lines.append(f"  Authority: {r.authority_class} ({r.authority_id})")
    if r.delegated_from:
        lines.append(f"  Delegated from: {r.delegated_from}")
    lines.append(f"  Type: {r.decision_type}")
    if r.timestamp:
        lines.append(f"  Timestamp: {r.timestamp}")
    if r.verdict_reason:
        lines.append(f"  Reason: {r.verdict_reason}")

    if result.superseded_receipt:
        sr = result.superseded_receipt
        lines.append(f"  Supersedes: {sr.receipt_id}")
        lines.append(f"    Prior outcome: {sr.verdict} ({sr.disposition})")
        lines.append(f"    Prior authority: {sr.authority_class} ({sr.authority_id})")
        if sr.verdict_reason:
            lines.append(f"    Prior reason: {sr.verdict_reason}")
        if sr.verdict_reason_codes:
            lines.append(f"    Reason codes: {', '.join(sr.verdict_reason_codes)}")

    if result.obligations:
        lines.append("  Obligations:")
        for ob in result.obligations:
            status_str = ob.status.upper()
            lines.append(f"    {ob.obligation_id} ({status_str}, due {ob.due_at})")
            lines.append(f"      Type: {ob.obligation_type}, Severity: {ob.severity}")
            if ob.discharge_receipt_id:
                lines.append(f"      Discharged by: {ob.discharge_receipt_id}")
            if ob.status_reason:
                lines.append(f"      Note: {ob.status_reason}")

    if result.parent_chain:
        lines.append("  Parent chain:")
        for p in result.parent_chain:
            lines.append(f"    {p.receipt_id}: {p.verdict} ({p.disposition}) by {p.authority_id}")

    if result.missing_links:
        lines.append("  WARNINGS:")
        for ml in result.missing_links:
            lines.append(f"    [MISSING] {ml.relation}: {ml.message}")

    return "\n".join(lines)


__all__ = [
    "WhyResult",
    "ReceiptSummary",
    "ObligationSummary",
    "MissingLink",
    "ReceiptIndex",
    "explain_why",
    "render_text",
]
