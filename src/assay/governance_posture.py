"""Governance posture evaluation and snapshot.

Governance posture is a statement about admissibility conditions at a declared
evaluation point — not metadata about evidence, but context that determines
whether evidence should be promoted, trusted at a given tier, or accepted
without caveat.

Two distinct truths:
  - Production posture: what was the governance state when evidence was produced?
    (embedded in sealed receipt chain, immutable after sealing)
  - Current posture: what is the governance state now, at verification/query time?
    (computed live from obligation store)

These must never collapse. A pack's production posture is historical fact; current
posture is live assessment. Divergence between them is a signal, not a bug.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class PostureState(str, Enum):
    """Governance posture classification.

    Status classes, not scores. Numericizing posture invites gaming and
    compensatory tradeoffs. Status classes preserve doctrine.
    """

    CLEAN = "CLEAN"  # no open obligations
    DEBT_OUTSTANDING = "DEBT_OUTSTANDING"  # open obligations, none overdue
    DEBT_OVERDUE = "DEBT_OVERDUE"  # at least one overdue obligation
    UNKNOWN = "UNKNOWN"  # obligation store unreadable or unavailable


# Receipt type constant for sealed chain embedding
POSTURE_RECEIPT_TYPE = "governance_posture_snapshot"

# Schema version for the snapshot receipt
POSTURE_SCHEMA_VERSION = "0.1.0"

# Policy version for derivation provenance
POSTURE_POLICY_VERSION = "governance.obligation.v1"


@dataclass
class GovernancePostureSnapshot:
    """Snapshot of governance posture at a declared evaluation point.

    This is emitted as a receipt in the sealed chain, making governance
    context an artifact (not a comment) that travels with the evidence.

    Fields follow the user's sharpening: posture at a declared evaluation
    point, with derivation basis and policy version, not just a bare status.
    """

    posture: str  # PostureState value
    evaluated_at: str  # ISO-8601 — when this was computed
    obligation_ids: List[str]  # open obligation IDs at evaluation time
    open_count: int
    overdue_count: int
    policy_version: str = POSTURE_POLICY_VERSION
    derivation_scope: str = "local_obligation_store"
    derivation_basis: str = "all open obligations at evaluation time"

    def to_receipt_dict(self) -> Dict[str, Any]:
        """Convert to a receipt dict for embedding in sealed chain."""
        return {
            "type": POSTURE_RECEIPT_TYPE,
            "schema_version": POSTURE_SCHEMA_VERSION,
            "posture": self.posture,
            "evaluated_at": self.evaluated_at,
            "obligation_ids": self.obligation_ids,
            "open_count": self.open_count,
            "overdue_count": self.overdue_count,
            "policy_version": self.policy_version,
            "derivation_scope": self.derivation_scope,
            "derivation_basis": self.derivation_basis,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GovernancePostureSnapshot":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


class DivergenceType(str, Enum):
    """Machine-usable classification of posture divergence.

    Prevents downstream tooling from parsing English to understand
    what kind of disagreement exists between production and current posture.
    """

    NONE = "NONE"  # no divergence
    DEBT_RESOLVED = "DEBT_RESOLVED"  # was impaired at production, now clean
    DEBT_ACCRUED = "DEBT_ACCRUED"  # was clean at production, now impaired
    DEBT_WORSENED = "DEBT_WORSENED"  # was outstanding, now overdue
    DEBT_IMPROVED = "DEBT_IMPROVED"  # was overdue, now just outstanding (not yet clean)
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"  # current posture unknown (store unreadable)
    PRODUCTION_UNAVAILABLE = "PRODUCTION_UNAVAILABLE"  # pack predates posture embedding
    STATE_CHANGED = "STATE_CHANGED"  # catch-all for other transitions


@dataclass
class PostureDivergence:
    """Divergence between production posture and current posture.

    When these differ, the evidence was produced under different governance
    conditions than currently hold. This is information, not necessarily error.
    """

    production_posture: str  # PostureState value at seal time
    current_posture: str  # PostureState value now
    diverged: bool  # whether they differ
    divergence_type: str  # DivergenceType value — machine-usable classification
    production_evaluated_at: str  # when production posture was computed
    current_evaluated_at: str  # when current posture was computed
    detail: Optional[str] = None  # human explanation of divergence

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


def evaluate_posture(
    obligation_store: Optional[Any] = None,
) -> GovernancePostureSnapshot:
    """Evaluate current governance posture from the obligation store.

    Args:
        obligation_store: Optional ObligationStore instance. Uses default if None.

    Returns a snapshot that can be emitted as a receipt or used for
    live comparison. Resilient — returns UNKNOWN if store is unreadable.
    """
    now = datetime.now(timezone.utc)

    try:
        if obligation_store is None:
            from assay.obligation import ObligationStore

            obligation_store = ObligationStore()
        pending = obligation_store.list_pending()
    except Exception:
        return GovernancePostureSnapshot(
            posture=PostureState.UNKNOWN.value,
            evaluated_at=now.isoformat(),
            obligation_ids=[],
            open_count=0,
            overdue_count=0,
            derivation_basis="obligation store unavailable",
        )

    if not pending:
        return GovernancePostureSnapshot(
            posture=PostureState.CLEAN.value,
            evaluated_at=now.isoformat(),
            obligation_ids=[],
            open_count=0,
            overdue_count=0,
        )

    obligation_ids = [ob.obligation_id for ob in pending]
    overdue_count = 0
    for ob in pending:
        try:
            due = datetime.fromisoformat(ob.due_at.replace("Z", "+00:00"))
            if due < now:
                overdue_count += 1
        except (ValueError, AttributeError):
            overdue_count += 1  # unparseable = treat as overdue

    posture = (
        PostureState.DEBT_OVERDUE.value
        if overdue_count > 0
        else PostureState.DEBT_OUTSTANDING.value
    )

    return GovernancePostureSnapshot(
        posture=posture,
        evaluated_at=now.isoformat(),
        obligation_ids=obligation_ids,
        open_count=len(pending),
        overdue_count=overdue_count,
    )


def extract_production_posture(
    entries: List[Dict[str, Any]],
) -> Optional[GovernancePostureSnapshot]:
    """Extract governance posture snapshot from a pack's receipt entries.

    Looks for the last governance_posture_snapshot receipt in the chain.
    Returns None if no posture receipt exists (pack produced before posture
    embedding was enabled).
    """
    latest = None
    for entry in entries:
        if entry.get("type") == POSTURE_RECEIPT_TYPE:
            latest = entry
    if latest is None:
        return None
    # Strip store metadata
    clean = {k: v for k, v in latest.items() if not k.startswith("_")}
    return GovernancePostureSnapshot.from_dict(clean)


def compute_divergence(
    production: Optional[GovernancePostureSnapshot],
    current: GovernancePostureSnapshot,
) -> PostureDivergence:
    """Compare production posture with current posture.

    If production posture is None (pack predates posture embedding),
    reports UNAVAILABLE production posture with divergence = True if current
    is not CLEAN (conservative: absence of historical data is notable).

    Returns a PostureDivergence with a machine-usable divergence_type enum
    so downstream tooling can act on the kind of disagreement without parsing
    human-readable detail strings.
    """
    _CLEAN = PostureState.CLEAN.value
    _OUTSTANDING = PostureState.DEBT_OUTSTANDING.value
    _OVERDUE = PostureState.DEBT_OVERDUE.value
    _UNKNOWN = PostureState.UNKNOWN.value

    if production is None:
        notable = current.posture != _CLEAN
        return PostureDivergence(
            production_posture="UNAVAILABLE",
            current_posture=current.posture,
            diverged=notable,
            divergence_type=DivergenceType.PRODUCTION_UNAVAILABLE.value,
            production_evaluated_at="N/A",
            current_evaluated_at=current.evaluated_at,
            detail="Pack predates governance posture embedding",
        )

    if current.posture == _UNKNOWN:
        return PostureDivergence(
            production_posture=production.posture,
            current_posture=current.posture,
            diverged=True,
            divergence_type=DivergenceType.STORE_UNAVAILABLE.value,
            production_evaluated_at=production.evaluated_at,
            current_evaluated_at=current.evaluated_at,
            detail="Current obligation store unavailable; cannot verify live posture",
        )

    diverged = production.posture != current.posture

    if not diverged:
        return PostureDivergence(
            production_posture=production.posture,
            current_posture=current.posture,
            diverged=False,
            divergence_type=DivergenceType.NONE.value,
            production_evaluated_at=production.evaluated_at,
            current_evaluated_at=current.evaluated_at,
        )

    # Classify the divergence direction
    prod = production.posture
    curr = current.posture

    if curr == _CLEAN and prod in (_OUTSTANDING, _OVERDUE):
        div_type = DivergenceType.DEBT_RESOLVED
        detail = "Governance debt was outstanding at production but has since been resolved"
    elif prod == _CLEAN and curr in (_OUTSTANDING, _OVERDUE):
        div_type = DivergenceType.DEBT_ACCRUED
        detail = "Governance debt accrued after pack was produced"
    elif prod == _OUTSTANDING and curr == _OVERDUE:
        div_type = DivergenceType.DEBT_WORSENED
        detail = "Governance debt was outstanding at production and is now overdue"
    elif prod == _OVERDUE and curr == _OUTSTANDING:
        div_type = DivergenceType.DEBT_IMPROVED
        detail = "Governance debt was overdue at production but is no longer overdue (still outstanding)"
    else:
        div_type = DivergenceType.STATE_CHANGED
        detail = f"Posture changed from {prod} to {curr}"

    return PostureDivergence(
        production_posture=production.posture,
        current_posture=current.posture,
        diverged=True,
        divergence_type=div_type.value,
        production_evaluated_at=production.evaluated_at,
        current_evaluated_at=current.evaluated_at,
        detail=detail,
    )


__all__ = [
    "PostureState",
    "DivergenceType",
    "GovernancePostureSnapshot",
    "PostureDivergence",
    "POSTURE_RECEIPT_TYPE",
    "evaluate_posture",
    "extract_production_posture",
    "compute_divergence",
]
