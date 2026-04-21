"""Bulk summary of every commitment in the store.

Shared data source for ``assay commitments list`` and
``assay commitments overdue``. Previously carried its own corpus walk;
now delegates to :func:`assay.commitment_projection.project_commitment_lifecycle`
so the detector, explainer, and summarizer all consume one projection
instead of each re-deriving lifecycle semantics.

This module contributes only:
    - the ``CommitmentSummary`` / ``SummariesResult`` shape
      (``is_overdue`` is derived here because it depends on ``now``)
    - the sort key (``registered_seq`` ascending) for reproducible
      CLI output

Everything else — registration facts, closure semantics, integrity
handling — comes from the shared projection.

Read-only. Integrity failures from the projection surface via the
``integrity_error`` field; callers decide whether to exit nonzero.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from assay.commitment_projection import project_commitment_lifecycle
from assay.store import AssayStore


@dataclass(frozen=True)
class CommitmentSummary:
    """Compact per-commitment state for list/overdue views.

    States:
        OPEN       — registered, not yet closed or terminated.
        CLOSED     — ended by fulfillment.commitment_kept or
                     fulfillment.commitment_broken (fulfillment outcomes).
        TERMINATED — ended by commitment.terminated
                     (revoked | superseded | amended). NOT a fulfillment
                     outcome; see membrane doctrine note.

    Doctrine: "Kept, broken, revoked, amended, and superseded may all
    end a commitment's active life, but only kept/broken are
    fulfillment outcomes." Only OPEN is active. Both CLOSED and
    TERMINATED are ended, but they are distinct terminal states and
    MUST NOT be conflated.
    """

    commitment_id: str
    state: str  # OPEN | CLOSED | TERMINATED
    actor_id: str
    text: str
    commitment_type: str
    due_at: Optional[str]
    registered_seq: int
    closing_terminal_seq: Optional[int]
    closing_terminal_type: Optional[str]
    is_overdue: bool
    # Populated when state == TERMINATED; None otherwise.
    terminal_reason: Optional[str] = None  # revoked | superseded | amended
    termination_seq: Optional[int] = None
    replacement_commitment_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "state": self.state,
            "actor_id": self.actor_id,
            "text": self.text,
            "commitment_type": self.commitment_type,
            "due_at": self.due_at,
            "registered_seq": self.registered_seq,
            "closing_terminal_seq": self.closing_terminal_seq,
            "closing_terminal_type": self.closing_terminal_type,
            "is_overdue": self.is_overdue,
            "terminal_reason": self.terminal_reason,
            "termination_seq": self.termination_seq,
            "replacement_commitment_id": self.replacement_commitment_id,
        }


@dataclass(frozen=True)
class SummariesResult:
    """Output of ``summarize_all_commitments``.

    ``integrity_error`` is ``None`` on a clean projection; otherwise
    ``commitments`` is empty and the error message describes the
    integrity failure (malformed JSON, missing ``_store_seq``, etc.).
    """

    commitments: List[CommitmentSummary]
    scanned_at: str
    integrity_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitments": [c.to_dict() for c in self.commitments],
            "scanned_at": self.scanned_at,
            "integrity_error": self.integrity_error,
        }


def summarize_all_commitments(
    store: AssayStore,
    *,
    now: Optional[datetime] = None,
) -> SummariesResult:
    """Bulk-summarize every commitment in ``store`` via the shared projection.

    Delegates the corpus walk and closure semantics to
    :func:`project_commitment_lifecycle`. This function's remaining
    job is to derive the ``is_overdue`` flag (``now``-dependent) and
    render the per-commitment summaries in a stable
    ``registered_seq``-ascending order for reproducible CLI output.
    """
    reference = now or datetime.now(timezone.utc)

    projection = project_commitment_lifecycle(store, now=reference)

    if projection.integrity_error is not None:
        return SummariesResult(
            commitments=[],
            scanned_at=projection.scanned_at,
            integrity_error=projection.integrity_error,
        )

    summaries: List[CommitmentSummary] = []
    for reg in sorted(
        projection.registrations.values(), key=lambda r: r.seq
    ):
        closure = projection.closures.get(reg.commitment_id)
        termination = projection.terminations.get(reg.commitment_id)

        # First-terminal-wins across closures and terminations. The
        # projector already enforces this: a commitment that entered
        # ``closures`` cannot subsequently enter ``terminations``, and
        # vice-versa. Defensive tie-break if both ever appeared: whichever
        # has the smaller seq wins.
        if closure and termination:
            if closure.closing_terminal_seq <= termination.seq:
                termination = None
            else:
                closure = None

        if closure:
            state = "CLOSED"
            closing_seq = closure.closing_terminal_seq
            closing_type = closure.closing_terminal_type
            terminal_reason = None
            termination_seq = None
            replacement_commitment_id = None
        elif termination:
            state = "TERMINATED"
            closing_seq = None
            closing_type = None
            terminal_reason = termination.terminal_reason
            termination_seq = termination.seq
            replacement_commitment_id = termination.replacement_commitment_id
        else:
            state = "OPEN"
            closing_seq = None
            closing_type = None
            terminal_reason = None
            termination_seq = None
            replacement_commitment_id = None

        # is_overdue only applies to OPEN commitments. TERMINATED and
        # CLOSED have ended their active life and are never overdue.
        is_overdue = False
        if state == "OPEN" and reg.due_at:
            parsed = _parse_iso(reg.due_at)
            if parsed is not None and parsed < reference:
                is_overdue = True

        summaries.append(
            CommitmentSummary(
                commitment_id=reg.commitment_id,
                state=state,
                actor_id=reg.actor_id,
                text=reg.text,
                commitment_type=reg.commitment_type,
                due_at=reg.due_at,
                registered_seq=reg.seq,
                closing_terminal_seq=closing_seq,
                closing_terminal_type=closing_type,
                is_overdue=is_overdue,
                terminal_reason=terminal_reason,
                termination_seq=termination_seq,
                replacement_commitment_id=replacement_commitment_id,
            )
        )

    return SummariesResult(
        commitments=summaries,
        scanned_at=projection.scanned_at,
    )


def _parse_iso(value: str) -> Optional[datetime]:
    """Parse ISO-8601; return None if unparseable."""
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


__all__ = [
    "CommitmentSummary",
    "SummariesResult",
    "summarize_all_commitments",
]
