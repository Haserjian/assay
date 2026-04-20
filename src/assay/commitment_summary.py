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
    """Compact per-commitment state for list/overdue views."""

    commitment_id: str
    state: str  # OPEN | CLOSED
    actor_id: str
    text: str
    commitment_type: str
    due_at: Optional[str]
    registered_seq: int
    closing_terminal_seq: Optional[int]
    closing_terminal_type: Optional[str]
    is_overdue: bool

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
        state = "CLOSED" if closure else "OPEN"
        closing_seq = closure.closing_terminal_seq if closure else None
        closing_type = closure.closing_terminal_type if closure else None

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
