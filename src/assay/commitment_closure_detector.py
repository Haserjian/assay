"""Commitment closure detector — DOCTOR_COMMITMENT_001.

Pure-read detection of overdue open commitments. Consumes the shared
projection from
:func:`assay.commitment_projection.project_commitment_lifecycle`;
previously carried its own corpus walk.

Responsibility boundary:
    This module contributes only the "overdue + open" filter. Closure
    semantics, registration tracking, observation anchoring, and
    validity checks all live in the projector now.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from assay.commitment_projection import project_commitment_lifecycle
from assay.store import AssayStore


@dataclass(frozen=True)
class OpenOverdueCommitment:
    """A detected open, overdue commitment."""

    commitment_id: str
    trace_id: str
    episode_id: str
    actor_id: str
    text: str
    commitment_type: str
    registered_at: str
    due_at: str
    trace_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "trace_id": self.trace_id,
            "episode_id": self.episode_id,
            "actor_id": self.actor_id,
            "text": self.text,
            "commitment_type": self.commitment_type,
            "registered_at": self.registered_at,
            "due_at": self.due_at,
            "trace_path": self.trace_path,
        }


@dataclass(frozen=True)
class CommitmentClosureResult:
    """Result of scanning a store for open, overdue commitments."""

    open_commitments: List[OpenOverdueCommitment] = field(default_factory=list)
    total_traces_scanned: int = 0
    total_registered_found: int = 0
    total_closed_found: int = 0
    total_open_found: int = 0
    scanned_at: str = ""

    @property
    def clean(self) -> bool:
        return self.total_open_found == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "total_traces_scanned": self.total_traces_scanned,
            "total_registered_found": self.total_registered_found,
            "total_closed_found": self.total_closed_found,
            "total_open_found": self.total_open_found,
            "scanned_at": self.scanned_at,
            "open_commitments": [c.to_dict() for c in self.open_commitments],
        }


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


def detect_open_overdue_commitments(
    store: AssayStore,
    *,
    now: Optional[datetime] = None,
) -> CommitmentClosureResult:
    """Scan a store for open, overdue commitments.

    Closure semantics and corpus-walk logic are handled by the shared
    projection (see :func:`project_commitment_lifecycle`). This
    function's remaining job is the overdue filter:

        - the commitment is registered
        - no valid closure exists for it (per the projection)
        - its ``due_at`` is parseable and in the past relative to ``now``

    Commitments without ``due_at`` are treated as perpetual.
    Commitments whose ``due_at`` is unparseable are also treated as
    perpetual (conservative — matches pre-extraction behavior).

    Corruption surfaces as ``ReceiptStoreIntegrityError`` from the
    underlying projection walk; this function does not swallow it.
    """
    reference = now or datetime.now(timezone.utc)

    projection = project_commitment_lifecycle(store, now=reference)

    # Integrity failure parity: the pre-extraction detector propagated
    # ``ReceiptStoreIntegrityError`` directly rather than returning a
    # result with an error field. Preserve that contract — and the
    # original traceback for forensics — by re-raising the projection's
    # captured exception directly instead of wrapping its message in a
    # fresh instance.
    if projection.integrity_exception is not None:
        raise projection.integrity_exception

    open_commitments: List[OpenOverdueCommitment] = []
    for cmt_id, reg in projection.registrations.items():
        if cmt_id in projection.closures:
            continue  # closed by fulfillment — not overdue
        if cmt_id in projection.terminations:
            continue  # terminated (revoked | superseded | amended) — not overdue
        if not reg.due_at:
            continue  # perpetual
        due_dt = _parse_iso(reg.due_at)
        if due_dt is None:
            continue  # unparseable → perpetual (conservative)
        if due_dt >= reference:
            continue  # not yet overdue
        open_commitments.append(
            OpenOverdueCommitment(
                commitment_id=reg.commitment_id,
                trace_id=reg.trace_id,
                episode_id=reg.episode_id,
                actor_id=reg.actor_id,
                text=reg.text,
                commitment_type=reg.commitment_type,
                registered_at=reg.registered_at,
                due_at=reg.due_at,
                trace_path=None,
            )
        )

    return CommitmentClosureResult(
        open_commitments=open_commitments,
        total_traces_scanned=projection.total_traces_scanned,
        total_registered_found=len(projection.registrations),
        total_closed_found=len(projection.closures),
        total_open_found=len(open_commitments),
        scanned_at=projection.scanned_at,
    )


def check_commitment_health(
    store: AssayStore,
    *,
    loud: bool = True,
) -> bool:
    """Run overdue-commitment detection; optionally print to stderr.

    Returns True if the store is clean (no overdue open commitments).
    """
    import sys

    result = detect_open_overdue_commitments(store)
    if loud and not result.clean:
        print(
            f"[CONSTITUTIONAL VIOLATION] {result.total_open_found} overdue commitment(s) "
            "with no terminal fulfillment",
            file=sys.stderr,
        )
        for c in result.open_commitments:
            print(
                f"  open: commitment_id={c.commitment_id} "
                f"episode_id={c.episode_id} "
                f"due_at={c.due_at} "
                f"actor_id={c.actor_id} "
                f"trace={c.trace_id}",
                file=sys.stderr,
            )
    return result.clean


__all__ = [
    "OpenOverdueCommitment",
    "CommitmentClosureResult",
    "detect_open_overdue_commitments",
    "check_commitment_health",
]
