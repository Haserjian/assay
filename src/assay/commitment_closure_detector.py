"""Commitment closure detector — DOCTOR_COMMITMENT_001.

Pure-read scan of an AssayStore that flags ``commitment.registered`` receipts
with a past ``due_at`` and no terminal fulfillment
(``fulfillment.commitment_kept`` | ``fulfillment.commitment_broken``).

Mirrors ``contradiction_detector.py`` structurally. No mutations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
    TERMINAL_FULFILLMENT_TYPES,
    _iter_all_receipts,
)
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


def _extract_receipt_type(entry: Dict[str, Any]) -> str:
    return str(entry.get("type") or entry.get("receipt_type") or "")


def _extract_timestamp(entry: Dict[str, Any]) -> str:
    return str(entry.get("timestamp") or entry.get("_stored_at") or "")


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

    Closure rule (order-aware):
        A terminal fulfillment closes commitment C if, *at the point the
        terminal is encountered in receipt order*:
          - C was already registered (``commitment.registered``); AND
          - result R was already observed (``result.observed`` with
            ``result_id == terminal.result_id``); AND
          - that observation's ``references`` list explicitly carried
            ``{"kind": "commitment", "id": C}``.

    Future observations cannot retroactively legitimize prior terminals.
    Forged terminals written before any observation — or naming a result
    that observed a different commitment — do not close anything.

    A commitment is "open and overdue" when:
        - It is registered.
        - Its ``due_at`` is parseable and in the past relative to ``now``.
        - No valid closure edge was observed for it.

    Commitments without ``due_at`` are treated as perpetual in Slice 1
    and never flagged. Commitments whose ``due_at`` is unparseable are
    treated conservatively as perpetual.

    Scan is full-store and fail-closed: corruption surfaces as
    ``ReceiptStoreIntegrityError``, not as missing evidence.

    Args:
        store: The AssayStore to scan.
        now: Reference time for overdue comparison. Defaults to
            ``datetime.now(timezone.utc)``.

    Returns:
        CommitmentClosureResult with all findings.
    """
    reference = now or datetime.now(timezone.utc)
    scanned_at = reference.isoformat()

    registered: Dict[str, Dict[str, Any]] = {}
    # result_id -> set of commitment_ids the observation explicitly referenced.
    observed_result_anchors: Dict[str, Set[str]] = {}
    closed_ids: Set[str] = set()
    trace_ids_seen: Set[str] = set()

    # Walk receipts in store order (path-sorted, then line order).
    # _iter_all_receipts raises ReceiptStoreIntegrityError on corruption.
    for entry in _iter_all_receipts(store):
        rt = _extract_receipt_type(entry)
        trace_id = str(entry.get("_trace_id") or "")
        if trace_id:
            trace_ids_seen.add(trace_id)

        if rt == COMMITMENT_REGISTRATION_RECEIPT_TYPE:
            cmt_id = entry.get("commitment_id")
            if cmt_id and cmt_id not in registered:
                registered[cmt_id] = {
                    "trace_id": trace_id,
                    "trace_path": None,
                    "episode_id": str(entry.get("episode_id") or ""),
                    "actor_id": str(entry.get("actor_id") or ""),
                    "text": str(entry.get("text") or ""),
                    "commitment_type": str(entry.get("commitment_type") or ""),
                    "registered_at": _extract_timestamp(entry),
                    "due_at": str(entry.get("due_at") or ""),
                }
            continue

        if rt == RESULT_OBSERVATION_RECEIPT_TYPE:
            result_id = entry.get("result_id")
            if not result_id:
                continue
            anchors = observed_result_anchors.setdefault(str(result_id), set())
            for ref in entry.get("references") or []:
                if (
                    isinstance(ref, dict)
                    and ref.get("kind") == "commitment"
                    and ref.get("id")
                ):
                    anchors.add(str(ref["id"]))
            continue

        if rt in TERMINAL_FULFILLMENT_TYPES:
            cmt_id = entry.get("commitment_id")
            result_id = entry.get("result_id")
            if not cmt_id or not result_id:
                continue
            cmt_id_s = str(cmt_id)
            result_id_s = str(result_id)
            # At the temporal point of THIS terminal:
            #   - commitment must already be registered
            #   - result must already be observed with this commitment in refs
            if cmt_id_s not in registered:
                continue  # terminal precedes registration — invalid
            if cmt_id_s not in observed_result_anchors.get(result_id_s, set()):
                continue  # no valid (result_id, commitment_id) edge yet — invalid
            closed_ids.add(cmt_id_s)
            continue

    open_commitments: List[OpenOverdueCommitment] = []
    for cmt_id, info in registered.items():
        if cmt_id in closed_ids:
            continue
        due_at_str = info["due_at"]
        if not due_at_str:
            continue  # perpetual
        due_at_dt = _parse_iso(due_at_str)
        if due_at_dt is None:
            continue  # unparseable → perpetual (conservative)
        if due_at_dt >= reference:
            continue  # not yet overdue
        open_commitments.append(OpenOverdueCommitment(
            commitment_id=cmt_id,
            trace_id=info["trace_id"],
            episode_id=info["episode_id"],
            actor_id=info["actor_id"],
            text=info["text"],
            commitment_type=info["commitment_type"],
            registered_at=info["registered_at"],
            due_at=info["due_at"],
            trace_path=info["trace_path"],
        ))

    return CommitmentClosureResult(
        open_commitments=open_commitments,
        total_traces_scanned=len(trace_ids_seen),
        total_registered_found=len(registered),
        total_closed_found=len(closed_ids),
        total_open_found=len(open_commitments),
        scanned_at=scanned_at,
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
