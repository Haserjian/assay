"""Single-pass bulk summary of every commitment in the store.

Used as the shared data source for ``assay commitments list`` and
``assay commitments overdue``. The underlying walk is the same
causal-order primitive the detector/explainer trust
(``_iter_all_receipts``); this module never re-implements lifecycle
semantics — it just aggregates them in one pass.

Design constraint (from slice review):
    ``list`` must NOT call ``explain_commitment`` per id (N×corpus
    rescan). This module does one full-store walk and emits a per-
    commitment summary; ``overdue`` is a filtered view over the same
    summaries.

Read-only. Fails closed on corrupt / mixed / legacy corpus by returning
an empty summaries list with ``integrity_error`` set — callers decide
whether to exit nonzero or continue.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
    TERMINAL_FULFILLMENT_TYPES,
    _iter_all_receipts,
)
from assay.store import AssayStore, ReceiptStoreIntegrityError


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

    ``integrity_error`` is ``None`` on a clean walk; otherwise
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
    """Bulk-summarize every commitment in ``store`` in one corpus pass.

    Closure rule matches the detector/explainer: a terminal closes
    commitment C iff, at the terminal's ``_store_seq`` encounter point:

        - C has been registered
        - some prior ``result.observed`` carries the terminal's
          ``result_id`` AND lists ``{"kind": "commitment", "id": C}``
          in its ``references``

    Later observations do not retroactively legitimize earlier terminals.
    The first valid terminal wins per commitment; later valid-looking
    terminals are ignored (they would be ``invalid anchor`` in the
    explainer's timeline).

    Returns an empty list with ``integrity_error`` set on
    ``ReceiptStoreIntegrityError`` from the underlying iterator.
    """
    reference = now or datetime.now(timezone.utc)
    scanned_at = reference.isoformat()

    try:
        entries = list(_iter_all_receipts(store))
    except ReceiptStoreIntegrityError as exc:
        return SummariesResult(
            commitments=[],
            scanned_at=scanned_at,
            integrity_error=str(exc),
        )

    registered: Dict[str, Dict[str, Any]] = {}
    observed_result_anchors: Dict[str, Set[str]] = {}
    closing_terminals: Dict[str, Tuple[int, str]] = {}

    for entry in entries:
        rt = str(entry.get("type") or entry.get("receipt_type") or "")
        seq = entry.get("_store_seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            # Defensive: _iter_all_receipts already enforces this.
            continue

        if rt == COMMITMENT_REGISTRATION_RECEIPT_TYPE:
            cmt_id = entry.get("commitment_id")
            if cmt_id and cmt_id not in registered:
                registered[str(cmt_id)] = {
                    "registered_seq": seq,
                    "actor_id": str(entry.get("actor_id") or ""),
                    "text": str(entry.get("text") or ""),
                    "commitment_type": str(entry.get("commitment_type") or ""),
                    "due_at": entry.get("due_at") or None,
                }
            continue

        if rt == RESULT_OBSERVATION_RECEIPT_TYPE:
            result_id = entry.get("result_id")
            if not result_id:
                continue
            for ref in entry.get("references") or []:
                if (
                    isinstance(ref, dict)
                    and ref.get("kind") == "commitment"
                    and ref.get("id")
                ):
                    observed_result_anchors.setdefault(
                        str(result_id), set()
                    ).add(str(ref["id"]))
            continue

        if rt in TERMINAL_FULFILLMENT_TYPES:
            cmt_id = entry.get("commitment_id")
            result_id = entry.get("result_id")
            if not cmt_id or not result_id:
                continue
            cmt_s = str(cmt_id)
            result_s = str(result_id)
            if cmt_s not in registered:
                continue
            if cmt_s not in observed_result_anchors.get(result_s, set()):
                continue
            # First valid terminal wins. Later terminals for an already-
            # closed commitment are ignored for summary purposes.
            if cmt_s not in closing_terminals:
                closing_terminals[cmt_s] = (seq, rt)
            continue

    summaries: List[CommitmentSummary] = []
    # Stable order: by registered_seq so CLI output is reproducible.
    for cmt_id, info in sorted(
        registered.items(), key=lambda item: item[1]["registered_seq"]
    ):
        closing = closing_terminals.get(cmt_id)
        state = "CLOSED" if closing else "OPEN"
        closing_seq = closing[0] if closing else None
        closing_type = closing[1] if closing else None

        is_overdue = False
        if state == "OPEN" and info["due_at"]:
            parsed = _parse_iso(str(info["due_at"]))
            if parsed is not None and parsed < reference:
                is_overdue = True

        summaries.append(
            CommitmentSummary(
                commitment_id=cmt_id,
                state=state,
                actor_id=info["actor_id"],
                text=info["text"],
                commitment_type=info["commitment_type"],
                due_at=info["due_at"],
                registered_seq=info["registered_seq"],
                closing_terminal_seq=closing_seq,
                closing_terminal_type=closing_type,
                is_overdue=is_overdue,
            )
        )

    return SummariesResult(commitments=summaries, scanned_at=scanned_at)


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
