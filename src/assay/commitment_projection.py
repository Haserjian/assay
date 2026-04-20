"""Shared commitment-lifecycle projector.

Single source of truth for the per-aggregate closure doctrine ratified
in ``docs/doctrine/COMMITMENT_ORDERING.md``:

    - Lifecycle semantics project per commitment.
    - ``_store_seq`` is immutable witnessed append order; used for
      traversal and tie-breaking, never as a semantic global order.
    - A terminal fulfillment closes commitment ``C`` iff, at the
      terminal's ``_store_seq`` encounter point:
        * ``C`` was already registered, AND
        * a prior ``result.observed`` with the terminal's ``result_id``
          explicitly included ``{"kind": "commitment", "id": C}`` in
          its ``references`` list.

Before this module existed, the detector, explainer, and summarizer
each re-derived that rule from ``_iter_all_receipts`` independently.
Three readers, three near-identical walks, three opportunities for
semantic drift. This module collapses them into one pass.

Consumers (in order of how they derive their outputs from the
projection):

    1. ``commitment_summary.summarize_all_commitments``
    2. ``commitment_closure_detector.detect_open_overdue_commitments``
    3. ``commitment_explain.explain_commitment``

The projector is behavior-preserving by construction — every fact it
records is what each of the three readers already computed, just in a
shared structured form.

Purity contract:
    - Read-only. Never calls ``store.append`` / ``append_dict``.
    - Walks via ``_iter_all_receipts``, which fails closed on
      unreadable files, malformed JSON, missing/duplicate/negative/
      non-integer/non-monotonic ``_store_seq``, and mixed legacy+
      stamped state.
    - Integrity failures surface as ``integrity_error``; all other
      projection fields are empty in that case.
    - No prose. No CLI formatting. No ``is_overdue`` derivation (that
      is a per-reader, ``now``-dependent derivation — the projector
      records the facts, consumers interpret them).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
    TERMINAL_FULFILLMENT_TYPES,
    _iter_all_receipts,
)
from assay.store import AssayStore, ReceiptStoreIntegrityError


# ---------------------------------------------------------------------------
# Projected fact dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistrationFact:
    """The first ``commitment.registered`` receipt seen for a commitment.

    Subsequent registrations with the same commitment_id are ignored
    (first-seen wins) — matches the pre-extraction behavior in every
    reader.
    """

    commitment_id: str
    seq: int  # _store_seq of the registration receipt
    trace_id: str
    episode_id: str
    actor_id: str
    text: str
    commitment_type: str
    due_at: Optional[str]
    registered_at: str  # receipt-side timestamp (not _stored_at)


@dataclass(frozen=True)
class ObservationAnchorFact:
    """A ``result.observed`` receipt that names at least one commitment.

    Observations with an empty / missing ``references`` list do not
    anchor anything and are not recorded here.
    """

    seq: int  # _store_seq of the observation receipt
    result_id: str
    referenced_commitment_ids: Tuple[str, ...]


@dataclass(frozen=True)
class TerminalFact:
    """A terminal fulfillment receipt naming a commitment.

    Validity is determined at the terminal's encounter point in
    ``_store_seq`` order. Invalid terminals are kept — the explainer
    surfaces them in its timeline with the reason — but they do not
    produce a ``ClosureFact``.
    """

    seq: int  # _store_seq of the terminal receipt
    receipt_type: str  # "fulfillment.commitment_kept" | "commitment_broken"
    commitment_id: str
    result_id: str
    is_valid_closure: bool
    invalid_reasons: Tuple[str, ...]  # empty iff is_valid_closure


@dataclass(frozen=True)
class ClosureFact:
    """Derived: the single terminal (if any) that closed a commitment.

    First valid terminal in ``_store_seq`` order wins. Subsequent
    valid-looking terminals for the same commitment are recorded as
    ``TerminalFact`` with ``is_valid_closure=False`` and reason
    ``"post-closure terminal ..."``.
    """

    commitment_id: str
    closing_terminal_seq: int
    closing_terminal_type: str
    anchor_observation_seq: int  # seq of the result.observed that anchored it


@dataclass(frozen=True)
class CommitmentLifecycleProjection:
    """Ground-truth projection of the commitment lifecycle as recorded in
    the store's receipt corpus, in ``_store_seq`` order.

    Consumers derive their specific outputs by filtering / interpreting
    these facts; the projector itself never formats or decides.
    """

    # Per-commitment registration (first-seen wins), keyed by commitment_id
    registrations: Dict[str, RegistrationFact] = field(default_factory=dict)

    # Every observation that referenced at least one commitment, in
    # ``_store_seq`` order. Explainer filters this for per-commitment
    # timeline lines.
    observation_anchors: List[ObservationAnchorFact] = field(default_factory=list)

    # Every terminal receipt naming a commitment, in ``_store_seq``
    # order, with validity marked.
    terminals: List[TerminalFact] = field(default_factory=list)

    # Derived: commitment_id -> ClosureFact for commitments that have a
    # valid closing terminal.
    closures: Dict[str, ClosureFact] = field(default_factory=dict)

    # For detector's total_traces_scanned
    total_traces_scanned: int = 0

    # ISO-8601 timestamp when the projection was computed
    scanned_at: str = ""

    # Integrity failure from ``_iter_all_receipts`` surfaces here.
    # On integrity failure, all other fields are empty.
    integrity_error: Optional[str] = None


# ---------------------------------------------------------------------------
# The projector
# ---------------------------------------------------------------------------


def project_commitment_lifecycle(
    store: AssayStore,
    *,
    now: Optional[datetime] = None,
) -> CommitmentLifecycleProjection:
    """Walk ``store`` in ``_store_seq`` order and project lifecycle facts.

    Single pass. Same closure rule as the detector/explainer/summarizer.
    No derivations (e.g. ``is_overdue``) — those are per-reader,
    ``now``-dependent, and do not belong in the shared projection.

    Raises nothing; integrity failures from ``_iter_all_receipts`` are
    caught and surfaced via the ``integrity_error`` field so every
    consumer handles them uniformly.

    Args:
        store: the AssayStore to scan.
        now: reference time for the ``scanned_at`` stamp. Defaults to
            ``datetime.now(timezone.utc)``.

    Returns:
        ``CommitmentLifecycleProjection`` with registrations, anchors,
        terminals (valid + invalid with reasons), and derived closures.
    """
    reference = now or datetime.now(timezone.utc)
    scanned_at = reference.isoformat()

    try:
        entries = list(_iter_all_receipts(store))
    except ReceiptStoreIntegrityError as exc:
        return CommitmentLifecycleProjection(
            scanned_at=scanned_at,
            integrity_error=str(exc),
        )

    registrations: Dict[str, RegistrationFact] = {}
    observation_anchors: List[ObservationAnchorFact] = []
    terminals: List[TerminalFact] = []
    closures: Dict[str, ClosureFact] = {}
    trace_ids_seen: Set[str] = set()

    # Rolling state used to decide terminal validity at encounter time.
    # Keyed by (result_id, commitment_id); value is the most recent
    # observation seq where that pair was anchored. Updated on every
    # observation; consulted on every terminal.
    anchor_seq_by_pair: Dict[Tuple[str, str], int] = {}

    for entry in entries:
        rt = _extract_receipt_type(entry)
        seq = entry.get("_store_seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            # Defensive: _iter_all_receipts already enforces this.
            continue

        trace_id = str(entry.get("_trace_id") or "")
        if trace_id:
            trace_ids_seen.add(trace_id)

        if rt == COMMITMENT_REGISTRATION_RECEIPT_TYPE:
            cmt_id_raw = entry.get("commitment_id")
            if not cmt_id_raw:
                continue
            cmt_id = str(cmt_id_raw)
            if cmt_id in registrations:
                # First-seen wins. Matches pre-extraction behavior.
                continue
            registrations[cmt_id] = RegistrationFact(
                commitment_id=cmt_id,
                seq=seq,
                trace_id=trace_id,
                episode_id=str(entry.get("episode_id") or ""),
                actor_id=str(entry.get("actor_id") or ""),
                text=str(entry.get("text") or ""),
                commitment_type=str(entry.get("commitment_type") or ""),
                due_at=_opt_str(entry.get("due_at")),
                registered_at=_extract_timestamp(entry),
            )
            continue

        if rt == RESULT_OBSERVATION_RECEIPT_TYPE:
            result_id_raw = entry.get("result_id")
            if not result_id_raw:
                continue
            result_id = str(result_id_raw)
            referenced: List[str] = []
            for ref in entry.get("references") or []:
                if (
                    isinstance(ref, dict)
                    and ref.get("kind") == "commitment"
                    and ref.get("id")
                ):
                    ref_cmt = str(ref["id"])
                    referenced.append(ref_cmt)
                    # Latest observation seq wins (still strictly < future
                    # terminal seqs because we walk in _store_seq order).
                    anchor_seq_by_pair[(result_id, ref_cmt)] = seq

            if referenced:
                observation_anchors.append(
                    ObservationAnchorFact(
                        seq=seq,
                        result_id=result_id,
                        referenced_commitment_ids=tuple(referenced),
                    )
                )
            continue

        if rt in TERMINAL_FULFILLMENT_TYPES:
            cmt_id_raw = entry.get("commitment_id")
            result_id_raw = entry.get("result_id")
            if not cmt_id_raw or not result_id_raw:
                continue
            cmt_id = str(cmt_id_raw)
            result_id = str(result_id_raw)

            has_registration = cmt_id in registrations
            anchor_seq = anchor_seq_by_pair.get((result_id, cmt_id))
            has_anchor = anchor_seq is not None
            already_closed = cmt_id in closures

            reasons: List[str] = []
            if not has_registration:
                reasons.append("no registration seen before this terminal")
            if not has_anchor:
                reasons.append(
                    f"no anchor edge from result_id={result_id!r} to "
                    f"commitment={cmt_id!r} at the terminal's encounter point"
                )
            if already_closed:
                reasons.append(
                    f"post-closure terminal (commitment already closed "
                    f"by seq={closures[cmt_id].closing_terminal_seq})"
                )

            is_valid = not reasons

            terminals.append(
                TerminalFact(
                    seq=seq,
                    receipt_type=rt,
                    commitment_id=cmt_id,
                    result_id=result_id,
                    is_valid_closure=is_valid,
                    invalid_reasons=tuple(reasons),
                )
            )

            if is_valid:
                # anchor_seq is not None here because has_anchor was True.
                closures[cmt_id] = ClosureFact(
                    commitment_id=cmt_id,
                    closing_terminal_seq=seq,
                    closing_terminal_type=rt,
                    anchor_observation_seq=anchor_seq,  # type: ignore[arg-type]
                )
            continue

    return CommitmentLifecycleProjection(
        registrations=registrations,
        observation_anchors=observation_anchors,
        terminals=terminals,
        closures=closures,
        total_traces_scanned=len(trace_ids_seen),
        scanned_at=scanned_at,
    )


# ---------------------------------------------------------------------------
# Small internal helpers (kept local to this module — not exported)
# ---------------------------------------------------------------------------


def _extract_receipt_type(entry: Dict[str, Any]) -> str:
    return str(entry.get("type") or entry.get("receipt_type") or "")


def _extract_timestamp(entry: Dict[str, Any]) -> str:
    return str(entry.get("timestamp") or entry.get("_stored_at") or "")


def _opt_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value)
    return s if s else None


__all__ = [
    "RegistrationFact",
    "ObservationAnchorFact",
    "TerminalFact",
    "ClosureFact",
    "CommitmentLifecycleProjection",
    "project_commitment_lifecycle",
]
