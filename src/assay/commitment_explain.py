"""Read-only doctrine surface: explain why a commitment is OPEN / CLOSED.

The Slice 1 wedge made closure semantics enforceable at the storage layer.
This module makes those semantics *inspectable* by humans. It walks the
receipt corpus in ``_store_seq`` order (the same chronology the detector
trusts) and reports, for a given commitment_id:

    - Whether it was registered, and where in receipt order
    - All result.observed receipts whose references include it
    - All terminal fulfillment receipts naming it, and whether each one
      had a valid anchor edge at its encounter point
    - The resulting state (``OPEN`` | ``CLOSED`` | ``NOT_REGISTERED`` |
      ``INVALID_STORE``) and a plain-text decision explaining why

Invariants this module preserves:
    - Read-only. Never calls ``store.append`` / ``store.append_dict``.
    - Fails closed on corpus corruption, mixed state, or integrity
      violations (surfaces them as ``INVALID_STORE`` rather than
      proceeding with partial data).
    - Uses the same causal-order primitive (``_store_seq``) as the
      detector — not a parallel or approximate rule.

Not a repair tool. Intentionally does not offer remediation beyond
naming the missing condition.

CLI:
    assay commitments explain <id> [--json] [--base-dir PATH]

The command's home in the larger CLI tree is ``assay commitments``, a
new sub-app added by this module. We intentionally do NOT mount at
``assay explain`` because that name already belongs to the proof-pack
explainer (``@assay_app.command("explain")`` in ``commands.py``);
mounting a sub-app there would silently shadow the pack-explain command.
Future commitment-scoped subcommands (``list``, ``overdue``, ``verify``)
attach to the same ``commitments`` group.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import typer

from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
    TERMINAL_FULFILLMENT_TYPES,
    _iter_all_receipts,
)
from assay.commitment_summary import (
    CommitmentSummary,
    SummariesResult,
    summarize_all_commitments,
)
from assay.store import (
    AssayStore,
    ReceiptStoreIntegrityError,
    get_default_store,
)


@dataclass(frozen=True)
class ExplainLine:
    """One receipt in the explanation timeline."""

    seq: int
    receipt_type: str
    summary: str
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "receipt_type": self.receipt_type,
            "summary": self.summary,
            "note": self.note,
        }


@dataclass(frozen=True)
class ExplainResult:
    """The full explanation record for a single commitment."""

    commitment_id: str
    state: str  # CLOSED | OPEN | NOT_REGISTERED | INVALID_STORE
    registration: Optional[ExplainLine]
    timeline: List[ExplainLine]
    decision: str
    integrity_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "state": self.state,
            "registration": (
                self.registration.to_dict() if self.registration else None
            ),
            "timeline": [line.to_dict() for line in self.timeline],
            "decision": self.decision,
            "integrity_error": self.integrity_error,
        }


def explain_commitment(store: AssayStore, commitment_id: str) -> ExplainResult:
    """Walk ``store`` in ``_store_seq`` order and explain ``commitment_id``'s state.

    Pure-read. Fails closed on corpus corruption: returns
    ``state="INVALID_STORE"`` with the integrity error, rather than
    proceeding with partial / mixed / corrupt evidence.

    Closure rule matches the detector:
        A terminal fulfillment closes commitment C at the point it is
        encountered IFF, at that seq position:
            - C has been registered
            - some prior result.observed receipt with result_id=R
              exists whose references explicitly include
              ``{"kind": "commitment", "id": C}``

        Later observations cannot retroactively legitimize earlier
        terminals.
    """
    try:
        entries = list(_iter_all_receipts(store))
    except ReceiptStoreIntegrityError as exc:
        return ExplainResult(
            commitment_id=commitment_id,
            state="INVALID_STORE",
            registration=None,
            timeline=[],
            decision=(
                "INVALID_STORE: the receipt corpus failed strict integrity "
                "validation. Cannot reason about commitment state until the "
                "store is repaired."
            ),
            integrity_error=str(exc),
        )

    registration: Optional[ExplainLine] = None
    timeline: List[ExplainLine] = []
    # result_id -> set of commitment_ids whose anchor edge is present
    # by the point we reach each receipt in seq order.
    observed_result_anchors: Dict[str, Set[str]] = {}

    closing_terminal_seq: Optional[int] = None
    closing_terminal_type: Optional[str] = None
    closing_anchor_seq: Optional[int] = None
    terminal_lines_for_cmt: List[ExplainLine] = []

    for entry in entries:
        rt = str(entry.get("type") or entry.get("receipt_type") or "")
        seq = entry.get("_store_seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            # _iter_all_receipts already fails closed on missing/invalid seq;
            # this branch is defensive and should not be reachable.
            continue

        if rt == COMMITMENT_REGISTRATION_RECEIPT_TYPE:
            if entry.get("commitment_id") != commitment_id:
                continue
            line = ExplainLine(
                seq=seq,
                receipt_type=rt,
                summary=(
                    f"registered by actor_id={entry.get('actor_id', '?')!r}, "
                    f"due_at={entry.get('due_at', 'perpetual')}"
                ),
                note="ok",
            )
            if registration is None:
                registration = line
            timeline.append(line)
            continue

        if rt == RESULT_OBSERVATION_RECEIPT_TYPE:
            result_id = entry.get("result_id")
            if not result_id:
                continue
            referenced: Set[str] = set()
            for ref in entry.get("references") or []:
                if (
                    isinstance(ref, dict)
                    and ref.get("kind") == "commitment"
                    and ref.get("id")
                ):
                    referenced.add(str(ref["id"]))
            observed_result_anchors.setdefault(str(result_id), set()).update(
                referenced
            )

            if commitment_id in referenced:
                timeline.append(ExplainLine(
                    seq=seq,
                    receipt_type=rt,
                    summary=f"observed result_id={result_id!r}",
                    note="anchor edge present",
                ))
            continue

        if rt in TERMINAL_FULFILLMENT_TYPES:
            if entry.get("commitment_id") != commitment_id:
                continue
            result_id = str(entry.get("result_id") or "")
            has_registration = registration is not None
            anchors_for_result = observed_result_anchors.get(result_id, set())
            has_anchor_edge = commitment_id in anchors_for_result
            already_closed = closing_terminal_seq is not None
            is_valid_closure = (
                has_registration and has_anchor_edge and not already_closed
            )

            if is_valid_closure:
                closing_terminal_seq = seq
                closing_terminal_type = rt
                # Find the most recent matching observation line for the
                # decision text (seq of the anchor edge).
                for prev in timeline:
                    if (
                        prev.receipt_type == RESULT_OBSERVATION_RECEIPT_TYPE
                        and f"result_id={result_id!r}" in prev.summary
                    ):
                        closing_anchor_seq = prev.seq
                line = ExplainLine(
                    seq=seq,
                    receipt_type=rt,
                    summary=f"fulfillment for result_id={result_id!r}",
                    note="closes commitment",
                )
            else:
                reasons: List[str] = []
                if not has_registration:
                    reasons.append(
                        "no registration seen before this terminal"
                    )
                if not has_anchor_edge:
                    reasons.append(
                        f"no anchor edge from result_id={result_id!r} "
                        f"to commitment={commitment_id!r} "
                        "at the terminal's encounter point"
                    )
                if already_closed:
                    reasons.append(
                        f"post-closure terminal (commitment already closed "
                        f"by seq={closing_terminal_seq})"
                    )
                reason_text = "; ".join(reasons) or "unknown"
                line = ExplainLine(
                    seq=seq,
                    receipt_type=rt,
                    summary=f"fulfillment for result_id={result_id!r}",
                    note=f"invalid anchor ({reason_text})",
                )
            timeline.append(line)
            terminal_lines_for_cmt.append(line)
            continue

    # ----- Decision -----

    if registration is None:
        return ExplainResult(
            commitment_id=commitment_id,
            state="NOT_REGISTERED",
            registration=None,
            timeline=timeline,
            decision=(
                f"NOT_REGISTERED: no commitment.registered receipt found "
                f"for commitment_id={commitment_id!r}."
            ),
        )

    if closing_terminal_seq is not None:
        anchor_hint = (
            f" and anchor result.observed seq={closing_anchor_seq} "
            "explicitly references this commitment"
            if closing_anchor_seq is not None
            else ""
        )
        decision = (
            f"CLOSED because terminal {closing_terminal_type!r} "
            f"seq={closing_terminal_seq} occurred with a valid anchor edge"
            f"{anchor_hint}."
        )
        return ExplainResult(
            commitment_id=commitment_id,
            state="CLOSED",
            registration=registration,
            timeline=timeline,
            decision=decision,
        )

    # OPEN: compose an informative reason.
    if not terminal_lines_for_cmt:
        decision = (
            "OPEN because the commitment is registered but no fulfillment "
            "(commitment_kept or commitment_broken) terminal receipt has "
            "been emitted for it yet."
        )
    else:
        invalid_summaries = [
            f"seq={line.seq} ({line.note})"
            for line in terminal_lines_for_cmt
        ]
        decision = (
            "OPEN because at least one terminal fulfillment receipt names "
            "this commitment, but none had a valid anchor edge at its "
            "encounter point in _store_seq order. Invalid terminals: "
            + "; ".join(invalid_summaries)
            + "."
        )

    return ExplainResult(
        commitment_id=commitment_id,
        state="OPEN",
        registration=registration,
        timeline=timeline,
        decision=decision,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


commitments_app = typer.Typer(
    name="commitments",
    help=(
        "Commitment-lifecycle operator surface. "
        "Subcommands: list (all commitments), overdue (OPEN past due_at), "
        "explain (single commitment state)."
    ),
    no_args_is_help=True,
)


@commitments_app.callback()
def _commitments_root() -> None:
    """Commitment-lifecycle sub-app.

    The callback exists to keep Typer treating ``commitments`` as a
    command *group* (not collapsed into a single-command CLI) even when
    only one subcommand is registered. Future subcommands (``list``,
    ``overdue``, ``verify``) attach here naturally.
    """


@commitments_app.command("explain")
def explain_commitment_cmd(
    commitment_id: str = typer.Argument(
        ..., help="The commitment_id to explain."
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the result as JSON instead of plain text.",
    ),
    base_dir: Optional[Path] = typer.Option(
        None,
        "--base-dir",
        help=(
            "Override the default AssayStore location. Useful for "
            "inspecting a specific store; defaults to ~/.assay."
        ),
    ),
) -> None:
    """Explain the lifecycle state of a commitment.

    Read-only: does not mutate store state, does not emit receipts.
    """
    if base_dir is not None:
        store = AssayStore(base_dir=base_dir)
    else:
        store = get_default_store()

    result = explain_commitment(store, commitment_id)

    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    typer.echo(f"Commitment: {result.commitment_id}")
    typer.echo(f"State: {result.state}")
    if result.integrity_error:
        typer.echo(f"Integrity error: {result.integrity_error}")
    if result.registration is not None:
        r = result.registration
        typer.echo("Registration:")
        typer.echo(f"  seq={r.seq} type={r.receipt_type}")
        typer.echo(f"  {r.summary}")
    if result.timeline:
        typer.echo("Timeline:")
        for line in result.timeline:
            typer.echo(
                f"  seq={line.seq:<6} {line.receipt_type:<40} "
                f"{line.note}"
            )
            typer.echo(f"       {line.summary}")
    typer.echo("Decision:")
    typer.echo(f"  {result.decision}")


def _resolve_store(base_dir: Optional[Path]) -> AssayStore:
    """Shared base-dir resolution for commitments_app subcommands."""
    if base_dir is not None:
        return AssayStore(base_dir=base_dir)
    return get_default_store()


def _format_summary_line(s: CommitmentSummary) -> str:
    """One-line operator text for a :class:`CommitmentSummary`.

    Stable shape for easy grepping by operators; tests should assert
    structured fields from ``--json``, not this prose format.
    """
    overdue_marker = " [OVERDUE]" if s.is_overdue else ""
    closing = (
        f" via seq={s.closing_terminal_seq} ({s.closing_terminal_type})"
        if s.closing_terminal_seq is not None
        else ""
    )
    return (
        f"{s.commitment_id}  {s.state}{overdue_marker}  "
        f"registered_seq={s.registered_seq}  "
        f"due={s.due_at or 'perpetual'}  actor={s.actor_id}{closing}"
    )


@commitments_app.command("list")
def list_commitments_cmd(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the result as JSON instead of plain text.",
    ),
    base_dir: Optional[Path] = typer.Option(
        None,
        "--base-dir",
        help=(
            "Override the default AssayStore location. Useful for "
            "inspecting a specific store; defaults to ~/.assay."
        ),
    ),
) -> None:
    """List all commitments in the store with their current state.

    Open commitments past their ``due_at`` are flagged ``[OVERDUE]``.
    Read-only: does not mutate store state, does not emit receipts.

    Exits nonzero if the store fails strict integrity validation.
    """
    store = _resolve_store(base_dir)
    result = summarize_all_commitments(store)

    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        if result.integrity_error:
            raise typer.Exit(1)
        return

    if result.integrity_error:
        typer.echo(f"INVALID_STORE: {result.integrity_error}")
        raise typer.Exit(1)

    if not result.commitments:
        typer.echo("No commitments registered.")
        return

    typer.echo(
        f"{len(result.commitments)} commitment(s) "
        f"(scanned_at={result.scanned_at})"
    )
    for s in result.commitments:
        typer.echo(_format_summary_line(s))
        if s.text:
            typer.echo(f"    {s.text}")


@commitments_app.command("overdue")
def overdue_commitments_cmd(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the result as JSON instead of plain text.",
    ),
    base_dir: Optional[Path] = typer.Option(
        None,
        "--base-dir",
        help=(
            "Override the default AssayStore location. Useful for "
            "inspecting a specific store; defaults to ~/.assay."
        ),
    ),
) -> None:
    """Show only commitments that are OPEN and past their ``due_at``.

    Filtered view over the same bulk scan used by ``commitments list``.
    Read-only: does not mutate store state, does not emit receipts.

    Exits nonzero if the store fails strict integrity validation.
    """
    store = _resolve_store(base_dir)
    full_result = summarize_all_commitments(store)
    overdue_only = [c for c in full_result.commitments if c.is_overdue]
    filtered = SummariesResult(
        commitments=overdue_only,
        scanned_at=full_result.scanned_at,
        integrity_error=full_result.integrity_error,
    )

    if json_output:
        typer.echo(json.dumps(filtered.to_dict(), indent=2))
        if filtered.integrity_error:
            raise typer.Exit(1)
        return

    if filtered.integrity_error:
        typer.echo(f"INVALID_STORE: {filtered.integrity_error}")
        raise typer.Exit(1)

    if not overdue_only:
        typer.echo("No overdue commitments.")
        return

    typer.echo(
        f"{len(overdue_only)} overdue commitment(s) "
        f"(scanned_at={filtered.scanned_at})"
    )
    for s in overdue_only:
        typer.echo(_format_summary_line(s))
        if s.text:
            typer.echo(f"    {s.text}")


__all__ = [
    "ExplainLine",
    "ExplainResult",
    "explain_commitment",
    "commitments_app",
    "explain_commitment_cmd",
    "list_commitments_cmd",
    "overdue_commitments_cmd",
]
