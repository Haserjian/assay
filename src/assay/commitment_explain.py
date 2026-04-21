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
from typing import Any, Dict, List, Optional

import typer

from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
)
from assay.commitment_projection import project_commitment_lifecycle
from assay.commitment_summary import (
    CommitmentSummary,
    SummariesResult,
    summarize_all_commitments,
)
from assay.store import (
    AssayStore,
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
    """The full explanation record for a single commitment.

    States:
        CLOSED         — ended by fulfillment (kept | broken).
        TERMINATED     — ended by commitment.terminated (revoked |
                         superseded | amended). Non-fulfillment ending.
        OPEN           — registered, no terminal event yet.
        NOT_REGISTERED — no registration receipt found.
        INVALID_STORE  — the receipt corpus failed integrity validation.
    """

    commitment_id: str
    state: str  # CLOSED | TERMINATED | OPEN | NOT_REGISTERED | INVALID_STORE
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
    """Explain ``commitment_id``'s state from the shared lifecycle projection.

    Pure-read. Fails closed on corpus corruption: returns
    ``state="INVALID_STORE"`` with the integrity error, rather than
    proceeding with partial / mixed / corrupt evidence.

    Closure semantics come from
    :func:`assay.commitment_projection.project_commitment_lifecycle`;
    this function's remaining job is the per-commitment presentation:
    selecting the commitment's own registration / anchor-observation /
    terminal lines from the projection, building the timeline in
    ``_store_seq`` order, and composing the plain-text decision string.
    """
    projection = project_commitment_lifecycle(store)

    if projection.integrity_error is not None:
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
            integrity_error=projection.integrity_error,
        )

    reg_fact = projection.registrations.get(commitment_id)
    closure_fact = projection.closures.get(commitment_id)
    termination_fact = projection.terminations.get(commitment_id)

    # Build the per-commitment timeline. The projection already has
    # everything we need; we just filter and translate facts into the
    # presentation-layer ``ExplainLine`` shape, then sort by seq.

    registration: Optional[ExplainLine] = None
    if reg_fact is not None:
        due_at_display = reg_fact.due_at if reg_fact.due_at else "perpetual"
        registration = ExplainLine(
            seq=reg_fact.seq,
            receipt_type=COMMITMENT_REGISTRATION_RECEIPT_TYPE,
            summary=(
                f"registered by actor_id={reg_fact.actor_id!r}, "
                f"due_at={due_at_display}"
            ),
            note="ok",
        )

    # Observation lines: only those referencing this commitment.
    observation_lines: List[ExplainLine] = []
    for obs in projection.observation_anchors:
        if commitment_id not in obs.referenced_commitment_ids:
            continue
        observation_lines.append(
            ExplainLine(
                seq=obs.seq,
                receipt_type=RESULT_OBSERVATION_RECEIPT_TYPE,
                summary=f"observed result_id={obs.result_id!r}",
                note="anchor edge present",
            )
        )

    # Terminal lines: only those naming this commitment.
    terminal_lines_for_cmt: List[ExplainLine] = []
    for term in projection.terminals:
        if term.commitment_id != commitment_id:
            continue
        if term.is_valid_closure:
            line = ExplainLine(
                seq=term.seq,
                receipt_type=term.receipt_type,
                summary=f"fulfillment for result_id={term.result_id!r}",
                note="closes commitment",
            )
        else:
            reason_text = "; ".join(term.invalid_reasons) or "unknown"
            line = ExplainLine(
                seq=term.seq,
                receipt_type=term.receipt_type,
                summary=f"fulfillment for result_id={term.result_id!r}",
                note=f"invalid anchor ({reason_text})",
            )
        terminal_lines_for_cmt.append(line)

    # Termination line (commitment.terminated, if any).
    termination_line: Optional[ExplainLine] = None
    if termination_fact is not None:
        replacement_hint = (
            f", replacement={termination_fact.replacement_commitment_id!r}"
            if termination_fact.replacement_commitment_id
            else ""
        )
        amended_hint = (
            f", amended_field={termination_fact.amended_field!r}"
            if termination_fact.amended_field
            and termination_fact.amended_field != "none"
            else ""
        )
        termination_line = ExplainLine(
            seq=termination_fact.seq,
            receipt_type="commitment.terminated",
            summary=(
                f"terminated (reason={termination_fact.terminal_reason}"
                f"{amended_hint}{replacement_hint})"
            ),
            note="terminates commitment",
        )

    # Compose the timeline in seq order. The projection guarantees seq
    # is the authoritative causal key for this per-aggregate view.
    timeline: List[ExplainLine] = []
    if registration is not None:
        timeline.append(registration)
    timeline.extend(observation_lines)
    timeline.extend(terminal_lines_for_cmt)
    if termination_line is not None:
        timeline.append(termination_line)
    timeline.sort(key=lambda line: line.seq)

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

    if closure_fact is not None:
        anchor_hint = (
            f" and anchor result.observed seq={closure_fact.anchor_observation_seq} "
            "explicitly references this commitment"
        )
        decision = (
            f"CLOSED because terminal {closure_fact.closing_terminal_type!r} "
            f"seq={closure_fact.closing_terminal_seq} occurred with a valid "
            f"anchor edge{anchor_hint}."
        )
        return ExplainResult(
            commitment_id=commitment_id,
            state="CLOSED",
            registration=registration,
            timeline=timeline,
            decision=decision,
        )

    if termination_fact is not None:
        replacement_hint = (
            f" replacement_commitment_id="
            f"{termination_fact.replacement_commitment_id!r}."
            if termination_fact.replacement_commitment_id
            else ""
        )
        decision = (
            f"TERMINATED because commitment.terminated "
            f"seq={termination_fact.seq} ended the commitment "
            f"with terminal_reason={termination_fact.terminal_reason!r}. "
            "This is a non-fulfillment ending — not a kept/broken "
            "outcome." + (f" {replacement_hint}" if replacement_hint else "")
        )
        return ExplainResult(
            commitment_id=commitment_id,
            state="TERMINATED",
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
    if s.closing_terminal_seq is not None:
        closing = f" via seq={s.closing_terminal_seq} ({s.closing_terminal_type})"
    elif s.termination_seq is not None:
        replacement = (
            f" replacement={s.replacement_commitment_id}"
            if s.replacement_commitment_id
            else ""
        )
        closing = (
            f" via seq={s.termination_seq} "
            f"(commitment.terminated:{s.terminal_reason}){replacement}"
        )
    else:
        closing = ""
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
