"""Legacy-store migration: backfill ``_store_seq`` on pre-Slice-1 receipts.

The Slice 1 commitment-fulfillment wedge treats ``_store_seq`` as the
authoritative receipt-order primitive and fails closed on any receipt
lacking it. That is the correct posture for new-format stores, but an
unannounced upgrade for stores written before the primitive existed.

This module provides an explicit migration. It does NOT run implicitly,
and it does NOT silently reinterpret path order as causal order.

Ordering basis
--------------
Legacy receipts have no witnessed global order, so migration must
reconstruct one. The chosen basis is:

    (sorted trace-file path, physical line number within file)

Within a file this preserves append order exactly. Across files it uses
lexicographic path order as a best-effort approximation. The migration
records this basis explicitly so consumers can tell reconstructed order
apart from witnessed order.

Guarantees
----------
- Refuses to run if any receipt already carries a ``_store_seq`` (mixed
  state is an operator decision, not a migration one).
- Refuses to run on malformed JSON or unreadable files.
- Atomic per-file rewrites via ``.tmp`` + ``rename``.
- Updates ``<base_dir>/.store_seq`` so subsequent writes continue the
  monotonic sequence.
- Emits a summary dict that callers may log or persist as an audit trail.

Invariant preserved
-------------------
Canonical payload hashes (``canonical_hash``, ``receipt_hash``) already
exclude ``_store_seq`` from their input in every consumer updated by
Slice 1, so adding the field does not invalidate existing signatures.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from assay.commitment_fulfillment import ReceiptStoreIntegrityError
from assay.store import AssayStore


class StoreMigrationError(RuntimeError):
    """Raised when migration cannot safely proceed.

    Distinct from ``ReceiptStoreIntegrityError`` — this signals an
    operator condition (mixed state, malformed data) rather than a
    runtime invariant failure.
    """


@dataclass(frozen=True)
class MigrationResult:
    """Audit summary of a migration run."""

    files_scanned: int
    files_rewritten: int
    receipts_backfilled: int
    next_seq: int
    ordering_basis: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_rewritten": self.files_rewritten,
            "receipts_backfilled": self.receipts_backfilled,
            "next_seq": self.next_seq,
            "ordering_basis": self.ordering_basis,
        }


def migrate_legacy_store_seq(store: AssayStore) -> MigrationResult:
    """Backfill ``_store_seq`` on legacy receipts in ``store``.

    The store must be in a pre-migration state: either wholly free of
    ``_store_seq`` (pure legacy) or wholly carrying it (already
    migrated — no-op). Mixed state is refused explicitly.

    After a successful run:
        - Every receipt carries an integer ``_store_seq``.
        - Within each file, ``_store_seq`` strictly increases in
          physical line order.
        - Across files, seqs assigned in lexicographic path order.
        - ``<base_dir>/.store_seq`` is set to ``max(seq) + 1``.

    Raises:
        StoreMigrationError: Mixed legacy/migrated state, duplicate
            pre-existing seqs, non-integer seqs, or malformed data.
        ReceiptStoreIntegrityError: Relayed from lower-level readers.

    Returns:
        MigrationResult describing the run.
    """
    base = store.base_dir
    if not base.exists():
        return MigrationResult(
            files_scanned=0,
            files_rewritten=0,
            receipts_backfilled=0,
            next_seq=0,
            ordering_basis="empty_store",
        )

    trace_files = sorted(base.rglob("trace_*.jsonl"))

    # First pass: load everything, classify state.
    loaded: List[tuple[Path, List[Dict[str, Any]]]] = []
    existing_seqs: List[int] = []
    total_entries = 0
    entries_without_seq = 0

    for trace_file in trace_files:
        if not trace_file.is_file():
            continue
        try:
            handle = open(trace_file)
        except OSError as exc:
            raise ReceiptStoreIntegrityError(
                f"Cannot read trace file {trace_file}: {exc}"
            ) from exc
        entries: List[Dict[str, Any]] = []
        with handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ReceiptStoreIntegrityError(
                        f"Malformed JSON in {trace_file} line {line_number}: {exc}"
                    ) from exc
                total_entries += 1
                seq = entry.get("_store_seq")
                if seq is None:
                    entries_without_seq += 1
                elif isinstance(seq, int) and not isinstance(seq, bool):
                    existing_seqs.append(seq)
                else:
                    raise StoreMigrationError(
                        f"Non-integer _store_seq at {trace_file} line "
                        f"{line_number}: {seq!r}. Refusing to migrate."
                    )
                entries.append(entry)
        loaded.append((trace_file, entries))

    if total_entries == 0:
        return MigrationResult(
            files_scanned=len(trace_files),
            files_rewritten=0,
            receipts_backfilled=0,
            next_seq=0,
            ordering_basis="empty_store",
        )

    # Reject mixed state.
    if existing_seqs and entries_without_seq:
        raise StoreMigrationError(
            f"Mixed state: {entries_without_seq} receipts lack _store_seq "
            f"and {len(existing_seqs)} receipts already carry one. "
            "Refusing to migrate. Operator must decide how to repair."
        )

    # Reject duplicates in pre-existing seqs.
    if len(existing_seqs) != len(set(existing_seqs)):
        raise StoreMigrationError(
            "Duplicate _store_seq values already present in store. "
            "Refusing to migrate."
        )

    # Already fully migrated — no-op.
    if entries_without_seq == 0:
        next_seq = max(existing_seqs) + 1 if existing_seqs else 0
        _persist_counter(store, next_seq)
        return MigrationResult(
            files_scanned=len(trace_files),
            files_rewritten=0,
            receipts_backfilled=0,
            next_seq=next_seq,
            ordering_basis="already_migrated",
        )

    # Pure legacy path: assign seqs in (file, line) order starting at 0.
    next_seq = 0
    files_rewritten = 0
    receipts_backfilled = 0
    for trace_file, entries in loaded:
        file_changed = False
        new_lines: List[str] = []
        for entry in entries:
            if "_store_seq" not in entry:
                entry["_store_seq"] = next_seq
                next_seq += 1
                receipts_backfilled += 1
                file_changed = True
            new_lines.append(json.dumps(entry, default=str) + "\n")
        if file_changed:
            tmp_path = trace_file.with_suffix(trace_file.suffix + ".tmp")
            tmp_path.write_text("".join(new_lines))
            tmp_path.replace(trace_file)
            files_rewritten += 1

    _persist_counter(store, next_seq)

    return MigrationResult(
        files_scanned=len(trace_files),
        files_rewritten=files_rewritten,
        receipts_backfilled=receipts_backfilled,
        next_seq=next_seq,
        ordering_basis="path_then_line",
    )


def _persist_counter(store: AssayStore, next_seq: int) -> None:
    """Write ``next_seq`` into ``<base_dir>/.store_seq`` atomically enough.

    Uses ``.tmp`` + ``rename`` to avoid partial writes on crash. Does not
    hold the cross-process seq lock because migration is expected to run
    offline while no writers are active. Operators that cannot guarantee
    that quiescence should serialize migration externally.
    """
    seq_file = store.base_dir / ".store_seq"
    tmp_path = seq_file.with_suffix(seq_file.suffix + ".tmp")
    tmp_path.write_text(str(next_seq))
    tmp_path.replace(seq_file)


__all__ = [
    "MigrationResult",
    "StoreMigrationError",
    "migrate_legacy_store_seq",
]


def _cli_main(argv: List[str]) -> int:
    """Operator CLI: migrate an AssayStore at the given base_dir.

    Usage::

        python -m assay.store_seq_migration <base_dir>

    Exit codes:
        0 — migration ran successfully (including already-migrated no-op).
        2 — usage error (wrong number of arguments).
        3 — StoreMigrationError (mixed state, duplicate seqs, etc.).
        4 — ReceiptStoreIntegrityError (corruption during scan).
        1 — any other unexpected error.
    """
    import sys

    if len(argv) != 1:
        sys.stderr.write(
            "usage: python -m assay.store_seq_migration <base_dir>\n"
        )
        return 2

    base_dir = Path(argv[0])
    store = AssayStore(base_dir=base_dir)

    try:
        result = migrate_legacy_store_seq(store)
    except StoreMigrationError as exc:
        sys.stderr.write(f"migration refused: {exc}\n")
        return 3
    except ReceiptStoreIntegrityError as exc:
        sys.stderr.write(f"integrity failure during migration: {exc}\n")
        return 4
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"unexpected migration error: {exc}\n")
        return 1

    sys.stdout.write(
        "migration ok: "
        f"files_scanned={result.files_scanned} "
        f"files_rewritten={result.files_rewritten} "
        f"receipts_backfilled={result.receipts_backfilled} "
        f"next_seq={result.next_seq} "
        f"ordering_basis={result.ordering_basis}\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess in tests
    import sys

    sys.exit(_cli_main(sys.argv[1:]))
