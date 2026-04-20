"""
Assay receipt storage.

Persists receipts to disk with trace IDs for auditability.
Default location: ~/.assay/

Thread-safe and process-safe. Uses threading.RLock for in-process
concurrency and O_APPEND + fcntl.flock(LOCK_EX) for cross-process safety.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay._receipts.compat.pyd import BaseModel

# Advisory file locking -- POSIX only, graceful no-op on Windows
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

_LEGACY_HOME = ".loom/assay"
_NEW_HOME = ".assay"


class ReceiptStoreIntegrityError(RuntimeError):
    """Raised when the store's trace corpus is unreadable, malformed, or
    otherwise in a state where normal writes cannot proceed safely.

    Covers:
        - unreadable trace files
        - malformed JSON lines
        - mixed state (some receipts with ``_store_seq``, some without)
        - within-file ``_store_seq`` regression or duplicates

    Distinct from :class:`MigrationRequiredError`: that is an operator-
    solvable state with a clear remediation path (run migration). An
    integrity error signals the corpus itself has been tampered with or
    damaged and requires explicit repair tooling — no silent recovery.
    """


class MigrationRequiredError(RuntimeError):
    """Raised by the write path when a store carries legacy receipts without
    ``_store_seq`` and has not been migrated.

    A pure legacy store must be migrated explicitly before new writes, or
    the next ordinary write would silently convert the store to mixed
    state (which ``migrate_legacy_store_seq`` then correctly refuses to
    touch, stranding the operator).

    Resolution:
        from assay.store_seq_migration import migrate_legacy_store_seq
        migrate_legacy_store_seq(store)

    Or via CLI:
        python -m assay.store_seq_migration <base_dir>
    """


def assay_home() -> Path:
    """Return the Assay data directory.

    Uses ~/.assay/ by default. Falls back to ~/.loom/assay/ if the legacy
    path exists and the new one does not (backward compatibility).
    """
    new = Path.home() / _NEW_HOME
    if new.exists():
        return new
    legacy = Path.home() / _LEGACY_HOME
    if legacy.exists():
        return legacy
    return new


def generate_trace_id() -> str:
    """Generate a unique trace ID for a session."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"trace_{ts}_{uuid.uuid4().hex[:8]}"


class AssayStore:
    """
    Persistent storage for Assay receipts.

    Thread-safe: all mutable operations are protected by a reentrant lock.
    Process-safe: writes use O_APPEND + fcntl.flock(LOCK_EX) for atomicity.

    Receipts are stored as JSONL files organized by date:
        ~/.assay/2025-02-05/trace_xxx.jsonl
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = assay_home()
        self.base_dir = Path(base_dir)
        self._current_trace_id: Optional[str] = None
        self._current_file: Optional[Path] = None
        self._lock = threading.RLock()
        # Store-wide monotonic receipt sequence primitive. Its state lives
        # ON DISK at ``<base_dir>/.store_seq`` and is mutated under
        # ``fcntl.flock(LOCK_EX)`` so that multiple AssayStore instances
        # (including across processes) cannot allocate the same seq.
        # Allocation + receipt persistence run in a single critical section:
        # no writer releases the seq-file lock between "take a seq" and
        # "put the receipt bearing that seq on disk". Lexicographic trace-
        # path order is NOT a valid chronology; ``_store_seq`` is the
        # authority.
        self._seq_file = self.base_dir / ".store_seq"

    def start_trace(self, trace_id: Optional[str] = None) -> str:
        """Start a new trace, returning the trace ID.

        If trace_id is provided and exists, appends to existing trace file
        (even if it's in a different day's directory). This prevents cross-day
        trace splitting.
        """
        with self._lock:
            self._current_trace_id = trace_id or generate_trace_id()

            # If trace_id provided, try to find existing trace file first
            if trace_id is not None:
                existing_file = self._find_trace_file(trace_id)
                if existing_file:
                    self._current_file = existing_file
                    return self._current_trace_id

            # Create new trace file in today's directory
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            day_dir = self.base_dir / today
            day_dir.mkdir(parents=True, exist_ok=True)

            self._current_file = day_dir / f"{self._current_trace_id}.jsonl"
            return self._current_trace_id

    def _find_trace_file(self, trace_id: str) -> Optional[Path]:
        """Find existing trace file across all date directories."""
        if not self.base_dir.exists():
            return None
        for day_dir in self.base_dir.iterdir():
            if not day_dir.is_dir():
                continue
            trace_file = day_dir / f"{trace_id}.jsonl"
            if trace_file.exists():
                return trace_file
        return None

    @property
    def trace_id(self) -> Optional[str]:
        """Current trace ID, if any."""
        return self._current_trace_id

    @property
    def current_trace_id(self) -> Optional[str]:
        """Alias for trace_id (for integration compatibility)."""
        return self._current_trace_id

    @property
    def trace_file(self) -> Optional[Path]:
        """Current trace file path, if any."""
        return self._current_file

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        """Write all bytes, retrying on short writes."""
        mv = memoryview(data)
        while mv:
            n = os.write(fd, mv)
            mv = mv[n:]

    def _write_line(self, line_bytes: bytes) -> None:
        """Write a single JSONL line atomically.

        Thread-lock must be held by caller.  For cross-process safety
        we always acquire fcntl.flock (even for small writes) to prevent
        byte interleaving when multiple processes write concurrently.
        """
        fd = os.open(
            str(self._current_file),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o644,
        )
        try:
            if _HAS_FCNTL:
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    self._write_all(fd, line_bytes)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                self._write_all(fd, line_bytes)
        finally:
            os.close(fd)

    def _classify_store_for_write_strict(self) -> Tuple[int, int]:
        """Full-corpus strict validation for the write path.

        Walks every ``trace_*.jsonl`` file under ``base_dir``. Enforces the
        same stamped-store integrity invariants as the detector's
        ``_iter_all_receipts``: corrupt, duplicated, non-monotonic, or
        non-integer ``_store_seq`` values all fail closed.

        Classification buckets:
            * ABSENT — receipt lacks ``_store_seq`` key entirely (legacy).
            * VALID — ``_store_seq`` is a non-boolean integer ≥ 0, unique
              store-wide, and strictly increasing within its trace file.
            * CORRUPT — ``_store_seq`` is present but not a valid integer,
              or violates uniqueness / within-file monotonicity. Always
              an integrity error.

        Returns:
            ``(max_store_seq_seen, legacy_count)``

            * ``max_store_seq_seen`` is the largest VALID ``_store_seq``,
              or ``-1`` if no receipt carries one.
            * ``legacy_count`` is the number of ABSENT-bucket receipts.
              A positive value with zero stamped receipts signals
              PURE_LEGACY; callers should raise
              :class:`MigrationRequiredError`.

        State decoding by caller (assuming this method returned cleanly):
            ``(max=-1, legacy=0)``  → EMPTY (first-ever write allowed)
            ``(max>=0, legacy=0)``  → CURRENT (next_seq = max+1 or counter)
            ``(_,      legacy>0)``  → PURE_LEGACY (raise MigrationRequiredError)

        Raises:
            ReceiptStoreIntegrityError on:
                - any unreadable trace file
                - any malformed JSON line
                - MIXED state (VALID AND ABSENT receipts both present)
                - duplicate ``_store_seq`` anywhere in the corpus
                - within-file regression or equality of ``_store_seq``
                - ``_store_seq`` present but not an integer (or a bool),
                  or a negative integer

        The ``.store_seq`` counter file is intentionally NOT consulted
        here: it is only authoritative for a corpus that has passed this
        check.
        """
        max_seq = -1
        stamped = 0
        legacy = 0
        if not self.base_dir.exists():
            return max_seq, legacy

        # seq -> "file:line" witness of first occurrence, for duplicate detection.
        seen_seqs: Dict[int, str] = {}

        for trace_file in sorted(self.base_dir.rglob("trace_*.jsonl")):
            if not trace_file.is_file():
                continue
            try:
                handle = open(trace_file)
            except OSError as exc:
                raise ReceiptStoreIntegrityError(
                    f"Cannot read trace file {trace_file} during write "
                    f"validation: {exc}. Write refused."
                ) from exc
            last_seq_in_file = -1
            with handle:
                for line_number, line in enumerate(handle, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        entry = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        raise ReceiptStoreIntegrityError(
                            f"Malformed JSON in {trace_file} line "
                            f"{line_number}: {exc}. Write refused: the "
                            "trace corpus must be readable before new "
                            "receipts can be written."
                        ) from exc

                    # Classify this receipt's _store_seq.
                    if "_store_seq" not in entry:
                        legacy += 1
                        continue
                    seq = entry["_store_seq"]
                    # bool is subclass of int in Python — reject explicitly.
                    if not isinstance(seq, int) or isinstance(seq, bool):
                        raise ReceiptStoreIntegrityError(
                            f"Non-integer _store_seq at {trace_file} line "
                            f"{line_number}: got {seq!r} "
                            f"({type(seq).__name__}). Write refused; this "
                            "is corpus corruption, not legacy data."
                        )
                    if seq < 0:
                        raise ReceiptStoreIntegrityError(
                            f"Negative _store_seq at {trace_file} line "
                            f"{line_number}: {seq}. Write refused."
                        )
                    if seq in seen_seqs:
                        raise ReceiptStoreIntegrityError(
                            f"Duplicate _store_seq={seq} at {trace_file} "
                            f"line {line_number}; first seen at "
                            f"{seen_seqs[seq]}. Write refused: "
                            "store-local sequence must be unique."
                        )
                    if seq <= last_seq_in_file:
                        raise ReceiptStoreIntegrityError(
                            f"Non-monotonic _store_seq in {trace_file} "
                            f"line {line_number}: {seq} <= previous "
                            f"{last_seq_in_file}. Write refused: "
                            "within-file sequence must strictly increase."
                        )
                    seen_seqs[seq] = f"{trace_file}:{line_number}"
                    last_seq_in_file = seq
                    stamped += 1
                    if seq > max_seq:
                        max_seq = seq

        if stamped > 0 and legacy > 0:
            raise ReceiptStoreIntegrityError(
                f"AssayStore at {self.base_dir} is in mixed state: "
                f"{stamped} receipts stamped with _store_seq and "
                f"{legacy} receipts without. Normal writes refused. "
                "Mixed state cannot be healed by automatic migration; "
                "explicit operator repair is required."
            )

        return max_seq, legacy

    def _raise_migration_required(self) -> None:
        raise MigrationRequiredError(
            f"AssayStore at {self.base_dir} contains legacy "
            "receipts without _store_seq. Appending now would "
            "create unrecoverable mixed state (migration "
            "refuses to repair a mixed store). Run migration "
            "before writing: "
            "`python -m assay.store_seq_migration "
            f"{self.base_dir}` "
            "(or `from assay.store_seq_migration import "
            "migrate_legacy_store_seq; "
            "migrate_legacy_store_seq(store)`)."
        )

    def _persist_entry_with_store_seq(self, data: Dict[str, Any]) -> None:
        """Atomically allocate the next ``_store_seq`` and write ``data``.

        Rollout contract (enforced on every write):

            EMPTY          — allow; start at seq 0
            CURRENT        — allow; allocate from ``.store_seq`` counter or
                             ``max(_store_seq) + 1``, whichever is higher
            PURE_LEGACY    — refuse with :class:`MigrationRequiredError`
            MIXED          — refuse with :class:`ReceiptStoreIntegrityError`
            CORRUPT        — refuse with :class:`ReceiptStoreIntegrityError`

        ``.store_seq`` is NOT a health certificate. Its presence does not
        bypass corpus validation; the counter is only authoritative for a
        corpus that has just passed strict classification.

        Cross-process-safe: the durable ``<base_dir>/.store_seq`` file is
        opened under ``fcntl.flock(LOCK_EX)`` around allocation and
        persistence. The strict classifier is also re-run under the lock
        to close the narrow ToCTTOU window between the pre-check and
        counter read.
        """
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Strict full-corpus validation BEFORE touching ``.store_seq``.
        # Fails closed on corrupt / mixed state. On PURE_LEGACY we still
        # get here (no raise from the classifier) and refuse with a
        # migration-pointer error — leaving ``.store_seq`` uncreated.
        _, legacy_count = self._classify_store_for_write_strict()
        if legacy_count > 0:
            self._raise_migration_required()

        seq_fd = os.open(
            str(self._seq_file),
            os.O_RDWR | os.O_CREAT,
            0o644,
        )
        try:
            if _HAS_FCNTL:
                fcntl.flock(seq_fd, fcntl.LOCK_EX)
            try:
                # Defensive re-classification under the lock: closes a
                # narrow window where another writer could have changed
                # corpus state between the pre-check and here.
                max_seq_in_corpus, legacy_count = (
                    self._classify_store_for_write_strict()
                )
                if legacy_count > 0:
                    self._raise_migration_required()

                # Corpus is EMPTY or CURRENT. Allocate from the counter
                # file if it's valid; otherwise reconstruct defensively
                # from the corpus. Never allocate a seq that would
                # non-monotonically collide with an existing receipt.
                os.lseek(seq_fd, 0, os.SEEK_SET)
                raw = os.read(seq_fd, 64)
                text = raw.decode("utf-8").strip() if raw else ""
                if text:
                    try:
                        counter_seq = int(text)
                    except ValueError as exc:
                        raise RuntimeError(
                            f"AssayStore sequence counter at "
                            f"{self._seq_file} is corrupted: {text!r}"
                        ) from exc
                    if counter_seq < 0:
                        raise RuntimeError(
                            f"AssayStore sequence counter at "
                            f"{self._seq_file} is negative: {counter_seq}"
                        )
                    # Defensive: if the counter has somehow fallen behind
                    # the corpus (external reset, partial rollback), use
                    # whichever is higher to preserve strict monotonicity.
                    next_seq = max(counter_seq, max_seq_in_corpus + 1)
                else:
                    next_seq = max_seq_in_corpus + 1

                # Stamp receipt with allocated seq and persist to trace file.
                data["_store_seq"] = next_seq
                line = json.dumps(data, default=str) + "\n"
                self._write_line(line.encode("utf-8"))

                # Persist incremented counter.
                new_counter = str(next_seq + 1).encode("utf-8")
                os.lseek(seq_fd, 0, os.SEEK_SET)
                os.ftruncate(seq_fd, 0)
                self._write_all(seq_fd, new_counter)
            finally:
                if _HAS_FCNTL:
                    try:
                        fcntl.flock(seq_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
        finally:
            os.close(seq_fd)

    def append(self, receipt: BaseModel) -> str:
        """
        Append a receipt to the current trace.

        Returns the receipt ID.
        """
        with self._lock:
            if self._current_file is None:
                self.start_trace()

            # Serialize with Pydantic
            data = receipt.model_dump(mode="json", exclude_none=True)

            # Add trace metadata (trace_id + wall-clock). _store_seq is
            # stamped inside the cross-process critical section below.
            data["_trace_id"] = self._current_trace_id
            data["_stored_at"] = datetime.now(timezone.utc).isoformat()

            self._persist_entry_with_store_seq(data)

            return data.get("receipt_id", "unknown")

    def append_dict(self, data: Dict[str, Any]) -> None:
        """Append arbitrary dict to trace (for verdicts, metadata)."""
        with self._lock:
            if self._current_file is None:
                self.start_trace()

            data["_trace_id"] = self._current_trace_id
            data["_stored_at"] = datetime.now(timezone.utc).isoformat()

            self._persist_entry_with_store_seq(data)

    def read_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Read all entries from a trace file."""
        trace_file = self._find_trace_file(trace_id)
        if trace_file is None:
            return []
        entries = []
        with open(trace_file) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        return entries

    def read_trace_raw(self, trace_id: str) -> Optional[bytes]:
        """Read raw bytes from a trace file (for forensic fidelity)."""
        trace_file = self._find_trace_file(trace_id)
        if trace_file is None:
            return None
        return trace_file.read_bytes()

    def list_traces(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent traces with metadata."""
        traces = []
        if not self.base_dir.exists():
            return traces

        for day_dir in sorted(self.base_dir.iterdir(), reverse=True):
            if not day_dir.is_dir():
                continue
            for trace_file in sorted(day_dir.glob("trace_*.jsonl"), reverse=True):
                stat = trace_file.stat()
                traces.append({
                    "trace_id": trace_file.stem,
                    "date": day_dir.name,
                    "path": str(trace_file),
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                })
                if len(traces) >= limit:
                    return traces
        return traces


# ---------------------------------------------------------------------------
# Module-level globals (protected by _module_lock)
# ---------------------------------------------------------------------------

_module_lock = threading.Lock()
_default_store: Optional[AssayStore] = None
_seq_counter: int = 0
_seq_trace_id: Optional[str] = None


def get_default_store() -> AssayStore:
    """Get or create the default AssayStore."""
    global _default_store
    with _module_lock:
        if _default_store is None:
            _default_store = AssayStore()
        return _default_store


def emit_receipt(
    type: str,
    data: Optional[Dict[str, Any]] = None,
    *,
    receipt_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    schema_version: str = "3.0",
    seq: Optional[int] = None,
    parent_receipt_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Emit a receipt to the current trace.

    Picks up ASSAY_TRACE_ID from the environment (set by `assay run`).
    Falls back to creating a new trace if no env var is set.

    ``seq`` is auto-assigned (monotonically increasing) if not provided.
    Explicit ``seq`` values bypass the counter but do not reset it.

    ``parent_receipt_id`` links this receipt to a prior receipt, enabling
    causal chain traversal (e.g. a guardian verdict that references the
    model call it evaluated).

    Thread-safe: global seq counter and trace setup are protected by
    _module_lock.  The store write itself is protected by the store's
    own RLock.

    Usage::

        from assay.store import emit_receipt

        r = emit_receipt("model_call", {"model": "gpt-4", "tokens": 1200})
        emit_receipt("guardian_verdict", {"verdict": "allow"},
                     parent_receipt_id=r["receipt_id"])

    Returns the full receipt dict that was written.
    """
    global _seq_counter, _seq_trace_id

    store = get_default_store()

    with _module_lock:
        # Pick up trace from environment or start a new one
        trace_id = os.environ.get("ASSAY_TRACE_ID")
        if store.trace_id is None:
            _seq_counter = 0
            _seq_trace_id = trace_id
            store.start_trace(trace_id)
        elif trace_id and store.trace_id != trace_id:
            # Env trace changed -- switch to it, reset counter
            _seq_counter = 0
            _seq_trace_id = trace_id
            store.start_trace(trace_id)

        # Auto-assign seq if not provided
        if seq is None:
            seq = _seq_counter
        _seq_counter = max(_seq_counter, seq) + 1

    # Build receipt dict (no module lock needed -- local vars only)
    receipt: Dict[str, Any] = {
        "receipt_id": receipt_id or f"r_{uuid.uuid4().hex[:12]}",
        "type": type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "schema_version": schema_version,
        "seq": seq,
    }
    if parent_receipt_id is not None:
        receipt["parent_receipt_id"] = parent_receipt_id
    if data:
        receipt.update(data)

    # Write (store has its own RLock)
    store.append_dict(receipt)
    return receipt


__all__ = [
    "assay_home",
    "generate_trace_id",
    "AssayStore",
    "MigrationRequiredError",
    "ReceiptStoreIntegrityError",
    "get_default_store",
    "emit_receipt",
]
