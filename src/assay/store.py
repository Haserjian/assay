"""
Assay receipt storage.

Persists receipts to disk with trace IDs for auditability.
Default location: ~/.assay/

Thread-safe and process-safe. Uses threading.RLock for in-process
concurrency and O_APPEND + fcntl.flock for cross-process safety.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.compat.pyd import BaseModel

# ---------------------------------------------------------------------------
# POSIX atomicity threshold.  O_APPEND writes under this size are atomic
# on POSIX.  Larger writes get flock protection.
# ---------------------------------------------------------------------------
_PIPE_BUF = 4096 if sys.platform != "win32" else 512

# Advisory file locking -- POSIX only, graceful no-op on Windows
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

_LEGACY_HOME = ".loom/assay"
_NEW_HOME = ".assay"


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
    Process-safe: writes use O_APPEND for POSIX atomicity, with fcntl.flock
    fallback for oversized writes (> PIPE_BUF).

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

        Thread-lock must be held by caller.  For cross-process safety:
        - Writes < PIPE_BUF: O_APPEND guarantees POSIX atomicity.
        - Writes >= PIPE_BUF: additionally protected by fcntl.flock.
        """
        fd = os.open(
            str(self._current_file),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o644,
        )
        try:
            if len(line_bytes) >= _PIPE_BUF and _HAS_FCNTL:
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    self._write_all(fd, line_bytes)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                self._write_all(fd, line_bytes)
        finally:
            os.close(fd)

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

            # Add trace metadata
            data["_trace_id"] = self._current_trace_id
            data["_stored_at"] = datetime.now(timezone.utc).isoformat()

            line = json.dumps(data, default=str) + "\n"
            self._write_line(line.encode("utf-8"))

            return data.get("receipt_id", "unknown")

    def append_dict(self, data: Dict[str, Any]) -> None:
        """Append arbitrary dict to trace (for verdicts, metadata)."""
        with self._lock:
            if self._current_file is None:
                self.start_trace()

            data["_trace_id"] = self._current_trace_id
            data["_stored_at"] = datetime.now(timezone.utc).isoformat()

            line = json.dumps(data, default=str) + "\n"
            self._write_line(line.encode("utf-8"))

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
) -> Dict[str, Any]:
    """Emit a receipt to the current trace.

    Picks up ASSAY_TRACE_ID from the environment (set by `assay run`).
    Falls back to creating a new trace if no env var is set.

    ``seq`` is auto-assigned (monotonically increasing) if not provided.
    Explicit ``seq`` values bypass the counter but do not reset it.

    Thread-safe: global seq counter and trace setup are protected by
    _module_lock.  The store write itself is protected by the store's
    own RLock.

    Usage::

        from assay.store import emit_receipt

        emit_receipt("model_call", {"model": "gpt-4", "tokens": 1200})
        emit_receipt("guardian_verdict", {"verdict": "allow", "tool": "web_search"})

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
    if data:
        receipt.update(data)

    # Write (store has its own RLock)
    store.append_dict(receipt)
    return receipt


__all__ = [
    "assay_home",
    "generate_trace_id",
    "AssayStore",
    "get_default_store",
    "emit_receipt",
]
