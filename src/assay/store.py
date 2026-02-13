"""
Assay receipt storage.

Persists receipts to disk with trace IDs for auditability.
Default location: ~/.assay/
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.compat.pyd import BaseModel


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

    Receipts are stored as JSONL files organized by date:
        ~/.assay/2025-02-05/trace_xxx.jsonl
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = assay_home()
        self.base_dir = Path(base_dir)
        self._current_trace_id: Optional[str] = None
        self._current_file: Optional[Path] = None

    def start_trace(self, trace_id: Optional[str] = None) -> str:
        """Start a new trace, returning the trace ID.

        If trace_id is provided and exists, appends to existing trace file
        (even if it's in a different day's directory). This prevents cross-day
        trace splitting.
        """
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

    def append(self, receipt: BaseModel) -> str:
        """
        Append a receipt to the current trace.

        Returns the receipt ID.
        """
        if self._current_file is None:
            self.start_trace()

        # Serialize with Pydantic
        data = receipt.model_dump(mode="json", exclude_none=True)

        # Add trace metadata
        data["_trace_id"] = self._current_trace_id
        data["_stored_at"] = datetime.now(timezone.utc).isoformat()

        with open(self._current_file, "a") as f:
            f.write(json.dumps(data, default=str) + "\n")

        return data.get("receipt_id", "unknown")

    def append_dict(self, data: Dict[str, Any]) -> None:
        """Append arbitrary dict to trace (for verdicts, metadata)."""
        if self._current_file is None:
            self.start_trace()

        data["_trace_id"] = self._current_trace_id
        data["_stored_at"] = datetime.now(timezone.utc).isoformat()

        with open(self._current_file, "a") as f:
            f.write(json.dumps(data, default=str) + "\n")

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


# Global default store
_default_store: Optional[AssayStore] = None

# Auto-incrementing sequence counter for emit_receipt
_seq_counter: int = 0


def get_default_store() -> AssayStore:
    """Get or create the default AssayStore."""
    global _default_store
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

    Usage::

        from assay.store import emit_receipt

        emit_receipt("model_call", {"model": "gpt-4", "tokens": 1200})
        emit_receipt("guardian_verdict", {"verdict": "allow", "tool": "web_search"})

    Returns the full receipt dict that was written.
    """
    global _seq_counter
    import os

    store = get_default_store()

    # Pick up trace from environment or start a new one
    trace_id = os.environ.get("ASSAY_TRACE_ID")
    if store.trace_id is None:
        _seq_counter = 0
        store.start_trace(trace_id)
    elif trace_id and store.trace_id != trace_id:
        # Env trace changed -- switch to it, reset counter
        _seq_counter = 0
        store.start_trace(trace_id)

    # Auto-assign seq if not provided
    if seq is None:
        seq = _seq_counter
    _seq_counter = max(_seq_counter, seq) + 1

    receipt: Dict[str, Any] = {
        "receipt_id": receipt_id or f"r_{uuid.uuid4().hex[:12]}",
        "type": type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "schema_version": schema_version,
        "seq": seq,
    }
    if data:
        receipt.update(data)

    store.append_dict(receipt)
    return receipt


__all__ = [
    "assay_home",
    "generate_trace_id",
    "AssayStore",
    "get_default_store",
    "emit_receipt",
]
