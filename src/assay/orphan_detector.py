"""
Episode orphan detector -- constitutional integrity check.

Kernel Gap Ledger Row #1, Bypass #4: Assay optional context manager.
Episodes created with bare `open_episode()` (no `with` block) can be
garbage collected without ever emitting a terminal receipt.

This module provides a store-backed detector that:
1. Scans all traces in an AssayStore
2. Identifies episodes with `episode.opened` but no terminal receipt
   (`episode.closed` or `episode.abandoned`)
3. Reports them loudly without mutating store state

Constitutional law:
    Every episode must terminate constitutionally: either by a typed
    terminal receipt, or by an explicit detector-reported violation.

Design constraints:
    - Pure read. Never mutates the store.
    - Explicit surfacing over magical cleanup.
    - Auditable: returns structured results, not boolean.
    - Backward compatible: treats traces without episode.opened as
      legacy (not orphaned).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from assay.store import AssayStore


# Terminal receipt types that prove an episode was constitutionally closed.
TERMINAL_RECEIPT_TYPES = frozenset({
    "episode.closed",
    "episode.abandoned",
})

# The receipt type that proves an episode was opened.
OPENED_RECEIPT_TYPE = "episode.opened"


@dataclass(frozen=True)
class OrphanedEpisode:
    """A detected orphaned episode -- opened but never terminalized."""

    episode_id: str
    trace_id: str
    opened_at: str
    receipt_count: int
    last_receipt_type: str
    last_receipt_at: str
    trace_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "trace_id": self.trace_id,
            "opened_at": self.opened_at,
            "receipt_count": self.receipt_count,
            "last_receipt_type": self.last_receipt_type,
            "last_receipt_at": self.last_receipt_at,
            "trace_path": self.trace_path,
        }


@dataclass(frozen=True)
class OrphanDetectionResult:
    """Result of scanning a store for orphaned episodes."""

    orphans: List[OrphanedEpisode] = field(default_factory=list)
    total_traces_scanned: int = 0
    total_episodes_found: int = 0
    total_orphans_found: int = 0
    scanned_at: str = ""

    @property
    def clean(self) -> bool:
        """True if no orphaned episodes were found."""
        return self.total_orphans_found == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "total_traces_scanned": self.total_traces_scanned,
            "total_episodes_found": self.total_episodes_found,
            "total_orphans_found": self.total_orphans_found,
            "scanned_at": self.scanned_at,
            "orphans": [orphan.to_dict() for orphan in self.orphans],
        }


def _extract_episode_id(entry: Dict[str, Any]) -> Optional[str]:
    """Extract episode_id from a trace entry."""
    return entry.get("episode_id") or None


def _extract_receipt_type(entry: Dict[str, Any]) -> str:
    """Extract receipt type from a trace entry."""
    return str(entry.get("type") or entry.get("receipt_type") or "")


def _extract_timestamp(entry: Dict[str, Any]) -> str:
    """Extract timestamp from a trace entry."""
    return str(entry.get("timestamp") or entry.get("_stored_at") or "")


def detect_orphaned_episodes(
    store: AssayStore,
    *,
    max_traces: int = 1000,
) -> OrphanDetectionResult:
    """Scan a store for orphaned episodes.

    An orphaned episode is one that has an `episode.opened` receipt
    but no `episode.closed` or `episode.abandoned` receipt in the
    same trace.

    This is a pure-read operation. It never mutates the store.

    Args:
        store: The AssayStore to scan.
        max_traces: Maximum number of traces to scan (most recent first).

    Returns:
        OrphanDetectionResult with all findings.
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    traces = store.list_traces(limit=max_traces)

    orphans: List[OrphanedEpisode] = []
    total_episodes = 0

    for trace_meta in traces:
        trace_id = trace_meta["trace_id"]
        trace_path = trace_meta.get("path")
        entries = store.read_trace(trace_id)
        if not entries:
            continue

        # Track episodes within this trace
        episodes_in_trace: Dict[str, Dict[str, Any]] = {}

        for entry in entries:
            receipt_type = _extract_receipt_type(entry)
            episode_id = _extract_episode_id(entry)

            if receipt_type == OPENED_RECEIPT_TYPE and episode_id:
                if episode_id not in episodes_in_trace:
                    episodes_in_trace[episode_id] = {
                        "opened_at": _extract_timestamp(entry),
                        "receipt_count": 0,
                        "last_receipt_type": receipt_type,
                        "last_receipt_at": _extract_timestamp(entry),
                        "terminalized": False,
                    }

            if episode_id and episode_id in episodes_in_trace:
                info = episodes_in_trace[episode_id]
                info["receipt_count"] += 1
                info["last_receipt_type"] = receipt_type
                info["last_receipt_at"] = _extract_timestamp(entry)

                if receipt_type in TERMINAL_RECEIPT_TYPES:
                    info["terminalized"] = True

        total_episodes += len(episodes_in_trace)

        for episode_id, info in episodes_in_trace.items():
            if not info["terminalized"]:
                orphans.append(OrphanedEpisode(
                    episode_id=episode_id,
                    trace_id=trace_id,
                    opened_at=info["opened_at"],
                    receipt_count=info["receipt_count"],
                    last_receipt_type=info["last_receipt_type"],
                    last_receipt_at=info["last_receipt_at"],
                    trace_path=trace_path,
                ))

    return OrphanDetectionResult(
        orphans=orphans,
        total_traces_scanned=len(traces),
        total_episodes_found=total_episodes,
        total_orphans_found=len(orphans),
        scanned_at=scanned_at,
    )


def check_episode_health(
    store: AssayStore,
    *,
    max_traces: int = 1000,
    loud: bool = True,
) -> bool:
    """Run orphan detection and optionally print findings.

    Returns True if the store is clean (no orphans).
    Returns False if orphaned episodes are found.

    This is the entry point for CI/startup health checks.
    """
    result = detect_orphaned_episodes(store, max_traces=max_traces)

    if loud and not result.clean:
        import sys
        print(
            f"[CONSTITUTIONAL VIOLATION] {result.total_orphans_found} orphaned episode(s) detected",
            file=sys.stderr,
        )
        for orphan in result.orphans:
            print(
                f"  orphan: episode_id={orphan.episode_id} "
                f"trace={orphan.trace_id} "
                f"opened_at={orphan.opened_at} "
                f"receipts={orphan.receipt_count} "
                f"last={orphan.last_receipt_type}",
                file=sys.stderr,
            )

    return result.clean
