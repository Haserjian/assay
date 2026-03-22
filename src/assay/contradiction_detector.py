"""
Contradiction closure detector -- constitutional integrity check.

Row #3 Receipt Composition Law (ROW3_RECEIPT_COMPOSITION_DRAFT.md), Stage 3a:
Wire "cannot imply" violations into assay doctor.

Closure law (from ROW3 Part 2):
    contradiction.registered is closed by contradiction.resolved.
    Remaining if not closed: Open conflict -- blocks proof tier cap removal.

This module provides a store-backed detector that:
1. Scans all traces in an AssayStore
2. Identifies contradiction.registered receipts without a paired
   contradiction.resolved (matched by contradiction_id within the same trace)
3. Reports them loudly without mutating store state

Constitutional law:
    Every contradiction.registered receipt must have a corresponding
    contradiction.resolved receipt with the same contradiction_id.
    An open conflict is a constitutional violation that blocks proof-tier
    cap removal and must be surfaced explicitly.

Design constraints:
    - Pure read. Never mutates the store.
    - Explicit surfacing over magical cleanup.
    - Auditable: returns structured results, not boolean.
    - Mirrors orphan_detector.py pattern exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from assay.store import AssayStore


# Receipt types for the contradiction lifecycle.
REGISTERED_RECEIPT_TYPE = "contradiction.registered"
RESOLVED_RECEIPT_TYPE = "contradiction.resolved"


@dataclass(frozen=True)
class OpenContradiction:
    """A detected open contradiction -- registered but never resolved."""

    contradiction_id: str
    trace_id: str
    episode_id: str
    registered_at: str
    claim_a_id: str
    claim_b_id: str
    severity: str
    trace_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "trace_id": self.trace_id,
            "episode_id": self.episode_id,
            "registered_at": self.registered_at,
            "claim_a_id": self.claim_a_id,
            "claim_b_id": self.claim_b_id,
            "severity": self.severity,
            "trace_path": self.trace_path,
        }


@dataclass(frozen=True)
class ContradictionClosureResult:
    """Result of scanning a store for open (unresolved) contradictions."""

    open_contradictions: List[OpenContradiction] = field(default_factory=list)
    total_traces_scanned: int = 0
    total_registered_found: int = 0
    total_open_found: int = 0
    scanned_at: str = ""

    @property
    def clean(self) -> bool:
        """True if no open contradictions were found."""
        return self.total_open_found == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "total_traces_scanned": self.total_traces_scanned,
            "total_registered_found": self.total_registered_found,
            "total_open_found": self.total_open_found,
            "scanned_at": self.scanned_at,
            "open_contradictions": [c.to_dict() for c in self.open_contradictions],
        }


def _extract_receipt_type(entry: Dict[str, Any]) -> str:
    """Extract receipt type from a trace entry."""
    return str(entry.get("type") or entry.get("receipt_type") or "")


def _extract_timestamp(entry: Dict[str, Any]) -> str:
    """Extract timestamp from a trace entry."""
    return str(entry.get("timestamp") or entry.get("_stored_at") or "")


def detect_open_contradictions(
    store: AssayStore,
    *,
    max_traces: int = 1000,
) -> ContradictionClosureResult:
    """Scan a store for open (unresolved) contradictions.

    An open contradiction is one that has a `contradiction.registered` receipt
    but no `contradiction.resolved` receipt with the same contradiction_id
    in the same trace.

    This is a pure-read operation. It never mutates the store.

    Args:
        store: The AssayStore to scan.
        max_traces: Maximum number of traces to scan (most recent first).

    Returns:
        ContradictionClosureResult with all findings.
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    traces = store.list_traces(limit=max_traces)

    open_contradictions: List[OpenContradiction] = []
    total_registered = 0

    for trace_meta in traces:
        trace_id = trace_meta["trace_id"]
        trace_path = trace_meta.get("path")
        entries = store.read_trace(trace_id)
        if not entries:
            continue

        # Track registered contradictions within this trace: id -> info dict
        registered: Dict[str, Dict[str, Any]] = {}
        resolved_ids: Set[str] = set()

        for entry in entries:
            receipt_type = _extract_receipt_type(entry)
            contradiction_id = entry.get("contradiction_id")

            if receipt_type == REGISTERED_RECEIPT_TYPE and contradiction_id:
                if contradiction_id not in registered:
                    registered[contradiction_id] = {
                        "episode_id": str(entry.get("episode_id") or ""),
                        "registered_at": _extract_timestamp(entry),
                        "claim_a_id": str(entry.get("claim_a_id") or ""),
                        "claim_b_id": str(entry.get("claim_b_id") or ""),
                        "severity": str(entry.get("severity") or "unknown"),
                    }

            elif receipt_type == RESOLVED_RECEIPT_TYPE and contradiction_id:
                resolved_ids.add(contradiction_id)

        total_registered += len(registered)

        for ctr_id, info in registered.items():
            if ctr_id not in resolved_ids:
                open_contradictions.append(OpenContradiction(
                    contradiction_id=ctr_id,
                    trace_id=trace_id,
                    episode_id=info["episode_id"],
                    registered_at=info["registered_at"],
                    claim_a_id=info["claim_a_id"],
                    claim_b_id=info["claim_b_id"],
                    severity=info["severity"],
                    trace_path=trace_path,
                ))

    return ContradictionClosureResult(
        open_contradictions=open_contradictions,
        total_traces_scanned=len(traces),
        total_registered_found=total_registered,
        total_open_found=len(open_contradictions),
        scanned_at=scanned_at,
    )


def check_contradiction_health(
    store: AssayStore,
    *,
    max_traces: int = 1000,
    loud: bool = True,
) -> bool:
    """Run contradiction detection and optionally print findings.

    Returns True if the store is clean (no open contradictions).
    Returns False if open contradictions are found.

    This is the entry point for CI/startup health checks.
    """
    result = detect_open_contradictions(store, max_traces=max_traces)

    if loud and not result.clean:
        import sys
        print(
            f"[CONSTITUTIONAL VIOLATION] {result.total_open_found} open contradiction(s) detected",
            file=sys.stderr,
        )
        for contradiction in result.open_contradictions:
            print(
                f"  open: contradiction_id={contradiction.contradiction_id} "
                f"trace={contradiction.trace_id} "
                f"episode_id={contradiction.episode_id} "
                f"registered_at={contradiction.registered_at} "
                f"severity={contradiction.severity}",
                file=sys.stderr,
            )

    return result.clean


__all__ = [
    "REGISTERED_RECEIPT_TYPE",
    "RESOLVED_RECEIPT_TYPE",
    "OpenContradiction",
    "ContradictionClosureResult",
    "detect_open_contradictions",
    "check_contradiction_health",
]
