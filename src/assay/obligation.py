"""Obligation lifecycle model and store.

Obligations are forward-looking commitments created by constitutional events
(e.g., an authority override that creates mandatory review debt).

Storage: ~/.assay/obligations.jsonl — full-state snapshots, newest wins by
obligation_id. This is NOT philosophically append-only in the event-sourcing
sense; it stores the latest state of each obligation as a complete snapshot.
To find current state, read backwards and take first match per obligation_id.

Design note: This is product-layer infrastructure. It consumes constitutional
constraints from the court layer (CCIO) but does not invent them. The
authority semantics of overrides remain in Decision Receipt doctrine.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.store import assay_home

# Advisory file locking -- POSIX only
try:
    import fcntl

    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_obligation_id() -> str:
    return f"OB-{uuid.uuid4().hex[:12]}"


# Valid obligation statuses and their semantics:
#   open       — unresolved, accruing constitutional debt
#   discharged — resolved by a review receipt
#   waived     — explicitly forgiven (requires reason)
#   escalated  — forwarded to higher authority
VALID_STATUSES = {"open", "discharged", "waived", "escalated"}

# Valid severity levels
VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}

# Valid obligation types (extensible — add here, not in receipts)
VALID_TYPES = {"override_review"}


@dataclass
class Obligation:
    """A forward-looking commitment created by a constitutional event.

    Debts close. Scars persist. This models debts — obligations that have
    a lifecycle (open -> discharged/waived/escalated) and a deadline.
    Scars (persistent historical markers) are a separate future concern.
    """

    obligation_id: str
    source_receipt_id: str  # override receipt that created this
    superseded_receipt_id: str  # original refusal that was overridden
    created_by_actor: str  # who caused the obligation (the overrider)
    owner: str  # who must resolve it (may differ from creator)
    obligation_type: str  # "override_review" (extensible later)
    severity: str  # HIGH | MEDIUM | LOW
    status: str  # open | discharged | waived | escalated
    created_at: str  # ISO-8601
    due_at: str  # ISO-8601
    discharge_receipt_id: Optional[str] = None  # receipt proving resolution
    waiver_reason: Optional[str] = None
    escalated_to: Optional[str] = None
    status_reason: Optional[str] = None  # human-readable note on last transition

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Strip None values for cleaner storage
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Obligation":
        # Accept only known fields
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def validate(self) -> List[str]:
        """Return list of validation errors (empty = valid)."""
        errors: List[str] = []
        if self.status not in VALID_STATUSES:
            errors.append(f"Unknown status: {self.status!r}")
        if self.severity not in VALID_SEVERITIES:
            errors.append(f"Unknown severity: {self.severity!r}")
        if self.obligation_type not in VALID_TYPES:
            errors.append(f"Unknown obligation_type: {self.obligation_type!r}")
        if self.status == "discharged" and not self.discharge_receipt_id:
            errors.append("Discharged obligation must have discharge_receipt_id")
        if self.status == "waived" and not self.waiver_reason:
            errors.append("Waived obligation must have waiver_reason")
        if self.status == "escalated" and not self.escalated_to:
            errors.append("Escalated obligation must have escalated_to")
        return errors


def create_override_obligation(
    *,
    source_receipt_id: str,
    superseded_receipt_id: str,
    created_by_actor: str,
    owner: Optional[str] = None,
    severity: str = "HIGH",
    due_days: int = 7,
    obligation_id: Optional[str] = None,
) -> Obligation:
    """Create an obligation from an authority override.

    By default, the owner is the same actor who created the override.
    Override review obligations default to HIGH severity and 7-day SLA.
    """
    now = datetime.now(timezone.utc)
    return Obligation(
        obligation_id=obligation_id or _generate_obligation_id(),
        source_receipt_id=source_receipt_id,
        superseded_receipt_id=superseded_receipt_id,
        created_by_actor=created_by_actor,
        owner=owner or created_by_actor,
        obligation_type="override_review",
        severity=severity,
        status="open",
        created_at=now.isoformat(),
        due_at=(now + timedelta(days=due_days)).isoformat(),
    )


def discharge_obligation(
    obligation: Obligation,
    *,
    discharge_receipt_id: str,
    reason: Optional[str] = None,
) -> Obligation:
    """Discharge an obligation with a review receipt."""
    return Obligation(
        obligation_id=obligation.obligation_id,
        source_receipt_id=obligation.source_receipt_id,
        superseded_receipt_id=obligation.superseded_receipt_id,
        created_by_actor=obligation.created_by_actor,
        owner=obligation.owner,
        obligation_type=obligation.obligation_type,
        severity=obligation.severity,
        status="discharged",
        created_at=obligation.created_at,
        due_at=obligation.due_at,
        discharge_receipt_id=discharge_receipt_id,
        status_reason=reason or f"Discharged by review receipt {discharge_receipt_id}",
    )


class ObligationStore:
    """Persistent storage for obligations.

    Stores full-state snapshots in ~/.assay/obligations.jsonl.
    Newest snapshot wins per obligation_id.
    Thread-safe via RLock, process-safe via fcntl.flock.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = assay_home()
        self.base_dir = Path(base_dir)
        self._file = self.base_dir / "obligations.jsonl"
        self._lock = threading.RLock()

    def save(self, obligation: Obligation) -> None:
        """Persist an obligation snapshot."""
        errors = obligation.validate()
        if errors:
            raise ValueError(f"Invalid obligation: {'; '.join(errors)}")

        with self._lock:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            data = obligation.to_dict()
            data["_saved_at"] = _utc_now()
            line = json.dumps(data, default=str) + "\n"
            line_bytes = line.encode("utf-8")

            fd = os.open(str(self._file), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                if _HAS_FCNTL:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    try:
                        os.write(fd, line_bytes)
                    finally:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                else:
                    os.write(fd, line_bytes)
            finally:
                os.close(fd)

    def get(self, obligation_id: str) -> Optional[Obligation]:
        """Get latest state of an obligation by ID."""
        with self._lock:
            if not self._file.exists():
                return None
            # Read backwards — newest snapshot wins
            latest = None
            with open(self._file) as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        if data.get("obligation_id") == obligation_id:
                            latest = data
            if latest is None:
                return None
            # Strip internal fields
            latest = {k: v for k, v in latest.items() if not k.startswith("_")}
            return Obligation.from_dict(latest)

    def find_by_receipt(self, receipt_id: str) -> List[Obligation]:
        """Find all obligations linked to a receipt (as source or superseded)."""
        results: List[Obligation] = []
        seen_ids: Dict[str, Obligation] = {}
        with self._lock:
            if not self._file.exists():
                return results
            with open(self._file) as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        if data.get("source_receipt_id") == receipt_id or \
                           data.get("superseded_receipt_id") == receipt_id:
                            clean = {k: v for k, v in data.items() if not k.startswith("_")}
                            seen_ids[data["obligation_id"]] = Obligation.from_dict(clean)
        return list(seen_ids.values())

    def list_pending(self) -> List[Obligation]:
        """List all obligations with status='open'."""
        latest: Dict[str, Obligation] = {}
        with self._lock:
            if not self._file.exists():
                return []
            with open(self._file) as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        clean = {k: v for k, v in data.items() if not k.startswith("_")}
                        ob = Obligation.from_dict(clean)
                        latest[ob.obligation_id] = ob
        return [ob for ob in latest.values() if ob.status == "open"]


__all__ = [
    "Obligation",
    "ObligationStore",
    "create_override_obligation",
    "discharge_obligation",
    "VALID_STATUSES",
    "VALID_SEVERITIES",
    "VALID_TYPES",
]
