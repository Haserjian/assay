"""
Episode-native SDK for long-lived runtimes.

This module exposes the three-mode Assay model as a Python API:

  Mode 1 (Wrapper):  assay run -- python app.py  (unchanged CLI)
  Mode 2 (Runtime):  open_episode / emit / seal_checkpoint
  Mode 3 (Settlement): verify_checkpoint / verify_pack

The Episode facade wraps existing infrastructure:
  - AssayStore for receipt persistence
  - ProofPack for checkpoint sealing
  - verify_receipt_pack / verify_pack_manifest for verification

Design rules:
  - No new storage format; uses the same JSONL traces and 5-file packs.
  - No new receipt schema; emits the same schema_version="3.0" receipts.
  - No new signing model; uses the same Ed25519 keystore.
  - Thread-safe: delegates to AssayStore's RLock.
  - One Episode = one trace = one causal chain of receipts.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from assay.claim_verifier import ClaimSpec
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.integrity import VerifyResult
from assay.keystore import AssayKeyStore, get_default_keystore
from assay.proof_pack import ProofPack
from assay.receipt_composition import require_allowed_successor
from assay.store import AssayStore, get_default_store


# ---------------------------------------------------------------------------
# Constitutional contract types
# ---------------------------------------------------------------------------

class EpisodeState(str, Enum):
    """Lifecycle state for a constitutional episode."""

    OPEN = "open"
    EXECUTING = "executing"
    AWAITING_GUARDIAN = "awaiting_guardian"
    SETTLED = "settled"
    PERSISTED = "persisted"
    ABANDONED = "abandoned"


class SettlementOutcome(str, Enum):
    """Judgment outcome for a settled episode."""

    PASS = "pass"
    HONEST_FAIL = "honest_fail"
    TAMPERED = "tampered"


class EpisodeDirectiveCode(str, Enum):
    """Canonical bridge directives for Assay constitutional episodes."""

    REOPEN_FOR_RETRY = "REOPEN_FOR_RETRY"
    ROUTE_TO_REVIEW = "ROUTE_TO_REVIEW"
    CLOSE_AS_TAINTED = "CLOSE_AS_TAINTED"
    CLOSE_AS_REFUSED = "CLOSE_AS_REFUSED"


ASSAY_EPISODE_TARGET_SUBSTRATE = "assay.episode.lifecycle_state"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return _utc_now()
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    return _utc_now()


def _normalize_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return _isoformat(value)
    if isinstance(value, tuple):
        return [_normalize_value(item) for item in value]
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, set):
        return [_normalize_value(item) for item in sorted(value, key=repr)]
    if isinstance(value, Mapping):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _normalize_value(value.to_dict())
    if hasattr(value, "__dict__") and not isinstance(value, type):
        return _normalize_value({k: v for k, v in vars(value).items() if not k.startswith("_")})
    return value


def _canonical_hash(data: Mapping[str, Any]) -> str:
    return hashlib.sha256(jcs_canonicalize(_normalize_value(dict(data)))).hexdigest()


def _stable_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True)
class Obligation:
    """Normative expectation for an episode."""

    obligation_id: str
    description: str = ""
    expected_receipt_types: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "description": self.description,
            "expected_receipt_types": list(self.expected_receipt_types),
        }

    @classmethod
    def from_value(cls, value: Any) -> "Obligation":
        if isinstance(value, Obligation):
            return value
        if isinstance(value, Mapping):
            obligation_id = str(value.get("obligation_id") or value.get("id") or value.get("name") or "").strip()
            if not obligation_id:
                raise ValueError("obligation_id is required")
            description = str(value.get("description") or value.get("summary") or "")
            receipt_types_value = (
                value.get("expected_receipt_types")
                or value.get("required_receipt_types")
                or value.get("receipt_types")
                or value.get("receipt_type")
                or ()
            )
            if isinstance(receipt_types_value, str):
                receipt_types = (receipt_types_value,)
            else:
                receipt_types = tuple(str(item) for item in receipt_types_value)
            return cls(
                obligation_id=obligation_id,
                description=description,
                expected_receipt_types=receipt_types,
            )
        if isinstance(value, str):
            return cls(obligation_id=value, expected_receipt_types=(value,))
        raise TypeError(f"Unsupported obligation value: {type(value)!r}")


@dataclass(frozen=True)
class Receipt:
    """Canonical receipt object indexed by the episode."""

    receipt_id: str
    episode_id: str
    receipt_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utc_now)
    seq: int = 0
    parent_receipt_id: Optional[str] = None
    task_id: Optional[str] = None
    schema_version: str = "3.0"
    canonical_hash: str = ""

    def to_dict(self, *, include_canonical_hash: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "type": self.receipt_type,
            "timestamp": _isoformat(self.created_at),
            "schema_version": self.schema_version,
            "seq": self.seq,
            "episode_id": self.episode_id,
        }
        if self.parent_receipt_id is not None:
            data["parent_receipt_id"] = self.parent_receipt_id
        if self.task_id is not None:
            data["task_id"] = self.task_id
        if include_canonical_hash and self.canonical_hash:
            data["canonical_hash"] = self.canonical_hash
        payload = _normalize_value(self.payload)
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key not in data:
                    data[key] = value
        return data

    @classmethod
    def create(
        cls,
        *,
        episode_id: str,
        receipt_type: str,
        payload: Optional[Mapping[str, Any]] = None,
        receipt_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
        seq: int = 0,
        parent_receipt_id: Optional[str] = None,
        task_id: Optional[str] = None,
        schema_version: str = "3.0",
    ) -> "Receipt":
        body = {
            "receipt_id": receipt_id or _stable_id("r"),
            "type": receipt_type,
            "timestamp": _isoformat(created_at or _utc_now()),
            "schema_version": schema_version,
            "seq": seq,
            "episode_id": episode_id,
        }
        if parent_receipt_id is not None:
            body["parent_receipt_id"] = parent_receipt_id
        if task_id is not None:
            body["task_id"] = task_id
        normalized_payload = _normalize_value(dict(payload or {}))
        if isinstance(normalized_payload, dict):
            for key, value in normalized_payload.items():
                if key not in body:
                    body[key] = value
        canonical_hash = _canonical_hash(body)
        return cls(
            receipt_id=str(body["receipt_id"]),
            episode_id=str(episode_id),
            receipt_type=str(receipt_type),
            payload=dict(normalized_payload) if isinstance(normalized_payload, dict) else {},
            created_at=_parse_datetime(body["timestamp"]),
            seq=int(seq),
            parent_receipt_id=parent_receipt_id,
            task_id=task_id,
            schema_version=str(schema_version),
            canonical_hash=canonical_hash,
        )

    @classmethod
    def from_trace_dict(cls, data: Mapping[str, Any]) -> "Receipt":
        receipt_type = str(data.get("type") or data.get("receipt_type") or "")
        receipt_id = str(data.get("receipt_id") or _stable_id("r"))
        episode_id = str(data.get("episode_id") or "")
        timestamp = _parse_datetime(data.get("timestamp") or data.get("created_at"))
        seq = int(data.get("seq") or 0)
        parent_receipt_id = data.get("parent_receipt_id")
        task_id = data.get("task_id")
        schema_version = str(data.get("schema_version") or "3.0")
        payload: Dict[str, Any] = {
            key: value
            for key, value in data.items()
            if key not in {
                "receipt_id",
                "receipt_type",
                "type",
                "timestamp",
                "created_at",
                "schema_version",
                "seq",
                "episode_id",
                "parent_receipt_id",
                "task_id",
                "canonical_hash",
                "_trace_id",
                "_stored_at",
            }
        }
        canonical_hash = str(data.get("canonical_hash") or "")
        receipt = cls(
            receipt_id=receipt_id,
            episode_id=episode_id,
            receipt_type=receipt_type,
            payload=payload,
            created_at=timestamp,
            seq=seq,
            parent_receipt_id=str(parent_receipt_id) if parent_receipt_id is not None else None,
            task_id=str(task_id) if task_id is not None else None,
            schema_version=schema_version,
            canonical_hash=canonical_hash,
        )
        if not receipt.canonical_hash:
            object.__setattr__(receipt, "canonical_hash", receipt.compute_hash())
        return receipt

    def compute_hash(self) -> str:
        return _canonical_hash(self.to_dict(include_canonical_hash=False))

    def to_trace_dict(self) -> Dict[str, Any]:
        return self.to_dict(include_canonical_hash=True)


@dataclass(frozen=True)
class SettlementRecord:
    """Guardian judgment bound to a settled episode."""

    decision_id: str
    outcome: SettlementOutcome
    completeness_score: float
    missing_obligations: Tuple[str, ...]
    contradiction_ids: Tuple[str, ...] = ()
    guardian_notes: str = ""
    finalized_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "outcome": self.outcome.value,
            "completeness_score": self.completeness_score,
            "missing_obligations": list(self.missing_obligations),
            "contradiction_ids": list(self.contradiction_ids),
            "guardian_notes": self.guardian_notes,
            "finalized_at": _isoformat(self.finalized_at),
        }


@dataclass(frozen=True)
class ProofPackArtifact:
    """Materialized proof-pack artifact emitted after settlement."""

    proof_pack_id: str
    episode_id: str
    pack_dir: Optional[Path]
    proof_pack_hash: str
    receipt_ids: Tuple[str, ...]
    settlement_decision_id: str
    emitted_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_pack_id": self.proof_pack_id,
            "episode_id": self.episode_id,
            "pack_dir": str(self.pack_dir) if self.pack_dir is not None else None,
            "proof_pack_hash": self.proof_pack_hash,
            "receipt_ids": list(self.receipt_ids),
            "settlement_decision_id": self.settlement_decision_id,
            "emitted_at": _isoformat(self.emitted_at),
        }


@dataclass(frozen=True)
class MemoryRecord:
    """Verified episode snapshot persisted to memory."""

    episode_id: str
    snapshot: Dict[str, Any]
    snapshot_hash: str
    proof_pack_hash: str
    settled_at: str
    persisted_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "snapshot": _normalize_value(self.snapshot),
            "snapshot_hash": self.snapshot_hash,
            "proof_pack_hash": self.proof_pack_hash,
            "settled_at": self.settled_at,
            "persisted_at": self.persisted_at,
        }


MEMORY_GRAPH: Dict[str, MemoryRecord] = {}


def _bucket_for_receipt_type(receipt_type: str) -> str:
    if receipt_type.startswith("task.") or receipt_type.endswith(".task"):
        return "tasks"
    if receipt_type.startswith("claim.") or receipt_type.startswith("claim_"):
        return "claims"
    if "contradiction" in receipt_type:
        return "contradictions"
    if receipt_type.startswith("decision.") or receipt_type.startswith("episode.settled"):
        return "decisions"
    if "pack" in receipt_type:
        return "packs"
    return "receipts"


def _receipt_payload_from_data(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return dict(data or {})


def _child_mapping() -> Dict[str, List[str]]:
    return {
        "tasks": [],
        "receipts": [],
        "claims": [],
        "contradictions": [],
        "decisions": [],
        "packs": [],
    }


def _coerce_obligations(values: Optional[Sequence[Any]]) -> Tuple[Obligation, ...]:
    return tuple(Obligation.from_value(value) for value in (values or ()))


def _expected_receipt_types(obligation: Obligation) -> Tuple[str, ...]:
    if obligation.expected_receipt_types:
        return obligation.expected_receipt_types
    return (obligation.obligation_id,)


def _snapshot_hash(snapshot: Mapping[str, Any]) -> str:
    return _canonical_hash(snapshot)


def _string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        token = value.strip()
        return [token] if token else []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items: List[str] = []
        for entry in value:
            token = str(entry).strip()
            if token:
                items.append(token)
        return items
    token = str(value).strip()
    return [token] if token else []


def _coerce_episode_state_directive_payload(directive: Any) -> Dict[str, Any]:
    if isinstance(directive, Mapping):
        payload = dict(directive)
    elif hasattr(directive, "to_dict") and callable(directive.to_dict):
        payload = dict(directive.to_dict())
    elif hasattr(directive, "__dict__") and not isinstance(directive, type):
        payload = {
            key: value
            for key, value in vars(directive).items()
            if not key.startswith("_")
        }
    else:
        raise TypeError("directive must be a mapping or mapping-like object")

    episode_id = str(payload.get("episode_id") or "").strip()
    if not episode_id:
        raise ValueError("episode_id is required")

    directive_value = payload.get("directive")
    if isinstance(directive_value, EpisodeDirectiveCode):
        directive_code = directive_value
    else:
        directive_code = EpisodeDirectiveCode(str(directive_value))

    source_lane = str(payload.get("source_lane") or "").strip()
    if not source_lane:
        raise ValueError("source_lane is required")

    source_artifact_ref = str(payload.get("source_artifact_ref") or "").strip()
    if not source_artifact_ref:
        raise ValueError("source_artifact_ref is required")

    source_authority_ceiling = str(payload.get("source_authority_ceiling") or "").strip()
    if not source_authority_ceiling:
        raise ValueError("source_authority_ceiling is required")

    target_substrate = payload.get("target_substrate")
    if target_substrate is not None:
        target_value = (
            target_substrate.value if isinstance(target_substrate, Enum) else str(target_substrate)
        )
        if target_value != ASSAY_EPISODE_TARGET_SUBSTRATE:
            raise ValueError(
                "directive target_substrate is not consumable by the Assay episode substrate"
            )
    else:
        target_value = ASSAY_EPISODE_TARGET_SUBSTRATE

    return {
        "episode_id": episode_id,
        "directive": directive_code,
        "directive_id": str(payload.get("directive_id") or _stable_id("directive")),
        "source_lane": source_lane,
        "source_artifact_ref": source_artifact_ref,
        "source_authority_ceiling": source_authority_ceiling,
        "target_substrate": target_value,
        "source_reason_codes": _string_list(payload.get("source_reason_codes")),
        "settlement_reason_codes": _string_list(payload.get("settlement_reason_codes")),
        "evidence_refs": _string_list(payload.get("evidence_refs")),
    }


def _receipt_lookup_from_trace(entries: Sequence[Mapping[str, Any]]) -> Dict[str, Receipt]:
    lookup: Dict[str, Receipt] = {}
    for entry in entries:
        receipt = Receipt.from_trace_dict(entry)
        lookup[receipt.receipt_id] = receipt
    return lookup


def _strip_runtime_metadata(entry: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in entry.items()
        if key not in {"_trace_id", "_stored_at"}
    }
# ---------------------------------------------------------------------------
# Checkpoint result
# ---------------------------------------------------------------------------

@dataclass
class Checkpoint:
    """A sealed proof pack at a point in the episode."""

    pack_dir: Path
    episode_id: str
    reason: str
    receipt_count: int
    sealed_at: str


# ---------------------------------------------------------------------------
# Verdict (thin wrapper over VerifyResult for ergonomics)
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    """Settlement posture for a checkpoint.

    .ok is True only when both integrity and claims pass.
    The underlying VerifyResult is available as .detail for inspection.
    """

    ok: bool
    integrity_pass: bool
    claims_pass: bool
    errors: List[str] = field(default_factory=list)
    detail: Optional[VerifyResult] = None

    @property
    def honest_fail(self) -> bool:
        """True when evidence is authentic but claims failed.

        This is exit-code 1 territory: real evidence of a real problem.
        """
        return self.integrity_pass and not self.claims_pass


# ---------------------------------------------------------------------------
# Episode
# ---------------------------------------------------------------------------

class Episode:
    """An episode-scoped evidence session.

    Wraps an AssayStore trace with episode-level metadata, receipt
    emission, checkpoint sealing, and settlement verification.

    Usage::

        episode = open_episode(policy_version="v2.1")

        episode.emit("model.invoked", {"model": "gpt-4", "tokens": 800})
        episode.emit("guardian.approved", {"action": "send_email"})

        checkpoint = episode.seal_checkpoint(reason="before_send_email")
        verdict = verify_checkpoint(checkpoint)

        if verdict.ok:
            send_email()
        elif verdict.honest_fail:
            escalate()

        episode.close()

    The episode emits bookend receipts (episode.opened / episode.closed)
    automatically so the proof pack always has a bounded narrative.
    """

    def __init__(
        self,
        *,
        episode_id: Optional[str] = None,
        policy_version: Optional[str] = None,
        guardian_profile: Optional[str] = None,
        risk_class: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        store: Optional[AssayStore] = None,
        claims: Optional[List[ClaimSpec]] = None,
        obligation_context: Optional[Dict[str, Any]] = None,
        required_obligations: Optional[Sequence[Any]] = None,
        parent_episode_id: Optional[str] = None,
        state: EpisodeState = EpisodeState.OPEN,
        outcome: Optional[SettlementOutcome] = None,
    ):
        self._store = store or get_default_store()
        self._episode_id = episode_id or _generate_episode_id()
        self._policy_version = policy_version
        self._guardian_profile = guardian_profile
        self._risk_class = risk_class
        self._metadata = metadata or {}
        self._claims = claims
        self._closed = False
        self._checkpoint_count = 0
        self._receipt_ids: List[str] = []
        self.receipts: List[Receipt] = []
        self.receipt_index: Dict[str, Receipt] = {}
        self.receipts_by_type: Dict[str, List[str]] = {}
        self.child_ids: Dict[str, List[str]] = _child_mapping()
        self.obligation_context: Dict[str, Any] = dict(obligation_context or {})
        self.required_obligations: Tuple[Obligation, ...] = _coerce_obligations(required_obligations)
        self.parent_episode_id = parent_episode_id
        self.state = state if isinstance(state, EpisodeState) else EpisodeState(str(state))
        self.outcome = outcome if isinstance(outcome, SettlementOutcome) or outcome is None else SettlementOutcome(str(outcome))
        self.opened_at = _utc_now()
        self.execution_started_at: Optional[datetime] = None
        self.execution_completed_at: Optional[datetime] = None
        self.execution_window: Optional[Tuple[datetime, Optional[datetime]]] = None
        self.settled_at: Optional[datetime] = None
        self.persisted_at: Optional[datetime] = None
        self.decision_id: Optional[str] = None
        self.settlement: Optional[SettlementRecord] = None
        self.proof_pack: Optional[ProofPackArtifact] = None
        self.proof_pack_hash: Optional[str] = None
        self.persisted: bool = False

        # Start a dedicated trace for this episode
        self._trace_id = self._store.start_trace()

        # Emit opening receipt
        self._emit_lifecycle(
            "episode.opened",
            {
                "policy_version": self._policy_version,
                "guardian_profile": self._guardian_profile,
                "risk_class": self._risk_class,
                **({"metadata": self._metadata} if self._metadata else {}),
                **({"obligation_context": self.obligation_context} if self.obligation_context else {}),
                **({"required_obligations": [obligation.to_dict() for obligation in self.required_obligations]} if self.required_obligations else {}),
                **({"parent_episode_id": self.parent_episode_id} if self.parent_episode_id else {}),
            },
            created_at=self.opened_at,
            enforce_state=False,
        )

    @property
    def episode_id(self) -> str:
        return self._episode_id

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def receipt_count(self) -> int:
        return len(self._receipt_ids)

    # ------------------------------------------------------------------
    # Receipt emission
    # ------------------------------------------------------------------

    def emit(
        self,
        receipt_type: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        parent_receipt_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> str:
        """Emit a receipt into this episode's trace.

        Returns the receipt_id for causal linking.
        """
        if self._closed:
            raise EpisodeClosedError(
                f"Episode {self._episode_id} is closed; cannot emit receipts."
            )
        return self.record_receipt(
            receipt_type,
            data,
            parent_receipt_id=parent_receipt_id,
            task_id=task_id,
        ).receipt_id

    def record_receipt(
        self,
        receipt_type: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        parent_receipt_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Receipt:
        """Emit and track a receipt, returning the canonical object."""
        if self._closed:
            raise EpisodeClosedError(
                f"Episode {self._episode_id} is closed; cannot emit receipts."
            )
        return self._emit_raw(
            receipt_type,
            data,
            parent_receipt_id=parent_receipt_id,
            task_id=task_id,
            enforce_state=True,
        )

    def _ensure_can_emit(self) -> None:
        if self.state not in {EpisodeState.OPEN, EpisodeState.EXECUTING}:
            raise EpisodeStateError(f"Episode {self._episode_id} cannot emit from {self.state.value}")

    def _emit_raw(
        self,
        receipt_type: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        parent_receipt_id: Optional[str] = None,
        task_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
        enforce_state: bool = True,
    ) -> Receipt:
        """Internal: emit and track a receipt, returning the canonical object."""
        if enforce_state:
            self._ensure_can_emit()
            if self.state == EpisodeState.OPEN:
                self.transition(EpisodeState.EXECUTING)

        predecessor_type = self.receipts[-1].receipt_type if self.receipts else None
        require_allowed_successor(predecessor_type, receipt_type)

        receipt = Receipt.create(
            episode_id=self._episode_id,
            receipt_type=receipt_type,
            payload=_receipt_payload_from_data(data),
            seq=len(self._receipt_ids),
            parent_receipt_id=parent_receipt_id,
            task_id=task_id,
            created_at=created_at,
        )

        # User data goes in first; structural fields override so they
        # cannot be accidentally (or maliciously) clobbered.
        entry = receipt.to_trace_dict()
        self._store.append_dict(dict(entry))
        self._receipt_ids.append(receipt.receipt_id)
        self.receipts.append(receipt)
        self.receipt_index[receipt.receipt_id] = receipt
        self.receipts_by_type.setdefault(receipt.receipt_type, []).append(receipt.receipt_id)
        self.child_ids["receipts"].append(receipt.receipt_id)
        bucket = _bucket_for_receipt_type(receipt.receipt_type)
        if bucket != "receipts":
            self.child_ids[bucket].append(receipt.receipt_id)
        if task_id is not None:
            self.child_ids["tasks"].append(task_id)
        return receipt

    def _emit_lifecycle(
        self,
        receipt_type: str,
        data: Dict[str, Any],
        *,
        created_at: Optional[datetime] = None,
        enforce_state: bool = False,
    ) -> Receipt:
        """Emit a lifecycle receipt (opened/closed)."""
        return self._emit_raw(
            receipt_type,
            data,
            created_at=created_at,
            enforce_state=enforce_state,
        )

    # ------------------------------------------------------------------
    # Constitutional lifecycle
    # ------------------------------------------------------------------

    def transition(self, next_state: EpisodeState) -> None:
        """Advance the constitutional state machine.

        Closed episodes reject all transitions. ABANDONED causes closure,
        but closure cannot be followed by ABANDONED.
        """
        if not isinstance(next_state, EpisodeState):
            next_state = EpisodeState(str(next_state))

        # Closed check FIRST — before same-state early return.
        # A closed episode rejects ALL transitions, even no-ops.
        if self._closed:
            raise EpisodeStateError(
                f"Episode {self._episode_id} is closed; "
                f"cannot transition to {next_state.value}"
            )

        if next_state == self.state:
            return

        allowed: Dict[EpisodeState, Tuple[EpisodeState, ...]] = {
            EpisodeState.OPEN: (EpisodeState.EXECUTING, EpisodeState.ABANDONED),
            EpisodeState.EXECUTING: (EpisodeState.AWAITING_GUARDIAN, EpisodeState.ABANDONED),
            EpisodeState.AWAITING_GUARDIAN: (
                EpisodeState.EXECUTING,
                EpisodeState.SETTLED,
                EpisodeState.ABANDONED,
            ),
            EpisodeState.SETTLED: (EpisodeState.PERSISTED, EpisodeState.ABANDONED),
        }
        if next_state not in allowed.get(self.state, ()):
            raise EpisodeStateError(f"Invalid transition: {self.state.value} -> {next_state.value}")

        now = _utc_now()
        if next_state == EpisodeState.EXECUTING:
            self.execution_started_at = self.execution_started_at or now
            if self.state == EpisodeState.AWAITING_GUARDIAN:
                self.execution_completed_at = None
            self.execution_window = (self.execution_started_at, self.execution_completed_at)
        elif next_state == EpisodeState.AWAITING_GUARDIAN:
            self.execution_started_at = self.execution_started_at or now
            self.execution_completed_at = now
            self.execution_window = (self.execution_started_at, self.execution_completed_at)
        elif next_state == EpisodeState.SETTLED:
            self.settled_at = now
        elif next_state == EpisodeState.PERSISTED:
            self.persisted_at = now
        elif next_state == EpisodeState.ABANDONED:
            # ABANDONED is a terminal state. It MUST emit a receipt.
            # Without this, episodes can silently disappear — violating
            # "no silent epistemic death."
            self._emit_lifecycle("episode.abandoned", {
                "abandoned_from": self.state.value,
                "receipt_count": len(self._receipt_ids),
                "abandoned_at": now.isoformat(),
            }, enforce_state=False)

        self.state = next_state

        # If we just entered ABANDONED, also close the episode to prevent
        # further emission and ensure episode.closed receipt is emitted.
        if next_state == EpisodeState.ABANDONED and not self._closed:
            self.close(status="abandoned")

    def start_execution(self) -> None:
        """Enter EXECUTING state."""
        if self.state == EpisodeState.EXECUTING:
            return
        if self.state != EpisodeState.OPEN:
            raise EpisodeStateError(f"Episode {self._episode_id} cannot start execution from {self.state.value}")
        self.transition(EpisodeState.EXECUTING)

    def mark_execution_complete(self) -> None:
        """Enter AWAITING_GUARDIAN state."""
        if self.state == EpisodeState.AWAITING_GUARDIAN:
            return
        if self.state == EpisodeState.OPEN:
            self.start_execution()
        if self.state != EpisodeState.EXECUTING:
            raise EpisodeStateError(f"Episode {self._episode_id} cannot complete execution from {self.state.value}")
        self.transition(EpisodeState.AWAITING_GUARDIAN)

    def _directive_receipt_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "directive": payload["directive"].value,
            "directive_id": payload["directive_id"],
            "source_lane": payload["source_lane"],
            "source_artifact_ref": payload["source_artifact_ref"],
            "source_authority_ceiling": payload["source_authority_ceiling"],
            "target_substrate": payload["target_substrate"],
            "source_reason_codes": list(payload["source_reason_codes"]),
            "settlement_reason_codes": list(payload["settlement_reason_codes"]),
            "evidence_refs": list(payload["evidence_refs"]),
        }

    def _find_directive_receipt(self, directive_id: str) -> Optional[Receipt]:
        for receipt_id in self.receipts_by_type.get("episode.state_directed", []):
            receipt = self.receipt_index[receipt_id]
            if str(receipt.payload.get("directive_id")) == directive_id:
                return receipt
        return None

    def _validate_episode_state_directive(self, payload: Mapping[str, Any]) -> bool:
        directive_id = str(payload["directive_id"])
        existing = self._find_directive_receipt(directive_id)
        expected_payload = self._directive_receipt_payload(payload)
        if existing is not None:
            if existing.payload != expected_payload:
                raise EpisodeStateError(
                    f"directive_id {directive_id} was already consumed with different payload"
                )
            return False

        directive_code = payload["directive"]
        if directive_code == EpisodeDirectiveCode.REOPEN_FOR_RETRY:
            if self.state not in {
                EpisodeState.OPEN,
                EpisodeState.EXECUTING,
                EpisodeState.AWAITING_GUARDIAN,
            }:
                raise EpisodeStateError(
                    f"Episode {self._episode_id} cannot apply {directive_code.value} from {self.state.value}"
                )
            return True

        if directive_code == EpisodeDirectiveCode.ROUTE_TO_REVIEW:
            if self.state not in {
                EpisodeState.OPEN,
                EpisodeState.EXECUTING,
                EpisodeState.AWAITING_GUARDIAN,
            }:
                raise EpisodeStateError(
                    f"Episode {self._episode_id} cannot route to review from {self.state.value}"
                )
            return True

        if self.settlement is not None:
            raise EpisodeStateError(
                f"Episode {self._episode_id} already has a settlement; cannot apply terminal directive"
            )
        if self.state not in {
            EpisodeState.OPEN,
            EpisodeState.EXECUTING,
            EpisodeState.AWAITING_GUARDIAN,
        }:
            raise EpisodeStateError(
                f"Episode {self._episode_id} cannot settle from {self.state.value}"
            )
        return True

    def apply_episode_state_directive(self, directive: Any) -> None:
        """Apply a canonical bridge directive to the Assay episode substrate."""
        if self._closed:
            raise EpisodeStateError(
                f"Episode {self._episode_id} is closed; cannot apply episode-state directive"
            )

        try:
            payload = _coerce_episode_state_directive_payload(directive)
        except (TypeError, ValueError) as exc:
            raise EpisodeStateError(f"Invalid episode-state directive: {exc}") from exc

        if payload["episode_id"] != self._episode_id:
            raise EpisodeStateError(
                f"directive episode_id {payload['episode_id']} does not match episode {self._episode_id}"
            )

        if not self._validate_episode_state_directive(payload):
            return

        self._emit_raw(
            "episode.state_directed",
            self._directive_receipt_payload(payload),
            enforce_state=False,
        )

        directive_code = payload["directive"]
        if directive_code == EpisodeDirectiveCode.REOPEN_FOR_RETRY:
            self._apply_retry_directive(payload)
            return
        if directive_code == EpisodeDirectiveCode.ROUTE_TO_REVIEW:
            self._apply_review_directive()
            return

        outcome = (
            SettlementOutcome.TAMPERED
            if directive_code == EpisodeDirectiveCode.CLOSE_AS_TAINTED
            else SettlementOutcome.HONEST_FAIL
        )
        self._apply_terminal_directive(payload, outcome=outcome)

    def _apply_retry_directive(self, payload: Mapping[str, Any]) -> None:
        if self.state == EpisodeState.OPEN:
            self.start_execution()
            return
        if self.state == EpisodeState.EXECUTING:
            return
        if self.state == EpisodeState.AWAITING_GUARDIAN:
            self.transition(EpisodeState.EXECUTING)
            return
        raise EpisodeStateError(
            f"Episode {self._episode_id} cannot apply {payload['directive'].value} from {self.state.value}"
        )

    def _apply_review_directive(self) -> None:
        if self.state == EpisodeState.OPEN:
            self.start_execution()
        if self.state == EpisodeState.EXECUTING:
            self.mark_execution_complete()
            return
        if self.state == EpisodeState.AWAITING_GUARDIAN:
            return
        raise EpisodeStateError(
            f"Episode {self._episode_id} cannot route to review from {self.state.value}"
        )

    def _apply_terminal_directive(
        self,
        payload: Mapping[str, Any],
        *,
        outcome: SettlementOutcome,
    ) -> SettlementRecord:
        if self.settlement is not None:
            raise EpisodeStateError(
                f"Episode {self._episode_id} already has a settlement; cannot apply terminal directive"
            )

        if self.state == EpisodeState.OPEN:
            self.start_execution()
        if self.state == EpisodeState.EXECUTING:
            self.mark_execution_complete()
        if self.state != EpisodeState.AWAITING_GUARDIAN:
            raise EpisodeStateError(
                f"Episode {self._episode_id} cannot settle from {self.state.value}"
            )

        completeness_score, missing = self.evaluate_completeness()
        contradiction_ids = tuple(
            receipt.receipt_id
            for receipt in self.receipts
            if "contradiction" in receipt.receipt_type
        )
        tampered = outcome == SettlementOutcome.TAMPERED
        decision_time = _utc_now()
        decision_receipt = self._emit_raw(
            "episode.settled",
            {
                "outcome": outcome.value,
                "completeness_score": completeness_score,
                "missing_obligations": list(missing),
                "contradiction_ids": list(contradiction_ids),
                "tampered": tampered,
                "directive": payload["directive"].value,
                "directive_id": payload["directive_id"],
                "source_lane": payload["source_lane"],
                "source_artifact_ref": payload["source_artifact_ref"],
                "source_authority_ceiling": payload["source_authority_ceiling"],
                "source_reason_codes": list(payload["source_reason_codes"]),
                "settlement_reason_codes": list(payload["settlement_reason_codes"]),
                "evidence_refs": list(payload["evidence_refs"]),
                "directed": True,
            },
            created_at=decision_time,
            enforce_state=False,
        )
        self.decision_id = decision_receipt.receipt_id
        self.outcome = outcome
        self.transition(EpisodeState.SETTLED)
        self.settled_at = decision_time
        self.settlement = SettlementRecord(
            decision_id=decision_receipt.receipt_id,
            outcome=outcome,
            completeness_score=completeness_score,
            missing_obligations=missing,
            contradiction_ids=contradiction_ids,
            guardian_notes=(
                f"episode_state_directive:{payload['directive'].value} "
                f"source={payload['source_artifact_ref']}"
            ),
            finalized_at=decision_time,
        )
        return self.settlement

    def add_child(self, kind: str, child_id: str) -> None:
        """Register lineage information for the episode."""
        if kind not in self.child_ids:
            raise ValueError(f"Unknown child kind: {kind}")
        self.child_ids[kind].append(child_id)

    def evaluate_completeness(
        self,
        receipts: Optional[Sequence[Any]] = None,
    ) -> Tuple[float, Tuple[str, ...]]:
        """Measure obligation coverage against the observed receipts."""
        if receipts is None:
            observed_types = set(self.receipts_by_type)
        else:
            observed_types = set()
            for entry in receipts:
                if isinstance(entry, Receipt):
                    observed_types.add(entry.receipt_type)
                elif isinstance(entry, Mapping):
                    observed_types.add(str(entry.get("type") or entry.get("receipt_type") or ""))
                else:
                    observed_types.add(str(getattr(entry, "receipt_type", "")))

        missing: List[str] = []
        for obligation in self.required_obligations:
            expected_types = _expected_receipt_types(obligation)
            if not expected_types:
                continue
            if not all(expected in observed_types for expected in expected_types):
                missing.append(obligation.obligation_id)

        if not self.required_obligations:
            completeness = 1.0
        else:
            completeness = (len(self.required_obligations) - len(missing)) / len(self.required_obligations)
        return completeness, tuple(missing)

    def detect_tampering(self, receipts: Optional[Sequence[Mapping[str, Any]]] = None) -> bool:
        """Check whether the stored trace diverges from the in-memory receipt log."""
        live_entries: Sequence[Mapping[str, Any]]
        if receipts is None:
            live_entries = self._store.read_trace(self._trace_id)
        else:
            live_entries = receipts

        if len(live_entries) != len(self.receipts):
            return True

        for stored_entry, canonical_receipt in zip(live_entries, self.receipts):
            sanitised = _strip_runtime_metadata(stored_entry)
            if sanitised != canonical_receipt.to_trace_dict():
                return True

        return False

    def _settlement_snapshot(self) -> Dict[str, Any]:
        """Return the canonical episode body used for hashing and persistence."""
        return {
            "episode_id": self._episode_id,
            "policy_version": self._policy_version,
            "guardian_profile": self._guardian_profile,
            "risk_class": self._risk_class,
            "metadata": _normalize_value(self._metadata),
            "obligation_context": _normalize_value(self.obligation_context),
            "parent_episode_id": self.parent_episode_id,
            "required_obligations": [obligation.to_dict() for obligation in self.required_obligations],
            "state": self.state.value,
            "outcome": self.outcome.value if isinstance(self.outcome, SettlementOutcome) else self.outcome,
            "opened_at": _isoformat(self.opened_at),
            "execution_started_at": _isoformat(self.execution_started_at) if self.execution_started_at else None,
            "execution_completed_at": _isoformat(self.execution_completed_at) if self.execution_completed_at else None,
            "execution_window": [
                _isoformat(self.execution_window[0]) if self.execution_window and self.execution_window[0] else None,
                _isoformat(self.execution_window[1]) if self.execution_window and self.execution_window[1] else None,
            ] if self.execution_window else None,
            "settled_at": _isoformat(self.settled_at) if self.settled_at else None,
            "child_ids": _normalize_value(self.child_ids),
            "receipts": [receipt.to_trace_dict() for receipt in self.receipts],
            "settlement": self.settlement.to_dict() if self.settlement else None,
            "decision_id": self.decision_id,
            "proof_pack_hash": self.proof_pack_hash,
            "proof_pack": self.proof_pack.to_dict() if self.proof_pack else None,
            "closed": self._closed,
        }

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Return the settled episode snapshot with derived metadata included."""
        snapshot = self._settlement_snapshot()
        snapshot["proof_pack_hash"] = self.proof_pack_hash
        snapshot["persisted_at"] = _isoformat(self.persisted_at) if self.persisted_at else None
        return snapshot

    def canonical_snapshot_hash(self) -> str:
        """Hash the episode body excluding derived persistence metadata."""
        body = self._settlement_snapshot()
        body.pop("proof_pack_hash", None)
        body.pop("proof_pack", None)
        body.pop("closed", None)
        child_ids = dict(body.get("child_ids") or {})
        child_ids.pop("packs", None)
        body["child_ids"] = child_ids
        if body.get("state") == EpisodeState.PERSISTED.value:
            body["state"] = EpisodeState.SETTLED.value
        return _snapshot_hash(body)

    def settle(self) -> SettlementRecord:
        """Compute guardian settlement and emit the settlement receipt."""
        if self.settlement is not None:
            return self.settlement

        if self.state == EpisodeState.OPEN:
            self.start_execution()
        if self.state == EpisodeState.EXECUTING:
            self.mark_execution_complete()
        if self.state != EpisodeState.AWAITING_GUARDIAN:
            if self.state in {EpisodeState.SETTLED, EpisodeState.PERSISTED} and self.settlement is not None:
                return self.settlement
            raise EpisodeStateError(
                f"Episode {self._episode_id} cannot settle from {self.state.value}"
            )

        tampered = self.detect_tampering()
        completeness_score, missing = self.evaluate_completeness()
        contradiction_ids = tuple(
            receipt.receipt_id
            for receipt in self.receipts
            if "contradiction" in receipt.receipt_type
        )
        if tampered:
            outcome = SettlementOutcome.TAMPERED
        elif missing:
            outcome = SettlementOutcome.HONEST_FAIL
        else:
            outcome = SettlementOutcome.PASS

        decision_time = _utc_now()
        decision_receipt = self._emit_raw(
            "episode.settled",
            {
                "outcome": outcome.value,
                "completeness_score": completeness_score,
                "missing_obligations": list(missing),
                "contradiction_ids": list(contradiction_ids),
                "tampered": tampered,
            },
            created_at=decision_time,
            enforce_state=False,
        )
        self.decision_id = decision_receipt.receipt_id
        self.outcome = outcome
        self.transition(EpisodeState.SETTLED)
        self.settled_at = decision_time
        self.settlement = SettlementRecord(
            decision_id=decision_receipt.receipt_id,
            outcome=outcome,
            completeness_score=completeness_score,
            missing_obligations=missing,
            contradiction_ids=contradiction_ids,
            guardian_notes="auto-settlement",
            finalized_at=decision_time,
        )
        return self.settlement

    def emit_proof_pack(
        self,
        output_dir: Optional[Path] = None,
        *,
        keystore: Optional[AssayKeyStore] = None,
        mode: str = "shadow",
    ) -> ProofPackArtifact:
        """Materialize a proof pack for the settled episode."""
        if self.settlement is None:
            self.settle()
        if self.state not in {EpisodeState.SETTLED, EpisodeState.PERSISTED}:
            raise EpisodeStateError(f"Episode {self._episode_id} must be settled before proof pack emission")
        if self.proof_pack is not None:
            if output_dir is not None and self.proof_pack.pack_dir is not None and Path(output_dir) != self.proof_pack.pack_dir:
                raise EpisodeStateError("Episode already emitted a proof pack to a different directory")
            return self.proof_pack

        entries = self._store.read_trace(self._trace_id)
        if not entries:
            raise ValueError(f"No receipts in trace {self._trace_id}")

        ks = keystore or get_default_keystore()
        if output_dir is None:
            output_dir = Path(f"proof_pack_{self._trace_id}")

        pack = ProofPack(
            run_id=self._trace_id,
            entries=entries,
            mode=mode,
            claims=self._claims,
        )
        pack_dir = pack.build(output_dir, keystore=ks)

        proof_pack_hash = self.canonical_snapshot_hash()
        artifact = ProofPackArtifact(
            proof_pack_id=pack_dir.name,
            episode_id=self._episode_id,
            pack_dir=pack_dir,
            proof_pack_hash=proof_pack_hash,
            receipt_ids=tuple(self._receipt_ids),
            settlement_decision_id=self.decision_id or "",
        )
        self.proof_pack = artifact
        self.proof_pack_hash = proof_pack_hash
        self.child_ids["packs"].append(artifact.proof_pack_id)
        return artifact

    def persist(self) -> MemoryRecord:
        """Persist a settled episode into the memory graph."""
        if self.state == EpisodeState.PERSISTED and self._episode_id in MEMORY_GRAPH:
            return MEMORY_GRAPH[self._episode_id]
        if self.settlement is None or self.proof_pack is None or not self.proof_pack_hash:
            raise EpisodePersistenceError("Episode must be settled and have a proof pack before persistence")
        if self.state != EpisodeState.SETTLED:
            raise EpisodePersistenceError(f"Episode {self._episode_id} cannot persist from {self.state.value}")

        persisted_time = _utc_now()
        self.persisted_at = persisted_time
        snapshot = self.to_canonical_dict()
        snapshot_hash = self.canonical_snapshot_hash()
        record = MemoryRecord(
            episode_id=self._episode_id,
            snapshot=snapshot,
            snapshot_hash=snapshot_hash,
            proof_pack_hash=self.proof_pack_hash,
            settled_at=_isoformat(self.settled_at or _utc_now()),
            persisted_at=_isoformat(persisted_time),
        )
        MEMORY_GRAPH[self._episode_id] = record
        self.persisted = True
        self.transition(EpisodeState.PERSISTED)
        self.persisted_at = persisted_time
        return record

    # ------------------------------------------------------------------
    # Checkpoint sealing
    # ------------------------------------------------------------------

    def seal_checkpoint(
        self,
        reason: str = "checkpoint",
        *,
        output_dir: Optional[Path] = None,
        keystore: Optional[AssayKeyStore] = None,
        mode: str = "shadow",
    ) -> Checkpoint:
        """Seal current receipts into a signed proof pack.

        This does not close the episode. More receipts can be emitted
        after a checkpoint (e.g. for multi-phase workflows).

        Args:
            reason: Why the checkpoint was sealed (human-readable).
            output_dir: Where to write the pack. Defaults to
                        ./proof_pack_{trace_id}_cp{N}/
            keystore: Optional key store. Defaults to ~/.assay/keys/.
            mode: shadow | enforced | breakglass.

        Returns:
            Checkpoint with the pack directory and metadata.
        """
        if self._closed:
            raise EpisodeClosedError(
                f"Episode {self._episode_id} is closed; cannot seal checkpoint."
            )

        self._checkpoint_count += 1

        # Emit governance posture snapshot before sealing.
        # This makes governance context an artifact in the sealed chain,
        # not a side-channel comment. Every pack carries its governance weather.
        try:
            from assay.governance_posture import (
                POSTURE_RECEIPT_TYPE,
                evaluate_posture,
            )
            posture = evaluate_posture()
            posture_data = posture.to_receipt_dict()
            posture_data.pop("type", None)  # _emit_raw sets the type
            self._emit_raw(
                POSTURE_RECEIPT_TYPE,
                posture_data,
                enforce_state=False,
            )
        except Exception:
            pass  # Posture emission is best-effort; don't block sealing

        # Emit checkpoint receipt before sealing
        self._emit_raw(
            "checkpoint.sealed",
            {
                "reason": reason,
                "checkpoint_number": self._checkpoint_count,
                "receipt_count": len(self._receipt_ids),
            },
            enforce_state=False,
        )

        # Read current trace
        entries = self._store.read_trace(self._trace_id)
        if not entries:
            raise ValueError(f"No receipts in trace {self._trace_id}")

        # Determine output path
        if output_dir is None:
            suffix = f"_cp{self._checkpoint_count}" if self._checkpoint_count > 1 else ""
            output_dir = Path(f"proof_pack_{self._trace_id}{suffix}")

        ks = keystore or get_default_keystore()

        pack = ProofPack(
            run_id=self._trace_id,
            entries=entries,
            mode=mode,
            claims=self._claims,
        )
        pack_dir = pack.build(output_dir, keystore=ks)

        sealed_at = datetime.now(timezone.utc).isoformat()

        return Checkpoint(
            pack_dir=pack_dir,
            episode_id=self._episode_id,
            reason=reason,
            receipt_count=len(entries),
            sealed_at=sealed_at,
        )

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(
        self,
        status: str = "completed",
        summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Close the episode. No more receipts can be emitted after this."""
        if self._closed:
            return  # idempotent

        self._emit_lifecycle("episode.closed", {
            "status": status,
            "receipt_count": len(self._receipt_ids),
            **({"summary": summary} if summary else {}),
        })
        self._closed = True

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Episode":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._closed:
            status = "failed" if exc_type else "completed"
            self.close(status=status)
        return None  # do not suppress exceptions


# ---------------------------------------------------------------------------
# Verification (standalone, works on any checkpoint/pack)
# ---------------------------------------------------------------------------

def verify_checkpoint(
    checkpoint: Checkpoint,
    *,
    keystore: Optional[AssayKeyStore] = None,
    claims: Optional[List[ClaimSpec]] = None,
    check_expiry: bool = False,
) -> Verdict:
    """Verify a sealed checkpoint and return a settlement verdict.

    This is the settlement gate: call it before allowing a
    consequential action to proceed.

    Args:
        checkpoint: A Checkpoint from episode.seal_checkpoint().
        keystore: Optional key store for signature verification.
        claims: Additional claims to check beyond pack-embedded ones.
        check_expiry: If True, fail packs past their valid_until.

    Returns:
        Verdict with .ok, .integrity_pass, .claims_pass, .honest_fail.
    """
    return verify_pack(
        checkpoint.pack_dir,
        keystore=keystore,
        claims=claims,
        check_expiry=check_expiry,
    )


def verify_pack(
    pack_dir: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
    claims: Optional[List[ClaimSpec]] = None,
    check_expiry: bool = False,
) -> Verdict:
    """Verify any proof pack directory and return a Verdict.

    Works on packs from seal_checkpoint() or from assay run.
    """
    import json as _json

    from assay.claim_verifier import verify_claims
    from assay.integrity import verify_pack_manifest, verify_receipt_pack

    pack_dir = Path(pack_dir)
    errors: List[str] = []

    # Load receipts
    receipt_path = pack_dir / "receipt_pack.jsonl"
    if not receipt_path.exists():
        return Verdict(
            ok=False, integrity_pass=False, claims_pass=False,
            errors=["receipt_pack.jsonl not found"],
        )

    entries = []
    for line in receipt_path.read_text().splitlines():
        if line.strip():
            entries.append(_json.loads(line))

    # Integrity check on receipts
    receipt_result = verify_receipt_pack(entries)
    integrity_pass = receipt_result.passed

    if not integrity_pass:
        for e in receipt_result.errors:
            errors.append(f"{e.code}: {e.message}")

    # Manifest check (if manifest exists)
    manifest_path = pack_dir / "pack_manifest.json"
    if manifest_path.exists():
        ks = keystore or get_default_keystore()
        manifest = _json.loads(manifest_path.read_text())
        manifest_result = verify_pack_manifest(manifest, pack_dir, ks)
        if not manifest_result.passed:
            integrity_pass = False
            for e in manifest_result.errors:
                errors.append(f"{e.code}: {e.message}")

        # Check expiry
        if check_expiry:
            valid_until = manifest.get("attestation", {}).get("valid_until")
            if valid_until:
                try:
                    expiry = datetime.fromisoformat(valid_until)
                    if datetime.now(timezone.utc) > expiry:
                        errors.append("E_PACK_STALE: pack has expired")
                        integrity_pass = False
                except (ValueError, TypeError):
                    pass

    # Claims check
    claims_pass = True
    if claims:
        claim_result = verify_claims(entries, claims)
        claims_pass = claim_result.passed
        if not claims_pass:
            for r in claim_result.results:
                if not r.passed:
                    errors.append(f"claim:{r.claim_id}: expected {r.expected}, got {r.actual}")

    return Verdict(
        ok=integrity_pass and claims_pass,
        integrity_pass=integrity_pass,
        claims_pass=claims_pass,
        errors=errors,
        detail=receipt_result,
    )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def open_episode(
    *,
    episode_id: Optional[str] = None,
    policy_version: Optional[str] = None,
    guardian_profile: Optional[str] = None,
    risk_class: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    store: Optional[AssayStore] = None,
    claims: Optional[List[ClaimSpec]] = None,
    obligation_context: Optional[Dict[str, Any]] = None,
    required_obligations: Optional[Sequence[Any]] = None,
    parent_episode_id: Optional[str] = None,
    state: EpisodeState = EpisodeState.OPEN,
    outcome: Optional[SettlementOutcome] = None,
) -> Episode:
    """Open a new evidence episode.

    This is the primary entry point for Mode 2 (Runtime mode).

    Usage::

        episode = assay.open_episode(policy_version="v2.1")
        episode.emit("model.invoked", {"model": "gpt-4"})
        checkpoint = episode.seal_checkpoint(reason="before_action")
        verdict = assay.verify_checkpoint(checkpoint)
        episode.close()

    Or as a context manager::

        with assay.open_episode() as ep:
            ep.emit("tool.invoked", {"tool": "search"})
            cp = ep.seal_checkpoint()
            v = assay.verify_checkpoint(cp)
    """
    return Episode(
        episode_id=episode_id,
        policy_version=policy_version,
        guardian_profile=guardian_profile,
        risk_class=risk_class,
        metadata=metadata,
        store=store,
        claims=claims,
        obligation_context=obligation_context,
        required_obligations=required_obligations,
        parent_episode_id=parent_episode_id,
        state=state,
        outcome=outcome,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def emit_receipt(
    episode: Episode,
    receipt_type: str,
    data: Optional[Dict[str, Any]] = None,
    *,
    parent_receipt_id: Optional[str] = None,
    task_id: Optional[str] = None,
) -> Receipt:
    """Module-level receipt helper for the constitutional contract."""
    return episode.record_receipt(
        receipt_type,
        data,
        parent_receipt_id=parent_receipt_id,
        task_id=task_id,
    )


def start_execution(episode: Episode) -> None:
    episode.start_execution()


def mark_execution_complete(episode: Episode) -> None:
    episode.mark_execution_complete()


def evaluate_completeness(
    episode: Episode,
    receipts: Optional[Sequence[Any]] = None,
) -> Tuple[float, Tuple[str, ...]]:
    return episode.evaluate_completeness(receipts=receipts)


def settle_episode(episode: Episode) -> SettlementRecord:
    return episode.settle()


def emit_proof_pack(
    episode: Episode,
    output_dir: Optional[Path] = None,
    *,
    keystore: Optional[AssayKeyStore] = None,
    mode: str = "shadow",
) -> ProofPackArtifact:
    return episode.emit_proof_pack(output_dir=output_dir, keystore=keystore, mode=mode)


def persist_episode(episode: Episode) -> MemoryRecord:
    return episode.persist()


def apply_episode_state_directive(episode: Episode, directive: Any) -> None:
    episode.apply_episode_state_directive(directive)


def get_memory_record(episode_id: str) -> Optional[MemoryRecord]:
    return MEMORY_GRAPH.get(episode_id)


class EpisodeStateError(RuntimeError):
    """Raised when the episode state machine is violated."""


class EpisodePersistenceError(RuntimeError):
    """Raised when a settled episode cannot be persisted."""


def _generate_episode_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"ep_{ts}_{uuid.uuid4().hex[:8]}"


class EpisodeClosedError(RuntimeError):
    """Raised when trying to emit or seal on a closed episode."""
    pass


__all__ = [
    "Checkpoint",
    "ASSAY_EPISODE_TARGET_SUBSTRATE",
    "EpisodeDirectiveCode",
    "EpisodeState",
    "Episode",
    "EpisodeClosedError",
    "EpisodePersistenceError",
    "EpisodeStateError",
    "Obligation",
    "ProofPackArtifact",
    "Receipt",
    "SettlementOutcome",
    "SettlementRecord",
    "MemoryRecord",
    "MEMORY_GRAPH",
    "Verdict",
    "emit_proof_pack",
    "emit_receipt",
    "evaluate_completeness",
    "get_memory_record",
    "apply_episode_state_directive",
    "mark_execution_complete",
    "persist_episode",
    "settle_episode",
    "start_execution",
    "open_episode",
    "verify_checkpoint",
    "verify_pack",
]
