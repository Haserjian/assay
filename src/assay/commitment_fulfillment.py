"""Commitment → Result → Fulfillment wedge — Slice 1.

Doctrine source: loom-staging docs/architecture/authority_nouns.md
(commit 9c5921d5, frozen).

Event lifecycle:
    commitment.registered      — a declared forward-looking commitment.
    result.observed            — a non-adjudicating observation referencing
                                 zero or more commitments. Never closes.
    fulfillment.commitment_kept    — terminal: commitment was kept.
    fulfillment.commitment_broken  — terminal: commitment was broken.

Invariants:
    1. Every commitment.registered must have a resolvable policy_hash. The
       embedded PolicyResolver must bind to a COMPILE_RECEIPT.json whose
       policy_hash equals the receipt's policy_hash.
    2. result.observed is non-adjudicating. It MUST NOT contain ``fulfills``
       or ``closes`` fields. References are typed ({"kind": "commitment",
       "id": ...}) and do not, by themselves, close anything.
    3. A commitment has zero or one terminal fulfillment. Emission of a
       second terminal for the same commitment_id raises
       ``TerminalFulfillmentError``.

This module does NOT adjudicate the obligation namespace collision with
``src/assay/obligation.py`` (override-debt semantics). Slice 2 must resolve
that before adding the obligation side of the wedge.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from importlib import resources
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from jsonschema import Draft202012Validator

from assay.episode import Episode
from assay.policy_resolver import PolicyResolutionError, PolicyResolver, resolve_policy
from assay.store import AssayStore, ReceiptStoreIntegrityError


SCHEMA_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Receipt-type constants — DOCTRINE-EXACT serialized form
# ---------------------------------------------------------------------------

COMMITMENT_REGISTRATION_RECEIPT_TYPE = "commitment.registered"
RESULT_OBSERVATION_RECEIPT_TYPE = "result.observed"
FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE = "fulfillment.commitment_kept"
FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE = "fulfillment.commitment_broken"

TERMINAL_FULFILLMENT_TYPES = frozenset({
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TerminalFulfillmentError(ValueError):
    """Raised when emitting a terminal fulfillment for an already-closed commitment.

    A commitment has zero or one terminal fulfillment (kept | broken).
    Attempting to emit a second terminal for the same commitment_id is a
    constitutional violation of the closure invariant.
    """


class UnanchoredFulfillmentError(ValueError):
    """Raised when a terminal fulfillment cannot anchor to its referents.

    A terminal fulfillment must anchor to:
        1. A prior ``commitment.registered`` receipt with the same commitment_id.
        2. A prior ``result.observed`` receipt whose ``result_id`` equals the
           terminal's ``result_id`` **and** whose ``references`` list contains
           an explicit commitment reference to the terminal's ``commitment_id``.

    Existence alone is insufficient: a result that observed a different
    commitment must not adjudicate this one. The anchor is the
    ``(result_id, commitment_id)`` edge, not bare id existence.
    """


# ``ReceiptStoreIntegrityError`` is defined in ``assay.store`` (its home is
# the storage substrate, not the commitment wedge). We re-export it here
# for backwards-compat with tests/consumers that imported it from this
# module in earlier iterations of the slice.


# ---------------------------------------------------------------------------
# Schema validator cache
# ---------------------------------------------------------------------------

_SCHEMA_VALIDATORS: Dict[str, Draft202012Validator] = {}


def _get_validator(schema_name: str) -> Draft202012Validator:
    validator = _SCHEMA_VALIDATORS.get(schema_name)
    if validator is None:
        schema_path = resources.files("assay").joinpath(f"schemas/{schema_name}")
        schema = json.loads(schema_path.read_text())
        validator = Draft202012Validator(schema)
        _SCHEMA_VALIDATORS[schema_name] = validator
    return validator


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


@dataclass
class CommitmentRegistrationArtifact:
    """A declared forward-looking commitment."""

    commitment_id: str
    timestamp: str
    episode_id: str
    actor_id: str
    text: str
    commitment_type: str
    policy_hash: str
    policy_resolver: Dict[str, Any]
    due_at: Optional[str] = None
    evidence_uri: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "commitment_registration"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def validate(self) -> None:
        _get_validator("commitment_registration.v0.1.schema.json").validate(
            self.to_dict()
        )


@dataclass
class ResultObservationArtifact:
    """A non-adjudicating observation.

    Results NEVER close commitments. The ``references`` list is typed but
    carries no adjudicating meaning: only a terminal fulfillment can close
    a commitment.
    """

    result_id: str
    timestamp: str
    episode_id: str
    text: str
    evidence_uri: str
    policy_hash: str
    policy_resolver: Dict[str, Any]
    references: List[Dict[str, Any]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "result_observation"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # result.observed MUST NOT carry fulfills/closes semantics. Strip
        # defensively even though no field sources them.
        d.pop("fulfills", None)
        d.pop("closes", None)
        return d

    def validate(self) -> None:
        _get_validator("result_observation.v0.1.schema.json").validate(self.to_dict())


@dataclass
class FulfillmentKeptArtifact:
    """Terminal closure: a commitment was kept."""

    fulfillment_id: str
    timestamp: str
    episode_id: str
    commitment_id: str
    result_id: str
    evaluator: str
    evaluator_version: str
    policy_hash: str
    policy_resolver: Dict[str, Any]
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "fulfillment_commitment_kept"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_validator("fulfillment_commitment_kept.v0.1.schema.json").validate(
            self.to_dict()
        )


@dataclass
class FulfillmentBrokenArtifact:
    """Terminal closure: a commitment was broken."""

    fulfillment_id: str
    timestamp: str
    episode_id: str
    commitment_id: str
    result_id: str
    evaluator: str
    evaluator_version: str
    policy_hash: str
    policy_resolver: Dict[str, Any]
    violation_reason: str
    schema_version: str = SCHEMA_VERSION
    artifact_type: str = "fulfillment_commitment_broken"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        _get_validator("fulfillment_commitment_broken.v0.1.schema.json").validate(
            self.to_dict()
        )


# ---------------------------------------------------------------------------
# Store scanning helpers (full-store, uncapped)
# ---------------------------------------------------------------------------


def _iter_all_receipts(store: AssayStore) -> Iterator[Dict[str, Any]]:
    """Iterate all receipts in store-wide ``_store_seq`` order.

    ``_store_seq`` is the store's witnessed append order: the monotonic,
    immutable envelope field assigned by ``AssayStore.append`` /
    ``append_dict`` at write time. It is a STORAGE primitive — used for
    deterministic traversal, tie-breaking, and tamper detection. It is
    NOT a semantic global happens-before relation between unrelated
    aggregates; that is always a per-aggregate question.
    See ``docs/doctrine/COMMITMENT_ORDERING.md``.

    Lexicographic trace-path order is NOT a valid chronology because
    ``AssayStore.start_trace(trace_id=...)`` accepts arbitrary trace IDs.

    Fail-closed on every ambiguity: unreadable files, malformed JSON,
    missing ``_store_seq``, non-integer ``_store_seq``, duplicated
    ``_store_seq``, or a ``_store_seq`` that regresses within a single
    file (tampering detection). Any of these raise
    ``ReceiptStoreIntegrityError``. Receipt-backed invariants must never
    treat corruption or ambiguity as absence.

    Blank lines are tolerated (common append-only artifact).
    """
    base = store.base_dir
    if not base.exists():
        return

    entries: List[Tuple[int, Dict[str, Any]]] = []
    seen_seqs: Dict[int, str] = {}  # seq -> "file:line" witness of first occurrence

    for trace_file in sorted(base.rglob("trace_*.jsonl")):
        if not trace_file.is_file():
            continue
        try:
            handle = open(trace_file)
        except OSError as exc:
            raise ReceiptStoreIntegrityError(
                f"Cannot read trace file {trace_file}: {exc}"
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
                        f"Malformed JSON in {trace_file} line {line_number}: {exc}"
                    ) from exc
                seq = entry.get("_store_seq")
                if not isinstance(seq, int) or isinstance(seq, bool):
                    raise ReceiptStoreIntegrityError(
                        f"Missing or non-integer _store_seq in {trace_file} "
                        f"line {line_number}. Slice 1 requires every receipt "
                        "to carry a monotonic _store_seq stamped at write time."
                    )
                if seq in seen_seqs:
                    raise ReceiptStoreIntegrityError(
                        f"Duplicate _store_seq={seq} at {trace_file} line "
                        f"{line_number}; first seen at {seen_seqs[seq]}. "
                        "Store-local sequence must be unique."
                    )
                if seq <= last_seq_in_file:
                    raise ReceiptStoreIntegrityError(
                        f"Non-monotonic _store_seq in {trace_file} line "
                        f"{line_number}: {seq} <= previous {last_seq_in_file}. "
                        "Within-file sequence must strictly increase."
                    )
                seen_seqs[seq] = f"{trace_file}:{line_number}"
                last_seq_in_file = seq
                entries.append((seq, entry))

    entries.sort(key=lambda t: t[0])
    for _, entry in entries:
        yield entry


def _extract_receipt_type(entry: Dict[str, Any]) -> str:
    return str(entry.get("type") or entry.get("receipt_type") or "")


def _find_receipt_by_field(
    store: AssayStore,
    receipt_type: str,
    id_field: str,
    id_value: str,
) -> Optional[Dict[str, Any]]:
    """Return the first receipt in ``store`` matching both type and id field.

    Type-aware: a bare ``id_field`` match on some unrelated receipt type
    does not count. The scan is full-store (no cap).
    """
    for entry in _iter_all_receipts(store):
        if _extract_receipt_type(entry) != receipt_type:
            continue
        if entry.get(id_field) != id_value:
            continue
        return entry
    return None


def _assert_commitment_exists(store: AssayStore, commitment_id: str) -> None:
    """Raise UnanchoredFulfillmentError if commitment_id has no registration."""
    if _find_receipt_by_field(
        store,
        COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id",
        commitment_id,
    ) is None:
        raise UnanchoredFulfillmentError(
            f"Fulfillment references unknown commitment_id={commitment_id!r}. "
            f"No commitment.registered receipt with that id exists in the store. "
            "A terminal fulfillment must anchor to a prior registration."
        )


def _assert_result_anchors_commitment(
    store: AssayStore,
    *,
    result_id: str,
    commitment_id: str,
) -> None:
    """Raise UnanchoredFulfillmentError unless a result.observed edge exists.

    The edge the wedge requires: some ``result.observed`` receipt with
    ``result_id`` whose ``references`` list contains an explicit
    ``{"kind": "commitment", "id": commitment_id}`` entry.

    Bare ``result_id`` existence is not sufficient — a result observed for
    a different commitment must not adjudicate this one.
    """
    found_result_receipt = False
    for entry in _iter_all_receipts(store):
        if _extract_receipt_type(entry) != RESULT_OBSERVATION_RECEIPT_TYPE:
            continue
        if entry.get("result_id") != result_id:
            continue
        found_result_receipt = True
        for ref in entry.get("references") or []:
            if (
                isinstance(ref, dict)
                and ref.get("kind") == "commitment"
                and ref.get("id") == commitment_id
            ):
                return  # edge exists: (result_id, commitment_id)
    if not found_result_receipt:
        raise UnanchoredFulfillmentError(
            f"Fulfillment references unknown result_id={result_id!r}. "
            f"No result.observed receipt with that id exists in the store. "
            "A terminal fulfillment must cite a prior observation that "
            "references its commitment."
        )
    raise UnanchoredFulfillmentError(
        f"result_id={result_id!r} exists but does not reference "
        f"commitment_id={commitment_id!r}. "
        "A terminal fulfillment must cite an observation whose "
        "references list includes the commitment it closes."
    )


def _assert_no_existing_terminal(store: AssayStore, commitment_id: str) -> None:
    """Scan the entire store for a prior terminal fulfillment of this commitment.

    Full-store scan, no cap. Raises TerminalFulfillmentError if one is found.
    """
    for entry in _iter_all_receipts(store):
        entry_type = _extract_receipt_type(entry)
        if entry_type not in TERMINAL_FULFILLMENT_TYPES:
            continue
        if entry.get("commitment_id") != commitment_id:
            continue
        raise TerminalFulfillmentError(
            f"Commitment {commitment_id!r} already has a terminal fulfillment: "
            f"type={entry_type!r} "
            f"fulfillment_id={entry.get('fulfillment_id')!r}. "
            "A commitment has zero or one terminal fulfillment."
        )


# ---------------------------------------------------------------------------
# Policy-binding verification
# ---------------------------------------------------------------------------


def _verify_policy_binding(artifact: Any) -> None:
    """Verify an artifact's policy_hash is backed by a resolvable policy.

    Checks:
        1. The artifact's embedded ``policy_resolver.policy_hash`` equals
           the artifact's top-level ``policy_hash``.
        2. Resolving the PolicyResolver yields a COMPILE_RECEIPT whose
           own ``policy_hash`` equals the expected hash.

    Applied uniformly to every Slice 1 receipt. Closure records (result +
    fulfillment) must clear the same bar as registration.
    """
    resolver_dict = artifact.policy_resolver
    if not isinstance(resolver_dict, dict):
        raise PolicyResolutionError(
            "Artifact.policy_resolver must be a dict with keys "
            "{'kind','ref','policy_hash'}."
        )
    embedded_hash = resolver_dict.get("policy_hash")
    if embedded_hash != artifact.policy_hash:
        raise PolicyResolutionError(
            f"Artifact policy_hash={artifact.policy_hash!r} does not match "
            f"embedded policy_resolver.policy_hash={embedded_hash!r}. "
            "Receipt refused."
        )
    try:
        resolver = PolicyResolver(
            kind=resolver_dict["kind"],
            ref=resolver_dict["ref"],
            policy_hash=resolver_dict["policy_hash"],
        )
    except KeyError as exc:
        raise PolicyResolutionError(
            f"Artifact.policy_resolver missing required key: {exc}"
        ) from exc
    resolve_policy(resolver)


# ---------------------------------------------------------------------------
# Emit functions
# ---------------------------------------------------------------------------


def emit_commitment_registration(
    episode: Episode,
    commitment: Union[CommitmentRegistrationArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> CommitmentRegistrationArtifact:
    """Emit a commitment.registered receipt after verifying the policy binding.

    Raises:
        PolicyResolutionError: If the embedded resolver cannot resolve, or
            the artifact's top-level ``policy_hash`` does not match both
            the embedded resolver hash and the resolved COMPILE_RECEIPT.
    """
    artifact = (
        commitment
        if isinstance(commitment, CommitmentRegistrationArtifact)
        else CommitmentRegistrationArtifact(**commitment)
    )
    _verify_policy_binding(artifact)
    artifact.validate()
    episode.emit(
        COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_result_observation(
    episode: Episode,
    result: Union[ResultObservationArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> ResultObservationArtifact:
    """Emit a result.observed receipt.

    Non-adjudicating: never closes a commitment. Terminal closure is the
    exclusive job of fulfillment.commitment_kept | commitment_broken.

    Raises:
        PolicyResolutionError: If the embedded resolver cannot resolve, or
            policy_hash bindings are inconsistent.
    """
    artifact = (
        result
        if isinstance(result, ResultObservationArtifact)
        else ResultObservationArtifact(**result)
    )
    _verify_policy_binding(artifact)
    artifact.validate()
    episode.emit(
        RESULT_OBSERVATION_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_fulfillment_kept(
    episode: Episode,
    fulfillment: Union[FulfillmentKeptArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> FulfillmentKeptArtifact:
    """Emit a fulfillment.commitment_kept receipt.

    Guards four invariants before writing:
        1. Policy binding is consistent and resolvable.
        2. The referenced commitment exists as a commitment.registered receipt.
        3. The referenced result exists as a result.observed receipt.
        4. No prior terminal fulfillment names this commitment
           (zero-or-one terminal invariant).

    Raises:
        PolicyResolutionError: On any policy-binding defect.
        UnanchoredFulfillmentError: If commitment or result referents are
            not present in the store.
        TerminalFulfillmentError: If a prior terminal already closes this
            commitment.
    """
    artifact = (
        fulfillment
        if isinstance(fulfillment, FulfillmentKeptArtifact)
        else FulfillmentKeptArtifact(**fulfillment)
    )
    store = episode._store
    _verify_policy_binding(artifact)
    _assert_commitment_exists(store, artifact.commitment_id)
    _assert_result_anchors_commitment(
        store,
        result_id=artifact.result_id,
        commitment_id=artifact.commitment_id,
    )
    _assert_no_existing_terminal(store, artifact.commitment_id)
    artifact.validate()
    episode.emit(
        FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


def emit_fulfillment_broken(
    episode: Episode,
    fulfillment: Union[FulfillmentBrokenArtifact, Dict[str, Any]],
    *,
    parent_receipt_id: Optional[str] = None,
) -> FulfillmentBrokenArtifact:
    """Emit a fulfillment.commitment_broken receipt.

    Same four invariants as ``emit_fulfillment_kept``.

    Raises:
        PolicyResolutionError, UnanchoredFulfillmentError, TerminalFulfillmentError
    """
    artifact = (
        fulfillment
        if isinstance(fulfillment, FulfillmentBrokenArtifact)
        else FulfillmentBrokenArtifact(**fulfillment)
    )
    store = episode._store
    _verify_policy_binding(artifact)
    _assert_commitment_exists(store, artifact.commitment_id)
    _assert_result_anchors_commitment(
        store,
        result_id=artifact.result_id,
        commitment_id=artifact.commitment_id,
    )
    _assert_no_existing_terminal(store, artifact.commitment_id)
    artifact.validate()
    episode.emit(
        FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
        artifact.to_dict(),
        parent_receipt_id=parent_receipt_id,
    )
    return artifact


__all__ = [
    "SCHEMA_VERSION",
    "COMMITMENT_REGISTRATION_RECEIPT_TYPE",
    "RESULT_OBSERVATION_RECEIPT_TYPE",
    "FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE",
    "FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE",
    "TERMINAL_FULFILLMENT_TYPES",
    "TerminalFulfillmentError",
    "UnanchoredFulfillmentError",
    "ReceiptStoreIntegrityError",
    "CommitmentRegistrationArtifact",
    "ResultObservationArtifact",
    "FulfillmentKeptArtifact",
    "FulfillmentBrokenArtifact",
    "emit_commitment_registration",
    "emit_result_observation",
    "emit_fulfillment_kept",
    "emit_fulfillment_broken",
]
