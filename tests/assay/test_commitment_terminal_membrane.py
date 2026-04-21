"""Commitment terminal-state membrane tests.

Makes revoked, amended, and superseded commitments machine-visible
terminal state, not prose notes, so ``list`` and ``overdue`` remain
honest.

Doctrine sentence:
    "Kept, broken, revoked, amended, and superseded may all end a
    commitment's active life, but only kept/broken are fulfillment
    outcomes."

Implementation invariant:
    "If it changes list or overdue, it must be state, not commentary."

Grammar preservation note:
    This module keeps the existing commitment/fulfillment vocabulary
    exactly: ``fulfillment.commitment_kept`` and
    ``fulfillment.commitment_broken`` remain unchanged. A new
    ``commitment.terminated`` event covers non-fulfillment endings
    (revoked | superseded | amended). No "verified" or "breached"
    vocabulary is introduced.
"""
from __future__ import annotations

import json
import pytest

from assay.commitment_closure_detector import detect_open_overdue_commitments
from assay.commitment_fulfillment import (
    ACCEPTED_AUTHORITY_MODES,
    AUTHORITY_MODES,
    AuthorityModeUnsupportedError,
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    COMMITMENT_TERMINATED_RECEIPT_TYPE,
    CommitmentTerminatedArtifact,
    FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    PROBE_SCOPED_ALLOWED_EVENT_TYPES,
    PROBE_SCOPED_RECEIPT_TYPE,
    ProbeScopedArtifact,
    RESULT_OBSERVATION_RECEIPT_TYPE,
    TerminalFulfillmentError,
    UnanchoredFulfillmentError,
    derive_commitment_id,
    derive_idempotency_key,
    emit_commitment_terminated,
    emit_probe_scoped,
    normalize_first_authored_text,
)
from assay.commitment_projection import project_commitment_lifecycle
from assay.commitment_summary import summarize_all_commitments
from assay.episode import Episode
from assay.store import AssayStore


POLICY_HASH = "sha256:" + "c" * 64


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path):
    store = AssayStore(base_dir=tmp_path / "store")
    store.start_trace()
    return store


def _write_registered(
    store,
    commitment_id,
    *,
    actor_id="alice",
    due_at="2020-01-01T00:00:00Z",
    text=None,
    supersedes_commitment_id=None,
    lineage_root_commitment_id=None,
):
    """Register a commitment via direct append.

    Uses a deep-past due_at by default so overdue-filter tests work.
    """
    data = {
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": commitment_id,
        "episode_id": "ep_test",
        "actor_id": actor_id,
        "text": text or f"Commitment {commitment_id}.",
        "commitment_type": "delivery",
        "policy_hash": POLICY_HASH,
        "timestamp": "2026-04-20T10:00:00.000Z",
    }
    if due_at is not None:
        data["due_at"] = due_at
    if supersedes_commitment_id is not None:
        data["supersedes_commitment_id"] = supersedes_commitment_id
    if lineage_root_commitment_id is not None:
        data["lineage_root_commitment_id"] = lineage_root_commitment_id
    store.append_dict(data)


def _write_result(store, result_id, references=None):
    store.append_dict({
        "type": RESULT_OBSERVATION_RECEIPT_TYPE,
        "result_id": result_id,
        "episode_id": "ep_test",
        "text": f"Observed {result_id}.",
        "evidence_uri": "file:///tmp/evidence.log",
        "policy_hash": POLICY_HASH,
        "references": references or [],
        "timestamp": "2026-04-20T11:00:00.000Z",
    })


def _write_kept(store, commitment_id, result_id):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": f"ful_kept_{commitment_id}",
        "episode_id": "ep_test",
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": POLICY_HASH,
        "timestamp": "2026-04-20T12:00:00.000Z",
    })


def _write_broken(store, commitment_id, result_id, reason="violated"):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
        "fulfillment_id": f"ful_broken_{commitment_id}",
        "episode_id": "ep_test",
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": POLICY_HASH,
        "violation_reason": reason,
        "timestamp": "2026-04-20T12:00:00.000Z",
    })


def _make_terminated_artifact(
    commitment_id,
    *,
    terminal_reason="revoked",
    amended_field=None,
    authority_mode="self",
    idempotency_key=None,
    replacement_commitment_id=None,
    supersedes_commitment_id=None,
    lineage_root_commitment_id=None,
    terminated_by_actor="alice",
):
    return CommitmentTerminatedArtifact(
        commitment_id=commitment_id,
        timestamp="2026-04-20T13:00:00.000Z",
        terminated_at="2026-04-20T13:00:00.000Z",
        terminated_by_actor=terminated_by_actor,
        terminal_reason=terminal_reason,
        amended_field=amended_field,
        authority_mode=authority_mode,
        idempotency_key=idempotency_key or f"idem_{commitment_id}_{terminal_reason}",
        replacement_commitment_id=replacement_commitment_id,
        supersedes_commitment_id=supersedes_commitment_id,
        lineage_root_commitment_id=lineage_root_commitment_id,
    )


def _write_terminated(
    store,
    commitment_id,
    *,
    terminal_reason="revoked",
    amended_field=None,
    authority_mode="self",
    idempotency_key=None,
    replacement_commitment_id=None,
    supersedes_commitment_id=None,
    lineage_root_commitment_id=None,
):
    """Direct write of a commitment.terminated receipt (bypasses emit guards).

    Use sparingly — ``emit_commitment_terminated`` is the authorized path.
    """
    data = {
        "type": COMMITMENT_TERMINATED_RECEIPT_TYPE,
        "commitment_id": commitment_id,
        "episode_id": "ep_test",
        "timestamp": "2026-04-20T13:00:00.000Z",
        "terminated_at": "2026-04-20T13:00:00.000Z",
        "terminated_by_actor": "alice",
        "terminal_reason": terminal_reason,
        "authority_mode": authority_mode,
        "idempotency_key": (
            idempotency_key or f"idem_{commitment_id}_{terminal_reason}"
        ),
    }
    if amended_field is not None:
        data["amended_field"] = amended_field
    if replacement_commitment_id is not None:
        data["replacement_commitment_id"] = replacement_commitment_id
    if supersedes_commitment_id is not None:
        data["supersedes_commitment_id"] = supersedes_commitment_id
    if lineage_root_commitment_id is not None:
        data["lineage_root_commitment_id"] = lineage_root_commitment_id
    store.append_dict(data)


# ---------------------------------------------------------------------------
# Tests 1–8: the projection-level membrane invariants
# ---------------------------------------------------------------------------


def test_01_revoked_disappears_from_active_list(tmp_store):
    """Test 1: Revoked commitment disappears from active list.

    The active subset is state == OPEN; a revoked commitment must show
    state == TERMINATED with terminal_reason == "revoked", and MUST NOT
    appear in the OPEN subset.
    """
    _write_registered(tmp_store, "cmt_rev")
    _write_terminated(tmp_store, "cmt_rev", terminal_reason="revoked")

    result = summarize_all_commitments(tmp_store)
    assert len(result.commitments) == 1
    s = result.commitments[0]

    assert s.commitment_id == "cmt_rev"
    assert s.state == "TERMINATED"
    assert s.terminal_reason == "revoked"
    # Active list = OPEN subset. Revoked must be excluded.
    active = [c for c in result.commitments if c.state == "OPEN"]
    assert active == []


def test_02_revoked_not_overdue(tmp_store):
    """Test 2: Revoked commitment does not appear as overdue."""
    _write_registered(tmp_store, "cmt_rev", due_at="2020-01-01T00:00:00Z")
    _write_terminated(tmp_store, "cmt_rev", terminal_reason="revoked")

    detector = detect_open_overdue_commitments(tmp_store)
    assert detector.total_open_found == 0
    assert detector.clean
    assert all(c.commitment_id != "cmt_rev" for c in detector.open_commitments)

    # Summary path parity: is_overdue is False for TERMINATED.
    summary = summarize_all_commitments(tmp_store)
    assert summary.commitments[0].is_overdue is False


def test_03_superseded_disappears_from_active_list(tmp_store):
    """Test 3: Superseded commitment disappears from active list.

    The replacement is registered separately and remains active; the
    original enters TERMINATED state with terminal_reason == "superseded".
    """
    _write_registered(tmp_store, "cmt_old")
    _write_terminated(
        tmp_store,
        "cmt_old",
        terminal_reason="superseded",
        replacement_commitment_id="cmt_new",
    )
    _write_registered(
        tmp_store,
        "cmt_new",
        supersedes_commitment_id="cmt_old",
    )

    result = summarize_all_commitments(tmp_store)
    by_id = {c.commitment_id: c for c in result.commitments}

    assert by_id["cmt_old"].state == "TERMINATED"
    assert by_id["cmt_old"].terminal_reason == "superseded"
    assert by_id["cmt_new"].state == "OPEN"

    # Active list excludes cmt_old.
    active_ids = {c.commitment_id for c in result.commitments if c.state == "OPEN"}
    assert active_ids == {"cmt_new"}


def test_04_replacement_remains_active_if_not_terminal(tmp_store):
    """Test 4: Replacement commitment remains active if not terminal."""
    _write_registered(tmp_store, "cmt_old")
    _write_terminated(
        tmp_store,
        "cmt_old",
        terminal_reason="amended",
        amended_field="due_at",
        replacement_commitment_id="cmt_new",
    )
    _write_registered(
        tmp_store,
        "cmt_new",
        supersedes_commitment_id="cmt_old",
    )

    result = summarize_all_commitments(tmp_store)
    by_id = {c.commitment_id: c for c in result.commitments}

    # cmt_new is not terminal — neither closed nor terminated — so OPEN.
    assert by_id["cmt_new"].state == "OPEN"
    # The replacement is not itself terminal; termination_seq is None.
    assert by_id["cmt_new"].termination_seq is None
    assert by_id["cmt_new"].closing_terminal_seq is None


def test_05_amended_original_disappears_from_active_list(tmp_store):
    """Test 5: Amended original disappears from active list."""
    _write_registered(tmp_store, "cmt_orig", due_at="2020-01-01T00:00:00Z")
    _write_terminated(
        tmp_store,
        "cmt_orig",
        terminal_reason="amended",
        amended_field="due_at",
        replacement_commitment_id="cmt_orig_v2",
    )
    _write_registered(
        tmp_store,
        "cmt_orig_v2",
        due_at="2099-01-01T00:00:00Z",
        supersedes_commitment_id="cmt_orig",
    )

    result = summarize_all_commitments(tmp_store)
    by_id = {c.commitment_id: c for c in result.commitments}

    # Original is terminated (amended), not active.
    assert by_id["cmt_orig"].state == "TERMINATED"
    assert by_id["cmt_orig"].terminal_reason == "amended"
    # Original is NOT overdue despite its past due_at, because TERMINATED.
    assert by_id["cmt_orig"].is_overdue is False
    # Replacement is active.
    assert by_id["cmt_orig_v2"].state == "OPEN"

    active_ids = {c.commitment_id for c in result.commitments if c.state == "OPEN"}
    assert active_ids == {"cmt_orig_v2"}


def test_06_amended_replacement_carries_supersedes_commitment_id(tmp_store):
    """Test 6: Amended replacement carries supersedes_commitment_id.

    The projection exposes the supersession edge; the replacement's
    registered receipt declares it.
    """
    _write_registered(tmp_store, "cmt_orig")
    _write_terminated(
        tmp_store,
        "cmt_orig",
        terminal_reason="amended",
        amended_field="scope",
        replacement_commitment_id="cmt_orig_v2",
    )
    _write_registered(
        tmp_store,
        "cmt_orig_v2",
        supersedes_commitment_id="cmt_orig",
        lineage_root_commitment_id="cmt_orig",
    )

    projection = project_commitment_lifecycle(tmp_store)
    edges = projection.supersession_edges
    assert len(edges) >= 1

    edge = next(e for e in edges if e.predecessor_commitment_id == "cmt_orig")
    assert edge.successor_commitment_id == "cmt_orig_v2"
    # Either the registration or the termination may have declared the
    # edge; lineage_root appears on at least one side. Assert the root
    # is reachable somewhere in the projection's edge set.
    roots = {e.lineage_root_commitment_id for e in edges}
    assert "cmt_orig" in roots


def test_07_kept_remains_fulfillment_not_terminated(tmp_store):
    """Test 7: Kept / fulfillment.commitment_kept remains fulfillment, not
    commitment.terminated.

    Grammar preservation: kept is a fulfillment outcome, NOT a
    termination. State is CLOSED, closing_terminal_type is
    ``fulfillment.commitment_kept``, and the commitment does NOT show up
    in projection.terminations.
    """
    _write_registered(tmp_store, "cmt_k")
    _write_result(
        tmp_store,
        "res_k",
        references=[{"kind": "commitment", "id": "cmt_k"}],
    )
    _write_kept(tmp_store, "cmt_k", "res_k")

    result = summarize_all_commitments(tmp_store)
    s = result.commitments[0]
    assert s.state == "CLOSED"
    assert s.closing_terminal_type == FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE
    assert s.terminal_reason is None
    assert s.termination_seq is None

    projection = project_commitment_lifecycle(tmp_store)
    assert "cmt_k" in projection.closures
    assert "cmt_k" not in projection.terminations


def test_08_broken_remains_fulfillment_not_terminated(tmp_store):
    """Test 8: Broken / fulfillment.commitment_broken remains fulfillment
    outcome, not commitment.terminated.

    Same grammar invariant as kept: broken is a fulfillment outcome, not
    a termination. State is CLOSED with closing_terminal_type =
    ``fulfillment.commitment_broken``.
    """
    _write_registered(tmp_store, "cmt_b")
    _write_result(
        tmp_store,
        "res_b",
        references=[{"kind": "commitment", "id": "cmt_b"}],
    )
    _write_broken(tmp_store, "cmt_b", "res_b")

    result = summarize_all_commitments(tmp_store)
    s = result.commitments[0]
    assert s.state == "CLOSED"
    assert s.closing_terminal_type == FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE
    assert s.terminal_reason is None
    assert s.termination_seq is None

    projection = project_commitment_lifecycle(tmp_store)
    assert "cmt_b" in projection.closures
    assert "cmt_b" not in projection.terminations


# ---------------------------------------------------------------------------
# Tests 9–11: the emit-path guards
# ---------------------------------------------------------------------------


def test_09_replay_same_idempotency_key_is_noop(tmp_store):
    """Test 9: Replaying same idempotency_key is a no-op.

    Two calls to ``emit_commitment_terminated`` with the same
    commitment_id AND same idempotency_key produce exactly one on-disk
    event. The second call returns ``(artifact, wrote_event=False)``.
    """
    _write_registered(tmp_store, "cmt_idem")
    episode = Episode(store=tmp_store, episode_id="ep_idem")

    artifact = _make_terminated_artifact(
        "cmt_idem",
        terminal_reason="revoked",
        idempotency_key="idem_once",
    )

    _, wrote1 = emit_commitment_terminated(episode, artifact)
    assert wrote1 is True

    # Replay with the same idempotency_key.
    _, wrote2 = emit_commitment_terminated(episode, artifact)
    assert wrote2 is False

    # Exactly one on-disk terminated event for this commitment.
    projection = project_commitment_lifecycle(tmp_store)
    termination_events = [
        t for t in projection.terminations.values()
        if t.commitment_id == "cmt_idem"
    ]
    assert len(termination_events) == 1

    raw_events = [
        e for e in _iter_terminated_events(tmp_store)
        if e["commitment_id"] == "cmt_idem"
    ]
    assert len(raw_events) == 1


def test_10_different_idempotency_key_on_terminated_raises(tmp_store):
    """Test 10: Different idempotency_key attempting to terminate an
    already-terminal commitment_id raises validation error at emission;
    no event is written.
    """
    _write_registered(tmp_store, "cmt_conflict")
    episode = Episode(store=tmp_store, episode_id="ep_conflict")

    first = _make_terminated_artifact(
        "cmt_conflict",
        terminal_reason="revoked",
        idempotency_key="idem_first",
    )
    emit_commitment_terminated(episode, first)

    # Count events before the conflicting call.
    before = [
        e for e in _iter_terminated_events(tmp_store)
        if e["commitment_id"] == "cmt_conflict"
    ]
    assert len(before) == 1

    conflict = _make_terminated_artifact(
        "cmt_conflict",
        terminal_reason="superseded",
        idempotency_key="idem_second",
        replacement_commitment_id="cmt_replace",
    )
    with pytest.raises(TerminalFulfillmentError):
        emit_commitment_terminated(episode, conflict)

    # No new event written.
    after = [
        e for e in _iter_terminated_events(tmp_store)
        if e["commitment_id"] == "cmt_conflict"
    ]
    assert len(after) == 1
    # First event is still the one on disk.
    assert after[0]["idempotency_key"] == "idem_first"
    assert after[0]["terminal_reason"] == "revoked"


def test_10b_terminate_unregistered_commitment_rejected_no_event(tmp_store):
    """Unregistered commitments cannot be terminated."""
    episode = Episode(store=tmp_store, episode_id="ep_missing")
    artifact = _make_terminated_artifact(
        "cmt_missing",
        terminal_reason="revoked",
        idempotency_key="idem_missing",
    )

    with pytest.raises(UnanchoredFulfillmentError):
        emit_commitment_terminated(episode, artifact)

    assert list(_iter_terminated_events(tmp_store)) == []


def test_10c_amended_requires_replacement_commitment_id(tmp_store):
    """Amendment must terminate only via replacement registration."""
    _write_registered(tmp_store, "cmt_amend")
    episode = Episode(store=tmp_store, episode_id="ep_amend")
    artifact = _make_terminated_artifact(
        "cmt_amend",
        terminal_reason="amended",
        amended_field="due_at",
        idempotency_key="idem_amend",
        replacement_commitment_id=None,
    )

    with pytest.raises(ValueError, match="replacement_commitment_id"):
        emit_commitment_terminated(episode, artifact)

    assert list(_iter_terminated_events(tmp_store)) == []


def test_11_non_self_authority_mode_rejected_no_event(tmp_store):
    """Test 11: authority_mode values other than ``self`` are rejected at
    validation time with explicit "not supported in current probe"
    diagnostic; no event is written.
    """
    _write_registered(tmp_store, "cmt_auth")
    episode = Episode(store=tmp_store, episode_id="ep_auth")

    # Every non-``self`` value is schema-valid but rejected at emission.
    non_self_modes = AUTHORITY_MODES - ACCEPTED_AUTHORITY_MODES
    assert non_self_modes == {"owner", "policy", "external"}

    for mode in non_self_modes:
        artifact = _make_terminated_artifact(
            "cmt_auth",
            terminal_reason="revoked",
            authority_mode=mode,
            idempotency_key=f"idem_{mode}",
        )
        with pytest.raises(AuthorityModeUnsupportedError) as exc_info:
            emit_commitment_terminated(episode, artifact)
        assert "not supported in the current probe" in str(exc_info.value)

    # Invalid (non-enum) authority_mode fails schema validation BEFORE
    # emission; nothing is written.
    from jsonschema import ValidationError as _SchemaValidationError

    bad_artifact = _make_terminated_artifact(
        "cmt_auth",
        terminal_reason="revoked",
        authority_mode="god_mode",  # not in the schema enum
        idempotency_key="idem_bad",
    )
    with pytest.raises(_SchemaValidationError):
        emit_commitment_terminated(episode, bad_artifact)

    # No commitment.terminated for this commitment on disk.
    events = [
        e for e in _iter_terminated_events(tmp_store)
        if e["commitment_id"] == "cmt_auth"
    ]
    assert events == []


# ---------------------------------------------------------------------------
# Tests 12–13: supersession edges + probe.scoped
# ---------------------------------------------------------------------------


def test_12_projection_exposes_immediate_supersession_edge(tmp_store):
    """Test 12: Projection reconstructs or exposes immediate supersession
    edge without requiring full-chain duplication.

    Three-step chain A -> B -> C. Each edge is stored only as an
    immediate edge; the projection does NOT duplicate the full chain
    onto each event. Consumers reconstruct chains from edges when
    needed.
    """
    _write_registered(tmp_store, "cmt_A")
    _write_terminated(
        tmp_store,
        "cmt_A",
        terminal_reason="amended",
        amended_field="scope",
        replacement_commitment_id="cmt_B",
    )
    _write_registered(
        tmp_store,
        "cmt_B",
        supersedes_commitment_id="cmt_A",
        lineage_root_commitment_id="cmt_A",
    )
    _write_terminated(
        tmp_store,
        "cmt_B",
        terminal_reason="amended",
        amended_field="scope",
        replacement_commitment_id="cmt_C",
    )
    _write_registered(
        tmp_store,
        "cmt_C",
        supersedes_commitment_id="cmt_B",
        lineage_root_commitment_id="cmt_A",
    )

    projection = project_commitment_lifecycle(tmp_store)

    # Every stored edge is a single predecessor->successor hop. No edge
    # stores the full chain on its body.
    predecessors = {e.predecessor_commitment_id for e in projection.supersession_edges}
    successors = {e.successor_commitment_id for e in projection.supersession_edges}
    assert {"cmt_A", "cmt_B"} <= predecessors
    assert {"cmt_B", "cmt_C"} <= successors

    # Chain reconstruction from the edge set (no full-chain duplication
    # on any single event).
    pred_to_succ = {
        e.predecessor_commitment_id: e.successor_commitment_id
        for e in projection.supersession_edges
    }
    chain = ["cmt_A"]
    node = "cmt_A"
    while node in pred_to_succ:
        node = pred_to_succ[node]
        chain.append(node)
        if len(chain) > 10:
            break  # guard against cycles
    assert chain == ["cmt_A", "cmt_B", "cmt_C"]

    # Each termination records at most its immediate replacement.
    for cmt in ("cmt_A", "cmt_B"):
        term = projection.terminations[cmt]
        assert term.replacement_commitment_id in {"cmt_B", "cmt_C"}
        # No chain fields like "successor_chain" or "lineage_chain".
        assert not hasattr(term, "successor_chain")
        assert not hasattr(term, "lineage_chain")


def test_13_probe_scoped_validates_allowed_events_and_scope(tmp_store):
    """Test 13: probe.scoped receipt validates allowed event types and scope.

    Emit a probe.scoped receipt and confirm its shape.
    """
    episode = Episode(store=tmp_store, episode_id="ep_probe")
    artifact = ProbeScopedArtifact(
        probe_name="claude-organism-second-emitter",
        scope="self-authored-only",
        owner_equals_author=True,
        delegation_allowed=False,
        external_ingestion_allowed=False,
        allowed_event_types=[
            COMMITMENT_REGISTRATION_RECEIPT_TYPE,
            COMMITMENT_TERMINATED_RECEIPT_TYPE,
            FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
            FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
        ],
        membrane_version="0.1.0",
        code_commit="cb06d0f9c3d04d29fbc3cdb7326f1424c0b82d87",
        emitted_at="2026-04-20T13:30:00.000Z",
    )

    emit_probe_scoped(episode, artifact)

    # Read the probe.scoped event back from the store and assert its
    # fields match. Scope is the declared boundary; allowed_event_types
    # is the whitelist the probe promises not to exceed.
    events = [
        e for e in _iter_all_events(tmp_store)
        if e.get("type") == PROBE_SCOPED_RECEIPT_TYPE
    ]
    assert len(events) == 1
    event = events[0]

    assert event["probe_name"] == "claude-organism-second-emitter"
    assert event["scope"] == "self-authored-only"
    assert event["owner_equals_author"] is True
    assert event["delegation_allowed"] is False
    assert event["external_ingestion_allowed"] is False
    assert set(event["allowed_event_types"]) == PROBE_SCOPED_ALLOWED_EVENT_TYPES

    # The probe does NOT claim result.observed in its allowed types.
    # That is intentional — this membrane PR does not wire result
    # emission through the claude-organism probe.
    assert RESULT_OBSERVATION_RECEIPT_TYPE not in event["allowed_event_types"]

    # Schema-invalid probe.scoped is rejected (empty allowed_event_types
    # is a schema violation).
    from jsonschema import ValidationError as _SchemaValidationError

    bad = ProbeScopedArtifact(
        probe_name="bad",
        scope="self-authored-only",
        owner_equals_author=True,
        delegation_allowed=False,
        external_ingestion_allowed=False,
        allowed_event_types=[],  # violates minItems=1
        membrane_version="0.1.0",
        code_commit="cb06d0f",
        emitted_at="2026-04-20T13:30:00.000Z",
    )
    with pytest.raises(_SchemaValidationError):
        bad.validate()

    wrong_allowed = ProbeScopedArtifact(
        probe_name="wrong-allowed",
        scope="self-authored-only",
        owner_equals_author=True,
        delegation_allowed=False,
        external_ingestion_allowed=False,
        allowed_event_types=[
            COMMITMENT_REGISTRATION_RECEIPT_TYPE,
            COMMITMENT_TERMINATED_RECEIPT_TYPE,
            FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
            RESULT_OBSERVATION_RECEIPT_TYPE,
        ],
        membrane_version="0.1.0",
        code_commit="cb06d0f",
        emitted_at="2026-04-20T13:30:00.000Z",
    )
    with pytest.raises(_SchemaValidationError):
        wrong_allowed.validate()


# ---------------------------------------------------------------------------
# Secondary coverage: identity derivation + normalization
# ---------------------------------------------------------------------------


class TestIdentityDerivation:
    """Normalization rule + derivations (membrane note contract)."""

    def test_normalize_nfc(self):
        # é as decomposed vs composed; NFC collapses to composed.
        decomposed = "café"
        composed = "café"
        assert decomposed != composed
        assert normalize_first_authored_text(decomposed) == composed

    def test_normalize_trim_and_collapse_whitespace(self):
        raw = "   hello    world \t\n there   "
        assert normalize_first_authored_text(raw) == "hello world there"

    def test_normalize_preserves_case(self):
        assert normalize_first_authored_text("Foo Bar") == "Foo Bar"
        assert normalize_first_authored_text("FOO") != "foo"

    def test_derive_commitment_id_is_stable_and_depends_on_all_fields(self):
        base = dict(
            emitter_namespace="claude-organism",
            actor="alice",
            plan_slot_key="slot_A",
            first_authored_text="Ship the report by Friday.",
        )
        id1 = derive_commitment_id(**base)
        id2 = derive_commitment_id(**base)
        assert id1 == id2
        assert id1.startswith("cmt_")
        # Whitespace-different text normalizes to the same id.
        id_w = derive_commitment_id(
            **{**base, "first_authored_text": "  Ship   the report by Friday.  "}
        )
        assert id_w == id1
        # Case-different text → different id (case is preserved).
        id_c = derive_commitment_id(
            **{**base, "first_authored_text": "ship the report by friday."}
        )
        assert id_c != id1
        # Different actor → different id.
        id_a = derive_commitment_id(**{**base, "actor": "bob"})
        assert id_a != id1

    def test_derive_idempotency_key_stable(self):
        base = dict(
            emitter_namespace="claude-organism",
            operation_id="op_42",
            commitment_id="cmt_abc",
            event_type=COMMITMENT_TERMINATED_RECEIPT_TYPE,
        )
        k1 = derive_idempotency_key(**base)
        k2 = derive_idempotency_key(**base)
        assert k1 == k2
        assert k1.startswith("idem_")
        k3 = derive_idempotency_key(**{**base, "operation_id": "op_43"})
        assert k3 != k1


# ---------------------------------------------------------------------------
# Small iteration helpers (kept local — do not export)
# ---------------------------------------------------------------------------


def _iter_all_events(store):
    """Iterate every receipt on disk (across all trace files)."""
    for trace_file in sorted(store.base_dir.rglob("trace_*.jsonl")):
        if not trace_file.is_file():
            continue
        with open(trace_file) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def _iter_terminated_events(store):
    """Iterate commitment.terminated events from disk."""
    for entry in _iter_all_events(store):
        if entry.get("type") == COMMITMENT_TERMINATED_RECEIPT_TYPE:
            yield entry
