"""Property-based regression for the terminal-uniqueness invariant.

The target invariant:

    For any sequence of valid-looking receipt writes around a single
    commitment, the detector/explainer layer identifies AT MOST ONE
    valid closure for that commitment.

This is the class of bug Slice 1's review rounds kept surfacing by
inspection: invariants implicitly encoded but not locked against
sequence-space exploration. A property test closes the loop by
generating *many* sequences and asserting the invariant holds.

Scope note (Slice 1 vs Slice 2):

    reader may observe: multiple terminal receipts exist in the store
    semantic closure must decide: only one valid closure counts
    writer will enforce: no second valid terminal can be appended

This test is about the *semantic closure* (reader) layer. It
deliberately uses direct ``store.append_dict`` writes to explore the
full state space of on-disk evidence, even cases the emit-path writer
would refuse. That lets the test verify the reader's judgment is
robust regardless of how the on-disk evidence arrived — which is what
"semantic closure" means: the reader must be right even if the writer
is imperfect or bypassed.

Strategy design:

    We sample small finite pools of commitment_ids and result_ids so
    Hypothesis can meaningfully collide references. Events are one of:
        - register commitment
        - observe result (with a random subset of commitment refs)
        - fulfill kept (commitment_id, result_id)
        - fulfill broken (commitment_id, result_id)
    Ordering matters: events are applied in generation order, so
    ``_store_seq`` chronology reflects that.

    Sequences are bounded (max 20 events, 3 commitment_ids, 4
    result_ids) to keep the search space tractable and the fail
    messages debuggable.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from assay.commitment_closure_detector import detect_open_overdue_commitments
from assay.commitment_explain import explain_commitment
from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
)
from assay.store import AssayStore

# -- Finite pools. Small so Hypothesis can produce meaningful collisions. ---

COMMITMENT_POOL = ["cmt_A", "cmt_B", "cmt_C"]
RESULT_POOL = ["res_1", "res_2", "res_3", "res_4"]
TERMINAL_KIND_POOL = ["kept", "broken"]


# --- Atomic event strategies. ------------------------------------------------

# "register": declare a commitment. The actual commitment_id is chosen from
# the pool; duplicates are allowed — the store accepts them, and the reader
# must correctly handle (first-seen wins).
register_strategy = st.tuples(
    st.just("register"),
    st.sampled_from(COMMITMENT_POOL),
)

# "observe": record a result, referencing an arbitrary subset of commitments.
# An empty ref set is allowed (a result that doesn't anchor anything) — the
# reader must not confuse this with a closing anchor.
observe_strategy = st.tuples(
    st.just("observe"),
    st.sampled_from(RESULT_POOL),
    st.lists(
        st.sampled_from(COMMITMENT_POOL),
        min_size=0,
        max_size=len(COMMITMENT_POOL),
        unique=True,
    ),
)

# "terminal": fulfillment.commitment_kept | commitment_broken naming any
# commitment + any result. May or may not have a valid anchor in the store
# by the time it is written — the reader must not count an unanchored
# terminal as a closure.
terminal_strategy = st.tuples(
    st.sampled_from(["kept", "broken"]),
    st.sampled_from(COMMITMENT_POOL),
    st.sampled_from(RESULT_POOL),
)

event_strategy = st.one_of(
    register_strategy,
    observe_strategy,
    terminal_strategy,
)

sequence_strategy = st.lists(event_strategy, min_size=0, max_size=20)


# --- Helpers to materialize events as on-disk receipts. ----------------------

_POLICY_HASH = "sha256:" + "c" * 64


def _apply_event_to_store(
    store: AssayStore,
    event: Tuple,
    counter: List[int],
) -> None:
    """Write one event to ``store`` via direct ``append_dict``.

    Uses a shared mutable counter for unique per-event ids (fulfillment_id,
    episode_id suffixes) so the test generates unique identifiers even when
    the same (commitment_id, result_id) pair is revisited.
    """
    kind = event[0]
    counter[0] += 1
    idx = counter[0]

    if kind == "register":
        cmt_id = event[1]
        store.append_dict({
            "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
            "commitment_id": cmt_id,
            "episode_id": f"ep_{idx}",
            "actor_id": "actor_hyp",
            "text": f"hypothesis-generated commitment {idx}",
            "commitment_type": "delivery",
            "policy_hash": _POLICY_HASH,
            # Use a deep past due_at so the detector flags unclosed
            # registrations; irrelevant to terminal-uniqueness but makes
            # the detector call meaningful.
            "due_at": "2020-01-01T00:00:00Z",
            "timestamp": "2026-04-20T10:00:00.000Z",
        })
        return

    if kind == "observe":
        result_id = event[1]
        ref_cmt_ids = event[2]
        store.append_dict({
            "type": RESULT_OBSERVATION_RECEIPT_TYPE,
            "result_id": result_id,
            "episode_id": f"ep_{idx}",
            "text": f"observation {idx}",
            "evidence_uri": f"file:///tmp/ev_{idx}.log",
            "policy_hash": _POLICY_HASH,
            "references": [
                {"kind": "commitment", "id": cid} for cid in ref_cmt_ids
            ],
            "timestamp": "2026-04-20T11:00:00.000Z",
        })
        return

    if kind in ("kept", "broken"):
        cmt_id = event[1]
        result_id = event[2]
        rt = (
            FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE
            if kind == "kept"
            else FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE
        )
        body: Dict[str, Any] = {
            "type": rt,
            "fulfillment_id": f"ful_{idx}",
            "episode_id": f"ep_{idx}",
            "commitment_id": cmt_id,
            "result_id": result_id,
            "evaluator": "hyp",
            "evaluator_version": "0.1",
            "policy_hash": _POLICY_HASH,
            "timestamp": "2026-04-20T12:00:00.000Z",
        }
        if kind == "broken":
            body["violation_reason"] = f"reason_{idx}"
        store.append_dict(body)
        return

    raise AssertionError(f"unknown event kind: {kind!r}")


# --- The property tests. -----------------------------------------------------


# Fresh isolated store per example. We use a TemporaryDirectory inside the
# test body (not a pytest tmp_path fixture) because Hypothesis re-invokes
# the test function many times per run and pytest function-scoped fixtures
# don't mix cleanly with that.
#
# ``suppress_health_check``: HealthCheck.differing_executors sometimes
# flags the tmp-dir lifecycle; it's safe for our use and suppressing it
# keeps the test focused on the invariant.


@given(sequence_strategy)
@settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.differing_executors],
)
def test_at_most_one_valid_closure_per_commitment(sequence):
    """The headline invariant.

    For every commitment registered in the generated sequence, the
    explainer/detector pair reports either 0 or 1 valid closure for it —
    never 2, regardless of how many terminal receipts name it on disk or
    in what order those terminals and their candidate anchors appeared.
    """
    with tempfile.TemporaryDirectory() as tmp:
        store = AssayStore(base_dir=Path(tmp))
        store.start_trace()

        counter = [0]
        for event in sequence:
            _apply_event_to_store(store, event, counter)

        # Collect every distinct commitment_id that appeared. (Empty
        # sequences yield nothing to check; assume-skip those.)
        seen_cmts: set = set()
        for event in sequence:
            if event[0] == "register":
                seen_cmts.add(event[1])
            elif event[0] in ("kept", "broken"):
                # Terminals naming unregistered commitments are also
                # worth inspecting — they must never look like closures.
                seen_cmts.add(event[1])
        assume(len(seen_cmts) > 0)

        for cmt_id in seen_cmts:
            result = explain_commitment(store, cmt_id)
            # Integrity failure is an unrelated class of behavior; we
            # only care about the invariant on valid-corpus runs. If it
            # trips, the test flags it — explain_commitment returning
            # INVALID_STORE from a clean-generated sequence would itself
            # be a bug.
            assert result.state != "INVALID_STORE", (
                f"unexpected INVALID_STORE for cmt_id={cmt_id!r}; "
                f"integrity_error={result.integrity_error!r}; "
                f"sequence={sequence!r}"
            )

            closures = [
                line for line in result.timeline
                if line.note == "closes commitment"
            ]
            assert len(closures) <= 1, (
                f"commitment_id={cmt_id!r} shows {len(closures)} closures, "
                f"expected <= 1. Closures: {closures}. "
                f"State: {result.state}. Sequence: {sequence!r}"
            )

            # Explainer state must agree with closure count.
            if len(closures) == 1:
                assert result.state == "CLOSED", (
                    f"1 closure but state={result.state!r}; "
                    f"decision={result.decision!r}"
                )
            else:
                # Either registered-but-not-closed, or never registered.
                assert result.state in ("OPEN", "NOT_REGISTERED"), (
                    f"0 closures but state={result.state!r}"
                )


@given(sequence_strategy)
@settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.differing_executors],
)
def test_detector_and_explainer_agree_on_closure(sequence):
    """The detector's ``closed_ids`` and the explainer's ``state=CLOSED``
    must agree for every registered commitment.

    Both readers use ``_iter_all_receipts`` and the same order-aware
    anchor logic; any disagreement indicates a drift between the
    detector's aggregation and the explainer's per-commitment walk.
    """
    with tempfile.TemporaryDirectory() as tmp:
        store = AssayStore(base_dir=Path(tmp))
        store.start_trace()

        counter = [0]
        for event in sequence:
            _apply_event_to_store(store, event, counter)

        registered_cmts = {
            event[1] for event in sequence if event[0] == "register"
        }
        assume(len(registered_cmts) > 0)

        detector_result = detect_open_overdue_commitments(store)
        open_from_detector = {c.commitment_id for c in detector_result.open_commitments}

        for cmt_id in registered_cmts:
            ex = explain_commitment(store, cmt_id)
            explainer_says_closed = ex.state == "CLOSED"
            detector_says_open = cmt_id in open_from_detector

            # All generated commitments are registered with a past due_at,
            # so the detector treats any not-closed registered commitment
            # as OPEN (overdue). Explainer says CLOSED iff detector does
            # NOT say OPEN — equivalent because both are derived from the
            # same anchored-terminal rule.
            if explainer_says_closed:
                assert not detector_says_open, (
                    f"disagreement for cmt_id={cmt_id!r}: explainer "
                    f"says CLOSED but detector lists it as OPEN. "
                    f"detector.open={open_from_detector!r}; "
                    f"explainer={ex.decision!r}; sequence={sequence!r}"
                )
            elif ex.state == "OPEN":
                assert detector_says_open, (
                    f"disagreement for cmt_id={cmt_id!r}: explainer "
                    f"says OPEN but detector does NOT list it as overdue. "
                    f"detector.open={open_from_detector!r}; "
                    f"explainer={ex.decision!r}; sequence={sequence!r}"
                )
            # If explainer says NOT_REGISTERED despite us seeing a
            # register event, something is badly wrong — surface it.
            else:
                pytest.fail(
                    f"unexpected explainer state={ex.state!r} for "
                    f"cmt_id={cmt_id!r} that WAS registered in the sequence. "
                    f"sequence={sequence!r}"
                )


@given(sequence_strategy)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.differing_executors],
)
def test_closing_terminal_precedes_its_anchor_in_seq_order_never_closes(sequence):
    """A terminal whose anchor (matching observation) is AFTER it in
    ``_store_seq`` order must never be counted as the closing terminal.

    This is the specific causal invariant from the detector: at a
    terminal's encounter point, the anchor edge must already be present.
    Later observations cannot retroactively legitimize the terminal.

    Implementation note on the structural assertion:
        The closing terminal's ``_store_seq`` is taken from
        ``ExplainLine.seq`` (a structured int field) via the line whose
        ``note == "closes commitment"``. The terminal's ``result_id`` is
        taken from the generated event sequence itself — because
        ``store.append_dict`` stamps ``_store_seq`` in write order,
        event index == _store_seq for this direct-write test.

        The anchor's ``_store_seq`` is found by walking the generated
        events up to that terminal index for a prior ``observe`` whose
        ``result_id`` matches and whose ``references`` list contains
        this commitment_id.

        No ``ExplainResult.decision`` prose is parsed. The property holds
        against semantic invariants, not wording.
    """
    with tempfile.TemporaryDirectory() as tmp:
        store = AssayStore(base_dir=Path(tmp))
        store.start_trace()

        counter = [0]
        for event in sequence:
            _apply_event_to_store(store, event, counter)

        # Because direct ``append_dict`` to a fresh store yields
        # ``_store_seq == 0`` for the first write, and every subsequent
        # write increments by 1, the generated event at index ``i`` is
        # precisely the receipt whose ``_store_seq`` is ``i``. Asserting
        # this in code keeps the mapping honest if the test helper ever
        # grows extra writes.
        assert _verify_event_index_matches_store_seq(store, sequence)

        seen_cmts = {
            event[1] for event in sequence if event[0] == "register"
        }
        assume(len(seen_cmts) > 0)

        for cmt_id in seen_cmts:
            result = explain_commitment(store, cmt_id)
            if result.state != "CLOSED":
                continue

            # Structural: closing terminal's seq comes straight from the
            # ExplainLine integer field, not from parsing prose.
            closures = [
                line for line in result.timeline
                if line.note == "closes commitment"
            ]
            assert len(closures) == 1, (
                f"expected exactly 1 closure, got {closures}"
            )
            terminal_seq = closures[0].seq

            # Structural: terminal's result_id comes from the generated
            # event at index == terminal_seq, not from prose.
            terminal_event = sequence[terminal_seq]
            assert terminal_event[0] in ("kept", "broken"), (
                f"expected terminal event at seq={terminal_seq}, got "
                f"{terminal_event!r}"
            )
            terminal_cmt_id = terminal_event[1]
            terminal_result_id = terminal_event[2]
            assert terminal_cmt_id == cmt_id, (
                f"closing terminal at seq={terminal_seq} names "
                f"cmt_id={terminal_cmt_id!r} but explainer attributed "
                f"the closure to cmt_id={cmt_id!r}"
            )

            # Structural: scan the generated sequence for the anchor —
            # an earlier ``observe`` whose result_id matches and whose
            # refs include this commitment.
            anchor_seq = _find_anchor_seq_in_sequence(
                sequence, terminal_seq, cmt_id, terminal_result_id
            )
            assert anchor_seq is not None, (
                f"state=CLOSED for cmt_id={cmt_id!r} but no matching "
                f"observation precedes terminal seq={terminal_seq} in the "
                f"generated sequence. sequence={sequence!r}"
            )
            assert anchor_seq < terminal_seq, (
                f"closure violates causal order: anchor seq={anchor_seq} "
                f">= terminal seq={terminal_seq} for cmt_id={cmt_id!r}. "
                f"sequence={sequence!r}"
            )


# --- Structural helpers for the causal-order property. ----------------------


def _verify_event_index_matches_store_seq(
    store: AssayStore, sequence: List[Tuple]
) -> bool:
    """Confirm that the i-th generated event landed at ``_store_seq == i``.

    This anchors the structural causal-order assertion: the test derives
    order by event index, and this check ensures that index really is the
    persisted ``_store_seq``. If the helper were ever changed to emit
    extra implicit writes, this assertion would flag the drift.
    """
    if not sequence:
        return True
    for trace_file in sorted(store.base_dir.rglob("trace_*.jsonl")):
        if not trace_file.is_file():
            continue
        import json as _json
        with open(trace_file) as handle:
            seqs = []
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                entry = _json.loads(line)
                seqs.append(entry.get("_store_seq"))
        # Test assumes single trace file for a single-trace sequence run.
        if seqs == list(range(len(sequence))):
            return True
    return False


def _find_anchor_seq_in_sequence(
    sequence: List[Tuple],
    terminal_seq: int,
    commitment_id: str,
    result_id: str,
) -> "int | None":
    """Return the ``_store_seq`` of the latest qualifying observation before
    ``terminal_seq``, or ``None`` if no such observation exists.

    Qualifying observation: an ``observe`` event whose ``result_id`` matches
    and whose ``references`` list includes ``commitment_id``.
    """
    latest: "int | None" = None
    for i in range(terminal_seq):
        event = sequence[i]
        if event[0] != "observe":
            continue
        _, ev_result_id, ref_cmt_ids = event
        if ev_result_id == result_id and commitment_id in ref_cmt_ids:
            latest = i  # keep scanning for the most recent one
    return latest
