"""Parity test: the three readers agree on one adversarial corpus.

Purpose:
    After extracting ``project_commitment_lifecycle`` as the shared
    source of truth, the detector / explainer / summarizer all derive
    their outputs from the same projection. This test verifies their
    outputs stay consistent on a single corpus that exercises every
    adversarial case Slice 1's reviews surfaced.

    If any reader drifts (e.g. a future change re-derives lifecycle
    semantics locally instead of going through the projection), this
    test fails before the drift ships.

Adversarial corpus:
    A hand-crafted event sequence designed to trip on each class of
    closure pathology simultaneously, on one store, in one walk:

        - VALID_CLOSED  — registered, observed with anchor, then kept
        - INVALID_TERMINAL — terminal before any observation exists
        - RETROACTIVE_OBS  — observation appended AFTER a terminal
                             (does not retroactively close)
        - WRONG_ANCHOR     — observation references a different
                             commitment than the terminal names
        - BAD_DUE_AT       — malformed ``due_at`` string (not overdue)
        - NOT_REGISTERED   — a commitment_id that never appears
        - PERPETUAL        — open, no due_at, must never appear
                             overdue

Read-only. No receipts emitted.
"""
from __future__ import annotations

import pytest

from assay.commitment_closure_detector import detect_open_overdue_commitments
from assay.commitment_explain import explain_commitment
from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
)
from assay.commitment_summary import summarize_all_commitments
from assay.store import AssayStore


def _build_adversarial_corpus(tmp_path) -> AssayStore:
    """Return a store with an event sequence hitting every closure pathology.

    Ordering is significant — each case is arranged in ``_store_seq``
    order such that the reader's anchor/encounter rules are the thing
    actually being tested.
    """
    store = AssayStore(base_dir=tmp_path / "adversarial")
    store.start_trace()

    # --- VALID_CLOSED: proper register → observe → kept chain ---------------
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_valid_closed",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "Deliverable A.",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "due_at": "2020-01-01T00:00:00Z",
        "timestamp": "2026-04-20T10:00:00Z",
    })
    store.append_dict({
        "type": RESULT_OBSERVATION_RECEIPT_TYPE,
        "result_id": "res_valid",
        "episode_id": "ep",
        "text": "shipped",
        "evidence_uri": "file:///t/e.log",
        "policy_hash": "sha256:" + "c" * 64,
        "references": [{"kind": "commitment", "id": "cmt_valid_closed"}],
        "timestamp": "2026-04-20T11:00:00Z",
    })
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": "ful_valid",
        "episode_id": "ep",
        "commitment_id": "cmt_valid_closed",
        "result_id": "res_valid",
        "evaluator": "qa",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T12:00:00Z",
    })

    # --- INVALID_TERMINAL: terminal before any observation ------------------
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_invalid_terminal",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "forged",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "due_at": "2020-01-01T00:00:00Z",
        "timestamp": "2026-04-20T10:00:00Z",
    })
    # Terminal at this seq has NO prior observation referencing this cmt.
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": "ful_forged_early",
        "episode_id": "ep",
        "commitment_id": "cmt_invalid_terminal",
        "result_id": "res_never_observed",
        "evaluator": "qa",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T11:00:00Z",
    })

    # --- RETROACTIVE_OBS: terminal first, observation later -----------------
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_retro",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "retro",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "due_at": "2020-01-01T00:00:00Z",
        "timestamp": "2026-04-20T10:00:00Z",
    })
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": "ful_retro_early",
        "episode_id": "ep",
        "commitment_id": "cmt_retro",
        "result_id": "res_retro",
        "evaluator": "qa",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T11:00:00Z",
    })
    # Observation arrives AFTER the terminal — cannot retroactively close.
    store.append_dict({
        "type": RESULT_OBSERVATION_RECEIPT_TYPE,
        "result_id": "res_retro",
        "episode_id": "ep",
        "text": "late observation",
        "evidence_uri": "file:///t/e.log",
        "policy_hash": "sha256:" + "c" * 64,
        "references": [{"kind": "commitment", "id": "cmt_retro"}],
        "timestamp": "2026-04-20T12:00:00Z",
    })

    # --- WRONG_ANCHOR: observation references a different commitment --------
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_wrong_A",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "A",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "due_at": "2020-01-01T00:00:00Z",
        "timestamp": "2026-04-20T10:00:00Z",
    })
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_wrong_B",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "B",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "due_at": "2020-01-01T00:00:00Z",
        "timestamp": "2026-04-20T10:00:00Z",
    })
    # res_B observed only for cmt_wrong_B.
    store.append_dict({
        "type": RESULT_OBSERVATION_RECEIPT_TYPE,
        "result_id": "res_B",
        "episode_id": "ep",
        "text": "B shipped",
        "evidence_uri": "file:///t/e.log",
        "policy_hash": "sha256:" + "c" * 64,
        "references": [{"kind": "commitment", "id": "cmt_wrong_B"}],
        "timestamp": "2026-04-20T11:00:00Z",
    })
    # Terminal tries to close cmt_wrong_A with res_B — wrong anchor edge.
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": "ful_wrong_anchor",
        "episode_id": "ep",
        "commitment_id": "cmt_wrong_A",
        "result_id": "res_B",
        "evaluator": "qa",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T12:00:00Z",
    })

    # --- BAD_DUE_AT: unparseable due_at (not overdue) -----------------------
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_bad_due",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "bad_due",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "due_at": "this-is-not-a-valid-iso-8601-timestamp",
        "timestamp": "2026-04-20T10:00:00Z",
    })

    # --- PERPETUAL: open, no due_at -----------------------------------------
    store.append_dict({
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": "cmt_perpetual",
        "episode_id": "ep",
        "actor_id": "alice",
        "text": "forever open",
        "commitment_type": "delivery",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T10:00:00Z",
    })

    return store


def test_three_readers_agree_on_adversarial_corpus(tmp_path):
    """Detector, explainer, and summarizer must agree on every commitment in
    one adversarial corpus — same projection, same conclusions.

    If the projector changes or a reader drifts off the projection, this
    test surfaces the divergence.
    """
    store = _build_adversarial_corpus(tmp_path)

    detector_result = detect_open_overdue_commitments(store)
    summarizer_result = summarize_all_commitments(store)

    # Header counts match.
    assert detector_result.total_registered_found == len(summarizer_result.commitments)
    assert detector_result.total_closed_found == sum(
        1 for s in summarizer_result.commitments if s.state == "CLOSED"
    )
    summarizer_overdue_ids = {
        s.commitment_id for s in summarizer_result.commitments if s.is_overdue
    }
    detector_overdue_ids = {
        c.commitment_id for c in detector_result.open_commitments
    }
    assert detector_overdue_ids == summarizer_overdue_ids

    # Expected overall state per commitment.
    expected_state = {
        "cmt_valid_closed": "CLOSED",
        "cmt_invalid_terminal": "OPEN",
        "cmt_retro": "OPEN",
        "cmt_wrong_A": "OPEN",
        "cmt_wrong_B": "OPEN",
        "cmt_bad_due": "OPEN",
        "cmt_perpetual": "OPEN",
    }
    summarizer_by_id = {s.commitment_id: s for s in summarizer_result.commitments}

    for cmt_id, expected in expected_state.items():
        summary = summarizer_by_id[cmt_id]
        explanation = explain_commitment(store, cmt_id)

        assert summary.state == expected, (
            f"summarizer disagrees for {cmt_id!r}: got {summary.state!r}, "
            f"expected {expected!r}"
        )
        assert explanation.state == expected, (
            f"explainer disagrees for {cmt_id!r}: got {explanation.state!r}, "
            f"expected {expected!r}"
        )

    # NOT_REGISTERED parity: a commitment that was never registered must
    # surface as NOT_REGISTERED in the explainer and must not appear in
    # the summarizer or detector output.
    phantom = "cmt_never_registered"
    assert explain_commitment(store, phantom).state == "NOT_REGISTERED"
    assert phantom not in summarizer_by_id
    assert phantom not in detector_overdue_ids


def test_overdue_classification_agrees_on_adversarial_corpus(tmp_path):
    """Overdue classification is the highest-leverage place for reader drift
    (it depends on both closure state AND due_at parsing). Lock it tightly.

    Expected per our corpus:
        - cmt_valid_closed : NOT overdue (closed)
        - cmt_invalid_terminal : overdue (registered past, never closed)
        - cmt_retro : overdue (registered past, terminal invalid, never closed)
        - cmt_wrong_A : overdue
        - cmt_wrong_B : overdue (no terminal at all)
        - cmt_bad_due : NOT overdue (unparseable due_at → perpetual)
        - cmt_perpetual : NOT overdue (no due_at)
    """
    store = _build_adversarial_corpus(tmp_path)

    expected_overdue = {
        "cmt_invalid_terminal",
        "cmt_retro",
        "cmt_wrong_A",
        "cmt_wrong_B",
    }

    detector_overdue = {
        c.commitment_id for c in detect_open_overdue_commitments(store).open_commitments
    }
    summarizer_overdue = {
        s.commitment_id
        for s in summarize_all_commitments(store).commitments
        if s.is_overdue
    }

    assert detector_overdue == expected_overdue, (
        f"detector overdue set mismatch: "
        f"got {detector_overdue!r}, expected {expected_overdue!r}"
    )
    assert summarizer_overdue == expected_overdue, (
        f"summarizer overdue set mismatch: "
        f"got {summarizer_overdue!r}, expected {expected_overdue!r}"
    )


def test_explainer_closed_anchor_seq_matches_projection(tmp_path):
    """For a CLOSED commitment, the anchor seq cited in the explainer's
    decision must match the ``anchor_observation_seq`` the projection
    recorded. If the explainer re-derives the anchor from a different
    source, the two can drift — this test locks the agreement.
    """
    from assay.commitment_projection import project_commitment_lifecycle

    store = _build_adversarial_corpus(tmp_path)

    projection = project_commitment_lifecycle(store)
    closure = projection.closures["cmt_valid_closed"]
    explanation = explain_commitment(store, "cmt_valid_closed")

    assert explanation.state == "CLOSED"
    # The explainer's closing ExplainLine seq must match the projection.
    closing_lines = [
        line for line in explanation.timeline
        if line.note == "closes commitment"
    ]
    assert len(closing_lines) == 1
    assert closing_lines[0].seq == closure.closing_terminal_seq
    # Anchor seq appears in the decision string; the specific integer
    # must match. Parsing minimally here is acceptable because the
    # decision format is part of the explainer's stable contract.
    anchor_token = f"anchor result.observed seq={closure.anchor_observation_seq} "
    assert anchor_token in explanation.decision, (
        f"expected {anchor_token!r} in decision, got: {explanation.decision!r}"
    )
