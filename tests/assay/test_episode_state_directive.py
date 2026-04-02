from __future__ import annotations

from pathlib import Path

import pytest

from assay.episode import (
    ASSAY_EPISODE_TARGET_SUBSTRATE,
    EpisodeDirectiveCode,
    EpisodeState,
    EpisodeStateError,
    SettlementOutcome,
    apply_episode_state_directive,
    open_episode,
)
from assay.store import AssayStore


@pytest.fixture
def tmp_store(tmp_path: Path) -> AssayStore:
    return AssayStore(base_dir=tmp_path / "assay_store")


def _directive(
    episode_id: str,
    directive: EpisodeDirectiveCode,
    **overrides,
):
    payload = {
        "episode_id": episode_id,
        "directive": directive.value,
        "directive_id": f"directive-{directive.value.lower()}",
        "source_lane": "refusal_admissibility",
        "source_artifact_ref": "decision_v1:dr-001",
        "source_authority_ceiling": "refusal_admissibility",
        "target_substrate": ASSAY_EPISODE_TARGET_SUBSTRATE,
        "source_reason_codes": [f"admissibility:{directive.value.lower()}"],
        "settlement_reason_codes": [],
        "evidence_refs": ["receipt:gate_eval:coherence"],
    }
    payload.update(overrides)
    return payload


def _receipts(ep, receipt_type: str):
    return [receipt for receipt in ep.receipts if receipt.receipt_type == receipt_type]


def test_route_to_review_routes_open_episode_to_awaiting_guardian(tmp_store: AssayStore) -> None:
    episode = open_episode(store=tmp_store)

    apply_episode_state_directive(
        episode,
        _directive(episode.episode_id, EpisodeDirectiveCode.ROUTE_TO_REVIEW),
    )

    assert episode.state == EpisodeState.AWAITING_GUARDIAN
    directed = _receipts(episode, "episode.state_directed")
    assert len(directed) == 1
    assert directed[0].payload["directive"] == EpisodeDirectiveCode.ROUTE_TO_REVIEW.value


def test_reopen_for_retry_reopens_guardian_hold_to_executing(tmp_store: AssayStore) -> None:
    episode = open_episode(store=tmp_store)
    episode.start_execution()
    episode.mark_execution_complete()

    apply_episode_state_directive(
        episode,
        _directive(episode.episode_id, EpisodeDirectiveCode.REOPEN_FOR_RETRY),
    )

    assert episode.state == EpisodeState.EXECUTING
    assert episode.execution_completed_at is None


def test_duplicate_directive_id_is_idempotent(tmp_store: AssayStore) -> None:
    episode = open_episode(store=tmp_store)
    directive = _directive(episode.episode_id, EpisodeDirectiveCode.ROUTE_TO_REVIEW)

    apply_episode_state_directive(episode, directive)
    receipt_count_after_first_apply = len(episode.receipts)

    apply_episode_state_directive(episode, directive)

    assert episode.state == EpisodeState.AWAITING_GUARDIAN
    assert len(episode.receipts) == receipt_count_after_first_apply
    directed = _receipts(episode, "episode.state_directed")
    assert len(directed) == 1
    assert directed[0].payload["directive_id"] == directive["directive_id"]


def test_close_as_tainted_settles_episode_as_tampered(tmp_store: AssayStore) -> None:
    episode = open_episode(store=tmp_store)
    episode.start_execution()
    episode.mark_execution_complete()

    apply_episode_state_directive(
        episode,
        _directive(episode.episode_id, EpisodeDirectiveCode.CLOSE_AS_TAINTED),
    )

    assert episode.state == EpisodeState.SETTLED
    assert episode.outcome == SettlementOutcome.TAMPERED
    assert episode.settlement is not None
    assert episode.settlement.outcome == SettlementOutcome.TAMPERED
    settled = _receipts(episode, "episode.settled")
    assert settled[-1].payload["directive"] == EpisodeDirectiveCode.CLOSE_AS_TAINTED.value
    assert settled[-1].payload["directed"] is True


def test_close_as_refused_settles_episode_as_honest_fail(tmp_store: AssayStore) -> None:
    episode = open_episode(store=tmp_store)
    episode.start_execution()
    episode.mark_execution_complete()

    apply_episode_state_directive(
        episode,
        _directive(episode.episode_id, EpisodeDirectiveCode.CLOSE_AS_REFUSED),
    )

    assert episode.state == EpisodeState.SETTLED
    assert episode.outcome == SettlementOutcome.HONEST_FAIL
    assert episode.settlement is not None
    assert episode.settlement.outcome == SettlementOutcome.HONEST_FAIL


def test_stale_terminal_directive_is_rejected_before_emitting_receipt(
    tmp_store: AssayStore,
) -> None:
    episode = open_episode(store=tmp_store)
    episode.start_execution()
    episode.mark_execution_complete()

    apply_episode_state_directive(
        episode,
        _directive(episode.episode_id, EpisodeDirectiveCode.CLOSE_AS_REFUSED),
    )
    directed_count = len(_receipts(episode, "episode.state_directed"))
    settled_count = len(_receipts(episode, "episode.settled"))

    with pytest.raises(EpisodeStateError, match="already has a settlement"):
        apply_episode_state_directive(
            episode,
            _directive(
                episode.episode_id,
                EpisodeDirectiveCode.CLOSE_AS_TAINTED,
                directive_id="directive-close-as-tainted-stale",
            ),
        )

    assert episode.state == EpisodeState.SETTLED
    assert episode.outcome == SettlementOutcome.HONEST_FAIL
    assert len(_receipts(episode, "episode.state_directed")) == directed_count
    assert len(_receipts(episode, "episode.settled")) == settled_count


def test_mismatched_episode_id_fails_closed(tmp_store: AssayStore) -> None:
    episode = open_episode(store=tmp_store)

    with pytest.raises(EpisodeStateError, match="does not match episode"):
        apply_episode_state_directive(
            episode,
            _directive("ep_other", EpisodeDirectiveCode.ROUTE_TO_REVIEW),
        )