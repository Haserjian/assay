"""
Episode ABANDONED Receipt Tests

Kernel Gap Ledger Row #1: Episode Termination
Bypass class: silent terminal state (ABANDONED)
Proof of closure: these tests prove ABANDONED can never be silent epistemic death.

Constitutional law:
    No episode may enter a terminal state without emitting a typed receipt.
    ABANDONED is a terminal state. It must leave a forensic trace.
    Closed episodes reject all transitions (no zombie emission).
"""

import pytest
from assay.episode import (
    Episode,
    EpisodeClosedError,
    EpisodeState,
    EpisodeStateError,
    open_episode,
)
from assay.store import AssayStore


@pytest.fixture
def tmp_store(tmp_path):
    """Create a temporary AssayStore for test isolation."""
    return AssayStore(base_dir=tmp_path / "assay_store")


def _find_receipts_by_type(ep: Episode, receipt_type: str):
    """Find all receipts of a given type in the episode."""
    return [r for r in ep.receipts if r.receipt_type == receipt_type]


# ---------------------------------------------------------------------------
# 1. ABANDONED emits typed receipt from every source state
# ---------------------------------------------------------------------------

class TestAbandonedEmitsReceipt:
    """Entering ABANDONED must always emit a typed episode.abandoned receipt."""

    def test_abandon_from_open(self, tmp_store):
        """OPEN -> ABANDONED emits episode.abandoned with abandoned_from='open'."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert len(abandoned) == 1
        assert abandoned[0].payload["abandoned_from"] == "open"
        assert ep.state == EpisodeState.ABANDONED
        assert ep._closed is True

    def test_abandon_from_executing(self, tmp_store):
        """EXECUTING -> ABANDONED emits episode.abandoned with abandoned_from='executing'."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.EXECUTING)
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert len(abandoned) == 1
        assert abandoned[0].payload["abandoned_from"] == "executing"

    def test_abandon_from_awaiting_guardian(self, tmp_store):
        """AWAITING_GUARDIAN -> ABANDONED records source state."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.EXECUTING)
        ep.transition(EpisodeState.AWAITING_GUARDIAN)
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert len(abandoned) == 1
        assert abandoned[0].payload["abandoned_from"] == "awaiting_guardian"

    def test_abandon_from_settled(self, tmp_store):
        """SETTLED -> ABANDONED records source state."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.EXECUTING)
        ep.transition(EpisodeState.AWAITING_GUARDIAN)
        ep.transition(EpisodeState.SETTLED)
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert len(abandoned) == 1
        assert abandoned[0].payload["abandoned_from"] == "settled"


# ---------------------------------------------------------------------------
# 2. ABANDONED receipt has correct forensic content
# ---------------------------------------------------------------------------

class TestAbandonedReceiptContent:
    """The abandoned receipt must contain full forensic information."""

    def test_abandoned_receipt_has_episode_id(self, tmp_store):
        """episode.abandoned receipt has the correct episode_id."""
        ep = open_episode(store=tmp_store)
        episode_id = ep.episode_id
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert len(abandoned) == 1
        assert abandoned[0].episode_id == episode_id

    def test_abandoned_receipt_has_abandoned_at(self, tmp_store):
        """episode.abandoned receipt records the abandonment timestamp."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert "abandoned_at" in abandoned[0].payload

    def test_abandoned_receipt_has_receipt_count(self, tmp_store):
        """episode.abandoned receipt records how many receipts existed at abandon time."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})
        ep.transition(EpisodeState.ABANDONED)

        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        # receipt_count should reflect receipts before abandon (opened + model.invoked = 2)
        assert abandoned[0].payload["receipt_count"] >= 2

    def test_abandon_also_emits_episode_closed(self, tmp_store):
        """Transitioning to ABANDONED also emits episode.closed with status=abandoned."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)

        closed = _find_receipts_by_type(ep, "episode.closed")
        assert len(closed) == 1
        assert closed[0].payload["status"] == "abandoned"


# ---------------------------------------------------------------------------
# 3. ABANDONED closes the episode (immutability)
# ---------------------------------------------------------------------------

class TestAbandonedClosesEpisode:
    """After ABANDONED, the episode is closed and immutable."""

    def test_abandon_sets_closed_flag(self, tmp_store):
        """ABANDONED sets _closed=True."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)
        assert ep._closed is True

    def test_abandon_prevents_further_emission(self, tmp_store):
        """After ABANDONED, emit() raises EpisodeClosedError."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)

        with pytest.raises(EpisodeClosedError):
            ep.emit("test.receipt", {"data": "should fail"})

    def test_abandon_is_idempotent_on_close(self, tmp_store):
        """Calling close() after abandon doesn't emit duplicate receipts."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)
        receipts_after_abandon = len(ep.receipts)

        ep.close(status="abandoned")  # should be idempotent
        assert len(ep.receipts) == receipts_after_abandon


# ---------------------------------------------------------------------------
# 4. P1 REGRESSION: closed episodes reject all transitions (no zombies)
# ---------------------------------------------------------------------------

class TestClosedEpisodeRejectsTransition:
    """A closed episode must reject all state transitions.

    This is the P1 regression guard. Without this, a caller could:
        ep.close()
        ep.transition(EpisodeState.ABANDONED)  # zombie emission!
    """

    def test_close_then_abandon_raises(self, tmp_store):
        """close() then transition(ABANDONED) raises EpisodeStateError."""
        ep = open_episode(store=tmp_store)
        ep.close(status="completed")

        with pytest.raises(EpisodeStateError, match="closed"):
            ep.transition(EpisodeState.ABANDONED)

    def test_close_then_any_transition_raises(self, tmp_store):
        """close() then any transition raises."""
        ep = open_episode(store=tmp_store)
        ep.close(status="completed")

        for state in [EpisodeState.EXECUTING, EpisodeState.ABANDONED]:
            with pytest.raises(EpisodeStateError, match="closed"):
                ep.transition(state)

    def test_abandon_then_second_abandon_raises(self, tmp_store):
        """Double abandon raises (first abandon closes, second is rejected)."""
        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)

        with pytest.raises(EpisodeStateError, match="closed"):
            ep.transition(EpisodeState.ABANDONED)

    def test_no_receipts_emitted_after_close(self, tmp_store):
        """No new receipts are added when transition is rejected on closed episode."""
        ep = open_episode(store=tmp_store)
        ep.close(status="completed")
        count_after_close = len(ep.receipts)

        with pytest.raises(EpisodeStateError):
            ep.transition(EpisodeState.ABANDONED)

        assert len(ep.receipts) == count_after_close  # nothing added


# ---------------------------------------------------------------------------
# 5. Context manager interaction
# ---------------------------------------------------------------------------

class TestAbandonedContextManager:
    """ABANDONED interacts correctly with context manager."""

    def test_context_manager_exception_closes_episode(self, tmp_store):
        """Exception in with block emits episode.closed with status=failed."""
        with pytest.raises(ValueError):
            with open_episode(store=tmp_store) as ep:
                raise ValueError("boom")

        assert ep._closed is True
        closed = _find_receipts_by_type(ep, "episode.closed")
        assert len(closed) == 1
        assert closed[0].payload["status"] == "failed"

    def test_bare_open_then_abandon_works(self, tmp_store):
        """open_episode() without with, then explicit abandon, works."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})
        ep.transition(EpisodeState.ABANDONED)

        assert ep._closed is True
        abandoned = _find_receipts_by_type(ep, "episode.abandoned")
        assert len(abandoned) == 1
        closed = _find_receipts_by_type(ep, "episode.closed")
        assert len(closed) == 1


# ---------------------------------------------------------------------------
# 6. No silent epistemic death
# ---------------------------------------------------------------------------

class TestNoSilentEpistemicDeath:
    """The constitutional invariant: no episode disappears without trace."""

    def test_every_abandon_path_produces_typed_receipts(self, tmp_store):
        """Any path to ABANDONED produces exactly one episode.abandoned + one episode.closed."""
        for source_states in [
            [],                    # OPEN -> ABANDONED
            [EpisodeState.EXECUTING],  # EXECUTING -> ABANDONED
        ]:
            ep = open_episode(store=tmp_store)
            for s in source_states:
                ep.transition(s)
            ep.transition(EpisodeState.ABANDONED)

            abandoned = _find_receipts_by_type(ep, "episode.abandoned")
            closed = _find_receipts_by_type(ep, "episode.closed")
            assert len(abandoned) == 1, f"Expected 1 abandoned receipt, got {len(abandoned)}"
            assert len(closed) == 1, f"Expected 1 closed receipt, got {len(closed)}"

    def test_opened_receipt_always_present(self, tmp_store):
        """Even the most minimal episode has episode.opened."""
        ep = open_episode(store=tmp_store)
        opened = _find_receipts_by_type(ep, "episode.opened")
        assert len(opened) == 1

        ep.transition(EpisodeState.ABANDONED)
        # Still has the opened receipt
        opened = _find_receipts_by_type(ep, "episode.opened")
        assert len(opened) == 1
