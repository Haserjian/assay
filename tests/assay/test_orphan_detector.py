"""
Episode Orphan Detection Tests

Kernel Gap Ledger Row #1, Bypass #4: Assay optional context manager.
Proof that the orphan detector correctly identifies episodes that
were opened but never terminalized.

Constitutional law:
    Every episode must terminate constitutionally: either by a typed
    terminal receipt, or by an explicit detector-reported constitutional
    violation.

These tests prove:
    1. Bare open_episode() without close is detected as orphan
    2. Context-manager episodes are NOT flagged
    3. Explicitly abandoned episodes are NOT flagged
    4. Explicitly closed episodes are NOT flagged
    5. Mixed stores (some orphaned, some healthy) report correctly
    6. Empty stores report clean
    7. Legacy traces (no episode.opened) are not false positives
    8. Detector is pure-read (store not mutated)
    9. check_episode_health returns correct boolean
    10. Multiple orphans in the same store are all reported
"""

import pytest

from assay.episode import (
    Episode,
    EpisodeState,
    open_episode,
)
from assay.orphan_detector import (
    OrphanDetectionResult,
    OrphanedEpisode,
    check_episode_health,
    detect_orphaned_episodes,
)
from assay.store import AssayStore


@pytest.fixture
def tmp_store(tmp_path):
    """Create a temporary AssayStore for test isolation."""
    return AssayStore(base_dir=tmp_path / "assay_store")


# ---------------------------------------------------------------------------
# 1. Orphan detection: bare open_episode without close
# ---------------------------------------------------------------------------


class TestOrphanDetection:
    """Detector finds episodes opened but never closed."""

    def test_bare_open_episode_is_detected(self, tmp_store):
        """An episode opened without close/abandon is an orphan."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})
        # Deliberately NOT closing -- this is the orphan scenario
        episode_id = ep.episode_id

        result = detect_orphaned_episodes(tmp_store)

        assert not result.clean
        assert result.total_orphans_found == 1
        assert result.orphans[0].episode_id == episode_id

    def test_bare_open_no_emit_is_detected(self, tmp_store):
        """Even an episode with zero user receipts (just episode.opened) is an orphan."""
        ep = open_episode(store=tmp_store)
        episode_id = ep.episode_id

        result = detect_orphaned_episodes(tmp_store)

        assert not result.clean
        assert result.total_orphans_found == 1
        assert result.orphans[0].episode_id == episode_id
        assert result.orphans[0].receipt_count == 1  # just episode.opened

    def test_multiple_orphans_all_reported(self, tmp_store):
        """Multiple orphaned episodes in the same store are all found."""
        ep1 = open_episode(store=tmp_store)
        ep2 = open_episode(store=tmp_store)
        ep3 = open_episode(store=tmp_store)

        result = detect_orphaned_episodes(tmp_store)

        assert result.total_orphans_found == 3
        orphan_ids = {o.episode_id for o in result.orphans}
        assert ep1.episode_id in orphan_ids
        assert ep2.episode_id in orphan_ids
        assert ep3.episode_id in orphan_ids


# ---------------------------------------------------------------------------
# 2. Healthy episodes are NOT flagged
# ---------------------------------------------------------------------------


class TestHealthyEpisodesNotFlagged:
    """Properly closed/abandoned episodes are not false positives."""

    def test_context_manager_episode_not_flagged(self, tmp_store):
        """Episode used with `with` block is closed by __exit__."""
        with open_episode(store=tmp_store) as ep:
            ep.emit("model.invoked", {"model": "test"})

        result = detect_orphaned_episodes(tmp_store)
        assert result.clean
        assert result.total_orphans_found == 0

    def test_explicitly_closed_episode_not_flagged(self, tmp_store):
        """Episode explicitly closed is not an orphan."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})
        ep.close()

        result = detect_orphaned_episodes(tmp_store)
        assert result.clean

    def test_explicitly_abandoned_episode_not_flagged(self, tmp_store):
        """Episode abandoned via transition(ABANDONED) is not an orphan."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})
        ep.transition(EpisodeState.ABANDONED)

        result = detect_orphaned_episodes(tmp_store)
        assert result.clean

    def test_context_manager_with_exception_not_flagged(self, tmp_store):
        """Episode where context manager catches exception is still closed."""
        with pytest.raises(ValueError):
            with open_episode(store=tmp_store) as ep:
                ep.emit("model.invoked", {"model": "test"})
                raise ValueError("boom")

        result = detect_orphaned_episodes(tmp_store)
        assert result.clean

    def test_settled_and_closed_episode_not_flagged(self, tmp_store):
        """Episode that goes through full lifecycle is not an orphan."""
        with open_episode(store=tmp_store) as ep:
            ep.emit("model.invoked", {"model": "test"})
            ep.emit("guardian.approved", {"action": "test"})

        result = detect_orphaned_episodes(tmp_store)
        assert result.clean


# ---------------------------------------------------------------------------
# 3. Mixed stores
# ---------------------------------------------------------------------------


class TestMixedStores:
    """Stores with both healthy and orphaned episodes report correctly."""

    def test_mixed_healthy_and_orphaned(self, tmp_store):
        """One healthy + one orphaned = 1 orphan reported."""
        # Healthy
        with open_episode(store=tmp_store) as ep1:
            ep1.emit("model.invoked", {"model": "test"})

        # Orphan
        ep2 = open_episode(store=tmp_store)
        ep2.emit("model.invoked", {"model": "test"})

        result = detect_orphaned_episodes(tmp_store)

        assert not result.clean
        assert result.total_orphans_found == 1
        assert result.total_episodes_found == 2
        assert result.orphans[0].episode_id == ep2.episode_id

    def test_mixed_abandoned_and_orphaned(self, tmp_store):
        """One abandoned + one orphaned = 1 orphan reported."""
        # Abandoned (healthy)
        ep1 = open_episode(store=tmp_store)
        ep1.transition(EpisodeState.ABANDONED)

        # Orphan
        ep2 = open_episode(store=tmp_store)

        result = detect_orphaned_episodes(tmp_store)

        assert result.total_orphans_found == 1
        assert result.orphans[0].episode_id == ep2.episode_id


# ---------------------------------------------------------------------------
# 4. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases: empty stores, legacy traces, detector purity."""

    def test_empty_store_is_clean(self, tmp_store):
        """An empty store has no orphans."""
        result = detect_orphaned_episodes(tmp_store)

        assert result.clean
        assert result.total_traces_scanned == 0
        assert result.total_episodes_found == 0
        assert result.total_orphans_found == 0

    def test_detector_does_not_mutate_store(self, tmp_store):
        """Detector is pure-read: running it doesn't change the trace."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})

        trace_before = tmp_store.read_trace(ep.trace_id)
        detect_orphaned_episodes(tmp_store)
        trace_after = tmp_store.read_trace(ep.trace_id)

        assert len(trace_before) == len(trace_after)
        for before, after in zip(trace_before, trace_after):
            # Exclude runtime metadata that might differ
            b = {k: v for k, v in before.items() if not k.startswith("_")}
            a = {k: v for k, v in after.items() if not k.startswith("_")}
            assert b == a

    def test_result_has_scanned_at(self, tmp_store):
        """Result includes a scan timestamp."""
        result = detect_orphaned_episodes(tmp_store)
        assert result.scanned_at != ""

    def test_orphan_has_forensic_fields(self, tmp_store):
        """Orphaned episode report has all forensic fields populated."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})

        result = detect_orphaned_episodes(tmp_store)
        orphan = result.orphans[0]

        assert orphan.episode_id == ep.episode_id
        assert orphan.trace_id == ep.trace_id
        assert orphan.opened_at != ""
        assert orphan.receipt_count == 2  # episode.opened + model.invoked
        assert orphan.last_receipt_type == "model.invoked"
        assert orphan.last_receipt_at != ""

    def test_to_dict_round_trips(self, tmp_store):
        """OrphanDetectionResult.to_dict() returns serializable data."""
        ep = open_episode(store=tmp_store)

        result = detect_orphaned_episodes(tmp_store)
        d = result.to_dict()

        assert isinstance(d, dict)
        assert d["clean"] is False
        assert d["total_orphans_found"] == 1
        assert len(d["orphans"]) == 1
        assert d["orphans"][0]["episode_id"] == ep.episode_id


# ---------------------------------------------------------------------------
# 5. check_episode_health integration
# ---------------------------------------------------------------------------


class TestCheckEpisodeHealth:
    """The CI/startup entry point returns correct booleans."""

    def test_health_check_returns_true_for_clean_store(self, tmp_store):
        """Clean store returns True."""
        with open_episode(store=tmp_store) as ep:
            ep.emit("model.invoked", {"model": "test"})

        assert check_episode_health(tmp_store, loud=False) is True

    def test_health_check_returns_false_for_orphaned_store(self, tmp_store):
        """Orphaned store returns False."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "test"})

        assert check_episode_health(tmp_store, loud=False) is False

    def test_health_check_loud_prints_to_stderr(self, tmp_store, capsys):
        """Loud mode prints orphan details to stderr."""
        ep = open_episode(store=tmp_store)

        check_episode_health(tmp_store, loud=True)

        captured = capsys.readouterr()
        assert "CONSTITUTIONAL VIOLATION" in captured.err
        assert ep.episode_id in captured.err

    def test_health_check_empty_store_is_clean(self, tmp_store):
        """Empty store is healthy."""
        assert check_episode_health(tmp_store, loud=False) is True
