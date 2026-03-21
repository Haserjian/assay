"""
Tests for DOCTOR_ORPHAN_001 — orphan episode detection wired into assay doctor.

Kernel Gap Ledger Row #1: Episode Termination
Proves: orphan detector is operationally reachable through assay doctor,
not just a library function sitting on a shelf.
"""

import pytest
from assay.doctor import (
    CheckStatus,
    Profile,
    Severity,
    run_doctor,
    _check_orphan_001,
)
from assay.episode import EpisodeState, open_episode
from assay.store import AssayStore


@pytest.fixture
def tmp_store(tmp_path):
    return AssayStore(base_dir=tmp_path / "assay_store")


# ---------------------------------------------------------------------------
# 1. Direct check function
# ---------------------------------------------------------------------------

class TestCheckOrphan001:
    """Test the _check_orphan_001 doctor check directly."""

    def test_clean_store_passes(self, tmp_store, monkeypatch):
        """Empty store reports no orphans."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)
        result = _check_orphan_001()
        assert result.status == CheckStatus.PASS
        assert result.id == "DOCTOR_ORPHAN_001"

    def test_orphaned_episode_fails(self, tmp_store, monkeypatch):
        """Store with orphaned episode reports FAIL."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        # Create an episode and abandon it without closing
        ep = open_episode(store=tmp_store)
        # Don't close — this is the orphan

        result = _check_orphan_001()
        assert result.status == CheckStatus.FAIL
        assert result.severity == Severity.HIGH
        assert result.evidence["orphan_count"] >= 1

    def test_closed_episode_passes(self, tmp_store, monkeypatch):
        """Store with properly closed episode reports PASS."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        with open_episode(store=tmp_store) as ep:
            ep.emit("model.invoked", {"model": "test"})

        result = _check_orphan_001()
        assert result.status == CheckStatus.PASS

    def test_abandoned_episode_passes(self, tmp_store, monkeypatch):
        """Store with properly abandoned episode reports PASS."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        ep = open_episode(store=tmp_store)
        ep.transition(EpisodeState.ABANDONED)

        result = _check_orphan_001()
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 2. Wired into run_doctor
# ---------------------------------------------------------------------------

class TestDoctorOrphanWiring:
    """Verify DOCTOR_ORPHAN_001 runs as part of doctor profiles."""

    def test_orphan_check_in_local_profile(self, tmp_store, monkeypatch):
        """Orphan check runs in LOCAL profile."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        report = run_doctor(Profile.LOCAL)
        check_ids = [c.id for c in report.checks]
        assert "DOCTOR_ORPHAN_001" in check_ids

    def test_orphan_check_in_ci_profile(self, tmp_store, monkeypatch):
        """Orphan check runs in CI profile."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        report = run_doctor(Profile.CI)
        check_ids = [c.id for c in report.checks]
        assert "DOCTOR_ORPHAN_001" in check_ids

    def test_orphan_failure_makes_doctor_fail(self, tmp_store, monkeypatch):
        """Orphaned episode causes doctor to report overall failure."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        # Create orphan
        ep = open_episode(store=tmp_store)

        report = run_doctor(Profile.LOCAL)
        orphan_check = next(c for c in report.checks if c.id == "DOCTOR_ORPHAN_001")
        assert orphan_check.status == CheckStatus.FAIL
        assert report.exit_code != 0  # doctor reports failure

    def test_clean_store_doctor_passes_orphan_check(self, tmp_store, monkeypatch):
        """Clean store passes orphan check within doctor."""
        monkeypatch.setattr("assay.store.get_default_store", lambda: tmp_store)

        report = run_doctor(Profile.LOCAL)
        orphan_check = next(c for c in report.checks if c.id == "DOCTOR_ORPHAN_001")
        assert orphan_check.status == CheckStatus.PASS
