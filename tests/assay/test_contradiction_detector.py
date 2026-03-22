"""
Contradiction Closure Detection Tests

Row #3 Receipt Composition Law, Stage 3a:
Wire "cannot imply" violations into assay doctor.

Closure law: contradiction.registered must be closed by contradiction.resolved.
An open contradiction is a constitutional violation.

These tests prove:
    1. Registered without resolved is detected as open conflict
    2. Registered with matching resolved is NOT flagged
    3. Multiple open contradictions are all reported
    4. Only the contradiction_id with no matching resolved is open (not others)
    5. Mixed stores (some open, some resolved) report correctly
    6. Empty stores report clean
    7. Traces without contradiction receipts are not false positives
    8. Detector is pure-read (store not mutated)
    9. check_contradiction_health returns correct boolean
    10. Result has scanned_at timestamp
    11. OpenContradiction has all forensic fields populated
    12. to_dict round-trips correctly
    13. DOCTOR_CONTRADICTION_001 check integrates into run_doctor
    14. DOCTOR_ORPHAN_001 check integrates into run_doctor
    15. check_orphans=False does not include store-backed checks
"""

import pytest

from assay.contradiction_detector import (
    ContradictionClosureResult,
    OpenContradiction,
    check_contradiction_health,
    detect_open_contradictions,
)
from assay.store import AssayStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path):
    """Create a temporary AssayStore for test isolation."""
    return AssayStore(base_dir=tmp_path / "assay_store")


# ---------------------------------------------------------------------------
# Helpers: write contradiction receipts to the store
# ---------------------------------------------------------------------------


def _write_registered(store, contradiction_id, *, episode_id="ep_test", severity="medium"):
    """Write a contradiction.registered receipt to the current trace."""
    store.append_dict({
        "type": "contradiction.registered",
        "contradiction_id": contradiction_id,
        "episode_id": episode_id,
        "claim_a_id": "claim_a",
        "claim_b_id": "claim_b",
        "severity": severity,
        "timestamp": "2026-01-01T00:00:00.000Z",
    })


def _write_resolved(store, contradiction_id, *, episode_id="ep_test"):
    """Write a contradiction.resolved receipt to the current trace."""
    store.append_dict({
        "type": "contradiction.resolved",
        "contradiction_id": contradiction_id,
        "episode_id": episode_id,
        "timestamp": "2026-01-01T00:01:00.000Z",
    })


def _start_new_trace(store):
    """Start a fresh trace and return the trace_id."""
    return store.start_trace()


# ---------------------------------------------------------------------------
# 1. Open contradictions are detected
# ---------------------------------------------------------------------------


class TestOpenContradictionDetection:
    """Detector finds contradiction.registered without paired contradiction.resolved."""

    def test_registered_without_resolved_is_open(self, tmp_store):
        """A contradiction.registered with no resolved is an open conflict."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")

        result = detect_open_contradictions(tmp_store)

        assert not result.clean
        assert result.total_open_found == 1
        assert result.open_contradictions[0].contradiction_id == "ctr_001"

    def test_multiple_open_contradictions_all_reported(self, tmp_store):
        """Multiple open contradictions in one trace are all found."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")
        _write_registered(tmp_store, "ctr_002")
        _write_registered(tmp_store, "ctr_003")

        result = detect_open_contradictions(tmp_store)

        assert result.total_open_found == 3
        ids = {c.contradiction_id for c in result.open_contradictions}
        assert "ctr_001" in ids
        assert "ctr_002" in ids
        assert "ctr_003" in ids

    def test_only_unresolved_contradiction_is_open(self, tmp_store):
        """When one is resolved and one is not, only the open one is reported."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_open")
        _write_registered(tmp_store, "ctr_closed")
        _write_resolved(tmp_store, "ctr_closed")

        result = detect_open_contradictions(tmp_store)

        assert result.total_open_found == 1
        assert result.open_contradictions[0].contradiction_id == "ctr_open"


# ---------------------------------------------------------------------------
# 2. Resolved contradictions are NOT flagged
# ---------------------------------------------------------------------------


class TestResolvedContradictionsNotFlagged:
    """Properly resolved contradictions are not false positives."""

    def test_registered_then_resolved_is_clean(self, tmp_store):
        """A contradiction.registered followed by contradiction.resolved is healthy."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")
        _write_resolved(tmp_store, "ctr_001")

        result = detect_open_contradictions(tmp_store)

        assert result.clean
        assert result.total_open_found == 0

    def test_multiple_resolved_all_clean(self, tmp_store):
        """Multiple registered+resolved pairs are all clean."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")
        _write_resolved(tmp_store, "ctr_001")
        _write_registered(tmp_store, "ctr_002")
        _write_resolved(tmp_store, "ctr_002")

        result = detect_open_contradictions(tmp_store)

        assert result.clean
        assert result.total_registered_found == 2
        assert result.total_open_found == 0

    def test_resolved_before_registered_still_closes(self, tmp_store):
        """resolved appearing before registered in the same trace still closes it."""
        _start_new_trace(tmp_store)
        _write_resolved(tmp_store, "ctr_001")
        _write_registered(tmp_store, "ctr_001")

        result = detect_open_contradictions(tmp_store)

        assert result.clean


# ---------------------------------------------------------------------------
# 3. Mixed stores
# ---------------------------------------------------------------------------


class TestMixedStores:
    """Stores with both open and resolved contradictions report correctly."""

    def test_mixed_open_and_resolved(self, tmp_store):
        """One open + one resolved = 1 open reported."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_open")
        _write_registered(tmp_store, "ctr_resolved")
        _write_resolved(tmp_store, "ctr_resolved")

        result = detect_open_contradictions(tmp_store)

        assert not result.clean
        assert result.total_open_found == 1
        assert result.total_registered_found == 2
        assert result.open_contradictions[0].contradiction_id == "ctr_open"

    def test_open_contradiction_across_separate_traces(self, tmp_store):
        """Open contradictions in different traces are both detected."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")

        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_002")

        result = detect_open_contradictions(tmp_store)

        assert result.total_open_found == 2
        ids = {c.contradiction_id for c in result.open_contradictions}
        assert "ctr_001" in ids
        assert "ctr_002" in ids


# ---------------------------------------------------------------------------
# 4. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases: empty stores, legacy traces, detector purity."""

    def test_empty_store_is_clean(self, tmp_store):
        """An empty store has no open contradictions."""
        result = detect_open_contradictions(tmp_store)

        assert result.clean
        assert result.total_traces_scanned == 0
        assert result.total_registered_found == 0
        assert result.total_open_found == 0

    def test_trace_without_contradiction_receipts_not_flagged(self, tmp_store):
        """Traces with only other receipt types are not false positives."""
        _start_new_trace(tmp_store)
        tmp_store.append_dict({
            "type": "model.invoked",
            "episode_id": "ep_test",
        })
        tmp_store.append_dict({
            "type": "episode.opened",
            "episode_id": "ep_test",
        })

        result = detect_open_contradictions(tmp_store)

        assert result.clean
        assert result.total_registered_found == 0

    def test_detector_does_not_mutate_store(self, tmp_store):
        """Detector is pure-read: running it doesn't change the trace."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")

        trace_id = tmp_store.trace_id
        trace_before = tmp_store.read_trace(trace_id)
        detect_open_contradictions(tmp_store)
        trace_after = tmp_store.read_trace(trace_id)

        assert len(trace_before) == len(trace_after)
        for before, after in zip(trace_before, trace_after):
            b = {k: v for k, v in before.items() if not k.startswith("_")}
            a = {k: v for k, v in after.items() if not k.startswith("_")}
            assert b == a

    def test_result_has_scanned_at(self, tmp_store):
        """Result includes a scan timestamp."""
        result = detect_open_contradictions(tmp_store)
        assert result.scanned_at != ""

    def test_open_contradiction_has_forensic_fields(self, tmp_store):
        """OpenContradiction report has all forensic fields populated."""
        _start_new_trace(tmp_store)
        _write_registered(
            tmp_store, "ctr_forensic",
            episode_id="ep_forensic",
            severity="critical",
        )

        result = detect_open_contradictions(tmp_store)
        c = result.open_contradictions[0]

        assert c.contradiction_id == "ctr_forensic"
        assert c.episode_id == "ep_forensic"
        assert c.severity == "critical"
        assert c.claim_a_id == "claim_a"
        assert c.claim_b_id == "claim_b"
        assert c.registered_at != ""
        assert c.trace_id != ""

    def test_to_dict_round_trips(self, tmp_store):
        """ContradictionClosureResult.to_dict() returns serializable data."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_dict_test")

        result = detect_open_contradictions(tmp_store)
        d = result.to_dict()

        assert isinstance(d, dict)
        assert d["clean"] is False
        assert d["total_open_found"] == 1
        assert len(d["open_contradictions"]) == 1
        assert d["open_contradictions"][0]["contradiction_id"] == "ctr_dict_test"

    def test_resolved_only_no_registered_is_clean(self, tmp_store):
        """A resolved receipt with no registered is not an error."""
        _start_new_trace(tmp_store)
        _write_resolved(tmp_store, "ctr_orphan_resolved")

        result = detect_open_contradictions(tmp_store)

        assert result.clean
        assert result.total_registered_found == 0


# ---------------------------------------------------------------------------
# 5. check_contradiction_health integration
# ---------------------------------------------------------------------------


class TestCheckContradictionHealth:
    """The CI/startup entry point returns correct booleans."""

    def test_health_check_returns_true_for_clean_store(self, tmp_store):
        """Clean store returns True."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")
        _write_resolved(tmp_store, "ctr_001")

        assert check_contradiction_health(tmp_store, loud=False) is True

    def test_health_check_returns_false_for_open_contradiction(self, tmp_store):
        """Open contradiction returns False."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_001")

        assert check_contradiction_health(tmp_store, loud=False) is False

    def test_health_check_loud_prints_to_stderr(self, tmp_store, capsys):
        """Loud mode prints open contradiction details to stderr."""
        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_loud_test")

        check_contradiction_health(tmp_store, loud=True)

        captured = capsys.readouterr()
        assert "CONSTITUTIONAL VIOLATION" in captured.err
        assert "ctr_loud_test" in captured.err

    def test_health_check_empty_store_is_clean(self, tmp_store):
        """Empty store is healthy."""
        assert check_contradiction_health(tmp_store, loud=False) is True


# ---------------------------------------------------------------------------
# 6. Doctor integration: DOCTOR_CONTRADICTION_001 and DOCTOR_ORPHAN_001
# ---------------------------------------------------------------------------


class TestDoctorIntegration:
    """DOCTOR_CONTRADICTION_001 and DOCTOR_ORPHAN_001 wire into run_doctor."""

    def test_contradiction_check_not_in_default_run(self, tmp_store):
        """DOCTOR_CONTRADICTION_001 is not run by default."""
        from assay.doctor import run_doctor, Profile

        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_not_default")

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=False)

        ids = [c.id for c in report.checks]
        assert "DOCTOR_CONTRADICTION_001" not in ids
        assert "DOCTOR_ORPHAN_001" not in ids

    def test_contradiction_check_runs_with_check_orphans(self, tmp_store):
        """With check_orphans=True, DOCTOR_CONTRADICTION_001 runs."""
        from assay.doctor import run_doctor, Profile, CheckStatus

        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_flagged")

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=True)

        ids = [c.id for c in report.checks]
        assert "DOCTOR_CONTRADICTION_001" in ids
        assert "DOCTOR_ORPHAN_001" in ids

        contradiction_result = next(c for c in report.checks if c.id == "DOCTOR_CONTRADICTION_001")
        assert contradiction_result.status == CheckStatus.FAIL
        assert "1 open contradiction" in contradiction_result.message

    def test_contradiction_check_passes_when_clean(self, tmp_store):
        """DOCTOR_CONTRADICTION_001 passes when all contradictions are resolved."""
        from assay.doctor import run_doctor, Profile, CheckStatus

        _start_new_trace(tmp_store)
        _write_registered(tmp_store, "ctr_clean")
        _write_resolved(tmp_store, "ctr_clean")

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=True)

        contradiction_result = next(c for c in report.checks if c.id == "DOCTOR_CONTRADICTION_001")
        assert contradiction_result.status == CheckStatus.PASS

    def test_orphan_check_passes_when_no_orphans(self, tmp_store):
        """DOCTOR_ORPHAN_001 passes when store has only closed episodes."""
        from assay.doctor import run_doctor, Profile, CheckStatus
        from assay.episode import open_episode

        with open_episode(store=tmp_store) as ep:
            ep.emit("model.invoked", {"model": "test"})

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=True)

        orphan_result = next(c for c in report.checks if c.id == "DOCTOR_ORPHAN_001")
        assert orphan_result.status == CheckStatus.PASS

    def test_check_orphans_false_keeps_normal_profile_checks(self, tmp_store):
        """check_orphans=False runs the normal profile checks without modification."""
        from assay.doctor import run_doctor, Profile, _PROFILE_CHECKS

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=False)

        ids = [c.id for c in report.checks]
        expected_ids = _PROFILE_CHECKS[Profile.LOCAL]
        for expected in expected_ids:
            assert expected in ids

    def test_check_orphans_true_appends_store_checks(self, tmp_store):
        """check_orphans=True appends DOCTOR_ORPHAN_001 and DOCTOR_CONTRADICTION_001."""
        from assay.doctor import run_doctor, Profile

        report = run_doctor(Profile.LOCAL, store=tmp_store, check_orphans=True)

        ids = [c.id for c in report.checks]
        assert "DOCTOR_ORPHAN_001" in ids
        assert "DOCTOR_CONTRADICTION_001" in ids
