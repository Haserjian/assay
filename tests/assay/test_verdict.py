"""Tests for verdict computation — full policy matrix coverage."""
from __future__ import annotations

import pytest

from assay.verdict import (
    VerificationDimensions,
    VerdictResult,
    compute_verdict,
    extract_dimensions,
)


def _dims(**overrides) -> VerificationDimensions:
    """Create dimensions with clean defaults (everything valid/fresh/clean)."""
    defaults = {
        "signature_valid": True,
        "schema_valid": True,
        "content_hash_valid": True,
        "freshness_status": "fresh",
        "governance_status": "none",
        "event_integrity": "no_events",
    }
    defaults.update(overrides)
    return VerificationDimensions(**defaults)


# ---------------------------------------------------------------------------
# Hard failures (FAIL in all modes)
# ---------------------------------------------------------------------------

class TestHardFailures:
    def test_signature_invalid_fails_everywhere(self) -> None:
        d = _dims(signature_valid=False)
        for mode in ("permissive", "buyer-safe", "strict"):
            r = compute_verdict(d, policy_mode=mode)
            assert r.verdict == "FAIL", f"Expected FAIL in {mode}"
            assert "signature" in r.reason.lower()

    def test_schema_invalid_fails_everywhere(self) -> None:
        d = _dims(schema_valid=False)
        for mode in ("permissive", "buyer-safe", "strict"):
            r = compute_verdict(d, policy_mode=mode)
            assert r.verdict == "FAIL", f"Expected FAIL in {mode}"

    def test_content_hash_invalid_fails_everywhere(self) -> None:
        d = _dims(content_hash_valid=False)
        for mode in ("permissive", "buyer-safe", "strict"):
            r = compute_verdict(d, policy_mode=mode)
            assert r.verdict == "FAIL", f"Expected FAIL in {mode}"
            assert "tampering" in r.reason.lower()

    def test_revoked_fails_everywhere(self) -> None:
        d = _dims(governance_status="revoked")
        for mode in ("permissive", "buyer-safe", "strict"):
            r = compute_verdict(d, policy_mode=mode)
            assert r.verdict == "FAIL", f"Expected FAIL in {mode}"
            assert "revoked" in r.reason.lower()


# ---------------------------------------------------------------------------
# Event integrity issues
# ---------------------------------------------------------------------------

class TestEventIntegrity:
    def test_some_invalid_warns_permissive(self) -> None:
        d = _dims(event_integrity="some_invalid")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "WARN"

    def test_some_invalid_warns_buyer_safe(self) -> None:
        d = _dims(event_integrity="some_invalid")
        r = compute_verdict(d, policy_mode="buyer-safe")
        assert r.verdict == "WARN"

    def test_some_invalid_fails_strict(self) -> None:
        d = _dims(event_integrity="some_invalid")
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "FAIL"


# ---------------------------------------------------------------------------
# Superseded
# ---------------------------------------------------------------------------

class TestSuperseded:
    def test_superseded_warns_permissive(self) -> None:
        d = _dims(governance_status="superseded")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "WARN"

    def test_superseded_warns_buyer_safe(self) -> None:
        d = _dims(governance_status="superseded")
        r = compute_verdict(d, policy_mode="buyer-safe")
        assert r.verdict == "WARN"

    def test_superseded_fails_strict(self) -> None:
        d = _dims(governance_status="superseded")
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "FAIL"


# ---------------------------------------------------------------------------
# Challenged
# ---------------------------------------------------------------------------

class TestChallenged:
    def test_challenged_warns_permissive(self) -> None:
        d = _dims(governance_status="challenged")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "WARN"

    def test_challenged_fails_buyer_safe(self) -> None:
        d = _dims(governance_status="challenged")
        r = compute_verdict(d, policy_mode="buyer-safe")
        assert r.verdict == "FAIL"

    def test_challenged_fails_strict(self) -> None:
        d = _dims(governance_status="challenged")
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "FAIL"


# ---------------------------------------------------------------------------
# Stale
# ---------------------------------------------------------------------------

class TestStale:
    def test_stale_warns_permissive(self) -> None:
        d = _dims(freshness_status="stale")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "WARN"

    def test_stale_fails_buyer_safe(self) -> None:
        d = _dims(freshness_status="stale")
        r = compute_verdict(d, policy_mode="buyer-safe")
        assert r.verdict == "FAIL"

    def test_stale_fails_strict(self) -> None:
        d = _dims(freshness_status="stale")
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "FAIL"


# ---------------------------------------------------------------------------
# Unsigned
# ---------------------------------------------------------------------------

class TestUnsigned:
    def test_unsigned_warns_permissive(self) -> None:
        d = _dims(signature_valid=None)
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "WARN"

    def test_unsigned_warns_buyer_safe(self) -> None:
        d = _dims(signature_valid=None)
        r = compute_verdict(d, policy_mode="buyer-safe")
        assert r.verdict == "WARN"

    def test_unsigned_fails_strict(self) -> None:
        d = _dims(signature_valid=None)
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "FAIL"


# ---------------------------------------------------------------------------
# Clean passport
# ---------------------------------------------------------------------------

class TestCleanPassport:
    def test_clean_passes_everywhere(self) -> None:
        d = _dims()
        for mode in ("permissive", "buyer-safe", "strict"):
            r = compute_verdict(d, policy_mode=mode)
            assert r.verdict == "PASS", f"Expected PASS in {mode}"

    def test_clean_with_no_events_passes(self) -> None:
        d = _dims(event_integrity="no_events")
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "PASS"

    def test_clean_with_all_valid_events_passes(self) -> None:
        d = _dims(event_integrity="all_valid")
        r = compute_verdict(d, policy_mode="strict")
        assert r.verdict == "PASS"


# ---------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------

class TestPrecedence:
    def test_revoked_beats_challenged(self) -> None:
        """Even with challenged + revoked, revoked wins (FAIL)."""
        d = _dims(governance_status="revoked")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "FAIL"
        assert "revoked" in r.reason.lower()

    def test_signature_invalid_beats_stale(self) -> None:
        """Integrity failure overrides temporal status."""
        d = _dims(signature_valid=False, freshness_status="stale")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "FAIL"
        assert "signature" in r.reason.lower()

    def test_schema_invalid_beats_governance(self) -> None:
        d = _dims(schema_valid=False, governance_status="challenged")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.verdict == "FAIL"
        assert "schema" in r.reason.lower()


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_pass_exit_0(self) -> None:
        d = _dims()
        r = compute_verdict(d)
        assert r.exit_code == 0

    def test_warn_exit_1(self) -> None:
        d = _dims(governance_status="challenged")
        r = compute_verdict(d, policy_mode="permissive")
        assert r.exit_code == 1

    def test_fail_exit_2(self) -> None:
        d = _dims(signature_valid=False)
        r = compute_verdict(d)
        assert r.exit_code == 2


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_verdict_to_dict(self) -> None:
        d = _dims()
        r = compute_verdict(d, policy_mode="buyer-safe")
        rd = r.to_dict()
        assert rd["reliance_verdict"] == "PASS"
        assert rd["policy_mode"] == "buyer-safe"
        assert "dimensions" in rd

    def test_dimensions_to_dict(self) -> None:
        d = _dims(governance_status="challenged")
        dd = d.to_dict()
        assert dd["governance_status"] == "challenged"
        assert dd["signature_valid"] is True


# ---------------------------------------------------------------------------
# Dimension extraction
# ---------------------------------------------------------------------------

class TestExtractDimensions:
    def test_extract_clean_passport(self) -> None:
        passport = {
            "passport_version": "0.1",
            "issued_at": "2026-03-14T00:00:00+00:00",
            "valid_until": "2027-03-14T00:00:00+00:00",
            "subject": {"name": "Test"},
            "claims": [{"claim_id": "C-001"}],
        }
        sig_result = {"signature_valid": True, "id_valid": True}
        d = extract_dimensions(passport, signature_result=sig_result)
        assert d.signature_valid is True
        assert d.content_hash_valid is True
        assert d.schema_valid is True
        assert d.freshness_status == "fresh"

    def test_extract_unsigned(self) -> None:
        passport = {
            "passport_version": "0.1",
            "issued_at": "2026-03-14T00:00:00+00:00",
            "valid_until": "2027-03-14T00:00:00+00:00",
            "subject": {"name": "Test"},
            "claims": [],
        }
        d = extract_dimensions(passport)
        assert d.signature_valid is None

    def test_extract_stale(self) -> None:
        passport = {
            "passport_version": "0.1",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "valid_until": "2025-01-02T00:00:00+00:00",
            "subject": {"name": "Test"},
            "claims": [],
        }
        d = extract_dimensions(passport)
        assert d.freshness_status == "stale"

    def test_extract_missing_required_fields(self) -> None:
        passport = {"passport_version": "0.1"}
        d = extract_dimensions(passport)
        assert d.schema_valid is False
