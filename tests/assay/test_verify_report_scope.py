"""Tests for the scope (Scope & Caveats) object in verify_report.json.

The scope object is the verifier boundary contract: a verdict must always
carry its boundary. PASS must not imply output correctness, safety, legal
compliance, policy fitness, instrumentation completeness, or signer authority
beyond configured trust.

This is local Assay verifier vocabulary, not estate-wide proof vocabulary.
"""
from __future__ import annotations

from assay.integrity import VerifyResult
from assay.manifest_schema import validate_verify_report
from assay.verify_report import (
    SCOPE_DOES_NOT_PROVE,
    SCOPE_PROVES_INTEGRITY,
    SCOPE_SCHEMA_VERSION,
    build_verify_report,
)

_SHA = "a" * 64


def _build(
    *,
    passed: bool = True,
    claim_check: str | None = None,
    replay_verdict: str = "NOT_RUN",
) -> dict:
    result = VerifyResult(passed=passed)
    return build_verify_report(
        verify_result=result,
        verified_at="2026-06-09T00:00:00+00:00",
        verifier_name="assay verify-pack",
        verifier_version="test",
        claim_check=claim_check,
        replay_verdict=replay_verdict,
        pack_root_sha256=_SHA,
        pack_manifest_sha256=_SHA,
    )


class TestScopePresence:
    def test_scope_present_on_pass(self):
        report = _build(passed=True)
        assert report["overall_verdict"] == "PASS"
        assert report["scope"]["schema"] == SCOPE_SCHEMA_VERSION

    def test_scope_present_on_honest_fail(self):
        report = _build(passed=True, claim_check="FAIL")
        assert report["overall_verdict"] == "HONEST_FAIL"
        assert report["scope"]["schema"] == SCOPE_SCHEMA_VERSION

    def test_scope_present_on_tampered(self):
        report = _build(passed=False)
        assert report["overall_verdict"] == "TAMPERED"
        assert report["scope"]["schema"] == SCOPE_SCHEMA_VERSION

    def test_report_validates_against_schema(self):
        for kwargs in (
            {"passed": True},
            {"passed": True, "claim_check": "FAIL"},
            {"passed": False},
        ):
            report = _build(**kwargs)
            errors = validate_verify_report(report)
            assert errors == [], f"schema errors for {kwargs}: {errors}"


class TestScopeBoundary:
    def test_pass_proves_integrity_facts_only(self):
        report = _build(passed=True)
        proves = report["scope"]["proves"]
        for item in SCOPE_PROVES_INTEGRITY:
            assert item in proves
        # No claim set evaluated -> no claim facts proven.
        assert "claim_set_satisfied" not in proves
        assert "claim_set_evaluated" not in proves

    def test_pass_never_implies_safety_or_fitness(self):
        report = _build(passed=True, claim_check="PASS")
        does_not_prove = report["scope"]["does_not_prove"]
        for item in SCOPE_DOES_NOT_PROVE:
            assert item in does_not_prove

    def test_claim_pass_adds_claim_facts(self):
        report = _build(passed=True, claim_check="PASS")
        proves = report["scope"]["proves"]
        assert "claim_set_evaluated" in proves
        assert "claim_set_satisfied" in proves

    def test_honest_fail_evaluated_but_not_satisfied(self):
        report = _build(passed=True, claim_check="FAIL")
        proves = report["scope"]["proves"]
        assert "claim_set_evaluated" in proves
        assert "claim_set_satisfied" not in proves
        # Integrity facts still proven: the evidence object is intact.
        for item in SCOPE_PROVES_INTEGRITY:
            assert item in proves


class TestScopeTampered:
    """A tampered pack must not over-speak.

    Integrity failed, so normal channel claims are unavailable; the only
    thing this run proves is that tampering was detected.
    """

    def test_tampered_proves_collapses(self):
        report = _build(passed=False)
        assert report["scope"]["proves"] == ["tamper_evidence_detected"]

    def test_tampered_does_not_prove_integrity_facts(self):
        report = _build(passed=False)
        does_not_prove = report["scope"]["does_not_prove"]
        for item in SCOPE_PROVES_INTEGRITY:
            assert item in does_not_prove
        for item in SCOPE_DOES_NOT_PROVE:
            assert item in does_not_prove

    def test_tampered_carries_explanatory_note(self):
        report = _build(passed=False)
        assert "not intact" in report["scope"]["note"]

    def test_tampered_overrides_claim_pass(self):
        # Even if the claim channel reported PASS, a tampered object cannot
        # support claim facts.
        report = _build(passed=False, claim_check="PASS")
        assert report["scope"]["proves"] == ["tamper_evidence_detected"]
        assert "claim_set_satisfied" not in report["scope"]["proves"]


class TestScopeChannels:
    def test_channels_reflect_not_run_honestly(self):
        report = _build(passed=True)
        channels = report["scope"]["channels"]
        assert channels["integrity"] == "ran"
        assert channels["claim"] == "not_evaluated"
        assert channels["replay"] == "not_run"
        assert channels["trust"] == "not_evaluated"

    def test_channels_reflect_ran(self):
        report = _build(passed=True, claim_check="PASS", replay_verdict="MATCH")
        channels = report["scope"]["channels"]
        assert channels["claim"] == "ran"
        assert channels["replay"] == "ran"

    def test_replay_match_adds_proof_only_when_run(self):
        report = _build(passed=True, replay_verdict="MATCH")
        assert "replay_match" in report["scope"]["proves"]
        report = _build(passed=True, replay_verdict="NOT_RUN")
        assert "replay_match" not in report["scope"]["proves"]

    def test_scope_consistent_with_unevaluated_channels(self):
        # Scope restates existing channel truth; it must not contradict it.
        report = _build(passed=True)
        for channel in report["unevaluated_channels"]:
            assert report["scope"]["channels"][channel] in (
                "not_run",
                "not_evaluated",
            )


class TestScopeExtensions:
    def test_extensions_reserved_and_empty(self):
        """`extensions` is reserved and non-normative.

        It exists only as a future extension point; the core verifier ignores
        it. No extension vocabulary (SIGIL, proof tiers, authority ladders,
        etc.) is defined here.
        """
        for kwargs in ({"passed": True}, {"passed": False}):
            report = _build(**kwargs)
            assert report["scope"]["extensions"] == {}

    def test_report_id_unaffected_by_scope(self):
        # report_id is seeded from verdicts and metadata only; adding scope
        # must not change identity semantics.
        a = _build(passed=True)
        b = _build(passed=True)
        assert a["report_id"] == b["report_id"]
