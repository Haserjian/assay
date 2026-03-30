"""Tests for the comparability engine.

Covers:
  - Match rules (exact, content_hash, version_match, within_threshold)
  - Canonicalization
  - Contract loading and validation
  - Evidence bundle loading and completeness
  - Denial engine: SATISFIED, DENIED, DOWNGRADED, UNDETERMINED
  - Instrument continuity
  - Consequence derivation
  - Conformance matrix (dirty cases from spec)
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any, Dict

import pytest

from assay.comparability.bundle import EvidenceBundle
from assay.comparability.canonicalize import canonicalize_content, content_hash
from assay.comparability.contract import (
    ComparabilityContract,
    ContractValidationError,
    ParityField,
    load_contract,
)
from assay.comparability.engine import evaluate
from assay.comparability.match_rules import apply_rule, available_rules
from assay.comparability.types import (
    ClaimStatus,
    ClaimUnderTest,
    FieldRequirement,
    InstrumentContinuity,
    ParityFieldGroup,
    Severity,
    Verdict,
)


# ---------------------------------------------------------------------------
# Fixtures: a minimal contract and matching bundles
# ---------------------------------------------------------------------------

def _make_contract(**overrides: Any) -> ComparabilityContract:
    """Build a minimal judge comparability contract for testing."""
    fields = overrides.pop("parity_fields", None) or [
        ParityField(
            field="judge_model",
            match_rule="exact",
            severity=Severity.INVALIDATING,
            group=ParityFieldGroup.INSTRUMENT_IDENTITY,
            rationale="Different models = different instrument.",
        ),
        ParityField(
            field="judge_model_version",
            match_rule="exact",
            severity=Severity.INVALIDATING,
            group=ParityFieldGroup.INSTRUMENT_IDENTITY,
            rationale="Version change = instrument change.",
        ),
        ParityField(
            field="judge_prompt_template",
            match_rule="content_hash",
            severity=Severity.INVALIDATING,
            group=ParityFieldGroup.INSTRUMENT_IDENTITY,
            rationale="Prompt change = criteria change.",
        ),
        ParityField(
            field="judge_temperature",
            match_rule="exact",
            severity=Severity.INVALIDATING,
            group=ParityFieldGroup.EXECUTION_PARAMS,
            rationale="Temperature affects distribution.",
        ),
        ParityField(
            field="judge_max_tokens",
            match_rule="exact",
            severity=Severity.DEGRADING,
            group=ParityFieldGroup.EXECUTION_PARAMS,
            rationale="May truncate reasoning.",
        ),
        ParityField(
            field="presentation_order",
            match_rule="exact",
            severity=Severity.DEGRADING,
            group=ParityFieldGroup.EVAL_SURFACE,
            rationale="Position bias.",
        ),
    ]
    defaults = dict(
        contract_id="test-contract-001",
        name="Test Judge Contract",
        version="0.1.0",
        domain="llm_as_judge",
        parity_fields=fields,
    )
    defaults.update(overrides)
    return ComparabilityContract(**defaults)


def _make_bundle(
    overrides: Dict[str, Any] | None = None,
    **kwargs: Any,
) -> EvidenceBundle:
    """Build a clean evidence bundle with all fields matching the test contract."""
    fields = {
        "judge_model": "gpt-4o",
        "judge_model_version": "gpt-4o-2024-08-06",
        "judge_prompt_template": "Rate the response on helpfulness from 1-5.\n",
        "judge_temperature": 0.0,
        "judge_max_tokens": 1024,
        "presentation_order": "fixed",
    }
    if overrides:
        fields.update(overrides)
    defaults = dict(
        fields=fields,
        label="test-bundle",
        ref="test/pack",
    )
    defaults.update(kwargs)
    return EvidenceBundle(**defaults)


# ===================================================================
# Match rules
# ===================================================================

class TestMatchRules:
    def test_exact_match(self):
        assert apply_rule("exact", "gpt-4o", "gpt-4o") is True

    def test_exact_mismatch(self):
        assert apply_rule("exact", "gpt-4o", "gpt-4o-mini") is False

    def test_exact_numeric(self):
        assert apply_rule("exact", 0.0, 0.0) is True
        assert apply_rule("exact", 0.0, 0.3) is False

    def test_exact_bool(self):
        assert apply_rule("exact", True, True) is True
        assert apply_rule("exact", True, False) is False

    def test_content_hash_identical_content(self):
        assert apply_rule("content_hash", "hello world\n", "hello world\n") is True

    def test_content_hash_different_content(self):
        assert apply_rule("content_hash", "hello\n", "goodbye\n") is False

    def test_content_hash_whitespace_normalization(self):
        # Trailing newline normalization makes these match
        assert apply_rule("content_hash", "hello", "hello\n") is True

    def test_content_hash_crlf_normalization(self):
        assert apply_rule("content_hash", "line1\nline2\n", "line1\r\nline2\r\n") is True

    def test_content_hash_precomputed(self):
        h = content_hash("hello world\n")
        assert apply_rule("content_hash", h, h) is True

    def test_content_hash_mixed_mode_rejected(self):
        """Mixed raw/hash representation must NEVER satisfy — prevents spoofing."""
        h = content_hash("hello world")
        # Attacker supplies pre-hash of baseline content; candidate is raw
        assert apply_rule("content_hash", h, "hello world") is False
        # Reverse direction: raw baseline, pre-hash candidate
        assert apply_rule("content_hash", "hello world", h) is False

    def test_content_hash_attacker_prehash_spoof(self):
        """Attacker pre-computes hash of baseline prompt and injects it."""
        baseline_prompt = "You are a careful, strict judge..."
        attacker_value = content_hash(baseline_prompt)
        # This is the exact attack: candidate presents the hash, not the content
        assert apply_rule("content_hash", baseline_prompt, attacker_value) is False
        assert apply_rule("content_hash", attacker_value, baseline_prompt) is False

    def test_content_hash_same_representation_still_works(self):
        """Both raw or both hash still compare correctly."""
        # raw vs raw: identical
        assert apply_rule("content_hash", "same content", "same content") is True
        # raw vs raw: different
        assert apply_rule("content_hash", "content A", "content B") is False
        # hash vs hash: identical
        h = content_hash("test")
        assert apply_rule("content_hash", h, h) is True
        # hash vs hash: different
        h2 = content_hash("other")
        assert apply_rule("content_hash", h, h2) is False

    def test_content_hash_case_insensitive_hex(self):
        """SHA-256 hex comparison must be case-insensitive."""
        lower = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        upper = "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
        mixed = "sha256:AbCdEf0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789"
        assert apply_rule("content_hash", lower, upper) is True
        assert apply_rule("content_hash", lower, mixed) is True

    def test_content_hash_malformed_hash_rejected(self):
        """Pre-computed hashes must be valid format (sha256: + 64 hex chars)."""
        # Too short
        short = "sha256:deadbeef"
        assert apply_rule("content_hash", short, short) is False
        # Not hex
        bad_hex = "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        assert apply_rule("content_hash", bad_hex, bad_hex) is False
        # Correct format works
        valid = "sha256:deadbeef00000000000000000000000000000000000000000000000000000000"
        assert apply_rule("content_hash", valid, valid) is True

    def test_version_match(self):
        assert apply_rule("version_match", "1.2.3", "1.2.3") is True
        assert apply_rule("version_match", "1.2.3", "1.2.4") is False

    def test_version_match_strips_whitespace(self):
        assert apply_rule("version_match", " 1.2.3 ", "1.2.3") is True

    def test_within_threshold_pass(self):
        assert apply_rule("within_threshold", 0.0, 0.05, threshold=0.1) is True

    def test_within_threshold_fail(self):
        assert apply_rule("within_threshold", 0.0, 0.5, threshold=0.1) is False

    def test_within_threshold_no_threshold_falls_back_exact(self):
        assert apply_rule("within_threshold", 0.0, 0.0) is True
        assert apply_rule("within_threshold", 0.0, 0.1) is False

    def test_unknown_rule_raises(self):
        with pytest.raises(KeyError, match="Unknown match rule"):
            apply_rule("nonexistent", "a", "b")

    def test_available_rules(self):
        rules = available_rules()
        assert "exact" in rules
        assert "content_hash" in rules
        assert "version_match" in rules
        assert "within_threshold" in rules


# ===================================================================
# Canonicalization
# ===================================================================

class TestCanonicalization:
    def test_crlf_to_lf(self):
        result = canonicalize_content("a\r\nb\r\n")
        assert result == b"a\nb\n"

    def test_bare_cr_to_lf(self):
        result = canonicalize_content("a\rb\r")
        assert result == b"a\nb\n"

    def test_trailing_newline_added(self):
        result = canonicalize_content("hello")
        assert result == b"hello\n"

    def test_trailing_newlines_collapsed(self):
        result = canonicalize_content("hello\n\n\n")
        assert result == b"hello\n"

    def test_bytes_input(self):
        result = canonicalize_content(b"hello\r\n")
        assert result == b"hello\n"

    def test_content_hash_deterministic(self):
        h1 = content_hash("hello world")
        h2 = content_hash("hello world\n")
        h3 = content_hash("hello world\r\n")
        assert h1 == h2 == h3

    def test_content_hash_format(self):
        h = content_hash("test")
        assert h.startswith("sha256:")
        assert len(h) == 7 + 64  # "sha256:" + 64 hex chars


# ===================================================================
# Contract loading
# ===================================================================

class TestContractLoading:
    def test_load_yaml_contract(self, tmp_path: Path):
        contract_path = tmp_path / "test.yaml"
        contract_path.write_text(textwrap.dedent("""\
            comparability_contract:
              version: "0.1.0"
              id: "test-001"
              name: "Test Contract"
              domain: "llm_as_judge"
              scope:
                description: "Test scope"
                metric_family: "test"
              parity_fields:
                - field: judge_model
                  match_rule: exact
                  severity: INVALIDATING
                  group: instrument_identity
                  rationale: "Models differ"
                - field: judge_max_tokens
                  match_rule: exact
                  severity: DEGRADING
                  group: execution_params
                  rationale: "May truncate"
              outcomes:
                SATISFIED: "All match"
                DENIED: "Mismatch"
              out_of_scope:
                - "Statistical significance"
        """))

        contract = load_contract(contract_path)
        assert contract.name == "Test Contract"
        assert contract.contract_id == "test-001"
        assert len(contract.parity_fields) == 2
        assert contract.parity_fields[0].severity == Severity.INVALIDATING
        assert contract.parity_fields[1].severity == Severity.DEGRADING
        assert contract.parity_fields[0].group == ParityFieldGroup.INSTRUMENT_IDENTITY
        assert len(contract.out_of_scope) == 1

    def test_load_json_contract(self, tmp_path: Path):
        contract_path = tmp_path / "test.json"
        contract_path.write_text(json.dumps({
            "name": "JSON Contract",
            "parity_fields": [
                {
                    "field": "judge_model",
                    "match_rule": "exact",
                    "severity": "INVALIDATING",
                    "group": "instrument_identity",
                    "rationale": "Models differ",
                }
            ],
        }))

        contract = load_contract(contract_path)
        assert contract.name == "JSON Contract"
        assert len(contract.parity_fields) == 1

    def test_missing_file_raises(self):
        with pytest.raises(ContractValidationError, match="not found"):
            load_contract("/nonexistent/contract.yaml")

    def test_missing_name_raises(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"parity_fields": []}))
        with pytest.raises(ContractValidationError, match="missing required field"):
            load_contract(p)

    def test_unknown_rule_raises(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({
            "name": "Bad",
            "parity_fields": [
                {"field": "x", "match_rule": "magic", "severity": "INVALIDATING"}
            ],
        }))
        with pytest.raises(ContractValidationError, match="unknown match_rule"):
            load_contract(p)

    def test_required_field_names(self):
        contract = _make_contract()
        names = contract.required_field_names()
        assert "judge_model" in names
        assert "judge_temperature" in names

    def test_fields_by_group(self):
        contract = _make_contract()
        groups = contract.fields_by_group()
        assert ParityFieldGroup.INSTRUMENT_IDENTITY in groups
        assert ParityFieldGroup.EXECUTION_PARAMS in groups
        assert ParityFieldGroup.EVAL_SURFACE in groups

    def test_instrument_identity_fields(self):
        contract = _make_contract()
        fields = contract.instrument_identity_fields()
        names = [f.field for f in fields]
        assert "judge_model" in names
        assert "judge_model_version" in names
        assert "judge_prompt_template" in names
        assert "judge_temperature" not in names

    def test_load_real_contract(self):
        """Load the actual judge-comparability-v1.yaml from the repo."""
        contract_path = Path(__file__).parent.parent.parent / "contracts" / "judge-comparability-v1.yaml"
        if not contract_path.exists():
            pytest.skip("Real contract file not found")
        contract = load_contract(contract_path)
        assert contract.name == "LLM-as-Judge Comparability v1"
        assert len(contract.parity_fields) == 15
        assert contract.domain == "llm_as_judge"


# ===================================================================
# Evidence bundle
# ===================================================================

class TestEvidenceBundle:
    def test_get_field(self):
        bundle = _make_bundle()
        assert bundle.get("judge_model") == "gpt-4o"
        assert bundle.get("nonexistent") is None

    def test_has_field(self):
        bundle = _make_bundle()
        assert bundle.has("judge_model") is True
        assert bundle.has("nonexistent") is False

    def test_completeness_complete(self):
        bundle = _make_bundle()
        c = bundle.completeness(["judge_model", "judge_temperature"])
        assert c.status == "COMPLETE"
        assert c.missing_fields == []

    def test_completeness_incomplete(self):
        bundle = _make_bundle()
        c = bundle.completeness(["judge_model", "missing_field"])
        assert c.status == "INCOMPLETE"
        assert "missing_field" in c.missing_fields

    def test_config_divergence(self):
        bundle = EvidenceBundle(
            fields={"judge_model": "gpt-4o"},
            requested_config={"judge_model": "gpt-4o-mini"},
            executed_config={"judge_model": "gpt-4o"},
        )
        assert bundle.config_diverged("judge_model") is True

    def test_config_no_divergence(self):
        bundle = EvidenceBundle(
            fields={"judge_model": "gpt-4o"},
            requested_config={"judge_model": "gpt-4o"},
            executed_config={"judge_model": "gpt-4o"},
        )
        assert bundle.config_diverged("judge_model") is False

    def test_diverged_fields(self):
        bundle = EvidenceBundle(
            fields={},
            requested_config={"a": 1, "b": 2, "c": 3},
            executed_config={"a": 1, "b": 99, "c": 3},
        )
        assert bundle.diverged_fields() == ["b"]

    def test_field_source_provenance(self):
        bundle = EvidenceBundle(
            fields={"judge_model": "gpt-4o"},
            field_sources={"judge_model": "env:OPENAI_MODEL"},
        )
        source = bundle.get_source("judge_model")
        assert source is not None
        assert source.source == "env:OPENAI_MODEL"
        assert source.method == "declared"

    def test_load_bundle_json(self, tmp_path: Path):
        from assay.comparability.bundle import load_bundle

        p = tmp_path / "evidence_bundle.json"
        p.write_text(json.dumps({
            "label": "test run",
            "ref": "packs/baseline",
            "fields": {"judge_model": "gpt-4o", "judge_temperature": 0.0},
            "field_sources": {"judge_model": "config:eval.yaml"},
        }))
        bundle = load_bundle(p)
        assert bundle.label == "test run"
        assert bundle.get("judge_model") == "gpt-4o"
        assert bundle.field_sources["judge_model"] == "config:eval.yaml"

    def test_to_dict(self):
        bundle = _make_bundle()
        d = bundle.to_dict()
        assert "fields" in d
        assert d["fields"]["judge_model"] == "gpt-4o"


# ===================================================================
# Denial engine: verdict cases
# ===================================================================

class TestDenialEngine:
    """Core denial engine tests — the conformance matrix."""

    def test_satisfied_clean_pair(self):
        """All fields match → SATISFIED."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle()

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.SATISFIED
        assert diff.consequence.claim_status == ClaimStatus.ADMISSIBLE
        assert len(diff.mismatches) == 0
        assert len(diff.satisfied_fields) == 6
        assert diff.instrument_continuity == InstrumentContinuity.PRESERVED
        assert diff.exit_code == 0

    def test_denied_model_change(self):
        """Judge model changed → DENIED (INVALIDATING)."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_model": "gpt-4o-mini"})

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DENIED
        assert diff.consequence.claim_status == ClaimStatus.INADMISSIBLE
        assert len(diff.mismatches) == 1
        assert diff.mismatches[0].field == "judge_model"
        assert diff.mismatches[0].severity == Severity.INVALIDATING
        assert diff.instrument_continuity == InstrumentContinuity.BROKEN
        assert diff.exit_code == 1

    def test_denied_model_version_drift(self):
        """Model version changed via env var → DENIED."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_model_version": "gpt-4o-2024-11-20"})

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DENIED
        assert diff.instrument_continuity == InstrumentContinuity.BROKEN

    def test_denied_prompt_template_edit(self):
        """Prompt template changed → DENIED (content_hash mismatch)."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({
            "judge_prompt_template": "Rate helpfulness 1-5. Be lenient with formatting.\n"
        })

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DENIED
        assert any(m.field == "judge_prompt_template" for m in diff.mismatches)

    def test_denied_temperature_change(self):
        """Temperature changed → DENIED."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_temperature": 0.3})

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DENIED

    def test_downgraded_degrading_only(self):
        """Only DEGRADING mismatches → DOWNGRADED."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_max_tokens": 2048})

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DOWNGRADED
        assert diff.consequence.claim_status == ClaimStatus.ADMISSIBLE_WITH_CAVEAT
        assert "attach_mismatch_disclosure" in diff.consequence.required_actions
        assert diff.exit_code == 1

    def test_downgraded_multiple_degrading(self):
        """Multiple DEGRADING mismatches → still DOWNGRADED."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({
            "judge_max_tokens": 2048,
            "presentation_order": "randomized",
        })

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DOWNGRADED
        assert len(diff.mismatches) == 2

    def test_denied_beats_degrading(self):
        """INVALIDATING + DEGRADING → DENIED (not DOWNGRADED)."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({
            "judge_model": "claude-3.5-sonnet",  # INVALIDATING
            "judge_max_tokens": 2048,              # DEGRADING
        })

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DENIED
        assert len(diff.mismatches) == 2

    def test_undetermined_missing_fields(self):
        """Required fields missing → UNDETERMINED."""
        contract = _make_contract()
        baseline = _make_bundle()
        # Candidate missing judge_model and judge_model_version
        candidate = EvidenceBundle(
            fields={
                "judge_prompt_template": "Rate the response on helpfulness from 1-5.\n",
                "judge_temperature": 0.0,
                "judge_max_tokens": 1024,
                "presentation_order": "fixed",
            },
        )

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.UNDETERMINED
        assert diff.consequence.claim_status == ClaimStatus.PENDING_REVIEW
        assert diff.exit_code == 2

    def test_denied_trumps_missing(self):
        """INVALIDATING mismatch + missing fields → DENIED (not UNDETERMINED).

        Once you know the comparison is invalid, the honest answer is DENIED,
        not "we can't tell."
        """
        contract = _make_contract()
        baseline = _make_bundle()
        # Candidate: model changed (INVALIDATING) + version missing
        candidate = EvidenceBundle(
            fields={
                "judge_model": "different-model",  # INVALIDATING mismatch
                "judge_prompt_template": "Rate the response on helpfulness from 1-5.\n",
                "judge_temperature": 0.0,
                "judge_max_tokens": 1024,
                "presentation_order": "fixed",
                # judge_model_version is missing
            },
        )

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.DENIED

    def test_undetermined_missing_plus_degrading(self):
        """Missing fields + DEGRADING mismatch → UNDETERMINED.

        Can't be confident in DOWNGRADED when picture is incomplete.
        """
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = EvidenceBundle(
            fields={
                "judge_prompt_template": "Rate the response on helpfulness from 1-5.\n",
                "judge_temperature": 0.0,
                "judge_max_tokens": 2048,  # DEGRADING mismatch
                "presentation_order": "fixed",
                # judge_model and judge_model_version missing
            },
        )

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict == Verdict.UNDETERMINED


# ===================================================================
# Instrument continuity
# ===================================================================

class TestInstrumentContinuity:
    def test_preserved_when_all_match(self):
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle()

        diff = evaluate(contract, baseline, candidate)

        assert diff.instrument_continuity == InstrumentContinuity.PRESERVED

    def test_broken_when_instrument_field_mismatches(self):
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_model": "different"})

        diff = evaluate(contract, baseline, candidate)

        assert diff.instrument_continuity == InstrumentContinuity.BROKEN

    def test_unknown_when_instrument_field_missing(self):
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = EvidenceBundle(
            fields={
                "judge_temperature": 0.0,
                "judge_max_tokens": 1024,
                "presentation_order": "fixed",
            },
        )

        diff = evaluate(contract, baseline, candidate)

        assert diff.instrument_continuity == InstrumentContinuity.UNKNOWN

    def test_broken_not_affected_by_execution_param_mismatch(self):
        """Execution param mismatch should not break instrument continuity."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_max_tokens": 2048})  # DEGRADING, execution_params

        diff = evaluate(contract, baseline, candidate)

        assert diff.instrument_continuity == InstrumentContinuity.PRESERVED


# ===================================================================
# Bundle completeness
# ===================================================================

class TestBundleCompleteness:
    def test_both_complete(self):
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle()

        diff = evaluate(contract, baseline, candidate)

        assert diff.baseline_completeness.status == "COMPLETE"
        assert diff.candidate_completeness.status == "COMPLETE"

    def test_candidate_incomplete(self):
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = EvidenceBundle(fields={"judge_model": "gpt-4o"})

        diff = evaluate(contract, baseline, candidate)

        assert diff.candidate_completeness.status == "INCOMPLETE"
        assert len(diff.candidate_completeness.missing_fields) > 0


# ===================================================================
# Consequence derivation
# ===================================================================

class TestConsequence:
    def test_satisfied_consequence(self):
        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())

        assert diff.consequence.claim_status == ClaimStatus.ADMISSIBLE
        assert diff.consequence.blocked_actions == []
        assert diff.consequence.required_actions == []

    def test_denied_consequence(self):
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_model": "different"}),
        )

        assert diff.consequence.claim_status == ClaimStatus.INADMISSIBLE
        assert "promotion" in diff.consequence.blocked_actions
        assert "rerun_under_pinned_config" in diff.consequence.required_actions

    def test_downgraded_consequence(self):
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_max_tokens": 2048}),
        )

        assert diff.consequence.claim_status == ClaimStatus.ADMISSIBLE_WITH_CAVEAT
        assert "report_without_caveat" in diff.consequence.blocked_actions

    def test_undetermined_consequence(self):
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            EvidenceBundle(fields={}),
        )

        assert diff.consequence.claim_status == ClaimStatus.PENDING_REVIEW
        assert "complete_evidence_bundle" in diff.consequence.required_actions


# ===================================================================
# Claim under test
# ===================================================================

class TestClaimUnderTest:
    def test_claim_attached_to_diff(self):
        contract = _make_contract()
        claim = ClaimUnderTest(
            claim_type="improvement",
            summary="candidate scores 11.1% higher on helpfulness",
            metric="mean_helpfulness_score",
            delta=0.42,
            direction="higher_is_better",
        )

        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle(),
            claim=claim,
        )

        assert diff.claim is not None
        assert diff.claim.summary == "candidate scores 11.1% higher on helpfulness"
        assert diff.claim.delta == 0.42


# ===================================================================
# Serialization
# ===================================================================

class TestSerialization:
    def test_constitutional_diff_to_dict(self):
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(label="baseline run"),
            _make_bundle({"judge_model": "different"}, label="candidate run"),
        )

        d = diff.to_dict()
        cd = d["constitutional_diff"]

        assert cd["version"] == "0.1.0"
        assert cd["comparability"]["verdict"] == "DENIED"
        assert len(cd["comparability"]["mismatches"]) >= 1
        assert cd["consequence"]["claim_status"] == "INADMISSIBLE"
        assert cd["entities"]["baseline"]["label"] == "baseline run"
        assert cd["entities"]["candidate"]["label"] == "candidate run"

    def test_diff_json_roundtrip(self):
        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())

        d = diff.to_dict()
        # Should be JSON-serializable
        serialized = json.dumps(d, indent=2)
        parsed = json.loads(serialized)
        assert parsed["constitutional_diff"]["comparability"]["verdict"] == "SATISFIED"

    def test_contract_to_dict(self):
        contract = _make_contract()
        d = contract.to_dict()
        cc = d["comparability_contract"]
        assert cc["name"] == "Test Judge Contract"
        assert len(cc["parity_fields"]) == 6

    def test_diff_structural_demotion_fields(self):
        """ConstitutionalDiff must carry non-authoritative labeling.

        This is a constitutional invariant: the diff is a diagnostic view,
        not evidence. These fields must never be removed or promoted.
        See OCD-13 decision record.
        """
        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())
        cd = diff.to_dict()["constitutional_diff"]

        assert cd["artifact_class"] == "diagnostic_diff"
        assert cd["evidence_status"] == "not_signed_not_authoritative"
        assert cd["verifier_action"] == "refer_to_signed_receipt"
        assert cd["authority_source_type"] == "comparability_verdict_receipt"
        assert cd["authority_container"] == "proof_pack"

    def test_diff_field_allowlist(self):
        """ConstitutionalDiff top-level keys must not grow authority-bearing fields.

        If a new field is added, this test forces a conscious decision.
        Authority-bearing names (signature, attestation, verified_by, etc.)
        cannot appear without breaking this test.
        """
        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())
        cd = diff.to_dict()["constitutional_diff"]

        ALLOWED_KEYS = {
            # Demotion / authority demarcation
            "artifact_class", "evidence_status", "verifier_action",
            "authority_source_type", "authority_container",
            # Identity
            "version", "diff_id", "created_at",
            # Content
            "entities", "comparability", "lineage",
            # Optional context
            "claim", "consequence",
            "baseline_completeness", "candidate_completeness",
        }

        actual_keys = set(cd.keys())
        unexpected = actual_keys - ALLOWED_KEYS
        assert not unexpected, (
            f"Unexpected keys in constitutional_diff: {unexpected}. "
            f"If intentional, add to ALLOWED_KEYS. If authority-bearing "
            f"(signature, attestation, verified_by, etc.), this violates OCD-13."
        )

    def test_diff_has_no_authority_bearing_fields(self):
        """ConstitutionalDiff must never carry signature or attestation fields.

        Broader than the allowlist: explicitly rejects a set of names that
        would imply evidence status regardless of where they appear.
        """
        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())
        cd = diff.to_dict()["constitutional_diff"]

        FORBIDDEN = {
            "signature", "signed_by", "signer_id", "signer_pubkey",
            "signer_pubkey_sha256", "attestation", "verified_by",
            "receipt", "receipt_id", "authority_signature",
        }
        found = FORBIDDEN & set(cd.keys())
        assert not found, (
            f"Authority-bearing fields found in diagnostic diff: {found}. "
            f"This violates OCD-13: the diff is not evidence."
        )

    def test_diff_carries_contract_hash(self):
        """Contract hash must be present for informational linkage."""
        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())
        cd = diff.to_dict()["constitutional_diff"]

        assert "contract_hash" in cd["lineage"]
        assert cd["lineage"]["contract_hash"].startswith("sha256:")


# ===================================================================
# Conformance matrix: dirty cases from spec
# ===================================================================

class TestConformanceMatrix:
    """Each case maps to a row in the spec's case law table."""

    def test_env_var_model_drift(self):
        """Model version drifts via env var → DENIED."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_model_version": "gpt-4o-2024-11-20"}),
        )
        assert diff.verdict == Verdict.DENIED
        assert diff.instrument_continuity == InstrumentContinuity.BROKEN

    def test_prompt_template_minor_edit(self):
        """'Minor' prompt edit → DENIED. No minor edit to a measurement instrument."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({
                "judge_prompt_template": "Rate the response on helpfulness from 1-5. Be lenient.\n"
            }),
        )
        assert diff.verdict == Verdict.DENIED

    def test_temperature_style_preference(self):
        """Temperature 0.0 vs 0.3 'for style' → DENIED."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_temperature": 0.3}),
        )
        assert diff.verdict == Verdict.DENIED

    def test_dataset_renamed_same_hash(self):
        """Dataset file renamed but content identical → SATISFIED.

        content_hash rule means identity is content-addressed, not name-addressed.
        """
        prompt = "Rate the response on helpfulness from 1-5.\n"
        contract = _make_contract()
        # Both have the same content, just use the hash
        h = content_hash(prompt)
        diff = evaluate(
            contract,
            _make_bundle({"judge_prompt_template": h}),
            _make_bundle({"judge_prompt_template": h}),
        )
        assert diff.verdict == Verdict.SATISFIED

    def test_dataset_same_name_changed_hash(self):
        """Dataset same name but different content → DENIED."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle({"judge_prompt_template": "Version A of the prompt.\n"}),
            _make_bundle({"judge_prompt_template": "Version B of the prompt.\n"}),
        )
        assert diff.verdict == Verdict.DENIED

    def test_missing_model_version(self):
        """Model version field missing → UNDETERMINED."""
        contract = _make_contract()
        fields = dict(_make_bundle().fields)
        del fields["judge_model_version"]
        candidate = EvidenceBundle(fields=fields)

        diff = evaluate(contract, _make_bundle(), candidate)

        # Missing instrument field, no mismatches → UNDETERMINED
        assert diff.verdict == Verdict.UNDETERMINED
        assert diff.instrument_continuity == InstrumentContinuity.UNKNOWN

    def test_missing_prompt_file(self):
        """Prompt template missing from bundle → UNDETERMINED."""
        contract = _make_contract()
        fields = dict(_make_bundle().fields)
        del fields["judge_prompt_template"]
        candidate = EvidenceBundle(fields=fields)

        diff = evaluate(contract, _make_bundle(), candidate)

        assert diff.verdict == Verdict.UNDETERMINED

    def test_temperature_drift_only(self):
        """Only temperature changed → DENIED (INVALIDATING in v0)."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_temperature": 0.1}),
        )
        assert diff.verdict == Verdict.DENIED

    def test_max_tokens_only(self):
        """Only max_tokens changed → DOWNGRADED (DEGRADING)."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_max_tokens": 512}),
        )
        assert diff.verdict == Verdict.DOWNGRADED

    def test_presentation_order_only(self):
        """Only presentation_order changed → DOWNGRADED."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"presentation_order": "randomized"}),
        )
        assert diff.verdict == Verdict.DOWNGRADED

    def test_multiple_invalidating(self):
        """Multiple INVALIDATING mismatches → DENIED with all listed."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({
                "judge_model": "claude-3-opus",
                "judge_model_version": "claude-3-opus-20240229",
                "judge_temperature": 0.5,
            }),
        )
        assert diff.verdict == Verdict.DENIED
        invalidating = [m for m in diff.mismatches if m.severity == Severity.INVALIDATING]
        assert len(invalidating) == 3

    def test_empty_candidate_bundle(self):
        """Completely empty candidate → UNDETERMINED."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            EvidenceBundle(fields={}),
        )
        assert diff.verdict == Verdict.UNDETERMINED
        assert diff.candidate_completeness.status == "INCOMPLETE"

    def test_both_bundles_empty(self):
        """Both bundles empty → UNDETERMINED."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            EvidenceBundle(fields={}),
            EvidenceBundle(fields={}),
        )
        assert diff.verdict == Verdict.UNDETERMINED


# ===================================================================
# P1 regression: null values must not produce false SATISFIED
# ===================================================================

class TestNullEvidenceHandling:
    """Null values on required parity fields are missing evidence, not present."""

    def test_has_returns_false_for_none(self):
        """has() must return False when stored value is None."""
        bundle = EvidenceBundle(fields={"judge_model": None})
        assert bundle.has("judge_model") is False

    def test_has_returns_false_for_absent(self):
        bundle = EvidenceBundle(fields={})
        assert bundle.has("judge_model") is False

    def test_has_returns_true_for_real_value(self):
        bundle = EvidenceBundle(fields={"judge_model": "gpt-4o"})
        assert bundle.has("judge_model") is True

    def test_has_returns_true_for_falsy_non_none(self):
        """Zero, empty string, False are present evidence (domain-dependent).

        Guards against future 'helpful' refactors that change has() to bool(value).
        Temperature 0.0 is the most common real-world falsy-but-valid value.
        """
        bundle = EvidenceBundle(fields={"x": 0, "y": "", "z": False, "t": 0.0})
        assert bundle.has("x") is True
        assert bundle.has("y") is True
        assert bundle.has("z") is True
        assert bundle.has("t") is True

    def test_null_both_sides_not_satisfied(self):
        """Both sides null on required field → UNDETERMINED, not SATISFIED."""
        contract = _make_contract()
        baseline = _make_bundle({"judge_model": None})
        candidate = _make_bundle({"judge_model": None})

        diff = evaluate(contract, baseline, candidate)

        assert diff.verdict != Verdict.SATISFIED
        assert diff.verdict == Verdict.UNDETERMINED

    def test_baseline_value_candidate_null(self):
        """Baseline has value, candidate null → field reported missing."""
        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_model": None})

        diff = evaluate(contract, baseline, candidate)

        # judge_model is missing from candidate, so not SATISFIED
        assert diff.verdict != Verdict.SATISFIED
        assert "judge_model" not in diff.satisfied_fields

    def test_completeness_treats_null_as_missing(self):
        """Bundle completeness must treat null values as missing."""
        bundle = EvidenceBundle(fields={"judge_model": None, "judge_temperature": 0.0})
        c = bundle.completeness(["judge_model", "judge_temperature"])
        assert c.status == "INCOMPLETE"
        assert "judge_model" in c.missing_fields

    def test_get_still_returns_none(self):
        """get() returns the raw value (None) — only has() is semantic."""
        bundle = EvidenceBundle(fields={"judge_model": None})
        assert bundle.get("judge_model") is None


# ===================================================================
# P1 regression: empty/null contract documents
# ===================================================================

class TestContractFailClosed:
    """Malformed contract files must produce ContractValidationError, not raw tracebacks."""

    def test_empty_yaml(self, tmp_path: Path):
        p = tmp_path / "empty.yaml"
        p.write_text("")
        with pytest.raises(ContractValidationError, match="empty"):
            load_contract(p)

    def test_null_yaml(self, tmp_path: Path):
        p = tmp_path / "null.yaml"
        p.write_text("null\n")
        with pytest.raises(ContractValidationError, match="empty"):
            load_contract(p)

    def test_yaml_root_is_list(self, tmp_path: Path):
        p = tmp_path / "list.yaml"
        p.write_text("- item1\n- item2\n")
        with pytest.raises(ContractValidationError, match="mapping"):
            load_contract(p)

    def test_yaml_root_is_string(self, tmp_path: Path):
        p = tmp_path / "string.yaml"
        p.write_text('"just a string"\n')
        with pytest.raises(ContractValidationError, match="mapping"):
            load_contract(p)

    def test_yaml_root_is_number(self, tmp_path: Path):
        p = tmp_path / "number.yaml"
        p.write_text("42\n")
        with pytest.raises(ContractValidationError, match="mapping"):
            load_contract(p)

    def test_json_null(self, tmp_path: Path):
        p = tmp_path / "null.json"
        p.write_text("null")
        with pytest.raises(ContractValidationError, match="empty"):
            load_contract(p)

    def test_json_root_is_list(self, tmp_path: Path):
        p = tmp_path / "list.json"
        p.write_text("[]")
        with pytest.raises(ContractValidationError, match="mapping"):
            load_contract(p)

    def test_empty_parity_fields_rejected(self, tmp_path: Path):
        """A contract with parity_fields: [] is a constitutional nullification."""
        p = tmp_path / "empty_fields.yaml"
        p.write_text("name: empty\nparity_fields: []\n")
        with pytest.raises(ContractValidationError, match="empty parity_fields"):
            load_contract(p)


# ===================================================================
# P2 regression: contract schema strictness
# ===================================================================

class TestContractStrictness:
    """Contract loader must not silently coerce or accept structural errors."""

    def test_invalid_requirement_raises(self, tmp_path: Path):
        """requirement: maybe must raise, not coerce to REQUIRED."""
        p = tmp_path / "bad_req.json"
        p.write_text(json.dumps({
            "name": "Bad",
            "parity_fields": [{
                "field": "judge_model",
                "match_rule": "exact",
                "severity": "INVALIDATING",
                "requirement": "maybe",
            }],
        }))
        with pytest.raises(ContractValidationError, match="Invalid requirement"):
            load_contract(p)

    def test_duplicate_field_raises(self, tmp_path: Path):
        """Duplicate field declarations must raise."""
        p = tmp_path / "dup.json"
        p.write_text(json.dumps({
            "name": "Dup",
            "parity_fields": [
                {"field": "judge_model", "match_rule": "exact", "severity": "INVALIDATING"},
                {"field": "judge_model", "match_rule": "exact", "severity": "DEGRADING"},
            ],
        }))
        with pytest.raises(ContractValidationError, match="duplicate field"):
            load_contract(p)

    def test_one_field_one_mismatch(self):
        """A single changed field must produce exactly one mismatch."""
        contract = _make_contract()
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_model": "different"}),
        )
        model_mismatches = [m for m in diff.mismatches if m.field == "judge_model"]
        assert len(model_mismatches) == 1

    def test_duplicate_field_in_wrapped_contract(self, tmp_path: Path):
        """Duplicate detection must work inside comparability_contract wrapper too."""
        p = tmp_path / "wrapped_dup.json"
        p.write_text(json.dumps({
            "comparability_contract": {
                "name": "Wrapped Dup",
                "parity_fields": [
                    {"field": "judge_model", "match_rule": "exact", "severity": "INVALIDATING"},
                    {"field": "judge_model", "match_rule": "exact", "severity": "INVALIDATING"},
                ],
            }
        }))
        with pytest.raises(ContractValidationError, match="duplicate"):
            load_contract(p)

    def test_optional_invalidating_rejected_at_load(self, tmp_path: Path):
        """OPTIONAL + INVALIDATING is contradictory and must be rejected.

        OCD-11: if a mismatch is invalidating, the field must be required.
        An optional field cannot invalidate a comparison.
        """
        p = tmp_path / "bad_combo.json"
        p.write_text(json.dumps({
            "name": "Bad combo",
            "parity_fields": [{
                "field": "judge_model",
                "match_rule": "exact",
                "severity": "INVALIDATING",
                "requirement": "OPTIONAL",
            }],
        }))
        with pytest.raises(ContractValidationError, match="INVALIDATING.*REQUIRED"):
            load_contract(p)

    def test_optional_degrading_is_allowed(self, tmp_path: Path):
        """OPTIONAL + DEGRADING is a valid combination (non-contradictory)."""
        p = tmp_path / "ok_combo.json"
        p.write_text(json.dumps({
            "name": "OK combo",
            "parity_fields": [{
                "field": "judge_model",
                "match_rule": "exact",
                "severity": "DEGRADING",
                "group": "execution_params",
                "requirement": "OPTIONAL",
            }],
        }))
        contract = load_contract(p)
        assert len(contract.parity_fields) == 1

    def test_required_invalidating_is_allowed(self, tmp_path: Path):
        """REQUIRED + INVALIDATING is the canonical valid combination."""
        p = tmp_path / "req_inv.json"
        p.write_text(json.dumps({
            "name": "Standard",
            "parity_fields": [{
                "field": "judge_model",
                "match_rule": "exact",
                "severity": "INVALIDATING",
                "requirement": "REQUIRED",
            }],
        }))
        contract = load_contract(p)
        assert len(contract.parity_fields) == 1


# ===================================================================
# CLI-level regression: malformed contract exits cleanly
# ===================================================================

class TestCLIMalformedContract:
    """assay compare with bad contract must exit cleanly, no raw traceback."""

    def test_empty_contract_exits_3(self, tmp_path: Path):
        """Empty YAML contract → exit 3 with structured error, no traceback."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        contract = tmp_path / "empty.yaml"
        contract.write_text("")
        baseline = tmp_path / "b.json"
        baseline.write_text(json.dumps({"fields": {"x": 1}}))
        candidate = tmp_path / "c.json"
        candidate.write_text(json.dumps({"fields": {"x": 1}}))

        runner = CliRunner()
        result = runner.invoke(assay_app, [
            "compare", str(baseline), str(candidate),
            "-c", str(contract), "--json",
        ])
        assert result.exit_code == 3
        output = json.loads(result.stdout)
        assert output["status"] == "error"
        assert "empty" in output["error"].lower()

    def test_directory_without_bundle_exits_cleanly(self, tmp_path: Path):
        """Directory with no sidecar bundle → exit 3, clear message."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        contract = tmp_path / "c.json"
        contract.write_text(json.dumps({
            "name": "Test",
            "parity_fields": [
                {"field": "x", "match_rule": "exact", "severity": "INVALIDATING"},
            ],
        }))

        runner = CliRunner()
        result = runner.invoke(assay_app, [
            "compare", str(tmp_path), str(tmp_path),
            "-c", str(contract), "--json",
        ])
        assert result.exit_code == 3
        output = json.loads(result.stdout)
        assert output["status"] == "error"
        assert "evidence bundle" in output["error"].lower()

    def test_directory_with_sidecar_resolves(self, tmp_path: Path):
        """Directory containing evidence_bundle.json resolves correctly."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        contract = tmp_path / "c.json"
        contract.write_text(json.dumps({
            "name": "Test",
            "parity_fields": [
                {"field": "x", "match_rule": "exact", "severity": "INVALIDATING"},
            ],
        }))

        # Create sidecar bundle in two subdirectories
        base_dir = tmp_path / "baseline"
        base_dir.mkdir()
        (base_dir / "evidence_bundle.json").write_text(json.dumps({
            "fields": {"x": "same"},
        }))
        cand_dir = tmp_path / "candidate"
        cand_dir.mkdir()
        (cand_dir / "evidence_bundle.json").write_text(json.dumps({
            "fields": {"x": "same"},
        }))

        runner = CliRunner()
        result = runner.invoke(assay_app, [
            "compare", str(base_dir), str(cand_dir),
            "-c", str(contract), "--json",
        ])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["constitutional_diff"]["comparability"]["verdict"] == "SATISFIED"


# ===================================================================
# Gate compare: enforcement boundary
# ===================================================================

class TestGateCompare:
    """assay gate compare is fail-closed. Only SATISFIED passes."""

    @pytest.fixture
    def cli_env(self, tmp_path):
        """Set up contract and bundle files for gate tests."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        contract = tmp_path / "contract.json"
        contract.write_text(json.dumps({
            "name": "Gate Test",
            "id": "gate-test-001",
            "parity_fields": [
                {"field": "judge_model", "match_rule": "exact", "severity": "INVALIDATING", "group": "instrument_identity"},
                {"field": "judge_max_tokens", "match_rule": "exact", "severity": "DEGRADING", "group": "execution_params"},
            ],
        }))

        def make_bundle(fields, name="b.json"):
            p = tmp_path / name
            p.write_text(json.dumps({"fields": fields}))
            return str(p)

        return {
            "runner": CliRunner(),
            "app": assay_app,
            "contract": str(contract),
            "make_bundle": make_bundle,
        }

    def test_satisfied_exits_0(self, cli_env):
        """Clean pair → exit 0 (PASS)."""
        b = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "base.json")
        c = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "cand.json")

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, c,
            "-c", cli_env["contract"], "--json",
        ])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["gate_result"] == "PASS"

    def test_denied_exits_1(self, cli_env):
        """INVALIDATING mismatch → exit 1 (FAIL)."""
        b = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "base.json")
        c = cli_env["make_bundle"]({"judge_model": "different", "judge_max_tokens": 1024}, "cand.json")

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, c,
            "-c", cli_env["contract"], "--json",
        ])
        assert result.exit_code == 1
        output = json.loads(result.stdout)
        assert output["gate_result"] == "FAIL"
        assert output["constitutional_diff"]["comparability"]["verdict"] == "DENIED"

    def test_downgraded_exits_1(self, cli_env):
        """DEGRADING mismatch → exit 1 (FAIL). Gate is strict."""
        b = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "base.json")
        c = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 2048}, "cand.json")

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, c,
            "-c", cli_env["contract"], "--json",
        ])
        assert result.exit_code == 1
        output = json.loads(result.stdout)
        assert output["gate_result"] == "FAIL"
        assert output["constitutional_diff"]["comparability"]["verdict"] == "DOWNGRADED"

    def test_undetermined_exits_1(self, cli_env):
        """Missing required fields → exit 1 (FAIL). UNDETERMINED = fail-closed."""
        b = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "base.json")
        c = cli_env["make_bundle"]({}, "cand.json")  # empty bundle

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, c,
            "-c", cli_env["contract"], "--json",
        ])
        assert result.exit_code == 1
        output = json.loads(result.stdout)
        assert output["gate_result"] == "FAIL"
        assert output["constitutional_diff"]["comparability"]["verdict"] == "UNDETERMINED"

    def test_bad_contract_exits_3(self, cli_env, tmp_path):
        """Invalid contract → exit 3."""
        bad = tmp_path / "bad.json"
        bad.write_text("null")

        b = cli_env["make_bundle"]({"x": 1}, "base.json")
        c = cli_env["make_bundle"]({"x": 1}, "cand.json")

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, c,
            "-c", str(bad), "--json",
        ])
        assert result.exit_code == 3

    def test_pack_root_resolution(self, cli_env, tmp_path):
        """Gate compare accepts pack directories with sidecar bundles."""
        base_dir = tmp_path / "base_pack"
        base_dir.mkdir()
        (base_dir / "evidence_bundle.json").write_text(json.dumps({
            "fields": {"judge_model": "gpt-4o", "judge_max_tokens": 1024},
        }))
        cand_dir = tmp_path / "cand_pack"
        cand_dir.mkdir()
        (cand_dir / "evidence_bundle.json").write_text(json.dumps({
            "fields": {"judge_model": "gpt-4o", "judge_max_tokens": 1024},
        }))

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", str(base_dir), str(cand_dir),
            "-c", cli_env["contract"], "--json",
        ])
        assert result.exit_code == 0

    def test_pack_root_missing_bundle_exits_3(self, cli_env, tmp_path):
        """Pack directory with no sidecar → exit 3."""
        empty_dir = tmp_path / "empty_pack"
        empty_dir.mkdir()

        b = cli_env["make_bundle"]({"x": 1}, "base.json")

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, str(empty_dir),
            "-c", cli_env["contract"], "--json",
        ])
        assert result.exit_code == 3

    def test_save_report(self, cli_env, tmp_path):
        """--save-report writes gate JSON to disk."""
        b = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "base.json")
        c = cli_env["make_bundle"]({"judge_model": "gpt-4o", "judge_max_tokens": 1024}, "cand.json")
        report = tmp_path / "gate_report.json"

        result = cli_env["runner"].invoke(cli_env["app"], [
            "gate", "compare", b, c,
            "-c", cli_env["contract"],
            "--save-report", str(report),
        ])
        assert result.exit_code == 0
        assert report.exists()
        data = json.loads(report.read_text())
        assert data["gate_result"] == "PASS"


# ===================================================================
# Receipt emission
# ===================================================================

class TestComparabilityReceipt:
    """Comparability receipts are emitted for all verdicts."""

    def test_receipt_payload_shape(self):
        """Receipt has all required fields."""
        from unittest.mock import patch

        contract = _make_contract()
        baseline = _make_bundle()
        candidate = _make_bundle({"judge_model": "different"})
        diff = evaluate(contract, baseline, candidate)

        emitted = []

        def mock_emit(type_name, data, **kwargs):
            emitted.append({"type": type_name, "data": data})
            return {"receipt_id": "test", "type": type_name, **data}

        with patch("assay.store.emit_receipt", side_effect=mock_emit):
            from assay.comparability.receipt import emit_comparability_receipt
            result = emit_comparability_receipt(diff)

        assert len(emitted) == 1
        assert emitted[0]["type"] == "comparability_verdict"
        payload = emitted[0]["data"]

        # Check required fields
        assert payload["verdict"] == "DENIED"
        assert payload["contract_id"] == "test-contract-001"
        assert payload["exit_code"] == 1
        assert payload["instrument_continuity"] == "BROKEN"
        assert payload["engine_version"]  # non-empty
        assert payload["source"] == "assay compare"
        assert payload["satisfied_count"] >= 0
        assert payload["mismatch_count"] >= 1
        assert payload["total_contract_fields"] >= 1

        # Mismatches present
        assert "mismatches" in payload
        assert payload["mismatches"][0]["field"] == "judge_model"
        assert payload["mismatches"][0]["severity"] == "INVALIDATING"

        # Consequence present
        assert payload["consequence"]["claim_status"] == "INADMISSIBLE"

    def test_satisfied_receipt_emitted(self):
        """SATISFIED verdicts also produce receipts (not just denials)."""
        from unittest.mock import patch

        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), _make_bundle())

        emitted = []

        def mock_emit(type_name, data, **kwargs):
            emitted.append(data)
            return {"receipt_id": "test", "type": type_name, **data}

        with patch("assay.store.emit_receipt", side_effect=mock_emit):
            from assay.comparability.receipt import emit_comparability_receipt
            emit_comparability_receipt(diff)

        assert len(emitted) == 1
        assert emitted[0]["verdict"] == "SATISFIED"
        assert "mismatches" not in emitted[0]  # no mismatches to report

    def test_receipt_json_serializable(self):
        """Receipt payload must be JSON-serializable."""
        from unittest.mock import patch

        contract = _make_contract()
        claim = ClaimUnderTest(
            claim_type="improvement",
            summary="test claim",
            metric="score",
            delta=0.42,
        )
        diff = evaluate(
            contract,
            _make_bundle(),
            _make_bundle({"judge_model": "different"}),
            claim=claim,
        )

        captured_payload = {}

        def mock_emit(type_name, data, **kwargs):
            captured_payload.update(data)
            return {"receipt_id": "test", "type": type_name, **data}

        with patch("assay.store.emit_receipt", side_effect=mock_emit):
            from assay.comparability.receipt import emit_comparability_receipt
            emit_comparability_receipt(diff)

        # Must not raise
        serialized = json.dumps(captured_payload, default=str)
        parsed = json.loads(serialized)
        assert parsed["verdict"] == "DENIED"
        assert parsed["claim"]["summary"] == "test claim"

    def test_undetermined_receipt_includes_missing_fields(self):
        """UNDETERMINED receipts record which fields were missing."""
        from unittest.mock import patch

        contract = _make_contract()
        diff = evaluate(contract, _make_bundle(), EvidenceBundle(fields={}))

        captured = {}

        def mock_emit(type_name, data, **kwargs):
            captured.update(data)
            return {"receipt_id": "test", "type": type_name, **data}

        with patch("assay.store.emit_receipt", side_effect=mock_emit):
            from assay.comparability.receipt import emit_comparability_receipt
            emit_comparability_receipt(diff)

        assert captured["verdict"] == "UNDETERMINED"
        assert "missing_required_fields" in captured
        assert len(captured["missing_required_fields"]) > 0


# ===================================================================
# Golden incident receipt: seed crystal for case law
# ===================================================================

class TestGoldenIncidentReceipt:
    """Full-loop test: contract + bundles → evaluate → receipt → verify shape.

    This is the seed crystal for case law. It exercises the complete
    path from evidence to structured precedent.
    """

    def test_judge_drift_incident_receipt(self):
        """Model version drift incident produces a complete, stable receipt."""
        from unittest.mock import patch

        # Load the real contract
        contract_path = Path(__file__).parent.parent.parent / "contracts" / "judge-comparability-v1.yaml"
        if not contract_path.exists():
            pytest.skip("Real contract not found")

        contract = load_contract(contract_path)

        # Simulate the three-act demo's dirty case
        baseline = EvidenceBundle(
            fields={
                "judge_model": "gpt-4o",
                "judge_model_version": "gpt-4o-2024-08-06",
                "judge_prompt_template": "Rate helpfulness 1-5.\n",
                "judge_system_prompt": "You are an evaluator.\n",
                "scoring_rubric": "1=bad, 5=good\n",
                "judge_temperature": 0.0,
                "judge_max_tokens": 1024,
                "judge_top_p": 1.0,
                "judge_passes": 1,
                "eval_dataset": "sha256:abcd" + "0" * 60,
                "eval_dataset_version": "v3",
                "presentation_order": "fixed",
                "input_format": "sha256:1234" + "0" * 60,
                "score_type": "likert",
                "score_range": "1-5",
            },
            label="baseline (Tuesday)",
            ref="packs/baseline/",
        )

        candidate = EvidenceBundle(
            fields={
                "judge_model": "gpt-4o",
                "judge_model_version": "gpt-4o-2024-11-20",  # DRIFTED
                "judge_prompt_template": "Rate helpfulness 1-5. Be lenient.\n",  # EDITED
                "judge_system_prompt": "You are an evaluator.\n",
                "scoring_rubric": "1=bad, 5=good\n",
                "judge_temperature": 0.0,
                "judge_max_tokens": 1024,
                "judge_top_p": 1.0,
                "judge_passes": 1,
                "eval_dataset": "sha256:abcd" + "0" * 60,
                "eval_dataset_version": "v3",
                "presentation_order": "fixed",
                "input_format": "sha256:1234" + "0" * 60,
                "score_type": "likert",
                "score_range": "1-5",
            },
            label="candidate (today, drifted)",
            ref="packs/candidate/",
        )

        claim = ClaimUnderTest(
            claim_type="improvement",
            summary="candidate scores 11.1% higher on helpfulness",
            metric="mean_helpfulness_score",
            delta=0.42,
        )

        # Run denial engine
        diff = evaluate(contract, baseline, candidate, claim=claim)

        # Capture receipt
        captured = {}

        def mock_emit(type_name, data, **kwargs):
            captured.update(data)
            return {"receipt_id": "incident-001", "type": type_name, **data}

        with patch("assay.store.emit_receipt", side_effect=mock_emit):
            from assay.comparability.receipt import emit_comparability_receipt
            emit_comparability_receipt(diff, source="assay gate compare")

        # --- Verify the incident receipt is complete and stable ---

        # Verdict
        assert captured["verdict"] == "DENIED"
        assert captured["exit_code"] == 1
        assert captured["instrument_continuity"] == "BROKEN"

        # Contract identity
        assert captured["contract_id"] == "judge-comparability-v1"
        assert captured["contract_version"] == "0.1.0"

        # Entity references
        assert captured["baseline_ref"] == "packs/baseline/"
        assert captured["candidate_ref"] == "packs/candidate/"
        assert captured["baseline_label"] == "baseline (Tuesday)"

        # Source
        assert captured["source"] == "assay gate compare"

        # Mismatches — exactly 2 INVALIDATING
        assert len(captured["mismatches"]) == 2
        mismatch_fields = {m["field"] for m in captured["mismatches"]}
        assert mismatch_fields == {"judge_model_version", "judge_prompt_template"}
        for m in captured["mismatches"]:
            assert m["severity"] == "INVALIDATING"
            assert m["group"] == "instrument_identity"

        # Consequence
        assert captured["consequence"]["claim_status"] == "INADMISSIBLE"
        assert "promotion" in captured["consequence"]["blocked_actions"]

        # Claim
        assert captured["claim"]["summary"] == "candidate scores 11.1% higher on helpfulness"
        assert captured["claim"]["delta"] == 0.42

        # Field counts
        assert captured["satisfied_count"] == 13
        assert captured["mismatch_count"] == 2
        assert captured["total_contract_fields"] == 15

        # JSON-serializable
        json.dumps(captured, default=str)

        # Contract hash present and stable
        assert "contract_hash" in captured
        assert captured["contract_hash"].startswith("sha256:")


# ===================================================================
# End-to-end receipt persistence: constitutional transaction test
# ===================================================================

class TestReceiptPersistence:
    """Verify that CLI commands actually persist receipts to the store.

    This closes the gap between "receipt payload is correct" (mock tests)
    and "constitutional transaction actually persisted" (e2e).
    """

    def test_compare_persists_receipt(self, tmp_path: Path):
        """assay compare writes a comparability_verdict receipt to the trace."""
        from typer.testing import CliRunner
        from assay.commands import assay_app
        from assay.store import AssayStore

        # Set up isolated store
        store_dir = tmp_path / "store"
        store_dir.mkdir()

        contract = tmp_path / "contract.json"
        contract.write_text(json.dumps({
            "name": "E2E Test",
            "id": "e2e-test-001",
            "version": "0.1.0",
            "parity_fields": [
                {"field": "judge_model", "match_rule": "exact",
                 "severity": "INVALIDATING", "group": "instrument_identity"},
            ],
        }))

        baseline = tmp_path / "base.json"
        baseline.write_text(json.dumps({
            "label": "baseline",
            "ref": "packs/base/",
            "fields": {"judge_model": "gpt-4o"},
        }))

        candidate = tmp_path / "cand.json"
        candidate.write_text(json.dumps({
            "label": "candidate",
            "ref": "packs/cand/",
            "fields": {"judge_model": "different-model"},
        }))

        # Patch the default store to use our isolated directory
        import assay.store as store_mod
        original_store = store_mod._default_store
        store_mod._default_store = AssayStore(base_dir=store_dir)
        try:
            runner = CliRunner()
            result = runner.invoke(assay_app, [
                "compare",
                str(baseline), str(candidate),
                "-c", str(contract),
                "--json",
            ])
            assert result.exit_code == 1  # DENIED

            # Find the receipt in the store
            store = store_mod._default_store
            trace_id = store.trace_id
            assert trace_id is not None

            entries = store.read_trace(trace_id)
            receipts = [e for e in entries if e.get("type") == "comparability_verdict"]
            assert len(receipts) == 1

            r = receipts[0]
            assert r["verdict"] == "DENIED"
            assert r["contract_id"] == "e2e-test-001"
            assert r["contract_version"] == "0.1.0"
            assert r["contract_hash"].startswith("sha256:")
            assert r["source"] == "assay compare"
            assert r["baseline_ref"] == "packs/base/"
            assert r["candidate_ref"] == "packs/cand/"
            assert r["engine_version"]  # non-empty
            assert r["exit_code"] == 1
            assert r["instrument_continuity"] == "BROKEN"
            assert len(r["mismatches"]) == 1
            assert r["mismatches"][0]["field"] == "judge_model"
            assert r["consequence"]["claim_status"] == "INADMISSIBLE"
            assert r["receipt_id"]  # auto-generated
            assert r["timestamp"]  # auto-generated
        finally:
            store_mod._default_store = original_store

    def test_gate_compare_persists_receipt(self, tmp_path: Path):
        """assay gate compare writes a receipt AND the verdict is recoverable."""
        from typer.testing import CliRunner
        from assay.commands import assay_app
        from assay.store import AssayStore

        store_dir = tmp_path / "store"
        store_dir.mkdir()

        contract = tmp_path / "contract.json"
        contract.write_text(json.dumps({
            "name": "Gate E2E",
            "id": "gate-e2e-001",
            "parity_fields": [
                {"field": "x", "match_rule": "exact",
                 "severity": "INVALIDATING", "group": "instrument_identity"},
            ],
        }))

        baseline = tmp_path / "base.json"
        baseline.write_text(json.dumps({"fields": {"x": "same"}}))
        candidate = tmp_path / "cand.json"
        candidate.write_text(json.dumps({"fields": {"x": "same"}}))

        import assay.store as store_mod
        original_store = store_mod._default_store
        store_mod._default_store = AssayStore(base_dir=store_dir)
        try:
            runner = CliRunner()
            result = runner.invoke(assay_app, [
                "gate", "compare",
                str(baseline), str(candidate),
                "-c", str(contract),
                "--json",
            ])
            assert result.exit_code == 0  # SATISFIED

            store = store_mod._default_store
            entries = store.read_trace(store.trace_id)
            receipts = [e for e in entries if e.get("type") == "comparability_verdict"]
            assert len(receipts) == 1

            r = receipts[0]
            assert r["verdict"] == "SATISFIED"
            assert r["source"] == "assay gate compare"
            assert r["contract_id"] == "gate-e2e-001"
        finally:
            store_mod._default_store = original_store
