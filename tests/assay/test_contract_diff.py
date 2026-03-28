"""Tests for contract diffing / replay engine.

Covers:
  - Structural diff between two contracts (clause changes)
  - Verdict replay over bundle pairs
  - Verdict flip detection with clause-level reasons
  - Determinism: same inputs produce same report
  - Edge cases: no flips, all flips, added/removed fields
"""
from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from assay.comparability.bundle import EvidenceBundle
from assay.comparability.contract import ComparabilityContract, ParityField
from assay.comparability.contract_diff import (
    ClauseChange,
    ContractDiffReport,
    VerdictFlip,
    diff_contracts,
    replay,
)
from assay.comparability.types import (
    ParityFieldGroup,
    Severity,
    Verdict,
)


# ---------------------------------------------------------------------------
# Fixtures: contracts and bundles
# ---------------------------------------------------------------------------

def _v1_contract() -> ComparabilityContract:
    """Judge comparability v1 — judge_temperature is INVALIDATING."""
    return ComparabilityContract(
        contract_id="judge-comparability-v1",
        name="LLM-as-Judge v1",
        version="0.1.0",
        domain="llm_as_judge",
        parity_fields=[
            ParityField(
                field="judge_model",
                match_rule="exact",
                severity=Severity.INVALIDATING,
                group=ParityFieldGroup.INSTRUMENT_IDENTITY,
                rationale="Different models = different instrument.",
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
        ],
    )


def _v2_contract() -> ComparabilityContract:
    """Judge comparability v2-draft — judge_temperature relaxed to DEGRADING."""
    return ComparabilityContract(
        contract_id="judge-comparability-v2-draft",
        name="LLM-as-Judge v2 (draft)",
        version="0.2.0-draft",
        domain="llm_as_judge",
        parity_fields=[
            ParityField(
                field="judge_model",
                match_rule="exact",
                severity=Severity.INVALIDATING,
                group=ParityFieldGroup.INSTRUMENT_IDENTITY,
                rationale="Different models = different instrument.",
            ),
            ParityField(
                field="judge_temperature",
                match_rule="exact",
                severity=Severity.DEGRADING,  # <-- RELAXED
                group=ParityFieldGroup.EXECUTION_PARAMS,
                rationale="Temperature affects variance but not instrument identity.",
            ),
            ParityField(
                field="judge_max_tokens",
                match_rule="exact",
                severity=Severity.DEGRADING,
                group=ParityFieldGroup.EXECUTION_PARAMS,
                rationale="May truncate reasoning.",
            ),
        ],
    )


def _matching_bundle(ref: str = "run_a") -> EvidenceBundle:
    """Bundle where all fields match the baseline."""
    return EvidenceBundle(
        fields={
            "judge_model": "gpt-4o-mini",
            "judge_temperature": 0.0,
            "judge_max_tokens": 512,
        },
        label=f"bundle-{ref}",
        ref=f"test/{ref}",
    )


def _temperature_drift_bundle() -> EvidenceBundle:
    """Bundle where only judge_temperature differs."""
    return EvidenceBundle(
        fields={
            "judge_model": "gpt-4o-mini",
            "judge_temperature": 0.3,  # <-- different
            "judge_max_tokens": 512,
        },
        label="bundle-temp-drift",
        ref="test/temp_drift",
    )


def _model_drift_bundle() -> EvidenceBundle:
    """Bundle where judge_model differs (always DENIED under both contracts)."""
    return EvidenceBundle(
        fields={
            "judge_model": "gpt-4o",  # <-- different
            "judge_temperature": 0.0,
            "judge_max_tokens": 512,
        },
        label="bundle-model-drift",
        ref="test/model_drift",
    )


def _max_tokens_drift_bundle() -> EvidenceBundle:
    """Bundle where only max_tokens differs (DEGRADING under both)."""
    return EvidenceBundle(
        fields={
            "judge_model": "gpt-4o-mini",
            "judge_temperature": 0.0,
            "judge_max_tokens": 256,  # <-- different
        },
        label="bundle-tokens-drift",
        ref="test/tokens_drift",
    )


# ===================================================================
# Structural diff tests
# ===================================================================

class TestDiffContracts:
    def test_identical_contracts_no_changes(self):
        v1 = _v1_contract()
        changes = diff_contracts(v1, v1)
        assert changes == []

    def test_severity_relaxation_detected(self):
        v1 = _v1_contract()
        v2 = _v2_contract()
        changes = diff_contracts(v1, v2)
        assert len(changes) == 1
        assert changes[0].field == "judge_temperature"
        assert changes[0].old_severity == Severity.INVALIDATING
        assert changes[0].new_severity == Severity.DEGRADING
        assert changes[0].change_type == "severity_relaxed"

    def test_severity_tightening_detected(self):
        # Reverse: v2 -> v1 should be a tightening
        v1 = _v1_contract()
        v2 = _v2_contract()
        changes = diff_contracts(v2, v1)
        assert len(changes) == 1
        assert changes[0].field == "judge_temperature"
        assert changes[0].change_type == "severity_tightened"

    def test_field_removed(self):
        v1 = _v1_contract()
        # v2 with judge_max_tokens removed
        v2 = ComparabilityContract(
            contract_id="test-v2",
            name="test",
            version="0.2.0",
            parity_fields=[
                ParityField(
                    field="judge_model",
                    match_rule="exact",
                    severity=Severity.INVALIDATING,
                    group=ParityFieldGroup.INSTRUMENT_IDENTITY,
                    rationale="",
                ),
                ParityField(
                    field="judge_temperature",
                    match_rule="exact",
                    severity=Severity.INVALIDATING,
                    group=ParityFieldGroup.EXECUTION_PARAMS,
                    rationale="",
                ),
            ],
        )
        changes = diff_contracts(v1, v2)
        removed = [c for c in changes if c.change_type == "field_removed"]
        assert len(removed) == 1
        assert removed[0].field == "judge_max_tokens"

    def test_field_added(self):
        v1 = _v1_contract()
        v2_fields = list(v1.parity_fields) + [
            ParityField(
                field="judge_seed",
                match_rule="exact",
                severity=Severity.INVALIDATING,
                group=ParityFieldGroup.EXECUTION_PARAMS,
                rationale="Seed controls determinism.",
            ),
        ]
        v2 = ComparabilityContract(
            contract_id="test-v2",
            name="test",
            version="0.2.0",
            parity_fields=v2_fields,
        )
        changes = diff_contracts(v1, v2)
        added = [c for c in changes if c.change_type == "field_added"]
        assert len(added) == 1
        assert added[0].field == "judge_seed"
        assert added[0].new_severity == Severity.INVALIDATING

    def test_clause_change_serialization(self):
        v1 = _v1_contract()
        v2 = _v2_contract()
        changes = diff_contracts(v1, v2)
        d = changes[0].to_dict()
        assert d["field"] == "judge_temperature"
        assert d["old_severity"] == "INVALIDATING"
        assert d["new_severity"] == "DEGRADING"
        assert d["change_type"] == "severity_relaxed"


# ===================================================================
# Verdict replay tests
# ===================================================================

class TestReplay:
    def test_temperature_drift_flips_from_denied_to_downgraded(self):
        """The core contract diff case: temperature relaxation flips verdict."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()
        candidate = _temperature_drift_bundle()

        report = replay(v1, v2, [(baseline, candidate)])

        assert report.total_pairs == 1
        assert len(report.flips) == 1
        assert report.stable_count == 0

        flip = report.flips[0]
        assert flip.old_verdict == Verdict.DENIED
        assert flip.new_verdict == Verdict.DOWNGRADED
        assert flip.triggering_field == "judge_temperature"
        assert "severity relaxed" in flip.reason
        assert "INVALIDATING" in flip.reason
        assert "DEGRADING" in flip.reason

    def test_model_drift_stays_denied_under_both(self):
        """Model identity mismatch is DENIED under both contracts — no flip."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()
        candidate = _model_drift_bundle()

        report = replay(v1, v2, [(baseline, candidate)])

        assert report.total_pairs == 1
        assert len(report.flips) == 0
        assert report.stable_count == 1

    def test_matching_bundles_satisfied_under_both(self):
        """Identical bundles are SATISFIED under both — no flip."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle("a")
        candidate = _matching_bundle("b")

        report = replay(v1, v2, [(baseline, candidate)])

        assert len(report.flips) == 0
        assert report.stable_count == 1

    def test_max_tokens_drift_stays_downgraded_under_both(self):
        """max_tokens is DEGRADING in both — DOWNGRADED under both, no flip."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()
        candidate = _max_tokens_drift_bundle()

        report = replay(v1, v2, [(baseline, candidate)])

        assert len(report.flips) == 0
        assert report.stable_count == 1

    def test_multiple_pairs_mixed(self):
        """Mix of flipping and stable pairs."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()

        pairs = [
            (baseline, _matching_bundle("b")),     # SATISFIED -> SATISFIED (stable)
            (baseline, _temperature_drift_bundle()),  # DENIED -> DOWNGRADED (flip)
            (baseline, _model_drift_bundle()),      # DENIED -> DENIED (stable)
            (baseline, _max_tokens_drift_bundle()), # DOWNGRADED -> DOWNGRADED (stable)
        ]

        report = replay(v1, v2, pairs)

        assert report.total_pairs == 4
        assert len(report.flips) == 1
        assert report.stable_count == 3
        assert report.flips[0].triggering_field == "judge_temperature"

    def test_replay_is_deterministic(self):
        """Same inputs produce identical output (ignoring diff_id/timestamps)."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()
        candidate = _temperature_drift_bundle()
        pairs = [(baseline, candidate)]

        report1 = replay(v1, v2, pairs)
        report2 = replay(v1, v2, pairs)

        # Compare serialized output (deterministic parts)
        d1 = report1.to_dict()
        d2 = report2.to_dict()
        assert d1["contract_diff"]["clause_changes"] == d2["contract_diff"]["clause_changes"]
        assert d1["contract_diff"]["flips"] == d2["contract_diff"]["flips"]
        assert d1["contract_diff"]["summary"] == d2["contract_diff"]["summary"]

    def test_empty_corpus(self):
        """No bundle pairs — report is valid but empty."""
        v1 = _v1_contract()
        v2 = _v2_contract()

        report = replay(v1, v2, [])

        assert report.total_pairs == 0
        assert len(report.flips) == 0
        assert report.stable_count == 0
        assert len(report.clause_changes) == 1  # temperature change still detected

    def test_flip_includes_correct_triggering_clauses(self):
        """Triggering clauses on a flip should reference only changed fields."""
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()
        candidate = _temperature_drift_bundle()

        report = replay(v1, v2, [(baseline, candidate)])

        flip = report.flips[0]
        assert len(flip.triggering_clauses) == 1
        assert flip.triggering_clauses[0].field == "judge_temperature"


# ===================================================================
# Report serialization tests
# ===================================================================

class TestReportSerialization:
    def test_report_to_dict_structure(self):
        v1 = _v1_contract()
        v2 = _v2_contract()
        baseline = _matching_bundle()
        candidate = _temperature_drift_bundle()

        report = replay(v1, v2, [(baseline, candidate)])
        d = report.to_dict()

        assert "contract_diff" in d
        cd = d["contract_diff"]
        assert "old" in cd
        assert "new" in cd
        assert "clause_changes" in cd
        assert "summary" in cd
        assert "flips" in cd

        assert cd["old"]["id"] == "judge-comparability-v1"
        assert cd["new"]["id"] == "judge-comparability-v2-draft"
        assert cd["summary"]["total_pairs"] == 1
        assert cd["summary"]["flips"] == 1

    def test_report_serializes_to_json(self):
        v1 = _v1_contract()
        v2 = _v2_contract()
        report = replay(v1, v2, [(_matching_bundle(), _temperature_drift_bundle())])

        # Should not raise
        json_str = json.dumps(report.to_dict(), indent=2)
        parsed = json.loads(json_str)
        assert parsed["contract_diff"]["summary"]["flips"] == 1


# ===================================================================
# Organic bundle replay tests (against real contract YAML)
# ===================================================================

class TestOrganicReplay:
    """Replay organic evidence bundles against v1 and v2-draft contracts.

    These tests load real bundle files from examples/llm_judge/organic/
    and verify that the contract diff correctly identifies flips.
    """

    @pytest.fixture
    def organic_bundles(self):
        """Load organic evidence bundles from disk."""
        from pathlib import Path
        organic_dir = Path(__file__).parent.parent.parent / "examples" / "llm_judge" / "organic"
        bundles = {}
        for run_dir in sorted(organic_dir.iterdir()):
            bundle_path = run_dir / "evidence_bundle.json"
            if bundle_path.exists():
                data = json.loads(bundle_path.read_text())
                bundles[run_dir.name] = EvidenceBundle(
                    fields=data["fields"],
                    label=data.get("label", run_dir.name),
                    ref=data.get("ref", str(run_dir)),
                )
        return bundles

    @pytest.fixture
    def real_contracts(self):
        """Load real v1 and v2-draft contracts."""
        from pathlib import Path
        from assay.comparability.contract import load_contract
        contracts_dir = Path(__file__).parent.parent.parent / "contracts"
        v1 = load_contract(contracts_dir / "judge-comparability-v1.yaml")
        v2 = load_contract(contracts_dir / "judge-comparability-v2-draft.yaml")
        return v1, v2

    def test_organic_model_drift_stays_denied(self, organic_bundles, real_contracts):
        """run_a (gpt-4o-mini) vs run_d_model_drift (gpt-4o) stays DENIED under both."""
        if "run_a" not in organic_bundles or "run_d_model_drift" not in organic_bundles:
            pytest.skip("Organic model drift bundles not available")

        v1, v2 = real_contracts
        baseline = organic_bundles["run_a"]
        candidate = organic_bundles["run_d_model_drift"]

        report = replay(v1, v2, [(baseline, candidate)])

        # Model identity mismatch is INVALIDATING in both — no flip
        assert len(report.flips) == 0
        assert report.stable_count == 1
