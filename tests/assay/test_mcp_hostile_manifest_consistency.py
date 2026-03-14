"""Manifest ↔ test consistency checks for the MCP Hostile Scenario Pack.

Separated from test_mcp_torture_garden.py so failure categories are distinct:
  - test_mcp_torture_garden.py fails  → a scenario assertion broke
  - this file fails                   → manifest and tests have drifted

The linked_test check uses AST parsing of the scenario test file to find
real class definitions — not substring matching, which could pass on
comments or stale docstring mentions.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from assay.mcp_hostile_scenarios import (
    EnforcementVerdict,
    EvidenceVerdict,
    ManifestLoadError,
    load_hostile_scenario_manifest,
)

_MANIFEST = Path(__file__).parent.parent.parent / "docs/hostile_scenarios/manifest.yaml"
_SCENARIO_FILE = Path(__file__).parent / "test_mcp_torture_garden.py"


def _scenario_class_names() -> set[str]:
    """Return all class names defined in test_mcp_torture_garden.py via AST parsing.

    This is stronger than substring matching: it finds only real class
    definitions, not mentions in comments, docstrings, or string literals.
    """
    source = _SCENARIO_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}


def _load() -> list:
    try:
        return load_hostile_scenario_manifest(_MANIFEST)
    except ManifestLoadError as exc:
        pytest.fail(f"Manifest failed to load: {exc}")


class TestManifestConsistency:
    """The manifest is the constitutional declaration; this file is its enforcer."""

    def test_manifest_loads_without_error(self):
        """load_hostile_scenario_manifest() must succeed and return at least one case."""
        cases = _load()
        assert len(cases) >= 1, "Manifest has no cases"

    def test_every_case_has_tg_prefixed_id(self):
        for case in _load():
            assert case.id.startswith("TG-"), (
                f"Case id '{case.id}' does not follow TG-NNN format"
            )

    def test_every_linked_test_is_a_real_class_in_scenario_file(self):
        """
        Primary drift alarm. Uses AST parsing — not substring matching.

        If this fails, the manifest names a class that does not exist as a
        real class definition in test_mcp_torture_garden.py.
        """
        defined_classes = _scenario_class_names()
        for case in _load():
            assert case.linked_test in defined_classes, (
                f"{case.id}: linked_test='{case.linked_test}' is not a class defined "
                f"in test_mcp_torture_garden.py. "
                f"Defined classes: {sorted(defined_classes)}"
            )

    def test_every_case_has_at_least_one_enforcement_verdict(self):
        for case in _load():
            has_enforcement = any([
                case.enforcement_verdict,
                case.enforcement_verdict_with_policy,
                case.enforcement_verdict_without_policy,
            ])
            assert has_enforcement, (
                f"{case.id}: no enforcement verdict axis — "
                "set enforcement_verdict or enforcement_verdict_with/without_policy"
            )

    def test_every_case_has_evidence_verdict(self):
        for case in _load():
            assert case.evidence_verdict, (
                f"{case.id}: evidence_verdict is empty or missing"
            )

    def test_every_case_has_non_empty_claim_boundaries(self):
        for case in _load():
            assert case.can_claim, f"{case.id}: can_claim is empty"
            assert case.cannot_claim, f"{case.id}: cannot_claim is empty"

    def test_every_case_has_boundary_under_test(self):
        for case in _load():
            assert case.boundary_under_test, (
                f"{case.id}: boundary_under_test is missing — "
                "every case must name the control surface it probes"
            )

    def test_verdict_values_use_shared_vocabulary(self):
        """All verdicts must come from the enums in mcp_hostile_scenarios.py."""
        valid_enforcement = {v.value.upper() for v in EnforcementVerdict}
        valid_evidence = {v.value.upper() for v in EvidenceVerdict}

        for case in _load():
            for attr in ("enforcement_verdict", "enforcement_verdict_with_policy",
                         "enforcement_verdict_without_policy"):
                val = getattr(case, attr)
                if val:
                    assert val.upper() in valid_enforcement, (
                        f"{case.id}: {attr}='{val}' not in EnforcementVerdict vocabulary. "
                        f"Valid: {valid_enforcement}"
                    )
            if case.evidence_verdict:
                assert case.evidence_verdict.upper() in valid_evidence, (
                    f"{case.id}: evidence_verdict='{case.evidence_verdict}' "
                    f"not in EvidenceVerdict vocabulary. Valid: {valid_evidence}"
                )
