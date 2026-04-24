"""Structural validation tests for the barrier_annotation v0.1 schema.

Scope: schema-only validation. This test does NOT adjudicate whether a
proof actually relativizes, is natural, or algebrizes; those judgments
are external to the primitive. The tests below check that the schema
itself is well-formed and that the fixture annotations validate (or
fail to validate) as the v0.1 vocabulary requires.

See notes/barrier-annotation-integration-spec.md in the barrier-
implications-note repo for the full integration spec.
"""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = ROOT / "docs" / "examples" / "barrier_annotations"
SCHEMA_NAME = "barrier_annotation.v0.1.schema.json"


def _load_schema() -> dict:
    schema_path = resources.files("assay").joinpath(f"schemas/{SCHEMA_NAME}")
    return json.loads(schema_path.read_text())


def _load_example(name: str) -> dict:
    return json.loads((EXAMPLES_DIR / name).read_text())


class TestBarrierAnnotationSchemaWellFormed:
    def test_schema_is_valid_draft_2020_12(self) -> None:
        Draft202012Validator.check_schema(_load_schema())


@pytest.mark.parametrize(
    "fixture_name, expected_barrier, expected_obstruction",
    [
        (
            "valid.bgs.v0.1.json",
            "RELATIVIZATION",
            "BGS_contradictory_oracle_worlds",
        ),
        (
            "valid.rr.v0.1.json",
            "NATURAL_PROOFS",
            "RR_constructive_large_against_PRF_class",
        ),
        (
            "valid.aw.v0.1.json",
            "ALGEBRIZATION",
            "AW_algebraic_oracle_contradictory_worlds",
        ),
    ],
)
class TestValidFixtures:
    def test_fixture_validates(
        self,
        fixture_name: str,
        expected_barrier: str,
        expected_obstruction: str,
    ) -> None:
        validator = Draft202012Validator(_load_schema())
        instance = _load_example(fixture_name)
        validator.validate(instance)
        assert instance["implicated_barrier"] == expected_barrier
        assert instance["obstruction_kind"] == expected_obstruction
        assert instance["artifact_type"] == "barrier_annotation"
        assert instance["version"] == "v0.1"


@pytest.mark.parametrize(
    "fixture_name, defect_kind",
    [
        (
            "invalid.missing_rr_prf_assumption.v0.1.json",
            "NATURAL_PROOFS branch requires SUBEXP_secure_PRFs_exist_in(...) in assumptions",
        ),
        (
            "invalid.arithmetizing_as_load_bearing.v0.1.json",
            "ALGEBRIZATION branch restricts barrier_predicates to {algebrizing}; arithmetizing belongs in auxiliary_descriptors",
        ),
        (
            "invalid.aw_composition_attempt.v0.1.json",
            "additionalProperties: false; composes_with is not a valid top-level field",
        ),
        (
            "invalid.unsupported_triple.v0.1.json",
            "obstruction_kind enum at v0.1 does not include post-2008 refinements",
        ),
    ],
)
class TestInvalidFixtures:
    def test_fixture_fails_schema_validation(
        self,
        fixture_name: str,
        defect_kind: str,
    ) -> None:
        validator = Draft202012Validator(_load_schema())
        instance = _load_example(fixture_name)
        errors = list(validator.iter_errors(instance))
        assert errors, (
            f"expected fixture {fixture_name} to fail schema validation "
            f"because {defect_kind}, but it validated cleanly"
        )
