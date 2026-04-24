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


def _error_matches_marker(err, marker: str) -> bool:
    """Return True if a jsonschema ValidationError references `marker` in its
    absolute instance path, its absolute schema path, or its message.

    We inspect three distinct surfaces so a test can pin the failure to the
    field it was designed to catch, rather than merely that any error occurred.
    """
    if marker in [str(p) for p in err.absolute_path]:
        return True
    if marker in [str(p) for p in err.absolute_schema_path]:
        return True
    if marker in err.message:
        return True
    return False


@pytest.mark.parametrize(
    "fixture_name, expected_marker, defect_kind",
    [
        (
            "invalid.missing_rr_prf_assumption.v0.1.json",
            "assumptions",
            "NATURAL_PROOFS branch requires exactly one SUBEXP_secure_PRFs_exist_in(...) in assumptions",
        ),
        (
            "invalid.arithmetizing_as_load_bearing.v0.1.json",
            "barrier_predicates",
            "ALGEBRIZATION branch restricts barrier_predicates to {algebrizing}; arithmetizing belongs in auxiliary_descriptors",
        ),
        (
            "invalid.aw_composition_attempt.v0.1.json",
            "composes_with",
            "additionalProperties: false; composes_with is not a valid top-level field",
        ),
        (
            "invalid.unsupported_triple.v0.1.json",
            "obstruction_kind",
            "obstruction_kind enum at v0.1 does not include post-2008 refinements",
        ),
        (
            "invalid.rr_missing_large.v0.1.json",
            "barrier_predicates",
            "NATURAL_PROOFS requires all three predicates; this fixture omits `large`",
        ),
        (
            "invalid.rr_missing_useful_against.v0.1.json",
            "barrier_predicates",
            "NATURAL_PROOFS requires all three predicates; this fixture omits useful_against(...)",
        ),
        (
            "invalid.rr_only_constructive.v0.1.json",
            "barrier_predicates",
            "NATURAL_PROOFS requires exactly three predicates; this fixture has only one",
        ),
        (
            "invalid.wrong_branch_closure.v0.1.json",
            "canonical_non_implications",
            "RELATIVIZATION branch requires the BGS closure pointer; this fixture points to the RR closure",
        ),
        (
            "invalid.arbitrary_closure_ref.v0.1.json",
            "canonical_non_implications",
            "ALGEBRIZATION branch requires the exact AW closure pointer; this fixture carries an arbitrary string",
        ),
    ],
)
class TestInvalidFixtures:
    def test_fixture_fails_schema_validation(
        self,
        fixture_name: str,
        expected_marker: str,
        defect_kind: str,
    ) -> None:
        validator = Draft202012Validator(_load_schema())
        instance = _load_example(fixture_name)
        errors = list(validator.iter_errors(instance))
        assert errors, (
            f"expected fixture {fixture_name} to fail schema validation "
            f"because {defect_kind}, but it validated cleanly"
        )

    def test_fixture_fails_for_intended_reason(
        self,
        fixture_name: str,
        expected_marker: str,
        defect_kind: str,
    ) -> None:
        """Failure must be traceable to the field the fixture was designed to probe.

        A loose `errors != []` assertion can pass for accidental reasons and
        does not actually protect the v0.1 contract. This check inspects
        ValidationError.absolute_path, ValidationError.absolute_schema_path,
        and ValidationError.message for a stable marker that identifies the
        intended defect.
        """
        validator = Draft202012Validator(_load_schema())
        instance = _load_example(fixture_name)
        errors = list(validator.iter_errors(instance))
        matching = [e for e in errors if _error_matches_marker(e, expected_marker)]
        assert matching, (
            f"fixture {fixture_name} failed validation, but no error referenced "
            f"`{expected_marker}` (the intended defect marker for: {defect_kind}). "
            f"Errors observed: "
            + "; ".join(
                f"path={list(e.absolute_path)} schema_path={list(e.absolute_schema_path)} "
                f"validator={e.validator} message={e.message[:80]}"
                for e in errors
            )
        )
