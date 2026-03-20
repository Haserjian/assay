"""Validation tests for checkpoint evaluation schema examples."""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = ROOT / "docs" / "examples" / "checkpoints"


def _load_schema(name: str) -> dict:
    schema_path = resources.files("assay").joinpath(
        f"schemas/{name}"
    )
    return json.loads(schema_path.read_text())


def _load_example(name: str) -> dict:
    return json.loads((EXAMPLES_DIR / name).read_text())


class TestCheckpointEvaluationSchema:
    def test_schema_is_valid_draft_2020_12(self) -> None:
        schema = _load_schema("checkpoint_evaluation.outbound_action.send_email.v0.1.schema.json")
        Draft202012Validator.check_schema(schema)

    def test_allow_if_approved_example_validates(self) -> None:
        validator = Draft202012Validator(_load_schema("checkpoint_evaluation.outbound_action.send_email.v0.1.schema.json"))
        instance = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")

        validator.validate(instance)
        assert instance["evaluation_outcome"]["route"] == "allow_if_approved"
        assert instance["evaluation_outcome"]["human_review_required"] is True

    def test_blocked_example_validates(self) -> None:
        validator = Draft202012Validator(_load_schema("checkpoint_evaluation.outbound_action.send_email.v0.1.schema.json"))
        instance = _load_example("outbound_action.send_email.blocked.v0.1.json")

        validator.validate(instance)
        assert instance["evaluation_outcome"]["route"] == "block"
        assert any(gap["blocking"] for gap in instance["evidence_bundle"]["gaps"])


class TestCheckpointRequestAndResolutionSchema:
    def test_request_schema_and_example_validate(self) -> None:
        schema = _load_schema("checkpoint_request.outbound_action.send_email.v0.1.schema.json")
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        instance = _load_example("outbound_action.send_email.request.v0.1.json")

        validator.validate(instance)
        assert instance["artifact_type"] == "checkpoint_request"

    def test_resolution_schema_and_released_example_validate(self) -> None:
        schema = _load_schema("checkpoint_resolution.outbound_action.send_email.v0.1.schema.json")
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        instance = _load_example("outbound_action.send_email.resolution.released.v0.1.json")

        validator.validate(instance)
        assert instance["resolution_outcome"] == "released"
        assert instance["final_evaluation_id"] == instance["evaluation_id"]

    def test_resolution_schema_and_blocked_example_validate(self) -> None:
        validator = Draft202012Validator(
            _load_schema("checkpoint_resolution.outbound_action.send_email.v0.1.schema.json")
        )
        instance = _load_example("outbound_action.send_email.resolution.blocked.v0.1.json")

        validator.validate(instance)
        assert instance["resolution_outcome"] == "blocked"
        assert instance["final_evaluation_id"] == instance["evaluation_id"]
