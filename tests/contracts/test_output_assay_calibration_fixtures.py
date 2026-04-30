"""Contract tests for Output Assay calibration fixtures.

These tests validate fixture shape only. They do not implement analyzer
behavior, call providers, or judge the external truth of artifact content.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "output_assay"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"

ALLOWED_DIRECTORY_CATEGORIES = {
    "positive_controls",
    "negative_controls",
    "mixed_quality",
    "business_artifacts",
    "non_claim_artifacts",
}
ALLOWED_FIXTURE_CATEGORIES = {
    "positive_control",
    "negative_control",
    "mixed_quality",
    "business_artifact",
    "non_claim_artifact",
}
ALLOWED_INTENT_CLASSES = {
    "argument",
    "plan",
    "technical_answer",
    "decision_memo",
    "status_update",
    "creative",
    "emotional_support",
    "brainstorm",
    "sales_pitch",
    "research_summary",
}
ALLOWED_ARTIFACT_KINDS = {
    "spec_proposal",
    "support_note",
    "boundary_example",
}
ALLOWED_RUN_DISPOSITIONS = {"pass", "warn", "block"}
ALLOWED_COMPRESSION_BEHAVIORS = {"preserve", "compress", "quarantine"}
ALLOWED_PROMOTION_SURFACES = {"observation_only", "claim_review_possible"}
ALLOWED_UNIT_TYPES = {
    "claim",
    "constraint",
    "action",
    "question",
    "decision",
    "risk",
    "emotion",
    "insight",
    "commitment",
    "instruction",
}
ALLOWED_SOURCE_ROLES = {
    "evidence",
    "assertion",
    "instruction",
    "context",
    "example",
    "unknown",
}
ALLOWED_OBSERVATION_STATUSES = {
    "draft",
    "guardian_passed",
    "guardian_warned",
    "guardian_blocked",
}
ALLOWED_ANCHORING_EXPECTATIONS = {"anchored", "unanchorable"}
ALLOWED_PROMOTION_STATUSES = {"eligible", "ineligible"}

REQUIRED_FIXTURE_FIELDS = {
    "fixture_id",
    "title",
    "status",
    "category",
    "artifact_path",
    "artifact_hash",
    "declared_intent_class",
    "expected_run_disposition",
    "expected_failure_modes",
    "expected_compression_behavior",
    "promotion_surface",
}
OPTIONAL_FIXTURE_FIELDS = {"artifact_kind", "labels", "notes"}
REQUIRED_RUN_FIELDS = {
    "fixture_id",
    "input_hash",
    "intent_class",
    "summary",
    "observed_units",
    "guardian_verdict",
    "compression",
    "truth_verification",
}
REQUIRED_GUARDIAN_FIELDS = {
    "run_status",
    "observation_counts",
    "failure_modes",
    "warnings",
    "block_reasons",
}
REQUIRED_UNIT_FIELDS = {
    "receipt_type",
    "unit_id",
    "unit_type",
    "source_role",
    "artifact_span",
    "normalized_text",
    "observation_status",
    "promotion_eligibility",
}
REQUIRED_PROMOTION_FIELDS = {"status", "reason"}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_prefixed(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_manifest() -> dict:
    return _load_json(MANIFEST_PATH)


def _fixture_directories() -> set[str]:
    dirs: set[str] = set()
    for category_dir in ALLOWED_DIRECTORY_CATEGORIES:
        base = FIXTURE_ROOT / category_dir
        if not base.exists():
            continue
        for child in base.iterdir():
            if child.is_dir() and (child / "fixture.json").exists():
                dirs.add(str(child.relative_to(FIXTURE_ROOT)))
    return dirs


def test_manifest_and_category_directories_exist() -> None:
    manifest = _load_manifest()

    assert FIXTURE_ROOT.exists()
    assert (FIXTURE_ROOT / "README.md").exists()
    assert MANIFEST_PATH.exists()
    assert manifest["schema_version"] == "0.1"
    assert manifest["status"] == "seed"
    assert manifest["fixture_root"] == "tests/fixtures/output_assay"
    assert set(manifest["categories"]) == ALLOWED_DIRECTORY_CATEGORIES

    for category_dir in ALLOWED_DIRECTORY_CATEGORIES:
        assert (FIXTURE_ROOT / category_dir).exists(), category_dir


def test_manifest_matches_fixture_directories() -> None:
    manifest = _load_manifest()
    manifest_paths = {entry["path"] for entry in manifest["fixtures"]}

    assert manifest_paths == _fixture_directories()

    for entry in manifest["fixtures"]:
        assert entry["status"] == "active", entry["fixture_id"]
        assert entry["category"] in ALLOWED_FIXTURE_CATEGORIES, entry["fixture_id"]
        assert (FIXTURE_ROOT / entry["path"]).exists(), entry["fixture_id"]


def test_fixture_metadata_contract() -> None:
    manifest = _load_manifest()

    for entry in manifest["fixtures"]:
        fixture_dir = FIXTURE_ROOT / entry["path"]
        fixture = _load_json(fixture_dir / "fixture.json")
        artifact_path = fixture_dir / fixture["artifact_path"]
        allowed_fields = REQUIRED_FIXTURE_FIELDS | OPTIONAL_FIXTURE_FIELDS

        assert set(fixture) <= allowed_fields, entry["fixture_id"]
        assert REQUIRED_FIXTURE_FIELDS <= set(fixture), entry["fixture_id"]
        assert fixture["fixture_id"] == entry["fixture_id"]
        assert fixture["category"] == entry["category"]
        assert fixture["status"] == entry["status"]
        assert fixture["declared_intent_class"] in ALLOWED_INTENT_CLASSES
        assert fixture["expected_run_disposition"] in ALLOWED_RUN_DISPOSITIONS
        assert fixture["expected_compression_behavior"] in ALLOWED_COMPRESSION_BEHAVIORS
        assert fixture["promotion_surface"] in ALLOWED_PROMOTION_SURFACES
        assert isinstance(fixture["expected_failure_modes"], list)
        if "artifact_kind" in fixture:
            assert fixture["artifact_kind"] in ALLOWED_ARTIFACT_KINDS
        assert artifact_path.exists(), entry["fixture_id"]
        assert fixture["artifact_hash"] == _sha256_prefixed(artifact_path)


def test_expected_run_contract() -> None:
    manifest = _load_manifest()

    for entry in manifest["fixtures"]:
        fixture_dir = FIXTURE_ROOT / entry["path"]
        fixture = _load_json(fixture_dir / "fixture.json")
        expected_run = _load_json(fixture_dir / "expected_run.json")
        guardian_verdict = expected_run["guardian_verdict"]
        compression = expected_run["compression"]
        truth_verification = expected_run["truth_verification"]
        observed_units = expected_run["observed_units"]

        assert set(expected_run) == REQUIRED_RUN_FIELDS, entry["fixture_id"]
        assert expected_run["fixture_id"] == fixture["fixture_id"]
        assert expected_run["input_hash"] == fixture["artifact_hash"]
        assert expected_run["intent_class"] == fixture["declared_intent_class"]
        assert isinstance(expected_run["summary"], str) and expected_run["summary"]
        assert isinstance(observed_units, list) and observed_units, entry["fixture_id"]

        assert REQUIRED_GUARDIAN_FIELDS <= set(guardian_verdict), entry["fixture_id"]
        assert guardian_verdict["run_status"] == fixture["expected_run_disposition"]
        assert guardian_verdict["run_status"] in ALLOWED_RUN_DISPOSITIONS
        assert guardian_verdict["failure_modes"] == fixture["expected_failure_modes"]
        assert compression["status"] == fixture["expected_compression_behavior"]
        assert compression["status"] in ALLOWED_COMPRESSION_BEHAVIORS
        assert truth_verification["performed"] is False
        assert truth_verification["tier"] == "internal_support_only"

        status_counts = {
            "guardian_passed": 0,
            "guardian_warned": 0,
            "guardian_blocked": 0,
        }

        for observed_unit in observed_units:
            assert REQUIRED_UNIT_FIELDS <= set(observed_unit), entry["fixture_id"]
            assert observed_unit["receipt_type"] == "artifact.unit_observed"
            assert observed_unit["unit_type"] in ALLOWED_UNIT_TYPES
            assert observed_unit["source_role"] in ALLOWED_SOURCE_ROLES
            assert observed_unit["observation_status"] in ALLOWED_OBSERVATION_STATUSES
            assert isinstance(observed_unit["normalized_text"], str)
            assert observed_unit["normalized_text"]

            if "anchoring_expectation" in observed_unit:
                assert (
                    observed_unit["anchoring_expectation"]
                    in ALLOWED_ANCHORING_EXPECTATIONS
                )
            if "anchoring_notes" in observed_unit:
                assert isinstance(observed_unit["anchoring_notes"], str)
                assert observed_unit["anchoring_notes"]

            artifact_span = observed_unit["artifact_span"]
            assert set(artifact_span) == {"text", "start_char", "end_char"}
            assert isinstance(artifact_span["text"], str) and artifact_span["text"]
            assert isinstance(artifact_span["start_char"], int)
            assert isinstance(artifact_span["end_char"], int)
            assert artifact_span["start_char"] <= artifact_span["end_char"]

            promotion_eligibility = observed_unit["promotion_eligibility"]
            assert REQUIRED_PROMOTION_FIELDS <= set(promotion_eligibility)
            assert promotion_eligibility["status"] in ALLOWED_PROMOTION_STATUSES
            assert isinstance(promotion_eligibility["reason"], str)
            assert promotion_eligibility["reason"]
            if "reasons" in promotion_eligibility:
                assert isinstance(promotion_eligibility["reasons"], list)
                assert promotion_eligibility["reasons"]
                assert all(
                    isinstance(reason, str) and reason
                    for reason in promotion_eligibility["reasons"]
                )

            if observed_unit["observation_status"] != "draft":
                status_counts[observed_unit["observation_status"]] += 1

            if observed_unit["unit_type"] != "claim":
                assert promotion_eligibility["status"] == "ineligible"

            if observed_unit["observation_status"] == "guardian_blocked":
                assert promotion_eligibility["status"] == "ineligible"

            if observed_unit.get("anchoring_expectation") == "unanchorable":
                assert observed_unit["observation_status"] == "guardian_blocked"
                assert promotion_eligibility["status"] == "ineligible"

            if guardian_verdict["run_status"] == "block":
                assert promotion_eligibility["status"] == "ineligible"

            if promotion_eligibility["status"] == "eligible":
                assert observed_unit["unit_type"] == "claim"
                assert observed_unit["observation_status"] != "guardian_blocked"
                assert "reasons" not in promotion_eligibility

        assert guardian_verdict["observation_counts"] == status_counts
