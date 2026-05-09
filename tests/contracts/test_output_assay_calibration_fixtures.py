"""Contract tests for Output Assay calibration fixtures.

These tests validate fixture shape only. They do not implement analyzer
behavior, call providers, or judge the external truth of artifact content.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
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
ALLOWED_MANIFEST_STATUSES = {"seed", "v0_complete"}
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

MIN_ACTIVE_FIXTURE_COUNT = 20
MIN_CATEGORY_COUNTS = {
    "positive_control": 5,
    "negative_control": 5,
    "mixed_quality": 5,
    "business_artifact": 3,
    "non_claim_artifact": 2,
}
RHETORICAL_PADDING_FAILURE_MODES = {"rhetorical_padding", "redundancy_padding"}
SUPPORT_GAP_FAILURE_MODES = {"support_gap", "unearned_confidence"}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_prefixed(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_manifest() -> dict:
    return _load_json(MANIFEST_PATH)


def _span_matches_artifact(
    artifact_text: str, artifact_span: dict[str, object]
) -> bool:
    start_char = artifact_span["start_char"]
    end_char = artifact_span["end_char"]
    span_text = artifact_span["text"]

    assert isinstance(start_char, int)
    assert isinstance(end_char, int)
    assert isinstance(span_text, str)

    if start_char < 0 or end_char < 0:
        return False
    if end_char > len(artifact_text):
        return False
    return artifact_text[start_char:end_char] == span_text


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


def _load_fixture_corpus() -> list[tuple[dict, dict, dict]]:
    manifest = _load_manifest()
    corpus: list[tuple[dict, dict, dict]] = []
    for entry in manifest["fixtures"]:
        fixture_dir = FIXTURE_ROOT / entry["path"]
        corpus.append(
            (
                entry,
                _load_json(fixture_dir / "fixture.json"),
                _load_json(fixture_dir / "expected_run.json"),
            )
        )
    return corpus


def test_manifest_and_category_directories_exist() -> None:
    manifest = _load_manifest()

    assert FIXTURE_ROOT.exists()
    assert (FIXTURE_ROOT / "README.md").exists()
    assert MANIFEST_PATH.exists()
    assert manifest["schema_version"] == "0.1"
    assert manifest["status"] in ALLOWED_MANIFEST_STATUSES
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
        artifact_text = (fixture_dir / fixture["artifact_path"]).read_text(
            encoding="utf-8"
        )
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
            assert artifact_span["start_char"] >= 0
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
                assert not _span_matches_artifact(artifact_text, artifact_span)
            else:
                assert _span_matches_artifact(artifact_text, artifact_span)

            if guardian_verdict["run_status"] == "block":
                assert promotion_eligibility["status"] == "ineligible"

            if promotion_eligibility["status"] == "eligible":
                assert observed_unit["unit_type"] == "claim"
                assert observed_unit["observation_status"] != "guardian_blocked"
                assert "reasons" not in promotion_eligibility

        assert guardian_verdict["observation_counts"] == status_counts


def test_calibration_completeness_gate() -> None:
    manifest = _load_manifest()
    active_corpus = [
        corpus_entry
        for corpus_entry in _load_fixture_corpus()
        if corpus_entry[0]["status"] == "active"
    ]
    category_counts = Counter(entry["category"] for entry, _, _ in active_corpus)
    run_statuses: set[str] = set()
    invalid_promotion_units: list[tuple[str, str, str]] = []
    blocked_run_promotion_units: list[tuple[str, str]] = []

    has_clean_positive_pass = False
    has_rhetorical_padding_negative = False
    has_support_gap_coverage = False
    has_mixed_claim_and_non_claim = False
    has_non_claim_observation_without_promotion = False

    for entry, fixture, expected_run in active_corpus:
        guardian_verdict = expected_run["guardian_verdict"]
        observed_units = expected_run["observed_units"]
        failure_modes = set(fixture["expected_failure_modes"]) | set(
            guardian_verdict["failure_modes"]
        )
        run_status = guardian_verdict["run_status"]
        run_statuses.add(run_status)

        if (
            entry["category"] == "positive_control"
            and run_status == "pass"
            and expected_run["compression"]["status"] == "preserve"
            and not guardian_verdict["failure_modes"]
        ):
            has_clean_positive_pass = True

        if entry["category"] == "negative_control" and (
            failure_modes & RHETORICAL_PADDING_FAILURE_MODES
        ):
            has_rhetorical_padding_negative = True

        if failure_modes & SUPPORT_GAP_FAILURE_MODES:
            has_support_gap_coverage = True

        if (
            entry["category"] == "mixed_quality"
            and any(
                observed_unit["unit_type"] == "claim"
                for observed_unit in observed_units
            )
            and any(
                observed_unit["unit_type"] != "claim"
                for observed_unit in observed_units
            )
        ):
            has_mixed_claim_and_non_claim = True

        if (
            entry["category"] == "non_claim_artifact"
            and observed_units
            and any(
                observed_unit["observation_status"]
                in {"guardian_passed", "guardian_warned"}
                for observed_unit in observed_units
            )
            and all(
                observed_unit["promotion_eligibility"]["status"] == "ineligible"
                for observed_unit in observed_units
            )
        ):
            has_non_claim_observation_without_promotion = True

        for observed_unit in observed_units:
            promotion_status = observed_unit["promotion_eligibility"]["status"]

            if observed_unit["unit_type"] != "claim" and promotion_status == "eligible":
                invalid_promotion_units.append(
                    (entry["fixture_id"], observed_unit["unit_id"], "non_claim_unit")
                )

            if (
                observed_unit["observation_status"] == "guardian_blocked"
                and promotion_status == "eligible"
            ):
                invalid_promotion_units.append(
                    (
                        entry["fixture_id"],
                        observed_unit["unit_id"],
                        "guardian_blocked",
                    )
                )

            if run_status == "block" and promotion_status == "eligible":
                blocked_run_promotion_units.append(
                    (entry["fixture_id"], observed_unit["unit_id"])
                )

    completeness_checks = {
        "minimum_active_fixture_count": len(active_corpus) >= MIN_ACTIVE_FIXTURE_COUNT,
        "minimum_positive_controls": (
            category_counts["positive_control"]
            >= MIN_CATEGORY_COUNTS["positive_control"]
        ),
        "minimum_negative_controls": (
            category_counts["negative_control"]
            >= MIN_CATEGORY_COUNTS["negative_control"]
        ),
        "minimum_mixed_quality": (
            category_counts["mixed_quality"] >= MIN_CATEGORY_COUNTS["mixed_quality"]
        ),
        "minimum_business_artifacts": (
            category_counts["business_artifact"]
            >= MIN_CATEGORY_COUNTS["business_artifact"]
        ),
        "minimum_non_claim_artifacts": (
            category_counts["non_claim_artifact"]
            >= MIN_CATEGORY_COUNTS["non_claim_artifact"]
        ),
        "has_clean_positive_pass": has_clean_positive_pass,
        "has_rhetorical_padding_negative": has_rhetorical_padding_negative,
        "has_support_gap_coverage": has_support_gap_coverage,
        "has_mixed_claim_and_non_claim": has_mixed_claim_and_non_claim,
        "has_non_claim_observation_without_promotion": (
            has_non_claim_observation_without_promotion
        ),
        "has_block_disposition": "block" in run_statuses,
        "has_warn_disposition": "warn" in run_statuses,
        "has_pass_disposition": "pass" in run_statuses,
    }

    assert all(completeness_checks.values()), completeness_checks
    assert not invalid_promotion_units, invalid_promotion_units
    assert not blocked_run_promotion_units, blocked_run_promotion_units

    if manifest["status"] == "v0_complete":
        assert all(completeness_checks.values()), completeness_checks
