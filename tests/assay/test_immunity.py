from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.immunity import (
    GUARDIAN_ACTIONS,
    ImmunityValidationError,
    classify_failure,
    derive_epigenetic_markers,
    derive_inoculation_pack,
    load_failure_artifact,
    validate_inoculation_pack,
    validate_marker_safety,
    write_immunity_artifacts,
)

runner = CliRunner()
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "immunity"
SCHEMA_DIR = Path(__file__).resolve().parents[2] / "src" / "assay" / "schemas"
REAL_HONEST_FAILURE_PACK_DIR = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "vectors"
    / "semantic"
    / "claim_insufficient"
)


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _write_minimal_proof_pack_directory(path: Path) -> None:
    path.mkdir()
    manifest = {
        "pack_id": "proof_pack_same",
        "created_at": "2026-05-08T00:00:00Z",
        "files": [{"path": "evidence.json", "sha256": "a" * 64}],
    }
    verify_report = {
        "status": "failed",
        "errors": [{"code": "E_MANIFEST_TAMPER", "message": "tamper detected"}],
    }
    (path / "pack_manifest.json").write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )
    (path / "verify_report.json").write_text(
        json.dumps(verify_report, sort_keys=True),
        encoding="utf-8",
    )


def _write_derived_immunity_artifacts(
    tmp_path: Path,
    fixture_name: str = "unsafe_tool_call_attempt",
) -> tuple[Path, Path]:
    pack = derive_inoculation_pack(_load_fixture(fixture_name))
    marker = derive_epigenetic_markers(pack)[0]
    paths = write_immunity_artifacts(pack, [marker], tmp_path / "immunity_artifacts")
    return paths["pack"], paths[marker.marker_id]


@pytest.mark.parametrize(
    ("fixture_name", "expected_class"),
    [
        ("dignity_boundary_near_miss", "dignity_boundary_near_miss"),
        ("receipt_lineage_conflict", "receipt_lineage_conflict"),
        ("unsafe_tool_call_attempt", "unsafe_tool_call_attempt"),
    ],
)
def test_valid_failure_artifact_produces_valid_inoculation_pack(
    fixture_name: str,
    expected_class: str,
) -> None:
    pack = derive_inoculation_pack(_load_fixture(fixture_name))

    validate_inoculation_pack(pack)
    assert pack.pack_id.startswith("ipack_")
    assert pack.failure_class == expected_class
    assert pack.source_failure_id.startswith("failure_")
    assert pack.recommended_markers
    assert pack.regression_tests


def test_valid_inoculation_pack_produces_epigenetic_marker() -> None:
    pack = derive_inoculation_pack(_load_fixture("unsafe_tool_call_attempt"))
    markers = derive_epigenetic_markers(pack)

    assert len(markers) == 1
    marker = markers[0]
    assert marker.marker_id.startswith("emarker_")
    assert marker.source_pack_id == pack.pack_id
    assert marker.marker_type == "unsafe_tool_call_attempt"
    assert marker.recommended_guardian_action == "block"
    validate_marker_safety(marker)


@pytest.mark.parametrize(
    "fixture_name",
    [
        "dignity_boundary_near_miss",
        "receipt_lineage_conflict",
        "unsafe_tool_call_attempt",
    ],
)
def test_generated_markers_obey_caution_only_invariant(fixture_name: str) -> None:
    pack = derive_inoculation_pack(_load_fixture(fixture_name))

    for marker in derive_epigenetic_markers(pack):
        assert marker.authority_delta <= 0
        assert marker.recommended_guardian_action in GUARDIAN_ACTIONS
        validate_marker_safety(marker)


def test_invalid_marker_actions_are_rejected() -> None:
    marker = _safe_marker_payload()
    marker["recommended_guardian_action"] = "launch_without_review"

    with pytest.raises(ImmunityValidationError, match="invalid guardian action"):
        validate_marker_safety(marker)


def test_authority_increasing_marker_proposals_are_rejected() -> None:
    marker = _safe_marker_payload()
    marker["authority_delta"] = 1

    with pytest.raises(ImmunityValidationError, match="authority_delta"):
        validate_marker_safety(marker)


def test_authority_grant_fields_are_rejected() -> None:
    marker = _safe_marker_payload()
    marker["granted_permissions"] = ["database.delete"]

    with pytest.raises(ImmunityValidationError, match="authority-granting"):
        validate_marker_safety(marker)


def test_pack_output_is_deterministic_for_same_input() -> None:
    artifact = _load_fixture("dignity_boundary_near_miss")

    pack_a = derive_inoculation_pack(artifact)
    pack_b = derive_inoculation_pack(artifact)
    markers_a = derive_epigenetic_markers(pack_a)
    markers_b = derive_epigenetic_markers(pack_b)

    assert pack_a.to_dict() == pack_b.to_dict()
    assert [marker.to_dict() for marker in markers_a] == [
        marker.to_dict() for marker in markers_b
    ]


def test_missing_required_fields_fail_cleanly() -> None:
    artifact = _load_fixture("dignity_boundary_near_miss")
    del artifact["minimal_replay_case"]

    with pytest.raises(ImmunityValidationError, match="missing required field"):
        derive_inoculation_pack(artifact)


def test_minimal_replay_case_is_preserved() -> None:
    artifact = _load_fixture("unsafe_tool_call_attempt")
    pack = derive_inoculation_pack(artifact)

    assert pack.minimal_replay_case == artifact["minimal_replay_case"]


def test_evidence_hashes_are_preserved_and_computed() -> None:
    artifact = _load_fixture("receipt_lineage_conflict")
    pack = derive_inoculation_pack(artifact)

    assert (
        pack.evidence_hashes["pack_manifest"]
        == artifact["evidence_hashes"]["pack_manifest"]
    )
    assert pack.evidence_hashes["input_artifact"].startswith("sha256:")
    assert pack.evidence_hashes["minimal_replay_case"].startswith("sha256:")


def test_expiration_and_rollback_metadata_exists() -> None:
    pack = derive_inoculation_pack(_load_fixture("dignity_boundary_near_miss"))
    marker = derive_epigenetic_markers(pack)[0]

    assert pack.review_after == "90d"
    assert pack.rollback_pointer == "policy_v12"
    assert marker.expires_after == "90d"
    assert marker.rollback_pointer == "policy_v12"


def test_artifacts_validate_against_json_schemas() -> None:
    pack = derive_inoculation_pack(_load_fixture("unsafe_tool_call_attempt"))
    marker = derive_epigenetic_markers(pack)[0]
    pack_schema = json.loads(
        (SCHEMA_DIR / "inoculation_pack.v0.1.schema.json").read_text(encoding="utf-8")
    )
    marker_schema = json.loads(
        (SCHEMA_DIR / "epigenetic_marker.v0.1.schema.json").read_text(encoding="utf-8")
    )

    Draft202012Validator(pack_schema).validate(pack.to_dict())
    Draft202012Validator(marker_schema).validate(marker.to_dict())


def test_cli_derive_writes_pack_and_marker(tmp_path: Path) -> None:
    fixture = FIXTURE_DIR / "unsafe_tool_call_attempt.json"
    out_dir = tmp_path / "immunity"

    result = runner.invoke(
        assay_app,
        ["immunity", "derive", str(fixture), "--out-dir", str(out_dir), "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    pack_path = Path(payload["inoculation_pack"])
    marker_path = Path(payload["markers"][0]["path"])
    assert pack_path.exists()
    assert marker_path.exists()
    assert json.loads(pack_path.read_text(encoding="utf-8"))["failure_class"] == (
        "unsafe_tool_call_attempt"
    )


def test_verify_valid_inoculation_pack_passes(tmp_path: Path) -> None:
    pack_path, _ = _write_derived_immunity_artifacts(tmp_path)

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(pack_path), "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["artifact_type"] == "assay.inoculation_pack"
    assert payload["valid"] is True
    assert payload["schema_valid"] is True
    assert payload["errors"] == []


def test_verify_valid_marker_passes(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(marker_path), "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["artifact_type"] == "assay.epigenetic_marker"
    assert payload["valid"] is True
    assert payload["schema_valid"] is True
    assert payload["errors"] == []


def test_verify_positive_authority_delta_fails(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["authority_delta"] = 1
    marker_path.write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(marker_path), "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "invalid"
    assert any("authority_delta" in error for error in payload["errors"])


def test_verify_forbidden_guardian_action_fails(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["recommended_guardian_action"] = "grant_permission"
    marker_path.write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(marker_path), "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "invalid"
    assert any(
        "authority-increasing guardian action" in error
        or "recommended_guardian_action" in error
        for error in payload["errors"]
    )


def test_verify_missing_rollback_or_expiration_fails(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["rollback_pointer"] = ""
    marker["expires_after"] = None
    marker["expires_at"] = None
    marker_path.write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(marker_path), "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "invalid"
    assert any(
        "rollback" in error or "expires" in error or "expiration" in error
        for error in payload["errors"]
    )


def test_verify_expired_marker_fails_as_stale(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["expires_after"] = None
    marker["expires_at"] = "2020-01-01T00:00:00Z"
    marker_path.write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(marker_path), "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "invalid"
    assert payload["stale"] is True
    assert any("stale" in error for error in payload["errors"])


def test_verify_malformed_json_exits_cleanly(tmp_path: Path) -> None:
    artifact_path = tmp_path / "bad_immunity.json"
    artifact_path.write_text("{bad json", encoding="utf-8")

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(artifact_path), "--json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["status"] == "error"
    assert "invalid JSON artifact" in payload["error"]


def test_verify_cli_json_output_is_stable(tmp_path: Path) -> None:
    pack_path, _ = _write_derived_immunity_artifacts(tmp_path)

    result_a = runner.invoke(
        assay_app,
        ["immunity", "verify", str(pack_path), "--json"],
    )
    result_b = runner.invoke(
        assay_app,
        ["immunity", "verify", str(pack_path), "--json"],
    )

    assert result_a.exit_code == 0
    assert result_b.exit_code == 0
    assert result_a.output == result_b.output


def test_verify_pack_id_mismatch_fails(tmp_path: Path) -> None:
    pack_path, _ = _write_derived_immunity_artifacts(tmp_path)
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    pack["pack_id"] = "ipack_badbadbadbadbadbadbadbad"
    pack_path.write_text(
        json.dumps(pack, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(pack_path), "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["identity_valid"] is False
    assert any("pack_id mismatch" in error for error in payload["errors"])


def test_verify_marker_id_mismatch_fails(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["marker_id"] = "emarker_badbadbadbadbadbadbadbad"
    marker_path.write_text(
        json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(marker_path), "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["identity_valid"] is False
    assert any("marker_id mismatch" in error for error in payload["errors"])


def test_verify_with_source_pack_binds_real_proof_pack(tmp_path: Path) -> None:
    artifact = load_failure_artifact(REAL_HONEST_FAILURE_PACK_DIR)
    pack = derive_inoculation_pack(artifact)
    marker = derive_epigenetic_markers(pack)[0]
    paths = write_immunity_artifacts(pack, [marker], tmp_path / "dogfood")

    result = runner.invoke(
        assay_app,
        [
            "immunity",
            "verify",
            str(paths["pack"]),
            "--source-pack",
            str(REAL_HONEST_FAILURE_PACK_DIR),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["source_bound"] is True
    assert payload["identity_valid"] is True


def test_verify_with_source_pack_detects_source_hash_mismatch(tmp_path: Path) -> None:
    source_copy = tmp_path / "claim_insufficient"
    shutil.copytree(REAL_HONEST_FAILURE_PACK_DIR, source_copy)
    artifact = load_failure_artifact(source_copy)
    pack = derive_inoculation_pack(artifact)
    marker = derive_epigenetic_markers(pack)[0]
    paths = write_immunity_artifacts(pack, [marker], tmp_path / "dogfood")
    verify_report_path = source_copy / "verify_report.json"
    verify_report = json.loads(verify_report_path.read_text(encoding="utf-8"))
    verify_report["warnings"] = ["mutated after immunity derivation"]
    verify_report_path.write_text(
        json.dumps(verify_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        assay_app,
        [
            "immunity",
            "verify",
            str(paths["pack"]),
            "--source-pack",
            str(source_copy),
            "--json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["source_bound"] is False
    assert any("source evidence hash mismatch" in error for error in payload["errors"])


def test_verify_marker_with_source_pack_fails_closed(tmp_path: Path) -> None:
    _, marker_path = _write_derived_immunity_artifacts(tmp_path)

    result = runner.invoke(
        assay_app,
        [
            "immunity",
            "verify",
            str(marker_path),
            "--source-pack",
            str(REAL_HONEST_FAILURE_PACK_DIR),
            "--json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["source_bound"] is False
    assert any("source binding requires an InoculationPack" in error for error in payload["errors"])


def test_signal_exports_source_bound_caution_signal(tmp_path: Path) -> None:
    artifact = load_failure_artifact(REAL_HONEST_FAILURE_PACK_DIR)
    pack = derive_inoculation_pack(artifact)
    marker = derive_epigenetic_markers(pack)[0]
    paths = write_immunity_artifacts(pack, [marker], tmp_path / "dogfood")

    result = runner.invoke(
        assay_app,
        [
            "immunity",
            "signal",
            str(paths["pack"]),
            "--marker",
            str(paths[marker.marker_id]),
            "--source-pack",
            str(REAL_HONEST_FAILURE_PACK_DIR),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    signal = payload["signal"]
    assert payload["status"] == "ok"
    assert signal["signal_type"] == "assay.guardian_caution_signal"
    assert signal["source_proof_pack_id"] == "pack_deterministic_a1efcfcc"
    assert signal["inoculation_pack_id"] == pack.pack_id
    assert signal["marker_id"] == marker.marker_id
    assert signal["recommended_action"] == marker.recommended_guardian_action
    assert signal["authority_delta"] <= 0
    assert signal["may_increase_authority"] is False
    assert signal["source_bound"] is True
    assert signal["identity_valid"] is True


def test_signal_rejects_marker_from_different_pack(tmp_path: Path) -> None:
    artifact = load_failure_artifact(REAL_HONEST_FAILURE_PACK_DIR)
    pack = derive_inoculation_pack(artifact)
    marker = derive_epigenetic_markers(pack)[0]
    paths = write_immunity_artifacts(pack, [marker], tmp_path / "dogfood")
    marker_payload = json.loads(paths[marker.marker_id].read_text(encoding="utf-8"))
    marker_payload["source_pack_id"] = "ipack_other"
    marker_payload["marker_id"] = "emarker_badbadbadbadbadbadbadbad"
    bad_marker_path = tmp_path / "bad_marker.json"
    bad_marker_path.write_text(
        json.dumps(marker_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        assay_app,
        [
            "immunity",
            "signal",
            str(paths["pack"]),
            "--marker",
            str(bad_marker_path),
            "--source-pack",
            str(REAL_HONEST_FAILURE_PACK_DIR),
            "--json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "invalid"
    assert "invalid EpigeneticMarker" in payload["error"]


def test_real_claim_insufficient_proof_pack_can_be_derived_and_verified(
    tmp_path: Path,
) -> None:
    artifact = load_failure_artifact(REAL_HONEST_FAILURE_PACK_DIR)
    pack = derive_inoculation_pack(artifact)
    marker = derive_epigenetic_markers(pack)[0]
    paths = write_immunity_artifacts(pack, [marker], tmp_path / "dogfood")

    pack_result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(paths["pack"]), "--json"],
    )
    marker_result = runner.invoke(
        assay_app,
        ["immunity", "verify", str(paths[marker.marker_id]), "--json"],
    )

    assert pack_result.exit_code == 0
    assert marker_result.exit_code == 0
    assert json.loads(pack_result.output)["status"] == "ok"
    assert json.loads(marker_result.output)["status"] == "ok"
    assert pack.source_proof_pack_id == "pack_deterministic_a1efcfcc"


def test_proof_pack_directory_derivation_is_path_independent(tmp_path: Path) -> None:
    pack_dir_a = tmp_path / "pack_a"
    pack_dir_b = tmp_path / "pack_b"
    _write_minimal_proof_pack_directory(pack_dir_a)
    _write_minimal_proof_pack_directory(pack_dir_b)

    pack_a = derive_inoculation_pack(load_failure_artifact(pack_dir_a))
    pack_b = derive_inoculation_pack(load_failure_artifact(pack_dir_b))

    assert pack_a.source_failure_id == pack_b.source_failure_id
    assert pack_a.pack_id == pack_b.pack_id
    assert "path" not in pack_a.minimal_replay_case
    assert pack_a.minimal_replay_case["command"] == "assay verify-pack <proof-pack-dir>"


def test_malformed_verify_report_fails_cleanly(tmp_path: Path) -> None:
    pack_dir = tmp_path / "bad_pack"
    pack_dir.mkdir()
    (pack_dir / "pack_manifest.json").write_text(
        json.dumps({"pack_id": "proof_pack_bad", "files": []}),
        encoding="utf-8",
    )
    (pack_dir / "verify_report.json").write_text("{bad json", encoding="utf-8")

    with pytest.raises(ImmunityValidationError, match="invalid verify_report.json"):
        load_failure_artifact(pack_dir)


def test_cli_malformed_verify_report_returns_structured_error(tmp_path: Path) -> None:
    pack_dir = tmp_path / "bad_pack"
    pack_dir.mkdir()
    (pack_dir / "pack_manifest.json").write_text(
        json.dumps({"pack_id": "proof_pack_bad", "files": []}),
        encoding="utf-8",
    )
    (pack_dir / "verify_report.json").write_text("{bad json", encoding="utf-8")

    result = runner.invoke(assay_app, ["immunity", "derive", str(pack_dir), "--json"])

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["status"] == "error"
    assert "invalid verify_report.json" in payload["error"]


def test_classify_failure_handles_cyclic_mapping_without_raw_value_error() -> None:
    artifact = {}
    artifact["self"] = artifact

    assert classify_failure(artifact) == "evidence_gap"


def _safe_marker_payload() -> dict:
    return {
        "marker_type": "evidence_gap",
        "source_pack_id": "ipack_test",
        "trigger_shape": "missing evidence",
        "recommended_guardian_action": "require_stronger_proof",
        "authority_delta": -1,
        "confidence": 0.8,
        "expires_after": "90d",
        "expires_at": None,
        "rollback_pointer": "policy_v12",
        "rationale": "Missing evidence requires stronger proof.",
        "evidence_hash": "sha256:abcd",
    }
