"""Tests for Output Assay operator report rendering and CLI wiring."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.output_assay import (
    render_output_assay_report,
    run_output_assay_locally,
)

runner = CliRunner()


def _valid_payload() -> dict[str, object]:
    return {
        "intent_class": "technical_answer",
        "summary": "The draft extracts one claim and one instruction without stamping any canonical receipt fields.",
        "observed_units": [
            {
                "unit_type": "claim",
                "source_role": "assertion",
                "artifact_span": {
                    "text": "Observation is not assertion.",
                    "start_char": 0,
                    "end_char": 29,
                },
                "normalized_text": "Observation is not assertion.",
                "observation_confidence": 0.94,
                "notes": "Candidate claim pending Guardian review.",
            },
            {
                "unit_type": "instruction",
                "source_role": "instruction",
                "artifact_span": {
                    "text": "Action: validate locally first.",
                    "start_char": 30,
                    "end_char": 61,
                },
                "normalized_text": "Action: validate locally first.",
                "observation_confidence": 0.81,
                "notes": "Non-claim units remain observation-only in v0.",
            },
        ],
    }


def _artifact_text() -> str:
    return "Observation is not assertion.\nAction: validate locally first.\n"


def _blocked_payload() -> dict[str, object]:
    return {
        "intent_class": "technical_answer",
        "summary": "The draft includes an unanchorable claim that should block.",
        "observed_units": [
            {
                "unit_type": "claim",
                "source_role": "assertion",
                "artifact_span": {
                    "text": "Observation is not assertion.",
                    "start_char": 0,
                    "end_char": 29,
                },
                "normalized_text": "Observation is not assertion.",
                "observation_confidence": 0.94,
                "notes": "Anchored claim.",
            },
            {
                "unit_type": "claim",
                "source_role": "assertion",
                "artifact_span": {
                    "text": "This hidden guarantee does not appear in the artifact.",
                    "start_char": 999,
                    "end_char": 1052,
                },
                "normalized_text": "This hidden guarantee does not appear in the artifact.",
                "observation_confidence": 0.79,
                "notes": "This should block because the span is unanchorable.",
            },
        ],
    }


def test_render_output_assay_report_for_guarded_run() -> None:
    result = run_output_assay_locally(_artifact_text(), _valid_payload())
    report = render_output_assay_report(result)

    expected = (
        "# OUTPUT ASSAY REPORT\n"
        "\n"
        "Run:\n"
        f"  status: {result.guardian_verdict.run_status.value}\n"
        f"  artifact_hash: {result.artifact_hash}\n"
        f"  run_id: {result.run_id}\n"
        f"  intent_class: {result.intent_class.value}\n"
        f"  summary: {result.summary}\n"
        "  truth_verification: performed=false tier=internal_support_only\n"
        "\n"
        "Observed units:\n"
        "  - claim / assertion / promotable=true / status=guardian_passed / span 0:29\n"
        "    text: Observation is not assertion.\n"
        "    reason: claim_unit_with_clean_provenance\n"
        "  - instruction / instruction / promotable=false / status=guardian_passed / span 30:61\n"
        "    text: Action: validate locally first.\n"
        "    reason: non_claim_unit\n"
        "\n"
        "Support posture:\n"
        "  failure_modes: none\n"
        "  warnings: none\n"
        "  block_reasons: none\n"
        "\n"
        "Decision:\n"
        "  preserve"
    )

    assert report == expected


def test_render_output_assay_report_for_extraction_failure() -> None:
    invalid_payload = {
        "intent_class": "technical_answer",
        "summary": "Missing observed units",
    }
    result = run_output_assay_locally(_artifact_text(), invalid_payload)
    report = render_output_assay_report(result)

    expected = (
        "# OUTPUT ASSAY REPORT\n"
        "\n"
        "Run:\n"
        "  status: extraction_failure\n"
        f"  artifact_hash: {result.artifact_hash}\n"
        f"  failure_id: {result.failure_id}\n"
        "  truth_verification: performed=false tier=internal_support_only\n"
        "\n"
        "Failure:\n"
        "  stage: draft_validation\n"
        "  failure_modes: schema_validation_failed\n"
        "  summary: The system failed to produce a trustworthy Output Assay run artifact during local draft validation.\n"
        "  errors:\n"
        "    - (root): 'observed_units' is a required property\n"
        "\n"
        "Decision:\n"
        "  quarantine (no trustworthy run artifact produced)"
    )

    assert report == expected


def test_output_assay_cli_renders_report(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "draft.json"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(json.dumps(_valid_payload(), indent=2), encoding="utf-8")

    expected = render_output_assay_report(
        run_output_assay_locally(_artifact_text(), _valid_payload())
    )

    result = runner.invoke(
        assay_app,
        ["output-assay", str(artifact), "--draft", str(draft), "--format", "report"],
    )

    assert result.exit_code == 0
    assert result.output == expected + "\n"


def test_output_assay_cli_renders_extraction_failure_report(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "draft.json"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(
        json.dumps(
            {
                "intent_class": "technical_answer",
                "summary": "Missing observed units",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    expected = render_output_assay_report(
        run_output_assay_locally(
            _artifact_text(),
            {
                "intent_class": "technical_answer",
                "summary": "Missing observed units",
            },
        )
    )

    result = runner.invoke(
        assay_app,
        ["output-assay", str(artifact), "--draft", str(draft), "--format", "report"],
    )

    assert result.exit_code == 0
    assert result.output == expected + "\n"


def test_output_assay_cli_supports_json_output(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "draft.json"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(json.dumps(_valid_payload(), indent=2), encoding="utf-8")

    result = runner.invoke(
        assay_app,
        ["output-assay", str(artifact), "--draft", str(draft), "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["receipt_type"] == "output_assay.run"
    assert payload["guardian_verdict"]["run_status"] == "pass"
    assert payload["compression"]["status"] == "preserve"


def test_output_assay_cli_writes_report_output_file(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "draft.json"
    output = tmp_path / "report.md"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(json.dumps(_valid_payload(), indent=2), encoding="utf-8")

    expected = render_output_assay_report(
        run_output_assay_locally(_artifact_text(), _valid_payload())
    )

    result = runner.invoke(
        assay_app,
        [
            "output-assay",
            str(artifact),
            "--draft",
            str(draft),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.read_text(encoding="utf-8") == expected + "\n"
    assert str(output) in result.output


def test_output_assay_cli_fail_on_block_returns_non_zero(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "blocked.json"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(json.dumps(_blocked_payload(), indent=2), encoding="utf-8")

    result = runner.invoke(
        assay_app,
        [
            "output-assay",
            str(artifact),
            "--draft",
            str(draft),
            "--fail-on",
            "block",
        ],
    )

    assert result.exit_code == 2
    assert "status: block" in result.output


def test_output_assay_cli_fail_on_extraction_failure_returns_non_zero(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "invalid.json"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(
        json.dumps(
            {
                "intent_class": "technical_answer",
                "summary": "Missing observed units",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        assay_app,
        [
            "output-assay",
            str(artifact),
            "--draft",
            str(draft),
            "--fail-on",
            "extraction_failure",
        ],
    )

    assert result.exit_code == 2
    assert "status: extraction_failure" in result.output


def test_output_assay_cli_fail_on_block_does_not_fail_pass_run(tmp_path) -> None:
    artifact = tmp_path / "artifact.md"
    draft = tmp_path / "draft.json"
    artifact.write_text(_artifact_text(), encoding="utf-8")
    draft.write_text(json.dumps(_valid_payload(), indent=2), encoding="utf-8")

    result = runner.invoke(
        assay_app,
        [
            "output-assay",
            str(artifact),
            "--draft",
            str(draft),
            "--fail-on",
            "block",
        ],
    )

    assert result.exit_code == 0
    assert "status: pass" in result.output
