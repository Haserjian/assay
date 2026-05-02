from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "assay_emit_receipt.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("assay_emit_receipt", SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_describes_existing_and_missing_artifacts(tmp_path):
    module = _load_module()
    artifact = tmp_path / "results.xml"
    artifact.write_text("<testsuite />\n", encoding="utf-8")

    receipt = module.build_receipt(
        pytest_exit_code=0,
        artifacts=["results.xml", "missing.log"],
        cwd=tmp_path,
        env={"ASSAY_RECEIPT_CREATED_AT": "2026-05-02T00:00:00Z"},
    )

    assert receipt["artifacts"][0]["exists"] is True
    assert receipt["artifacts"][0]["size_bytes"] == len("<testsuite />\n")
    assert len(receipt["artifacts"][0]["sha256"]) == 64
    assert receipt["artifacts"][1] == {
        "blocked_reason": "missing",
        "exists": False,
        "path": "missing.log",
        "sha256": None,
        "size_bytes": None,
    }


def test_maps_github_actions_environment(tmp_path):
    module = _load_module()
    env = {
        "ASSAY_RECEIPT_CREATED_AT": "2026-05-02T00:00:00Z",
        "ASSAY_RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "Haserjian/assay",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_NUMBER": "42",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": (
            "Haserjian/assay/.github/workflows/assay-receipt.yml"
            "@refs/heads/main"
        ),
        "GITHUB_WORKFLOW_SHA": "b" * 40,
        "RUNNER_ARCH": "X64",
        "RUNNER_OS": "Linux",
    }

    receipt = module.build_receipt(
        pytest_exit_code=1,
        artifacts=[],
        cwd=tmp_path,
        env=env,
    )

    assert receipt["workflow"] == {
        "provider": "github_actions",
        "workflow_ref": (
            "Haserjian/assay/.github/workflows/assay-receipt.yml"
            "@refs/heads/main"
        ),
        "workflow_sha": "b" * 40,
    }
    assert receipt["subject"]["repo"] == "Haserjian/assay"
    assert receipt["subject"]["commit_sha"] == "a" * 40
    assert receipt["subject"]["ref"] == "refs/heads/main"
    assert receipt["run"]["run_id"] == "123456789"
    assert receipt["run"]["run_attempt"] == "2"
    assert receipt["run"]["run_number"] == "42"
    assert receipt["runner"] == {
        "arch": "X64",
        "environment": "github-hosted",
        "os": "Linux",
    }
    assert receipt["test"]["exit_code"] == 1


def test_parses_failing_tests_from_pytest_log(tmp_path):
    module = _load_module()
    (tmp_path / "pytest.log").write_text(
        "\n".join(
            [
                "FAILED tests/test_math.py::TestAdd::test_negative - AssertionError",
                "tests/test_other.py::test_case[one] failed later",
                "FAILED tests/test_math.py::TestAdd::test_negative - duplicate",
            ]
        ),
        encoding="utf-8",
    )

    receipt = module.build_receipt(
        pytest_exit_code=1,
        artifacts=["pytest.log"],
        cwd=tmp_path,
        env={"ASSAY_RECEIPT_CREATED_AT": "2026-05-02T00:00:00Z"},
    )

    assert receipt["test"]["failing_tests"] == [
        "tests/test_math.py::TestAdd::test_negative",
        "tests/test_other.py::test_case[one]",
    ]


def test_cli_writes_sorted_json_and_preserves_nonzero_exit_code(tmp_path):
    (tmp_path / "results.xml").write_text(
        "<testsuite failures='1' />\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.log").write_text(
        "FAILED tests/test_cli.py::test_failure - AssertionError\n",
        encoding="utf-8",
    )
    out = tmp_path / "receipt.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--pytest-exit-code",
            "7",
            "--out",
            str(out),
            "--artifact",
            "results.xml",
            "--artifact",
            "pytest.log",
        ],
        cwd=tmp_path,
        env={"ASSAY_RECEIPT_CREATED_AT": "2026-05-02T00:00:00Z"},
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert completed.returncode == 0
    payload = out.read_text(encoding="utf-8")
    assert payload.startswith('{\n  "artifacts"')
    receipt = json.loads(payload)
    assert receipt["schema"] == "assay.receipt.v1"
    assert receipt["test"]["exit_code"] == 7
    assert receipt["test"]["failing_tests"] == ["tests/test_cli.py::test_failure"]
