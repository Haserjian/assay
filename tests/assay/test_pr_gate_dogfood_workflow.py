"""Tests for the PR Gate dogfood workflow contract."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "assay-pr-gate.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_pr_gate_dogfood_workflow_yaml_parses() -> None:
    payload = yaml.safe_load(_workflow_text())

    assert payload["name"] == "Assay PR Gate"
    assert "assay-pr-gate" in payload["jobs"]


def test_pr_gate_dogfood_workflow_uses_same_repo_guard() -> None:
    text = _workflow_text()

    assert "pull_request_target:" in text
    assert "github.event.pull_request.head.repo.full_name == github.repository" in text


def test_pr_gate_dogfood_workflow_does_not_checkout_pr_head() -> None:
    text = _workflow_text()

    assert "ref: ${{ github.event.pull_request.base.ref }}" in text
    assert "github.event.pull_request.head.ref" not in text
    assert "refs/pull/${PR_NUMBER}/head" in text


def test_pr_gate_dogfood_workflow_runs_full_command_sequence() -> None:
    text = _workflow_text()

    for command in (
        "assay pr-gate capture",
        "assay pr-gate evaluate",
        "assay pr-gate pack",
        "cosign sign-blob",
        "assay pr-gate verify",
        "assay pr-gate render-comment",
        "assay pr-gate upsert-comment",
        "actions/upload-artifact@v4",
    ):
        assert command in text


def test_pr_gate_dogfood_workflow_uses_stable_expected_identity() -> None:
    text = _workflow_text()

    assert (
        "https://github.com/Haserjian/assay/.github/workflows/"
        "assay-pr-gate.yml@refs/heads/main"
    ) in text
