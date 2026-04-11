"""Tests for the OpenClaw release-branch gate script."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_gate_module():
    script_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "check_openclaw_release_branch_gate.py"
    )
    spec = importlib.util.spec_from_file_location(
        "test_openclaw_release_branch_gate",
        script_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_is_branch_backed_distinguishes_detached_head() -> None:
    module = _load_gate_module()

    assert module.is_branch_backed("HEAD") is False
    assert module.is_branch_backed("openclaw/release-slice") is True


def test_has_pyproject_changes_detects_any_prebump_touch() -> None:
    module = _load_gate_module()

    assert module.has_pyproject_changes(["./pyproject.toml"], []) is True
    assert module.has_pyproject_changes([], ["pyproject.toml"]) is True
    assert (
        module.has_pyproject_changes(["README.md"], ["docs/openclaw-support.md"])
        is False
    )


def test_release_branch_gate_result_requires_all_green_conditions() -> None:
    module = _load_gate_module()

    result = module.OpenClawReleaseBranchGateResult(
        repository="/tmp/assay",
        branch_name="openclaw/release-slice",
        branch_backed=True,
        staged_pyproject_paths=[],
        unstaged_pyproject_paths=[],
        slice_report={"is_isolated": True},
        slice_isolated=True,
        smoke_ran=True,
        smoke_passed=True,
        smoke_exit_code=0,
    )
    assert result.passed is True

    touched = module.OpenClawReleaseBranchGateResult(
        repository="/tmp/assay",
        branch_name="openclaw/release-slice",
        branch_backed=True,
        staged_pyproject_paths=["pyproject.toml"],
        unstaged_pyproject_paths=[],
        slice_report={"is_isolated": True},
        slice_isolated=True,
        smoke_ran=False,
        smoke_passed=False,
        smoke_exit_code=None,
    )
    assert touched.passed is False
