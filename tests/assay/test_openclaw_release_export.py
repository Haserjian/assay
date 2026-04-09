"""Tests for the OpenClaw release-slice exporter script."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_export_module():
    script_path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "export_openclaw_release_slice.py"
    )
    spec = importlib.util.spec_from_file_location(
        "test_openclaw_release_export",
        script_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_worktree_add_args_detached_mode() -> None:
    module = _load_export_module()

    args = module._build_worktree_add_args(
        Path("/tmp/openclaw-slice"),
        branch_name=None,
    )

    assert args == [
        "worktree",
        "add",
        "--detach",
        "/tmp/openclaw-slice",
        "HEAD",
    ]


def test_build_worktree_add_args_branch_mode() -> None:
    module = _load_export_module()

    args = module._build_worktree_add_args(
        Path("/tmp/openclaw-slice"),
        branch_name="openclaw/release-slice",
    )

    assert args == [
        "worktree",
        "add",
        "-b",
        "openclaw/release-slice",
        "/tmp/openclaw-slice",
        "HEAD",
    ]
