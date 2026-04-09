"""Tests for the OpenClaw release-slice classifier."""

from __future__ import annotations

from assay._openclaw_release_slice import (
    OPENCLAW_RELEASE_PATTERNS,
    build_openclaw_release_slice_report_from_paths,
    classify_openclaw_release_paths,
    collect_openclaw_release_slice_paths,
    is_openclaw_release_path,
    normalize_repo_path,
)


def test_normalize_repo_path_stabilizes_git_output() -> None:
    assert (
        normalize_repo_path("./src/assay/openclaw_demo.py")
        == "src/assay/openclaw_demo.py"
    )
    assert (
        normalize_repo_path("src\\assay\\openclaw_demo.py")
        == "src/assay/openclaw_demo.py"
    )


def test_openclaw_release_allowlist_matches_expected_paths() -> None:
    assert is_openclaw_release_path("src/assay/openclaw_demo.py") is True
    assert is_openclaw_release_path("tests/assay/test_openclaw_bridge.py") is True
    assert is_openclaw_release_path("docs/openclaw-v1-claim-sheet.md") is True
    assert (
        is_openclaw_release_path("docs/specs/OPENCLAW_BRIDGE_GAP_ANALYSIS_V1.md")
        is True
    )
    assert (
        is_openclaw_release_path("docs/security/RELEASE_SECURITY_CHECKLIST.md") is True
    )
    assert (
        is_openclaw_release_path("scripts/check_openclaw_release_branch_gate.py")
        is True
    )
    assert is_openclaw_release_path("scripts/check_openclaw_metadata_floor.py") is True
    assert is_openclaw_release_path("scripts/export_openclaw_release_slice.py") is True
    assert is_openclaw_release_path("src/assay/explain.py") is False
    assert (
        is_openclaw_release_path(
            "docs/specs/PROOF_PACK_SCOPE_AND_RECEIPT_MAPPING_V1.md"
        )
        is False
    )
    assert is_openclaw_release_path("pyproject.toml") is False


def test_classify_openclaw_release_paths_splits_scope_cleanly() -> None:
    in_scope, out_of_scope = classify_openclaw_release_paths(
        [
            "README.md",
            "src/assay/commands.py",
            "src/assay/explain.py",
            "assay_openclaw_demo/DEMO_SUMMARY.json",
        ],
        allowed_patterns=OPENCLAW_RELEASE_PATTERNS,
    )

    assert in_scope == ["README.md", "src/assay/commands.py"]
    assert out_of_scope == [
        "assay_openclaw_demo/DEMO_SUMMARY.json",
        "src/assay/explain.py",
    ]


def test_release_slice_report_marks_mixed_tree_as_hold() -> None:
    report = build_openclaw_release_slice_report_from_paths(
        repository="/tmp/assay",
        staged_paths=["src/assay/openclaw_bridge.py"],
        unstaged_paths=["docs/openclaw-support.md", "src/assay/proof_pack.py"],
        untracked_paths=["scripts/check_openclaw_release_slice.py"],
    )

    assert report.has_changes is True
    assert report.is_isolated is False
    assert report.staged_in_scope == ["src/assay/openclaw_bridge.py"]
    assert report.unstaged_in_scope == ["docs/openclaw-support.md"]
    assert report.unstaged_out_of_scope == ["src/assay/proof_pack.py"]
    assert report.untracked_in_scope == ["scripts/check_openclaw_release_slice.py"]


def test_release_slice_report_passes_when_only_openclaw_paths_change() -> None:
    report = build_openclaw_release_slice_report_from_paths(
        repository="/tmp/assay",
        staged_paths=["src/assay/openclaw_demo.py"],
        unstaged_paths=["README.md", "docs/openclaw-v1-claim-sheet.md"],
        untracked_paths=["tests/assay/test_openclaw_release_slice.py"],
    )

    assert report.has_changes is True
    assert report.is_isolated is True
    assert report.staged_out_of_scope == []
    assert report.unstaged_out_of_scope == []
    assert report.untracked_out_of_scope == []


def test_release_slice_report_blocks_version_bump_surface() -> None:
    report = build_openclaw_release_slice_report_from_paths(
        repository="/tmp/assay",
        staged_paths=["pyproject.toml"],
    )

    assert report.is_isolated is False
    assert report.staged_out_of_scope == ["pyproject.toml"]


def test_collect_release_slice_paths_dedups_all_in_scope_buckets() -> None:
    report = build_openclaw_release_slice_report_from_paths(
        repository="/tmp/assay",
        staged_paths=["src/assay/openclaw_demo.py"],
        unstaged_paths=["README.md", "docs/openclaw-v1-claim-sheet.md"],
        untracked_paths=[
            "scripts/check_openclaw_release_branch_gate.py",
            "scripts/check_openclaw_metadata_floor.py",
            "scripts/check_openclaw_release_slice.py",
            "scripts/export_openclaw_release_slice.py",
        ],
    )

    assert collect_openclaw_release_slice_paths(report) == [
        "README.md",
        "docs/openclaw-v1-claim-sheet.md",
        "scripts/check_openclaw_metadata_floor.py",
        "scripts/check_openclaw_release_branch_gate.py",
        "scripts/check_openclaw_release_slice.py",
        "scripts/export_openclaw_release_slice.py",
        "src/assay/openclaw_demo.py",
    ]
