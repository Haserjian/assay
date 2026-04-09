"""Helpers for checking whether the working tree is isolated to the OpenClaw slice."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

OPENCLAW_RELEASE_PATTERNS: tuple[str, ...] = (
    ".gitignore",
    "README.md",
    "docs/START_HERE.md",
    "docs/openclaw-v1-claim-sheet.md",
    "docs/openclaw-support.md",
    "docs/security/RELEASE_SECURITY_CHECKLIST.md",
    "docs/specs/OPENCLAW_*",
    "scripts/check_openclaw_release_branch_gate.py",
    "scripts/check_openclaw_metadata_floor.py",
    "scripts/check_openclaw_release_slice.py",
    "scripts/export_openclaw_release_slice.py",
    "scripts/smoke_openclaw_package.sh",
    "src/assay/_openclaw_release_slice.py",
    "src/assay/bridge.py",
    "src/assay/commands.py",
    "src/assay/openclaw_*",
    "tests/assay/test_bridge.py",
    "tests/assay/test_openclaw_*",
)


@dataclass(frozen=True)
class OpenClawReleaseSliceReport:
    """Classification of repository changes against the OpenClaw release slice."""

    repository: str
    allowed_patterns: list[str]
    staged_in_scope: list[str]
    staged_out_of_scope: list[str]
    unstaged_in_scope: list[str]
    unstaged_out_of_scope: list[str]
    untracked_in_scope: list[str]
    untracked_out_of_scope: list[str]

    @property
    def has_changes(self) -> bool:
        return any(
            (
                self.staged_in_scope,
                self.staged_out_of_scope,
                self.unstaged_in_scope,
                self.unstaged_out_of_scope,
                self.untracked_in_scope,
                self.untracked_out_of_scope,
            )
        )

    @property
    def is_isolated(self) -> bool:
        return not any(
            (
                self.staged_out_of_scope,
                self.unstaged_out_of_scope,
                self.untracked_out_of_scope,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "allowed_patterns": self.allowed_patterns,
            "has_changes": self.has_changes,
            "is_isolated": self.is_isolated,
            "staged": {
                "in_scope": self.staged_in_scope,
                "out_of_scope": self.staged_out_of_scope,
            },
            "unstaged": {
                "in_scope": self.unstaged_in_scope,
                "out_of_scope": self.unstaged_out_of_scope,
            },
            "untracked": {
                "in_scope": self.untracked_in_scope,
                "out_of_scope": self.untracked_out_of_scope,
            },
        }


def normalize_repo_path(path: str) -> str:
    """Normalize git-reported paths to a stable relative POSIX form."""

    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")


def is_openclaw_release_path(
    path: str,
    *,
    allowed_patterns: Sequence[str] = OPENCLAW_RELEASE_PATTERNS,
) -> bool:
    """Return whether a path is part of the intended OpenClaw review slice."""

    candidate = normalize_repo_path(path)
    pure_path = PurePosixPath(candidate)
    return any(pure_path.match(pattern) for pattern in allowed_patterns)


def classify_openclaw_release_paths(
    paths: Iterable[str],
    *,
    allowed_patterns: Sequence[str] = OPENCLAW_RELEASE_PATTERNS,
) -> tuple[list[str], list[str]]:
    """Split paths into in-scope and out-of-scope buckets."""

    in_scope: list[str] = []
    out_of_scope: list[str] = []
    seen: set[str] = set()

    for raw_path in paths:
        path = normalize_repo_path(raw_path)
        if not path or path in seen:
            continue
        seen.add(path)
        if is_openclaw_release_path(path, allowed_patterns=allowed_patterns):
            in_scope.append(path)
        else:
            out_of_scope.append(path)

    return sorted(in_scope), sorted(out_of_scope)


def build_openclaw_release_slice_report_from_paths(
    *,
    repository: str,
    staged_paths: Iterable[str] = (),
    unstaged_paths: Iterable[str] = (),
    untracked_paths: Iterable[str] = (),
    allowed_patterns: Sequence[str] = OPENCLAW_RELEASE_PATTERNS,
) -> OpenClawReleaseSliceReport:
    """Build a release-slice report from explicit path lists."""

    staged_in_scope, staged_out_of_scope = classify_openclaw_release_paths(
        staged_paths,
        allowed_patterns=allowed_patterns,
    )
    unstaged_in_scope, unstaged_out_of_scope = classify_openclaw_release_paths(
        unstaged_paths,
        allowed_patterns=allowed_patterns,
    )
    untracked_in_scope, untracked_out_of_scope = classify_openclaw_release_paths(
        untracked_paths,
        allowed_patterns=allowed_patterns,
    )

    return OpenClawReleaseSliceReport(
        repository=repository,
        allowed_patterns=list(allowed_patterns),
        staged_in_scope=staged_in_scope,
        staged_out_of_scope=staged_out_of_scope,
        unstaged_in_scope=unstaged_in_scope,
        unstaged_out_of_scope=unstaged_out_of_scope,
        untracked_in_scope=untracked_in_scope,
        untracked_out_of_scope=untracked_out_of_scope,
    )


def build_openclaw_release_slice_report(repo_root: Path) -> OpenClawReleaseSliceReport:
    """Inspect git state and classify current changes against the slice allowlist."""

    repo_root = repo_root.resolve()
    return build_openclaw_release_slice_report_from_paths(
        repository=str(repo_root),
        staged_paths=_git_name_list(repo_root, "diff", "--name-only", "--cached"),
        unstaged_paths=_git_name_list(repo_root, "diff", "--name-only"),
        untracked_paths=_git_name_list(
            repo_root,
            "ls-files",
            "--others",
            "--exclude-standard",
        ),
    )


def collect_openclaw_release_slice_paths(
    report: OpenClawReleaseSliceReport,
) -> list[str]:
    """Return the deduplicated in-scope paths represented by a slice report."""

    buckets = (
        report.staged_in_scope,
        report.unstaged_in_scope,
        report.untracked_in_scope,
    )
    merged: list[str] = []
    seen: set[str] = set()
    for bucket in buckets:
        for path in bucket:
            normalized = normalize_repo_path(path)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            merged.append(normalized)
    return sorted(merged)


def _git_name_list(repo_root: Path, *args: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        normalize_repo_path(line) for line in result.stdout.splitlines() if line.strip()
    ]
