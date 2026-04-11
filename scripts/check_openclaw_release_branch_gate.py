#!/usr/bin/env python3
"""Run the OpenClaw pre-version-bump gate inside an exported review branch."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
SLICE_MODULE_PATH = REPO_ROOT / "src" / "assay" / "_openclaw_release_slice.py"
SMOKE_SCRIPT_PATH = REPO_ROOT / "scripts" / "smoke_openclaw_package.sh"


@dataclass(frozen=True)
class OpenClawReleaseBranchGateResult:
    """Result of the pre-version-bump gate for an exported OpenClaw slice."""

    repository: str
    branch_name: str
    branch_backed: bool
    staged_pyproject_paths: list[str]
    unstaged_pyproject_paths: list[str]
    slice_report: dict[str, object]
    slice_isolated: bool
    smoke_ran: bool
    smoke_passed: bool
    smoke_exit_code: Optional[int]

    @property
    def pyproject_touched(self) -> bool:
        return bool(self.staged_pyproject_paths or self.unstaged_pyproject_paths)

    @property
    def passed(self) -> bool:
        return (
            self.branch_backed
            and not self.pyproject_touched
            and self.slice_isolated
            and self.smoke_passed
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "branch_name": self.branch_name,
            "branch_backed": self.branch_backed,
            "pyproject_touched": self.pyproject_touched,
            "staged_pyproject_paths": self.staged_pyproject_paths,
            "unstaged_pyproject_paths": self.unstaged_pyproject_paths,
            "slice_isolated": self.slice_isolated,
            "slice_report": self.slice_report,
            "smoke_ran": self.smoke_ran,
            "smoke_passed": self.smoke_passed,
            "smoke_exit_code": self.smoke_exit_code,
            "passed": self.passed,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the OpenClaw release-branch gate inside an exported review slice "
            "before any version bump work."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable gate report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_openclaw_release_branch_gate(REPO_ROOT)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.passed else 1

    print("=== OpenClaw Release-Branch Gate ===")
    print(f"Repository: {result.repository}")
    print(f"Branch:     {result.branch_name}")
    print(f"Result:     {'PASS' if result.passed else 'HOLD'}")
    print(f"Branch-backed slice: {'yes' if result.branch_backed else 'no'}")
    print(f"Slice isolated:      {'yes' if result.slice_isolated else 'no'}")
    print(
        f"pyproject.toml untouched: {'yes' if not result.pyproject_touched else 'no'}"
    )
    if result.smoke_ran:
        print(f"Artifact checks:     {'PASS' if result.smoke_passed else 'FAIL'}")
    else:
        print("Artifact checks:     blocked")

    if not result.branch_backed:
        print()
        print(
            "Export a branch-backed review slice first with "
            "python3 scripts/export_openclaw_release_slice.py --output <dir> --branch <review-branch>."
        )
    if result.pyproject_touched:
        print()
        print("pyproject.toml has already changed in this checkout:")
        for path in result.staged_pyproject_paths:
            print(f"  staged:   {path}")
        for path in result.unstaged_pyproject_paths:
            print(f"  unstaged: {path}")
        print("Reset or recreate the exported slice before running the pre-bump gate.")
    if not result.slice_isolated:
        print()
        print(
            "The slice checker still sees out-of-scope drift. Run "
            "python3 scripts/check_openclaw_release_slice.py --json for details."
        )
    if result.smoke_ran and not result.smoke_passed:
        print()
        print(
            "Packaged artifact checks failed. Fix the exported slice until "
            "scripts/smoke_openclaw_package.sh passes; that path now includes "
            "metadata-floor validation via scripts/check_openclaw_metadata_floor.py."
        )

    return 0 if result.passed else 1


def run_openclaw_release_branch_gate(
    repo_root: Path,
) -> OpenClawReleaseBranchGateResult:
    module = _load_slice_module()
    build_report = module.build_openclaw_release_slice_report
    report = build_report(repo_root.resolve())

    branch_name = _git_stdout(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    branch_backed = is_branch_backed(branch_name)
    staged_pyproject_paths = _git_name_list(
        repo_root,
        "diff",
        "--name-only",
        "--cached",
        "--",
        "pyproject.toml",
    )
    unstaged_pyproject_paths = _git_name_list(
        repo_root,
        "diff",
        "--name-only",
        "--",
        "pyproject.toml",
    )

    smoke_ran = False
    smoke_passed = False
    smoke_exit_code: Optional[int] = None

    if (
        branch_backed
        and not has_pyproject_changes(
            staged_pyproject_paths,
            unstaged_pyproject_paths,
        )
        and report.is_isolated
    ):
        smoke_ran = True
        smoke = subprocess.run(
            ["bash", str(SMOKE_SCRIPT_PATH)],
            check=False,
            cwd=repo_root,
        )
        smoke_exit_code = smoke.returncode
        smoke_passed = smoke.returncode == 0

    return OpenClawReleaseBranchGateResult(
        repository=str(repo_root.resolve()),
        branch_name=branch_name,
        branch_backed=branch_backed,
        staged_pyproject_paths=staged_pyproject_paths,
        unstaged_pyproject_paths=unstaged_pyproject_paths,
        slice_report=report.to_dict(),
        slice_isolated=report.is_isolated,
        smoke_ran=smoke_ran,
        smoke_passed=smoke_passed,
        smoke_exit_code=smoke_exit_code,
    )


def is_branch_backed(branch_name: str) -> bool:
    return bool(branch_name and branch_name != "HEAD")


def has_pyproject_changes(
    staged_paths: Iterable[str],
    unstaged_paths: Iterable[str],
) -> bool:
    return any(
        _normalize_repo_path(path) == "pyproject.toml"
        for path in [*staged_paths, *unstaged_paths]
    )


def _load_slice_module():
    spec = importlib.util.spec_from_file_location(
        "_openclaw_release_branch_gate",
        SLICE_MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Could not load OpenClaw slice module from {SLICE_MODULE_PATH}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git_stdout(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git_name_list(repo_root: Path, *args: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        _normalize_repo_path(line)
        for line in result.stdout.splitlines()
        if line.strip()
    ]


def _normalize_repo_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")


if __name__ == "__main__":
    raise SystemExit(main())
