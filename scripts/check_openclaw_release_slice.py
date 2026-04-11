#!/usr/bin/env python3
"""Check whether the current Assay worktree is isolated to the OpenClaw slice."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "assay" / "_openclaw_release_slice.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Classify staged, unstaged, and untracked paths against the "
            "intended OpenClaw release slice."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    build_openclaw_release_slice_report = _load_build_report()

    report = build_openclaw_release_slice_report(REPO_ROOT)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0 if report.is_isolated else 1

    print("=== OpenClaw Release Slice Check ===")
    print(f"Repository: {report.repository}")
    print(
        "Result: isolated"
        if report.is_isolated
        else "Result: HOLD — out-of-scope changes are still present"
    )

    if not report.has_changes:
        print("No staged, unstaged, or untracked changes were found.")
        return 0

    _print_bucket("Staged in scope", report.staged_in_scope)
    _print_bucket("Staged out of scope", report.staged_out_of_scope)
    _print_bucket("Unstaged in scope", report.unstaged_in_scope)
    _print_bucket("Unstaged out of scope", report.unstaged_out_of_scope)
    _print_bucket("Untracked in scope", report.untracked_in_scope)
    _print_bucket("Untracked out of scope", report.untracked_out_of_scope)

    if not report.is_isolated:
        print(
            "Remove or split the out-of-scope paths before treating this checkout "
            "as an OpenClaw release slice."
        )
        print(
            "Do not run package smoke, review the slice, or touch pyproject.toml "
            "for versioning until this check returns isolated."
        )
        print(
            "If you are starting from a mixed tree, export an isolated review slice with "
            "python3 scripts/export_openclaw_release_slice.py --output <dir> --branch <review-branch> --run-smoke."
        )
    return 0 if report.is_isolated else 1


def _load_build_report():
    spec = importlib.util.spec_from_file_location(
        "_openclaw_release_slice",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load OpenClaw slice module from {MODULE_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.build_openclaw_release_slice_report


def _print_bucket(label: str, paths: list[str]) -> None:
    if not paths:
        return
    print()
    print(f"{label}:")
    for path in paths:
        print(f"  - {path}")


if __name__ == "__main__":
    raise SystemExit(main())
