#!/usr/bin/env python3
"""Create an isolated OpenClaw release-slice worktree from the current checkout."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "assay" / "_openclaw_release_slice.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create an isolated worktree at HEAD and overlay only the in-scope "
            "OpenClaw release-slice paths from the current checkout."
        )
    )
    parser.add_argument(
        "--branch",
        help=(
            "Optional branch name for the exported review slice. "
            "If omitted, the worktree stays detached at HEAD."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for the isolated review slice.",
    )
    parser.add_argument(
        "--run-smoke",
        action="store_true",
        help="Run scripts/smoke_openclaw_package.sh in the exported slice.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable result summary.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    module = _load_slice_module()
    build_report = module.build_openclaw_release_slice_report
    collect_paths = module.collect_openclaw_release_slice_paths

    report = build_report(REPO_ROOT)
    in_scope_paths = collect_paths(report)
    head_commit = _run_git("rev-parse", "HEAD").stdout.strip()
    if not in_scope_paths:
        print(
            "No in-scope OpenClaw paths were found in the current checkout.",
            file=sys.stderr,
        )
        return 1

    output_dir = Path(args.output).expanduser().resolve()
    if output_dir.exists():
        if any(output_dir.iterdir()):
            print(f"Output directory is not empty: {output_dir}", file=sys.stderr)
            return 1
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    _run_git(*_build_worktree_add_args(output_dir, branch_name=args.branch))
    try:
        for rel_path in in_scope_paths:
            _overlay_path(REPO_ROOT / rel_path, output_dir / rel_path)

        export_report = build_report(output_dir)
        smoke_ran = False
        smoke_passed = False
        if export_report.is_isolated and args.run_smoke:
            smoke_ran = True
            run_kwargs: dict[str, object] = {
                "args": ["bash", str(output_dir / "scripts" / "smoke_openclaw_package.sh")],
                "check": True,
                "cwd": output_dir,
            }
            if args.json:
                run_kwargs["stdout"] = sys.stderr
                run_kwargs["stderr"] = sys.stderr
            subprocess.run(**run_kwargs)
            smoke_passed = True

        if args.json:
            print(
                json.dumps(
                    {
                        "source_repository": str(REPO_ROOT),
                        "source_head": head_commit,
                        "output_directory": str(output_dir),
                        "branch_name": args.branch,
                        "worktree_mode": "branch" if args.branch else "detached",
                        "copied_paths": in_scope_paths,
                        "source_report": report.to_dict(),
                        "export_report": export_report.to_dict(),
                        "smoke_ran": smoke_ran,
                        "smoke_passed": smoke_passed,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print("=== OpenClaw Release Slice Export ===")
            print(f"Source repo: {REPO_ROOT}")
            print(f"Source HEAD: {head_commit}")
            print(f"Output dir:  {output_dir}")
            print(f"Branch:      {args.branch if args.branch else '(detached HEAD)'}")
            print(f"Copied paths: {len(in_scope_paths)}")
            print(f"Slice isolated: {'yes' if export_report.is_isolated else 'no'}")
            print(f"Package smoke: {'PASS' if smoke_passed else 'not run'}")
            if not export_report.is_isolated:
                print(
                    "Exported slice is still not isolated; inspect the export report."
                )
        return 0 if export_report.is_isolated else 1
    except Exception:
        _run_git("worktree", "remove", "--force", str(output_dir), check=False)
        raise


def _load_slice_module():
    spec = importlib.util.spec_from_file_location(
        "_openclaw_release_slice_export",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load OpenClaw slice module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _build_worktree_add_args(output_dir: Path, *, branch_name: str | None) -> list[str]:
    if branch_name:
        return ["worktree", "add", "-b", branch_name, str(output_dir), "HEAD"]
    return ["worktree", "add", "--detach", str(output_dir), "HEAD"]


def _run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _overlay_path(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.exists():
        if source.is_dir():
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)
        return

    if destination.is_dir():
        shutil.rmtree(destination)
    elif destination.exists():
        destination.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
