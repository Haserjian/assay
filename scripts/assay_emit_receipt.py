#!/usr/bin/env python3
"""Emit a portable Assay pytest receipt for CI signing.

This script is intentionally local-only: it reads environment variables,
git metadata, pytest output files, and artifact bytes. It performs no
network calls and does not decide whether pytest passed the gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

DEFAULT_PYTEST_COMMAND = (
    "PYTHONHASHSEED=0 pytest -q --maxfail=1 --tb=short --junitxml=results.xml"
)
DEFAULT_PROOF_TIER = "tier3_ci_pytest_sigstore_bundle_v1"
PYTEST_NODEID_RE = re.compile(
    r"([A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_./\[\]-]+)+)"
)


def _run_git(args: Sequence[str], cwd: Path) -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = completed.stdout.strip()
    return value or None


def _repo_slug_from_remote(remote_url: Optional[str]) -> Optional[str]:
    if not remote_url:
        return None
    value = remote_url.strip()
    if value.endswith(".git"):
        value = value[:-4]
    if value.startswith("git@") and ":" in value:
        value = value.split(":", 1)[1]
    elif "://" in value:
        value = value.rstrip("/").rsplit("/", 2)
        if len(value) >= 2:
            return "/".join(value[-2:])
        return None
    if "/" in value:
        parts = value.strip("/").split("/")
        if len(parts) >= 2:
            return "/".join(parts[-2:])
    return None


def _current_ref(cwd: Path, env: Mapping[str, str]) -> str:
    github_ref = env.get("GITHUB_REF")
    if github_ref:
        return github_ref
    branch = _run_git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd)
    if branch:
        return f"refs/heads/{branch}"
    return _run_git(["rev-parse", "--short", "HEAD"], cwd) or "unknown"


def _created_at(env: Mapping[str, str]) -> str:
    override = env.get("ASSAY_RECEIPT_CREATED_AT")
    if override:
        return override
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe_artifact(path_text: str, cwd: Path) -> dict[str, Any]:
    path = Path(path_text)
    file_path = path if path.is_absolute() else cwd / path
    display_path = str(path)
    if file_path.exists() and file_path.is_file():
        return {
            "exists": True,
            "path": display_path,
            "sha256": _sha256_file(file_path),
            "size_bytes": file_path.stat().st_size,
        }
    return {
        "blocked_reason": "missing",
        "exists": False,
        "path": display_path,
        "sha256": None,
        "size_bytes": None,
    }


def parse_failing_tests(log_path: str, cwd: Path) -> list[str]:
    path = Path(log_path)
    file_path = path if path.is_absolute() else cwd / path
    if not file_path.exists() or not file_path.is_file():
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return sorted(set(PYTEST_NODEID_RE.findall(text)))


def _first_named_artifact(artifacts: Sequence[str], suffix: str, fallback: str) -> str:
    for artifact in artifacts:
        if Path(artifact).name == fallback:
            return artifact
    for artifact in artifacts:
        if Path(artifact).suffix == suffix:
            return artifact
    return fallback


def build_receipt(
    *,
    pytest_exit_code: int,
    artifacts: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
) -> dict[str, Any]:
    repo = env.get("GITHUB_REPOSITORY") or _repo_slug_from_remote(
        _run_git(["remote", "get-url", "origin"], cwd)
    )
    commit_sha = env.get("GITHUB_SHA") or _run_git(["rev-parse", "HEAD"], cwd)
    tree_sha = _run_git(["rev-parse", "HEAD^{tree}"], cwd)
    junit_path = _first_named_artifact(artifacts, ".xml", "results.xml")
    log_path = _first_named_artifact(artifacts, ".log", "pytest.log")

    return {
        "artifacts": [describe_artifact(artifact, cwd) for artifact in artifacts],
        "created_at": _created_at(env),
        "proof_tier": env.get("ASSAY_PROOF_TIER", DEFAULT_PROOF_TIER),
        "run": {
            "event_name": env.get("GITHUB_EVENT_NAME", "unknown"),
            "run_attempt": env.get("GITHUB_RUN_ATTEMPT", "unknown"),
            "run_id": env.get("GITHUB_RUN_ID", "unknown"),
            "run_number": env.get("GITHUB_RUN_NUMBER", "unknown"),
        },
        "runner": {
            "arch": env.get("RUNNER_ARCH", "unknown"),
            "environment": env.get("ASSAY_RUNNER_ENVIRONMENT")
            or env.get("RUNNER_ENVIRONMENT", "unknown"),
            "os": env.get("RUNNER_OS", "unknown"),
        },
        "schema": "assay.receipt.v1",
        "subject": {
            "commit_sha": commit_sha or "unknown",
            "ref": _current_ref(cwd, env),
            "repo": repo or "unknown",
            "tree_sha": tree_sha or "unknown",
        },
        "test": {
            "command": env.get("ASSAY_PYTEST_COMMAND", DEFAULT_PYTEST_COMMAND),
            "exit_code": int(pytest_exit_code),
            "failing_tests": parse_failing_tests(log_path, cwd),
            "framework": "pytest",
            "junit": junit_path,
            "log": log_path,
        },
        "workflow": {
            "provider": (
                "github_actions" if env.get("GITHUB_ACTIONS") == "true" else "local"
            ),
            "workflow_ref": env.get("GITHUB_WORKFLOW_REF", "unknown"),
            "workflow_sha": env.get("GITHUB_WORKFLOW_SHA", "unknown"),
        },
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit an Assay pytest receipt for later Sigstore signing.",
    )
    parser.add_argument(
        "--pytest-exit-code",
        required=True,
        type=int,
        help="Original pytest process exit code",
    )
    parser.add_argument("--out", required=True, help="Path to write receipt JSON")
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Artifact path to hash. Repeat for multiple artifacts.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    cwd = Path.cwd()
    receipt = build_receipt(
        pytest_exit_code=args.pytest_exit_code,
        artifacts=args.artifact,
        cwd=cwd,
        env=os.environ,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
