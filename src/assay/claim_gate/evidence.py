"""Conservative evidence discovery for Assay Claim Gate."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Set

from assay.claim_gate.policy import ClaimGatePolicy


def build_evidence_index(
    *,
    repo_root: Path,
    head: str,
    requirements: Iterable[str],
    policy: ClaimGatePolicy,
) -> Dict[str, List[str]]:
    """Find configured evidence paths for each requirement.

    Claim Gate only accepts evidence from paths explicitly configured in the
    policy and present at the inspected head ref.
    """
    repo_root = repo_root.resolve()
    repo_paths = _git_repo_paths(repo_root, head)
    index: Dict[str, List[str]] = {}
    for requirement in sorted(set(requirements)):
        found: List[str] = []
        for pattern in policy.evidence_paths.get(requirement, []):
            found.extend(_resolve_pattern(pattern, repo_paths))
        if found:
            index[requirement] = sorted(dict.fromkeys(found))
    return index


def _resolve_pattern(pattern: str, repo_paths: Set[str]) -> List[str]:
    normalized_pattern = _normalize_relative_path(pattern)
    if _has_glob(pattern):
        return sorted(
            path for path in repo_paths if fnmatch.fnmatchcase(path, normalized_pattern)
        )
    if normalized_pattern in repo_paths:
        return [normalized_pattern]
    return []


def _git_repo_paths(repo_root: Path, ref: str) -> Set[str]:
    output = _run_git(repo_root, ["ls-tree", "-r", "--name-only", ref])
    return {
        _normalize_relative_path(line) for line in output.splitlines() if line.strip()
    }


def _has_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


def _normalize_relative_path(path: str) -> str:
    return Path(path.replace("\\", "/")).as_posix().lstrip("./")


def _run_git(repo_root: Path, args: List[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        raise OSError(f"git {' '.join(args)} failed: {stderr[:400]}")
    return proc.stdout
