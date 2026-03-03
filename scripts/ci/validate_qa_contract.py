#!/usr/bin/env python3
"""Validate repository workflows against .github/qa_contract.yaml."""
from __future__ import annotations

import argparse
import copy
import re
import sys
from pathlib import Path
from typing import Any

import yaml

_SHA_REF_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _collect_uses(node: Any, out: set[str] | None = None) -> set[str]:
    if out is None:
        out = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                out.add(value)
            else:
                _collect_uses(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_uses(item, out)
    return out


def _is_local_or_docker(uses_value: str) -> bool:
    return uses_value.startswith("./") or uses_value.startswith("docker://")


def _is_pinned_uses(uses_value: str) -> bool:
    if _is_local_or_docker(uses_value):
        return True
    return "@" in uses_value


def _is_sha_pinned(uses_value: str) -> bool:
    if _is_local_or_docker(uses_value):
        return True
    if "@" not in uses_value:
        return False
    _, ref = uses_value.rsplit("@", 1)
    return bool(_SHA_REF_RE.fullmatch(ref.strip()))


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in out
            and isinstance(out[key], dict)
            and isinstance(value, dict)
        ):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _resolve_tier(contract: dict[str, Any], tier: str | None) -> tuple[dict[str, Any], str]:
    tiers = contract.get("tiers")
    if not isinstance(tiers, dict):
        # Backward-compatible v1 contract shape.
        return {
            "invariants": contract.get("invariants", {}),
            "policy": contract.get("policy", {}),
            "checks": contract.get("checks", {}),
        }, tier or contract.get("repo_tier", "default")

    selected = tier or contract.get("active_tier")
    if not isinstance(selected, str) or not selected.strip():
        raise ValueError("contract missing active_tier and no --tier supplied")
    selected = selected.strip()

    def _resolve(name: str, stack: tuple[str, ...] = ()) -> dict[str, Any]:
        if name in stack:
            raise ValueError(f"tier inheritance cycle detected: {' -> '.join(stack + (name,))}")
        node = tiers.get(name)
        if not isinstance(node, dict):
            raise ValueError(f"tier '{name}' not found")

        parent = node.get("extends")
        if parent is not None and not isinstance(parent, str):
            raise ValueError(f"tier '{name}' has non-string extends value")

        resolved: dict[str, Any] = {}
        if isinstance(parent, str) and parent.strip():
            resolved = _resolve(parent.strip(), stack + (name,))

        node_no_extends = {k: v for k, v in node.items() if k != "extends"}
        return _deep_merge(resolved, node_no_extends)

    return _resolve(selected), selected


def _step_matches_requirement(step: dict[str, Any], requirement: Any) -> bool:
    name = step.get("name") if isinstance(step.get("name"), str) else ""
    run = step.get("run") if isinstance(step.get("run"), str) else ""
    uses = step.get("uses") if isinstance(step.get("uses"), str) else ""

    if isinstance(requirement, str):
        return name == requirement

    if not isinstance(requirement, dict):
        return False

    checks: list[bool] = []
    if "name" in requirement:
        checks.append(name == str(requirement["name"]))
    if "name_contains" in requirement:
        checks.append(str(requirement["name_contains"]) in name)
    if "run_contains" in requirement:
        checks.append(str(requirement["run_contains"]) in run)
    if "uses" in requirement:
        checks.append(uses == str(requirement["uses"]))

    return bool(checks) and all(checks)


def _req_to_label(requirement: Any) -> str:
    if isinstance(requirement, str):
        return f"name='{requirement}'"
    if isinstance(requirement, dict):
        parts = [f"{k}={v!r}" for k, v in requirement.items()]
        return "{" + ", ".join(parts) + "}"
    return repr(requirement)


def _validate_workflow(
    workflow_path: Path,
    wf_contract: dict[str, Any],
    policy: dict[str, Any],
    errors: list[str],
) -> tuple[set[str], set[str]]:
    if not workflow_path.exists():
        errors.append(f"missing workflow file: {workflow_path}")
        return set(), set()

    workflow = _load_yaml(workflow_path)
    if workflow.get("name") != wf_contract.get("workflow_name"):
        errors.append(
            f"{workflow_path}: workflow name mismatch (expected '{wf_contract.get('workflow_name')}', got '{workflow.get('name')}')"
        )

    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        errors.append(f"{workflow_path}: missing or invalid jobs map")
        return _collect_uses(workflow), set()

    discovered_checks = set(jobs.keys())

    for job_contract in wf_contract.get("required_jobs", []):
        job_id = job_contract.get("id")
        if job_id not in jobs:
            errors.append(f"{workflow_path}: missing required job '{job_id}'")
            continue

        job = jobs[job_id]
        steps = job.get("steps", []) if isinstance(job, dict) else []
        steps = [s for s in steps if isinstance(s, dict)]

        required_steps: list[Any] = []
        required_steps.extend(job_contract.get("required_steps", []))
        # Backward-compatible legacy key.
        required_steps.extend(job_contract.get("required_step_names", []))

        for req_step in required_steps:
            if not any(_step_matches_requirement(step, req_step) for step in steps):
                errors.append(
                    f"{workflow_path}:{job_id}: missing required step match {_req_to_label(req_step)}"
                )

        matrix_contract = job_contract.get("required_matrix", {})
        matrix_key = matrix_contract.get("key")
        matrix_values = matrix_contract.get("values", [])
        if matrix_key:
            actual_matrix = (
                job.get("strategy", {}).get("matrix", {})
                if isinstance(job, dict)
                else {}
            )
            actual_values = actual_matrix.get(matrix_key)
            if not isinstance(actual_values, list):
                errors.append(
                    f"{workflow_path}:{job_id}: matrix key '{matrix_key}' missing or not a list"
                )
            elif set(str(v) for v in actual_values) != set(str(v) for v in matrix_values):
                errors.append(
                    f"{workflow_path}:{job_id}: matrix '{matrix_key}' mismatch (expected {matrix_values}, got {actual_values})"
                )

    uses_values = _collect_uses(workflow)
    if policy.get("require_pinned_uses", False):
        for uses_value in sorted(uses_values):
            if not _is_pinned_uses(uses_value):
                errors.append(f"{workflow_path}: unpinned action/reference '{uses_value}'")

    if policy.get("require_uses_sha", False):
        for uses_value in sorted(uses_values):
            if not _is_sha_pinned(uses_value):
                errors.append(f"{workflow_path}: non-SHA action/reference '{uses_value}'")

    return uses_values, discovered_checks


def _validate_check_sets(checks_cfg: dict[str, Any], discovered: set[str], errors: list[str]) -> None:
    required = checks_cfg.get("required", []) if isinstance(checks_cfg, dict) else []
    advisory = checks_cfg.get("advisory", []) if isinstance(checks_cfg, dict) else []

    required_set = set(str(x) for x in required)
    advisory_set = set(str(x) for x in advisory)

    overlap = required_set & advisory_set
    if overlap:
        errors.append(f"checks.required and checks.advisory overlap: {sorted(overlap)}")

    for check in sorted(required_set | advisory_set):
        if check not in discovered:
            errors.append(f"contract check '{check}' not found in discovered workflow jobs")


def validate_contract(contract_path: Path, repo_root: Path, tier: str | None = None) -> tuple[list[str], str]:
    errors: list[str] = []

    if not contract_path.exists():
        return [f"contract file not found: {contract_path}"], tier or "unknown"

    contract = _load_yaml(contract_path)
    try:
        resolved, selected_tier = _resolve_tier(contract, tier)
    except ValueError as exc:
        return [f"invalid tier config: {exc}"], tier or "unknown"

    invariants = resolved.get("invariants", {}) if isinstance(resolved, dict) else {}
    policy = resolved.get("policy", {}) if isinstance(resolved, dict) else {}
    checks_cfg = resolved.get("checks", {}) if isinstance(resolved, dict) else {}

    all_uses: set[str] = set()
    discovered_checks: set[str] = set()

    for wf_contract in invariants.get("required_workflows", []):
        rel_path = wf_contract.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            errors.append("contract has required_workflows entry without valid 'path'")
            continue
        workflow_path = repo_root / rel_path
        uses_values, checks = _validate_workflow(workflow_path, wf_contract, policy, errors)
        all_uses |= uses_values
        discovered_checks |= checks

    for required_uses in invariants.get("required_uses", []):
        if required_uses not in all_uses:
            errors.append(
                f"required action/reference not found in required workflows: '{required_uses}'"
            )

    _validate_check_sets(checks_cfg, discovered_checks, errors)
    return errors, selected_tier


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--contract",
        default=".github/qa_contract.yaml",
        help="Path to qa contract yaml (default: .github/qa_contract.yaml)",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root (default: current directory)",
    )
    parser.add_argument(
        "--tier",
        default=None,
        help="Override contract tier selection (default: active_tier)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    contract_path = (repo_root / args.contract).resolve()

    errors, tier = validate_contract(contract_path, repo_root, tier=args.tier)
    if errors:
        print(f"QA contract validation: FAIL (tier={tier})")
        for err in errors:
            print(f"- {err}")
        return 1

    print(f"QA contract validation: PASS (tier={tier})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
