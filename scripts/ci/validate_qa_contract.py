#!/usr/bin/env python3
"""Validate repository workflows against .github/qa_contract.yaml."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml


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


def _is_pinned_uses(uses_value: str) -> bool:
    if uses_value.startswith("./"):
        return True
    if uses_value.startswith("docker://"):
        return True
    return "@" in uses_value


def _validate_workflow(
    workflow_path: Path,
    wf_contract: dict[str, Any],
    policy: dict[str, Any],
    errors: list[str],
) -> set[str]:
    if not workflow_path.exists():
        errors.append(f"missing workflow file: {workflow_path}")
        return set()

    workflow = _load_yaml(workflow_path)
    if workflow.get("name") != wf_contract.get("workflow_name"):
        errors.append(
            f"{workflow_path}: workflow name mismatch (expected '{wf_contract.get('workflow_name')}', got '{workflow.get('name')}')"
        )

    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        errors.append(f"{workflow_path}: missing or invalid jobs map")
        return _collect_uses(workflow)

    for job_contract in wf_contract.get("required_jobs", []):
        job_id = job_contract.get("id")
        if job_id not in jobs:
            errors.append(f"{workflow_path}: missing required job '{job_id}'")
            continue

        job = jobs[job_id]
        steps = job.get("steps", []) if isinstance(job, dict) else []
        step_names = {
            s.get("name")
            for s in steps
            if isinstance(s, dict) and isinstance(s.get("name"), str)
        }

        for req_step in job_contract.get("required_step_names", []):
            if req_step not in step_names:
                errors.append(
                    f"{workflow_path}:{job_id}: missing required step '{req_step}'"
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
            else:
                if set(str(v) for v in actual_values) != set(str(v) for v in matrix_values):
                    errors.append(
                        f"{workflow_path}:{job_id}: matrix '{matrix_key}' mismatch (expected {matrix_values}, got {actual_values})"
                    )

    uses_values = _collect_uses(workflow)
    if policy.get("require_pinned_uses", False):
        for uses_value in sorted(uses_values):
            if not _is_pinned_uses(uses_value):
                errors.append(f"{workflow_path}: unpinned action/reference '{uses_value}'")

    return uses_values


def validate_contract(contract_path: Path, repo_root: Path) -> list[str]:
    errors: list[str] = []

    if not contract_path.exists():
        return [f"contract file not found: {contract_path}"]

    contract = _load_yaml(contract_path)
    invariants = contract.get("invariants", {})
    policy = contract.get("policy", {})

    all_uses: set[str] = set()
    for wf_contract in invariants.get("required_workflows", []):
        rel_path = wf_contract.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            errors.append("contract has required_workflows entry without valid 'path'")
            continue
        workflow_path = repo_root / rel_path
        all_uses |= _validate_workflow(workflow_path, wf_contract, policy, errors)

    for required_uses in invariants.get("required_uses", []):
        if required_uses not in all_uses:
            errors.append(
                f"required action/reference not found in required workflows: '{required_uses}'"
            )

    return errors


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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    contract_path = (repo_root / args.contract).resolve()

    errors = validate_contract(contract_path, repo_root)
    if errors:
        print("QA contract validation: FAIL")
        for err in errors:
            print(f"- {err}")
        return 1

    print("QA contract validation: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
