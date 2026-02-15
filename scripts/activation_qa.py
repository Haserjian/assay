#!/usr/bin/env python3
"""Activation QA harness for Stage 1 user flows.

Validates the core activation surface end-to-end in a temp workspace:
  - status JSON contract
  - start CI/MCP guided flows JSON contracts
  - MCP policy template generation
  - CI workflow template generation
  - high-friction remediation JSON contracts

Run:
  python scripts/activation_qa.py
  python scripts/activation_qa.py --workdir /tmp/assay-qa
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _assay_env() -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(_repo_root() / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = src_path if not existing else f"{src_path}{os.pathsep}{existing}"
    return env


def _run_assay(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "assay.cli", *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=_assay_env(),
        text=True,
        capture_output=True,
        check=False,
    )


def _json_from_stdout(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    out = proc.stdout.strip()
    if not out:
        raise ValueError("expected JSON output but stdout was empty")
    return json.loads(out)


def run_activation_qa(workdir: Path) -> list[CheckResult]:
    results: list[CheckResult] = []

    # Create a tiny project command used in generated CI workflow checks.
    (workdir / "app.py").write_text("print('assay activation qa')\n", encoding="utf-8")

    # 1) status --json
    proc = _run_assay(["status", "--json"], workdir)
    try:
        data = _json_from_stdout(proc)
        required = {"command", "version", "key", "store", "lockfile", "latest_pack", "mcp_proxy"}
        ok = proc.returncode == 0 and data.get("command") == "status" and required.issubset(set(data.keys()))
        detail = f"exit={proc.returncode}, keys_ok={required.issubset(set(data.keys()))}"
    except Exception as e:
        ok = False
        detail = f"status parse failed: {e}"
    results.append(CheckResult("status_json_contract", ok, detail))

    # 2) start ci --json
    proc = _run_assay(["start", "ci", "--json"], workdir)
    try:
        data = _json_from_stdout(proc)
        steps = data.get("steps", [])
        ok = proc.returncode == 0 and data.get("command") == "start ci" and len(steps) == 5
        detail = f"exit={proc.returncode}, steps={len(steps)}"
    except Exception as e:
        ok = False
        detail = f"start ci parse failed: {e}"
    results.append(CheckResult("start_ci_contract", ok, detail))

    # 3) start mcp --json
    proc = _run_assay(["start", "mcp", "--json"], workdir)
    try:
        data = _json_from_stdout(proc)
        steps = data.get("steps", [])
        ok = proc.returncode == 0 and data.get("command") == "start mcp" and len(steps) == 4
        detail = f"exit={proc.returncode}, steps={len(steps)}"
    except Exception as e:
        ok = False
        detail = f"start mcp parse failed: {e}"
    results.append(CheckResult("start_mcp_contract", ok, detail))

    # 4) mcp policy init --json
    proc = _run_assay(["mcp", "policy", "init", "--server-id", "qa-server", "--json"], workdir)
    policy_file = workdir / "assay.mcp-policy.yaml"
    try:
        data = _json_from_stdout(proc)
        ok = (
            proc.returncode == 0
            and data.get("command") == "mcp policy init"
            and data.get("status") == "ok"
            and policy_file.exists()
        )
        detail = f"exit={proc.returncode}, file_exists={policy_file.exists()}"
    except Exception as e:
        ok = False
        detail = f"mcp policy init parse failed: {e}"
    results.append(CheckResult("mcp_policy_template", ok, detail))

    # 5) ci init github --json
    proc = _run_assay(["ci", "init", "github", "--run-command", "python app.py", "--json"], workdir)
    workflow = workdir / ".github" / "workflows" / "assay-verify.yml"
    try:
        data = _json_from_stdout(proc)
        wf_text = workflow.read_text(encoding="utf-8") if workflow.exists() else ""
        ok = (
            proc.returncode == 0
            and data.get("command") == "ci init"
            and data.get("status") == "ok"
            and workflow.exists()
            and "Regression Gate" in wf_text
            and "--report" in wf_text
        )
        detail = f"exit={proc.returncode}, workflow_exists={workflow.exists()}"
    except Exception as e:
        ok = False
        detail = f"ci init parse failed: {e}"
    results.append(CheckResult("ci_template_generation", ok, detail))

    # 6) run --json (expected remediation error)
    proc = _run_assay(["run", "--json"], workdir)
    try:
        data = _json_from_stdout(proc)
        ok = proc.returncode == 1 and data.get("error") == "no_command_provided"
        detail = f"exit={proc.returncode}, error={data.get('error')}"
    except Exception as e:
        ok = False
        detail = f"run remediation parse failed: {e}"
    results.append(CheckResult("run_no_command_remediation", ok, detail))

    # 7) mcp-proxy --json (expected remediation error)
    proc = _run_assay(["mcp-proxy", "--json"], workdir)
    try:
        data = _json_from_stdout(proc)
        ok = proc.returncode == 3 and data.get("error") == "no_server_command_provided"
        detail = f"exit={proc.returncode}, error={data.get('error')}"
    except Exception as e:
        ok = False
        detail = f"mcp-proxy remediation parse failed: {e}"
    results.append(CheckResult("mcp_proxy_no_command_remediation", ok, detail))

    return results


def _print_results(results: list[CheckResult], workdir: Path) -> None:
    passed = sum(1 for r in results if r.passed)
    total = len(results)

    print("=== Assay Activation QA Harness ===")
    print(f"Work dir: {workdir}")
    print("")
    for r in results:
        tag = "PASS" if r.passed else "FAIL"
        print(f"[{tag}] {r.name}: {r.detail}")
    print("")
    print(f"Result: {passed}/{total} checks passed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Assay Stage 1 activation QA checks.")
    parser.add_argument("--workdir", default=None, help="Workspace directory (default: temp dir)")
    parser.add_argument("--keep-workdir", action="store_true", help="Keep temp workspace after run")
    args = parser.parse_args()

    temp_created = False
    if args.workdir:
        workdir = Path(args.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="assay-activation-"))
        temp_created = True

    try:
        results = run_activation_qa(workdir)
        _print_results(results, workdir)
        return 0 if all(r.passed for r in results) else 1
    finally:
        if temp_created and not args.keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
