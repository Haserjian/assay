"""Executable guided workflows for Assay.

Each flow is a sequence of steps that map to RunCards in ORDER_OF_OPERATIONS.md.
Default mode is dry-run (show plan). Use --apply to execute.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FlowStep:
    """A single step in an Assay flow."""
    number: int
    title: str
    command: str = ""
    note: str = ""
    command_fn: Optional[Callable[[Dict[int, "StepResult"]], str]] = None
    skip_fn: Optional[Callable[[Path, Dict[int, "StepResult"]], Tuple[bool, str]]] = None
    print_only: bool = False
    expected_exit_codes: List[int] = field(default_factory=lambda: [0])


@dataclass
class StepResult:
    """Result of executing a single flow step."""
    step_number: int
    title: str
    command: str
    status: str  # "ok", "skipped", "failed", "print_only", "planned"
    exit_code: Optional[int] = None
    skip_reason: Optional[str] = None


@dataclass
class FlowDefinition:
    """A named multi-step flow."""
    name: str
    description: str
    steps: List[FlowStep]


@dataclass
class FlowResult:
    """Aggregate result of running a complete flow."""
    flow_name: str
    status: str  # "ok", "failed", "dry_run"
    steps: List[StepResult]
    failed_step: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow": self.flow_name,
            "status": self.status,
            "steps": [
                {
                    "step": s.step_number,
                    "title": s.title,
                    "command": s.command,
                    "status": s.status,
                    "exit_code": s.exit_code,
                    "skip_reason": s.skip_reason,
                }
                for s in self.steps
            ],
            "failed_step": self.failed_step,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def run_flow(
    flow: FlowDefinition,
    *,
    apply: bool = False,
    cwd: Optional[Path] = None,
    json_mode: bool = False,
) -> FlowResult:
    """Execute or dry-run a flow.

    apply=False (default): returns plan with status "planned" for each step.
    apply=True: executes each step via subprocess, fail-fast on unexpected error.
    """
    work_dir = (cwd or Path(".")).resolve()
    step_results: Dict[int, StepResult] = {}
    all_results: List[StepResult] = []
    failed_step: Optional[int] = None

    for step in flow.steps:
        # Resolve command
        if step.command_fn is not None:
            cmd = step.command_fn(step_results)
        else:
            cmd = step.command

        # Check skip condition
        if step.skip_fn is not None:
            should_skip, reason = step.skip_fn(work_dir, step_results)
            if should_skip:
                result = StepResult(
                    step_number=step.number,
                    title=step.title,
                    command=cmd,
                    status="skipped",
                    skip_reason=reason,
                )
                step_results[step.number] = result
                all_results.append(result)
                continue

        # Print-only steps are never executed
        if step.print_only:
            result = StepResult(
                step_number=step.number,
                title=step.title,
                command=cmd,
                status="print_only",
            )
            step_results[step.number] = result
            all_results.append(result)
            continue

        # Dry-run: just record what would happen
        if not apply:
            result = StepResult(
                step_number=step.number,
                title=step.title,
                command=cmd,
                status="planned",
            )
            step_results[step.number] = result
            all_results.append(result)
            continue

        # Execute via subprocess
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=work_dir,
            capture_output=json_mode,
            text=True,
        )

        status = "ok" if proc.returncode in step.expected_exit_codes else "failed"
        result = StepResult(
            step_number=step.number,
            title=step.title,
            command=cmd,
            status=status,
            exit_code=proc.returncode,
        )
        step_results[step.number] = result
        all_results.append(result)

        if status == "failed":
            failed_step = step.number
            break

    overall = "dry_run" if not apply else ("ok" if failed_step is None else "failed")
    return FlowResult(
        flow_name=flow.name,
        status=overall,
        steps=all_results,
        failed_step=failed_step,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_flow_dry_run(flow: FlowDefinition, console: Any) -> None:
    """Print a dry-run plan showing numbered steps."""
    console.print()
    console.print(f"[bold]assay flow {flow.name}[/]  --  {flow.description}")
    console.print()
    console.print("[dim]Dry run -- no commands executed. Use --apply to run.[/]")
    console.print()

    for step in flow.steps:
        prefix = "[dim](info)[/] " if step.print_only else ""
        console.print(f"  [bold cyan]Step {step.number}:[/] {prefix}{step.title}")
        if step.command.startswith("#"):
            console.print(f"    [dim]{step.command}[/]")
        else:
            console.print(f"    [green]$ {step.command}[/]")
        if step.note:
            console.print(f"    [dim]{step.note}[/]")
        console.print()

    console.print(f"[bold]To execute:[/] assay flow {flow.name} --apply")
    console.print()


def render_flow_result(result: FlowResult, console: Any) -> None:
    """Print the result of an executed flow."""
    console.print()
    status_color = "green" if result.status == "ok" else "red"
    console.print(f"[bold]assay flow {result.flow_name}[/]  --  [{status_color}]{result.status.upper()}[/]")
    console.print()

    for step in result.steps:
        if step.status == "ok":
            badge = "[green]PASS[/]"
        elif step.status == "skipped":
            badge = "[yellow]SKIP[/]"
        elif step.status == "print_only":
            badge = "[dim]INFO[/]"
        elif step.status == "failed":
            badge = "[red]FAIL[/]"
        else:
            badge = f"[dim]{step.status}[/]"

        console.print(f"  Step {step.step_number}: {badge}  {step.title}")
        if step.skip_reason:
            console.print(f"    [dim]{step.skip_reason}[/]")
        if step.status == "failed":
            console.print(f"    [red]Exit code: {step.exit_code}[/]")
            console.print(f"    [red]Command: {step.command}[/]")

    console.print()
    if result.failed_step is not None:
        console.print(f"[red]Flow stopped at step {result.failed_step}. Fix the issue and re-run.[/]")
        console.print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_latest_pack(cwd: Path) -> str:
    """Find the most recently created proof_pack_* directory."""
    packs = sorted(
        [p for p in cwd.glob("proof_pack_*") if p.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return str(packs[0]) if packs else "./proof_pack_*/"


# ---------------------------------------------------------------------------
# Flow definitions
# ---------------------------------------------------------------------------

def build_flow_try() -> FlowDefinition:
    """RunCard A: demo tamper detection."""
    return FlowDefinition(
        name="try",
        description="See Assay in action: generate demo packs and verify them.",
        steps=[
            FlowStep(
                number=1,
                title="Generate demo challenge packs",
                command="assay demo-challenge",
                note="Creates challenge_pack/good/ and challenge_pack/tampered/.",
            ),
            FlowStep(
                number=2,
                title="Verify the good pack (should PASS)",
                command="assay verify-pack ./challenge_pack/good/",
                note="Exit 0 = integrity OK, claims OK.",
            ),
            FlowStep(
                number=3,
                title="Verify the tampered pack (should FAIL)",
                command="assay verify-pack ./challenge_pack/tampered/",
                note="Exit 2 = tampered evidence detected.",
                expected_exit_codes=[0, 2],
            ),
        ],
    )


def build_flow_adopt(run_command: str = "python app.py", path: str = ".") -> FlowDefinition:
    """RunCard B: instrument and capture."""

    def _pack_cmd(results: Dict[int, StepResult]) -> str:
        # After step 3 (assay run), find the latest pack
        cwd = Path(".").resolve()
        pack = _find_latest_pack(cwd)
        return f"assay verify-pack {pack}"

    def _explain_cmd(results: Dict[int, StepResult]) -> str:
        cwd = Path(".").resolve()
        pack = _find_latest_pack(cwd)
        return f"assay explain {pack}"

    return FlowDefinition(
        name="adopt",
        description="Instrument your project: scan, patch, run, verify, explain.",
        steps=[
            FlowStep(
                number=1,
                title="Scan for uninstrumented call sites",
                command=f"assay scan {path}",
                note="Finds LLM API calls missing receipt instrumentation.",
            ),
            FlowStep(
                number=2,
                title="Patch entrypoint with SDK integration",
                command=f"assay patch {path} --yes",
                note="Auto-inserts 2-line SDK patches.",
            ),
            FlowStep(
                number=3,
                title="Run with receipts and build proof pack",
                command=f"assay run -c receipt_completeness -- {run_command}",
                note="Wraps your command, collects receipts, builds signed pack.",
            ),
            FlowStep(
                number=4,
                title="Verify the proof pack",
                command=f"assay verify-pack ./proof_pack_*/",
                command_fn=_pack_cmd,
                note="Checks integrity + claims.",
            ),
            FlowStep(
                number=5,
                title="Explain the proof pack",
                command=f"assay explain ./proof_pack_*/",
                command_fn=_explain_cmd,
                note="Human-readable summary of what the pack proves.",
            ),
        ],
    )


def build_flow_ci(run_command: str = "python app.py") -> FlowDefinition:
    """RunCard C+D: CI evidence gate."""

    def _skip_lock(cwd: Path, _results: Dict[int, StepResult]) -> Tuple[bool, str]:
        if (cwd / "assay.lock").exists():
            return True, "assay.lock already exists"
        return False, ""

    return FlowDefinition(
        name="ci",
        description="Set up CI evidence gating: lock, CI workflow, baseline.",
        steps=[
            FlowStep(
                number=1,
                title="Create verification lockfile",
                command="assay lock init",
                note="Freezes claim set for reproducible CI verification.",
                skip_fn=_skip_lock,
            ),
            FlowStep(
                number=2,
                title="Generate CI workflow",
                command=f'assay ci init github --run-command "{run_command}"',
                note="Writes .github/workflows/assay-verify.yml.",
            ),
            FlowStep(
                number=3,
                title="Set diff baseline",
                command="assay baseline set ./proof_pack_*/",
                note="Saves current pack as baseline for regression detection.",
            ),
        ],
    )


def build_flow_mcp(server_command: Optional[str] = None) -> FlowDefinition:
    """RunCard G: MCP tool call audit."""

    def _skip_policy(cwd: Path, _results: Dict[int, StepResult]) -> Tuple[bool, str]:
        if (cwd / "assay.mcp-policy.yaml").exists():
            return True, "assay.mcp-policy.yaml already exists"
        return False, ""

    proxy_cmd = f"assay mcp-proxy -- {server_command}" if server_command else "assay mcp-proxy -- <your-server-command>"

    return FlowDefinition(
        name="mcp",
        description="Set up MCP tool call auditing.",
        steps=[
            FlowStep(
                number=1,
                title="Initialize MCP policy file",
                command="assay mcp policy init",
                note="Creates assay.mcp-policy.yaml with privacy-by-default settings.",
                skip_fn=_skip_policy,
            ),
            FlowStep(
                number=2,
                title="Start MCP proxy (long-running)",
                command=proxy_cmd,
                note="Wraps your MCP server with receipt emission. Run manually.",
                print_only=True,
            ),
        ],
    )


def build_flow_audit(pack_dir: str = "./proof_pack_*/") -> FlowDefinition:
    """RunCard F: auditor handoff."""
    return FlowDefinition(
        name="audit",
        description="Auditor handoff: verify, explain, and bundle evidence.",
        steps=[
            FlowStep(
                number=1,
                title="Verify proof pack integrity",
                command=f"assay verify-pack {pack_dir} --require-claim-pass",
                note="Full verification with claim gate.",
            ),
            FlowStep(
                number=2,
                title="Generate plain-English explanation",
                command=f"assay explain {pack_dir}",
                note="Human-readable summary for auditors.",
            ),
            FlowStep(
                number=3,
                title="Bundle for handoff (future)",
                command=f"# assay audit bundle {pack_dir}  (not yet implemented)",
                note="Will create a self-contained evidence bundle.",
                print_only=True,
            ),
        ],
    )
