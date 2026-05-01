"""
Assay CLI commands: AI evidence that's harder to fake and easier to verify.

Commands:
  assay try           - See what Assay does in 15 seconds (start here)
    assay try-openclaw  - OpenClaw membrane demo with proof-pack verification
  assay reviewer verify - Verify a Reviewer Packet and explain the settlement
  assay run           - Run a command and build a Proof Pack from receipts
  assay verify-pack   - Verify a Proof Pack's integrity
  assay verify-signer - Extract and verify signer identity from a proof pack
  assay explain       - Plain-English summary of a proof pack
  assay analyze       - Cost, latency, and error analysis of receipts
  assay diff          - Compare two proof packs (claims, cost, latency, models)
  assay scan          - Find uninstrumented LLM call sites
  assay patch         - Auto-insert SDK integration patches
  assay doctor        - Preflight checks
  assay onboard       - Guided setup
  assay demo-incident - Two-act scenario (honest failure demo)
  assay demo-challenge- CTF-style good + tampered pack pair
  assay demo-pack     - Build + verify a demo pack
  assay proof-pack    - Build a signed Proof Pack from an existing trace
  assay lock init     - Create a lockfile with sane defaults
  assay lock write    - Write a lockfile with explicit card list
  assay lock check    - Validate an existing lockfile
  assay baseline set  - Save a pack as the diff baseline
  assay baseline get  - Show current diff baseline
  assay flow try      - Demo: generate + verify tamper detection
  assay flow adopt    - Instrument: scan -> patch -> run -> verify -> explain
  assay flow ci       - CI gate: lock -> ci init -> baseline
  assay flow mcp      - MCP audit: policy init -> proxy guidance
  assay flow audit    - Auditor handoff: verify -> explain -> bundle
  assay audit bundle  - Create self-contained evidence bundle for auditor handoff
  assay ci init       - Generate CI workflow
  assay cards list    - List built-in run cards
  assay cards show    - Show card details and claims
  assay key list      - List local signing keys
  assay key rotate    - Generate and switch to a new signer key
  assay key set-active - Set active signer key
  assay mcp-proxy     - MCP Notary Proxy (receipt every tool call)
  assay status        - One-screen operational dashboard
  assay score         - Evidence Readiness Score for this repository
  assay report        - Unified Evidence Readiness Report (HTML/SARIF/markdown)
  assay output-assay  - Render a local Output Assay report from artifact + draft
  assay start demo    - See Assay in action (quickstart flow)
  assay start ci      - Set up CI evidence gating
  assay start mcp     - Set up MCP tool call auditing
  assay compare       - Contract-based comparability evaluation (denial engine)
  assay compliance report - Map evidence pack to regulatory framework controls
  assay version       - Show version info
"""

from __future__ import annotations

import base64
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

_DEFAULT_FEEDBACK_URL = "https://github.com/Haserjian/assay/discussions"
_CI_FEEDBACK_SUPPRESSION_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "BUILD_ID",
    "JENKINS_URL",
    "TF_BUILD",
    "BUILDKITE",
    "CIRCLECI",
)

assay_app = typer.Typer(
    name="assay",
    help="Signed evidence for AI systems. Start with: assay try",
    no_args_is_help=True,
)


def _append_query_param(url: str, key: str, value: str) -> str:
    """Return url with the given query parameter set."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[key] = value
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def _feedback_url_for_source(source: str) -> str:
    """Return the feedback URL for a human-facing surface."""
    base = os.environ.get("ASSAY_FEEDBACK_URL", _DEFAULT_FEEDBACK_URL)
    return _append_query_param(base, "src", source)


def _should_show_feedback_footer(stdout: Any = None) -> bool:
    """Return True when a human-facing footer should be shown."""
    stream = stdout if stdout is not None else sys.stdout
    is_tty = getattr(stream, "isatty", lambda: False)()
    if not is_tty:
        return False
    return not any(os.environ.get(var) for var in _CI_FEEDBACK_SUPPRESSION_VARS)


def _clamp(value: float, name: str) -> float:
    """Clamp value to [0, 1] and warn if out of range."""
    if value < 0 or value > 1:
        clamped = max(0.0, min(1.0, value))
        console.print(f"[yellow]Warning: {name}={value} clamped to {clamped}[/]")
        return clamped
    return value


def _output_json(data: Dict[str, Any], exit_code: Optional[int] = None) -> None:
    """Print structured JSON to stdout and exit.

    Exit codes:
    - 0: success (status == "ok")
    - 1: error (status == "error" or "blocked")
    - 2: verification failed (status == "failed")
    - 3: bad input (invalid arguments, missing files)

    Can be overridden with explicit exit_code parameter.
    """
    print(json.dumps(data, indent=2, default=str))
    if exit_code is not None:
        raise typer.Exit(exit_code)
    status = data.get("status", "ok")
    if status == "ok":
        raise typer.Exit(0)
    elif status == "failed":
        raise typer.Exit(2)
    else:  # "error", "blocked", etc.
        raise typer.Exit(1)


def _extract_action_class(action: str) -> str:
    """Extract action class from action string (e.g., 'shell:pytest' -> 'shell')."""
    if ":" in action:
        return action.split(":")[0]
    return "unknown"


def _machine_coverage_ratio(coverage_summary: Dict[str, int]) -> Dict[str, float | int]:
    """Summarize machine-verifiable reviewer-packet coverage for console output."""
    numerator = int(coverage_summary.get("EVIDENCED", 0))
    denominator = (
        numerator
        + int(coverage_summary.get("PARTIAL", 0))
        + int(coverage_summary.get("FAILED", 0))
    )
    value = (numerator / denominator) if denominator else 0.0
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": value,
    }


@assay_app.command("validate", hidden=True)
def validate_action(
    action: str = typer.Argument(
        ..., help="Action to validate (e.g., 'shell:rm -rf /')"
    ),
    coherence_delta: float = typer.Option(
        0.0, "--coherence", "-c", help="Expected coherence change (-1 to 1)"
    ),
    dignity_delta: float = typer.Option(
        0.0, "--dignity", "-d", help="Expected dignity impact (-1 to 1)"
    ),
    emit_receipt: bool = typer.Option(
        True, "--receipt/--no-receipt", help="Emit validation receipt"
    ),
    persist: bool = typer.Option(
        True, "--persist/--no-persist", help="Persist receipts to disk"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Validate an action against Guardian rules.

    Checks:
    1. No coherence gain by dignity debt
    2. Receipt will be emitted (auditability)

    Receipts are persisted to ~/.assay/<date>/<trace_id>.jsonl

    Examples:
        assay validate "shell:pytest" --coherence 0.1 --dignity 0.0
        assay validate "shell:rm -rf /" --coherence 0.1 --dignity -0.5
    """
    from assay import __version__
    from assay.guardian import no_action_without_receipt, no_coherence_by_dignity_debt
    from assay.store import get_default_store

    # Start trace
    store = get_default_store() if persist else None
    trace_id = store.start_trace() if store else "no-persist"

    # Extract action class for taxonomy
    action_class = _extract_action_class(action)

    # Check Guardian rules
    verdict1 = no_coherence_by_dignity_debt(coherence_delta, dignity_delta)
    verdict2 = no_action_without_receipt(emit_receipt, action_class)

    all_passed = verdict1.allowed and verdict2.allowed

    verdict_entry = {
        "type": "guardian_check",
        "action": action,
        "action_class": action_class,
        "coherence_delta": coherence_delta,
        "dignity_delta": dignity_delta,
        "verdicts": {
            "no_coherence_by_dignity_debt": {
                "allowed": verdict1.allowed,
                "reason": verdict1.reason,
                "clause0_violation": verdict1.clause0_violation,
            },
            "no_action_without_receipt": {
                "allowed": verdict2.allowed,
                "reason": verdict2.reason,
            },
        },
        "overall_allowed": all_passed,
        "assay_version": __version__,
    }

    def _emit_blockage_receipt() -> Optional[str]:
        if not emit_receipt or all_passed:
            return None
        if not verdict1.allowed:
            from assay._receipts.domains.blockages import create_contradiction_receipt

            receipt = create_contradiction_receipt(
                claim_a=f"Action '{action}' improves coherence (+{coherence_delta:.2f})",
                claim_a_confidence=0.8,
                claim_b=f"Action causes dignity harm ({dignity_delta:.2f})",
                claim_b_confidence=0.9,
                impacted_invariants=["clause0_dignity_floor"],
                resolution_attempted=True,
                resolution_result="BLOCKED: COHERENCE_BY_DIGNITY_DEBT",
            )
        elif not verdict2.allowed:
            from assay._receipts.domains.blockages import create_incompleteness_receipt

            receipt = create_incompleteness_receipt(
                undecidable_claim=f"Cannot execute '{action}' without audit trail",
                missing_evidence=["receipt_emission"],
                impact_if_wrong="high",
                recommended_action="gather_evidence",
            )
        else:
            return None

        if store:
            store.append(receipt)
        return receipt.receipt_id

    # JSON output - check BEFORE any console prints to avoid contamination
    if output_json:
        if store:
            store.append_dict(verdict_entry)
        blockage_receipt_id = _emit_blockage_receipt()
        result = {
            "command": "validate",
            "trace_id": trace_id,
            "status": "ok" if all_passed else "blocked",
            "action": action,
            "action_class": action_class,
            "allowed": all_passed,
            "verdicts": verdict_entry["verdicts"],
            "inputs": {
                "coherence_delta": coherence_delta,
                "dignity_delta": dignity_delta,
            },
        }
        if store:
            result["trace_file"] = str(store.trace_file)
        if blockage_receipt_id:
            result["blockage_receipt_id"] = blockage_receipt_id
        _output_json(result)

    # Console output for non-JSON mode
    console.print(f"[dim]Trace: {trace_id}[/]\n")
    console.print(f"[bold]Validating:[/] {action}")
    console.print(f"  Action class: {action_class}")
    console.print(f"  Coherence delta: {coherence_delta:+.2f}")
    console.print(f"  Dignity delta: {dignity_delta:+.2f}")
    console.print()

    # Log verdicts to trace
    if store:
        store.append_dict(verdict_entry)

    # Display results
    if verdict1.allowed:
        console.print("[green]+[/] No coherence by dignity debt: PASS")
    else:
        console.print(
            f"[red]-[/] No coherence by dignity debt: FAIL ({verdict1.reason})"
        )
        if verdict1.clause0_violation:
            console.print("  [red bold]CLAUSE 0 VIOLATION[/]")

    if verdict2.allowed:
        console.print("[green]+[/] Receipt emission: PASS")
    else:
        console.print(f"[red]-[/] Receipt emission: FAIL ({verdict2.reason})")

    console.print()

    if all_passed:
        console.print("[green bold]ACTION ALLOWED[/]")
        if store:
            console.print(f"\n[dim]Trace stored: {store.trace_file}[/]")
    else:
        console.print("[red bold]ACTION BLOCKED[/]")

        # Emit appropriate blockage receipt based on which rule failed
        if emit_receipt:
            receipt_id = _emit_blockage_receipt()
            if receipt_id:
                console.print(f"\n[dim]Blockage receipt: {receipt_id}[/]")

        if store:
            console.print(f"[dim]Trace stored: {store.trace_file}[/]")

        raise typer.Exit(1)


@assay_app.command("health", hidden=True)
def check_health(
    coherence: float = typer.Option(
        0.8, "--coherence", "-c", help="Current coherence (0-1)"
    ),
    tension: float = typer.Option(0.2, "--tension", "-t", help="Current tension (0-1)"),
    tension_delta: float = typer.Option(
        -0.01, "--tension-delta", help="Tension rate of change"
    ),
    dignity: float = typer.Option(0.3, "--dignity", "-d", help="Current dignity (0-1)"),
    volatility: float = typer.Option(
        0.1, "--volatility", "-v", help="Current volatility (0-1)"
    ),
    stateful: bool = typer.Option(
        False, "--stateful", help="Use hysteresis tracker (persists state)"
    ),
    trace_id: Optional[str] = typer.Option(
        None, "--trace", help="Trace ID for stateful mode"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Check system health and grace window status.

    Grace window = stable, low-friction state where actions are safer.
    Values are clamped to [0, 1] range.

    Use --stateful to enable hysteresis (requires N consecutive passes/failures
    to change state, prevents flickering).

    Examples:
        assay health
        assay health --coherence 0.9 --tension 0.1 --dignity 0.4
        assay health --tension 0.5  # High tension - not in grace
        assay health --stateful --trace trace_xxx  # With hysteresis
    """
    from assay.health import (
        GraceConfig,
        GraceTracker,
        check_grace_status,
        clamp,
        format_grace_status,
    )
    from assay.store import get_default_store

    # Clamp inputs
    coherence = clamp(coherence)
    tension = clamp(tension)
    dignity = clamp(dignity)
    volatility = clamp(volatility)

    cfg = GraceConfig()
    store = get_default_store()

    if stateful:
        # Use GraceTracker with hysteresis
        # Load previous tracker state from trace if it exists
        tracker = GraceTracker(cfg=cfg)
        trace_warning: Optional[str] = None

        if trace_id:
            # Load history from existing trace and continue appending to it
            entries = store.read_trace(trace_id)
            if not entries:
                trace_warning = f"trace {trace_id} not found, creating new trace"
                trace_id = store.start_trace()
            else:
                # Set store to append to this existing trace
                store.start_trace(trace_id)
                for entry in entries:
                    if entry.get("type") == "grace_check":
                        # Replay history to rebuild tracker state
                        tracker.update(
                            entry.get("coherence", 0.8),
                            entry.get("tension", 0.2),
                            entry.get("tension_delta", 0.0),
                            entry.get("dignity", 0.3),
                            entry.get("volatility", 0.1),
                        )
        else:
            trace_id = store.start_trace()

        # Update with current values
        in_grace = tracker.update(
            coherence, tension, tension_delta, dignity, volatility
        )

        # Persist this check
        store.append_dict(
            {
                "type": "grace_check",
                "coherence": coherence,
                "tension": tension,
                "tension_delta": tension_delta,
                "dignity": dignity,
                "volatility": volatility,
                "in_grace": in_grace,
                "history": tracker.history,
                "stateful": True,
            }
        )

        # JSON output - check BEFORE any console prints to avoid contamination
        if output_json:
            result = {
                "command": "health",
                "trace_id": trace_id,
                "status": "ok",
                "in_grace": in_grace,
                "stateful": True,
                "history": tracker.history,
                "window_size": cfg.window_size,
                "inputs": {
                    "coherence": coherence,
                    "tension": tension,
                    "tension_delta": tension_delta,
                    "dignity": dignity,
                    "volatility": volatility,
                },
            }
            if trace_warning:
                result["warning"] = trace_warning
            _output_json(result)

        # Console warning (only in non-JSON mode)
        if trace_warning:
            console.print(f"[yellow]Warning: {trace_warning}[/]")

        # Display with hysteresis info
        status_text = "GRACE WINDOW" if in_grace else "NOT IN GRACE"
        history_str = "".join("+" if h else "-" for h in tracker.history)
        panel_content = f"Status: {status_text}\nHysteresis window: [{history_str}] (need {cfg.window_size} consecutive)"

        console.print(
            Panel(
                panel_content,
                title=f"[{'green' if in_grace else 'yellow'} bold]{status_text}[/]",
                border_style="green" if in_grace else "yellow",
            )
        )
        console.print(f"\n[dim]Trace: {trace_id}[/]")

    else:
        # Single-step check (no hysteresis)
        status = check_grace_status(
            coherence=coherence,
            tension=tension,
            tension_derivative=tension_delta,
            dignity=dignity,
            volatility=volatility,
        )

        if output_json:
            _output_json(
                {
                    "command": "health",
                    "status": "ok",
                    "in_grace": status.in_grace,
                    "stateful": False,
                    "checks": {
                        "coherence_ok": status.coherence_ok,
                        "tension_ok": status.tension_ok,
                        "tension_decreasing": status.tension_decreasing,
                        "dignity_ok": status.dignity_ok,
                        "volatility_ok": status.volatility_ok,
                    },
                    "inputs": {
                        "coherence": coherence,
                        "tension": tension,
                        "tension_delta": tension_delta,
                        "dignity": dignity,
                        "volatility": volatility,
                    },
                }
            )

        # Display with colors
        if status.in_grace:
            console.print(
                Panel(
                    format_grace_status(status)
                    .replace("[+]", "[green]+[/]")
                    .replace("[-]", "[red]-[/]"),
                    title="[green bold]GRACE WINDOW[/]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    format_grace_status(status)
                    .replace("[+]", "[green]+[/]")
                    .replace("[-]", "[red]-[/]"),
                    title="[yellow bold]NOT IN GRACE[/]",
                    border_style="yellow",
                )
            )

    # Show config
    console.print(
        f"\n[dim]Thresholds: C>={cfg.c_hi} T<={cfg.t_lo} D>={cfg.d_floor} V<={cfg.v_max}[/]"
    )


@assay_app.command("demo", hidden=True)
def run_demo(
    scenario: str = typer.Option(
        "all",
        "--scenario",
        "-s",
        help="Demo scenario: all, incomplete, contradiction, paradox, guardian",
    ),
    persist: bool = typer.Option(
        True, "--persist/--no-persist", help="Persist receipts to disk"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Run demonstration showing receipts + blockages.

    All receipts are persisted to ~/.assay/ with a trace ID.

    Scenarios:
    - all: Run all demos
    - incomplete: Missing evidence prevents decision
    - contradiction: Two claims conflict
    - paradox: Contradiction requires frame change
    - guardian: Blocked by dignity rule

    Perfect for asciinema recording.

    Examples:
        assay demo
        assay demo --scenario guardian
        assay demo --json
    """
    from assay import __version__
    from assay.store import get_default_store

    # Start trace
    store = get_default_store() if persist else None
    trace_id = store.start_trace() if store else "no-persist"

    silent = output_json

    if not silent:
        console.print(f"[bold cyan]Assay {__version__} Demo[/]")
        console.print("AI evidence that's harder to fake and easier to verify")
        console.print(f"[dim]Trace: {trace_id}[/]\n")

    if scenario in ("all", "incomplete"):
        _demo_incompleteness(store, silent=silent)

    if scenario in ("all", "contradiction"):
        _demo_contradiction(store, silent=silent)

    if scenario in ("all", "paradox"):
        _demo_paradox(store, silent=silent)

    if scenario in ("all", "guardian"):
        _demo_guardian(store, silent=silent)

    if output_json:
        entries = store.read_trace(trace_id) if store else []
        type_counts = Counter(
            (entry.get("type") or entry.get("receipt_type") or "unknown")
            for entry in entries
        )
        result: Dict[str, Any] = {
            "command": "demo",
            "status": "ok",
            "trace_id": trace_id,
            "scenario": scenario,
            "entry_count": len(entries),
            "type_counts": dict(type_counts),
            "persisted": store is not None,
        }
        if store:
            result["trace_file"] = str(store.trace_file)
        _output_json(result)

    console.print("\n[bold green]Demo complete.[/]")
    console.print("[dim]Every refusal left a structured proof.[/]")

    if store:
        console.print(f"\n[bold]Trace stored:[/] {store.trace_file}")


def _demo_incompleteness(store=None, silent: bool = False):
    """Demo: Incompleteness receipt."""
    if not silent:
        console.print(Panel("[bold]Scenario: Incompleteness[/]", style="cyan"))
        console.print("Attempting to run assay without target repository...\n")

    from assay._receipts.domains.blockages import create_incompleteness_receipt

    receipt = create_incompleteness_receipt(
        undecidable_claim="Cannot run security scan without target repository",
        missing_evidence=["target_repo", "scan_policy"],
        impact_if_wrong="high",
        recommended_action="gather_evidence",
    )

    if store:
        store.append(receipt)

    if not silent:
        console.print("[red]BLOCKED[/]: Missing required context")
        console.print(f"  Claim: {receipt.undecidable_claim}")
        console.print(f"  Missing: {', '.join(receipt.missing_evidence)}")
        console.print(f"  Impact if wrong: {receipt.impact_if_wrong}")
        console.print(f"  Recommended: {receipt.recommended_action}")
        console.print(f"\n[dim]Receipt ID: {receipt.receipt_id}[/]\n")


def _demo_contradiction(store=None, silent: bool = False):
    """Demo: Contradiction receipt."""
    if not silent:
        console.print(Panel("[bold]Scenario: Contradiction[/]", style="yellow"))
        console.print("Policy check vs coherence check disagree...\n")

    from assay._receipts.domains.blockages import create_contradiction_receipt

    receipt = create_contradiction_receipt(
        claim_a="Action improves system coherence (+0.15)",
        claim_a_confidence=0.85,
        claim_b="Action violates rate limit policy",
        claim_b_confidence=0.92,
        impacted_invariants=["policy_compliance", "coherence_monotonicity"],
        resolution_attempted=True,
        resolution_result="Deferred to human review",
    )

    if store:
        store.append(receipt)

    if not silent:
        console.print("[yellow]CONTRADICTION DETECTED[/]")
        console.print(
            f"  Claim A ({receipt.claim_a_confidence:.0%}): {receipt.claim_a}"
        )
        console.print(
            f"  Claim B ({receipt.claim_b_confidence:.0%}): {receipt.claim_b}"
        )
        console.print(f"  Invariants: {', '.join(receipt.impacted_invariants)}")
        console.print(f"  Resolution: {receipt.resolution_result}")
        console.print(f"\n[dim]Receipt ID: {receipt.receipt_id}[/]\n")


def _demo_paradox(store=None, silent: bool = False):
    """Demo: Paradox receipt."""
    if not silent:
        console.print(Panel("[bold]Scenario: Paradox[/]", style="red"))
        console.print("Contradiction persists after resolution attempt...\n")

    from assay._receipts.domains.blockages import create_paradox_receipt

    receipt = create_paradox_receipt(
        contradiction_id="con_abc123",
        why_frame_change_required="Both claims are valid under current policy framework. "
        "Resolving requires updating the rate limit policy itself.",
        candidate_reframes=[
            "Add exception for coherence-improving actions",
            "Implement grace period for near-threshold requests",
            "Escalate rate limit decisions to council",
        ],
        escalation_path="council",
        dignity_risk=0.3,
    )

    if store:
        store.append(receipt)

    if not silent:
        console.print("[red]PARADOX - FRAME CHANGE REQUIRED[/]")
        console.print(f"  Source: {receipt.contradiction_id}")
        console.print(f"  Why: {receipt.why_frame_change_required[:80]}...")
        console.print(f"  Dignity risk: {receipt.dignity_risk:.0%}")
        console.print(f"  Escalation: {receipt.escalation_path}")
        console.print("  Candidate reframes:")
        for reframe in receipt.candidate_reframes:
            console.print(f"    - {reframe}")
        console.print(f"\n[dim]Receipt ID: {receipt.receipt_id}[/]\n")


def _demo_guardian(store=None, silent: bool = False):
    """Demo: Guardian rule blocking action."""
    if not silent:
        console.print(Panel("[bold]Scenario: Guardian Block[/]", style="magenta"))
        console.print("Attempting action that trades dignity for coherence...\n")

    from assay.guardian import no_coherence_by_dignity_debt

    coherence_delta = 0.15
    dignity_delta = -0.08

    if not silent:
        console.print("  Proposed action: Cache user data without consent")
        console.print(f"  Coherence gain: +{coherence_delta:.0%}")
        console.print(f"  Dignity cost: {dignity_delta:.0%}")
        console.print()

    verdict = no_coherence_by_dignity_debt(coherence_delta, dignity_delta)

    if store:
        store.append_dict(
            {
                "type": "guardian_verdict",
                "rule": "no_coherence_by_dignity_debt",
                "coherence_delta": coherence_delta,
                "dignity_delta": dignity_delta,
                "dignity_composite": 0.65,
                "allowed": verdict.allowed,
                "reason": verdict.reason,
                "clause0_violation": verdict.clause0_violation,
            }
        )

    if not silent:
        if not verdict.allowed:
            console.print(f"[red bold]BLOCKED: {verdict.reason}[/]")
            if verdict.clause0_violation:
                console.print("[red]  CLAUSE 0 VIOLATION: Dignity floor breached[/]")
            console.print("\n[dim]No coherence gain by dignity debt.[/]\n")
        else:
            console.print("[green]ALLOWED[/]")


@assay_app.command("show", hidden=True)
def show_trace(
    trace_id: str = typer.Argument(..., help="Trace ID to show"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Show receipts from a trace.

    Examples:
        assay show trace_20250205T143022_abc12345
        assay show trace_xxx --json
    """
    from assay.store import get_default_store

    store = get_default_store()
    entries = store.read_trace(trace_id)

    if not entries:
        if output_json:
            _output_json(
                {
                    "command": "show",
                    "trace_id": trace_id,
                    "status": "error",
                    "errors": [f"Trace not found: {trace_id}"],
                }
            )
        console.print(f"[red]Trace not found:[/] {trace_id}")
        raise typer.Exit(1)

    if output_json:
        _output_json(
            {
                "command": "show",
                "trace_id": trace_id,
                "status": "ok",
                "entry_count": len(entries),
                "entries": entries,
            }
        )

    console.print(f"[bold]Trace:[/] {trace_id}")
    console.print(f"[dim]Entries: {len(entries)}[/]\n")

    for i, entry in enumerate(entries, 1):
        entry_type = entry.get("type") or entry.get("receipt_type", "unknown")
        receipt_id = entry.get("receipt_id", "-")
        stored_at = entry.get("_stored_at", "-")

        console.print(f"{i}. [{entry_type}] {receipt_id}")
        console.print(f"   [dim]{stored_at}[/]")

        # Show key fields based on type
        if entry_type == "IncompletenessReceipt":
            console.print(f"   Claim: {entry.get('undecidable_claim', '-')}")
        elif entry_type == "ContradictionReceipt":
            console.print(f"   Claim A: {entry.get('claim_a', '-')}")
            console.print(f"   Claim B: {entry.get('claim_b', '-')}")
        elif entry_type == "guardian_check":
            console.print(f"   Action: {entry.get('action', '-')}")
            console.print(f"   Allowed: {entry.get('overall_allowed', '-')}")
        console.print()


@assay_app.command("list", hidden=True)
def list_traces(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of traces to show"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    List recent traces.

    Examples:
        assay list
        assay list --limit 20
        assay list --json
    """
    from assay.store import get_default_store

    store = get_default_store()
    traces = store.list_traces(limit=limit)

    if output_json:
        _output_json(
            {
                "command": "list",
                "status": "ok",
                "count": len(traces),
                "traces": traces,
            }
        )

    if not traces:
        console.print("[dim]No traces found.[/]")
        console.print("[dim]Run 'assay demo' to create one.[/]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Trace ID", style="cyan")
    table.add_column("Date")
    table.add_column("Size", justify="right")
    table.add_column("Modified")

    for t in traces:
        size = (
            f"{t['size_bytes']} B"
            if t["size_bytes"] < 1024
            else f"{t['size_bytes'] // 1024} KB"
        )
        table.add_row(
            t["trace_id"],
            t["date"],
            size,
            t["modified"][:19],
        )

    console.print(table)


@assay_app.command("verify", hidden=True)
def verify_trace(
    trace_id: str = typer.Argument(..., help="Trace ID to verify"),
    strict: bool = typer.Option(
        False, "--strict", help="Enable strict mode (check hashes/signatures)"
    ),
    policy_override: Optional[List[str]] = typer.Option(
        None,
        "--policy-override",
        help="Override policy values (repeatable, e.g., dignity_floor=0.5)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Verify trace integrity.

    Checks:
    - Every entry has required fields (type or receipt_type)
    - Receipt IDs are unique within the trace
    - Temporal ordering is consistent (_stored_at increases)
    - Parent references are valid (if present)

    With --strict: also verifies hashes and signatures (if present).

    With --policy-override: re-verify with different policy thresholds.
    This is the killer demo feature: show a trace that passed, then watch
    it fail when the bar is raised.

    Exit codes:
    - 0: Verification passed
    - 1: Error (trace not found, etc.)
    - 2: Verification failed

    Examples:
        assay verify trace_20250205T143022_abc12345
        assay verify trace_xxx --strict
        assay verify trace_xxx --json
        assay verify trace_xxx --policy-override dignity_floor=0.5
        assay verify trace_xxx --policy-override dignity_floor=0.8 --policy-override coherence_floor=0.9
    """
    from assay.store import get_default_store

    store = get_default_store()
    entries = store.read_trace(trace_id)

    if not entries:
        if output_json:
            _output_json(
                {
                    "command": "verify",
                    "trace_id": trace_id,
                    "status": "error",
                    "errors": [f"Trace not found: {trace_id}"],
                }
            )
        console.print(f"[red]Trace not found:[/] {trace_id}")
        raise typer.Exit(1)

    # Parse policy overrides
    overrides: Dict[str, float] = {}
    if policy_override:
        for override in policy_override:
            if "=" not in override:
                if output_json:
                    _output_json(
                        {
                            "command": "verify",
                            "trace_id": trace_id,
                            "status": "error",
                            "errors": [
                                f"Invalid policy override format: {override} (expected key=value)"
                            ],
                        }
                    )
                console.print(f"[red]Invalid policy override format:[/] {override}")
                console.print(
                    "[dim]Expected format: key=value (e.g., dignity_floor=0.5)[/]"
                )
                raise typer.Exit(1)
            key, value = override.split("=", 1)
            try:
                overrides[key.strip()] = float(value.strip())
            except ValueError:
                if output_json:
                    _output_json(
                        {
                            "command": "verify",
                            "trace_id": trace_id,
                            "status": "error",
                            "errors": [
                                f"Invalid policy override value: {value} (expected float)"
                            ],
                        }
                    )
                console.print(f"[red]Invalid policy override value:[/] {value}")
                raise typer.Exit(1)

    errors: List[str] = []
    warnings: List[str] = []
    policy_violations: List[Dict[str, Any]] = []
    prev_stored_at: Optional[str] = None

    # Pre-compute all receipt IDs in the trace for parent reference validation
    all_receipt_ids: set = set()
    for entry in entries:
        receipt_id = entry.get("receipt_id")
        if receipt_id:
            all_receipt_ids.add(receipt_id)

    # Track IDs seen so far for duplicate detection
    seen_receipt_ids: set = set()

    for i, entry in enumerate(entries):
        entry_num = i + 1

        # Check required fields
        entry_type = entry.get("type") or entry.get("receipt_type")
        if not entry_type:
            errors.append(f"Entry {entry_num}: missing type or receipt_type")

        # Check receipt_id uniqueness
        receipt_id = entry.get("receipt_id")
        if receipt_id:
            if receipt_id in seen_receipt_ids:
                errors.append(f"Entry {entry_num}: duplicate receipt_id '{receipt_id}'")
            seen_receipt_ids.add(receipt_id)

        # Check temporal ordering
        stored_at = entry.get("_stored_at")
        if stored_at and prev_stored_at:
            if stored_at < prev_stored_at:
                errors.append(
                    f"Entry {entry_num}: temporal ordering violation (_stored_at goes backwards)"
                )
        prev_stored_at = stored_at

        # Check parent references (if present)
        # ParadoxReceipt has contradiction_id, other receipts may have parent_receipt_id
        parent_id = entry.get("parent_receipt_id") or entry.get("contradiction_id")
        if parent_id and parent_id not in all_receipt_ids:
            warnings.append(
                f"Entry {entry_num}: parent reference '{parent_id}' not found in trace"
            )

        # Policy override checks
        if overrides:
            # Check dignity_floor override
            if "dignity_floor" in overrides:
                floor = overrides["dignity_floor"]
                # Look for dignity_composite in various places
                dignity = entry.get("dignity_composite")
                if dignity is None:
                    # Check in verdicts or nested structures
                    verdicts = entry.get("verdicts", {})
                    if isinstance(verdicts, dict):
                        for v in verdicts.values():
                            if isinstance(v, dict) and "dignity_composite" in v:
                                dignity = v.get("dignity_composite")
                                break

                if dignity is not None:
                    try:
                        dignity_val = float(dignity)
                        if dignity_val < floor:
                            policy_violations.append(
                                {
                                    "entry": entry_num,
                                    "receipt_id": receipt_id,
                                    "field": "dignity_composite",
                                    "value": dignity_val,
                                    "floor": floor,
                                }
                            )
                            errors.append(
                                f"Entry {entry_num}: dignity_composite ({dignity_val:.3f}) "
                                f"below policy floor ({floor:.3f})"
                            )
                    except (ValueError, TypeError):
                        pass

            # Check coherence_floor override
            if "coherence_floor" in overrides:
                floor = overrides["coherence_floor"]
                coherence = entry.get("coherence") or entry.get("coherence_delta")
                if coherence is not None:
                    try:
                        coherence_val = float(coherence)
                        if coherence_val < floor:
                            policy_violations.append(
                                {
                                    "entry": entry_num,
                                    "receipt_id": receipt_id,
                                    "field": "coherence",
                                    "value": coherence_val,
                                    "floor": floor,
                                }
                            )
                            errors.append(
                                f"Entry {entry_num}: coherence ({coherence_val:.3f}) "
                                f"below policy floor ({floor:.3f})"
                            )
                    except (ValueError, TypeError):
                        pass

        # Strict mode checks
        if strict:
            # Check for hash field
            proof = entry.get("proof", {})
            content_hash = (
                proof.get("hash") or entry.get("content_hash") or entry.get("hash")
            )

            if entry_type and "Receipt" in str(entry_type):
                if not content_hash:
                    warnings.append(
                        f"Entry {entry_num}: receipt has no content_hash (strict)"
                    )
                else:
                    # Verify hash matches content
                    try:
                        from assay._receipts.canonicalize import compute_payload_hash

                        # Exclude proof and trace metadata for hash computation
                        payload = {
                            k: v
                            for k, v in entry.items()
                            if k not in ("proof", "_trace_id", "_stored_at", "_store_seq")
                        }
                        # compute_payload_hash returns raw hex (OCD-1 resolved)
                        computed_hash = compute_payload_hash(
                            payload, algorithm="sha256"
                        )

                        # Normalize stored hash: strip prefix if present
                        hash_to_check = content_hash
                        if ":" in hash_to_check:
                            hash_to_check = hash_to_check.split(":", 1)[1]

                        if hash_to_check != computed_hash:
                            errors.append(
                                f"Entry {entry_num}: hash mismatch (computed {computed_hash[:25]}..., got {hash_to_check[:25]}...)"
                            )
                    except ImportError:
                        warnings.append(
                            f"Entry {entry_num}: cannot verify hash (canonicalize not available)"
                        )
                    except Exception as e:
                        warnings.append(
                            f"Entry {entry_num}: hash verification error: {e}"
                        )

                # Verify receipt_hash if present
                receipt_hash = entry.get("receipt_hash")
                if receipt_hash:
                    try:
                        from assay._receipts.canonicalize import compute_payload_hash

                        payload = {
                            k: v
                            for k, v in entry.items()
                            if k
                            not in ("proof", "_trace_id", "_stored_at", "_store_seq", "receipt_hash")
                        }
                        computed_receipt_hash = compute_payload_hash(
                            payload, algorithm="sha256"
                        )

                        # Normalize stored hash: strip prefix if present
                        hash_to_check = receipt_hash
                        if ":" in hash_to_check:
                            hash_to_check = hash_to_check.split(":", 1)[1]

                        if hash_to_check != computed_receipt_hash:
                            errors.append(
                                f"Entry {entry_num}: receipt_hash mismatch "
                                f"(computed {computed_receipt_hash[:25]}..., got {hash_to_check[:25]}...)"
                            )
                    except ImportError:
                        warnings.append(
                            f"Entry {entry_num}: cannot verify receipt_hash (canonicalize not available)"
                        )
                    except Exception as e:
                        warnings.append(
                            f"Entry {entry_num}: receipt_hash verification error: {e}"
                        )

                # Check signature if present
                signature = proof.get("producer_signature")
                if signature:
                    try:
                        # Signature verification requires the verify key
                        # For now, just note that signature is present
                        warnings.append(
                            f"Entry {entry_num}: signature present but key not configured for verification"
                        )
                    except Exception as e:
                        warnings.append(
                            f"Entry {entry_num}: signature check error: {e}"
                        )

    # Determine result
    passed = len(errors) == 0

    if output_json:
        result_data = {
            "command": "verify",
            "trace_id": trace_id,
            "status": "ok" if passed else "failed",
            "passed": passed,
            "entry_count": len(entries),
            "errors": errors,
            "warnings": warnings,
            "strict": strict,
        }
        if overrides:
            result_data["policy_override"] = overrides
            result_data["policy_violations"] = policy_violations
        _output_json(result_data)

    # Display results
    console.print(f"[bold]Verifying:[/] {trace_id}")
    console.print(f"[dim]Entries: {len(entries)}[/]")

    # Show policy overrides if any
    if overrides:
        console.print()
        console.print("[cyan]Policy overrides applied:[/]")
        for key, value in overrides.items():
            console.print(f"  {key} = {value}")
    console.print()

    if errors:
        console.print("[red bold]VERIFICATION FAILED[/]\n")
        for err in errors:
            console.print(f"  [red]-[/] {err}")
    else:
        console.print("[green bold]VERIFICATION PASSED[/]\n")

    if warnings:
        console.print("\n[yellow]Warnings:[/]")
        for warn in warnings:
            console.print(f"  [yellow]![/] {warn}")

    console.print(
        f"\n[dim]Checked: {len(entries)} entries, {len(all_receipt_ids)} receipts[/]"
    )

    if not passed:
        raise typer.Exit(2)


@assay_app.command("diff", hidden=True)
def diff_traces(
    trace_a: str = typer.Argument(..., help="First trace ID"),
    trace_b: str = typer.Argument(..., help="Second trace ID"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Compare two traces.

    Shows:
    - Entry count differences
    - Receipt type distribution
    - Receipt ID overlap (common, unique to each)

    Examples:
        assay diff trace_aaa trace_bbb
        assay diff trace_aaa trace_bbb --json
    """
    from collections import Counter

    from assay.store import get_default_store

    store = get_default_store()
    entries_a = store.read_trace(trace_a)
    entries_b = store.read_trace(trace_b)

    if not entries_a:
        if output_json:
            _output_json(
                {
                    "command": "diff",
                    "trace_a": trace_a,
                    "trace_b": trace_b,
                    "status": "error",
                    "errors": [f"Trace not found: {trace_a}"],
                }
            )
        console.print(f"[red]Trace not found:[/] {trace_a}")
        raise typer.Exit(1)
    if not entries_b:
        if output_json:
            _output_json(
                {
                    "command": "diff",
                    "trace_a": trace_a,
                    "trace_b": trace_b,
                    "status": "error",
                    "errors": [f"Trace not found: {trace_b}"],
                }
            )
        console.print(f"[red]Trace not found:[/] {trace_b}")
        raise typer.Exit(1)

    # Extract types
    def get_types(entries: List[Dict]) -> List[str]:
        return [e.get("type") or e.get("receipt_type", "unknown") for e in entries]

    types_a = get_types(entries_a)
    types_b = get_types(entries_b)

    counter_a = Counter(types_a)
    counter_b = Counter(types_b)

    # Find receipt_id overlap
    ids_a = {e.get("receipt_id") for e in entries_a if e.get("receipt_id")}
    ids_b = {e.get("receipt_id") for e in entries_b if e.get("receipt_id")}

    common_ids = ids_a & ids_b
    only_a = ids_a - ids_b
    only_b = ids_b - ids_a

    # Build diff result
    diff_result = {
        "command": "diff",
        "trace_a": trace_a,
        "trace_b": trace_b,
        "status": "ok",
        "entry_counts": {
            "trace_a": len(entries_a),
            "trace_b": len(entries_b),
            "difference": len(entries_b) - len(entries_a),
        },
        "type_distribution": {
            "trace_a": dict(counter_a),
            "trace_b": dict(counter_b),
        },
        "receipt_overlap": {
            "common": len(common_ids),
            "only_in_a": len(only_a),
            "only_in_b": len(only_b),
        },
    }

    if output_json:
        _output_json(diff_result)

    # Display
    console.print("[bold]Comparing traces[/]")
    console.print(f"  A: {trace_a}")
    console.print(f"  B: {trace_b}\n")

    # Entry counts
    table = Table(show_header=True, header_style="bold", title="Entry Counts")
    table.add_column("Metric")
    table.add_column("Trace A", justify="right")
    table.add_column("Trace B", justify="right")
    table.add_column("Diff", justify="right")

    table.add_row(
        "Total entries",
        str(len(entries_a)),
        str(len(entries_b)),
        f"{len(entries_b) - len(entries_a):+d}",
    )
    console.print(table)
    console.print()

    # Type distribution
    all_types = set(counter_a.keys()) | set(counter_b.keys())
    if all_types:
        type_table = Table(
            show_header=True, header_style="bold", title="Type Distribution"
        )
        type_table.add_column("Type")
        type_table.add_column("Trace A", justify="right")
        type_table.add_column("Trace B", justify="right")

        for t in sorted(all_types):
            type_table.add_row(t, str(counter_a.get(t, 0)), str(counter_b.get(t, 0)))
        console.print(type_table)
        console.print()

    # Receipt overlap
    console.print("[bold]Receipt IDs:[/]")
    console.print(f"  Common: {len(common_ids)}")
    console.print(f"  Only in A: {len(only_a)}")
    console.print(f"  Only in B: {len(only_b)}")

    if only_a:
        console.print(
            f"\n[dim]IDs only in A: {', '.join(list(only_a)[:5])}{'...' if len(only_a) > 5 else ''}[/]"
        )
    if only_b:
        console.print(
            f"[dim]IDs only in B: {', '.join(list(only_b)[:5])}{'...' if len(only_b) > 5 else ''}[/]"
        )


@assay_app.command("pack", hidden=True)
def create_pack(
    trace_id: str = typer.Argument(..., help="Trace ID to package"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output zip path (default: evidence_pack_<trace_id>.zip)",
    ),
    include_source: bool = typer.Option(
        False, "--include-source", help="Include relevant source files"
    ),
    forensic: bool = typer.Option(
        False, "--forensic", help="Preserve raw trace bytes (forensic fidelity)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Create an evidence pack for patent defense and demos.

    Produces a self-contained zip with:
    - trace.jsonl (the raw receipt chain)
    - verify_report.json (integrity verification results)
    - merkle_root.json (tamper-evident hash tree)
    - claim_map.json (patent claim -> code -> test mapping)
    - build_metadata.json (versions, timestamps, environment)
    - README.md (human-readable summary)

    Use --forensic to preserve raw trace bytes (for legal/audit parity).
    Default mode re-serializes entries (canonicalized, deterministic).

    Examples:
        assay pack trace_20250205T143022_abc12345
        assay pack trace_xxx -o evidence.zip
        assay pack trace_xxx --include-source
        assay pack trace_xxx --forensic  # Preserve exact bytes
    """
    from pathlib import Path

    from assay.evidence_pack import create_evidence_pack

    output_path = Path(output) if output else None

    try:
        result_path = create_evidence_pack(
            trace_id=trace_id,
            output_path=output_path,
            include_source=include_source,
            preserve_raw=forensic,
        )
    except ValueError as e:
        if output_json:
            _output_json(
                {
                    "command": "pack",
                    "status": "error",
                    "trace_id": trace_id,
                    "errors": [str(e)],
                }
            )
            return  # _output_json raises, but be explicit
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
    except Exception as e:
        if output_json:
            _output_json(
                {
                    "command": "pack",
                    "status": "error",
                    "trace_id": trace_id,
                    "errors": [str(e)],
                }
            )
            return  # _output_json raises, but be explicit
        console.print(f"[red]Unexpected error:[/] {e}")
        raise typer.Exit(1)

    # JSON output mode - emit and exit
    if output_json:
        _output_json(
            {
                "command": "pack",
                "status": "ok",
                "trace_id": trace_id,
                "output_path": str(result_path),
                "include_source": include_source,
                "forensic_mode": forensic,
            }
        )
        return  # _output_json raises, but be explicit

    # Console output mode
    console.print(f"[green bold]Evidence pack created:[/] {result_path}")
    console.print(f"\n[dim]Trace: {trace_id}[/]")
    console.print(f"[dim]Source files: {include_source}, Forensic mode: {forensic}[/]")


@assay_app.command("launch-check", hidden=True)
def launch_check(
    emit: bool = typer.Option(
        False, "--emit", help="Persist LaunchReadinessReceipt to disk"
    ),
    artifacts_dir: Optional[str] = typer.Option(
        None, "--artifacts-dir", help="Directory for stdout/stderr captures"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    timeout: int = typer.Option(120, "--timeout", help="Per-check timeout in seconds"),
):
    """
    Run verification suite and emit LaunchReadinessReceipt.

    Checks each component and captures pass/fail + artifact hashes:
    - assay --help (CLI installed)
    - assay demo (creates trace)
    - assay validate (Guardian rules work)
    - assay health (health checks work)
    - pytest tests/assay/ (unit tests pass)
    - pytest tests/receipts/test_patent_receipts.py (patent tests pass)
    - Evidence pack generation (from demo trace)

    Exit codes:
    - 0: All checks passed
    - 1: Execution error
    - 2: One or more checks failed

    Examples:
        assay launch-check
        assay launch-check --emit
        assay launch-check --json
        assay launch-check --artifacts-dir ./artifacts
    """
    import hashlib
    import os
    import subprocess
    import time
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path

    from rich.table import Table

    # Set up artifacts directory
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    if artifacts_dir:
        artifact_path = Path(artifacts_dir)
    else:
        artifact_path = (
            Path.home() / ".assay" / "artifacts" / "launch-check" / timestamp
        )
    artifact_path.mkdir(parents=True, exist_ok=True)

    # Get working directory (assay repo root)
    cwd = str(Path(__file__).parent.parent.parent)

    # Import receipt types
    from assay._receipts.domains.launch_readiness import (
        CheckResult,
        create_launch_readiness_receipt,
    )

    checks: List[Dict[str, Any]] = []
    demo_trace_id: Optional[str] = None

    def run_check(
        name: str, cmd: List[str], expect_trace: bool = False
    ) -> Dict[str, Any]:
        """Run a single check and capture results."""
        nonlocal demo_trace_id

        start_time = time.time()
        stdout_file = artifact_path / f"{name}_stdout.txt"
        stderr_file = artifact_path / f"{name}_stderr.txt"

        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(cwd) / "src")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            # Write captures
            stdout_file.write_text(result.stdout)
            stderr_file.write_text(result.stderr)

            # Compute artifact hash
            hash_payload = {
                "cmd": cmd,
                "cwd": cwd,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            artifact_hash = hashlib.sha256(
                json.dumps(hash_payload, sort_keys=True).encode()
            ).hexdigest()

            passed = result.returncode == 0

            # Extract trace_id from demo output if needed
            if expect_trace and passed:
                for line in result.stdout.split("\n"):
                    if "Trace:" in line or "trace_" in line:
                        import re

                        match = re.search(r"trace_\w+", line)
                        if match:
                            demo_trace_id = match.group(0)
                            break

            error_msg = None
            if not passed:
                error_msg = (
                    result.stderr[:500]
                    if result.stderr
                    else f"Exit code {result.returncode}"
                )

            return {
                "name": name,
                "cmd": cmd,
                "cwd": cwd,
                "passed": passed,
                "exit_code": result.returncode,
                "duration_ms": duration_ms,
                "stdout_path": str(stdout_file),
                "stderr_path": str(stderr_file),
                "artifact_hash": artifact_hash,
                "error_message": error_msg,
            }

        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start_time) * 1000)
            return {
                "name": name,
                "cmd": cmd,
                "cwd": cwd,
                "passed": False,
                "exit_code": -1,
                "duration_ms": duration_ms,
                "stdout_path": str(stdout_file),
                "stderr_path": str(stderr_file),
                "artifact_hash": None,
                "error_message": f"Timeout after {timeout}s",
            }
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return {
                "name": name,
                "cmd": cmd,
                "cwd": cwd,
                "passed": False,
                "exit_code": -1,
                "duration_ms": duration_ms,
                "stdout_path": str(stdout_file),
                "stderr_path": str(stderr_file),
                "artifact_hash": None,
                "error_message": str(e)[:500],
            }

    # Run checks
    console.print("[bold]Running launch readiness checks...[/]\n")

    # 1. CLI help
    console.print("  [dim]1/7[/] assay --help")
    checks.append(run_check("assay_help", ["python", "-m", "assay.cli", "--help"]))

    # 2. Demo
    console.print("  [dim]2/7[/] assay demo")
    checks.append(
        run_check(
            "assay_demo", ["python", "-m", "assay.cli", "demo"], expect_trace=True
        )
    )

    # 3. Validate
    console.print("  [dim]3/7[/] assay validate")
    checks.append(
        run_check(
            "assay_validate",
            [
                "python",
                "-m",
                "assay.cli",
                "validate",
                "test action",
                "--coherence",
                "0.8",
                "--dignity",
                "0.7",
                "--receipt",
            ],
        )
    )

    # 4. Health
    console.print("  [dim]4/7[/] assay health")
    checks.append(run_check("assay_health", ["python", "-m", "assay.cli", "health"]))

    # 5. Assay tests
    console.print("  [dim]5/7[/] pytest tests/assay/")
    checks.append(
        run_check(
            "assay_tests",
            ["python", "-m", "pytest", "tests/assay/", "-v", "--tb=short"],
        )
    )

    # 6. Patent receipt tests
    console.print("  [dim]6/7[/] pytest tests/receipts/test_patent_receipts.py")
    checks.append(
        run_check(
            "patent_tests",
            [
                "python",
                "-m",
                "pytest",
                "tests/receipts/test_patent_receipts.py",
                "-v",
                "--tb=short",
            ],
        )
    )

    # 7. Evidence pack (only if demo succeeded and we have a trace_id)
    console.print("  [dim]7/7[/] evidence pack generation")
    if demo_trace_id:
        pack_output = artifact_path / f"evidence_pack_{demo_trace_id}.zip"
        checks.append(
            run_check(
                "evidence_pack",
                [
                    "python",
                    "-m",
                    "assay.cli",
                    "pack",
                    demo_trace_id,
                    "-o",
                    str(pack_output),
                ],
            )
        )
    else:
        checks.append(
            {
                "name": "evidence_pack",
                "cmd": ["assay", "pack", "<trace_id>"],
                "cwd": cwd,
                "passed": False,
                "exit_code": -1,
                "duration_ms": 0,
                "stdout_path": None,
                "stderr_path": None,
                "artifact_hash": None,
                "error_message": "Skipped: no trace_id from demo",
            }
        )

    console.print()

    # Create check result objects
    check_results = []
    for c in checks:
        check_results.append(
            CheckResult(
                receipt_id=f"chk_{uuid.uuid4().hex[:12]}",
                name=c["name"],
                cmd=c["cmd"],
                cwd=c["cwd"],
                passed=c["passed"],
                exit_code=c["exit_code"],
                duration_ms=c["duration_ms"],
                stdout_path=c.get("stdout_path"),
                stderr_path=c.get("stderr_path"),
                artifact_hash=c.get("artifact_hash"),
                error_message=c.get("error_message"),
            )
        )

    # Create receipt
    receipt = create_launch_readiness_receipt(
        checks=check_results,
        artifacts_dir=str(artifact_path),
    )

    # Emit if requested
    receipt_path = None
    if emit:
        emit_dir = Path.home() / ".assay" / "launch" / timestamp
        emit_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = emit_dir / "LaunchReadinessReceipt.json"
        receipt_path.write_text(
            json.dumps(receipt.model_dump(mode="json"), indent=2, default=str)
        )

    # JSON output
    if output_json:
        result_data = {
            "command": "launch-check",
            "status": "ok" if receipt.overall_passed else "failed",
            "overall_passed": receipt.overall_passed,
            "component_summary": {
                "total": receipt.component_summary.total,
                "passed": receipt.component_summary.passed,
                "failed": receipt.component_summary.failed,
            },
            "checks": [c.model_dump(mode="json") for c in check_results],
            "system_fingerprint": receipt.system_fingerprint.model_dump(mode="json"),
            "artifacts_dir": str(artifact_path),
        }
        if receipt_path:
            result_data["receipt_path"] = str(receipt_path)
        _output_json(result_data, exit_code=0 if receipt.overall_passed else 2)
        return

    # Console output - Rich table
    table = Table(
        title="Launch Readiness Checks", show_header=True, header_style="bold"
    )
    table.add_column("Check", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Details")

    for c in check_results:
        status = "[green]PASS[/]" if c.passed else "[red]FAIL[/]"
        duration = f"{c.duration_ms}ms"
        details = (
            c.error_message[:50] + "..."
            if c.error_message and len(c.error_message) > 50
            else (c.error_message or "")
        )
        table.add_row(c.name, status, duration, details)

    console.print(table)
    console.print()

    # Summary
    summary = receipt.component_summary
    if receipt.overall_passed:
        console.print(
            f"[green bold]LAUNCH READINESS: PASSED[/] ({summary.passed}/{summary.total} checks)"
        )
    else:
        console.print(
            f"[red bold]LAUNCH READINESS: FAILED[/] ({summary.failed}/{summary.total} checks failed)"
        )

    # Fingerprint
    fp = receipt.system_fingerprint
    console.print(f"\n[dim]Platform: {fp.platform}[/]")
    console.print(f"[dim]Python: {fp.python_version}[/]")
    if fp.git_commit:
        dirty = " (dirty)" if fp.git_dirty else ""
        console.print(f"[dim]Git: {fp.git_commit}{dirty}[/]")

    console.print(f"\n[dim]Artifacts: {artifact_path}[/]")

    if receipt_path:
        console.print(f"[dim]Receipt: {receipt_path}[/]")
        console.print(
            f"\n[bold]LAUNCH_READINESS: {'PASSED' if receipt.overall_passed else 'FAILED'} path={receipt_path} receipt_id={receipt.receipt_id}[/]"
        )

    if not receipt.overall_passed:
        raise typer.Exit(2)


# --- Start Here commands registered first so panel appears at top of --help ---
# The actual implementations are below; this forward declaration just claims
# panel ordering in Typer's registration-order layout.
_TRY_PANEL = "Start Here"


@assay_app.command("try", rich_help_panel=_TRY_PANEL)
def try_cmd(
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """See what Assay does in 15 seconds.

    Builds a proof pack, verifies it, tampers with one byte,
    and verifies again. One command. No setup.

    Examples:
      pip install assay-ai
      assay try
    """
    import shutil
    import tempfile
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec
    from assay.integrity import verify_pack_manifest
    from assay.keystore import AssayKeyStore
    from assay.proof_pack import ProofPack

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        ks = AssayKeyStore(keys_dir=td / "keys")
        ks.generate_key("try-demo")

        receipts = [
            {
                "receipt_id": "r_try_001",
                "type": "model_call",
                "timestamp": "2026-03-08T12:00:00Z",
                "schema_version": "3.0",
                "seq": 0,
                "model_id": "gpt-4o",
                "provider": "openai",
                "total_tokens": 2400,
                "input_tokens": 1700,
                "output_tokens": 700,
                "latency_ms": 980,
                "finish_reason": "stop",
            },
            {
                "receipt_id": "r_try_002",
                "type": "guardian_verdict",
                "timestamp": "2026-03-08T12:00:01Z",
                "schema_version": "3.0",
                "seq": 1,
                "verdict": "allow",
                "action": "generate_report",
                "reason": "Content within policy bounds",
            },
        ]

        claims = [
            ClaimSpec(
                claim_id="model_called",
                description="At least one model_call receipt",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
            ClaimSpec(
                claim_id="guardian_ran",
                description="Guardian verdict was issued",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]

        pack = ProofPack(
            run_id="try-demo-run",
            entries=receipts,
            signer_id="try-demo",
            claims=claims,
            mode="shadow",
        )
        pack_dir = pack.build(td / "pack", keystore=ks)

        # Verify the good pack
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        att = manifest["attestation"]
        good_result = verify_pack_manifest(manifest, pack_dir, ks)

        # Create tampered copy
        tampered_dir = td / "tampered"
        shutil.copytree(pack_dir, tampered_dir)
        receipt_file = tampered_dir / "receipt_pack.jsonl"
        data = bytearray(receipt_file.read_bytes())
        target = b'"gpt-4o"'
        idx = data.find(target)
        if idx >= 0:
            data[idx + 1 : idx + 6] = b"gpt-5x"
        receipt_file.write_bytes(bytes(data))

        tampered_manifest = json.loads(
            (tampered_dir / "pack_manifest.json").read_text()
        )
        tampered_result = verify_pack_manifest(tampered_manifest, tampered_dir, ks)

    good_pass = good_result.passed
    tampered_pass = tampered_result.passed
    tampered_err = (
        tampered_result.errors[0].message if tampered_result.errors else "unknown"
    )

    if output_json:
        _output_json(
            {
                "command": "try",
                "status": "ok",
                "good_result": "PASS" if good_pass else "FAIL",
                "tampered_result": "PASS" if tampered_pass else "FAIL",
                "tampered_error": tampered_err,
                "receipts": len(receipts),
                "claims": len(claims),
            }
        )
        return

    console.print()
    console.print("[bold]assay try[/] - see what Assay does")
    console.print()

    # Step 1: good pack
    console.print(
        "  [bold]1.[/] Built a proof pack (2 receipts, 2 claims, Ed25519 signed)"
    )
    if good_pass:
        console.print("  [bold]2.[/] Verified it: [bold green]PASS[/]")
    else:
        console.print("  [bold]2.[/] Verified it: [bold red]FAIL[/]")

    console.print()

    # Step 2: tamper
    console.print("  [bold]3.[/] Changed one byte ([dim]gpt-4o -> gpt-5x[/])")
    if not tampered_pass:
        console.print(
            f"  [bold]4.[/] Verified again: [bold red]FAIL[/] - {tampered_err}"
        )
    else:
        console.print("  [bold]4.[/] Verified again: [bold green]PASS[/] (unexpected)")

    console.print()
    console.print("[bold]What happened:[/]")
    console.print("  Assay hashes every receipt and signs the pack.")
    console.print("  One changed byte breaks the chain. No server needed.")
    console.print()
    console.print("[bold]Next:[/]")
    console.print("  Set up Assay in your project:")
    console.print("    [bold]assay start[/]")
    console.print()
    console.print(
        "  [dim]Need a reviewer-ready artifact instead? See assay vendorq --help[/]"
    )


@assay_app.command("try-mcp", rich_help_panel=_TRY_PANEL)
def try_mcp_cmd(
    output_dir: str = typer.Option(
        "./assay_mcp_demo", "-o", "--output", help="Output directory for the proof pack"
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """See MCP tool-call auditing in 30 seconds.

    Starts a synthetic MCP tool server, wraps it with the Assay proxy,
    sends 3 tool calls, and produces a signed proof pack you can verify.
    One command. No API key. No setup.

    Examples:
      assay try-mcp
      assay verify-pack ./assay_mcp_demo/proof_pack/
    """
    import shutil
    import signal
    import subprocess
    import sys
    import tempfile
    import textwrap
    import threading
    import time
    from pathlib import Path

    out_path = Path(output_dir)

    # --- Inline demo server script ---
    demo_server_src = textwrap.dedent("""\
        import json, sys
        TOOLS = [
            {"name": "get_weather", "description": "Get current weather",
             "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}},
            {"name": "check_inventory", "description": "Check product stock",
             "inputSchema": {"type": "object", "properties": {"product_id": {"type": "string"}}, "required": ["product_id"]}},
            {"name": "calculate_risk", "description": "Calculate risk score",
             "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}, "category": {"type": "string"}}, "required": ["amount"]}},
        ]
        RESULTS = {
            "get_weather": lambda a: f"72F, Partly Cloudy in {a.get('city', '?')}",
            "check_inventory": lambda a: json.dumps({"product_id": a.get("product_id", "?"), "in_stock": 142, "warehouse": "US-WEST-2"}),
            "calculate_risk": lambda a: json.dumps({"score": 0.23, "level": "low", "amount": a.get("amount", 0)}),
        }
        def handle(msg):
            method, rid, params = msg.get("method"), msg.get("id"), msg.get("params", {})
            if method == "initialize":
                return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "assay-try-mcp-demo", "version": "0.1.0"}}}
            if method == "notifications/initialized": return None
            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
            if method == "tools/call":
                fn = RESULTS.get(params.get("name", ""))
                if fn: return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": fn(params.get("arguments", {}))}], "isError": False}}
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown tool: {params.get('name')}"}}
            if rid: return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
        for line in sys.stdin:
            line = line.strip()
            if not line: continue
            try: msg = json.loads(line)
            except: continue
            r = handle(msg)
            if r: sys.stdout.write(json.dumps(r) + "\\n"); sys.stdout.flush()
    """)

    # JSON-RPC requests: initialize, then 3 tool calls
    requests = [
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "assay-try-mcp", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}},
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 3,
            "params": {"name": "get_weather", "arguments": {"city": "Seattle"}},
        },
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 4,
            "params": {
                "name": "check_inventory",
                "arguments": {"product_id": "SKU-7291"},
            },
        },
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 5,
            "params": {
                "name": "calculate_risk",
                "arguments": {"amount": 15000, "category": "international_transfer"},
            },
        },
    ]

    tool_calls = [r for r in requests if r.get("method") == "tools/call"]

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        server_script = td / "demo_server.py"
        server_script.write_text(demo_server_src)
        audit_dir = td / "mcp_audit"

        if not output_json:
            console.print()
            console.print(
                "[bold]assay try-mcp[/] — MCP tool-call auditing in 30 seconds"
            )
            console.print()
            console.print("  [dim]Starting synthetic MCP tool server...[/]")

        # Start proxy wrapping the demo server
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "assay",
                "mcp-proxy",
                "--audit-dir",
                str(audit_dir),
                "--store-args",
                "--store-results",
                "--server-id",
                "try-mcp-demo",
                "--",
                sys.executable,
                str(server_script),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(td),
        )

        # Drain stdout/stderr to prevent pipe deadlock
        stdout_buf, stderr_buf = [], []

        def drain(pipe, buf):
            for line in pipe:
                buf.append(line)

        t_out = threading.Thread(
            target=drain, args=(proc.stdout, stdout_buf), daemon=True
        )
        t_err = threading.Thread(
            target=drain, args=(proc.stderr, stderr_buf), daemon=True
        )
        t_out.start()
        t_err.start()

        # Send requests with small delays
        for i, req in enumerate(requests):
            proc.stdin.write((json.dumps(req) + "\n").encode())
            proc.stdin.flush()
            if req.get("method") == "tools/call" and not output_json:
                call_idx = sum(
                    1 for r in requests[: i + 1] if r.get("method") == "tools/call"
                )
                name = req["params"]["name"]
                args_str = json.dumps(req["params"]["arguments"])
                console.print(
                    f"  [bold]{call_idx}.[/] {name}({args_str}) [green]→ receipted[/]"
                )
            time.sleep(0.3)

        # Close stdin to signal session end
        proc.stdin.close()

        # Wait for proxy shutdown + pack build
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        # Find the built pack
        packs_dir = audit_dir / "packs"
        built_pack = None
        if packs_dir.exists():
            pack_dirs = sorted(packs_dir.iterdir())
            if pack_dirs:
                built_pack = pack_dirs[-1]

        if not built_pack or not built_pack.is_dir():
            if output_json:
                _output_json(
                    {
                        "command": "try-mcp",
                        "status": "error",
                        "error": "no_pack_produced",
                    },
                    exit_code=1,
                )
            else:
                console.print(
                    "\n  [red]Error:[/] No proof pack produced. Proxy may have failed."
                )
                stderr_text = b"".join(stderr_buf).decode(errors="replace").strip()
                if stderr_text:
                    for line in stderr_text.splitlines()[-3:]:
                        console.print(f"    [dim]{line.strip()}[/]")
            raise typer.Exit(1)

        # Copy pack to output directory
        pack_dest = out_path / "proof_pack"
        if pack_dest.exists():
            shutil.rmtree(pack_dest)
        out_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(built_pack, pack_dest)

    # Verify the pack

    manifest_path = pack_dest / "pack_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    att = manifest.get("attestation", {})
    pack_id = att.get("pack_id", "unknown")
    receipt_count = att.get("n_receipts", att.get("receipt_count", 0))

    # Verify (use default keystore which has the assay-local key)
    verify_result = subprocess.run(
        [sys.executable, "-m", "assay", "verify-pack", str(pack_dest), "--json"],
        capture_output=True,
        text=True,
    )
    verify_passed = verify_result.returncode == 0

    if output_json:
        verify_data = {}
        if verify_result.stdout.strip().startswith("{"):
            verify_data = json.loads(verify_result.stdout)
        _output_json(
            {
                "command": "try-mcp",
                "status": "ok" if verify_passed else "error",
                "pack_id": pack_id,
                "receipts": receipt_count,
                "tool_calls": len(tool_calls),
                "verification": "PASS" if verify_passed else "FAIL",
                "pack_dir": str(pack_dest),
                "verify_exit_code": verify_result.returncode,
            }
        )
        return

    console.print()

    if verify_passed:
        console.print(
            Panel(
                f"[bold]Pack ID:[/]    {pack_id}\n"
                f"[bold]Integrity:[/]  [bold green]PASS[/]\n"
                f"[bold]Receipts:[/]   {receipt_count}\n"
                f"[bold]Tool calls:[/] {len(tool_calls)} (get_weather, check_inventory, calculate_risk)\n"
                f"[bold]Output:[/]     {pack_dest}",
                title="[bold green]MCP Proof Pack Built & Verified[/]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"Pack built but verification returned exit {verify_result.returncode}.\n"
                f"Pack at: {pack_dest}",
                title="[bold red]Verification Issue[/]",
                border_style="red",
            )
        )

    console.print()
    console.print("[bold]What happened:[/]")
    console.print("  Assay proxied 3 MCP tool calls through a synthetic server.")
    console.print(
        "  Each call was receipted. The session was signed into a proof pack."
    )
    console.print("  The pack is offline-verifiable — no server, no trust required.")
    console.print()
    console.print("[bold]Verify it yourself:[/]")
    console.print(f"  [green]$ assay verify-pack {pack_dest}[/]")
    console.print()
    console.print("[bold]Next:[/]")
    console.print("  Wrap your own MCP server:")
    console.print("    [green]$ assay mcp-proxy -- python my_server.py[/]")
    console.print()
    console.print("  Add a policy file:")
    console.print("    [green]$ assay mcp policy init[/]")
    console.print(
        "    [green]$ assay mcp-proxy --policy assay.mcp-policy.yaml -- python my_server.py[/]"
    )


@assay_app.command("try-openclaw", rich_help_panel=_TRY_PANEL)
def try_openclaw_cmd(
    output_dir: str = typer.Option(
        "./assay_openclaw_demo",
        "-o",
        "--output",
        help="Output directory for the demo artifacts and proof pack",
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """See the OpenClaw membrane posture with a deterministic proof path.

    Produces:
    - one allowed public web fetch through the subprocess membrane
    - one denied localhost fetch blocked by policy
    - one imported OpenClaw session-log event
    - one blocked sensitive browser action via the receipt adapter
    - one signed proof pack built from the projected evidence

    The demo uses deterministic synthetic OpenClaw responses so it survives on a
    clean machine without a live OpenClaw install.
    """
    from pathlib import Path

    from assay.openclaw_demo import run_openclaw_demo

    out_path = Path(output_dir)

    if not output_json:
        console.print()
        console.print(
            "[bold]assay try-openclaw[/] — OpenClaw membrane demo with offline verification"
        )
        console.print()
        console.print(
            "  [dim]Uses deterministic synthetic OpenClaw responses; no live OpenClaw process required.[/]"
        )
        console.print("  [bold]1.[/] Allowed public web fetch [green]→ receipted[/]")
        console.print("  [bold]2.[/] Blocked localhost fetch [yellow]→ denied[/]")
        console.print(
            "  [bold]3.[/] Imported session-log browser event [green]→ receipted[/]"
        )
        console.print(
            "  [bold]4.[/] Blocked sensitive browser action [yellow]→ blocked[/]"
        )

    result = run_openclaw_demo(out_path)

    if output_json:
        _output_json(
            {
                "command": "try-openclaw",
                "status": "ok" if result.verification_passed else "error",
                "pack_dir": str(result.pack_dir),
                "session_log": str(result.session_log_path),
                "summary": str(result.summary_path),
                "projected_receipts": len(result.projected_entries),
                "imported_events": result.import_report.imported_count,
                "skipped_import_entries": result.import_report.skipped_count,
                "import_status": result.import_report.completeness,
                "import_total_lines": result.import_report.total_lines,
                "import_blank_lines": result.import_report.blank_lines,
                "verification": "PASS" if result.verification_passed else "FAIL",
                "errors": result.verification_errors,
            }
        )
        return

    console.print()
    if result.verification_passed:
        console.print(
            Panel(
                f"[bold]Integrity:[/]  [bold green]PASS[/]\n"
                f"[bold]Receipts:[/]   {len(result.projected_entries)} projected evidence entries\n"
                f"[bold]Imported:[/]   {result.import_report.imported_count} session-log entries ({result.import_report.skipped_count} skipped, {result.import_report.completeness})\n"
                f"[bold]Pack:[/]       {result.pack_dir}\n"
                f"[bold]Session log:[/] {result.session_log_path}\n"
                f"[bold]Summary:[/]    {result.summary_path}",
                title="[bold green]OpenClaw Demo Pack Built & Verified[/]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"Pack built but verification failed.\nPack: {result.pack_dir}",
                title="[bold red]OpenClaw Demo Verification Failed[/]",
                border_style="red",
            )
        )
        for error in result.verification_errors:
            console.print(f"  [red]-[/] {error.get('message', error)}")

    console.print()
    console.print("[bold]Verify it yourself:[/]")
    console.print(f"  [green]$ assay verify-pack {result.pack_dir}[/]")
    console.print()
    console.print(
        "[bold]Proof boundary:[/] The proof pack covers the projected evidence entries."
    )
    console.print(
        "[bold]Raw artifacts:[/] The bridge JSON artifacts and exported session log stay beside the pack for inspection."
    )


# --- End of early Start Here registration ---


@assay_app.command("version", rich_help_panel="Operate")
def show_version(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show Assay version and configuration."""
    from assay import __version__
    from assay.store import get_default_store

    store = get_default_store()

    if output_json:
        _output_json(
            {
                "command": "version",
                "status": "ok",
                "version": __version__,
                "storage_dir": str(store.base_dir),
                "components": {
                    "guardian_rules": [
                        "no_coherence_by_dignity_debt",
                        "no_action_without_receipt",
                    ],
                    "health_checks": ["grace_window"],
                    "blockage_receipts": ["incompleteness", "contradiction", "paradox"],
                },
            }
        )

    console.print(f"[bold]Assay {__version__}[/]")
    console.print("AI evidence that's harder to fake and easier to verify")
    console.print()
    console.print("Capabilities:")
    console.print("  - Scan: find uninstrumented LLM call sites")
    console.print("  - Instrument: OpenAI, Anthropic, LangChain (2 lines)")
    console.print("  - Proof packs: receipts + manifest + Ed25519 signature")
    console.print(
        "  - Verify: exit 0/1/2/3 (pass / honest failure / tampered / bad input)"
    )
    console.print()
    console.print(f"Storage: {store.base_dir}")

    # Non-blocking update hint — delegates to shared helper in _update.py
    try:
        from assay._update import check_for_update

        update = check_for_update(timeout=2.0)
        if update.available:
            console.print()
            console.print(f"[yellow]{update.message}[/]")
            console.print(f"[dim]  {update.update_command}[/]")
    except Exception:
        pass


@assay_app.command("status", hidden=True, rich_help_panel="Measure")
def status_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """One-screen operational dashboard: is Assay ready here?"""
    from datetime import datetime, timezone
    from pathlib import Path

    from assay import __version__
    from assay.keystore import AssayKeyStore
    from assay.store import get_default_store

    store = get_default_store()
    ks = AssayKeyStore()

    checks: dict = {}

    # 1. Version
    checks["version"] = __version__

    # 2. Key status
    try:
        signer = ks.get_active_signer()
        has_key = ks.has_key(signer)
        fp = ks.signer_fingerprint(signer)[:16] + "..." if has_key else None
        n_signers = len(ks.list_signers())
        checks["key"] = {
            "signer": signer,
            "has_key": has_key,
            "fingerprint": fp,
            "total_signers": n_signers,
        }
    except Exception:
        checks["key"] = {
            "signer": None,
            "has_key": False,
            "fingerprint": None,
            "total_signers": 0,
        }

    # 3. Store
    receipt_count = 0
    trace_count = 0
    store_dir = store.base_dir
    if store_dir.exists():
        for day_dir in store_dir.iterdir():
            if day_dir.is_dir() and len(day_dir.name) == 10:  # YYYY-MM-DD
                for f in day_dir.glob("*.jsonl"):
                    trace_count += 1
                    try:
                        receipt_count += sum(1 for _ in open(f))
                    except Exception:
                        pass
    checks["store"] = {
        "path": str(store_dir),
        "traces": trace_count,
        "receipts": receipt_count,
    }

    # 4. Lockfile
    lockfile = Path("assay.lock")
    checks["lockfile"] = {
        "present": lockfile.exists(),
        "path": str(lockfile) if lockfile.exists() else None,
    }
    if lockfile.exists():
        try:
            import json as _json

            lock_data = _json.loads(lockfile.read_text())
            checks["lockfile"]["lock_version"] = lock_data.get("lock_version")
            checks["lockfile"]["cards"] = list(lock_data.get("run_cards", {}).keys())
        except Exception:
            checks["lockfile"]["valid"] = False

    # 5. Latest pack
    cwd_packs = sorted(
        [
            d
            for d in Path(".").iterdir()
            if d.is_dir()
            and d.name.startswith("proof_pack")
            and (d / "pack_manifest.json").exists()
        ],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    if cwd_packs:
        latest = cwd_packs[0]
        try:
            import json as _json

            manifest = _json.loads((latest / "pack_manifest.json").read_text())
            mtime = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)
            age_secs = (datetime.now(timezone.utc) - mtime).total_seconds()
            if age_secs < 3600:
                age_str = f"{int(age_secs // 60)}m ago"
            elif age_secs < 86400:
                age_str = f"{int(age_secs // 3600)}h ago"
            else:
                age_str = f"{int(age_secs // 86400)}d ago"
            checks["latest_pack"] = {
                "path": str(latest),
                "pack_id": manifest.get("pack_id", "?"),
                "receipts": manifest.get("receipt_count_expected", "?"),
                "age": age_str,
            }
        except Exception:
            checks["latest_pack"] = {
                "path": str(latest),
                "pack_id": "?",
                "receipts": "?",
                "age": "?",
            }
    else:
        checks["latest_pack"] = None

    # 6. MCP proxy
    checks["mcp_proxy"] = {"available": True}  # command is wired if we got here

    if output_json:
        _output_json({"command": "status", **checks})
        return

    # Render dashboard
    console.print()
    table = Table(show_header=False, border_style="dim", pad_edge=False, box=None)
    table.add_column("label", style="bold", width=14)
    table.add_column("value")

    # Version
    table.add_row("Version", f"{__version__}")

    # Key
    key = checks["key"]
    if key["has_key"]:
        key_str = f"{key['signer']} ({key['fingerprint']})"
        if key["total_signers"] > 1:
            key_str += f"  [{key['total_signers']} keys total]"
        table.add_row("Signer", key_str)
    else:
        table.add_row("Signer", "[yellow]no key found[/]")

    # Store
    s = checks["store"]
    if s["receipts"] > 0:
        table.add_row("Store", f"{s['receipts']} receipts across {s['traces']} traces")
    else:
        table.add_row("Store", "[dim]empty[/]")

    # Lockfile
    lf = checks["lockfile"]
    if lf["present"]:
        cards_str = ", ".join(lf.get("cards", []))
        table.add_row("Lockfile", f"assay.lock ({cards_str})")
    else:
        table.add_row("Lockfile", "[dim]none in cwd[/]")

    # Latest pack
    lp = checks["latest_pack"]
    if lp:
        table.add_row(
            "Latest pack", f"{lp['path']}  ({lp['receipts']} receipts, {lp['age']})"
        )
    else:
        table.add_row("Latest pack", "[dim]none in cwd[/]")

    # MCP proxy
    table.add_row("MCP proxy", "ready")

    console.print(Panel(table, title="assay status", border_style="blue"))

    # Overall verdict
    ok = key["has_key"]
    if ok:
        console.print(
            "\n  [green]OPERATIONAL[/]  Ready to produce and verify evidence.\n"
        )
    else:
        console.print("\n  [yellow]SETUP NEEDED[/]  Run: assay quickstart\n")


@assay_app.command("score", rich_help_panel="Measure")
def score_cmd(
    path: str = typer.Argument(".", help="Repository directory to score"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compute an Evidence Readiness Score (0-100, A-F) for a repository.

    Use this to diagnose your repo's evidence quality. Shows a component
    breakdown with point estimates and specific commands to improve your score.

    For CI enforcement, use `assay gate check` instead.

    Assay works standalone -- no other tools required. Just `python3 -m pip install assay-ai`.
    """
    from pathlib import Path as P

    from assay.score import compute_evidence_readiness_score, gather_score_facts

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "score",
                    "status": "error",
                    "error": f"Directory not found: {path}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] Directory not found: {path}")
        raise typer.Exit(3)

    try:
        facts = gather_score_facts(root)
        score = compute_evidence_readiness_score(facts)
    except Exception as e:
        if output_json:
            _output_json(
                {
                    "command": "score",
                    "status": "error",
                    "error": str(e),
                },
                exit_code=2,
            )
        console.print(f"[red]Score error:[/] {e}")
        raise typer.Exit(2)

    if output_json:
        _output_json(
            {
                "command": "score",
                "status": "ok",
                "repo_path": str(root),
                **score,
                "facts": {
                    "scan": facts["scan"],
                    "lockfile": facts["lockfile"],
                    "ci": facts["ci"],
                    "receipts": facts["receipts"],
                    "keys": facts["keys"],
                },
            }
        )
        return

    console.print()
    grade_style = {
        "A": "green",
        "B": "green",
        "C": "yellow",
        "D": "yellow",
        "F": "red",
    }.get(score["grade"], "white")

    grade_desc = score.get("grade_description", "")
    desc_line = f'\n         [dim]"{grade_desc}"[/]' if grade_desc else ""

    header = (
        f"[bold]Evidence Readiness Score[/]\n\n"
        f"Repo:    {root}\n"
        f"Score:   [bold]{score['score']:.1f}[/] / 100\n"
        f"Grade:   [{grade_style}][bold]{score['grade']}[/]{desc_line}\n"
        f"Version: {score['score_version']}"
    )
    console.print(Panel.fit(header, title="assay score", border_style="blue"))

    # Build a lookup from component -> action detail for inline hints.
    action_by_comp: dict = {}
    for ad in score.get("next_actions_detail", []):
        if ad.get("component"):
            action_by_comp.setdefault(ad["component"], ad)

    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Component")
    table.add_column("Points", justify="right")
    table.add_column("Weight", justify="right")
    table.add_column("Status")
    table.add_column("Note")
    for key in ("coverage", "lockfile", "ci_gate", "receipts", "key_setup"):
        comp = score["breakdown"][key]
        note = comp["note"]
        ad = action_by_comp.get(key)
        if ad and ad["points_est"] > 0:
            note += f" [dim]→ {ad['command']} (+{ad['points_est']:.0f} pts est.)[/]"
        table.add_row(
            key,
            f"{comp['points']:.1f}",
            str(comp["weight"]),
            comp["status"],
            note,
        )
    console.print(table)

    if score["caps_applied"]:
        caps_lines = []
        for cap in score["caps_applied"]:
            caps_lines.append(
                f"- {cap['id']}: {cap['reason']} ({cap['before']['grade']} -> {cap['after']['grade']})"
            )
        console.print(
            Panel("\n".join(caps_lines), title="Caps Applied", border_style="yellow")
        )

    fp = score.get("fastest_path")
    if fp:
        console.print(
            f"\n[bold]Fastest path to {fp['target_grade']} ({fp['target_score']}+):[/] "
            f"{fp['command']} [dim](+{fp['points_est']:.0f} → ~{fp['projected_score']:.0f})[/]"
        )

    console.print("\n[bold]Next actions:[/]")
    for idx, ad in enumerate(score.get("next_actions_detail", []), 1):
        pts = (
            f" [dim](+{ad['points_est']:.0f} pts est.)[/]"
            if ad["points_est"] > 0
            else ""
        )
        console.print(f"  {idx}. {ad['action']}: {ad['command']}{pts}")

    console.print(f"\n[dim]{score['disclaimer']}[/]\n")


# ---------------------------------------------------------------------------
# assay report -- unified evidence readiness report
# ---------------------------------------------------------------------------


@assay_app.command("report", hidden=True, rich_help_panel="Measure")
def report_cmd(
    path: str = typer.Argument(".", help="Repository directory to report on"),
    output_path: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output path (default: evidence_report.html)"
    ),
    sarif: bool = typer.Option(
        False, "--sarif", help="Emit SARIF file for GitHub Code Scanning"
    ),
    sarif_path: Optional[str] = typer.Option(
        None, "--sarif-path", help="SARIF output path (default: evidence_report.sarif)"
    ),
    markdown: bool = typer.Option(
        False, "--markdown", "--md", help="Also emit markdown summary"
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Output report data as JSON"
    ),
):
    """Generate a unified Evidence Readiness Report (HTML + optional SARIF/markdown).

    Combines score card, evidence gap map, CI gate status, and next actions
    into a single self-contained HTML file with what-if simulator, content
    hash verification, and print-ready styles.

    Use --sarif to emit a SARIF 2.1.0 file for GitHub Code Scanning.
    Use --markdown to emit a condensed summary for $GITHUB_STEP_SUMMARY.
    """
    from pathlib import Path as P

    from assay.reporting.score_report import (
        build_score_report,
        render_html,
        render_markdown,
        render_sarif,
        write_json,
        write_markdown,
        write_report,
        write_sarif,
    )
    from assay.score import compute_evidence_readiness_score, gather_score_facts

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "report",
                    "status": "error",
                    "error": f"Directory not found: {path}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] Directory not found: {path}")
        raise typer.Exit(3)

    try:
        facts = gather_score_facts(root)
        score_data = compute_evidence_readiness_score(facts)
    except Exception as e:
        if output_json:
            _output_json(
                {"command": "report", "status": "error", "error": str(e)},
                exit_code=2,
            )
        console.print(f"[red]Report error:[/] {e}")
        raise typer.Exit(2)

    report = build_score_report(facts, score_data, root)

    # JSON to stdout
    if output_json:
        _output_json(
            {
                "command": "report",
                "status": "ok",
                "repo_path": str(root),
                "content_hash": report.content_hash,
                **score_data,
                "facts": facts,
            }
        )
        return

    # HTML
    html_path = P(output_path) if output_path else P("evidence_report.html")
    html = render_html(report)
    write_report(html, html_path)

    # JSON sidecar
    json_path = html_path.with_suffix(".json")
    write_json(report, json_path)

    # SARIF
    if sarif or sarif_path:
        sp = P(sarif_path) if sarif_path else html_path.with_suffix(".sarif")
        sarif_data = render_sarif(report)
        write_sarif(sarif_data, sp)
        console.print(f"  SARIF: {sp}")

    # Markdown
    if markdown:
        md_path = html_path.with_suffix(".md")
        md = render_markdown(report)
        write_markdown(md, md_path)
        console.print(f"  Markdown: {md_path}")

    console.print(
        f"Report written: {html_path} "
        f"(Grade: {score_data['grade']}, Score: {score_data['score']:.1f})"
    )


@assay_app.command("output-assay", rich_help_panel="Operate")
def output_assay_cmd(
    artifact_path: str = typer.Argument(..., help="Artifact text file to assay"),
    draft_path: str = typer.Option(
        ..., "--draft", help="Path to explicit Output Assay draft JSON"
    ),
    output_path: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write rendered output to a file instead of stdout",
    ),
    output_format: str = typer.Option(
        "report",
        "--format",
        help="Output format: report or json",
        case_sensitive=False,
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero on status: block or extraction_failure",
    ),
):
    """Render a local Output Assay report from artifact text and explicit draft JSON.

    This command stays provider-neutral: it reads artifact text plus an explicit
    draft payload, runs the local Output Assay pipeline, and renders either a
    deterministic Markdown report or structured JSON.
    """
    from pathlib import Path as P

    from assay.output_assay import run_output_assay_locally
    from assay.output_assay.report import (
        OutputAssayFailOn,
        OutputAssayReportFormat,
        render_output_assay_report,
        should_fail_output_assay_result,
    )

    try:
        normalized_format = OutputAssayReportFormat(output_format.lower())
    except ValueError:
        console.print(f"[red]Error:[/] Unsupported output format: {output_format}")
        raise typer.Exit(3)

    normalized_fail_on: OutputAssayFailOn | None = None
    if fail_on is not None:
        try:
            normalized_fail_on = OutputAssayFailOn(fail_on.lower())
        except ValueError:
            console.print(f"[red]Error:[/] Unsupported fail-on status: {fail_on}")
            raise typer.Exit(3)

    artifact = P(artifact_path)
    if not artifact.exists() or not artifact.is_file():
        console.print(f"[red]Error:[/] Artifact file not found: {artifact_path}")
        raise typer.Exit(3)

    draft = P(draft_path)
    if not draft.exists() or not draft.is_file():
        console.print(f"[red]Error:[/] Draft file not found: {draft_path}")
        raise typer.Exit(3)

    try:
        artifact_text = artifact.read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Error:[/] Could not read artifact file: {exc}")
        raise typer.Exit(3) from exc

    try:
        payload = json.loads(draft.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/] Draft JSON is invalid: {exc}")
        raise typer.Exit(3) from exc
    except OSError as exc:
        console.print(f"[red]Error:[/] Could not read draft file: {exc}")
        raise typer.Exit(3) from exc

    result = run_output_assay_locally(artifact_text, payload)

    if normalized_format == OutputAssayReportFormat.JSON:
        rendered_output = json.dumps(result.model_dump(mode="json"), indent=2)
    else:
        rendered_output = render_output_assay_report(result)

    if output_path is not None:
        destination = P(output_path)
        try:
            destination.write_text(rendered_output + "\n", encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Error:[/] Could not write output file: {exc}")
            raise typer.Exit(2) from exc
        typer.echo(f"Output Assay {normalized_format.value} written: {destination}")
    else:
        typer.echo(rendered_output)

    if should_fail_output_assay_result(result, normalized_fail_on):
        raise typer.Exit(2)


# ---------------------------------------------------------------------------
# assay start -- guided entrypoints
# ---------------------------------------------------------------------------

start_app = typer.Typer(
    name="start",
    help="Guided setup for your use case",
    no_args_is_help=True,
)
assay_app.add_typer(start_app, name="start", rich_help_panel="Start Here")


@start_app.command("demo")
def start_demo_cmd(
    path: str = typer.Argument(".", help="Project directory"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """See Assay in action: demo pack + scan + next steps.

    Runs the quickstart flow: generates a demo challenge, scans your
    project for uninstrumented call sites, and shows what to do next.
    """
    quickstart_cmd(path=path, skip_demo=False, output_json=output_json, force=False)


@start_app.command("ci")
def start_ci_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Set up CI evidence gating in 3 commands.

    Shows the exact commands to add Assay verification to your CI pipeline:
    run with receipts, verify the pack, lock the contract.
    """
    steps = [
        {
            "step": 1,
            "title": "Instrument your entrypoint",
            "commands": [
                "assay patch .",
                "# Or manually: from assay.integrations.openai import patch; patch()",
            ],
            "note": "Adds receipt emission to your SDK calls (2 lines per SDK).",
        },
        {
            "step": 2,
            "title": "Run with receipts and build a signed pack",
            "commands": [
                "assay run -c receipt_completeness -- python your_app.py",
            ],
            "note": "Wraps your command, collects receipts, builds a 5-file proof pack.",
        },
        {
            "step": 3,
            "title": "Verify the pack",
            "commands": [
                "assay verify-pack ./proof_pack_*/",
            ],
            "note": "Checks integrity + claims. Exit 0=pass, 1=honest failure, 2=tampered.",
        },
        {
            "step": 4,
            "title": "Lock the verification contract",
            "commands": [
                "assay lock init",
            ],
            "note": "Freezes claim set so every CI run uses the same checks.",
        },
        {
            "step": 5,
            "title": "Add to CI workflow",
            "commands": [
                "assay ci init github",
                "# Or add these steps to your existing workflow:",
                "#   assay run -c receipt_completeness -- python your_app.py",
                "#   assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass",
                "#   assay diff ./baseline/ ./proof_pack_*/ --gate-cost-pct 25 --gate-errors 0",
            ],
            "note": "Three commands, three exit codes, one lockfile.",
        },
    ]

    if output_json:
        _output_json({"command": "start ci", "steps": steps})
        return

    console.print()
    console.print("[bold]assay start ci[/]  --  CI evidence gate setup\n")

    for s in steps:
        console.print(f"  [bold cyan]Step {s['step']}:[/] {s['title']}")
        for cmd in s["commands"]:
            if cmd.startswith("#"):
                console.print(f"    [dim]{cmd}[/]")
            else:
                console.print(f"    [green]$ {cmd}[/]")
        console.print(f"    [dim]{s['note']}[/]")
        console.print()

    console.print("  [bold]Daily use after CI is green:[/]")
    console.print("    [green]$ assay diff ./proof_pack_*/ --against-previous --why[/]")
    console.print(
        "    [dim]Auto-discovers baseline, traces regressions to root cause.[/]\n"
    )


@start_app.command("mcp")
def start_mcp_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Set up MCP tool call auditing.

    Shows how to wrap an MCP server with the Assay proxy to get
    tamper-evident receipts for every tool invocation.
    """
    steps = [
        {
            "step": 1,
            "title": "Wrap your MCP server with the proxy",
            "commands": [
                "assay mcp-proxy -- python my_server.py",
                "# Or with server ID for receipt correlation:",
                "assay mcp-proxy --server-id my-server -- python my_server.py",
            ],
            "note": "Sits between client and server. Intercepts tools/call, emits one receipt per invocation.",
        },
        {
            "step": 2,
            "title": "Check session receipts",
            "commands": [
                "ls .assay/mcp/receipts/",
                "# Each session produces a JSONL trace file",
            ],
            "note": "Receipts are privacy-by-default: args and results are SHA-256 hashed, not stored.",
        },
        {
            "step": 3,
            "title": "Store full args/results (opt-in)",
            "commands": [
                "assay mcp-proxy --store-args --store-results -- python my_server.py",
            ],
            "note": "Use when you need full audit trail, not just tamper-evidence.",
        },
        {
            "step": 4,
            "title": "Verify session evidence",
            "commands": [
                "assay verify-pack .assay/mcp/packs/proof_pack_*/",
            ],
            "note": "Auto-pack builds a signed proof pack at clean session end.",
        },
    ]

    if output_json:
        _output_json({"command": "start mcp", "steps": steps})
        return

    console.print()
    console.print("[bold]assay start mcp[/]  --  MCP tool call auditing\n")

    for s in steps:
        console.print(f"  [bold cyan]Step {s['step']}:[/] {s['title']}")
        for cmd in s["commands"]:
            if cmd.startswith("#"):
                console.print(f"    [dim]{cmd}[/]")
            else:
                console.print(f"    [green]$ {cmd}[/]")
        console.print(f"    [dim]{s['note']}[/]")
        console.print()

    console.print("  [bold]What you get:[/]")
    console.print("    - One [cyan]MCPToolCallReceipt[/] per tool invocation")
    console.print("    - Session trace with [cyan]session_complete[/] flag")
    console.print("    - Auto-packed proof pack on clean session end")
    console.print("    - Privacy-by-default (hash-only unless opt-in)\n")


@assay_app.command("proof-pack", rich_help_panel="Build & Verify")
def proof_pack_cmd(
    trace_id: str = typer.Argument(..., help="Trace ID to package"),
    output_dir: str = typer.Option(None, "--output", "-o", help="Output directory"),
    mode: str = typer.Option(
        "shadow", "--mode", "-m", help="Mode: shadow|enforced|breakglass"
    ),
    run_card: Optional[List[str]] = typer.Option(
        None,
        "--run-card",
        "-c",
        help="Run card: builtin name or path to JSON file (repeatable)",
    ),
    emit_v2_receipts: bool = typer.Option(
        False,
        "--emit-v2-receipts",
        help=(
            "Also emit _unsigned/receipt_pack_v2.jsonl: one Ed25519-signed "
            "ReceiptV2 envelope per receipt, each carrying an attested "
            "pack_binding (pack_id, source_index, source_receipt_sha256, "
            "receipt_pack_sha256, pack_root_sha256). Sidecar artifact; the "
            "v1 5-file kernel is unaffected."
        ),
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Build a signed Proof Pack (5-file kernel) from a trace."""
    from pathlib import Path

    from assay.proof_pack import build_proof_pack
    from assay.run_cards import (
        collect_claims_from_cards,
        get_builtin_card,
        load_run_card,
    )

    # Resolve run cards to claims
    claims = None
    if run_card:
        cards = []
        for card_ref in run_card:
            builtin = get_builtin_card(card_ref)
            if builtin:
                cards.append(builtin)
            else:
                card_path = Path(card_ref)
                if card_path.exists():
                    cards.append(load_run_card(card_path))
                else:
                    console.print(f"[red]Error:[/] Unknown run card: {card_ref}")
                    raise typer.Exit(1)
        claims = collect_claims_from_cards(cards)

    out = Path(output_dir) if output_dir else Path(f"proof_pack_{trace_id}")

    try:
        result_dir = build_proof_pack(
            trace_id,
            output_dir=out,
            mode=mode,
            claims=claims,
            emit_v2_receipts=emit_v2_receipts,
        )
    except ValueError as e:
        if output_json:
            _output_json({"command": "proof-pack", "status": "error", "error": str(e)})
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    # Read manifest for summary
    manifest_path = result_dir / "pack_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    att = manifest.get("attestation", {})

    if output_json:
        _output_json(
            {
                "command": "proof-pack",
                "status": "ok",
                "pack_id": att.get("pack_id"),
                "trace_id": trace_id,
                "output_dir": str(result_dir),
                "receipt_integrity": att.get("receipt_integrity"),
                "claim_check": att.get("claim_check"),
                "n_receipts": att.get("n_receipts"),
                "hash_covered_files": [f["path"] for f in manifest.get("files", [])],
                "expected_files": manifest.get("expected_files", []),
            }
        )

    console.print()
    claim_line = f"Claims:     {att.get('claim_check', 'N/A')}\n" if claims else ""
    console.print(
        Panel.fit(
            f"[bold green]Proof Pack Built[/]\n\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Trace:      {trace_id}\n"
            f"Integrity:  {att.get('receipt_integrity')}\n"
            f"{claim_line}"
            f"Receipts:   {att.get('n_receipts')}\n"
            f"Mode:       {att.get('mode')}\n"
            f"Output:     {result_dir}/",
            title="assay proof-pack",
        )
    )

    # List files
    for f in sorted(result_dir.iterdir()):
        size = f.stat().st_size
        console.print(f"  {f.name:30s} {size:>8,} bytes")

    console.print()
    console.print(f"Next: [bold]assay verify-pack {result_dir}[/]")


@assay_app.command("verify-pack", rich_help_panel="Build & Verify")
def verify_pack_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    require_claim_pass: bool = typer.Option(
        False,
        "--require-claim-pass",
        help="Fail (exit 1) if claim_check is not PASS. For CI gating.",
    ),
    lock: Optional[str] = typer.Option(
        None,
        "--lock",
        help="Path to assay.lock file. Enforces locked verification semantics.",
    ),
    coverage_contract: Optional[str] = typer.Option(
        None,
        "--coverage-contract",
        help="Path to coverage contract JSON. Checks receipt callsite coverage.",
    ),
    min_coverage: float = typer.Option(
        0.8,
        "--min-coverage",
        help="Minimum coverage threshold (0.0-1.0). Used with --coverage-contract.",
    ),
    max_age_hours: Optional[float] = typer.Option(
        None,
        "--max-age-hours",
        help="Fail verification if pack timestamp_end is older than this many hours.",
    ),
    require_ci_binding: bool = typer.Option(
        False,
        "--require-ci-binding",
        help="Fail if attestation has no ci_binding block. For CI-only verification.",
    ),
    expected_commit_sha: Optional[str] = typer.Option(
        None,
        "--expected-commit-sha",
        help="Fail if ci_binding.commit_sha does not match this value.",
    ),
    require_witness: bool = typer.Option(
        False,
        "--require-witness",
        help="Fail if pack has no valid external witness bundle.",
    ),
    check_expiry: bool = typer.Option(
        False,
        "--check-expiry",
        help="Fail (exit 1) if attestation valid_until is in the past.",
    ),
    html_out: Optional[str] = typer.Option(
        None,
        "--html",
        help="Write a self-contained HTML verification report to this path.",
    ),
    badge_out: Optional[str] = typer.Option(
        None,
        "--badge",
        help="Write an SVG verification badge to this path.",
    ),
    trust_target: Optional[str] = typer.Option(
        None,
        "--trust-target",
        help="Evaluate trust acceptance for this target (local_verify, ci_gate, publication). Advisory only.",
    ),
    trust_policy_dir: Optional[str] = typer.Option(
        None,
        "--trust-policy-dir",
        help="Directory containing signers.yaml and acceptance.yaml for trust evaluation.",
    ),
    trust_enforce: bool = typer.Option(
        False,
        "--enforce-trust-gate",
        help=(
            "Promote trust evaluation to a hard gate for ci_gate. "
            "Exit 1 only when ALL four conditions hold: "
            "(1) this flag is set, "
            "(2) --trust-target is ci_gate, "
            "(3) policy loaded without errors, "
            "(4) acceptance decision is explicitly 'reject'. "
            "Any other state (warn, accept, not_evaluated, load error, other target) "
            "remains advisory."
        ),
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a Proof Pack's integrity (manifest, signatures, file hashes).

    Trust root for signer identity is assay.lock:signer_policy.allowed_fingerprints,
    not the embedded public key in the manifest. Use --lock to enforce key pinning.
    """
    from pathlib import Path

    from assay.keystore import get_default_keystore
    from assay.proof_pack import verify_proof_pack

    if not 0.0 <= min_coverage <= 1.0:
        if output_json:
            _output_json(
                {
                    "command": "verify-pack",
                    "status": "error",
                    "error": f"--min-coverage must be between 0.0 and 1.0, got {min_coverage}",
                },
                exit_code=3,
            )
        console.print(
            f"[red]Error:[/] --min-coverage must be between 0.0 and 1.0, got {min_coverage}"
        )
        raise typer.Exit(3)
    if max_age_hours is not None and max_age_hours <= 0:
        if output_json:
            _output_json(
                {
                    "command": "verify-pack",
                    "status": "error",
                    "error": f"--max-age-hours must be > 0, got {max_age_hours}",
                },
                exit_code=3,
            )
        console.print(
            f"[red]Error:[/] --max-age-hours must be > 0, got {max_age_hours}"
        )
        raise typer.Exit(3)

    if expected_commit_sha:
        import re

        if not re.match(r"^[a-fA-F0-9]{40}$", expected_commit_sha):
            msg = (
                f"--expected-commit-sha must be a full 40-character hex SHA, "
                f"got {expected_commit_sha!r} ({len(expected_commit_sha)} chars). "
                f"Use: git rev-parse HEAD"
            )
            if output_json:
                _output_json(
                    {"command": "verify-pack", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not manifest_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "verify-pack",
                    "status": "error",
                    "error": "pack_manifest.json not found",
                }
            )
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(1)

    manifest = json.loads(manifest_path.read_text())

    # Schema validation (verify-time enforcement)
    from assay.manifest_schema import validate_manifest

    schema_errors = validate_manifest(manifest)
    if schema_errors:
        if output_json:
            _output_json(
                {
                    "command": "verify-pack",
                    "status": "error",
                    "error": "schema_validation_failed",
                    "details": schema_errors,
                }
            )
        console.print("[red]Schema validation failed:[/]")
        for se in schema_errors[:10]:
            console.print(f"  {se}")
        raise typer.Exit(1)

    ks = get_default_keystore()
    result = verify_proof_pack(
        manifest,
        pack_path,
        ks,
        max_age_hours=max_age_hours,
        require_ci_binding=require_ci_binding,
        expected_commit_sha=expected_commit_sha,
    )

    att = manifest.get("attestation", {})
    claim_check = att.get("claim_check", "N/A")

    # Determine claim gate result
    claim_gate_failed = require_claim_pass and claim_check != "PASS"

    # Lock enforcement (fail-closed)
    lock_failed = False
    lock_errors: list = []
    if lock:
        from assay.lockfile import check_lockfile, load_lockfile, validate_against_lock

        lock_path = Path(lock)
        if not lock_path.exists():
            if output_json:
                _output_json(
                    {
                        "command": "verify-pack",
                        "status": "error",
                        "error": "lock_file_not_found",
                        "details": str(lock),
                        "fixes": [
                            "assay lock init",
                            f"assay verify-pack {pack_dir} --lock path/to/assay.lock",
                            f"assay verify-pack {pack_dir}",
                        ],
                    },
                    exit_code=2,
                )
            console.print(
                f"[red]Error:[/] Lock file not found: {lock}\n"
                "\n"
                "[bold]Fix:[/]\n"
                "  1. Create lock:          [bold]assay lock init[/]\n"
                f"  2. Use explicit path:    [bold]assay verify-pack {pack_dir} --lock path/to/assay.lock[/]\n"
                f"  3. Verify without lock:  [bold]assay verify-pack {pack_dir}[/]"
            )
            raise typer.Exit(2)

        # Step 1: Validate lockfile itself (structure, hashes, version)
        lock_issues = check_lockfile(lock_path)
        if lock_issues:
            if output_json:
                _output_json(
                    {
                        "command": "verify-pack",
                        "status": "error",
                        "error": "lockfile_invalid",
                        "details": lock_issues,
                    }
                )
            console.print(f"[red]Error:[/] Lockfile is invalid: {lock}")
            for issue in lock_issues:
                console.print(f"  [red]{issue}[/]")
            raise typer.Exit(2)

        # Step 2: Load (structural validation) + validate pack against lock
        lockfile_data = load_lockfile(lock_path)
        lock_result = validate_against_lock(manifest, lockfile_data)
        if not lock_result.passed:
            lock_failed = True
            lock_errors = lock_result.errors

    # Coverage contract verification
    coverage_failed = False
    coverage_result: Optional[dict] = None
    if coverage_contract:
        from assay.coverage import CoverageContract, verify_coverage

        cc_path = Path(coverage_contract)
        if not cc_path.exists():
            if output_json:
                _output_json(
                    {
                        "command": "verify-pack",
                        "status": "error",
                        "error": f"Coverage contract not found: {coverage_contract}",
                    }
                )
            console.print(
                f"[red]Error:[/] Coverage contract not found: {coverage_contract}"
            )
            raise typer.Exit(2)

        try:
            contract = CoverageContract.load(cc_path)
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            if output_json:
                _output_json(
                    {
                        "command": "verify-pack",
                        "status": "error",
                        "error": f"Invalid coverage contract: {e}",
                    }
                )
            console.print(f"[red]Error:[/] Invalid coverage contract: {e}")
            raise typer.Exit(2)

        # Load receipts from the pack (JSONL: one JSON object per line)
        receipts_path = pack_path / "receipt_pack.jsonl"
        pack_receipts = []
        if receipts_path.exists():
            for line in receipts_path.read_text().splitlines():
                line = line.strip()
                if line:
                    pack_receipts.append(json.loads(line))

        coverage_result = verify_coverage(contract, pack_receipts)
        if coverage_result["coverage_pct"] < min_coverage:
            coverage_failed = True

    # Witness verification (T2 trust)
    witness_failed = False
    witness_errors: list = []
    witness_sufficiency: Optional[float] = None
    if require_witness:
        from assay.witness import verify_witness_from_pack

        witness_result = verify_witness_from_pack(pack_path)
        witness_sufficiency = witness_result.sufficiency
        if not witness_result.passed:
            witness_failed = True
            witness_errors = witness_result.errors

    # Expiry check: valid_until in the past means the pack has expired.
    # This is an honest failure (exit 1), not a tamper (exit 2).
    # Malformed valid_until is also an expiry failure (fail-closed); see #75.
    expiry_failed = False
    expiry_kind: Optional[str] = None  # "expired" | "malformed"
    expiry_message = "--check-expiry: valid_until is in the past"
    if check_expiry:
        valid_until_str = att.get("valid_until")
        if valid_until_str:
            from datetime import datetime as _dt
            from datetime import timezone as _tz

            try:
                # Python 3.9/3.10 fromisoformat does not handle the 'Z' suffix.
                _vu = (
                    valid_until_str.replace("Z", "+00:00")
                    if valid_until_str.endswith("Z")
                    else valid_until_str
                )
                valid_until_ts = _dt.fromisoformat(_vu)
                if valid_until_ts.tzinfo is None:
                    valid_until_ts = valid_until_ts.replace(tzinfo=_tz.utc)
                if _dt.now(_tz.utc) > valid_until_ts:
                    expiry_failed = True
                    expiry_kind = "expired"
            except (ValueError, TypeError):
                expiry_failed = True
                expiry_kind = "malformed"
                expiry_message = (
                    f"--check-expiry: valid_until is malformed ({valid_until_str!r}); "
                    "treating as expiry failure"
                )

    overall_status = "ok"
    if not result.passed:
        overall_status = "failed"
    elif lock_failed:
        overall_status = "lock_mismatch"
    elif claim_gate_failed:
        overall_status = "claim_gate_failed"
    elif expiry_failed:
        overall_status = "expired"
    elif coverage_failed:
        overall_status = "coverage_below_threshold"
    elif witness_failed:
        overall_status = "witness_failed"

    # --- Signer identity warning (P1b: trust-boundary clarity) ---
    # Verification can confirm cryptographic validity without establishing
    # signer identity. When --lock is not used, the signer's public key is
    # not pinned — a substitute key would also verify. Surface this clearly.
    if result.passed and not lock:
        result.warnings.append(
            "Signature valid for supplied key material; signer identity not pinned. "
            "Use --lock for trust-anchored verification."
        )

    # --- Trust evaluation (advisory only — does not affect exit codes) ---
    trust_eval = None
    trust_load_errors: list[str] = []
    if trust_target:
        from assay.trust.acceptance import load_acceptance as _load_acceptance
        from assay.trust.evaluator import evaluate_trust
        from assay.trust.registry import load_registry as _load_registry

        _registry = None
        _acceptance = None
        if trust_policy_dir:
            _policy_path = Path(trust_policy_dir)
            _signers_path = _policy_path / "signers.yaml"
            _acceptance_path = _policy_path / "acceptance.yaml"
            try:
                if _signers_path.exists():
                    _registry = _load_registry(_signers_path)
            except Exception as exc:
                trust_load_errors.append(f"signers.yaml: {exc}")
            try:
                if _acceptance_path.exists():
                    _acceptance = _load_acceptance(_acceptance_path)
            except Exception as exc:
                trust_load_errors.append(f"acceptance.yaml: {exc}")

        trust_eval = evaluate_trust(
            result,
            manifest,
            registry=_registry,
            acceptance_policy=_acceptance,
            target=trust_target,
        )

    # --- Trust gate enforcement (opt-in, ci_gate only) ---
    # Enforce only when: flag set + target is ci_gate + policy loaded cleanly + explicit reject.
    # Any load error, warn, accept, or not_evaluated → remain advisory.
    trust_gate_failed = False
    if (
        trust_enforce
        and trust_target == "ci_gate"
        and not trust_load_errors
        and trust_eval is not None
        and trust_eval.acceptance.decision == "reject"
    ):
        trust_gate_failed = True
        if overall_status == "ok":
            overall_status = "trust_gate_rejected"

    # --- Artifact generation (does not affect exit codes) ---
    _artifact_paths: Dict[str, str] = {}
    if html_out or badge_out:
        from assay.verification_status import classify_verdict
        from assay.verify_render import (
            render_verification_badge,
            render_verification_html,
        )

        _ws_art: Optional[bool] = None
        if require_witness:
            _ws_art = not witness_failed
        _verdict = classify_verdict(
            integrity_passed=result.passed,
            claim_check=claim_check,
            witness_sufficient=_ws_art,
        )

        if html_out:
            from assay import __version__ as _assay_version

            html_str = render_verification_html(
                verdict=_verdict,
                pack_id=att.get("pack_id", "unknown"),
                run_id=att.get("run_id", "unknown"),
                pack_dir=str(pack_path),
                integrity_passed=result.passed,
                claim_check=claim_check,
                receipt_count=result.receipt_count,
                signer_id=att.get("signer_id", "unknown"),
                errors=[e.to_dict() for e in result.errors],
                warnings=result.warnings,
                head_hash=result.head_hash,
                version=_assay_version,
            )
            html_path = Path(html_out)
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.write_text(html_str, encoding="utf-8")
            _artifact_paths["html"] = str(html_path)

        if badge_out:
            svg_str = render_verification_badge(_verdict)
            badge_path = Path(badge_out)
            badge_path.parent.mkdir(parents=True, exist_ok=True)
            badge_path.write_text(svg_str, encoding="utf-8")
            _artifact_paths["badge"] = str(badge_path)

    # --- Governance posture (production + current + divergence) ---
    _posture_info: Optional[Dict[str, Any]] = None
    try:
        from assay.governance_posture import (
            compute_divergence,
            evaluate_posture,
            extract_production_posture,
        )

        # Load receipts for posture extraction
        _receipt_path = pack_path / "receipt_pack.jsonl"
        _pack_entries: list = []
        if _receipt_path.exists():
            for _line in _receipt_path.read_text().splitlines():
                if _line.strip():
                    _pack_entries.append(json.loads(_line))

        _production = extract_production_posture(_pack_entries)
        _current = evaluate_posture()
        _divergence = compute_divergence(_production, _current)

        _posture_info = {
            "production_posture": _divergence.production_posture,
            "production_evaluated_at": _divergence.production_evaluated_at,
            "current_posture": _divergence.current_posture,
            "current_evaluated_at": _divergence.current_evaluated_at,
            "diverged": _divergence.diverged,
            "divergence_type": _divergence.divergence_type,
        }
        if _divergence.detail:
            _posture_info["detail"] = _divergence.detail
        if _production:
            _posture_info["production_obligations"] = _production.obligation_ids
            _posture_info["production_open_count"] = _production.open_count
            _posture_info["production_overdue_count"] = _production.overdue_count
        if _current.obligation_ids:
            _posture_info["current_obligations"] = _current.obligation_ids
            _posture_info["current_open_count"] = _current.open_count
            _posture_info["current_overdue_count"] = _current.overdue_count
    except Exception:
        pass  # Posture display is best-effort

    if output_json:
        from assay.verification_status import classify_verdict

        # Compute verdict: witness_sufficient is None unless --require-witness
        _ws: Optional[bool] = None
        if require_witness:
            _ws = not witness_failed
        _verdict = classify_verdict(
            integrity_passed=result.passed,
            claim_check=claim_check,
            witness_sufficient=_ws,
        )
        out = {
            "command": "verify-pack",
            "status": overall_status,
            "verdict": _verdict,
            "claim_check": claim_check,
            **result.to_dict(),
        }
        if max_age_hours is not None:
            out["max_age_hours"] = max_age_hours
        if expiry_failed:
            out["expiry_status"] = expiry_kind  # "expired" | "malformed"
        if claim_gate_failed:
            out["claim_gate"] = f"--require-claim-pass: claim_check is '{claim_check}'"
        if lock_failed:
            out["lock_errors"] = [str(e) for e in lock_errors]
        if coverage_result is not None:
            out["coverage"] = coverage_result
        if witness_failed:
            out["witness_errors"] = witness_errors
        if witness_sufficiency is not None:
            out["witness_sufficiency"] = witness_sufficiency
        if _artifact_paths:
            out["artifacts"] = _artifact_paths
        if trust_eval is not None:
            _trust_out = trust_eval.to_dict()
            if trust_load_errors:
                _trust_out["load_errors"] = trust_load_errors
            out["trust"] = _trust_out
        if trust_gate_failed:
            out["trust_gate"] = "rejected_by_trust_policy"
        if _posture_info:
            out["governance_posture"] = _posture_info
        _output_json(out)

    # Print artifact paths in terminal mode
    if _artifact_paths and not output_json:
        for kind, apath in _artifact_paths.items():
            label = "HTML report" if kind == "html" else "Badge"
            console.print(f"  [dim]{label}:[/] {apath}")

    if lock_failed:
        console.print()
        console.print(
            Panel.fit(
                f"[bold red]LOCK MISMATCH[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Lock file:  {lock}\n"
                f"Mismatches: {len(lock_errors)}",
                title="assay verify-pack",
            )
        )
        for le in lock_errors:
            console.print(
                f"  [red]{le.field}[/]: expected {le.expected}, got {le.actual}"
            )
        console.print()
        raise typer.Exit(2)

    if witness_failed:
        console.print()
        console.print(
            Panel.fit(
                f"[bold red]WITNESS VERIFICATION FAILED[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Errors:     {len(witness_errors)}",
                title="assay verify-pack",
            )
        )
        for we in witness_errors:
            console.print(f"  [red]{we}[/]")
        console.print()
        raise typer.Exit(2)

    if (
        result.passed
        and not claim_gate_failed
        and not coverage_failed
        and not expiry_failed
    ):
        lock_line = f"\nLock:       PASS ({lock})" if lock else ""
        cov_line = ""
        if coverage_result is not None:
            pct = coverage_result["coverage_pct"]
            cov_line = f"\nCoverage:   {pct:.0%} ({coverage_result['covered_count']}/{coverage_result['total_count']})"
        posture_line = ""
        if _posture_info:
            _prod_p = _posture_info["production_posture"]
            _curr_p = _posture_info["current_posture"]
            _div = _posture_info["diverged"]
            if _prod_p == "CLEAN" and _curr_p == "CLEAN":
                posture_line = "\nGovernance: CLEAN"
            elif _prod_p == "UNAVAILABLE":
                if _curr_p != "CLEAN":
                    posture_line = f"\nGovernance: [yellow]{_curr_p}[/] (no production posture embedded)"
                # Don't show anything for UNAVAILABLE + CLEAN (old pack, no debt)
            else:
                posture_line = f"\nGovernance: [yellow]{_prod_p}[/] at production"
                if _div:
                    posture_line += f" → [yellow]{_curr_p}[/] now"
        console.print()
        console.print(
            Panel.fit(
                f"[bold green]VERIFICATION PASSED[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Integrity:  PASS\n"
                f"Claims:     {claim_check}\n"
                f"Receipts:   {result.receipt_count}\n"
                f"Head Hash:  {result.head_hash or 'N/A'}\n"
                f"Errors:     0\n"
                f"Warnings:   {len(result.warnings)}"
                f"{lock_line}"
                f"{cov_line}"
                f"{posture_line}",
                title="assay verify-pack",
            )
        )
    elif result.passed and expiry_failed:
        valid_until_str = att.get("valid_until", "N/A")
        console.print()
        console.print(
            Panel.fit(
                f"[bold yellow]PACK EXPIRED[/]\n\n"
                f"Pack ID:      {att.get('pack_id')}\n"
                f"Integrity:    PASS\n"
                f"Claims:       {claim_check}\n"
                f"Valid Until:  {valid_until_str}\n"
                f"Receipts:     {result.receipt_count}\n\n"
                f"{expiry_message}",
                title="assay verify-pack",
            )
        )
    elif result.passed and claim_gate_failed:
        console.print()
        console.print(
            Panel.fit(
                f"[bold yellow]CLAIM GATE FAILED[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Integrity:  PASS\n"
                f"Claims:     {claim_check}\n"
                f"Receipts:   {result.receipt_count}\n\n"
                f"--require-claim-pass was set but claim_check is '{claim_check}'",
                title="assay verify-pack",
            )
        )
    elif result.passed and coverage_failed and coverage_result is not None:
        pct = coverage_result["coverage_pct"]
        console.print()
        console.print(
            Panel.fit(
                f"[bold yellow]COVERAGE BELOW THRESHOLD[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Integrity:  PASS\n"
                f"Claims:     {claim_check}\n"
                f"Coverage:   {pct:.0%} ({coverage_result['covered_count']}/{coverage_result['total_count']})\n"
                f"Threshold:  {min_coverage:.0%}\n"
                f"Uncovered:  {len(coverage_result.get('uncovered_ids', []))} site(s)",
                title="assay verify-pack",
            )
        )
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold red]VERIFICATION FAILED[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Errors:     {len(result.errors)}",
                title="assay verify-pack",
            )
        )
        for err in result.errors:
            console.print(f"  [red]{err.code}[/]: {err.message}")

    if trust_load_errors and not output_json:
        for _tle in trust_load_errors:
            console.print(f"  [red]Trust policy load error:[/] {_tle}")

    if trust_eval is not None and not output_json:
        _te = trust_eval
        _auth_style = {
            "authorized": "green",
            "recognized": "yellow",
            "unrecognized": "red",
            "revoked": "red",
        }.get(_te.authorization.status, "dim")
        _acc_style = {"accept": "green", "warn": "yellow", "reject": "red"}.get(
            _te.acceptance.decision, "dim"
        )
        console.print(f"\n  Trust evaluation ({_te.acceptance.target}):")
        console.print(
            f"    authorization: [{_auth_style}]{_te.authorization.status}[/{_auth_style}]"
        )
        console.print(
            f"    acceptance:    [{_acc_style}]{_te.acceptance.decision}[/{_acc_style}]"
        )
        if _te.authorization.reason_codes:
            console.print(
                f"    auth reasons:  {', '.join(_te.authorization.reason_codes)}"
            )
        if _te.acceptance.reason_codes:
            console.print(
                f"    accept reasons: {', '.join(_te.acceptance.reason_codes)}"
            )

    if trust_gate_failed and not output_json:
        console.print()
        console.print(
            Panel.fit(
                f"[bold red]TRUST GATE REJECTED[/]\n\n"
                f"Pack ID:    {att.get('pack_id')}\n"
                f"Target:     ci_gate\n"
                f"Rationale:  {trust_eval.acceptance.rationale}",
                title="assay verify-pack",
            )
        )

    if result.warnings:
        for w in result.warnings:
            console.print(f"  [yellow]Warning:[/] {w}")

    console.print()

    if (
        result.passed
        and not claim_gate_failed
        and not coverage_failed
        and not expiry_failed
        and not lock
        and not trust_gate_failed
    ):
        console.print("Next: [bold]assay lock init[/]")
        console.print()

    if not result.passed:
        raise typer.Exit(2)
    if claim_gate_failed:
        raise typer.Exit(1)
    if expiry_failed:
        raise typer.Exit(1)
    if coverage_failed:
        raise typer.Exit(1)
    if trust_gate_failed:
        raise typer.Exit(1)


@assay_app.command("replay-judge", hidden=True)
def replay_judge_cmd(
    expected_pack: str = typer.Option(
        ...,
        "--expected-pack",
        "-e",
        help="Path to the expected (original/baseline) proof pack directory",
    ),
    observed_pack: str = typer.Option(
        ...,
        "--observed-pack",
        "-o",
        help="Path to the observed (replayed) proof pack directory",
    ),
    out_dir: str = typer.Option(
        ...,
        "--out-dir",
        "-O",
        help="Directory to write replay_judgment.json and replay_explanation_trace.json",
    ),
    key_id: Optional[str] = typer.Option(
        None,
        "--key-id",
        help="Signing key identity. Default: active key.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite output files if they already exist.",
    ),
    pretty: bool = typer.Option(
        False,
        "--pretty",
        help="Pretty-print JSON output (indented).",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compare two proof packs and emit a signed replay judgment plus explanation trace.

    Exit codes:
      0 = reproducible   1 = drifted   2 = unverifiable   3 = bad input
    """
    from pathlib import Path

    from assay.keystore import DEFAULT_SIGNER_ID, get_default_keystore
    from assay.replay_judge import write_replay_judgment

    expected_path = Path(expected_pack)
    observed_path = Path(observed_pack)
    out_path = Path(out_dir)

    # Early validation
    for label, p in [
        ("expected-pack", expected_path),
        ("observed-pack", observed_path),
    ]:
        if not p.exists():
            msg = f"--{label} directory does not exist: {p}"
            if output_json:
                _output_json(
                    {"command": "replay-judge", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)
        if not (p / "pack_manifest.json").exists():
            msg = f"--{label} directory missing pack_manifest.json: {p}"
            if output_json:
                _output_json(
                    {"command": "replay-judge", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

    ks = get_default_keystore()
    signer_id = key_id or DEFAULT_SIGNER_ID

    try:
        result = write_replay_judgment(
            expected_pack_dir=expected_path,
            observed_pack_dir=observed_path,
            out_dir=out_path,
            keystore=ks,
            signer_id=signer_id,
            overwrite=overwrite,
            pretty=pretty,
        )
    except FileExistsError as e:
        msg = str(e)
        if output_json:
            _output_json(
                {"command": "replay-judge", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)
    except Exception as e:
        msg = f"Internal error: {e}"
        if output_json:
            _output_json(
                {"command": "replay-judge", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "replay-judge",
                "status": "ok",
                "verdict": result.verdict,
                "judgment_id": result.judgment_id,
                "judgment_path": str(result.judgment_path),
                "trace_path": str(result.trace_path),
                "exit_code": result.exit_code,
            },
            exit_code=result.exit_code,
        )

    console.print(f"\nreplay verdict: [bold]{result.verdict}[/]")
    console.print(f"wrote: {result.judgment_path}")
    console.print(f"wrote: {result.trace_path}")
    console.print()

    raise typer.Exit(result.exit_code)


@assay_app.command("rce-verify", hidden=True)
def rce_verify_cmd(
    pack_dir: str = typer.Argument(
        ..., help="Path to the original RCE proof pack directory"
    ),
    out_dir: str = typer.Option(
        ...,
        "--out-dir",
        "-O",
        help="Directory to write rce_replay_result.json and rce_replay_details.json",
    ),
    verifier_id: str = typer.Option(
        "assay-rce-verify-py",
        "--verifier-id",
        help="Verifier implementation identifier recorded in the replay result receipt.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite output files when the output directory already exists.",
    ),
    pretty: bool = typer.Option(
        False,
        "--pretty",
        help="Pretty-print written JSON artifacts.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify an RCE pack against recorded traces.

    Exit codes:
      0 = MATCH   1 = DIVERGE   2 = INTEGRITY_FAIL   3 = bad input
    """
    from pathlib import Path

    from assay.rce_verify import write_rce_replay_result

    pack_path = Path(pack_dir)
    output_path = Path(out_dir)

    if not pack_path.exists():
        msg = f"Pack directory does not exist: {pack_path}"
        if output_json:
            _output_json(
                {"command": "rce-verify", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    try:
        result = write_rce_replay_result(
            pack_dir=pack_path,
            out_dir=output_path,
            verifier_id=verifier_id,
            overwrite=overwrite,
            pretty=pretty,
        )
    except FileExistsError as exc:
        msg = str(exc)
        if output_json:
            _output_json(
                {"command": "rce-verify", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)
    except Exception as exc:
        msg = f"Internal error: {exc}"
        if output_json:
            _output_json(
                {"command": "rce-verify", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "rce-verify",
                "status": "ok",
                "verdict": result.verdict,
                "receipt_path": str(result.receipt_path),
                "details_path": str(result.details_path),
                "exit_code": result.exit_code,
            },
            exit_code=result.exit_code,
        )

    console.print(f"\nrce verdict: [bold]{result.verdict}[/]")
    console.print(f"wrote: {result.receipt_path}")
    console.print(f"wrote: {result.details_path}")
    console.print()

    raise typer.Exit(result.exit_code)


@assay_app.command("accept", hidden=True, rich_help_panel="Advanced")
def accept_cmd(
    pack_dir: str = typer.Argument(..., help="Path to verified Proof Pack directory"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for ACCEPTANCE_RECEIPT.json. Default: <pack_dir>/ACCEPTANCE_RECEIPT.json",
    ),
    lock: Optional[str] = typer.Option(
        None,
        "--lock",
        help="Path to assay.lock file. Enforces locked verification before acceptance.",
    ),
    max_age_hours: Optional[float] = typer.Option(
        None,
        "--max-age-hours",
        help="Fail if pack is older than this many hours.",
    ),
    require_ci_binding: bool = typer.Option(
        False,
        "--require-ci-binding",
        help="Fail if pack has no CI binding.",
    ),
    expected_commit_sha: Optional[str] = typer.Option(
        None,
        "--expected-commit-sha",
        help="Fail if ci_binding.commit_sha does not match.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a Proof Pack and emit a signed ACCEPTANCE_RECEIPT.json.

    This is the contract-close command: it verifies the pack, then produces
    a single signed artifact that references the pack by hash and records
    the verification verdict.

    Exit codes follow the standard Assay contract:
      0 = integrity PASS, claims PASS (or N/A)
      1 = integrity PASS, claims FAIL
      2 = integrity FAIL or critical error
    """
    from pathlib import Path

    from assay.acceptance import generate_acceptance_receipt
    from assay.keystore import get_default_keystore
    from assay.proof_pack import verify_proof_pack

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not manifest_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "accept",
                    "status": "error",
                    "error": "pack_manifest.json not found",
                }
            )
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(2)

    manifest = json.loads(manifest_path.read_text())

    # Schema validation
    from assay.manifest_schema import validate_manifest

    schema_errors = validate_manifest(manifest)
    if schema_errors:
        if output_json:
            _output_json(
                {
                    "command": "accept",
                    "status": "error",
                    "error": "schema_validation_failed",
                    "details": schema_errors,
                }
            )
        console.print("[red]Schema validation failed:[/]")
        for se in schema_errors[:10]:
            console.print(f"  {se}")
        raise typer.Exit(2)

    ks = get_default_keystore()
    result = verify_proof_pack(
        manifest,
        pack_path,
        ks,
        max_age_hours=max_age_hours,
        require_ci_binding=require_ci_binding,
        expected_commit_sha=expected_commit_sha,
    )

    att = manifest.get("attestation", {})
    claim_check = att.get("claim_check", "N/A")
    integrity_passed = result.passed
    claims_verdict = claim_check

    # Determine exit code
    if not integrity_passed:
        exit_code = 2
    elif claim_check == "FAIL":
        exit_code = 1
    else:
        exit_code = 0

    lock_errors: list[str] = []

    # Lock enforcement
    if lock:
        from assay.lockfile import load_lockfile, validate_against_lock

        lock_path = Path(lock)
        if not lock_path.exists():
            if output_json:
                _output_json(
                    {
                        "command": "accept",
                        "status": "error",
                        "error": "lock_file_not_found",
                    },
                    exit_code=2,
                )
            console.print(f"[red]Error:[/] Lock file not found: {lock}")
            raise typer.Exit(2)
        lock_data = load_lockfile(lock_path)
        lock_result = validate_against_lock(manifest, lock_data)
        if not lock_result.passed:
            lock_errors = [str(err) for err in lock_result.errors]
            integrity_passed = False
            exit_code = 2

    # Generate receipt
    receipt_path = Path(output) if output else (pack_path / "ACCEPTANCE_RECEIPT.json")
    receipt = generate_acceptance_receipt(
        manifest,
        integrity_passed=integrity_passed,
        claims_verdict=claims_verdict,
        exit_code=exit_code,
        keystore=ks,
        output_path=receipt_path,
    )

    if output_json:
        _output_json(
            {
                "command": "accept",
                "status": "accepted"
                if exit_code == 0
                else ("claims_failed" if exit_code == 1 else "rejected"),
                "exit_code": exit_code,
                "receipt_path": str(receipt_path),
                "pack_id": receipt["pack_id"],
                "pack_root_sha256": receipt["pack_root_sha256"],
                "verification": receipt["verification"],
                "signer_id": receipt["signer"]["signer_id"],
                "lock_errors": lock_errors,
            },
            exit_code=exit_code,
        )

    if exit_code == 0:
        console.print(f"[bold green]Accepted[/] — {receipt_path}")
    elif exit_code == 1:
        console.print(
            f"[bold yellow]Claims failed[/] — receipt written to {receipt_path}"
        )
    else:
        console.print(f"[bold red]Rejected[/] — receipt written to {receipt_path}")

    console.print(f"  Pack ID:     {receipt['pack_id']}")
    console.print(f"  Integrity:   {receipt['verification']['integrity']}")
    console.print(f"  Claims:      {receipt['verification']['claims']}")
    console.print(f"  Exit code:   {exit_code}")
    console.print(f"  Signer:      {receipt['signer']['signer_id']}")
    if lock_errors:
        console.print("  Lock errors:")
        for err in lock_errors:
            console.print(f"    - {err}")
    console.print()

    raise typer.Exit(exit_code)


@assay_app.command("verify-acceptance", hidden=True, rich_help_panel="Advanced")
def verify_acceptance_cmd(
    receipt_path: str = typer.Argument(..., help="Path to ACCEPTANCE_RECEIPT.json"),
    expected_pack_root: Optional[str] = typer.Option(
        None,
        "--expected-pack-root",
        help="Expected pack_root_sha256. Fail if receipt references a different pack.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify an ACCEPTANCE_RECEIPT.json signature and optionally check pack reference.

    Exit codes:
      0 = receipt is valid
      2 = signature invalid or verification error
    """
    from pathlib import Path

    from assay.acceptance import verify_acceptance_receipt
    from assay.keystore import get_default_keystore

    rpath = Path(receipt_path)
    if not rpath.exists():
        if output_json:
            _output_json(
                {
                    "command": "verify-acceptance",
                    "status": "error",
                    "error": "receipt not found",
                }
            )
        console.print(f"[red]Error:[/] {rpath} not found")
        raise typer.Exit(2)

    receipt = json.loads(rpath.read_text())
    ks = get_default_keystore()
    result = verify_acceptance_receipt(
        receipt,
        keystore=ks,
        expected_pack_root=expected_pack_root,
    )

    if output_json:
        _output_json(
            {
                "command": "verify-acceptance",
                "status": "valid" if result.passed else "invalid",
                "pack_id": receipt.get("pack_id", ""),
                "pack_root_sha256": receipt.get("pack_root_sha256", ""),
                "verification": receipt.get("verification", {}),
                "errors": result.errors,
            },
            exit_code=0 if result.passed else 2,
        )

    if result.passed:
        console.print(f"[bold green]Valid[/] — {rpath}")
        console.print(f"  Pack ID:     {receipt.get('pack_id', 'N/A')}")
        console.print(
            f"  Integrity:   {receipt.get('verification', {}).get('integrity', 'N/A')}"
        )
        console.print(
            f"  Claims:      {receipt.get('verification', {}).get('claims', 'N/A')}"
        )
        console.print(f"  Issued:      {receipt.get('issued_at', 'N/A')}")
        console.print(
            f"  Signer:      {receipt.get('signer', {}).get('signer_id', 'N/A')}"
        )
    else:
        console.print(f"[bold red]Invalid[/] — {rpath}")
        for err in result.errors:
            console.print(f"  [red]{err}[/]")

    raise typer.Exit(0 if result.passed else 2)


@assay_app.command("witness", hidden=True, rich_help_panel="Advanced")
def witness_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    witness_type: str = typer.Option(
        "rfc3161",
        "--type",
        "-t",
        help="Witness provider type: rfc3161 (default) or rekor (not yet implemented).",
    ),
    tsa_url: str = typer.Option(
        "https://freetsa.org/tsr",
        "--tsa-url",
        help="TSA server URL (RFC 3161 only).",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for witness_bundle.json. Default: <pack_dir>/witness_bundle.json",
    ),
    acknowledge_debt: bool = typer.Option(
        False,
        "--acknowledge-debt",
        help="Proceed with witness submission despite governance debt. "
        "The acknowledgment is recorded in the witness bundle metadata.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Request an independent timestamp witness for a Proof Pack.

    Contacts a TSA (Time Stamping Authority) to obtain a signed timestamp
    proving that the pack's root hash existed at a specific time. The result
    is written as witness_bundle.json.

    Governance posture gate: Witness submission is a trust escalation — you're
    asking an external authority to attest to your evidence. If the pack was
    produced under DEBT_OVERDUE governance posture, submission is blocked
    unless --acknowledge-debt is provided. This is secondary policy (an optional
    promotion gate), not the primary doctrine (which is claim eligibility).

    Exit codes:
      0 = witness obtained successfully
      1 = governance posture gate blocked submission
      2 = error (network, TSA, missing pack)
    """
    from pathlib import Path

    from assay.adc_emitter import refresh_adc_witness_state
    from assay.keystore import get_default_keystore
    from assay.proof_pack import get_decision_credential_path, get_pack_summary_path
    from assay.witness import (
        WitnessError,
        generate_witness_bundle,
        verify_witness_from_pack,
    )

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not manifest_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "witness",
                    "status": "error",
                    "error": "pack_manifest.json not found",
                }
            )
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(2)

    # --- Governance posture gate (secondary policy) ---
    # Witness submission is a trust-escalation boundary. Packs produced under
    # DEBT_OVERDUE governance posture are blocked unless explicitly acknowledged.
    # DEBT_OUTSTANDING is warned but allowed. CLEAN passes silently.
    try:
        from assay.governance_posture import (
            PostureState,
            extract_production_posture,
        )

        _receipt_path = pack_path / "receipt_pack.jsonl"
        if _receipt_path.exists():
            _entries = []
            for _line in _receipt_path.read_text().splitlines():
                if _line.strip():
                    _entries.append(json.loads(_line))

            _prod_posture = extract_production_posture(_entries)
            _prod_state = _prod_posture.posture if _prod_posture else "UNAVAILABLE"

            if _prod_state == PostureState.DEBT_OVERDUE.value and not acknowledge_debt:
                _ob_ids = _prod_posture.obligation_ids if _prod_posture else []
                _msg = (
                    f"Witness submission blocked: pack was produced under "
                    f"DEBT_OVERDUE governance posture.\n"
                    f"  Overdue obligations: {', '.join(_ob_ids) or 'unknown'}\n\n"
                    f"  Resolve debt:      assay why <receipt-id>\n"
                    f"  Override:          assay witness {pack_dir} --acknowledge-debt"
                )
                if output_json:
                    _output_json(
                        {
                            "command": "witness",
                            "status": "blocked",
                            "error": "governance_posture_gate",
                            "production_posture": _prod_state,
                            "obligation_ids": _ob_ids,
                            "fix": f"assay witness {pack_dir} --acknowledge-debt",
                        },
                        exit_code=1,
                    )
                console.print(f"[bold red]BLOCKED[/]: {_msg}")
                raise typer.Exit(1)

            if _prod_state == PostureState.DEBT_OUTSTANDING.value:
                _ob_ids = _prod_posture.obligation_ids if _prod_posture else []
                console.print(
                    f"[yellow]Warning:[/] Pack produced under DEBT_OUTSTANDING "
                    f"governance posture ({len(_ob_ids)} open obligation(s)). "
                    f"Proceeding with witness submission."
                )
    except (typer.Exit, SystemExit):
        raise  # Re-raise exit from the gate
    except Exception:
        pass  # Posture gate is best-effort; don't block on evaluation failure

    out_path = Path(output) if output else None

    try:
        decision_credential_path = get_decision_credential_path(pack_path)
        decision_credential: Optional[dict] = None
        signer_id: Optional[str] = None
        keystore = None

        if decision_credential_path.exists():
            try:
                decision_credential = json.loads(decision_credential_path.read_text())
            except Exception as e:
                raise WitnessError(f"Invalid decision credential JSON: {e}") from e

            signer_id = str(decision_credential.get("issuer_id") or "")
            if not signer_id:
                raise WitnessError(
                    "decision_credential.json missing issuer_id; cannot refresh witness state"
                )

            keystore = get_default_keystore()
            if not keystore.has_key(signer_id):
                raise WitnessError(
                    f"Signer key not found for witness refresh: {signer_id}"
                )

            from assay.replay_judge import _verify_adc_signature

            expected_pubkey = base64.b64encode(
                keystore.get_verify_key(signer_id).encode()
            ).decode("ascii")
            expected_fp = keystore.signer_fingerprint(signer_id)
            if not _verify_adc_signature(
                decision_credential,
                expected_signer_pubkey=expected_pubkey,
                expected_signer_pubkey_sha256=expected_fp,
            ):
                raise WitnessError(
                    "decision_credential.json signature verification failed; "
                    "cannot refresh witness state"
                )

        bundle = generate_witness_bundle(
            pack_path,
            witness_type=witness_type,
            tsa_url=tsa_url,
            output_path=out_path,
        )

        bundle_path = out_path or (pack_path / "witness_bundle.json")
        witness_result = verify_witness_from_pack(pack_path, bundle_path=bundle_path)
        if not witness_result.passed:
            raise WitnessError(
                "Generated witness bundle failed verification: "
                + "; ".join(witness_result.errors)
            )

        if (
            decision_credential is not None
            and keystore is not None
            and signer_id is not None
        ):
            refreshed_adc = refresh_adc_witness_state(
                decision_credential,
                time_authority="tsa_anchored",
                witness_status="witnessed",
                sign_fn=lambda data: keystore.sign_b64(data, signer_id),
            )
            decision_credential_path.write_text(
                json.dumps(refreshed_adc, indent=2) + "\n"
            )
    except WitnessError as e:
        if output_json:
            _output_json(
                {"command": "witness", "status": "error", "error": str(e)}, exit_code=2
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(2)

    # Update PACK_SUMMARY.md if it exists in the unsigned sidecar dir
    summary_path = get_pack_summary_path(pack_path)
    if summary_path.exists():
        summary = summary_path.read_text()
        old_line = "- That timestamps are externally anchored (local clock was used)"
        new_line = (
            f"- Timestamps are externally anchored via {bundle['witness_type'].upper()} "
            f"witness ({bundle.get('tsa_url', 'TSA')})"
        )
        if old_line in summary:
            summary = summary.replace(old_line, new_line)
            summary_path.write_text(summary)

    if output_json:
        _output_json(
            {
                "command": "witness",
                "status": "ok",
                "witness_type": bundle["witness_type"],
                "pack_root_sha256": bundle["pack_root_sha256"],
                "gen_time": bundle.get("gen_time"),
                "bundle_path": str(bundle_path),
            },
            exit_code=0,
        )

    console.print(f"[bold green]Witness obtained[/] — {bundle_path}")
    console.print(f"  Type:        {bundle['witness_type']}")
    console.print(f"  Pack root:   {bundle['pack_root_sha256'][:16]}...")
    console.print(f"  TSA:         {bundle.get('tsa_url', 'N/A')}")
    console.print(f"  Gen time:    {bundle.get('gen_time', 'N/A')}")
    console.print(f"  Issued at:   {bundle['issued_at']}")
    console.print()

    raise typer.Exit(0)


@assay_app.command("verify-witness", hidden=True, rich_help_panel="Advanced")
def verify_witness_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    bundle: Optional[str] = typer.Option(
        None,
        "--bundle",
        "-b",
        help="Path to witness_bundle.json. Default: <pack_dir>/witness_bundle.json",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a witness bundle's timestamp token against the pack root hash.

    Checks:
      - Token signature via TSA certificate chain
      - Message imprint matches pack_root_sha256
      - Schema version and D12 invariant

    Exit codes:
      0 = witness verified
      2 = verification failed or error
    """
    from pathlib import Path

    from assay.witness import verify_witness_from_pack

    pack_path = Path(pack_dir)
    bundle_path = Path(bundle) if bundle else None

    result = verify_witness_from_pack(pack_path, bundle_path=bundle_path)

    if output_json:
        _output_json(
            {
                "command": "verify-witness",
                "status": "valid" if result.passed else "invalid",
                "gen_time": result.gen_time,
                "errors": result.errors,
            },
            exit_code=0 if result.passed else 2,
        )

    if result.passed:
        console.print("[bold green]Witness verified[/]")
        if result.gen_time:
            console.print(f"  Gen time:  {result.gen_time}")
    else:
        console.print("[bold red]Witness verification failed[/]")
        for err in result.errors:
            console.print(f"  [red]{err}[/]")

    raise typer.Exit(0 if result.passed else 2)


@assay_app.command("verify-signer", hidden=True, rich_help_panel="Advanced")
def verify_signer_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    expected: Optional[str] = typer.Option(
        None,
        "--expected",
        help="Expected signer_id. Fail (exit 1) if pack signer doesn't match.",
    ),
    fingerprint: Optional[str] = typer.Option(
        None,
        "--fingerprint",
        help="Expected pubkey fingerprint (hex prefix). Fail (exit 1) if mismatch.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Extract and verify signer identity from a proof pack.

    Shows who signed the pack, their public key fingerprint, and whether
    the key exists in the local keystore.

    Use --expected or --fingerprint to assert identity and fail on mismatch.

    Exit codes:
      0 = signer info extracted (and matches if --expected/--fingerprint given)
      1 = signer mismatch
      3 = bad input (pack doesn't exist, manifest missing)
    """
    from pathlib import Path

    from assay.keystore import get_default_keystore

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not pack_path.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "verify-signer",
                    "status": "error",
                    "error": f"Not a directory: {pack_dir}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not manifest_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "verify-signer",
                    "status": "error",
                    "error": "pack_manifest.json not found",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(3)

    manifest = json.loads(manifest_path.read_text())
    signer_id = manifest.get("signer_id", "unknown")
    signer_pubkey_sha256 = manifest.get("signer_pubkey_sha256")
    signature_alg = manifest.get("signature_alg", "ed25519")

    # Check local keystore
    ks = get_default_keystore()
    key_in_local = ks.has_key(signer_id)
    local_fp_match = False
    if key_in_local and signer_pubkey_sha256:
        try:
            local_fp = ks.signer_fingerprint(signer_id)
            local_fp_match = local_fp == signer_pubkey_sha256
        except Exception:
            pass

    # Check --expected
    match_ok = True
    mismatch_reason = None
    if expected is not None and signer_id != expected:
        match_ok = False
        mismatch_reason = f"Expected signer '{expected}', got '{signer_id}'"

    # Check --fingerprint (prefix match)
    if fingerprint is not None and signer_pubkey_sha256:
        if not signer_pubkey_sha256.startswith(fingerprint.lower()):
            match_ok = False
            mismatch_reason = f"Fingerprint mismatch: expected prefix {fingerprint}"
    elif fingerprint is not None and not signer_pubkey_sha256:
        match_ok = False
        mismatch_reason = "Pack has no signer_pubkey_sha256 to compare"

    status = "ok" if match_ok else "mismatch"
    result_data: Dict[str, Any] = {
        "command": "verify-signer",
        "status": status,
        "signer_id": signer_id,
        "signer_pubkey_sha256": signer_pubkey_sha256,
        "signature_alg": signature_alg,
        "key_in_local_keystore": key_in_local,
        "local_fingerprint_match": local_fp_match,
    }
    if mismatch_reason:
        result_data["mismatch_reason"] = mismatch_reason

    if output_json:
        _output_json(result_data, exit_code=0 if match_ok else 1)

    # Human output
    console.print()
    fp_display = signer_pubkey_sha256 or "N/A"
    local_badge = "[green]yes[/]" if key_in_local else "[yellow]no[/]"
    fp_badge = "[green]yes[/]" if local_fp_match else "[dim]no[/]"

    from rich.panel import Panel

    if match_ok:
        console.print(
            Panel.fit(
                f"[bold green]SIGNER VERIFIED[/]\n\n"
                f"Signer ID:       {signer_id}\n"
                f"Fingerprint:     {fp_display}\n"
                f"Algorithm:       {signature_alg}\n"
                f"In keystore:     {local_badge}\n"
                f"Local FP match:  {fp_badge}",
                title="assay verify-signer",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[bold red]SIGNER MISMATCH[/]\n\n"
                f"Signer ID:       {signer_id}\n"
                f"Fingerprint:     {fp_display}\n"
                f"Algorithm:       {signature_alg}\n"
                f"In keystore:     {local_badge}\n\n"
                f"[red]{mismatch_reason}[/]",
                title="assay verify-signer",
            )
        )
    console.print()

    if not match_ok:
        raise typer.Exit(1)


@assay_app.command("demo-pack", hidden=True, rich_help_panel="Advanced")
def demo_pack_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate, sign, and verify a Proof Pack in one command.

    Creates synthetic receipts (model_call, guardian_verdict, capability_use),
    builds a signed pack with claims, verifies it, then shows how different
    claims produce different outcomes against the same evidence.

    No API key, no configuration, no prior setup required.
    """
    import tempfile
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec
    from assay.integrity import verify_pack_manifest
    from assay.keystore import AssayKeyStore
    from assay.proof_pack import ProofPack

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        ks = AssayKeyStore(keys_dir=td / "keys")
        ks.generate_key("demo")

        # Synthetic receipts: a realistic mix of types
        ts_base = "2026-01-15T10:00:0"
        receipts = [
            {
                "receipt_id": "r_demo_001",
                "type": "model_call",
                "timestamp": f"{ts_base}0Z",
                "schema_version": "3.0",
                "seq": 0,
                "model_id": "claude-sonnet-4-20250514",
                "total_tokens": 1847,
            },
            {
                "receipt_id": "r_demo_002",
                "type": "guardian_verdict",
                "timestamp": f"{ts_base}1Z",
                "schema_version": "3.0",
                "seq": 1,
                "verdict": "allow",
                "tool": "web_search",
                "risk_score": 0.12,
            },
            {
                "receipt_id": "r_demo_003",
                "type": "model_call",
                "timestamp": f"{ts_base}2Z",
                "schema_version": "3.0",
                "seq": 2,
                "model_id": "claude-sonnet-4-20250514",
                "total_tokens": 523,
            },
            {
                "receipt_id": "r_demo_004",
                "type": "capability_use",
                "timestamp": f"{ts_base}3Z",
                "schema_version": "3.0",
                "seq": 3,
                "capability": "file_write",
                "target": "/tmp/output.txt",
            },
            {
                "receipt_id": "r_demo_005",
                "type": "model_call",
                "timestamp": f"{ts_base}4Z",
                "schema_version": "3.0",
                "seq": 4,
                "model_id": "claude-sonnet-4-20250514",
                "total_tokens": 312,
            },
        ]

        # Claims that PASS: these match the receipts above
        passing_claims = [
            ClaimSpec(
                claim_id="has_model_calls",
                description="At least one model_call receipt",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
            ClaimSpec(
                claim_id="has_guardian",
                description="Guardian was active",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
            ClaimSpec(
                claim_id="no_breakglass",
                description="No override receipts",
                check="no_receipt_type",
                params={"receipt_type": "breakglass"},
            ),
            ClaimSpec(
                claim_id="timestamps_ok",
                description="Timestamps are monotonic",
                check="timestamps_monotonic",
            ),
        ]

        # Build pack A: all claims pass
        pack_a = ProofPack(
            run_id="demo-passing",
            entries=receipts,
            signer_id="demo",
            claims=passing_claims,
            mode="shadow",
        )
        out_a = pack_a.build(td / "pack_pass", keystore=ks)
        manifest_a = json.loads((out_a / "pack_manifest.json").read_text())
        att_a = manifest_a["attestation"]
        result_a = verify_pack_manifest(manifest_a, out_a, ks)

        # Build pack B: same receipts, stricter claims -> one claim FAILS
        strict_claims = [
            ClaimSpec(
                claim_id="need_100_receipts",
                description="At least 100 receipts (will fail)",
                check="receipt_count_ge",
                params={"min_count": 100},
                severity="critical",
            ),
        ]
        pack_b = ProofPack(
            run_id="demo-failing",
            entries=receipts,  # same receipts
            signer_id="demo",
            claims=strict_claims,
            mode="shadow",
        )
        out_b = pack_b.build(td / "pack_fail", keystore=ks)
        manifest_b = json.loads((out_b / "pack_manifest.json").read_text())
        att_b = manifest_b["attestation"]

        if output_json:
            _output_json(
                {
                    "command": "demo-pack",
                    "status": "ok",
                    "pack_a": {
                        "pack_id": att_a["pack_id"],
                        "receipt_integrity": att_a["receipt_integrity"],
                        "claim_check": att_a["claim_check"],
                        "n_receipts": att_a["n_receipts"],
                        "verified": result_a.passed,
                    },
                    "pack_b": {
                        "pack_id": att_b["pack_id"],
                        "receipt_integrity": att_b["receipt_integrity"],
                        "claim_check": att_b["claim_check"],
                        "n_receipts": att_b["n_receipts"],
                    },
                }
            )

        # Output
        console.print()
        console.print("[bold]ASSAY DEMO PACK[/]")
        console.print()

        console.print("[dim]Step 1:[/] Created 5 synthetic receipts")
        for r in receipts:
            console.print(f"  {r['type']:20s} seq={r['seq']}  {r['receipt_id']}")

        console.print()
        console.print("[dim]Step 2:[/] Built Proof Pack A (4 claims, all should pass)")
        console.print(
            Panel.fit(
                f"Pack ID:    {att_a['pack_id']}\n"
                f"Integrity:  [green]{att_a['receipt_integrity']}[/]\n"
                f"Claims:     [green]{att_a['claim_check']}[/]\n"
                f"Receipts:   {att_a['n_receipts']}\n"
                f"Verified:   [green]{'PASS' if result_a.passed else 'FAIL'}[/]",
                title="Pack A: all claims pass",
            )
        )

        console.print(
            "[dim]Step 3:[/] Built Pack B (same receipts, stricter claim: need 100 receipts)"
        )
        console.print(
            Panel.fit(
                f"Pack ID:    {att_b['pack_id']}\n"
                f"Integrity:  [green]{att_b['receipt_integrity']}[/]  (same receipts = same integrity)\n"
                f"Claims:     [red]{att_b['claim_check']}[/]  (5 receipts < 100 required)\n"
                f"Receipts:   {att_b['n_receipts']}",
                title="Pack B: claim fails honestly",
            )
        )

        console.print()
        console.print(
            "[bold]Key insight:[/] Same evidence, different claims, different outcomes."
        )
        console.print(
            "Integrity PASS + Claim FAIL = honest failure report, not a cover-up."
        )
        console.print()
        console.print("[dim]Files in each pack:[/]")
        for f in sorted(out_a.iterdir()):
            console.print(f"  {f.name}")
        console.print()
        console.print("Next steps:")
        console.print(
            "  Emit receipts from your code:  [bold]from assay import emit_receipt[/]"
        )
        console.print(
            "  Wrap a command:                [bold]assay run -- python my_agent.py[/]"
        )
        console.print(
            "  Verify a pack:                 [bold]assay verify-pack <dir>[/]"
        )
        console.print(
            "  CI gate:                       [bold]assay verify-pack <dir> --require-claim-pass[/]"
        )


@assay_app.command(
    "run",
    context_settings={"allow_extra_args": True, "allow_interspersed_args": False},
    rich_help_panel="Build & Verify",
)
def run_cmd(
    ctx: typer.Context,
    run_card: Optional[List[str]] = typer.Option(
        None,
        "--run-card",
        "-c",
        help="Run card: builtin name or path to JSON file (repeatable)",
    ),
    output_dir: str = typer.Option(
        None, "--output", "-o", help="Output directory for proof pack"
    ),
    mode: str = typer.Option(
        "shadow", "--mode", "-m", help="Mode: shadow|enforced|breakglass"
    ),
    allow_empty: bool = typer.Option(
        False,
        "--allow-empty",
        help="Allow empty receipt packs (default: fail if no receipts emitted)",
    ),
    no_generate_key: bool = typer.Option(
        False,
        "--no-generate-key",
        help="Fail if signing key doesn't exist instead of auto-generating",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Run a command and build a Proof Pack from emitted receipts.

    Usage: assay run [OPTIONS] -- <command> [args...]

    The command's receipts are captured and packaged into a signed Proof Pack.
    """
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec
    from assay.keystore import get_default_keystore
    from assay.proof_pack import ProofPack
    from assay.run_cards import (
        collect_claims_from_cards,
        get_builtin_card,
        load_run_card,
    )
    from assay.store import get_default_store

    cmd_args = ctx.args
    if not cmd_args:
        if output_json:
            _output_json(
                {
                    "command": "run",
                    "status": "error",
                    "error": "no_command_provided",
                    "fixes": [
                        "assay run -- python app.py",
                        "assay run -- python app.py --mode fast",
                        "assay doctor",
                    ],
                },
                exit_code=1,
            )
        console.print(
            "[red]Error:[/] No command provided.\n"
            "\n"
            "[bold]Fix:[/]\n"
            "  1. Basic usage:           [bold]assay run -- python app.py[/]\n"
            "  2. With command flags:    [bold]assay run -- python app.py --mode fast[/]\n"
            "  3. Check environment:     [bold]assay doctor[/]"
        )
        raise typer.Exit(1)

    # Resolve run cards to claims
    claims: list[ClaimSpec] | None = None
    if run_card:
        cards = []
        for card_ref in run_card:
            builtin = get_builtin_card(card_ref)
            if builtin:
                cards.append(builtin)
            else:
                card_path = Path(card_ref)
                if card_path.exists():
                    cards.append(load_run_card(card_path))
                else:
                    console.print(f"[red]Error:[/] Unknown run card: {card_ref}")
                    raise typer.Exit(1)
        claims = collect_claims_from_cards(cards)

    # Start trace
    store = get_default_store()
    trace_id = store.start_trace()

    out = Path(output_dir) if output_dir else Path(f"proof_pack_{trace_id}")
    ks = get_default_keystore()
    signer_id = ks.get_active_signer()

    try:
        ks.get_verify_key(signer_id)
    except Exception:
        if no_generate_key:
            console.print(
                f"[red]Error:[/] Signing key '{signer_id}' not found.\n"
                f"Remove --no-generate-key to auto-generate on first run,\n"
                f"or run once without --no-generate-key to create the key."
            )
            raise typer.Exit(1)
        ks.generate_key(signer_id)
        console.print(f"[dim]assay run: generated signing key '{signer_id}'[/]")

    # Run the command with ASSAY_TRACE_ID in environment
    import os

    env = {**os.environ, "ASSAY_TRACE_ID": trace_id}
    exec_args = list(cmd_args)
    if exec_args and exec_args[0] == "python" and not shutil.which("python"):
        exec_args[0] = sys.executable
        console.print(
            "[dim]assay run: 'python' not found on PATH; "
            f"using current interpreter ({sys.executable})[/]"
        )

    console.print(f"[dim]assay run: trace={trace_id}[/]")
    console.print(f"[dim]assay run: executing: {' '.join(exec_args)}[/]")

    try:
        proc = subprocess.run(exec_args, capture_output=False, env=env)
    except FileNotFoundError:
        missing = exec_args[0] if exec_args else "<unknown>"
        if output_json:
            _output_json(
                {
                    "command": "run",
                    "status": "error",
                    "error": "command_not_found",
                    "missing_command": missing,
                    "fixes": [
                        "Use a full command path, e.g. /usr/bin/python3",
                        "Ensure the command is on PATH",
                        "assay doctor",
                    ],
                },
                exit_code=1,
            )
        console.print(
            f"[red]Error:[/] Command not found: [bold]{missing}[/]\n"
            "\n"
            "[bold]Fix:[/]\n"
            "  1. Use a full command path (e.g. [bold]/usr/bin/python3[/])\n"
            "  2. Ensure the command is available on PATH\n"
            "  3. Run [bold]assay doctor[/] to validate your environment"
        )
        raise typer.Exit(1)
    exit_code = proc.returncode

    console.print(f"[dim]assay run: command exited with code {exit_code}[/]")

    # Read whatever receipts were emitted during the run
    entries = store.read_trace(trace_id)

    if not entries and not allow_empty:
        if output_json:
            _output_json(
                {
                    "command": "run",
                    "status": "error",
                    "error": "no_receipts_emitted",
                    "trace_id": trace_id,
                    "fixes": [
                        "assay scan .",
                        "assay scan . --report",
                        "python3 -m pip install 'assay-ai[openai]'",
                        "assay run -- python app.py",
                        "assay doctor",
                    ],
                },
                exit_code=1,
            )
        console.print(
            "[red]Error:[/] No receipts emitted during run.\n"
            "\n"
            "[bold]Diagnose:[/]\n"
            "  1. Check for call sites:  [bold]assay scan .[/]\n"
            "     If scan finds 0 sites, your code may not use a supported SDK.\n"
            "  2. Check patch status:    [bold]assay scan . --report[/]\n"
            "     patch() must execute before any LLM API calls.\n"
            "     Your script needs [bold]# assay:patched[/] or an early import.\n"
            "  3. Missing SDK extra:     [bold]python3 -m pip install 'assay-ai\\[openai]'[/]\n"
            "     (or assay-ai\\[anthropic], assay-ai\\[all])\n"
            "  4. Missing separator:     [bold]assay run -- python app.py[/] (note the --)\n"
            "  5. Full diagnostic:       [bold]assay doctor[/]\n"
            "  6. Then re-run:           [bold]assay run -- <your command>[/]\n"
            "\n"
            "Use --allow-empty to build an empty pack anyway."
        )
        raise typer.Exit(1)
    if not entries:
        console.print(
            "[yellow]Warning:[/] No receipts emitted. Building empty pack (--allow-empty)."
        )
        entries = []

    from assay.proof_pack import detect_ci_binding

    pack = ProofPack(
        run_id=trace_id,
        entries=entries,
        signer_id=signer_id,
        claims=claims,
        mode=mode,
        ci_binding=detect_ci_binding(),
    )

    try:
        result_dir = pack.build(out, keystore=ks)
    except Exception as e:
        console.print(f"[red]Error building pack:[/] {e}")
        raise typer.Exit(1)

    manifest = json.loads((result_dir / "pack_manifest.json").read_text())
    att = manifest.get("attestation", {})

    if output_json:
        _output_json(
            {
                "command": "run",
                "status": "ok",
                "exit_code": exit_code,
                "trace_id": trace_id,
                "pack_id": att.get("pack_id"),
                "signer_id": signer_id,
                "output_dir": str(result_dir),
                "receipt_integrity": att.get("receipt_integrity"),
                "claim_check": att.get("claim_check"),
                "n_receipts": att.get("n_receipts"),
            }
        )

    claim_line = f"Claims:     {att.get('claim_check', 'N/A')}\n" if claims else ""
    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Proof Pack Built[/]\n\n"
            f"Trace:      {trace_id}\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Signer:     {signer_id}\n"
            f"Exit Code:  {exit_code}\n"
            f"Integrity:  {att.get('receipt_integrity')}\n"
            f"{claim_line}"
            f"Receipts:   {att.get('n_receipts')}\n"
            f"Output:     {result_dir}/",
            title="assay run",
        )
    )

    for f in sorted(result_dir.iterdir()):
        size = f.stat().st_size
        console.print(f"  {f.name:30s} {size:>8,} bytes")

    console.print()
    console.print(f"Next: [bold]assay verify-pack {result_dir}[/]")

    if exit_code != 0:
        raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# Key subcommands
# ---------------------------------------------------------------------------

key_app = typer.Typer(
    name="key",
    help="Manage local signing keys",
    no_args_is_help=True,
)
assay_app.add_typer(key_app, name="key", hidden=True, rich_help_panel="Operate")


@key_app.command("list")
def key_list_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List local signer keys and active signer."""
    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    info = ks.signer_info()
    active = ks.get_active_signer()

    if output_json:
        _output_json(
            {
                "command": "key list",
                "status": "ok",
                "active_signer": active,
                "signers": info,
            },
            exit_code=0,
        )

    if not info:
        console.print(
            Panel.fit(
                "[yellow]No signer keys found.[/]\n\n"
                "Generate one with:\n"
                "  [bold]assay key generate[/]",
                title="assay key list",
            )
        )
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("active", style="green", width=7)
    table.add_column("signer_id", style="cyan")
    table.add_column("fingerprint", style="dim")
    table.add_column("key_path", style="dim")

    for item in info:
        table.add_row(
            "yes" if item["active"] else "",
            item["signer_id"],
            item["fingerprint"][:16] + "...",
            item["key_path"],
        )

    console.print()
    console.print("[bold]assay key list[/]")
    console.print(table)
    console.print()
    console.print(f"[dim]Active signer:[/] {active}")


@key_app.command("set-active")
def key_set_active_cmd(
    signer_id: str = typer.Argument(..., help="Signer ID to set active"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Set active signer used by assay run/proof-pack."""
    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    try:
        ks.set_active_signer(signer_id)
    except ValueError as e:
        if output_json:
            _output_json(
                {"command": "key set-active", "status": "error", "error": str(e)},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    fp = ks.signer_fingerprint(signer_id)
    if output_json:
        _output_json(
            {
                "command": "key set-active",
                "status": "ok",
                "active_signer": signer_id,
                "fingerprint": fp,
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Active signer updated[/]\n\n"
            f"Signer:      {signer_id}\n"
            f"Fingerprint: {fp[:16]}...",
            title="assay key set-active",
        )
    )
    console.print()


@key_app.command("rotate")
def key_rotate_cmd(
    signer: Optional[str] = typer.Option(
        None,
        "--signer",
        help="Existing signer to rotate from (default: active signer)",
    ),
    new_signer: Optional[str] = typer.Option(
        None,
        "--new-signer",
        help="Signer ID for new key (default: <signer>-YYYYMMDDHHMMSS)",
    ),
    set_active: bool = typer.Option(
        True,
        "--set-active/--no-set-active",
        help="Set new signer as active after generation",
    ),
    lock: Optional[str] = typer.Option(
        None,
        "--lock",
        help="Optional lockfile path to append old/new signer fingerprints",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a new signer key and optionally switch active signer."""
    from datetime import datetime, timezone
    from pathlib import Path

    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    old_signer = signer or ks.get_active_signer()

    if not ks.has_key(old_signer):
        msg = (
            f"Signer not found: {old_signer}. "
            f"Create it with `assay key generate {old_signer}` "
            f"or pick an existing signer from `assay key list`."
        )
        if output_json:
            _output_json(
                {"command": "key rotate", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    if new_signer is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        new_signer = f"{old_signer}-{ts}"

    if ks.has_key(new_signer):
        msg = f"Signer already exists: {new_signer}"
        if output_json:
            _output_json(
                {"command": "key rotate", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    lock_path: Optional[Path] = None
    if lock:
        lock_path = Path(lock)
        if not lock_path.exists():
            msg = f"Lock file not found: {lock_path}"
            if output_json:
                _output_json(
                    {"command": "key rotate", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

    ks.generate_key(new_signer)
    if set_active:
        ks.set_active_signer(new_signer)

    old_fp = ks.signer_fingerprint(old_signer)
    new_fp = ks.signer_fingerprint(new_signer)

    lock_updated = False
    if lock_path is not None:
        from assay.lockfile import add_signer_fingerprints

        add_signer_fingerprints(lock_path, [old_fp, new_fp])
        lock_updated = True

    active = ks.get_active_signer()
    if output_json:
        _output_json(
            {
                "command": "key rotate",
                "status": "ok",
                "old_signer": old_signer,
                "new_signer": new_signer,
                "active_signer": active,
                "old_fingerprint": old_fp,
                "new_fingerprint": new_fp,
                "lock_updated": lock_updated,
                "lock_path": str(lock_path) if lock_path else None,
            },
            exit_code=0,
        )

    body = (
        f"[bold green]Signer key rotated[/]\n\n"
        f"Old signer:  {old_signer}\n"
        f"Old fp:      {old_fp[:16]}...\n"
        f"New signer:  {new_signer}\n"
        f"New fp:      {new_fp[:16]}...\n"
        f"Active:      {active}"
    )
    if lock_updated:
        body += f"\nLockfile:    {lock_path} (allowlist updated)"
    console.print()
    console.print(Panel.fit(body, title="assay key rotate"))
    console.print()


@key_app.command("generate")
def key_generate_cmd(
    signer_id: str = typer.Argument(
        "assay-local",
        help="Signer ID for the new key (default: assay-local)",
    ),
    set_active: bool = typer.Option(
        True,
        "--set-active/--no-set-active",
        help="Set as active signer after generation",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a new signing key pair."""
    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    if ks.has_key(signer_id):
        msg = f"Signer already exists: {signer_id}. Use `assay key rotate` to create a successor."
        if output_json:
            _output_json(
                {"command": "key generate", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    ks.generate_key(signer_id)
    if set_active:
        ks.set_active_signer(signer_id)

    fp = ks.signer_fingerprint(signer_id)
    active = ks.get_active_signer()

    if output_json:
        _output_json(
            {
                "command": "key generate",
                "status": "ok",
                "signer_id": signer_id,
                "fingerprint": fp,
                "active_signer": active,
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Key generated[/]\n\n"
            f"Signer:      {signer_id}\n"
            f"Fingerprint: {fp[:16]}...\n"
            f"Active:      {active}",
            title="assay key generate",
        )
    )
    console.print()


@key_app.command("info")
def key_info_cmd(
    signer_id: Optional[str] = typer.Argument(
        None,
        help="Signer ID to inspect (default: active signer)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show detailed info about a signer key."""
    import base64

    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    target = signer_id or ks.get_active_signer()

    if not ks.has_key(target):
        msg = f"Signer not found: {target}"
        if output_json:
            _output_json(
                {"command": "key info", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    fp = ks.signer_fingerprint(target)
    pub_bytes = ks.get_verify_key(target).encode()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    active = ks.get_active_signer()
    key_path = str(ks._key_path(target))
    pub_path = str(ks._pub_path(target))

    result = {
        "command": "key info",
        "status": "ok",
        "signer_id": target,
        "algorithm": "Ed25519",
        "fingerprint": fp,
        "pubkey_b64": pub_b64,
        "is_active": target == active,
        "key_path": key_path,
        "pub_path": pub_path,
    }

    if output_json:
        _output_json(result, exit_code=0)

    console.print()
    body = (
        f"Signer:      {target}\n"
        f"Algorithm:   Ed25519\n"
        f"Fingerprint: {fp}\n"
        f"Public key:  {pub_b64}\n"
        f"Active:      {'yes' if target == active else 'no'}\n"
        f"Key file:    {key_path}\n"
        f"Pub file:    {pub_path}"
    )
    console.print(Panel.fit(body, title="assay key info"))
    console.print()


@key_app.command("export")
def key_export_cmd(
    signer_id: Optional[str] = typer.Argument(
        None,
        help="Signer ID to export (default: active signer)",
    ),
    private: bool = typer.Option(
        False,
        "--private",
        help="Include private key (handle with care!)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output directory (default: ./<signer_id>-export/)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Export signer public key (and optionally private key) for backup or CI."""
    import base64
    from pathlib import Path

    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    target = signer_id or ks.get_active_signer()

    if not ks.has_key(target):
        msg = f"Signer not found: {target}"
        if output_json:
            _output_json(
                {"command": "key export", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    out_dir = Path(output) if output else Path(f"{target}-export")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Always export public key
    pub_bytes = ks.get_verify_key(target).encode()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    pub_file = out_dir / f"{target}.pub.b64"
    pub_file.write_text(pub_b64 + "\n")

    # Fingerprint file
    fp = ks.signer_fingerprint(target)
    fp_file = out_dir / f"{target}.fingerprint"
    fp_file.write_text(fp + "\n")

    files_exported = [str(pub_file), str(fp_file)]

    if private:
        key_bytes = ks.get_signing_key(target).encode()
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
        key_file = out_dir / f"{target}.key.b64"
        key_file.write_text(key_b64 + "\n")
        files_exported.append(str(key_file))

    result = {
        "command": "key export",
        "status": "ok",
        "signer_id": target,
        "fingerprint": fp,
        "files": files_exported,
        "includes_private": private,
    }

    if output_json:
        _output_json(result, exit_code=0)

    console.print()
    body = (
        f"[bold green]Key exported[/]\n\n"
        f"Signer:      {target}\n"
        f"Fingerprint: {fp[:16]}...\n"
        f"Files:\n"
    )
    for f in files_exported:
        body += f"  {f}\n"
    if private:
        body += "\n[yellow]Private key included -- store securely![/]"
    console.print(Panel.fit(body, title="assay key export"))
    console.print()


@key_app.command("import")
def key_import_cmd(
    pub_path: str = typer.Argument(..., help="Path to .pub.b64 file"),
    key_path: Optional[str] = typer.Option(
        None,
        "--private",
        help="Path to .key.b64 file (private key)",
    ),
    signer_id: Optional[str] = typer.Option(
        None,
        "--signer",
        help="Signer ID to assign (default: derived from filename)",
    ),
    set_active: bool = typer.Option(
        False,
        "--set-active",
        help="Set imported signer as active",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Import a signer key from exported .b64 files."""
    import base64
    from pathlib import Path

    from nacl.signing import SigningKey, VerifyKey

    from assay.keystore import get_default_keystore

    pub_file = Path(pub_path)
    if not pub_file.exists():
        msg = f"Public key file not found: {pub_path}"
        if output_json:
            _output_json(
                {"command": "key import", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    # Derive signer_id from filename if not given
    if signer_id is None:
        name = pub_file.stem  # e.g. "assay-local.pub" -> "assay-local.pub"
        # Strip ".pub" suffix if present
        if name.endswith(".pub"):
            name = name[:-4]
        signer_id = name

    ks = get_default_keystore()
    if ks.has_key(signer_id):
        msg = f"Signer already exists: {signer_id}. Delete first or use --signer to pick a different ID."
        if output_json:
            _output_json(
                {"command": "key import", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    # Read and validate public key
    try:
        pub_b64 = pub_file.read_text().strip()
        pub_bytes = base64.b64decode(pub_b64)
        VerifyKey(pub_bytes)  # validate
    except Exception as e:
        msg = f"Invalid public key file: {e}"
        if output_json:
            _output_json(
                {"command": "key import", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    has_private = False
    key_bytes = None
    if key_path:
        kf = Path(key_path)
        if not kf.exists():
            msg = f"Private key file not found: {key_path}"
            if output_json:
                _output_json(
                    {"command": "key import", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)
        try:
            key_b64 = kf.read_text().strip()
            key_bytes = base64.b64decode(key_b64)
            SigningKey(key_bytes)  # validate
            has_private = True
        except Exception as e:
            msg = f"Invalid private key file: {e}"
            if output_json:
                _output_json(
                    {"command": "key import", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

    # Write files
    ks.keys_dir.mkdir(parents=True, exist_ok=True)
    ks._pub_path(signer_id).write_bytes(pub_bytes)
    if has_private and key_bytes is not None:
        ks._key_path(signer_id).write_bytes(key_bytes)

    if set_active and has_private:
        ks.set_active_signer(signer_id)

    fp = ks.signer_fingerprint(signer_id)
    active = ks.get_active_signer()

    result = {
        "command": "key import",
        "status": "ok",
        "signer_id": signer_id,
        "fingerprint": fp,
        "has_private": has_private,
        "active_signer": active,
    }

    if output_json:
        _output_json(result, exit_code=0)

    console.print()
    body = (
        f"[bold green]Key imported[/]\n\n"
        f"Signer:      {signer_id}\n"
        f"Fingerprint: {fp[:16]}...\n"
        f"Has private: {'yes' if has_private else 'no (verify only)'}"
    )
    console.print(Panel.fit(body, title="assay key import"))
    console.print()


@key_app.command("revoke")
def key_revoke_cmd(
    signer_id: str = typer.Argument(..., help="Signer ID to revoke"),
    lock: Optional[str] = typer.Option(
        None,
        "--lock",
        help="Lockfile path to remove signer fingerprint from allowlist",
    ),
    delete: bool = typer.Option(
        False,
        "--delete",
        help="Also delete key files from disk",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Revoke a signer key (remove from lockfile allowlist, optionally delete)."""
    from pathlib import Path

    from assay.keystore import get_default_keystore

    ks = get_default_keystore()
    if not ks.has_key(signer_id):
        msg = f"Signer not found: {signer_id}"
        if output_json:
            _output_json(
                {"command": "key revoke", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    fp = ks.signer_fingerprint(signer_id)
    lock_updated = False
    removed_from_allowlist = False

    if lock:
        lock_path = Path(lock)
        if not lock_path.exists():
            msg = f"Lock file not found: {lock_path}"
            if output_json:
                _output_json(
                    {"command": "key revoke", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

        from assay.lockfile import load_lockfile

        lock_data = load_lockfile(lock_path)
        policy = lock_data.get("signer_policy", {})
        allowed = policy.get("allowed_fingerprints", [])
        if fp in allowed:
            allowed.remove(fp)
            policy["allowed_fingerprints"] = allowed
            lock_data["signer_policy"] = policy
            import json

            lock_path.write_text(json.dumps(lock_data, indent=2) + "\n")
            removed_from_allowlist = True
            lock_updated = True

    key_deleted = False
    if delete:
        key_deleted = ks.delete_key(signer_id)

    result = {
        "command": "key revoke",
        "status": "ok",
        "signer_id": signer_id,
        "fingerprint": fp,
        "lock_updated": lock_updated,
        "removed_from_allowlist": removed_from_allowlist,
        "key_deleted": key_deleted,
    }

    if output_json:
        _output_json(result, exit_code=0)

    console.print()
    body = (
        f"[bold yellow]Signer revoked[/]\n\n"
        f"Signer:      {signer_id}\n"
        f"Fingerprint: {fp[:16]}...\n"
    )
    if lock_updated:
        body += "Lockfile:    allowlist updated (fingerprint removed)\n"
    elif lock:
        body += "Lockfile:    fingerprint was not in allowlist\n"
    else:
        body += "Lockfile:    not specified (use --lock to update allowlist)\n"
    if key_deleted:
        body += "Key files:   deleted"
    elif delete:
        body += "Key files:   not found (already deleted)"
    else:
        body += "Key files:   retained (use --delete to remove)"
    console.print(Panel.fit(body, title="assay key revoke"))
    console.print()


# ---------------------------------------------------------------------------
# Lock subcommands
# ---------------------------------------------------------------------------

lock_app = typer.Typer(
    name="lock",
    help="Manage verifier lockfile (assay.lock)",
    no_args_is_help=True,
)
assay_app.add_typer(lock_app, name="lock", hidden=True, rich_help_panel="Operate")


@lock_app.command("write")
def lock_write_cmd(
    cards: str = typer.Option(
        ...,
        "--cards",
        "-c",
        help="Comma-separated RunCard IDs (e.g. receipt_completeness,guardian_enforcement)",
    ),
    signer: Optional[str] = typer.Option(
        None,
        "--signer",
        help="Comma-separated signer pubkey SHA-256 fingerprints for allowlist policy",
    ),
    output: str = typer.Option(
        "assay.lock",
        "--output",
        "-o",
        help="Output path for lockfile",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Write a verifier lockfile that freezes verification semantics."""
    from pathlib import Path

    from assay.lockfile import write_lockfile

    card_ids = [c.strip() for c in cards.split(",") if c.strip()]
    signer_fps = None
    if signer:
        signer_fps = [s.strip() for s in signer.split(",") if s.strip()]

    try:
        lockfile = write_lockfile(
            card_ids,
            signer_fingerprints=signer_fps,
            output_path=Path(output),
        )
    except ValueError as e:
        if output_json:
            _output_json({"command": "lock write", "status": "error", "error": str(e)})
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if output_json:
        _output_json(
            {
                "command": "lock write",
                "status": "ok",
                "output": output,
                "run_cards": len(card_ids),
                "composite_hash": lockfile["run_cards_composite_hash"],
            }
        )
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold green]Lockfile written[/]\n\n"
                f"Path:       {output}\n"
                f"RunCards:    {', '.join(card_ids)}\n"
                f"Composite:  {lockfile['run_cards_composite_hash'][:16]}...\n"
                f"Signer:     {lockfile['signer_policy']['mode']}",
                title="assay lock write",
            )
        )
        console.print()
        console.print(
            "Next: [bold]assay verify-pack <pack_dir> --lock assay.lock --require-claim-pass[/]"
        )
        console.print()


@lock_app.command("check")
def lock_check_cmd(
    path: str = typer.Argument("assay.lock", help="Path to lockfile"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Validate an existing lockfile (structure, card references, hashes)."""
    from pathlib import Path

    from assay.lockfile import check_lockfile

    lock_path = Path(path)
    if not lock_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "lock check",
                    "status": "error",
                    "error": f"Not found: {path}",
                }
            )
        console.print(f"[red]Error:[/] {path} not found")
        raise typer.Exit(1)

    issues = check_lockfile(lock_path)

    if output_json:
        _output_json(
            {
                "command": "lock check",
                "status": "ok" if not issues else "failed",
                "issues": issues,
            }
        )
    elif issues:
        console.print()
        console.print(
            Panel.fit(
                f"[bold red]Lockfile invalid[/]\n\n"
                f"Path:    {path}\n"
                f"Issues:  {len(issues)}",
                title="assay lock check",
            )
        )
        for issue in issues:
            console.print(f"  [red]{issue}[/]")
        console.print()
        raise typer.Exit(1)
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold green]Lockfile valid[/]\n\nPath:  {path}",
                title="assay lock check",
            )
        )
        console.print()


@lock_app.command("init")
def lock_init_cmd(
    output: str = typer.Option(
        "assay.lock",
        "--output",
        "-o",
        help="Output path for lockfile",
    ),
    from_pack: Optional[str] = typer.Option(
        None,
        "--from-pack",
        help="Copy claim_set_hash from an existing Proof Pack directory (avoids hash mismatch).",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Create a lockfile with sane defaults (receipt_completeness card)."""
    from pathlib import Path

    from assay.keystore import get_default_keystore
    from assay.lockfile import write_lockfile
    from assay.manifest_schema import validate_manifest
    from assay.proof_pack import verify_proof_pack

    card_ids = ["receipt_completeness"]
    out_path = Path(output)

    if out_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "lock init",
                    "status": "error",
                    "error": f"Already exists: {output} (use 'assay lock write' to overwrite)",
                }
            )
        console.print(
            f"[red]Error:[/] {output} already exists. Use [bold]assay lock write[/] to overwrite."
        )
        raise typer.Exit(1)

    # If --from-pack, extract claim_set_hash from the existing pack manifest
    pack_claim_set_hash = None
    if from_pack:
        pack_path = Path(from_pack)
        manifest_path = pack_path / "pack_manifest.json"
        if not manifest_path.exists():
            msg = f"No pack_manifest.json in {from_pack}"
            if output_json:
                _output_json({"command": "lock init", "status": "error", "error": msg})
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(1)
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON in {manifest_path}: {e.msg}"
            if output_json:
                _output_json({"command": "lock init", "status": "error", "error": msg})
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(1)

        schema_errors = validate_manifest(manifest)
        if schema_errors:
            msg = (
                f"Cannot import claim_set_hash from unverified pack: {from_pack} "
                f"(schema validation failed)"
            )
            if output_json:
                _output_json(
                    {
                        "command": "lock init",
                        "status": "error",
                        "error": msg,
                        "details": schema_errors,
                    }
                )
            console.print(f"[red]Error:[/] {msg}")
            for se in schema_errors[:5]:
                console.print(f"  [dim]{se}[/]")
            raise typer.Exit(1)

        ks = get_default_keystore()
        verify_result = verify_proof_pack(manifest, pack_path, ks)
        if not verify_result.passed:
            first = verify_result.errors[0] if verify_result.errors else None
            detail = (
                f"{first.code}: {first.message}"
                if first
                else "integrity verification failed"
            )
            msg = (
                f"Cannot import claim_set_hash from unverified pack: "
                f"{from_pack} ({detail})"
            )
            if output_json:
                _output_json(
                    {
                        "command": "lock init",
                        "status": "error",
                        "error": msg,
                    }
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(1)

        pack_claim_set_hash = manifest.get("claim_set_hash")
        if not pack_claim_set_hash:
            msg = f"Pack manifest in {from_pack} has no claim_set_hash"
            if output_json:
                _output_json({"command": "lock init", "status": "error", "error": msg})
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(1)

    try:
        lockfile = write_lockfile(card_ids, output_path=out_path)
    except ValueError as e:
        if output_json:
            _output_json({"command": "lock init", "status": "error", "error": str(e)})
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    # Override claim_set_hash from pack if specified
    if pack_claim_set_hash:
        lockfile["claim_set_hash"] = pack_claim_set_hash
        out_path.write_text(json.dumps(lockfile, indent=2) + "\n")

    if output_json:
        _output_json(
            {
                "command": "lock init",
                "status": "ok",
                "output": output,
                "run_cards": card_ids,
                "composite_hash": lockfile["run_cards_composite_hash"],
                "from_pack": from_pack,
            }
        )
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold green]Lockfile created[/]\n\n"
                f"Path:       {output}\n"
                f"RunCards:    {', '.join(card_ids)}\n"
                f"Composite:  {lockfile['run_cards_composite_hash'][:16]}...\n"
                f"Signer:     {lockfile['signer_policy']['mode']}",
                title="assay lock init",
            )
        )
        console.print()
        console.print(
            'Next: [bold]assay ci init github --run-command "python your_app.py"[/]'
        )
        console.print()


# ---------------------------------------------------------------------------
# Passport subcommands
# ---------------------------------------------------------------------------

from assay.passport_commands import passport_app

assay_app.add_typer(passport_app, name="passport", rich_help_panel="Advanced")

# ---------------------------------------------------------------------------
# Commitment-lifecycle inspection surface (assay commitments ...)
# ---------------------------------------------------------------------------
# NOTE: This is deliberately mounted at name="commitments", NOT "explain".
# The top-level "explain" command name is already owned by the proof-pack
# explainer (@assay_app.command("explain") below); mounting a Typer sub-app
# at "explain" silently shadows that command.

from assay.commitment_explain import commitments_app

assay_app.add_typer(
    commitments_app,
    name="commitments",
    rich_help_panel="Inspect",
)


@assay_app.command("xray", hidden=True, rich_help_panel="Advanced")
def xray_alias_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    report: Optional[str] = typer.Option(
        None, "--report", "-r", help="Output HTML report path"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """X-Ray diagnostic for a passport (alias for 'assay passport xray')."""
    from assay.passport_commands import passport_xray_cmd

    passport_xray_cmd(
        passport_file=passport_file, report=report, output_json=output_json
    )


# ---------------------------------------------------------------------------
# VendorQ subcommands
# ---------------------------------------------------------------------------

vendorq_app = typer.Typer(
    name="vendorq",
    help="Verifiable Vendor Packet: compile and verify questionnaire answers from proof packs",
    no_args_is_help=True,
)
assay_app.add_typer(
    vendorq_app, name="vendorq", hidden=True, rich_help_panel="Compliance & Audit"
)

reviewer_app = typer.Typer(
    name="reviewer",
    help="Reviewer Packet verification and settlement inspection.",
    no_args_is_help=True,
)
assay_app.add_typer(
    reviewer_app, name="reviewer", hidden=True, rich_help_panel="Compliance & Audit"
)

checkpoint_app = typer.Typer(
    name="checkpoint",
    help="Inspect checkpoint attempts",
    no_args_is_help=True,
)
assay_app.add_typer(checkpoint_app, name="checkpoint", rich_help_panel="Operate")

vendorq_lock_app = typer.Typer(
    name="lock",
    help="Manage vendorq.lock",
    no_args_is_help=True,
)
vendorq_app.add_typer(vendorq_lock_app, name="lock")


@checkpoint_app.command("view")
def checkpoint_view_cmd(
    checkpoint_attempt_id: str = typer.Argument(
        ..., help="Checkpoint attempt id to inspect"
    ),
    trace_id: str = typer.Option(
        ..., "--trace", help="Trace ID containing the checkpoint attempt"
    ),
    store_dir: Optional[str] = typer.Option(
        None,
        "--store-dir",
        help="Assay store directory (default: ~/.assay)",
    ),
    decision_receipt_paths: Optional[List[str]] = typer.Option(
        None,
        "--decision-receipt",
        help="Path to a canonical Decision Receipt JSON file (repeatable)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """View one checkpoint attempt as a counterparty-facing read model."""
    from pathlib import Path

    from assay.checkpoint_views import load_outbound_email_checkpoint_attempt_view
    from assay.checkpoints import CheckpointValidationError
    from assay.store import AssayStore

    store = AssayStore(base_dir=Path(store_dir) if store_dir else None)
    trace_entries = store.read_trace(trace_id)
    if not trace_entries:
        msg = f"Trace not found or empty: {trace_id}"
        if output_json:
            _output_json(
                {"command": "checkpoint view", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    decision_receipts: List[Dict[str, Any]] = []
    for receipt_path in decision_receipt_paths or []:
        path = Path(receipt_path)
        if not path.is_file():
            msg = f"Decision Receipt file not found: {receipt_path}"
            if output_json:
                _output_json(
                    {"command": "checkpoint view", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)
        try:
            decision_receipts.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            msg = f"Invalid Decision Receipt JSON at {receipt_path}: {exc}"
            if output_json:
                _output_json(
                    {"command": "checkpoint view", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

    try:
        view = load_outbound_email_checkpoint_attempt_view(
            store,
            trace_id,
            checkpoint_attempt_id=checkpoint_attempt_id,
            decision_receipts=decision_receipts or None,
        )
    except CheckpointValidationError as exc:
        msg = str(exc)
        if output_json:
            _output_json(
                {"command": "checkpoint view", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    payload = {
        "command": "checkpoint view",
        "status": "failed" if view.verification["status"] == "failed" else "ok",
        "trace_id": trace_id,
        **view.to_dict(),
    }

    if output_json:
        _output_json(
            payload, exit_code=2 if view.verification["status"] == "failed" else 0
        )

    console.print()
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Attempt:      {view.checkpoint_attempt_id}",
                    f"Trace:        {view.trace_id or trace_id}",
                    f"Type:         {view.checkpoint_type}",
                    f"Current:      {view.current_state}",
                    f"Verification: {view.verification['status']}",
                ]
            ),
            title="assay checkpoint view",
        )
    )

    attempted = view.attempted_crossing
    intent = attempted["attempt"]["intent"]
    action_target = attempted["attempt"]["action_target"]
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Requested at:  {attempted['requested_at']}",
                    f"Episode:       {attempted['subject']['episode_id']}",
                    f"Actor:         {attempted['subject']['actor_id']} ({attempted['subject']['actor_type']})",
                    f"Purpose:       {intent['purpose']}",
                    f"Target:        {action_target['system']}:{action_target['operation']}",
                    f"Relying party: {attempted['relying_party']['party_id']} ({attempted['relying_party']['role']})",
                    f"Consequence:   {attempted['relying_party']['consequence']}",
                ]
            ),
            title="Attempted Crossing",
        )
    )

    posture = view.last_eligible_posture
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Evaluation:    {posture['evaluation_id']}",
                    f"Evaluated at:  {posture['evaluated_at']}",
                    f"Route:         {posture['route']}",
                    f"Policy:        {posture['policy']['policy_id']}@{posture['policy']['policy_version']}",
                    f"Reason codes:  {', '.join(posture['reason_codes']) if posture['reason_codes'] else 'none'}",
                    f"Release conds: {', '.join(posture['release_conditions']) if posture['release_conditions'] else 'none'}",
                    f"Support:       {posture['uncertainty']['support']:.2f}",
                    f"Freshness:     {posture['uncertainty']['freshness']:.2f}",
                    f"Consensus:     {posture['uncertainty']['consensus']:.2f}",
                    f"Policy margin: {posture['uncertainty']['policy_margin']:.2f}",
                ]
            ),
            title="Last Eligible Posture",
        )
    )

    decision_table = Table(show_header=True, header_style="bold")
    decision_table.add_column("time", style="dim")
    decision_table.add_column("source")
    decision_table.add_column("authority")
    decision_table.add_column("verdict")
    decision_table.add_column("disposition")
    if view.authority_decisions:
        for decision in view.authority_decisions:
            decision_table.add_row(
                str(decision["timestamp"] or ""),
                decision["detail_source"],
                str(decision["authority_id"] or ""),
                str(decision["verdict"] or ""),
                str(decision["disposition"] or ""),
            )
    else:
        decision_table.add_row("-", "none", "-", "-", "-")
    console.print(decision_table)

    outcome = view.actual_outcome
    outcome_lines = [
        f"Status:        {outcome['status']}",
        f"Outcome:       {outcome.get('resolution_outcome') or 'pending'}",
        f"Resolved at:   {outcome.get('resolved_at') or '-'}",
        f"Final eval:    {outcome.get('final_evaluation_id') or '-'}",
        f"Reason codes:  {', '.join(outcome.get('reason_codes') or []) or 'none'}",
    ]
    if outcome.get("human_approval"):
        approval = outcome["human_approval"]
        outcome_lines.append(
            f"Approval:      {approval['decision']} by {approval['approver_id']}"
        )
    if outcome.get("dispatch_attempted_at"):
        outcome_lines.append(f"Dispatch at:   {outcome['dispatch_attempted_at']}")
    if outcome.get("effect_observed_at"):
        outcome_lines.append(f"Effect seen:   {outcome['effect_observed_at']}")
    console.print(Panel.fit("\n".join(outcome_lines), title="Actual Outcome"))

    if view.limitations:
        console.print(
            Panel.fit(
                "\n".join(f"- {item}" for item in view.limitations),
                title="Limitations",
            )
        )
    if view.verification["errors"]:
        console.print(
            Panel.fit(
                "\n".join(f"- {item}" for item in view.verification["errors"]),
                title="Verification Findings",
            )
        )

    raise typer.Exit(2 if view.verification["status"] == "failed" else 0)


@checkpoint_app.command("export-reviewer")
def checkpoint_export_reviewer_cmd(
    checkpoint_attempt_id: str = typer.Argument(
        ..., help="Checkpoint attempt id to package"
    ),
    proof_pack: str = typer.Option(
        ..., "--proof-pack", help="Path to proof pack directory"
    ),
    out: str = typer.Option(
        ..., "--out", "-o", help="Output reviewer packet directory"
    ),
    decision_receipt_paths: Optional[List[str]] = typer.Option(
        None,
        "--decision-receipt",
        help="Path to a canonical Decision Receipt JSON file (repeatable)",
    ),
    sign_packet: bool = typer.Option(
        False,
        "--sign-packet/--no-sign-packet",
        help="Sign the packet manifest with a local Ed25519 key",
    ),
    packet_signer: Optional[str] = typer.Option(
        None,
        "--packet-signer",
        help="Signer ID for packet-manifest signing (default: active signer)",
    ),
    keys_dir: Optional[str] = typer.Option(
        None,
        "--keys-dir",
        help="Optional keystore directory for packet-manifest signing",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compile a reviewer packet for one resolved outbound checkpoint attempt."""
    from pathlib import Path

    from assay.checkpoint_reviewer_packet import compile_checkpoint_reviewer_packet
    from assay.keystore import AssayKeyStore, get_default_keystore
    from assay.vendorq_models import VendorQInputError

    decision_receipts: List[Dict[str, Any]] = []
    for receipt_path in decision_receipt_paths or []:
        path = Path(receipt_path)
        if not path.is_file():
            msg = f"Decision Receipt file not found: {receipt_path}"
            if output_json:
                _output_json(
                    {
                        "command": "checkpoint export-reviewer",
                        "status": "error",
                        "error": msg,
                    },
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)
        try:
            decision_receipts.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            msg = f"Invalid Decision Receipt JSON at {receipt_path}: {exc}"
            if output_json:
                _output_json(
                    {
                        "command": "checkpoint export-reviewer",
                        "status": "error",
                        "error": msg,
                    },
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {msg}")
            raise typer.Exit(3)

    keystore = None
    packet_signer_id = None
    generated_signer = False
    if sign_packet:
        keystore = AssayKeyStore(Path(keys_dir)) if keys_dir else get_default_keystore()
        packet_signer_id = packet_signer or keystore.get_active_signer()
        if not keystore.has_key(packet_signer_id):
            keystore.generate_key(packet_signer_id)
            keystore.set_active_signer(packet_signer_id)
            generated_signer = True

    try:
        result = compile_checkpoint_reviewer_packet(
            proof_pack_dir=Path(proof_pack),
            checkpoint_attempt_id=checkpoint_attempt_id,
            out_dir=Path(out),
            decision_receipts=decision_receipts or None,
            keystore=keystore,
            packet_signer_id=packet_signer_id,
        )
    except VendorQInputError as exc:
        if output_json:
            _output_json(
                {
                    "command": "checkpoint export-reviewer",
                    "status": "error",
                    "error": str(exc),
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "checkpoint export-reviewer",
                "status": "ok",
                "generated_signer": generated_signer,
                "packet_signer_id": packet_signer_id,
                **result,
            },
            exit_code=0,
        )

    ratio = result["machine_coverage"]
    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Checkpoint Reviewer Packet Compiled[/]\n\n"
            f"Attempt:           {checkpoint_attempt_id}\n"
            f"Proof pack:        {proof_pack}\n"
            f"Settlement:        {result['settlement_state']}\n"
            f"Verification:      {result['verification_status']}\n"
            f"Packet manifest:   {'signed' if result['packet_manifest_signed'] else 'unsigned'}"
            f"{f' ({packet_signer_id})' if result['packet_manifest_signed'] and packet_signer_id else ''}\n"
            f"Machine coverage:  {ratio['numerator']}/{ratio['denominator']} ({ratio['value']:.2%})\n"
            f"Limitations:       {len(result['limitations'])}\n"
            f"Output directory:  {out}",
            title="assay checkpoint export-reviewer",
        )
    )
    console.print()


@vendorq_app.command("ingest")
def vendorq_ingest_cmd(
    in_path: str = typer.Option(
        ..., "--in", help="Input questionnaire file (.csv, .md, .xlsx)"
    ),
    source_label: str = typer.Option(
        "",
        "--source-label",
        help="Optional source label stored in payload (defaults to input basename)",
    ),
    out: str = typer.Option(
        ".assay/vendorq/questions.json",
        "--out",
        "-o",
        help="Output normalized questions JSON",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Normalize a questionnaire into vendorq.question.v1 JSON."""
    from pathlib import Path

    from assay.vendorq_ingest import ingest_questionnaire
    from assay.vendorq_models import VendorQInputError

    try:
        payload = ingest_questionnaire(
            Path(in_path), Path(out), source_label=source_label
        )
    except VendorQInputError as e:
        if output_json:
            _output_json(
                {
                    "command": "vendorq ingest",
                    "status": "error",
                    "error": str(e),
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "vendorq ingest",
                "status": "ok",
                "output": out,
                "schema_version": payload["schema_version"],
                "question_count": len(payload["questions"]),
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]VendorQ Questionnaire Ingested[/]\n\n"
            f"Input:      {in_path}\n"
            f"Output:     {out}\n"
            f"Questions:  {len(payload['questions'])}",
            title="assay vendorq ingest",
        )
    )
    console.print()


@vendorq_app.command("compile")
def vendorq_compile_cmd(
    questions: str = typer.Option(
        ..., "--questions", help="Path to vendorq.question.v1 JSON"
    ),
    pack: Optional[List[str]] = typer.Option(
        None, "--pack", help="Proof pack directory (repeatable)"
    ),
    policy: str = typer.Option(
        "conservative", "--policy", help="Policy profile: conservative|balanced"
    ),
    org_profile: Optional[str] = typer.Option(
        None, "--org-profile", help="Optional organization profile JSON"
    ),
    out: str = typer.Option(
        ".assay/vendorq/answers.json", "--out", "-o", help="Output answers JSON"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compile vendor questionnaire answers from questions + evidence packs."""
    from pathlib import Path

    from assay.vendorq_compile import compile_answers_payload
    from assay.vendorq_index import build_evidence_index
    from assay.vendorq_models import (
        VendorQInputError,
        canonical_sha256,
        load_json,
        validate_vendorq_schema,
        write_json,
    )

    try:
        questions_payload = load_json(Path(questions))
        validate_vendorq_schema("vendorq.question.v1.schema.json", questions_payload)
        questions_payload["questions_hash"] = canonical_sha256(
            questions_payload["questions"]
        )

        pack_dirs = [Path(p) for p in (pack or [])]
        evidence_index = (
            build_evidence_index(pack_dirs)
            if pack_dirs
            else {"packs": [], "by_pack": {}}
        )
        org = load_json(Path(org_profile)) if org_profile else None
        answers_payload = compile_answers_payload(
            questions_payload=questions_payload,
            evidence_index=evidence_index,
            policy_profile_name=policy,
            org_profile=org,
        )
        write_json(Path(out), answers_payload)
    except VendorQInputError as e:
        if output_json:
            _output_json(
                {"command": "vendorq compile", "status": "error", "error": str(e)},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "vendorq compile",
                "status": "ok",
                "output": out,
                "answer_count": len(answers_payload["answers"]),
                "policy_profile": answers_payload["policy_profile"],
                "questions_hash": answers_payload["questions_hash"],
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]VendorQ Answers Compiled[/]\n\n"
            f"Questions:      {questions}\n"
            f"Policy:         {answers_payload['policy_profile']}\n"
            f"Answer count:   {len(answers_payload['answers'])}\n"
            f"Output:         {out}",
            title="assay vendorq compile",
        )
    )
    console.print()


@vendorq_app.command("verify")
def vendorq_verify_cmd(
    answers: str = typer.Option(
        ..., "--answers", help="Path to vendorq.answer.v1 JSON"
    ),
    pack: List[str] = typer.Option(
        ..., "--pack", help="Proof pack directory (repeatable)"
    ),
    lock: Optional[str] = typer.Option(None, "--lock", help="Path to vendorq.lock"),
    strict: bool = typer.Option(
        False, "--strict", help="Treat stale evidence as errors"
    ),
    report_out: str = typer.Option(
        ".assay/vendorq/verify_report.json",
        "--report-out",
        help="Write verify report JSON",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify vendor questionnaire answers against evidence packs and lockfile."""
    from pathlib import Path

    from assay.vendorq_index import build_evidence_index
    from assay.vendorq_lock import load_vendorq_lock
    from assay.vendorq_models import VendorQInputError, load_json, write_json
    from assay.vendorq_verify import verify_answers_payload

    try:
        answers_payload = load_json(Path(answers))
        evidence_index = build_evidence_index([Path(p) for p in pack])
        policy_name = str(answers_payload.get("policy_profile", "conservative"))
        lock_payload = load_vendorq_lock(Path(lock)) if lock else None
        report = verify_answers_payload(
            answers_payload=answers_payload,
            evidence_index=evidence_index,
            policy_name=policy_name,
            strict=bool(strict),
            lock_payload=lock_payload,
        )
        write_json(Path(report_out), report)
    except VendorQInputError as e:
        if output_json:
            _output_json(
                {"command": "vendorq verify", "status": "error", "error": str(e)},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    failed = report["status"] != "ok"
    exit_code = 2 if failed else 0

    if output_json:
        _output_json(
            {
                "command": "vendorq verify",
                **report,
                "report_out": report_out,
            },
            exit_code=exit_code,
        )

    color = "green" if not failed else "red"
    console.print()
    console.print(
        Panel.fit(
            f"[bold {color}]VENDORQ {'VERIFICATION PASSED' if not failed else 'VERIFICATION FAILED'}[/]\n\n"
            f"Answers:          {answers}\n"
            f"Strict mode:      {strict}\n"
            f"Errors:           {report['summary']['errors']}\n"
            f"Warnings:         {report['summary']['warnings']}\n"
            f"Evidence chains:  {len(report.get('evidence_navigation', []))}\n"
            f"Report:           {report_out}",
            title="assay vendorq verify",
        )
    )
    if failed:
        for err in report.get("errors", [])[:20]:
            console.print(f"  [red]{err['code']}[/]: {err['message']}")
        console.print()
        raise typer.Exit(2)
    console.print()


@vendorq_app.command("export")
def vendorq_export_cmd(
    answers: str = typer.Option(
        ..., "--answers", help="Path to vendorq.answer.v1 JSON"
    ),
    format: str = typer.Option(..., "--format", help="Export format: json|md"),
    out: str = typer.Option(..., "--out", "-o", help="Output file path"),
    verify_report: Optional[str] = typer.Option(
        None, "--verify-report", help="Optional vendorq.verify_report.v1 JSON"
    ),
    coverage_out: Optional[str] = typer.Option(
        None, "--coverage-out", help="Optional vendorq.coverage_receipt.v1 JSON sidecar"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Export answers to JSON or Markdown auditor packet."""
    from pathlib import Path

    from assay.vendorq_export import export_answers
    from assay.vendorq_models import VendorQInputError, load_json

    try:
        answers_payload = load_json(Path(answers))
        verify_payload = load_json(Path(verify_report)) if verify_report else None
        export_answers(
            answers_payload=answers_payload,
            fmt=format,
            out_path=Path(out),
            verify_report=verify_payload,
            coverage_out_path=Path(coverage_out) if coverage_out else None,
        )
    except VendorQInputError as e:
        if output_json:
            _output_json(
                {"command": "vendorq export", "status": "error", "error": str(e)},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "vendorq export",
                "status": "ok",
                "format": format,
                "output": out,
                "coverage_output": coverage_out,
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]VendorQ Export Complete[/]\n\n"
            f"Input:    {answers}\n"
            f"Format:   {format}\n"
            f"Output:   {out}\n"
            f"Coverage: {coverage_out or '(not written)'}",
            title="assay vendorq export",
        )
    )
    console.print()


@vendorq_app.command("export-reviewer")
def vendorq_export_reviewer_cmd(
    proof_pack: str = typer.Option(
        ..., "--proof-pack", help="Path to proof pack directory"
    ),
    boundary: str = typer.Option(
        ..., "--boundary", help="Path to reviewer packet boundary JSON"
    ),
    mapping: str = typer.Option(
        ..., "--mapping", help="Path to reviewer packet question mapping JSON"
    ),
    out: str = typer.Option(
        ..., "--out", "-o", help="Output reviewer packet directory"
    ),
    baseline: Optional[str] = typer.Option(
        None, "--baseline", help="Optional baseline reviewer packet directory"
    ),
    challenge_receipt: Optional[str] = typer.Option(
        None,
        "--challenge-receipt",
        help="Optional challenge receipt path for refreshed packets",
    ),
    sign_packet: bool = typer.Option(
        False,
        "--sign-packet/--no-sign-packet",
        help="Sign the packet manifest with a local Ed25519 key",
    ),
    packet_signer: Optional[str] = typer.Option(
        None,
        "--packet-signer",
        help="Signer ID for packet-manifest signing (default: active signer)",
    ),
    keys_dir: Optional[str] = typer.Option(
        None,
        "--keys-dir",
        help="Optional keystore directory for packet-manifest signing",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Experimental: compile a reviewer packet from a proof pack plus declarative packet inputs."""
    from pathlib import Path

    from assay.keystore import AssayKeyStore, get_default_keystore
    from assay.reviewer_packet_compile import compile_reviewer_packet
    from assay.vendorq_models import VendorQInputError, load_json

    keystore = None
    packet_signer_id = None
    generated_signer = False
    if sign_packet:
        keystore = AssayKeyStore(Path(keys_dir)) if keys_dir else get_default_keystore()
        packet_signer_id = packet_signer or keystore.get_active_signer()
        if not keystore.has_key(packet_signer_id):
            keystore.generate_key(packet_signer_id)
            keystore.set_active_signer(packet_signer_id)
            generated_signer = True

    try:
        result = compile_reviewer_packet(
            proof_pack_dir=Path(proof_pack),
            boundary_payload=load_json(Path(boundary)),
            mapping_payload=load_json(Path(mapping)),
            out_dir=Path(out),
            baseline_packet_dir=Path(baseline) if baseline else None,
            keystore=keystore,
            packet_signer_id=packet_signer_id,
            packet_overrides=(
                {
                    "challenge_receipt_ref": challenge_receipt,
                    "challenge_status": "REFRESHED",
                }
                if challenge_receipt
                else None
            ),
        )
    except VendorQInputError as e:
        if output_json:
            _output_json(
                {
                    "command": "vendorq export-reviewer",
                    "status": "error",
                    "error": str(e),
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "vendorq export-reviewer",
                "status": "ok",
                "generated_signer": generated_signer,
                "packet_signer_id": packet_signer_id,
                **result,
            },
            exit_code=0,
        )

    coverage_summary = Counter(row["Status"] for row in result["coverage_rows"])
    ratio = _machine_coverage_ratio(dict(coverage_summary))
    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Reviewer Packet Compiled[/]\n\n"
            f"Proof pack:        {proof_pack}\n"
            f"Boundary:          {boundary}\n"
            f"Mapping:           {mapping}\n"
            f"Settlement:        {result['settlement_state']}\n"
            f"Packet manifest:   {'signed' if result['packet_manifest_signed'] else 'unsigned'}"
            f"{f' ({packet_signer_id})' if result['packet_manifest_signed'] and packet_signer_id else ''}\n"
            f"Machine coverage:  {ratio['numerator']}/{ratio['denominator']} ({ratio['value']:.2%})\n"
            f"Coverage rows:     {len(result['coverage_rows'])}\n"
            f"Output directory:  {out}",
            title="assay vendorq export-reviewer",
        )
    )
    console.print()


@reviewer_app.command("census")
def reviewer_census_cmd(
    packet_dir: str = typer.Argument(..., help="Path to Reviewer Packet directory"),
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Optional output directory for the census bundle"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Build a Decision Census report from a compiled reviewer packet."""
    from pathlib import Path

    from assay.reporting.decision_census import (
        build_decision_census_report,
        write_report,
    )
    from assay.vendorq_models import VendorQInputError

    packet_path = Path(packet_dir)
    out_dir = Path(out) if out else packet_path / "decision_census"

    try:
        report = build_decision_census_report(packet_path)
        bundle = write_report(report, out_dir)
    except VendorQInputError as exc:
        if output_json:
            _output_json(
                {
                    "command": "reviewer census",
                    "status": "error",
                    "error": str(exc),
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "reviewer census",
                "status": "ok",
                "report_id": report["report_id"],
                "output_dir": bundle["output_dir"],
                "gap_output_dir": bundle.get("gap_output_dir"),
                "gap_report_id": bundle.get("gap_report_id"),
                "gap_count": bundle.get("gap_count", 0),
                "coverage_summary": report["coverage_summary"],
                "decision_point_count": len(report["decision_points"]),
                "unsupported_surfaces": report.get("unsupported_surfaces", []),
                "inventory": report.get("inventory", {}),
            },
            exit_code=0,
        )

    summary = report["coverage_summary"]
    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Decision Census Report Built[/]\n\n"
            f"Packet:           {packet_dir}\n"
            f"Inventory basis:  {report.get('inventory', {}).get('basis', 'unknown')}\n"
            f"Coverage state:   {summary['coverage_state']}\n"
            f"Coverage ratio:   {summary['coverage_ratio']:.2f}\n"
            f"Expected points:  {summary['expected_count']}\n"
            f"Observed points:  {summary['observed_count']}\n"
            f"Missing points:   {summary['missing_count']}\n"
            f"Gaps emitted:     {bundle.get('gap_count', 0)}\n"
            f"Output directory: {bundle['output_dir']}",
            title="assay reviewer census",
        )
    )
    console.print()


@reviewer_app.command("census-gate")
def reviewer_census_gate_cmd(
    input_path: str = typer.Argument(
        ..., help="Path to a Decision Gaps JSON file or census output directory"
    ),
    max_missing: int = typer.Option(
        0, "--max-missing", help="Maximum allowed missing gaps before fail"
    ),
    max_uncertain: int = typer.Option(
        0, "--max-uncertain", help="Maximum allowed uncertain gaps before warn"
    ),
    max_total_gaps: int = typer.Option(
        0, "--max-total-gaps", help="Maximum allowed total gaps before fail"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Evaluate a Decision Gaps artifact against soft coverage thresholds."""
    from pathlib import Path

    from assay.reporting.decision_census import evaluate_gap_thresholds, load_gap_report
    from assay.vendorq_models import VendorQInputError

    try:
        gap_report = load_gap_report(Path(input_path))
        result = evaluate_gap_thresholds(
            gap_report,
            max_missing=max_missing,
            max_uncertain=max_uncertain,
            max_total_gaps=max_total_gaps,
        )
    except VendorQInputError as exc:
        if output_json:
            _output_json(
                {
                    "command": "reviewer census-gate",
                    "status": "error",
                    "error": str(exc),
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(3)

    exit_code = (
        0 if result["status"] == "pass" else 1 if result["status"] == "warn" else 2
    )
    if output_json:
        _output_json(
            {
                "command": "reviewer census-gate",
                "status": result["status"],
                **result,
            },
            exit_code=exit_code,
        )

    color = (
        "green"
        if result["status"] == "pass"
        else "yellow"
        if result["status"] == "warn"
        else "red"
    )
    console.print()
    console.print(
        Panel.fit(
            f"[bold {color}]Decision Census Gate[/]\n\n"
            f"Input:        {input_path}\n"
            f"Status:       {result['status']}\n"
            f"Gap count:    {result['gap_summary'].get('gap_count', 0)}\n"
            f"Missing:      {result['gap_summary'].get('missing_count', 0)}\n"
            f"Uncertain:    {result['gap_summary'].get('uncertain_count', 0)}\n"
            f"Thresholds:   max_missing={max_missing}, max_uncertain={max_uncertain}, max_total_gaps={max_total_gaps}",
            title="assay reviewer census-gate",
            border_style=color,
        )
    )
    if result["reasons"]:
        console.print()
        console.print("[bold]Reasons:[/]")
        for reason in result["reasons"]:
            console.print(f"  - {reason}")
    console.print()
    raise typer.Exit(exit_code)


@reviewer_app.command("verify")
def reviewer_verify_cmd(
    packet_dir: str = typer.Argument(..., help="Path to Reviewer Packet directory"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a Reviewer Packet and derive a single reviewer-facing settlement verdict."""
    from pathlib import Path

    from assay.reviewer_packet_verify import verify_reviewer_packet
    from assay.vendorq_models import VendorQInputError

    try:
        result = verify_reviewer_packet(Path(packet_dir))
    except VendorQInputError as exc:
        if output_json:
            _output_json(
                {
                    "command": "reviewer verify",
                    "status": "error",
                    "error": str(exc),
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(3)

    status = "ok" if result["packet_verified"] else "failed"
    payload = {
        "command": "reviewer verify",
        "status": status,
        **result,
    }
    if output_json:
        _output_json(payload, exit_code=0 if result["packet_verified"] else 2)

    coverage_summary = (
        ", ".join(
            f"{name}={count}"
            for name, count in sorted(result["coverage_summary"].items())
        )
        or "none"
    )
    ratio = _machine_coverage_ratio(result["coverage_summary"])
    console.print()
    console.print(
        Panel.fit(
            f"[bold]{'Reviewer Packet Verified' if result['packet_verified'] else 'Reviewer Packet Failed'}[/]\n\n"
            f"Packet:            {result['packet_id']}\n"
            f"Settlement:        {result['settlement_state']}\n"
            f"Interpretation:    {result['settlement_reason']}\n"
            f"Nested proof pack: {'PASS' if result['proof_pack']['verified'] else 'FAIL'}\n"
            f"Claims:            {result['claim_state']}\n"
            f"Scope:             {result['scope_state']}\n"
            f"Freshness:         {result['freshness_state']}\n"
            f"Regression:        {result['regression_state']}\n"
            f"Machine coverage:  {ratio['numerator']}/{ratio['denominator']} ({ratio['value']:.2%})\n"
            f"Coverage:          {coverage_summary}",
            title="assay reviewer verify",
            border_style="green" if result["packet_verified"] else "red",
        )
    )

    if result["errors"]:
        console.print()
        console.print("[bold red]Errors:[/]")
        for error in result["errors"][:10]:
            console.print(f"  - {error}")

    if result["warnings"]:
        console.print()
        console.print("[bold yellow]Warnings:[/]")
        for warning in result["warnings"][:10]:
            console.print(f"  - {warning}")

    raise typer.Exit(0 if result["packet_verified"] else 2)


@reviewer_app.command("packet")
def reviewer_packet_cmd(
    input_dir: str = typer.Option(
        ..., "--input", "-i", help="Path to compiled Reviewer Packet directory"
    ),
    output: str = typer.Option(..., "--output", "-o", help="Output HTML file path"),
):
    """Render a compiled Reviewer Packet as a self-contained HTML file."""
    from pathlib import Path

    from assay.packet_render import PacketRenderError, render_packet_html

    packet_dir = Path(input_dir)
    output_path = Path(output)

    try:
        html = render_packet_html(packet_dir)
    except PacketRenderError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(3)
    except Exception as exc:
        console.print(f"[red]Unexpected error:[/] {exc}")
        raise typer.Exit(1)

    output_path.write_text(html, encoding="utf-8")

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Reviewer Packet HTML rendered[/]\n\n"
            f"Input:  {packet_dir}\n"
            f"Output: {output_path}",
            title="assay reviewer packet",
        )
    )


@reviewer_app.command("challenge")
def reviewer_challenge_cmd(
    packet_dir: str = typer.Argument(..., help="Path to Reviewer Packet directory"),
    reason: str = typer.Option(
        ..., "--reason", help="Why the reviewer is challenging the packet"
    ),
    claim_ref: Optional[str] = typer.Option(
        None, "--claim-ref", help="Optional claim or question reference"
    ),
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Optional output challenge receipt path"
    ),
    signer_id: Optional[str] = typer.Option(
        None, "--signer-id", help="Signer identity for the challenge receipt"
    ),
    keys_dir: Optional[str] = typer.Option(
        None, "--keys-dir", help="Optional keystore directory"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Create a signed reviewer challenge receipt without introducing workflow software."""
    from pathlib import Path

    from assay.keystore import AssayKeyStore
    from assay.reviewer_packet_events import (
        build_reviewer_challenge,
        write_reviewer_challenge,
    )

    keystore = AssayKeyStore(Path(keys_dir)) if keys_dir else AssayKeyStore()
    payload = build_reviewer_challenge(
        packet_dir=Path(packet_dir),
        reason=reason,
        claim_ref=claim_ref,
        signer_id=signer_id,
        keystore=keystore,
    )
    destination = write_reviewer_challenge(
        Path(packet_dir), payload, out_path=Path(out) if out else None
    )

    if output_json:
        _output_json(
            {
                "command": "reviewer challenge",
                "status": "ok",
                "receipt_path": str(destination),
                "challenge_id": payload["challenge_id"],
                "packet_ref": payload["packet_ref"],
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Reviewer Challenge Created[/]\n\n"
            f"Packet:       {packet_dir}\n"
            f"Challenge ID: {payload['challenge_id']}\n"
            f"Reason:       {reason}\n"
            f"Receipt:      {destination}",
            title="assay reviewer challenge",
        )
    )
    console.print()
    raise typer.Exit(0)


@assay_app.command("attest", hidden=True, rich_help_panel="Advanced")
def attest_cmd(
    question: str = typer.Option(
        ..., "--question", help="Reviewer-facing question or claim"
    ),
    assertion: str = typer.Option(
        ..., "--assertion", help="Human assertion to package"
    ),
    attester: str = typer.Option(..., "--attester", help="Named human attester"),
    pack: str = typer.Option(
        ...,
        "--pack",
        help="Proof-pack or packet directory to attach the attestation beside",
    ),
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Optional output attestation path"
    ),
    signer_id: Optional[str] = typer.Option(
        None, "--signer-id", help="Signer identity for the attestation receipt"
    ),
    keys_dir: Optional[str] = typer.Option(
        None, "--keys-dir", help="Optional keystore directory"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Create a thin HUMAN_ATTESTED receipt that stays visibly separate from machine evidence."""
    from pathlib import Path

    from assay.keystore import AssayKeyStore
    from assay.reviewer_packet_events import (
        build_human_attestation,
        write_human_attestation,
    )

    keystore = AssayKeyStore(Path(keys_dir)) if keys_dir else AssayKeyStore()
    payload = build_human_attestation(
        question=question,
        assertion=assertion,
        attester=attester,
        signer_id=signer_id,
        keystore=keystore,
    )
    destination = write_human_attestation(
        Path(pack), payload, out_path=Path(out) if out else None
    )

    if output_json:
        _output_json(
            {
                "command": "attest",
                "status": "ok",
                "receipt_path": str(destination),
                "attestation_id": payload["attestation_id"],
                "evidence_type": payload["evidence_type"],
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Human Attestation Created[/]\n\n"
            f"Question:      {question}\n"
            f"Attester:      {attester}\n"
            f"Evidence type: {payload['evidence_type']}\n"
            f"Receipt:       {destination}",
            title="assay attest",
        )
    )
    console.print()
    raise typer.Exit(0)


@vendorq_lock_app.command("write")
def vendorq_lock_write_cmd(
    answers: str = typer.Option(
        ..., "--answers", help="Path to vendorq.answer.v1 JSON"
    ),
    pack: List[str] = typer.Option(
        ..., "--pack", help="Proof pack directory (repeatable)"
    ),
    out: str = typer.Option("vendorq.lock", "--out", "-o", help="Output lock path"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Write vendorq.lock with pinned questions/answers/policy and pack digests."""
    from pathlib import Path

    from assay.vendorq_index import build_evidence_index
    from assay.vendorq_lock import lock_fingerprint, write_vendorq_lock
    from assay.vendorq_models import VendorQInputError, load_json

    try:
        answers_payload = load_json(Path(answers))
        evidence_index = build_evidence_index([Path(p) for p in pack])
        lock_payload = write_vendorq_lock(answers_payload, evidence_index, Path(out))
    except VendorQInputError as e:
        if output_json:
            _output_json(
                {"command": "vendorq lock write", "status": "error", "error": str(e)},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "vendorq lock write",
                "status": "ok",
                "output": out,
                "fingerprint": lock_fingerprint(lock_payload),
                "pack_count": len(lock_payload["pack_digests"]),
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]vendorq.lock written[/]\n\n"
            f"Path:         {out}\n"
            f"Policy:       {lock_payload['policy_profile']}\n"
            f"Pack digests: {len(lock_payload['pack_digests'])}",
            title="assay vendorq lock write",
        )
    )
    console.print()


ci_app = typer.Typer(
    name="ci",
    help="Generate CI workflows for Assay verification",
    no_args_is_help=True,
)
assay_app.add_typer(ci_app, name="ci", hidden=True, rich_help_panel="Operate")


# ---------------------------------------------------------------------------
# baseline subcommands
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Packs subcommands
# ---------------------------------------------------------------------------

packs_app = typer.Typer(
    name="packs",
    help="Browse and manage local proof packs",
    no_args_is_help=True,
)
assay_app.add_typer(packs_app, name="packs", hidden=True, rich_help_panel="Operate")


def _discover_packs(search_dir: Optional[str] = None):
    """Find all proof packs in a directory. Returns list of (path, manifest) sorted by mtime desc."""
    import json as _json
    from pathlib import Path

    root = Path(search_dir) if search_dir else Path(".")
    packs = []
    for d in root.iterdir():
        if not d.is_dir() or not d.name.startswith("proof_pack"):
            continue
        manifest_path = d / "pack_manifest.json"
        if not manifest_path.exists():
            continue
        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
            packs.append((d, manifest))
        except Exception:
            continue
    packs.sort(key=lambda t: t[0].stat().st_mtime, reverse=True)
    return packs


@packs_app.command("list")
def packs_list_cmd(
    directory: Optional[str] = typer.Option(
        None,
        "-d",
        "--directory",
        help="Directory to search (default: cwd)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List all proof packs in the current directory."""
    from assay.diff import load_baseline

    packs = _discover_packs(directory)
    baseline = load_baseline()
    baseline_resolved = baseline.resolve() if baseline else None

    items = []
    for pack_dir, manifest in packs:
        att = manifest.get("attestation", {})
        is_baseline = (
            baseline_resolved is not None and pack_dir.resolve() == baseline_resolved
        )
        items.append(
            {
                "path": str(pack_dir),
                "pack_id": manifest.get("pack_id", "unknown"),
                "n_receipts": att.get("n_receipts", 0),
                "receipt_integrity": att.get("receipt_integrity", "unknown"),
                "claim_check": att.get("claim_check", "N/A"),
                "signer_id": manifest.get("signer_id", "unknown"),
                "timestamp": att.get("timestamp_start", ""),
                "is_baseline": is_baseline,
            }
        )

    if output_json:
        _output_json(
            {
                "command": "packs list",
                "status": "ok",
                "count": len(items),
                "packs": items,
            },
            exit_code=0,
        )

    if not items:
        console.print("No proof packs found. Create one with [bold]assay run[/].")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("", width=3)
    table.add_column("pack_id", style="cyan")
    table.add_column("receipts", justify="right")
    table.add_column("integrity")
    table.add_column("claims")
    table.add_column("signer", style="dim")
    table.add_column("timestamp", style="dim")

    for item in items:
        marker = "B" if item["is_baseline"] else ""
        integrity_style = "green" if item["receipt_integrity"] == "PASS" else "red"
        claim_style = (
            "green"
            if item["claim_check"] == "PASS"
            else ("yellow" if item["claim_check"] == "N/A" else "red")
        )
        table.add_row(
            marker,
            item["pack_id"],
            str(item["n_receipts"]),
            f"[{integrity_style}]{item['receipt_integrity']}[/]",
            f"[{claim_style}]{item['claim_check']}[/]",
            item["signer_id"],
            item["timestamp"][:19] if item["timestamp"] else "",
        )

    console.print()
    console.print("[bold]assay packs list[/]")
    console.print(table)
    if any(i["is_baseline"] for i in items):
        console.print("[dim]B = current diff baseline[/]")
    console.print()


@packs_app.command("show")
def packs_show_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show detailed metadata for a proof pack."""
    import json as _json
    from pathlib import Path

    p = Path(pack_dir)
    if not p.is_dir():
        msg = f"Not a directory: {pack_dir}"
        if output_json:
            _output_json(
                {"command": "packs show", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    manifest_path = p / "pack_manifest.json"
    if not manifest_path.exists():
        msg = f"No pack_manifest.json in {pack_dir}"
        if output_json:
            _output_json(
                {"command": "packs show", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    att = manifest.get("attestation", {})

    # Count actual receipt lines
    receipt_file = p / "receipt_pack.jsonl"
    actual_receipts = 0
    if receipt_file.exists():
        actual_receipts = sum(
            1 for line in receipt_file.read_text().splitlines() if line.strip()
        )

    # Check baseline
    from assay.diff import load_baseline

    baseline = load_baseline()
    is_baseline = baseline is not None and p.resolve() == baseline.resolve()

    # File inventory
    files = []
    for f_info in manifest.get("files", []):
        files.append(
            {
                "path": f_info["path"],
                "sha256": f_info.get("sha256", "")[:16] + "...",
                "bytes": f_info.get("bytes", 0),
            }
        )

    result = {
        "command": "packs show",
        "status": "ok",
        "path": str(p),
        "pack_id": manifest.get("pack_id", "unknown"),
        "pack_version": manifest.get("pack_version", "unknown"),
        "run_id": att.get("run_id", "unknown"),
        "n_receipts": att.get("n_receipts", 0),
        "actual_receipt_lines": actual_receipts,
        "receipt_integrity": att.get("receipt_integrity", "unknown"),
        "claim_check": att.get("claim_check", "N/A"),
        "assurance_level": att.get("assurance_level", "unknown"),
        "mode": att.get("mode", "unknown"),
        "signer_id": manifest.get("signer_id", "unknown"),
        "fingerprint": manifest.get("signer_pubkey_sha256", "")[:16] + "...",
        "signature_alg": manifest.get("signature_alg", "unknown"),
        "timestamp_start": att.get("timestamp_start", ""),
        "timestamp_end": att.get("timestamp_end", ""),
        "verifier_version": att.get("verifier_version", "unknown"),
        "is_baseline": is_baseline,
        "files": files,
    }

    if output_json:
        _output_json(result, exit_code=0)

    console.print()
    integrity_style = "green" if att.get("receipt_integrity") == "PASS" else "red"
    claim_style = (
        "green"
        if att.get("claim_check") == "PASS"
        else ("yellow" if att.get("claim_check") == "N/A" else "red")
    )

    body = (
        f"Pack ID:       {result['pack_id']}\n"
        f"Path:          {result['path']}\n"
        f"Run ID:        {result['run_id']}\n"
        f"Version:       {result['pack_version']}\n"
        f"Receipts:      {result['n_receipts']} (manifest) / {actual_receipts} (on disk)\n"
        f"Integrity:     [{integrity_style}]{result['receipt_integrity']}[/]\n"
        f"Claims:        [{claim_style}]{result['claim_check']}[/]\n"
        f"Assurance:     {result['assurance_level']}\n"
        f"Mode:          {result['mode']}\n"
        f"Signer:        {result['signer_id']} ({result['fingerprint']})\n"
        f"Algorithm:     {result['signature_alg']}\n"
        f"Time:          {result['timestamp_start'][:19]} .. {result['timestamp_end'][:19]}\n"
        f"Assay version: {result['verifier_version']}"
    )
    if is_baseline:
        body += "\nBaseline:      yes (current diff baseline)"

    console.print(Panel.fit(body, title="assay packs show"))

    if files:
        ft = Table(show_header=True, header_style="bold")
        ft.add_column("file")
        ft.add_column("sha256", style="dim")
        ft.add_column("bytes", justify="right")
        for f in files:
            ft.add_row(f["path"], f["sha256"], str(f["bytes"]))
        console.print(ft)
    console.print()


@packs_app.command("pin-baseline")
def packs_pin_baseline_cmd(
    pack_dir: str = typer.Argument(
        ..., help="Path to proof pack directory to pin as baseline"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Pin a proof pack as the diff baseline (alias for baseline set)."""
    from pathlib import Path

    from assay.diff import save_baseline

    p = Path(pack_dir)
    if not p.is_dir():
        msg = f"Not a directory: {pack_dir}"
        if output_json:
            _output_json(
                {"command": "packs pin-baseline", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    if not (p / "pack_manifest.json").exists():
        msg = f"No pack_manifest.json in {pack_dir}"
        if output_json:
            _output_json(
                {"command": "packs pin-baseline", "status": "error", "error": msg},
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    bf = save_baseline(p)
    if output_json:
        _output_json(
            {
                "command": "packs pin-baseline",
                "status": "ok",
                "pack_path": str(p.resolve()),
                "baseline_file": str(bf),
            },
            exit_code=0,
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Baseline pinned[/]\n\nPack:      {p}\nStored in: {bf}",
            title="assay packs pin-baseline",
        )
    )
    console.print("Next: [bold]assay diff <new_pack> --against-previous[/]")
    console.print()


baseline_app = typer.Typer(
    name="baseline",
    help="Manage the diff baseline pack pointer (.assay/baseline.json)",
    no_args_is_help=True,
)
assay_app.add_typer(
    baseline_app, name="baseline", hidden=True, rich_help_panel="Operate"
)


@baseline_app.command("set")
def baseline_set_cmd(
    pack_dir: str = typer.Argument(
        ..., help="Path to proof pack directory to use as baseline"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Save a proof pack as the diff baseline."""
    from pathlib import Path

    from assay.diff import save_baseline

    p = Path(pack_dir)
    if not p.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "baseline set",
                    "status": "error",
                    "error": f"Not a directory: {pack_dir}",
                }
            )
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not (p / "pack_manifest.json").exists():
        if output_json:
            _output_json(
                {
                    "command": "baseline set",
                    "status": "error",
                    "error": f"No pack_manifest.json in {pack_dir}",
                }
            )
        console.print(f"[red]Error:[/] No pack_manifest.json found in {pack_dir}")
        raise typer.Exit(3)

    bf = save_baseline(p)
    if output_json:
        _output_json(
            {
                "command": "baseline set",
                "status": "ok",
                "pack_path": str(p.resolve()),
                "baseline_file": str(bf),
            }
        )
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold green]Baseline set[/]\n\nPack:      {p}\nStored in: {bf}",
                title="assay baseline set",
            )
        )
        console.print()
        console.print("Next: [bold]assay diff <new_pack> --against-previous[/]")
        console.print()


@baseline_app.command("get")
def baseline_get_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show the current diff baseline pack."""
    from assay.diff import load_baseline

    baseline = load_baseline()
    if baseline is None:
        if output_json:
            _output_json(
                {"command": "baseline get", "status": "none", "pack_path": None}
            )
        else:
            console.print("No baseline set. Use [bold]assay baseline set <pack_dir>[/]")
        return

    if output_json:
        _output_json(
            {"command": "baseline get", "status": "ok", "pack_path": str(baseline)}
        )
    else:
        console.print(f"Baseline: [bold]{baseline}[/]")


# ---------------------------------------------------------------------------
# gate subcommands
# ---------------------------------------------------------------------------

gate_app = typer.Typer(
    name="gate",
    help="CI enforcement for evidence quality (use `assay score` for diagnostics)",
    no_args_is_help=True,
)
assay_app.add_typer(gate_app, name="gate", hidden=True, rich_help_panel="Advanced")


def _gate_error(msg: str, *, command: str = "assay gate", output_json: bool) -> None:
    """Emit a gate error (JSON + console) and exit 3.

    This is a shared helper for the repeated pattern in gate_check_cmd
    and gate_save_baseline_cmd. Always raises typer.Exit(3).
    """
    if output_json:
        _output_json({"command": command, "status": "error", "error": msg}, exit_code=3)
    console.print(f"[red]Error:[/] {msg}")
    raise typer.Exit(3)


def _gate_write_report(
    payload: dict, report_path: "Path", *, output_json: bool
) -> None:
    """Write a gate JSON report to disk, exiting 3 on write failure."""
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8"
        )
    except OSError as e:
        _gate_error(f"Cannot write report: {e}", output_json=output_json)


@gate_app.command("check")
def gate_check_cmd(
    path: str = typer.Argument(".", help="Repository directory to score"),
    min_score: Optional[float] = typer.Option(
        None, "--min-score", help="Minimum passing score (0-100)"
    ),
    fail_on_regression: bool = typer.Option(
        False, "--fail-on-regression", help="Fail if score dropped below baseline"
    ),
    require_lock: bool = typer.Option(
        False, "--require-lock", help="Fail if assay.lock is missing or invalid"
    ),
    baseline: Optional[str] = typer.Option(
        None,
        "--baseline",
        help="Path to score-baseline.json (default: .assay/score-baseline.json)",
    ),
    save_report: Optional[str] = typer.Option(
        None, "--save-report", help="Write gate JSON report to file"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Include score breakdown and next actions"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Enforce minimum evidence score in CI. Pass/fail only.

    For a detailed diagnostic with component breakdown and fix commands,
    use `assay score` or pass `--verbose` here.

    Exit 0 = PASS, exit 1 = FAIL, exit 3 = bad input.

    Examples:

        assay gate check --min-score 60

        assay gate check --min-score 60 --verbose

        assay gate check --fail-on-regression --baseline .assay/score-baseline.json --json
    """
    from pathlib import Path as P

    from assay.gate import (
        DEFAULT_BASELINE_PATH,
        evaluate_gate,
        load_score_baseline,
        normalize_score_value,
    )
    from assay.lockfile import check_lockfile
    from assay.score import compute_evidence_readiness_score, gather_score_facts

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        _gate_error(f"Directory not found: {path}", output_json=output_json)

    validated_min_score = None
    if min_score is not None:
        validated_min_score = normalize_score_value(min_score)
        if validated_min_score is None:
            _gate_error(
                "--min-score must be a finite number between 0 and 100",
                output_json=output_json,
            )

    # Compute current score
    try:
        facts = gather_score_facts(root)
        current = compute_evidence_readiness_score(facts)
    except Exception as e:
        _gate_error(str(e), output_json=output_json)

    # Load baseline if regression check requested
    baseline_score = None
    if fail_on_regression:
        bp = P(baseline) if baseline else root / DEFAULT_BASELINE_PATH
        baseline_score = load_score_baseline(bp)
        if baseline_score is None and bp.exists():
            _gate_error(f"Invalid baseline score in: {bp}", output_json=output_json)
        if baseline_score is None and baseline:
            _gate_error(f"Baseline not found: {baseline}", output_json=output_json)

    report = evaluate_gate(
        current_score=current,
        min_score=validated_min_score,
        fail_on_regression=fail_on_regression,
        baseline_score=baseline_score,
    )

    # Optional hard enforcement: lockfile must exist and validate.
    lock_status = "not_required"
    lock_issues: List[str] = []
    if require_lock:
        lock_path = root / "assay.lock"
        if not lock_path.exists():
            lock_status = "missing"
            report["result"] = "FAIL"
            report.setdefault("reasons", []).append(
                f"Required lockfile missing: {lock_path}"
            )
        else:
            lock_issues = check_lockfile(lock_path)
            if lock_issues:
                lock_status = "invalid"
                report["result"] = "FAIL"
                report.setdefault("reasons", []).append(
                    f"Required lockfile invalid: {lock_path} ({len(lock_issues)} issue(s))"
                )
            else:
                lock_status = "valid"

    exit_code = 0 if report["result"] == "PASS" else 1
    payload: Dict[str, Any] = {
        **report,
        "status": "ok" if exit_code == 0 else "blocked",
        "require_lock": require_lock,
        "lock_status": lock_status,
    }
    if verbose:
        payload["breakdown"] = current.get("breakdown", {})
        payload["next_actions"] = current.get("next_actions", [])
        payload["next_actions_detail"] = current.get("next_actions_detail", [])
        payload["fastest_path"] = current.get("fastest_path")
        payload["grade_description"] = current.get("grade_description", "")
        if lock_issues:
            payload["lock_issues"] = lock_issues

    report_path = None
    if save_report:
        report_path = P(save_report)
        payload = {**payload, "report_file": str(report_path)}
        _gate_write_report(payload, report_path, output_json=output_json)

    if output_json:
        _output_json(payload, exit_code=exit_code)

    # Console output
    color = "green" if report["result"] == "PASS" else "red"
    grade_desc = current.get("grade_description", "")
    desc_suffix = f'  [dim]"{grade_desc}"[/]' if grade_desc else ""
    lines = [
        f"[bold {color}]{report['result']}[/]",
        "",
        f"Score:    {report['current_score']:.1f} ({report['current_grade']}){desc_suffix}",
    ]
    if validated_min_score is not None:
        lines.append(f"Min:      {validated_min_score:.1f}")
    if baseline_score is not None:
        lines.append(f"Baseline: {baseline_score:.1f}")
    if report["regression_detected"]:
        lines.append("[red]Regression detected[/]")
    if report["reasons"]:
        lines.append("")
        for r in report["reasons"]:
            lines.append(f"  - {r}")

    console.print()
    console.print(Panel.fit("\n".join(lines), title="assay gate"))

    if verbose:
        breakdown = current.get("breakdown", {})
        action_by_comp: dict = {}
        for ad in current.get("next_actions_detail", []):
            if ad.get("component"):
                action_by_comp.setdefault(ad["component"], ad)

        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Component")
        table.add_column("Points", justify="right")
        table.add_column("Weight", justify="right")
        table.add_column("Status")
        table.add_column("Note")
        for key in ("coverage", "lockfile", "ci_gate", "receipts", "key_setup"):
            comp = breakdown.get(key, {})
            note = comp.get("note", "")
            ad = action_by_comp.get(key)
            if ad and ad["points_est"] > 0:
                note += f" [dim]→ {ad['command']} (+{ad['points_est']:.0f} pts est.)[/]"
            table.add_row(
                key,
                f"{comp.get('points', 0):.1f}",
                str(comp.get("weight", 0)),
                comp.get("status", ""),
                note,
            )
        console.print(table)

        fp = current.get("fastest_path")
        if fp:
            console.print(
                f"\n[bold]Fastest path to {fp['target_grade']} ({fp['target_score']}+):[/] "
                f"{fp['command']} [dim](+{fp['points_est']:.0f} → ~{fp['projected_score']:.0f})[/]"
            )

        actions_detail = current.get("next_actions_detail", [])
        if actions_detail:
            console.print("\n[bold]Next actions:[/]")
            for idx, ad in enumerate(actions_detail, 1):
                pts = (
                    f" [dim](+{ad['points_est']:.0f} pts est.)[/]"
                    if ad["points_est"] > 0
                    else ""
                )
                console.print(f"  {idx}. {ad['action']}: {ad['command']}{pts}")

    console.print()
    if report_path is not None:
        console.print(f"Report: [bold]{report_path}[/]")

    if exit_code == 0:
        console.print("Next: [bold]assay gate save-baseline[/] to lock in this score")
    elif not verbose:
        console.print(
            "Next: fix issues with [bold]assay score[/] to see breakdown, or use [bold]--verbose[/]"
        )

    console.print()
    raise typer.Exit(exit_code)


@gate_app.command("save-baseline")
def gate_save_baseline_cmd(
    path: str = typer.Argument(".", help="Repository directory to score"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output path (default: .assay/score-baseline.json)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Save the current Evidence Readiness Score as the gate baseline."""
    from pathlib import Path as P

    from assay.gate import DEFAULT_BASELINE_PATH, save_score_baseline
    from assay.score import compute_evidence_readiness_score, gather_score_facts

    _cmd = "assay gate save-baseline"

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        _gate_error(
            f"Directory not found: {path}", command=_cmd, output_json=output_json
        )

    try:
        facts = gather_score_facts(root)
        current = compute_evidence_readiness_score(facts)
    except Exception as e:
        _gate_error(str(e), command=_cmd, output_json=output_json)

    out_path = P(output) if output else root / DEFAULT_BASELINE_PATH
    try:
        save_score_baseline(current, out_path)
    except OSError as e:
        _gate_error(
            f"Cannot write baseline: {e}", command=_cmd, output_json=output_json
        )

    if output_json:
        _output_json(
            {
                "command": "assay gate save-baseline",
                "status": "ok",
                "score": current["score"],
                "grade": current["grade"],
                "baseline_file": str(out_path),
            }
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Baseline saved[/]\n\n"
            f"Score: {current['score']:.1f} ({current['grade']})\n"
            f"File:  {out_path}",
            title="assay gate save-baseline",
        )
    )
    console.print()
    console.print(
        f"Next: [bold]assay gate check --min-score {max(0, current['score'] - 5):.0f} --fail-on-regression[/]"
    )
    console.print()


@gate_app.command("compare")
def gate_compare_cmd(
    baseline: str = typer.Argument(
        ..., help="Baseline evidence bundle or pack directory"
    ),
    candidate: str = typer.Argument(
        ..., help="Candidate evidence bundle or pack directory"
    ),
    contract: Optional[str] = typer.Option(
        None,
        "--contract",
        "-c",
        help="Path to comparability contract. Defaults to bundled judge-comparability-v1.",
    ),
    save_report: Optional[str] = typer.Option(
        None, "--save-report", help="Write gate report JSON to file"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Enforce comparability verdict as a CI gate. Fail-closed.

    Unlike `assay compare` (advisory/diagnostic), this command is an
    enforcement boundary. UNDETERMINED is treated as failure because
    incomplete evidence cannot be trusted in a gate context.

    Exit codes:
      0  SATISFIED — comparison valid, gate passes
      1  DENIED / DOWNGRADED / UNDETERMINED — gate fails (fail-closed)
      3  Bad input

    Examples:

        assay gate compare baseline.json candidate.json -c contracts/judge-comparability-v1.yaml

        assay gate compare ./baseline_pack/ ./candidate_pack/ -c contract.yaml --json
    """
    from pathlib import Path as P

    from assay.comparability.bundle import find_bundle, load_bundle
    from assay.comparability.contract import ContractValidationError, load_contract
    from assay.comparability.engine import evaluate
    from assay.comparability.receipt import emit_comparability_receipt
    from assay.comparability.types import Verdict

    _cmd = "assay gate compare"

    # Load contract (resolve bundled default if not specified)
    from assay.contracts import resolve_contract_path

    contract_path = resolve_contract_path(contract)
    try:
        ctr = load_contract(contract_path)
    except ContractValidationError as e:
        _gate_error(str(e), command=_cmd, output_json=output_json)

    # Resolve and load bundles (accept files or pack directories)
    def _resolve_bundle(path_str: str, label: str) -> "EvidenceBundle":
        p = P(path_str)
        if p.is_dir():
            found = find_bundle(p)
            if found is None:
                _gate_error(
                    f"{label}: no evidence bundle found in directory {p}. "
                    f"Expected one of: evidence_bundle.json, evidence_bundle.yaml, "
                    f"judge_evidence.json, judge_evidence.yaml",
                    command=_cmd,
                    output_json=output_json,
                )
            p = found
        try:
            return load_bundle(p)
        except (FileNotFoundError, ValueError, IsADirectoryError) as e:
            _gate_error(f"{label}: {e}", command=_cmd, output_json=output_json)

    baseline_bundle = _resolve_bundle(baseline, "baseline")
    candidate_bundle = _resolve_bundle(candidate, "candidate")

    # Run denial engine
    diff = evaluate(ctr, baseline_bundle, candidate_bundle)

    # Emit receipt (all verdicts). Gate mode: fail closed on receipt failure.
    try:
        emit_comparability_receipt(diff, source="assay gate compare")
    except Exception as e:
        _gate_error(
            f"Receipt emission failed: {e}. "
            f"Gate cannot pass without governance receipt.",
            command=_cmd,
            output_json=output_json,
        )

    # Gate exit code: fail-closed. Only SATISFIED passes.
    gate_passed = diff.verdict == Verdict.SATISFIED
    exit_code = 0 if gate_passed else 1

    # Optional report
    if save_report:
        report_payload = {
            "command": _cmd,
            "gate_result": "PASS" if gate_passed else "FAIL",
            **diff.to_dict(),
        }
        _gate_write_report(report_payload, P(save_report), output_json=output_json)

    if output_json:
        payload = {
            "command": _cmd,
            "status": "ok",
            "gate_result": "PASS" if gate_passed else "FAIL",
            **diff.to_dict(),
        }
        _output_json(payload, exit_code=exit_code)
        return

    # Rich console output — reuse existing renderer
    _render_constitutional_diff(diff, ctr)

    # Gate banner
    if gate_passed:
        console.print(
            Panel(
                "[bold green]GATE: PASS[/]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]GATE: FAIL[/]\n\n"
                f"  Verdict {diff.verdict.value} is not SATISFIED.\n"
                f"  In gate mode, only SATISFIED passes.",
                border_style="red",
            )
        )

    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# bundle subcommands
# ---------------------------------------------------------------------------

bundle_app = typer.Typer(
    name="bundle",
    help="Evidence bundle utilities for comparability workflows",
    no_args_is_help=True,
)
assay_app.add_typer(bundle_app, name="bundle", rich_help_panel="Governance")


@bundle_app.command("init")
def bundle_init_cmd(
    contract: Optional[str] = typer.Option(
        None,
        "--contract",
        "-c",
        help="Path to comparability contract (YAML/JSON). Defaults to bundled judge-comparability-v1.",
    ),
    output: str = typer.Option(
        "evidence_bundle.json", "--output", "-o", help="Output file path"
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Output as JSON to stdout instead of file"
    ),
):
    """Scaffold a template evidence bundle from a comparability contract.

    Reads the contract's parity fields and generates a JSON file with
    all required fields stubbed to null. Fill in the values, then use
    with `assay compare` or `assay gate compare`.

    Examples:

        assay bundle init
        assay bundle init -c contracts/judge-comparability-v1.yaml -o my_bundle.json
    """
    from pathlib import Path as P

    from assay.comparability.contract import ContractValidationError, load_contract
    from assay.contracts import resolve_contract_path

    contract_path = resolve_contract_path(contract)
    try:
        ctr = load_contract(contract_path)
    except ContractValidationError as e:
        console.print(f"[red]Contract error:[/] {e}")
        raise typer.Exit(3)
    except FileNotFoundError:
        console.print(f"[red]Contract not found:[/] {contract_path}")
        raise typer.Exit(3)

    # Build scaffold with all parity fields stubbed
    fields: dict = {}
    field_sources: dict = {}
    for pf in ctr.parity_fields:
        fields[pf.field] = None
        field_sources[pf.field] = "TODO"

    scaffold = {
        "label": "TODO: descriptive label (e.g. gpt-4o @ prompt v2.3)",
        "ref": "TODO: path to results or proof pack",
        "fields": fields,
        "requested_config": {},
        "executed_config": {},
        "field_sources": field_sources,
    }

    import json

    payload = json.dumps(scaffold, indent=2) + "\n"

    if output_json:
        typer.echo(payload)
        return

    out_path = P(output)
    out_path.write_text(payload, encoding="utf-8")
    console.print(f"[green]Wrote template bundle:[/] {out_path}")
    console.print(
        f"  {len(fields)} fields stubbed from contract [bold]{ctr.contract_id}[/]"
    )
    console.print("  Fill in field values, then run:")
    contract_hint = f" -c {contract}" if contract else ""
    console.print(f"    [dim]assay compare baseline.json {out_path}{contract_hint}[/]")


# ---------------------------------------------------------------------------
# contract subcommands
# ---------------------------------------------------------------------------

contract_app = typer.Typer(
    name="contract",
    help="Comparability contract utilities (diff, inspect)",
    no_args_is_help=True,
)
assay_app.add_typer(
    contract_app, name="contract", hidden=True, rich_help_panel="Advanced"
)


@contract_app.command("diff")
def contract_diff_cmd(
    old: str = typer.Option(..., "--old", help="Path to old contract (YAML/JSON)"),
    new: str = typer.Option(..., "--new", help="Path to new contract (YAML/JSON)"),
    bundles: str = typer.Option(
        ..., "--bundles", help="Directory containing evidence bundle pairs"
    ),
    save_report: Optional[str] = typer.Option(
        None, "--save-report", help="Write diff report JSON to file"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Diff two contract versions by replaying evidence bundles.

    Loads two comparability contracts (old and new), finds evidence bundle
    pairs in the bundles directory, replays each pair under both contracts,
    and reports verdict flips with clause-level reasons.

    A "flip" is when the same evidence pair produces a different verdict
    under the new contract than the old one.

    Exit codes:
      0  No verdict flips (amendment is safe for this corpus)
      1  Verdict flips detected (amendment changes outcomes)
      3  Bad input

    Examples:

        assay contract diff \\
          --old contracts/judge-comparability-v1.yaml \\
          --new contracts/judge-comparability-v2-draft.yaml \\
          --bundles examples/llm_judge/organic/

        assay contract diff --old v1.yaml --new v2.yaml --bundles ./runs/ --json
    """
    from pathlib import Path as P

    from assay.comparability.bundle import find_bundle, load_bundle
    from assay.comparability.contract import ContractValidationError, load_contract
    from assay.comparability.contract_diff import replay

    # Load contracts
    try:
        old_ctr = load_contract(old)
    except (ContractValidationError, FileNotFoundError) as e:
        console.print(f"[red]Old contract error:[/] {e}")
        raise typer.Exit(3)

    try:
        new_ctr = load_contract(new)
    except (ContractValidationError, FileNotFoundError) as e:
        console.print(f"[red]New contract error:[/] {e}")
        raise typer.Exit(3)

    # Discover evidence bundles in the bundles directory
    bundles_dir = P(bundles)
    if not bundles_dir.is_dir():
        console.print(f"[red]Bundles directory not found:[/] {bundles}")
        raise typer.Exit(3)

    # Find all subdirectories with evidence_bundle.json
    bundle_dirs = sorted(
        [d for d in bundles_dir.iterdir() if d.is_dir() and find_bundle(d) is not None]
    )

    if len(bundle_dirs) < 2:
        console.print(
            f"[red]Need at least 2 bundle directories, found {len(bundle_dirs)}[/]"
        )
        raise typer.Exit(3)

    # Load bundles
    loaded_bundles = []
    for bd in bundle_dirs:
        bp = find_bundle(bd)
        if bp:
            loaded_bundles.append(load_bundle(bp))

    # Create pairs: first bundle is baseline, compare against all others
    baseline = loaded_bundles[0]
    pairs = [(baseline, candidate) for candidate in loaded_bundles[1:]]

    # Run replay
    report = replay(old_ctr, new_ctr, pairs)

    # Save report if requested
    if save_report:
        report_path = P(save_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report.to_dict(), indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    if output_json:
        _output_json(report.to_dict(), exit_code=0 if not report.flips else 1)
        return

    # Rich console output
    console.print()
    console.print(
        Panel(
            f"[bold]Contract Diff Report[/]\n"
            f"Old: {old_ctr.contract_id} v{old_ctr.version}\n"
            f"New: {new_ctr.contract_id} v{new_ctr.version}",
            border_style="blue",
        )
    )

    # Clause changes
    if report.clause_changes:
        console.print(f"\n[bold]Clause changes ({len(report.clause_changes)}):[/]")
        for cc in report.clause_changes:
            icon = {
                "severity_relaxed": "[yellow]\u2193[/]",
                "severity_tightened": "[red]\u2191[/]",
                "field_added": "[green]+[/]",
                "field_removed": "[red]-[/]",
                "rule_changed": "[cyan]~[/]",
            }.get(cc.change_type, "?")
            console.print(
                f"  {icon} {cc.field}: {cc.old_severity.value} \u2192 {cc.new_severity.value} ({cc.change_type})"
            )
    else:
        console.print("\n[dim]No clause changes.[/]")

    # Summary
    console.print("\n[bold]Replay summary:[/]")
    console.print(f"  Bundle pairs replayed: {report.total_pairs}")
    console.print(f"  Stable (no verdict change): {report.stable_count}")
    console.print(f"  Flips: {len(report.flips)}")

    # Flips
    if report.flips:
        console.print(f"\n[bold]Verdict flips ({len(report.flips)}):[/]")
        for flip in report.flips:
            console.print(f"\n  [bold]{flip.bundle_ref}[/]")
            console.print(
                f"    {flip.old_verdict.value} \u2192 {flip.new_verdict.value}"
            )
            console.print(f"    Trigger: {flip.triggering_field}")
            console.print(f"    Reason: {flip.reason}")
        console.print()
        console.print(
            Panel(
                f"[bold yellow]{len(report.flips)} verdict flip(s) detected[/]\n"
                f"The contract amendment changes outcomes for existing evidence.",
                border_style="yellow",
            )
        )
    else:
        console.print()
        console.print(
            Panel(
                "[bold green]No verdict flips[/]\n"
                "The contract amendment is safe for the current organic corpus.",
                border_style="green",
            )
        )

    raise typer.Exit(0 if not report.flips else 1)


# ---------------------------------------------------------------------------
# cards subcommands
# ---------------------------------------------------------------------------

cards_app = typer.Typer(
    name="cards",
    help="Inspect built-in and custom run cards",
    no_args_is_help=True,
)
assay_app.add_typer(cards_app, name="cards", hidden=True, rich_help_panel="Operate")


@cards_app.command("list")
def cards_list_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List all built-in run cards."""
    from assay.run_cards import get_all_builtin_cards

    cards = get_all_builtin_cards()

    if output_json:
        _output_json(
            {
                "command": "cards list",
                "status": "ok",
                "cards": [
                    {
                        "card_id": c.card_id,
                        "name": c.name,
                        "description": c.description,
                        "claims": len(c.claims),
                    }
                    for c in cards
                ],
            }
        )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Card ID", style="cyan")
    table.add_column("Name")
    table.add_column("Claims", justify="right")
    table.add_column("Description")

    for c in cards:
        table.add_row(c.card_id, c.name, str(len(c.claims)), c.description)

    console.print(table)


@cards_app.command("show")
def cards_show_cmd(
    card_id: str = typer.Argument(
        help="Card ID to display (e.g. receipt_completeness)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show details of a specific run card, including its claims."""
    from assay.run_cards import get_builtin_card

    card = get_builtin_card(card_id)
    if card is None:
        from assay.run_cards import BUILTIN_CARDS

        valid = ", ".join(sorted(BUILTIN_CARDS.keys()))
        if output_json:
            _output_json(
                {
                    "command": "cards show",
                    "status": "error",
                    "error": f"Unknown card: {card_id}",
                    "valid_cards": valid,
                },
                exit_code=3,
            )
        console.print(f"[red]Unknown card:[/] {card_id}")
        console.print(f"[dim]Valid cards: {valid}[/]")
        raise typer.Exit(3)

    if output_json:
        _output_json(
            {
                "command": "cards show",
                "status": "ok",
                **card.to_dict(),
                "claim_set_hash": card.claim_set_hash(),
            }
        )

    console.print(f"[bold]{card.name}[/]  [dim]({card.card_id})[/]")
    console.print(f"  {card.description}")
    console.print()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Claim ID", style="cyan")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Description")

    for cl in card.claims:
        sev_style = "red" if cl.severity == "critical" else "yellow"
        table.add_row(
            cl.claim_id, cl.check, f"[{sev_style}]{cl.severity}[/]", cl.description
        )

    console.print(table)

    if any(cl.params for cl in card.claims):
        console.print()
        for cl in card.claims:
            if cl.params:
                console.print(f"  [dim]{cl.claim_id} params:[/] {cl.params}")

    console.print(f"\n  [dim]Claim set hash: {card.claim_set_hash()}[/]")


@ci_app.command("init")
def ci_init_cmd(
    provider: str = typer.Argument("github", help="CI provider (currently: github)"),
    run_command: str = typer.Option(
        "python my_app.py",
        "--run-command",
        help="Command Assay should wrap in CI",
    ),
    cards: str = typer.Option(
        "receipt_completeness",
        "--cards",
        help="Comma-separated run cards for assay run",
    ),
    output: str = typer.Option(
        ".github/workflows/assay-verify.yml",
        "--output",
        "-o",
        help="Workflow output path",
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite existing workflow file"
    ),
    min_score: int = typer.Option(
        0,
        "--min-score",
        help="Minimum assay score to pass the gate (0 = advisory)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a CI workflow for Proof Pack generation + verification."""
    from pathlib import Path

    from assay import __version__

    provider_norm = provider.strip().lower()
    if provider_norm != "github":
        if output_json:
            _output_json(
                {
                    "command": "ci init",
                    "status": "error",
                    "error": f"Unsupported provider '{provider}'. Supported: github",
                }
            )
        console.print(
            f"[red]Error:[/] Unsupported provider '{provider}'. Supported: github"
        )
        raise typer.Exit(1)

    run_command = " ".join(run_command.strip().split())
    if not run_command:
        if output_json:
            _output_json(
                {
                    "command": "ci init",
                    "status": "error",
                    "error": "run_command cannot be empty",
                }
            )
        console.print("[red]Error:[/] --run-command cannot be empty")
        raise typer.Exit(1)

    is_placeholder = run_command == "python my_app.py"

    card_args = []
    for card in [c.strip() for c in cards.split(",") if c.strip()]:
        card_args.extend(["-c", card])
    card_flags = " ".join(card_args) if card_args else ""

    workflow_path = Path(output)
    if workflow_path.exists() and not force:
        if output_json:
            _output_json(
                {
                    "command": "ci init",
                    "status": "error",
                    "error": f"{output} already exists (use --force to overwrite)",
                }
            )
        console.print(
            f"[red]Error:[/] {output} already exists. Use --force to overwrite."
        )
        raise typer.Exit(1)

    workflow_path.parent.mkdir(parents=True, exist_ok=True)

    min_score_comment = (
        "  # raise this once your score is stable" if min_score == 0 else ""
    )
    placeholder_comment = (
        "  # TODO: replace with your actual run command" if is_placeholder else ""
    )

    workflow = f"""name: Assay Verify

on:
  pull_request:
  push:
    branches: [main]

jobs:
  assay-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Assay
        run: |
          python -m pip install --upgrade pip
          python -m pip install "assay-ai=={__version__}"

      - name: Score Gate
        run: |
          assay gate check . --min-score {min_score} --fail-on-regression --save-report assay_gate_report.json --verbose --json{min_score_comment}

      - name: Upload Gate Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: assay-gate-report
          path: assay_gate_report.json
          if-no-files-found: ignore

  assay-verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Assay
        run: |
          python -m pip install --upgrade pip
          python -m pip install "assay-ai=={__version__}"

      # Install your project dependencies before this step if needed.
      - name: Generate Proof Pack
        run: |
          assay run {card_flags} -- {run_command}{placeholder_comment}

      - name: Verify Proof Pack
        uses: Haserjian/assay-verify-action@v1
        with:
          pack-path: "proof_pack_*/"
          require-claim-pass: true
          comment-on-pr: true
          upload-artifact: true

  assay-report:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Assay
        run: |
          python -m pip install --upgrade pip
          python -m pip install "assay-ai=={__version__}"

      - name: Generate Evidence Report
        run: |
          assay report . -o evidence_report.html --sarif

      - name: Upload HTML Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: assay-evidence-report
          path: evidence_report.html
          if-no-files-found: ignore

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: evidence_report.sarif
"""

    workflow_path.write_text(workflow, encoding="utf-8")

    if output_json:
        _output_json(
            {
                "command": "ci init",
                "status": "ok",
                "provider": "github",
                "output": str(workflow_path),
                "run_command": run_command,
                "cards": [c.strip() for c in cards.split(",") if c.strip()],
                "min_score": min_score,
            }
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]CI workflow generated (3 jobs)[/]\n\n"
            f"Provider:   github\n"
            f"Output:     {workflow_path}\n"
            f"Run:        {run_command}\n"
            f"RunCards:   {cards}\n"
            f"MinScore:   {min_score}",
            title="assay ci init github",
        )
    )
    if is_placeholder:
        console.print(
            "[yellow]Warning:[/] Using placeholder command 'python my_app.py'."
        )
        console.print(
            f"  Edit [bold]{workflow_path}[/] and replace with your actual run command."
        )
        console.print(
            '  Or re-run: assay ci init github --run-command "python your_app.py" --force'
        )
        console.print()
    console.print("Next:")
    console.print(
        f"  1. Review [bold]{workflow_path}[/] (3 jobs: gate, verify, report)"
    )
    console.print("  2. Commit and push")
    console.print("  3. Open a PR to see score gate + verification + SARIF in checks")
    console.print()


@ci_app.command("doctor")
def ci_doctor_cmd(
    lock: Optional[str] = typer.Option(None, "--lock", help="Path to lockfile"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as failures"),
    output_json: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
):
    """Run doctor checks with the CI profile.

    Validates lockfile integrity, workflow wiring, exit code contract,
    and all standard CI prerequisites.

    Equivalent to: assay doctor --profile ci
    """
    from pathlib import Path as P

    from assay.doctor import Profile, run_doctor

    lock_path = P(lock) if lock else None
    report = run_doctor(Profile.CI, lock_path=lock_path, strict=strict)

    if output_json:
        _output_json(
            report.to_dict(),
            exit_code=report.exit_code_strict() if strict else report.exit_code,
        )
        return

    _render_doctor_report(report, strict)


# ---------------------------------------------------------------------------
# trust subcommands
# ---------------------------------------------------------------------------

trust_app = typer.Typer(
    name="trust",
    help="Bootstrap and manage trust policy for CI verification",
    no_args_is_help=True,
)
assay_app.add_typer(trust_app, name="trust", rich_help_panel="Operate")


# Action SHA for immutable pinning (assay-verify-action HEAD as of 2026-03-28)
_ACTION_SHA = "40af9bd1a9587d11f65e16639e6d1a6231ef4808"

_PROFILE_CONFIGS = {
    "minimal": {
        "description": "permissive",
        "enforce_trust": False,
        "unrecognized_decision": "accept",
        "unrecognized_reason": "Signer not yet registered — add fingerprint to trust/signers.yaml",
        "revoked_decision": "warn",
        "revoked_reason": "Signer has been revoked",
        "acceptance_header": (
            "# Minimal profile: permissive posture.\n"
            "# All signers accepted. Trust evaluation runs and reports\n"
            "# in the PR comment, but nothing is blocked.\n"
            "# Upgrade to --profile reviewer or --profile strict when ready."
        ),
        "signers_header": (
            "# This file defines who is allowed to sign proof packs.\n"
            "#\n"
            "# To register your signer:\n"
            "#   1. Run: assay key list\n"
            "#   2. Find the SHA-256 fingerprint of your active key\n"
            "#   3. Uncomment the example entry below and replace the placeholder\n"
            "#   4. Commit and push — your next PR will show trust status"
        ),
        "posture_summary": (
            "Trust posture: permissive\n"
            "  - All signers: accepted (trust summary shown, nothing blocked)\n"
            "  - Revoked signers: warned"
        ),
    },
    "reviewer": {
        "description": "advisory",
        "enforce_trust": False,
        "unrecognized_decision": "warn",
        "unrecognized_reason": "Unknown signer — register fingerprint in trust/signers.yaml",
        "revoked_decision": "reject",
        "revoked_reason": "Signer has been revoked",
        "acceptance_header": (
            "# Reviewer profile: advisory posture.\n"
            "# Trust evaluation runs and warns on unregistered signers.\n"
            "# Pipeline does not fail — warnings appear in PR comments.\n"
            "#\n"
            "# Reviewer packet examples:\n"
            "#   https://github.com/Haserjian/assay-proof-gallery (scenarios 05, 06)"
        ),
        "signers_header": (
            "# This file defines who is allowed to sign proof packs.\n"
            "# The reviewer profile expects you to register your CI signer\n"
            "# before reviewer packets will show clean trust status.\n"
            "#\n"
            "# To register your signer:\n"
            "#   1. Run: assay key list\n"
            "#   2. Find the SHA-256 fingerprint of your active key\n"
            "#   3. Uncomment the example entry below and replace the placeholder\n"
            "#   4. Commit and push\n"
            "#\n"
            "# For reviewer packet examples, see:\n"
            "#   Scenario 05 (buyer-facing):     https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/05-reviewer-packet-gaps\n"
            "#   Scenario 06 (NAIC AISET):       https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/06-naic-aiset-mapping"
        ),
        "posture_summary": (
            "Trust posture: advisory\n"
            "  - Authorized signers: accepted\n"
            "  - Unknown signers: warned (visible in PR, pipeline passes)\n"
            "  - Revoked signers: rejected"
        ),
    },
    "strict": {
        "description": "enforced",
        "enforce_trust": True,
        "unrecognized_decision": "reject",
        "unrecognized_reason": "Unknown signer — register fingerprint in trust/signers.yaml before pushing",
        "revoked_decision": "reject",
        "revoked_reason": "Signer has been revoked",
        "acceptance_header": (
            "# Strict profile: enforced posture.\n"
            "# Unregistered signers are REJECTED. The CI pipeline will fail\n"
            "# if a proof pack is signed by an unknown key.\n"
            "#\n"
            "# Make sure at least one signer is registered in signers.yaml\n"
            "# before pushing proof packs."
        ),
        "signers_header": (
            "# IMPORTANT: The strict profile enforces trust. Proof packs signed\n"
            "# by unregistered signers will FAIL the CI pipeline.\n"
            "#\n"
            "# You MUST register at least one signer before the first PR,\n"
            "# or the pipeline will reject all proof packs.\n"
            "#\n"
            "# To register your signer:\n"
            "#   1. Run: assay key list\n"
            "#   2. Find the SHA-256 fingerprint of your active key\n"
            "#   3. Uncomment the example entry below and replace the placeholder\n"
            "#   4. Commit trust/signers.yaml BEFORE pushing proof packs"
        ),
        "posture_summary": (
            "Trust posture: enforced\n"
            "  - Authorized signers: accepted\n"
            "  - Unknown signers: REJECTED (pipeline fails)\n"
            "  - Revoked signers: rejected\n"
            "\n"
            "  Register at least one signer BEFORE pushing proof packs,\n"
            "  or the pipeline will reject all packs."
        ),
    },
}


def _build_signers_yaml(profile: str, cfg: dict) -> str:
    return (
        f"# Assay Trust Policy — Signer Registry\n"
        f"# Generated by: assay trust bootstrap --profile {profile}\n"
        f"#\n"
        f"{cfg['signers_header']}\n"
        f"\n"
        f"version: 1\n"
        f"\n"
        f"signer_classes:\n"
        f"  ci-org:\n"
        f'    description: "Organization CI signer"\n'
        f"    allowed_targets: [ci_gate, publication]\n"
        f"  local-dev:\n"
        f'    description: "Developer local key (not sufficient for CI gate)"\n'
        f"    allowed_targets: [local_verify]\n"
        f"    not_sufficient_for: [ci_gate, publication]\n"
        f"\n"
        f"signers: []\n"
        f"# To add a signer, replace the empty list above with:\n"
        f"# signers:\n"
        f'#   - signer_id: "my-ci-signer"\n'
        f'#     signer_class: "ci-org"\n'
        f'#     fingerprint: "replace-with-output-of-assay-key-list"\n'
        f'#     lifecycle: "active"\n'
        f"#     grants:\n"
        f'#       - artifact_class: "proof_pack"\n'
        f'#         purpose: "*"\n'
    )


def _build_acceptance_yaml(profile: str, cfg: dict) -> str:
    return (
        f"# Assay Trust Policy — Acceptance Rules\n"
        f"# Generated by: assay trust bootstrap --profile {profile}\n"
        f"#\n"
        f"# Rules are evaluated top-to-bottom, first match wins.\n"
        f"#\n"
        f"{cfg['acceptance_header']}\n"
        f"\n"
        f"rules:\n"
        f"  # Accept authorized signers\n"
        f'  - artifact_class: "proof_pack"\n'
        f'    verification_level: "signature_verified"\n'
        f'    authorization_status: "authorized"\n'
        f'    target: "ci_gate"\n'
        f'    decision: "accept"\n'
        f'    reason: "Signed by authorized CI signer"\n'
        f"\n"
        f"  # Recognized but not-yet-authorized signers\n"
        f'  - artifact_class: "proof_pack"\n'
        f'    verification_level: "signature_verified"\n'
        f'    authorization_status: "recognized"\n'
        f'    target: "ci_gate"\n'
        f'    decision: "warn"\n'
        f'    reason: "Signer recognized but not authorized for ci_gate — check grants in signers.yaml"\n'
        f"\n"
        f"  # Unrecognized signers\n"
        f'  - artifact_class: "*"\n'
        f'    verification_level: "*"\n'
        f'    authorization_status: "unrecognized"\n'
        f'    target: "ci_gate"\n'
        f'    decision: "{cfg["unrecognized_decision"]}"\n'
        f'    reason: "{cfg["unrecognized_reason"]}"\n'
        f"\n"
        f"  # Revoked signers\n"
        f'  - artifact_class: "*"\n'
        f'    verification_level: "*"\n'
        f'    authorization_status: "revoked"\n'
        f'    target: "*"\n'
        f'    decision: "{cfg["revoked_decision"]}"\n'
        f'    reason: "{cfg["revoked_reason"]}"\n'
    )


def _build_trust_readme(profile: str) -> str:
    return (
        "# Trust Policy\n"
        "\n"
        "This directory contains the signer registry and acceptance rules\n"
        "for Assay proof pack verification in CI.\n"
        "\n"
        "## Quick start\n"
        "\n"
        "1. Find your signer fingerprint:\n"
        "   ```\n"
        "   assay key list\n"
        "   ```\n"
        "\n"
        "2. Add the fingerprint to `signers.yaml` under `signers:`\n"
        "   (replace the commented placeholder)\n"
        "\n"
        "3. Generate a proof pack: `assay run -- <your command>`\n"
        "\n"
        "4. Commit `trust/`, the proof pack, and push.\n"
        "   Trust evaluation appears in the next PR comment.\n"
        "\n"
        "**Note:** The generated workflow sets `require-pack: true`.\n"
        "If your repo does not produce proof packs on every PR,\n"
        "set `require-pack: false` in `.github/workflows/assay-verify.yml`.\n"
        "\n"
        "## Files\n"
        "\n"
        "| File | Purpose |\n"
        "|------|---------|\n"
        "| `signers.yaml` | Who is allowed to sign proof packs |\n"
        "| `acceptance.yaml` | What decisions apply per signer status and target |\n"
        "\n"
        "## Verification levels\n"
        "\n"
        "| Level | Meaning |\n"
        "|-------|---------|\n"
        "| `signature_verified` | Ed25519 signature valid, signer fingerprint extracted |\n"
        "| `hash_verified` | File hashes match manifest, no signature check |\n"
        "| `unverified` | No verification performed |\n"
        "\n"
        "## Reviewer packet examples\n"
        "\n"
        "- [Scenario 05: reviewer-packet-gaps](https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/05-reviewer-packet-gaps) — buyer-facing\n"
        "- [Scenario 06: naic-aiset-mapping](https://github.com/Haserjian/assay-proof-gallery/tree/main/gallery/06-naic-aiset-mapping) — compliance/regulatory\n"
        "\n"
        "## Upgrading trust posture\n"
        "\n"
        "| From | To | Change |\n"
        "|------|----|--------|\n"
        "| minimal | reviewer | Edit `acceptance.yaml`: change `unrecognized` decision from `accept` to `warn` |\n"
        "| reviewer | strict | Edit workflow: add `enforce-trust: true`. Edit `acceptance.yaml`: change `unrecognized` from `warn` to `reject` |\n"
    )


def _build_workflow_yaml(profile: str, cfg: dict) -> str:
    from assay import __version__

    enforce_line = ""
    if cfg["enforce_trust"]:
        enforce_line = "\n          enforce-trust: true"

    # CI annotation type maps to profile posture
    annotation_map = {
        "minimal": "notice",
        "reviewer": "warning",
        "strict": "error",
    }
    ann_type = annotation_map[profile]
    ann_msg = {
        "minimal": "Trust bootstrap active (permissive). Register your signer in trust/signers.yaml for authorization.",
        "reviewer": "Trust bootstrap active (advisory). Unregistered signers will produce warnings. Register in trust/signers.yaml.",
        "strict": "Trust bootstrap active (enforced). Unregistered signers will FAIL. Ensure trust/signers.yaml has your signer.",
    }

    return f"""# Assay Verify — generated by: assay trust bootstrap --profile {profile}
#
# Trust posture: {cfg["description"]}
# Action pinned to immutable commit SHA for supply-chain safety.

name: Assay Verify

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  assay-verify:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Trust posture annotation
        run: echo "::{ann_type}::{ann_msg[profile]}"

      - name: Verify Proof Packs
        uses: Haserjian/assay-verify-action@{_ACTION_SHA}
        with:
          pack-path: "proof_pack_*/"
          require-pack: true
          require-claim-pass: true
          comment-on-pr: true
          trust-target: ci_gate
          trust-policy-dir: trust/{enforce_line}
          assay-version: "{__version__}"
"""


@trust_app.command("bootstrap")
def trust_bootstrap_cmd(
    profile: str = typer.Option(
        "minimal", "--profile", "-p", help="Trust profile: minimal, reviewer, strict"
    ),
    output_dir: str = typer.Option(
        ".", "--output-dir", "-o", help="Root directory for emitted files"
    ),
    force: bool = typer.Option(
        False, "--force", help="Overwrite existing trust/ directory"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be written without writing"
    ),
):
    """Bootstrap trust policy files and CI workflow for proof pack verification."""
    from pathlib import Path

    profile = profile.strip().lower()
    if profile not in _PROFILE_CONFIGS:
        console.print(
            f"[red]Error:[/] Unknown profile '{profile}'. Choose: minimal, reviewer, strict"
        )
        raise typer.Exit(1)

    cfg = _PROFILE_CONFIGS[profile]
    root = Path(output_dir).resolve()
    trust_dir = root / "trust"
    workflow_path = root / ".github" / "workflows" / "assay-verify.yml"

    files = {
        trust_dir / "signers.yaml": _build_signers_yaml(profile, cfg),
        trust_dir / "acceptance.yaml": _build_acceptance_yaml(profile, cfg),
        trust_dir / "README.md": _build_trust_readme(profile),
        workflow_path: _build_workflow_yaml(profile, cfg),
    }

    # Check for existing files — refuse to overwrite any target without --force
    if not force and not dry_run:
        existing = [p for p in files if p.exists()]
        if existing:
            rel_paths = [
                str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
                for p in existing
            ]
            console.print("[red]Error:[/] Existing files would be overwritten:")
            for rp in rel_paths:
                console.print(f"  {rp}")
            console.print("Use --force to overwrite.")
            raise typer.Exit(1)

    if dry_run:
        console.print(
            f"\n[bold]Assay Trust Bootstrap[/] ({profile} profile) — dry run\n"
        )
        for path, content in files.items():
            rel = path.relative_to(root) if path.is_relative_to(root) else path
            console.print(f"  Would write: [bold]{rel}[/]")
        console.print()
        return

    # Write files
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # Print summary
    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Assay Trust Bootstrap[/] ({profile} profile)\n\n"
            f"Writing files:\n"
            f"  trust/signers.yaml              signer registry (placeholder — register your key)\n"
            f"  trust/acceptance.yaml           acceptance rules ({cfg['description']} mode)\n"
            f"  trust/README.md                 setup guide + gallery links\n"
            f"  .github/workflows/assay-verify.yml   CI workflow with trust evaluation\n\n"
            f"{cfg['posture_summary']}",
            title="assay trust bootstrap",
        )
    )
    console.print()
    console.print("Next steps:")
    console.print("  1. Run: [bold]assay key list[/]")
    console.print(
        "  2. Copy your fingerprint into [bold]trust/signers.yaml[/] (replace the placeholder)"
    )
    console.print("  3. Generate a proof pack: [bold]assay run -- <your command>[/]")
    console.print("  4. Commit trust/, proof pack, and push")
    console.print("  5. Open a PR — trust evaluation appears in the PR comment")
    console.print()
    console.print(
        "[dim]Note: The workflow requires at least one proof pack (require-pack: true).\n"
        "If your repo doesn't produce packs on every PR, set require-pack: false\n"
        "in .github/workflows/assay-verify.yml.[/dim]"
    )
    if profile == "reviewer":
        console.print()
        console.print("Reviewer packet examples:")
        console.print("  https://github.com/Haserjian/assay-proof-gallery")
        console.print("  Scenario 05: reviewer-packet-gaps (buyer-facing)")
        console.print("  Scenario 06: naic-aiset-mapping (compliance/regulatory)")
    if profile == "strict":
        console.print()
        console.print("[yellow]Warning:[/] Strict profile enforces trust.")
        console.print("  Register at least one signer BEFORE pushing proof packs.")
    console.print()


@assay_app.command("onboard", rich_help_panel="Operate", hidden=True)
def onboard_cmd(
    path: str = typer.Argument(".", help="Project directory to onboard"),
    run_command: Optional[str] = typer.Option(
        None,
        "--run-command",
        help="Command to wrap with assay run (e.g. 'python app.py')",
    ),
    entrypoint: Optional[str] = typer.Option(
        None,
        "--entrypoint",
        help="Entrypoint file hint for patch placement",
    ),
    skip_doctor: bool = typer.Option(
        False, "--skip-doctor", help="Skip assay doctor preflight"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Guided project setup: doctor -> scan -> patch suggestion -> first run commands.

    Use `assay quickstart` for a faster demo-first walkthrough.
    """
    from collections import Counter as _Counter
    from pathlib import Path as P

    from assay.doctor import Profile, run_doctor
    from assay.scanner import scan_directory

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "onboard",
                    "status": "error",
                    "error": f"Directory not found: {path}",
                }
            )
        console.print(f"[red]Error:[/] Directory not found: {path}")
        raise typer.Exit(1)

    doctor_report = None
    if not skip_doctor:
        doctor_report = run_doctor(Profile.LOCAL)

    scan_result = scan_directory(root)
    summary = scan_result.summary

    uninstrumented = [f for f in scan_result.findings if not f.instrumented]
    patch_line = next((f.fix for f in uninstrumented if f.fix), None)

    path_counts = _Counter(f.path for f in uninstrumented)
    top_paths = [p for p, _count in path_counts.most_common(3)]
    selected_entrypoint = entrypoint or (top_paths[0] if top_paths else "main.py")
    selected_run = run_command or f"python {selected_entrypoint}"

    next_steps: list[str] = []
    if patch_line:
        next_steps.append(
            f"Add to your entrypoint ({selected_entrypoint}): {patch_line}"
        )
    else:
        next_steps.append(
            "No SDK patterns detected; add manual emission: from assay import emit_receipt"
        )
    next_steps.append(
        f"Generate first Proof Pack: assay run -c receipt_completeness -- {selected_run}"
    )
    next_steps.append(
        "Verify + explain: assay verify-pack ./proof_pack_*/ && assay explain ./proof_pack_*/ --format md"
    )
    next_steps.append("Lock baseline: assay lock init")
    next_steps.append(
        'Enable CI: assay ci init github --run-command "' + selected_run + '"'
    )

    if output_json:
        _output_json(
            {
                "command": "onboard",
                "status": "ok",
                "path": str(root),
                "doctor": None
                if doctor_report is None
                else {
                    "status": doctor_report.overall_status,
                    "summary": doctor_report.summary,
                },
                "scan_summary": summary,
                "top_paths": top_paths,
                "entrypoint": selected_entrypoint,
                "run_command": selected_run,
                "patch_line": patch_line,
                "next_steps": next_steps,
            }
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold]Step 1: Preflight[/]\n"
            f"Doctor: {'skipped' if doctor_report is None else doctor_report.overall_status.upper()}\n\n"
            f"[bold]Step 2: Scan[/]\n"
            f"Call sites: {summary['sites_total']} total, {summary['uninstrumented']} uninstrumented\n"
            f"High/Med/Low: {summary['high']}/{summary['medium']}/{summary['low']}\n\n"
            f"[bold]Step 3: Suggested entrypoint[/]\n"
            f"{selected_entrypoint}\n\n"
            f"[bold]Step 4: Recommended run command[/]\n"
            f"{selected_run}",
            title="assay onboard",
        )
    )
    console.print()
    console.print("[bold]Next 5 moves:[/]")
    for i, step in enumerate(next_steps, 1):
        console.print(f"  {i}. {step}")
    console.print()


@assay_app.command("patch", rich_help_panel="Build & Verify", hidden=True)
def patch_cmd(
    path: str = typer.Argument(".", help="Directory to scan and patch"),
    entrypoint: Optional[str] = typer.Option(
        None,
        "--entrypoint",
        help="File to patch (auto-detected if omitted)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show diff without writing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply without confirmation"),
    backup: bool = typer.Option(
        True, "--backup/--no-backup", help="Back up original file before patching"
    ),
    undo: bool = typer.Option(
        False, "--undo", help="Restore from backup (reverses a previous patch)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Auto-insert SDK integration patches into your entrypoint."""
    from pathlib import Path as P

    from assay.patcher import apply_patch, generate_diff, plan_patch, undo_patch
    from assay.scanner import scan_directory

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "patch",
                    "status": "error",
                    "error": f"Directory not found: {path}",
                }
            )
        console.print(f"[red]Error:[/] Directory not found: {path}")
        raise typer.Exit(3)

    # Undo mode: restore from backup
    if undo:
        if entrypoint is None:
            bak_files = list(root.glob("**/*.assay.bak"))
            if not bak_files:
                if output_json:
                    _output_json(
                        {
                            "command": "patch",
                            "status": "error",
                            "error": "No .assay.bak files found",
                        }
                    )
                console.print("[red]No .assay.bak files found.[/] Nothing to undo.")
                raise typer.Exit(1)
            # Derive entrypoint from first .bak file
            bak = bak_files[0]
            entrypoint = str(bak.relative_to(root)).replace(".assay.bak", "")
        success = undo_patch(root, entrypoint)
        if output_json:
            _output_json(
                {
                    "command": "patch",
                    "action": "undo",
                    "status": "ok" if success else "error",
                    "entrypoint": entrypoint,
                },
                exit_code=0 if success else 1,
            )
        if success:
            console.print(f"[green]Restored {entrypoint}[/] from backup.")
        else:
            console.print(f"[red]No backup found for {entrypoint}[/]")
            raise typer.Exit(1)
        return

    scan_result = scan_directory(root)
    uninstrumented = [f for f in scan_result.findings if not f.instrumented]

    if not uninstrumented:
        if output_json:
            _output_json(
                {
                    "command": "patch",
                    "status": "ok",
                    "message": "No uninstrumented call sites found",
                }
            )
        console.print("[green]No uninstrumented call sites found.[/] Nothing to patch.")
        raise typer.Exit(0)

    try:
        plan = plan_patch(scan_result, root, entrypoint=entrypoint)
    except FileNotFoundError as e:
        if output_json:
            _output_json({"command": "patch", "status": "error", "error": str(e)})
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if not plan.has_work:
        msg = (
            f"Already patched: {', '.join(plan.already_patched)}"
            if plan.already_patched
            else "Nothing to patch"
        )
        if output_json:
            _output_json(
                {"command": "patch", "status": "ok", "message": msg, **plan.to_dict()}
            )
        console.print(f"[green]{msg}[/]")
        if plan.langchain_note:
            console.print(f"\n[yellow]Note:[/] {plan.langchain_note}")
        raise typer.Exit(0)

    # Show diff
    diff = generate_diff(plan, root)

    if output_json and dry_run:
        _output_json(
            {
                "command": "patch",
                "status": "dry_run",
                "diff": diff,
                **plan.to_dict(),
            },
            exit_code=0,
        )
        # _output_json raises typer.Exit(exit_code)

    if output_json:
        # Apply first, then report
        apply_patch(plan, root, backup=backup)
        _output_json(
            {
                "command": "patch",
                "status": "applied",
                "diff": diff,
                **plan.to_dict(),
            },
            exit_code=0,
        )
        # _output_json raises typer.Exit(exit_code)

    console.print(
        f"\n[bold]Scanning...[/] found {len(uninstrumented)} uninstrumented call sites"
    )
    console.print(f"[bold]Detected frameworks:[/] {', '.join(plan.frameworks)}")
    console.print(f"[bold]Entrypoint:[/] {plan.entrypoint}")
    if plan.already_patched:
        console.print(f"[dim]Already patched:[/] {', '.join(plan.already_patched)}")
    console.print()
    console.print(diff)
    console.print()

    if plan.langchain_note:
        console.print(f"[yellow]Note:[/] {plan.langchain_note}\n")

    if dry_run:
        console.print("[dim]Dry run -- no files changed.[/]")
        return

    if not yes:
        confirm = typer.confirm("Apply patch?")
        if not confirm:
            console.print("[dim]Cancelled.[/]")
            raise typer.Exit(0)

    apply_patch(plan, root, backup=backup)
    console.print(
        f"[green]Patched {plan.entrypoint}[/] with {len(plan.lines_to_insert)} integration line(s)."
    )

    # Check if other files still have uninstrumented call sites
    other_files = {f.path for f in uninstrumented if f.path != plan.entrypoint}
    if other_files:
        console.print(
            f"\n[dim]Note: {len(other_files)} other file(s) have uninstrumented call sites."
        )
        console.print(
            "  If your app has multiple entrypoints/processes, run assay patch again.[/dim]"
        )

    console.print(
        f"\nNext: [bold]assay run -c receipt_completeness -- python {plan.entrypoint}[/]"
    )


@assay_app.command("scan", rich_help_panel="Build & Verify")
def scan_cmd(
    path: str = typer.Argument(".", help="Directory to scan"),
    output_json: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
    ci: bool = typer.Option(
        False, "--ci", help="CI mode (non-zero exit on uninstrumented sites)"
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Minimum confidence to fail on in CI mode: high, medium, low",
    ),
    include: Optional[str] = typer.Option(
        None,
        "--include",
        help="Comma-separated glob patterns to include (e.g. 'src/**/*.py')",
    ),
    exclude: Optional[str] = typer.Option(
        None,
        "--exclude",
        help="Comma-separated glob patterns to exclude (e.g. 'tests/**')",
    ),
    report: bool = typer.Option(
        False,
        "--report",
        help="Generate a self-contained HTML evidence gap report",
    ),
    report_path: Optional[str] = typer.Option(
        None,
        "--report-path",
        help="Output path for HTML report (default: evidence_gap_report.html)",
    ),
    emit_contract: Optional[str] = typer.Option(
        None,
        "--emit-contract",
        help="Write a coverage contract JSON file from scan results. "
        "LangChain/LiteLLM sites are excluded by default (no runtime callsite_id support).",
    ),
    include_low: bool = typer.Option(
        False,
        "--include-low",
        help="Include LOW confidence sites in the coverage contract",
    ),
):
    """Scan a project for uninstrumented LLM call sites.

    Finds LLM SDK calls (OpenAI, Anthropic, LangChain) and reports which
    ones have evidence emission. Prints exact fix for each finding.

    \b
    Examples:
      assay scan .
      assay scan . --json
      assay scan . --report
      assay scan . --ci --fail-on high
      assay scan src/ --exclude "tests/**"
    """
    from pathlib import Path as P

    from assay.scanner import Confidence, scan_directory

    scan_path = P(path)
    if not scan_path.exists():
        msg = f"Directory not found: {path}"
        if output_json:
            _output_json(
                {"tool": "assay-scan", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)
    if not scan_path.is_dir():
        msg = f"Not a directory: {path}"
        if output_json:
            _output_json(
                {"tool": "assay-scan", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    include_pats = (
        [p.strip() for p in include.split(",") if p.strip()] if include else None
    )
    exclude_pats = (
        [p.strip() for p in exclude.split(",") if p.strip()] if exclude else None
    )

    try:
        result = scan_directory(scan_path, include=include_pats, exclude=exclude_pats)
    except Exception as e:
        if output_json:
            _output_json(
                {"tool": "assay-scan", "status": "error", "error": str(e)}, exit_code=2
            )
        else:
            console.print(f"[red]Scan error:[/] {e}")
        raise typer.Exit(2)

    # Emit coverage contract if requested
    if emit_contract:
        from assay.coverage import CoverageContract

        try:
            contract = CoverageContract.from_scan_result(
                result,
                include_low=include_low,
                project_root=str(P(path).resolve()),
            )
            # Count excluded framework sites for user visibility
            full_contract = CoverageContract.from_scan_result(
                result,
                include_low=include_low,
                include_all_frameworks=True,
                project_root=str(P(path).resolve()),
            )
            n_excluded = len(full_contract.call_sites) - len(contract.call_sites)

            contract_path = P(emit_contract)
            contract.write(contract_path)
            if not output_json:
                n = len(contract.call_sites)
                exc_note = (
                    f", {n_excluded} excluded (LangChain/LiteLLM)" if n_excluded else ""
                )
                console.print(
                    f"  [bold green]Coverage contract written:[/] {contract_path} "
                    f"({n} site{'s' if n != 1 else ''}{exc_note})"
                )
                console.print()
        except Exception as e:
            if output_json:
                _output_json(
                    {
                        "tool": "assay-scan",
                        "status": "error",
                        "error": f"contract emission failed: {e}",
                    },
                    exit_code=2,
                )
            else:
                console.print(f"[red]Contract emission error:[/] {e}")
            raise typer.Exit(2)

    # Generate HTML report if requested
    if report:
        from assay.reporting.evidence_gap import (
            build_report,
            render_html,
            write_json,
            write_report,
        )

        html_path = P(report_path) if report_path else P("evidence_gap_report.html")
        json_path = html_path.with_suffix(".json")

        try:
            gap_report = build_report(result.to_dict(), P(path))
            html = render_html(gap_report)
            write_report(html, html_path)
            write_json(gap_report, json_path)
        except Exception as e:
            if output_json:
                _output_json(
                    {
                        "tool": "assay-scan",
                        "status": "error",
                        "error": f"report generation failed: {e}",
                    },
                    exit_code=2,
                )
            else:
                console.print(f"[red]Report generation error:[/] {e}")
            raise typer.Exit(2)

        if not output_json:
            console.print(f"  [bold green]Report written:[/] {html_path}")
            console.print(f"  [dim]JSON sidecar:[/]  {json_path}")
            console.print()

    if output_json:
        # Determine exit code
        s = result.summary
        exit_code = 0
        if ci:
            threshold = {
                "high": Confidence.HIGH,
                "medium": Confidence.MEDIUM,
                "low": Confidence.LOW,
            }.get(fail_on, Confidence.HIGH)
            if threshold == Confidence.HIGH and s["high"] > 0:
                exit_code = 1
            elif threshold == Confidence.MEDIUM and (s["high"] + s["medium"]) > 0:
                exit_code = 1
            elif threshold == Confidence.LOW and s["uninstrumented"] > 0:
                exit_code = 1
        payload = result.to_dict()
        payload["scan_status"] = payload["status"]
        payload["status"] = "blocked" if (ci and exit_code != 0) else "ok"
        _output_json(payload, exit_code=exit_code)
        return

    # Human output
    s = result.summary
    console.print()

    if not result.findings:
        console.print("  [dim]No LLM call sites detected.[/]")
        console.print()
        console.print("  [bold]Next steps:[/]")
        console.print(
            "    1. If you use wrappers, add manual receipt emission near your model call:"
        )
        console.print("       from assay import emit_receipt")
        console.print(
            "       emit_receipt('model_call', {'provider': '...', 'model_id': '...'})"
        )
        console.print("    2. Run a first pack anyway:")
        console.print("       assay run --allow-empty -- python your_app.py")
        console.print("    3. Verify + demo confidence model:")
        console.print("       assay verify-pack ./proof_pack_*/")
        console.print("       assay demo-incident")
        console.print()
        raise typer.Exit(0)

    # Header
    console.print(
        f"  [bold]Found {s['sites_total']} LLM call site{'s' if s['sites_total'] != 1 else ''}:[/]"
    )
    console.print()

    conf_styles = {
        "high": "[red]HIGH[/]  ",
        "medium": "[yellow]MED[/]   ",
        "low": "[dim]LOW[/]   ",
    }
    status_styles = {
        True: "[green]INSTRUMENTED[/]",
        False: "[red]NO RECEIPT[/]  ",
    }

    for finding in result.findings:
        conf = conf_styles.get(finding.confidence.value, "")
        status = status_styles[finding.instrumented]
        console.print(
            f"  {conf} {finding.path}:{finding.line:<6} {finding.call:<45} {status}"
        )

    console.print()
    console.print(
        f"  [bold]{s['instrumented']}[/] of [bold]{s['sites_total']}[/] call sites instrumented. "
        f"[red]{s['uninstrumented']} uninstrumented[/] "
        f"({s['high']} high, {s['medium']} medium, {s['low']} low)"
    )

    if result.next_command:
        console.print()
        console.print("  [bold]Next steps:[/]")
        for line in result.next_command.split("\n"):
            console.print(f"    {line}")

    console.print()

    # Exit code
    if ci:
        threshold = {
            "high": Confidence.HIGH,
            "medium": Confidence.MEDIUM,
            "low": Confidence.LOW,
        }.get(fail_on, Confidence.HIGH)
        if threshold == Confidence.HIGH and s["high"] > 0:
            raise typer.Exit(1)
        elif threshold == Confidence.MEDIUM and (s["high"] + s["medium"]) > 0:
            raise typer.Exit(1)
        elif threshold == Confidence.LOW and s["uninstrumented"] > 0:
            raise typer.Exit(1)

    raise typer.Exit(0)


@assay_app.command("doctor", rich_help_panel="Operate")
def doctor_cmd(
    profile: str = typer.Option(
        "local",
        "--profile",
        "-p",
        help="Check profile: local, ci, release, ledger",
    ),
    pack: Optional[str] = typer.Option(
        None,
        "--pack",
        help="Path to Proof Pack directory to check",
    ),
    lock: Optional[str] = typer.Option(
        None,
        "--lock",
        help="Path to lockfile to check",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Treat warnings as failures",
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Apply safe automatic fixes (generate key, write lockfile)",
    ),
    check_orphans: bool = typer.Option(
        False,
        "--check-orphans",
        help="Also detect orphaned episodes and open contradictions (store-backed checks)",
    ),
):
    """Check if Assay is installed, configured, and ready to use.

    Answers four questions in under 2 seconds:
    1. Is Assay installed and runnable here?
    2. Can this machine create and verify packs?
    3. Is this repo configured for your claimed workflow?
    4. What is the single next command to become "green"?

    Use --check-orphans to also detect constitutional integrity violations:
    orphaned episodes (opened but never closed) and open contradictions
    (registered but never resolved).
    """
    from pathlib import Path

    from assay.doctor import CheckStatus, Profile, run_doctor

    # Parse profile
    try:
        prof = Profile(profile.lower())
    except ValueError:
        console.print(
            f"[red]Error:[/] Unknown profile '{profile}'. Use: local, ci, release, ledger"
        )
        raise typer.Exit(3)

    pack_dir = Path(pack) if pack else None
    lock_path = Path(lock) if lock else None

    # Run checks
    report = run_doctor(
        prof,
        pack_dir=pack_dir,
        lock_path=lock_path,
        strict=strict,
        check_orphans=check_orphans,
    )

    # Apply fixes if requested
    if fix:
        for check in report.checks:
            if check.status in (CheckStatus.WARN, CheckStatus.FAIL) and check.fix:
                if check.id == "DOCTOR_KEY_001" and check.status == CheckStatus.WARN:
                    try:
                        from assay.keystore import (
                            DEFAULT_SIGNER_ID,
                            get_default_keystore,
                        )

                        ks = get_default_keystore()
                        ks.generate_key(DEFAULT_SIGNER_ID)
                        check.status = CheckStatus.PASS
                        check.message += " (fixed: key generated)"
                        if not output_json:
                            console.print("  [green]Fixed:[/] Generated signing key")
                    except Exception as e:
                        if not output_json:
                            console.print(f"  [red]Fix failed:[/] {e}")

                elif check.id == "DOCTOR_LOCK_001" and check.status in (
                    CheckStatus.WARN,
                    CheckStatus.FAIL,
                ):
                    try:
                        from assay.lockfile import write_lockfile

                        target = lock_path or Path("assay.lock")
                        write_lockfile(
                            ["receipt_completeness"],
                            output_path=target,
                        )
                        check.status = CheckStatus.PASS
                        check.message += " (fixed: lockfile written)"
                        if not output_json:
                            console.print(f"  [green]Fixed:[/] Wrote {target}")
                        # Re-run LOCK_002 against the newly written lockfile
                        for other in report.checks:
                            if other.id == "DOCTOR_LOCK_002":
                                from assay.doctor import _check_lock_002

                                refreshed = _check_lock_002(target)
                                other.status = refreshed.status
                                other.message = refreshed.message
                                other.evidence = refreshed.evidence
                                other.fix = refreshed.fix
                                break
                    except Exception as e:
                        if not output_json:
                            console.print(f"  [red]Fix failed:[/] {e}")

        # Recompute next command after fixes
        from assay.doctor import _determine_next_command

        report.next_command = _determine_next_command(report)

    # Output
    if output_json:
        _output_json(
            report.to_dict(),
            exit_code=report.exit_code_strict() if strict else report.exit_code,
        )
        return

    _render_doctor_report(report, strict)


def _render_doctor_report(report, strict: bool = False) -> None:
    """Render a doctor report to console and exit with appropriate code."""
    from assay.doctor import CheckStatus

    console.print()
    console.print(f"[bold]assay doctor[/] (profile={report.profile.value})")
    console.print()

    status_styles = {
        "pass": "[green]PASS[/] ",
        "warn": "[yellow]WARN[/] ",
        "fail": "[red]FAIL[/] ",
        "skip": "[dim]SKIP[/] ",
    }

    for check in report.checks:
        style = status_styles.get(check.status.value, "")
        console.print(f"  {style} {check.id}  {check.message}")
        if check.status == CheckStatus.FAIL and check.fix:
            console.print(f"         [dim]Fix:[/] {check.fix}")

    # Summary line
    s = report.summary
    console.print()
    parts = []
    if s["pass"]:
        parts.append(f"[green]PASS: {s['pass']}[/]")
    if s["warn"]:
        parts.append(f"[yellow]WARN: {s['warn']}[/]")
    if s["fail"]:
        parts.append(f"[red]FAIL: {s['fail']}[/]")
    if s["skip"]:
        parts.append(f"[dim]SKIP: {s['skip']}[/]")
    console.print("  " + " | ".join(parts))

    if report.next_command:
        console.print()
        console.print(f"  [bold]Next:[/] {report.next_command}")

    console.print()

    exit_code = report.exit_code_strict() if strict else report.exit_code
    raise typer.Exit(exit_code)


@assay_app.command("explain", rich_help_panel="Operate")
def explain_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory"),
    output_format: str = typer.Option(
        "text", "--format", "-f", help="Output format: text, md, json"
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Output as JSON (same as --format json)"
    ),
    causal: bool = typer.Option(
        False, "--causal", help="Show backward causal chains from failures"
    ),
):
    """Explain a proof pack in plain English.

    Reads a proof pack and outputs a human-readable summary covering:
    what happened, integrity status, claim results, what the pack proves,
    and what it does NOT prove.

    With --causal, also traces failures backward to their root causes.

    Designed for non-engineers: compliance officers, auditors, executives.

    Examples:
      assay explain ./proof_pack_*/
      assay explain ./proof_pack_*/ --format md
      assay explain ./proof_pack_abc123/ --json
      assay explain ./proof_pack_*/ --causal
    """
    from pathlib import Path

    from assay.explain import explain_pack, render_md, render_text

    pd = Path(pack_dir)
    if not pd.is_dir():
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(1)

    info = explain_pack(pd)

    # Build causal chains if requested
    causal_data = None
    if causal:
        from assay.analyze import load_pack_receipts
        from assay.incident import (
            build_causal_chains,
            render_causal_md,
            render_causal_text,
        )

        try:
            receipts = load_pack_receipts(pd)
        except FileNotFoundError:
            receipts = []
        chains = build_causal_chains(receipts, info)
        causal_data = chains

    if output_json or output_format == "json":
        payload = {
            "command": "explain",
            "status": "ok",
            **info,
        }
        if causal_data is not None:
            payload["causal_chains"] = [c.to_dict() for c in causal_data]
        _output_json(payload)
        return

    if output_format == "md":
        console.print(render_md(info))
        if causal_data is not None:
            from assay.incident import render_causal_md

            console.print()
            console.print(render_causal_md(causal_data))
        return

    console.print()
    console.print(render_text(info))
    if causal_data is not None:
        from assay.incident import render_causal_text

        console.print()
        console.print(render_causal_text(causal_data))


@assay_app.command("demo-incident", rich_help_panel="Start Here")
def demo_incident_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Demonstrate how Assay catches policy violations.

    Runs a two-act scenario using synthetic data (no API key needed):

    Act 1: Agent runs correctly with gpt-4 and guardian check.
           Result: Integrity PASS, Claims PASS.

    Act 2: Someone swaps the model to gpt-3.5-turbo and removes
           the guardian check. Same code, different behavior.
           Result: Integrity PASS, Claims FAIL.

    This demonstrates "honest failure" -- the evidence is authentic,
    and it proves the run violated the declared standards.
    """
    import tempfile
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec
    from assay.integrity import verify_pack_manifest
    from assay.keystore import AssayKeyStore
    from assay.proof_pack import ProofPack

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        ks = AssayKeyStore(keys_dir=td / "keys")
        ks.generate_key("demo")

        ts_base = "2026-02-10T09:00:0"

        # --- ACT 1: Everything works correctly ---
        receipts_good = [
            {
                "receipt_id": "r_act1_001",
                "type": "model_call",
                "timestamp": f"{ts_base}0Z",
                "schema_version": "3.0",
                "seq": 0,
                "model_id": "gpt-4",
                "provider": "openai",
                "total_tokens": 2100,
                "input_tokens": 1500,
                "output_tokens": 600,
                "latency_ms": 1200,
                "finish_reason": "stop",
            },
            {
                "receipt_id": "r_act1_002",
                "type": "guardian_verdict",
                "timestamp": f"{ts_base}1Z",
                "schema_version": "3.0",
                "seq": 1,
                "verdict": "allow",
                "action": "generate_response",
                "reason": "Content meets safety policy",
            },
            {
                "receipt_id": "r_act1_003",
                "type": "model_call",
                "timestamp": f"{ts_base}2Z",
                "schema_version": "3.0",
                "seq": 2,
                "model_id": "gpt-4",
                "provider": "openai",
                "total_tokens": 1800,
                "input_tokens": 1200,
                "output_tokens": 600,
                "latency_ms": 980,
                "finish_reason": "stop",
            },
        ]

        # Claims: require guardian + model calls
        claims = [
            ClaimSpec(
                claim_id="has_model_calls",
                description="At least one model_call receipt",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
            ClaimSpec(
                claim_id="guardian_enforced",
                description="Guardian verdict was issued",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
            ClaimSpec(
                claim_id="no_breakglass",
                description="No override receipts",
                check="no_receipt_type",
                params={"receipt_type": "breakglass"},
            ),
        ]

        # Build & verify Act 1
        pack_good = ProofPack(
            run_id="incident-act1-correct",
            entries=receipts_good,
            signer_id="demo",
            claims=claims,
            mode="shadow",
        )
        out_good = pack_good.build(td / "pack_act1", keystore=ks)
        manifest_good = json.loads((out_good / "pack_manifest.json").read_text())
        att_good = manifest_good["attestation"]
        result_good = verify_pack_manifest(manifest_good, out_good, ks)

        # --- ACT 2: Model swapped, guardian removed ---
        receipts_bad = [
            {
                "receipt_id": "r_act2_001",
                "type": "model_call",
                "timestamp": f"{ts_base}5Z",
                "schema_version": "3.0",
                "seq": 0,
                "model_id": "gpt-3.5-turbo",  # <-- swapped
                "provider": "openai",
                "total_tokens": 900,
                "input_tokens": 600,
                "output_tokens": 300,
                "latency_ms": 340,
                "finish_reason": "stop",
            },
            # No guardian_verdict -- removed
            {
                "receipt_id": "r_act2_002",
                "type": "model_call",
                "timestamp": f"{ts_base}6Z",
                "schema_version": "3.0",
                "seq": 1,
                "model_id": "gpt-3.5-turbo",  # <-- swapped
                "provider": "openai",
                "total_tokens": 750,
                "input_tokens": 500,
                "output_tokens": 250,
                "latency_ms": 280,
                "finish_reason": "stop",
            },
        ]

        # Same claims applied to bad receipts
        pack_bad = ProofPack(
            run_id="incident-act2-violated",
            entries=receipts_bad,
            signer_id="demo",
            claims=claims,
            mode="shadow",
        )
        out_bad = pack_bad.build(td / "pack_act2", keystore=ks)
        manifest_bad = json.loads((out_bad / "pack_manifest.json").read_text())
        att_bad = manifest_bad["attestation"]

        if output_json:
            _output_json(
                {
                    "command": "demo-incident",
                    "status": "ok",
                    "act1": {
                        "pack_id": att_good["pack_id"],
                        "integrity": att_good["receipt_integrity"],
                        "claims": att_good["claim_check"],
                        "model": "gpt-4",
                        "guardian": True,
                        "n_receipts": att_good["n_receipts"],
                    },
                    "act2": {
                        "pack_id": att_bad["pack_id"],
                        "integrity": att_bad["receipt_integrity"],
                        "claims": att_bad["claim_check"],
                        "model": "gpt-3.5-turbo",
                        "guardian": False,
                        "n_receipts": att_bad["n_receipts"],
                    },
                }
            )

        # --- Console output ---
        console.print()
        console.print("[bold]ASSAY DEMO: INCIDENT DETECTION[/]")
        console.print()
        console.print("[dim]This demo shows how Assay catches policy violations[/]")
        console.print("[dim]using the same claims against different evidence.[/]")
        console.print()

        # Act 1
        console.print("[bold]ACT 1: Correct operation[/]")
        console.print("  Agent uses gpt-4 with guardian enforcement.")
        console.print("  3 receipts: 2 model_call (gpt-4) + 1 guardian_verdict")
        console.print()
        console.print(
            Panel.fit(
                f"Integrity:  [green]{att_good['receipt_integrity']}[/]\n"
                f"Claims:     [green]{att_good['claim_check']}[/]\n"
                f"  has_model_calls:    [green]PASS[/]\n"
                f"  guardian_enforced:  [green]PASS[/]\n"
                f"  no_breakglass:     [green]PASS[/]",
                title="Act 1: PASS / PASS",
                border_style="green",
            )
        )

        console.print()
        console.print("[bold]ACT 2: Someone cuts corners[/]")
        console.print("  Model swapped to gpt-3.5-turbo (cheaper, less capable).")
        console.print("  Guardian check removed entirely.")
        console.print("  2 receipts: 2 model_call (gpt-3.5-turbo), no guardian_verdict")
        console.print()
        console.print(
            Panel.fit(
                f"Integrity:  [green]{att_bad['receipt_integrity']}[/]  (evidence is authentic)\n"
                f"Claims:     [red]{att_bad['claim_check']}[/]  (policy violated)\n"
                f"  has_model_calls:    [green]PASS[/]\n"
                f"  guardian_enforced:  [red]FAIL[/]  -- no guardian_verdict receipt\n"
                f"  no_breakglass:     [green]PASS[/]",
                title="Act 2: PASS / FAIL",
                border_style="red",
            )
        )

        console.print()
        console.print("[bold]THE EVIDENCE[/]")
        console.print()
        console.print("  Act 1 receipts show: gpt-4, guardian approved")
        console.print("  Act 2 receipts show: gpt-3.5-turbo, no guardian")
        console.print()
        console.print("  The model was swapped. The guardian was removed.")
        console.print(
            "  The evidence is cryptographic. Nobody can argue about what happened."
        )
        console.print()

        console.print("[bold]KEY INSIGHT[/]")
        console.print()
        console.print("  Integrity PASS + Claims FAIL = [bold]honest failure[/].")
        console.print("  The evidence is authentic, and it proves the run")
        console.print("  violated the declared standards. This is not a bug.")
        console.print("  This is Assay working as designed.")
        console.print()
        console.print("[dim]To see the full explanation of each pack:[/]")
        console.print("  assay explain <pack_dir>")
        console.print()


@assay_app.command("quickstart", rich_help_panel="Operate", hidden=True)
def quickstart_cmd(
    path: str = typer.Argument(".", help="Project directory to explore"),
    skip_demo: bool = typer.Option(
        False, "--skip-demo", help="Skip demo-challenge generation"
    ),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
    force: bool = typer.Option(
        False, "--force", help="Bypass the large-directory guard"
    ),
):
    """One command to see Assay in action.

    Creates a demo challenge pack, scans your project for uninstrumented
    AI call sites, and prints actionable next steps.
    Use `assay onboard` for full setup with doctor + CI guidance.

    \b
    Examples:
      assay quickstart
      assay quickstart ./my_project
      assay quickstart --skip-demo
    """
    import shutil
    import tempfile
    from pathlib import Path as P

    from assay.scanner import scan_directory

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "quickstart",
                    "status": "error",
                    "error": f"Directory not found: {path}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] Directory not found: {path}")
        raise typer.Exit(3)

    # Guard: block scanning from system-wide directories
    _QUICKSTART_MAX_FILES = 10_000
    _QUICKSTART_WARN_DIRS = {
        P.home(),
        P("/"),
        P("/Users"),
        P("/home"),
    }
    if root in _QUICKSTART_WARN_DIRS and not force:
        msg = (
            f"Scanning {root} may take a long time.\n"
            "Tip: run from your project directory instead:\n"
            "  cd your-project && assay quickstart"
        )
        if output_json:
            _output_json(
                {"command": "quickstart", "status": "error", "error": msg}, exit_code=3
            )
        console.print(f"[yellow]Warning:[/] {msg}")
        raise typer.Exit(3)

    # Guard: bail if too many Python files (early exit, doesn't enumerate all)
    if not force:
        _py_count = 0
        for _ in root.rglob("*.py"):
            _py_count += 1
            if _py_count > _QUICKSTART_MAX_FILES:
                break
        if _py_count > _QUICKSTART_MAX_FILES:
            msg = (
                f"Found >{_QUICKSTART_MAX_FILES:,} Python files. "
                "This looks like a system directory, not a project.\n"
                "Tip: cd into your project first, or use --force to proceed."
            )
            if output_json:
                _output_json(
                    {"command": "quickstart", "status": "error", "error": msg},
                    exit_code=3,
                )
            console.print(f"[yellow]Warning:[/] {msg}")
            raise typer.Exit(3)

    def _print(*args, **kwargs):
        if not output_json:
            console.print(*args, **kwargs)

    results: dict = {"command": "quickstart", "steps": []}
    demo_dir = root / "challenge_pack"
    next_steps: list = []

    # Step 1: Demo challenge
    if not skip_demo:
        _print()
        _print("[bold]Step 1:[/] Creating demo challenge pack...")
        try:
            from assay.claim_verifier import ClaimSpec
            from assay.keystore import AssayKeyStore
            from assay.proof_pack import ProofPack

            with tempfile.TemporaryDirectory() as tmpdir:
                td = P(tmpdir)
                ks = AssayKeyStore(keys_dir=td / "keys")
                ks.generate_key("challenge")

                ts_base = "2026-02-10T12:00:0"
                receipts = [
                    {
                        "receipt_id": "r_chal_001",
                        "type": "model_call",
                        "timestamp": f"{ts_base}0Z",
                        "schema_version": "3.0",
                        "seq": 0,
                        "model_id": "gpt-4",
                        "provider": "openai",
                        "total_tokens": 2500,
                        "input_tokens": 1800,
                        "output_tokens": 700,
                        "latency_ms": 1100,
                        "finish_reason": "stop",
                    },
                    {
                        "receipt_id": "r_chal_002",
                        "type": "guardian_verdict",
                        "timestamp": f"{ts_base}1Z",
                        "schema_version": "3.0",
                        "seq": 1,
                        "verdict": "allow",
                        "action": "generate_summary",
                        "reason": "Content is within policy bounds",
                    },
                ]
                claims = [
                    ClaimSpec(
                        claim_id="has_model_calls",
                        description="At least one model_call receipt",
                        check="receipt_type_present",
                        params={"receipt_type": "model_call"},
                    ),
                ]

                pack = ProofPack(
                    run_id="quickstart-run",
                    entries=receipts,
                    signer_id="challenge",
                    claims=claims,
                    mode="shadow",
                )
                good_dir = pack.build(td / "good", keystore=ks)

                demo_dir.mkdir(parents=True, exist_ok=True)
                good_out = demo_dir / "good"
                tampered_out = demo_dir / "tampered"

                if good_out.exists():
                    shutil.rmtree(good_out)
                shutil.copytree(good_dir, good_out)

                if tampered_out.exists():
                    shutil.rmtree(tampered_out)
                shutil.copytree(good_dir, tampered_out)
                receipt_file = tampered_out / "receipt_pack.jsonl"
                data = bytearray(receipt_file.read_bytes())
                target = b'"gpt-4"'
                idx = data.find(target)
                if idx >= 0:
                    data[idx + 1 : idx + 6] = b"gpt-5"
                receipt_file.write_bytes(bytes(data))

            _print(f"  [green]Created[/] {demo_dir}/ (good + tampered packs)")
            results["steps"].append(
                {"step": "demo", "status": "ok", "dir": str(demo_dir)}
            )
            next_steps.append(
                f"Verify good pack:     assay verify-pack {demo_dir}/good/"
            )
            next_steps.append(
                f"Verify tampered pack: assay verify-pack {demo_dir}/tampered/"
            )
        except Exception as e:
            _print(f"  [yellow]Skipped:[/] {e}")
            results["steps"].append(
                {"step": "demo", "status": "skipped", "error": str(e)}
            )
    else:
        _print()
        _print("[dim]Step 1: Skipped (--skip-demo)[/]")
        results["steps"].append({"step": "demo", "status": "skipped"})

    # Step 2: Scan
    _print()
    _print("[bold]Step 2:[/] Scanning for AI call sites...")
    try:
        scan_result = scan_directory(root, exclude=["challenge_pack/**"])
        s = scan_result.summary
        uninstrumented = s["uninstrumented"]
        _print(
            f"  Found {s['sites_total']} call site(s): "
            f"[green]{s['instrumented']} instrumented[/], "
            f"[{'red' if uninstrumented else 'green'}]{uninstrumented} uninstrumented[/]"
        )

        results["steps"].append(
            {
                "step": "scan",
                "status": "ok",
                "sites_total": s["sites_total"],
                "instrumented": s["instrumented"],
                "uninstrumented": uninstrumented,
            }
        )

        # Generate report if there are findings (skip in JSON mode)
        if scan_result.findings and not output_json:
            from assay.reporting.evidence_gap import (
                build_report,
                render_html,
                write_report,
            )

            report_file = root / "assay_quickstart_report.html"
            gap_report = build_report(scan_result.to_dict(), root)
            html = render_html(gap_report)
            write_report(html, report_file)
            _print(f"  [green]Report:[/] {report_file}")
            results["steps"][-1]["report"] = str(report_file)

        if uninstrumented > 0:
            next_steps.append(f"Patch entrypoint:     assay patch {path}")
        next_steps.append(
            "Run with receipts:    assay run -c receipt_completeness -- python your_app.py"
        )
        next_steps.append("Lock baseline:        assay lock init")
        next_steps.append("Enable CI:            assay ci init github")

    except Exception as e:
        _print(f"  [yellow]Scan error:[/] {e}")
        results["steps"].append({"step": "scan", "status": "error", "error": str(e)})

    # Step 3: Next steps
    _print()
    scan_cmd = f"assay scan {path} --report"
    if not next_steps:
        _print("[dim]No AI call sites found.[/] Add SDK integrations and re-scan:")
        _print()
        _print("  python3 -m pip install 'assay-ai[openai]'")
        _print("  # Add to your entrypoint:")
        _print("  # from assay.integrations.openai import patch; patch()")
        _print()
        _print(f"  Then re-run: [bold]{scan_cmd}[/]")
        results["next_steps"] = [
            "Install SDK: python3 -m pip install 'assay-ai[openai]'",
            f"Re-scan: {scan_cmd}",
        ]
    else:
        # Separate demo (synthetic) steps from real-project steps
        demo_step_prefixes = ("Verify good pack", "Verify tampered pack")
        demo_steps = [
            s for s in next_steps if s.lstrip().startswith(demo_step_prefixes)
        ]
        real_steps_raw = [
            s for s in next_steps if not s.lstrip().startswith(demo_step_prefixes)
        ]
        real_steps_raw.insert(0, f"View gap report:      {scan_cmd}")

        if demo_steps:
            _print("[bold]Demo packs (synthetic — for learning the verifier):[/]")
            _print()
            for i, step in enumerate(demo_steps, 1):
                _print(f"  {i}. {step}")
            _print()

        _print("[bold]Your project (real instrumentation):[/]")
        _print()
        for i, step in enumerate(real_steps_raw, 1):
            _print(f"  {i}. {step}")

        results["next_steps"] = demo_steps + real_steps_raw
    _print()

    if output_json:
        results["status"] = "ok"
        _output_json(results, exit_code=0)


@assay_app.command("demo-challenge", rich_help_panel="Start Here")
def demo_challenge_cmd(
    output_dir: str = typer.Option(
        "./challenge_pack", "--output", "-o", help="Output directory"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a challenge: one valid pack, one tampered pack.

    Creates two proof packs side by side. One is authentic.
    One has been tampered with (a single byte changed in the receipts).
    Your machine decides which is real.

    No API key needed. No trust required. Just verification.

    Examples:
      assay demo-challenge
      assay verify-pack ./challenge_pack/good/
      assay verify-pack ./challenge_pack/tampered/
    """
    import hashlib
    import tempfile
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec
    from assay.keystore import AssayKeyStore
    from assay.proof_pack import ProofPack

    out = Path(output_dir)

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        ks = AssayKeyStore(keys_dir=td / "keys")
        ks.generate_key("challenge")

        ts_base = "2026-02-10T12:00:0"
        receipts = [
            {
                "receipt_id": "r_chal_001",
                "type": "model_call",
                "timestamp": f"{ts_base}0Z",
                "schema_version": "3.0",
                "seq": 0,
                "model_id": "gpt-4",
                "provider": "openai",
                "total_tokens": 2500,
                "input_tokens": 1800,
                "output_tokens": 700,
                "latency_ms": 1100,
                "finish_reason": "stop",
            },
            {
                "receipt_id": "r_chal_002",
                "type": "guardian_verdict",
                "timestamp": f"{ts_base}1Z",
                "schema_version": "3.0",
                "seq": 1,
                "verdict": "allow",
                "action": "generate_summary",
                "reason": "Content is within policy bounds",
            },
            {
                "receipt_id": "r_chal_003",
                "type": "model_call",
                "timestamp": f"{ts_base}2Z",
                "schema_version": "3.0",
                "seq": 2,
                "model_id": "gpt-4",
                "provider": "openai",
                "total_tokens": 1900,
                "input_tokens": 1300,
                "output_tokens": 600,
                "latency_ms": 950,
                "finish_reason": "stop",
            },
        ]

        claims = [
            ClaimSpec(
                claim_id="has_model_calls",
                description="At least one model_call receipt",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
            ClaimSpec(
                claim_id="guardian_enforced",
                description="Guardian verdict was issued",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]

        # Build the good pack
        pack = ProofPack(
            run_id="challenge-run",
            entries=receipts,
            signer_id="challenge",
            claims=claims,
            mode="shadow",
        )
        good_dir = pack.build(td / "good", keystore=ks)

        # Copy the good pack to output
        out.mkdir(parents=True, exist_ok=True)
        good_out = out / "good"
        tampered_out = out / "tampered"

        # Copy good pack
        import shutil

        if good_out.exists():
            shutil.rmtree(good_out)
        shutil.copytree(good_dir, good_out)

        # Create tampered pack: copy good, then flip one byte in receipt_pack.jsonl
        if tampered_out.exists():
            shutil.rmtree(tampered_out)
        shutil.copytree(good_dir, tampered_out)
        receipt_file = tampered_out / "receipt_pack.jsonl"
        data = bytearray(receipt_file.read_bytes())
        # Find "gpt-4" in the receipts and change it to "gpt-5" (one char)
        target = b'"gpt-4"'
        idx = data.find(target)
        if idx >= 0:
            data[idx + 1 : idx + 6] = b"gpt-5"
        receipt_file.write_bytes(bytes(data))

    # Generate SHA256 sums
    sha_lines = []
    for subdir in ["good", "tampered"]:
        for f in sorted((out / subdir).iterdir()):
            if f.is_dir():
                continue
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            sha_lines.append(f"{h}  {subdir}/{f.name}")
    sha_file = out / "SHA256SUMS.txt"
    sha_file.write_text("\n".join(sha_lines) + "\n")

    # Write instructions
    readme = out / "CHALLENGE.md"
    readme.write_text(
        "# Assay Challenge Pack\n\n"
        "Two proof packs. One is authentic. One has been tampered with.\n"
        "Your machine decides which is real.\n\n"
        "```bash\n"
        "python3 -m pip install assay-ai\n"
        "assay verify-pack ./good/\n"
        "assay verify-pack ./tampered/\n"
        "```\n\n"
        "One will exit 0 (authentic). One will exit non-zero (tampered).\n\n"
        "To see the full explanation:\n"
        "```bash\n"
        "assay explain ./good/\n"
        "assay explain ./tampered/\n"
        "```\n\n"
        "Learn more: https://github.com/Haserjian/assay\n"
    )

    # Auto-verify both packs for the inline demo
    from assay.integrity import verify_pack_manifest
    from assay.keystore import get_default_keystore

    good_manifest = json.loads((good_out / "pack_manifest.json").read_text())
    good_att = good_manifest["attestation"]
    tampered_manifest = json.loads((tampered_out / "pack_manifest.json").read_text())
    verify_ks = get_default_keystore()
    good_result = verify_pack_manifest(good_manifest, good_out, verify_ks)
    tampered_result = verify_pack_manifest(tampered_manifest, tampered_out, verify_ks)

    if output_json:
        _output_json(
            {
                "command": "demo-challenge",
                "status": "ok",
                "output_dir": str(out),
                "good_pack": str(good_out),
                "tampered_pack": str(tampered_out),
                "good_result": "PASS" if good_result.passed else "FAIL",
                "tampered_result": "PASS" if tampered_result.passed else "FAIL",
            }
        )

    console.print()
    console.print("[bold]ASSAY CHALLENGE PACK[/]")
    console.print()
    console.print(
        "  Created two proof packs. One is authentic. One has been tampered with."
    )
    console.print("  One byte changed in the receipts. Can your machine tell?")
    console.print()

    # Good pack result
    console.print(
        Panel.fit(
            f"[bold green]VERIFICATION PASSED[/]\n\n"
            f"Pack ID:    {good_att['pack_id']}\n"
            f"Integrity:  [green]PASS[/]\n"
            f"Claims:     [green]PASS[/]\n"
            f"Receipts:   {good_att['n_receipts']}\n"
            f"Head Hash:  {good_att.get('head_hash', 'N/A')[:16]}...\n"
            f"Signature:  Ed25519 [green]valid[/]",
            title=f"good/ -- assay verify-pack {good_out}/",
            border_style="green",
        )
    )
    console.print()

    # Tampered pack result
    err_msg = (
        tampered_result.errors[0].message if tampered_result.errors else "unknown error"
    )
    console.print(
        Panel.fit(
            f"[bold red]VERIFICATION FAILED[/]\n\n"
            f"Pack ID:    {good_att['pack_id']}\n"
            f"Integrity:  [red]FAIL[/]\n"
            f"Error:      [red]{err_msg}[/]",
            title=f"tampered/ -- assay verify-pack {tampered_out}/",
            border_style="red",
        )
    )

    console.print()
    console.print("  [bold]What happened:[/]")
    console.print(
        '  The tampered pack changed [bold]"gpt-4"[/] to [bold]"gpt-5"[/] in the receipts.'
    )
    console.print("  The manifest hash no longer matches. Verification fails.")
    console.print("  No server access needed. No trust required. Just math.")
    console.print()
    console.print("  [dim]To dig deeper:[/]")
    console.print(f"    assay explain {good_out}/")
    console.print(f"    assay explain {tampered_out}/")
    if _should_show_feedback_footer():
        console.print()
        console.print(
            f"  [dim]Feedback:[/] {_feedback_url_for_source('demo-challenge')}"
        )
    console.print()


@assay_app.command("analyze", rich_help_panel="Operate", hidden=True)
def analyze_cmd(
    pack_dir: Optional[str] = typer.Argument(None, help="Path to proof pack directory"),
    history: bool = typer.Option(
        False, "--history", help="Analyze local trace history instead of a pack"
    ),
    since: int = typer.Option(
        7, "--since", help="Days of history to analyze (with --history)"
    ),
    regime_detect: bool = typer.Option(
        False,
        "--regime-detect",
        help="Detect regime changes (model swaps, cost/latency drift)",
    ),
    window_hours: int = typer.Option(
        24,
        "--window-hours",
        help="Window size in hours for regime detection (default: 24)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Analyze receipts for cost, latency, and error breakdowns.

    Reads model_call receipts from a proof pack or local trace history
    and computes token usage, estimated cost, latency percentiles,
    error rates, and per-model/per-provider breakdowns.

    With --regime-detect, also detects regime changes across time windows:
    model swaps, cost spikes, latency drift, and error rate shifts.

    Pricing estimates are approximate.

    Examples:
      assay analyze ./proof_pack_*/
      assay analyze --history
      assay analyze --history --since 30
      assay analyze --history --regime-detect
      assay analyze --history --regime-detect --window-hours 12
      assay analyze ./proof_pack_*/ --json
    """
    from pathlib import Path

    from assay.analyze import (
        analyze_receipts,
        load_history_receipts,
        load_pack_receipts,
    )

    if not pack_dir and not history:
        console.print("[red]Error:[/] Provide a pack directory or use --history")
        raise typer.Exit(3)

    if pack_dir and history:
        console.print(
            "[red]Error:[/] Provide either a pack directory or --history, not both"
        )
        raise typer.Exit(3)

    try:
        if pack_dir:
            pd = Path(pack_dir)
            if not pd.is_dir():
                console.print(f"[red]Error:[/] {pack_dir} is not a directory")
                raise typer.Exit(3)
            receipts = load_pack_receipts(pd)
            result = analyze_receipts(receipts)
            result.source_type = "pack"
            result.source_path = str(pd)

            # Check if pack was verified
            manifest_path = pd / "pack_manifest.json"
            if manifest_path.exists():
                import json as _json

                manifest = _json.loads(manifest_path.read_text())
                att = manifest.get("attestation", {})
                integrity = str(
                    att.get("receipt_integrity") or att.get("integrity") or ""
                ).upper()
                result.verified = integrity == "PASS"
        else:
            receipts, trace_count = load_history_receipts(since_days=since)
            result = analyze_receipts(receipts)
            result.source_type = "history"
            from assay.store import assay_home

            result.source_path = str(assay_home())
            result.trace_count = trace_count
            result.history_days = since

    except FileNotFoundError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    # Regime detection
    regime_report = None
    if regime_detect:
        from assay.regime import detect_regimes

        regime_report = detect_regimes(receipts, window_hours=window_hours)

    if output_json:
        payload = {"command": "analyze", "status": "ok", **result.to_dict()}
        if regime_report is not None:
            payload["regime"] = regime_report.to_dict()
        _output_json(payload, exit_code=0)
        return

    # Rich table output
    _render_analysis(result, regime_report=regime_report)


def _render_analysis(result, regime_report=None) -> None:
    """Render analysis result to console with Rich tables."""
    console.print()

    if result.model_calls == 0:
        console.print("[yellow]No model_call receipts found.[/]")
        if result.total_receipts > 0:
            console.print(
                f"  ({result.total_receipts} total receipts, but none were model_call type)"
            )
        console.print()
        raise typer.Exit(0)

    # Header
    if result.source_type == "pack":
        source_label = f"pack: {result.source_path}"
    elif result.history_days is not None:
        source_label = f"history: last {result.history_days} days"
    else:
        source_label = "history"
    console.print(f"[bold]assay analyze[/]  ({source_label})")
    console.print()

    # Summary table
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column("key", style="dim")
    summary.add_column("value")
    summary.add_row("Model calls", str(result.model_calls))
    summary.add_row("Total receipts", str(result.total_receipts))
    summary.add_row("Input tokens", f"{result.input_tokens:,}")
    summary.add_row("Output tokens", f"{result.output_tokens:,}")
    summary.add_row("Total tokens", f"{result.total_tokens:,}")
    summary.add_row("Est. cost", f"${result.cost_usd:.4f}")
    if result.errors:
        summary.add_row("Errors", f"[red]{result.errors}[/] ({result.error_rate:.1%})")
    else:
        summary.add_row("Errors", "0")
    if result.time_start and result.time_end:
        summary.add_row("Time span", f"{result.time_start} .. {result.time_end}")
    if result.source_type == "history" and result.trace_count:
        summary.add_row("Traces", str(result.trace_count))
    console.print(Panel(summary, title="Summary", border_style="blue"))

    # Latency
    if result.latencies:
        lat = Table(show_header=False, box=None, padding=(0, 2))
        lat.add_column("key", style="dim")
        lat.add_column("value")
        lat.add_row("p50", f"{result.latency_p50} ms")
        lat.add_row("p95", f"{result.latency_p95} ms")
        lat.add_row("p99", f"{result.latency_p99} ms")
        lat.add_row("mean", f"{result.latency_mean} ms")
        lat.add_row("max", f"{result.latency_max} ms")
        console.print(Panel(lat, title="Latency", border_style="cyan"))

    # By model
    if result.by_model:
        model_table = Table(box=None, padding=(0, 1))
        model_table.add_column("Model", style="bold")
        model_table.add_column("Calls", justify="right")
        model_table.add_column("Tokens", justify="right")
        model_table.add_column("Cost", justify="right")
        model_table.add_column("Errors", justify="right")
        for model_id, b in sorted(result.by_model.items()):
            err_str = f"[red]{b['errors']}[/]" if b["errors"] else "0"
            model_table.add_row(
                model_id,
                str(b["calls"]),
                f"{b['total_tokens']:,}",
                f"${b['cost_usd']:.4f}",
                err_str,
            )
        console.print(Panel(model_table, title="By Model", border_style="green"))

    # By provider
    if len(result.by_provider) > 1:
        prov_table = Table(box=None, padding=(0, 1))
        prov_table.add_column("Provider", style="bold")
        prov_table.add_column("Calls", justify="right")
        prov_table.add_column("Tokens", justify="right")
        prov_table.add_column("Cost", justify="right")
        for prov, b in sorted(result.by_provider.items()):
            prov_table.add_row(
                prov, str(b["calls"]), f"{b['total_tokens']:,}", f"${b['cost_usd']:.4f}"
            )
        console.print(Panel(prov_table, title="By Provider", border_style="magenta"))

    # Finish reasons
    if result.finish_reasons:
        fr_parts = [
            f"{reason}: {count}"
            for reason, count in sorted(
                result.finish_reasons.items(), key=lambda x: str(x[0])
            )
        ]
        console.print(f"  [dim]Finish reasons:[/] {', '.join(fr_parts)}")

    # Regime detection results
    if regime_report is not None:
        console.print()
        _render_regime(regime_report)

    console.print()
    raise typer.Exit(0)


def _render_regime(report) -> None:
    """Render regime detection results to console."""
    _severity_style = {"alert": "bold red", "warning": "yellow", "info": "dim"}

    if not report.flags:
        console.print(
            Panel(
                f"[green]No regime changes detected[/] across {report.n_windows} "
                f"window(s) ({report.window_hours}h each, {report.n_receipts} calls).",
                title="Regime Detection",
                border_style="green",
            )
        )
        return

    # Summary
    parts = []
    if report.n_alerts:
        parts.append(f"[bold red]{report.n_alerts} alert(s)[/]")
    if report.n_warnings:
        parts.append(f"[yellow]{report.n_warnings} warning(s)[/]")
    if report.n_info:
        parts.append(f"[dim]{report.n_info} info[/]")
    summary_line = (
        f"{len(report.flags)} drift flag(s): {', '.join(parts)}  "
        f"({report.n_windows} windows, {report.window_hours}h each)"
    )

    # Flags table
    flag_table = Table(box=None, padding=(0, 1))
    flag_table.add_column("Severity", style="bold", width=8)
    flag_table.add_column("Type", width=14)
    flag_table.add_column("Window", width=22)
    flag_table.add_column("Description")
    for f in report.flags:
        style = _severity_style.get(f.severity, "")
        flag_table.add_row(
            f"[{style}]{f.severity.upper()}[/{style}]",
            f.flag_type,
            f.window_after[:19],
            f.description,
        )

    console.print(
        Panel(
            flag_table,
            title=f"Regime Detection -- {summary_line}",
            border_style="red" if report.n_alerts else "yellow",
        )
    )


@assay_app.command("diff", hidden=True, rich_help_panel="Advanced")
def diff_cmd(
    pack_a: str = typer.Argument(
        ..., help="Baseline pack directory (or current pack with --against-previous)"
    ),
    pack_b: Optional[str] = typer.Argument(None, help="Current pack directory"),
    against_previous: bool = typer.Option(
        False, "--against-previous", help="Auto-find baseline pack from same directory"
    ),
    why: bool = typer.Option(
        False, "--why", help="Explain regressions with receipt-level detail"
    ),
    report: Optional[str] = typer.Option(
        None, "--report", help="Write a self-contained diff report (.html or .json)"
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip integrity verification"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    gate_cost_pct: float = typer.Option(
        None, "--gate-cost-pct", help="Max allowed cost increase (percent, e.g. 20)"
    ),
    gate_p95_pct: float = typer.Option(
        None, "--gate-p95-pct", help="Max allowed p95 latency increase (percent)"
    ),
    gate_errors: int = typer.Option(
        None, "--gate-errors", help="Max allowed error count in pack B"
    ),
    gate_strict: bool = typer.Option(
        False, "--gate-strict", help="Fail gates when data is missing (instead of skip)"
    ),
):
    """Diff two proof packs: claims, cost, latency, model mix.

    Pack A is the baseline, Pack B is the current run.
    Verifies integrity of both packs before comparing.

    Exit codes:
      0  No regression
      1  Claim regression or threshold exceeded
      2  Integrity failure (tampered pack)
      3  Bad input

    Threshold gates (--gate-*) add CI-friendly budget checks on top of
    the diff.  A gate failure sets exit code 1 (same as claim regression).
    Gates are only evaluated when explicitly requested.

    Use --against-previous with a single pack argument to auto-discover
    the baseline pack from the same directory.

    Use --why to get receipt-level forensics when regressions are detected.
    Traces parent_receipt_id chains to show causal paths.

    Examples:
      assay diff ./proof_pack_old/ ./proof_pack_new/
      assay diff ./proof_pack_new/ --against-previous
      assay diff ./a/ ./b/ --why
      assay diff ./proof_pack_new/ --against-previous --why
      assay diff ./a/ ./b/ --gate-cost-pct 20 --gate-errors 0
      assay diff ./a/ ./b/ --gate-cost-pct 20 --report gate_report.html
    """
    from pathlib import Path

    from assay.diff import (
        diff_packs,
        evaluate_gates,
        explain_why,
        find_previous_pack,
        load_baseline,
    )

    # Resolve pack paths
    if against_previous:
        if pack_b is not None:
            console.print(
                "[red]Error:[/] --against-previous takes one pack argument, not two"
            )
            raise typer.Exit(3)
        current = Path(pack_a)
        if not current.is_dir():
            console.print(f"[red]Error:[/] {pack_a} is not a directory")
            raise typer.Exit(3)
        # Check saved baseline first, then fall back to mtime discovery
        previous = load_baseline()
        if previous is not None and previous.resolve() != current.resolve():
            console.print(f"  Using saved baseline: {previous}")
        else:
            previous = find_previous_pack(current)
        if previous is None:
            console.print(
                f"[red]Error:[/] No baseline found (no .assay/baseline.json, no previous proof_pack_* in {current.parent})\n"
                "\n"
                "[bold]Fix:[/]\n"
                "  1. Set a baseline:       [bold]assay baseline set ./proof_pack_old/[/]\n"
                "  2. Diff explicit packs:  [bold]assay diff ./proof_pack_old/ ./proof_pack_new/[/]\n"
                "  3. Create a baseline:    [bold]assay run -- python app.py[/]\n"
                f"  4. List packs:           [bold]ls -1 {current.parent}/proof_pack_*[/]"
            )
            raise typer.Exit(3)
        pa = previous
        pb = current
    else:
        if pack_b is None:
            console.print(
                "[red]Error:[/] Two pack arguments required (or use --against-previous)"
            )
            raise typer.Exit(3)
        pa = Path(pack_a)
        pb = Path(pack_b)

    if not pa.is_dir():
        console.print(f"[red]Error:[/] {pa} is not a directory")
        raise typer.Exit(3)
    if not pb.is_dir():
        console.print(f"[red]Error:[/] {pb} is not a directory")
        raise typer.Exit(3)

    result = diff_packs(pa, pb, verify=not no_verify)

    # Evaluate threshold gates if any were requested
    has_gates = (
        gate_cost_pct is not None or gate_p95_pct is not None or gate_errors is not None
    )
    gate_eval = None
    if has_gates:
        gate_eval = evaluate_gates(
            result,
            cost_pct=gate_cost_pct,
            p95_pct=gate_p95_pct,
            errors=gate_errors,
            strict=gate_strict,
        )

    # --why: explain regressions
    why_results = None
    if why and result.has_regression:
        why_results = explain_why(result, pb)

    # Determine final exit code: integrity (2) > regression/gate (1) > clean (0)
    exit_code = result.exit_code
    if exit_code == 0 and gate_eval is not None and gate_eval.any_failed:
        exit_code = 1

    # Optional report artifact (HTML by default; JSON when path ends in .json)
    if report:
        from assay.reporting.diff_gate import (
            build_report,
            render_html,
        )
        from assay.reporting.diff_gate import (
            write_json as write_diff_report_json,
        )
        from assay.reporting.diff_gate import (
            write_report as write_diff_report_html,
        )

        report_path = Path(report)
        try:
            diff_report = build_report(
                result,
                gate_eval=gate_eval,
                why_results=why_results,
                exit_code=exit_code,
                gate_strict=gate_strict,
            )
            if report_path.suffix.lower() == ".json":
                write_diff_report_json(diff_report, report_path)
            else:
                write_diff_report_html(render_html(diff_report), report_path)
        except Exception as e:
            if output_json:
                _output_json(
                    {
                        "command": "diff",
                        "status": "error",
                        "error": f"report generation failed: {e}",
                    },
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] report generation failed: {e}")
            raise typer.Exit(3)

    if output_json:
        payload = {"command": "diff", "status": "ok", **result.to_dict()}
        if gate_eval is not None:
            payload["gates"] = gate_eval.to_dict()
        if why_results is not None:
            payload["why"] = [w.to_dict() for w in why_results]
        if report:
            payload["report_path"] = report
        gates_failed = gate_eval is not None and gate_eval.any_failed
        payload["integrity_failed"] = not result.both_valid
        payload["claims_regressed"] = result.has_regression
        payload["gates_failed"] = gates_failed
        payload["has_regression"] = result.has_regression or gates_failed
        _output_json(payload, exit_code=exit_code)
        return

    if report:
        console.print(f"  [bold green]Report written:[/] {report}")

    _render_diff(
        result, gate_eval=gate_eval, exit_code=exit_code, why_results=why_results
    )


def _fmt_delta(a_val, b_val, fmt: str = "d", prefix: str = "", suffix: str = "") -> str:
    """Format a delta value with +/- and optional percentage."""
    delta = b_val - a_val
    if fmt == "d":
        delta_str = f"+{delta:,}" if delta >= 0 else f"{delta:,}"
    elif fmt == "cost":
        delta_str = f"+${delta:.4f}" if delta >= 0 else f"-${abs(delta):.4f}"
    elif fmt == "ms":
        delta_str = f"+{delta}ms" if delta >= 0 else f"{delta}ms"
    else:
        delta_str = f"+{delta}" if delta >= 0 else str(delta)

    pct = ""
    if a_val and a_val != 0:
        pct_val = (delta / a_val) * 100
        pct = f" ({pct_val:+.0f}%)"

    color = ""
    if "cost" in fmt or fmt == "d":
        # Higher cost/errors = red, lower = green
        if delta > 0 and suffix in ("", " errors"):
            color = "[red]"
        elif delta < 0:
            color = "[green]"
    elif fmt == "ms":
        # Higher latency = red
        if delta > 0:
            color = "[red]"
        elif delta < 0:
            color = "[green]"

    end = "[/]" if color else ""
    return f"{color}{prefix}{delta_str}{pct}{end}"


def _render_diff(result, *, gate_eval=None, exit_code=None, why_results=None) -> None:
    """Render diff result to console with Rich panels."""

    console.print()

    # Integrity failure -- stop here
    if not result.both_valid:
        console.print("[bold red]INTEGRITY CHECK FAILED[/]")
        console.print()
        for err in result.integrity_errors:
            console.print(f"  [red]{err}[/]")
        console.print()
        console.print("  Cannot diff packs with integrity failures.")
        console.print("  Run [bold]assay verify-pack[/] on each pack to investigate.")
        console.print()
        raise typer.Exit(2)

    # Header
    a = result.pack_a
    b = result.pack_b
    console.print("[bold]assay diff[/]")
    console.print()
    console.print(
        f"  Pack A: {a.path}  ({a.n_receipts} receipts, {a.timestamp_start[:10] if a.timestamp_start else '?'})"
    )
    console.print(
        f"  Pack B: {b.path}  ({b.n_receipts} receipts, {b.timestamp_start[:10] if b.timestamp_start else '?'})"
    )

    # Warnings
    if result.signer_changed:
        console.print(f"  [yellow]Signer changed:[/] {a.signer_id} -> {b.signer_id}")
    if result.version_changed:
        console.print(
            f"  [yellow]Verifier version changed:[/] {a.verifier_version} -> {b.verifier_version}"
        )
    if not result.same_claim_set:
        console.print(
            "  [yellow]Claim sets differ[/] (different cards or card versions)"
        )
    console.print()

    # Claims
    if result.claim_deltas:
        claims_table = Table(show_header=False, box=None, padding=(0, 2))
        claims_table.add_column("claim")
        claims_table.add_column("change")
        for cd in result.claim_deltas:
            a_str = (
                "[green]PASS[/]"
                if cd.a_passed
                else ("[red]FAIL[/]" if cd.a_passed is False else "[dim]--[/]")
            )
            b_str = (
                "[green]PASS[/]"
                if cd.b_passed
                else ("[red]FAIL[/]" if cd.b_passed is False else "[dim]--[/]")
            )
            status_str = ""
            if cd.regressed:
                status_str = "  [bold red]REGRESSED[/]"
            elif cd.status == "improved":
                status_str = "  [green]improved[/]"
            elif cd.status == "new":
                status_str = "  [cyan]new[/]"
            elif cd.status == "removed":
                status_str = "  [dim]removed[/]"
            claims_table.add_row(cd.claim_id, f"{a_str} -> {b_str}{status_str}")

        border = "red" if result.has_regression else "green"
        title = "Claims (REGRESSION DETECTED)" if result.has_regression else "Claims"
        console.print(Panel(claims_table, title=title, border_style=border))

    # Summary deltas
    aa = result.a_analysis
    ba = result.b_analysis
    if aa and ba:
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("key", style="dim")
        summary.add_column("a", justify="right")
        summary.add_column("arrow", justify="center")
        summary.add_column("b", justify="right")
        summary.add_column("delta")

        summary.add_row(
            "Model calls",
            str(aa.model_calls),
            "->",
            str(ba.model_calls),
            _fmt_delta(aa.model_calls, ba.model_calls),
        )
        summary.add_row(
            "Total tokens",
            f"{aa.total_tokens:,}",
            "->",
            f"{ba.total_tokens:,}",
            _fmt_delta(aa.total_tokens, ba.total_tokens),
        )
        summary.add_row(
            "Est. cost",
            f"${aa.cost_usd:.4f}",
            "->",
            f"${ba.cost_usd:.4f}",
            _fmt_delta(aa.cost_usd, ba.cost_usd, fmt="cost"),
        )

        err_color_a = "[red]" if aa.errors else ""
        err_color_b = "[red]" if ba.errors else ""
        err_end_a = "[/]" if aa.errors else ""
        err_end_b = "[/]" if ba.errors else ""
        summary.add_row(
            "Errors",
            f"{err_color_a}{aa.errors}{err_end_a}",
            "->",
            f"{err_color_b}{ba.errors}{err_end_b}",
            _fmt_delta(aa.errors, ba.errors),
        )

        if aa.latencies and ba.latencies:
            summary.add_row(
                "Latency p50",
                f"{aa.latency_p50}ms",
                "->",
                f"{ba.latency_p50}ms",
                _fmt_delta(aa.latency_p50 or 0, ba.latency_p50 or 0, fmt="ms"),
            )
            summary.add_row(
                "Latency p95",
                f"{aa.latency_p95}ms",
                "->",
                f"{ba.latency_p95}ms",
                _fmt_delta(aa.latency_p95 or 0, ba.latency_p95 or 0, fmt="ms"),
            )

        console.print(Panel(summary, title="Summary", border_style="blue"))

    # Model churn
    if result.model_deltas:
        model_table = Table(box=None, padding=(0, 1))
        model_table.add_column("Model", style="bold")
        model_table.add_column("A calls", justify="right")
        model_table.add_column("B calls", justify="right")
        model_table.add_column("Delta", justify="right")
        model_table.add_column("Status")

        for md in result.model_deltas:
            if md.status == "added":
                status = "[cyan]new[/]"
            elif md.status == "removed":
                status = "[yellow]removed[/]"
            else:
                status = _fmt_delta(md.a_calls, md.b_calls)

            model_table.add_row(
                md.model_id,
                str(md.a_calls) if md.a_calls else "--",
                str(md.b_calls) if md.b_calls else "--",
                _fmt_delta(md.a_calls, md.b_calls) if md.status == "changed" else "",
                status if md.status != "changed" else "",
            )
        console.print(Panel(model_table, title="Models", border_style="green"))

    # Threshold gates
    if gate_eval is not None and gate_eval.results:
        gate_table = Table(show_header=False, box=None, padding=(0, 2))
        gate_table.add_column("gate")
        gate_table.add_column("result")

        def _fmt_threshold(val: float, unit: str) -> str:
            s = f"{val:g}"
            if unit == "pct":
                s += "%"
            return s

        for g in gate_eval.results:
            if g.skipped:
                if g.passed:
                    gate_table.add_row(g.name, "[dim]skipped (no data)[/]")
                else:
                    gate_table.add_row(
                        g.name, "[red]FAIL[/]  [dim]missing data (strict mode)[/]"
                    )
            elif g.passed:
                actual_str = (
                    f"{g.actual:.1f}%"
                    if g.unit == "pct" and g.actual is not None
                    else str(int(g.actual))
                    if g.actual is not None
                    else "?"
                )
                gate_table.add_row(
                    g.name,
                    f"[green]PASS[/]  {actual_str} <= {_fmt_threshold(g.threshold, g.unit)}",
                )
            else:
                actual_str = (
                    f"{g.actual:.1f}%"
                    if g.unit == "pct" and g.actual is not None
                    else str(int(g.actual))
                    if g.actual is not None
                    else "inf"
                )
                gate_table.add_row(
                    g.name,
                    f"[red]FAIL[/]  {actual_str} > {_fmt_threshold(g.threshold, g.unit)}",
                )

        n_passed = sum(1 for g in gate_eval.results if g.passed and not g.skipped)
        n_failed = sum(1 for g in gate_eval.results if not g.passed)
        n_skipped = sum(1 for g in gate_eval.results if g.passed and g.skipped)
        gate_table.add_row(
            "", f"[dim]{n_passed} passed, {n_failed} failed, {n_skipped} skipped[/]"
        )

        border = "red" if gate_eval.any_failed else "green"
        title = "Gates (THRESHOLD EXCEEDED)" if gate_eval.any_failed else "Gates"
        console.print(Panel(gate_table, title=title, border_style=border))

    # --why panel
    if why_results:
        why_lines = []
        for w in why_results:
            why_lines.append(f"[bold red]{w.claim_id}[/] REGRESSED")
            if w.expected:
                why_lines.append(f"  Expected: {w.expected}")
            if w.actual:
                why_lines.append(f"  Actual:   {w.actual}")
            if w.evidence_receipt_ids:
                ids = ", ".join(w.evidence_receipt_ids[:5])
                why_lines.append(f"  Evidence: {ids}")
            for chain in w.causal_chains:
                parts = []
                for r in chain:
                    rid = r.get("receipt_id", "?")[:16]
                    rtype = r.get("type", "?")
                    parts.append(f"{rid} ({rtype})")
                why_lines.append(f"  Chain:    {' <- '.join(parts)}")
            why_lines.append("")

        console.print(
            Panel(
                "\n".join(why_lines).rstrip(),
                title="Why (receipt-level forensics)",
                border_style="yellow",
            )
        )

    final_exit = exit_code if exit_code is not None else result.exit_code
    console.print()
    gate_failed = gate_eval is not None and gate_eval.any_failed
    if result.has_regression or gate_failed:
        label = "REGRESSION DETECTED" if result.has_regression else "THRESHOLD EXCEEDED"
        console.print(f"  [bold red]Result: {label}[/]")
    else:
        console.print("  [bold green]Result: No regression[/]")
    console.print()

    raise typer.Exit(final_exit)


# ---------------------------------------------------------------------------
# MCP commands (policy, proxy)
# ---------------------------------------------------------------------------

mcp_app = typer.Typer(
    help="MCP tool-call auditing: policy templates and proxy.",
    no_args_is_help=True,
)
assay_app.add_typer(mcp_app, name="mcp", hidden=True, rich_help_panel="Advanced")

mcp_policy_app = typer.Typer(
    help="MCP policy file management.",
    no_args_is_help=True,
)
mcp_app.add_typer(mcp_policy_app, name="policy")


@mcp_policy_app.command("init")
def mcp_policy_init_cmd(
    output: str = typer.Option(
        "assay.mcp-policy.yaml", "-o", "--output", help="Output file path"
    ),
    server_id: Optional[str] = typer.Option(
        None, "--server-id", help="Server identifier to pre-fill"
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing file"),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Generate a starter MCP policy file.

    Creates an assay.mcp-policy.yaml with sensible defaults:
    privacy-by-default, no tool restrictions, auto-pack enabled.

    Edit the generated file to customize tool allow/deny lists,
    privacy settings, and budget thresholds.

    Examples:
      assay mcp policy init
      assay mcp policy init --server-id my-server
      assay mcp policy init -o custom-policy.yaml --force
    """
    from pathlib import Path as P

    out_path = P(output)
    if out_path.exists() and not force:
        if output_json:
            _output_json(
                {
                    "command": "mcp policy init",
                    "status": "error",
                    "error": f"File already exists: {output}",
                    "fix": "assay mcp policy init --force",
                },
                exit_code=1,
            )
        console.print(
            f"[red]Error:[/] {output} already exists. Use --force to overwrite."
        )
        raise typer.Exit(1)

    sid = server_id or "my-server"
    policy_content = f"""\
# Assay MCP Policy (v1)
# Generated by: assay mcp policy init
# Docs: https://github.com/Haserjian/assay
#
# This file configures the Assay MCP proxy for tool-call auditing.
# Validate with:
#   assay mcp policy validate assay.mcp-policy.yaml
# Start proxy with:
#   assay mcp-proxy --policy assay.mcp-policy.yaml -- python my_server.py

version: "1"

# Server identification
server_id: "{sid}"

# Mode: "audit" (record verdicts, never block) or "enforce" (block denied calls)
mode: audit

# Privacy settings (privacy-by-default)
# When false, arguments/results are SHA-256 hashed in receipts.
# Set to true only if you need cleartext in your audit trail.
store_args: false
store_results: false

# Auto-pack: build a signed proof pack when the session ends cleanly.
auto_pack: true

# Audit directory for receipts and packs.
audit_dir: ".assay/mcp"

# Tool restrictions (optional)
# Uncomment and customize to restrict which tools are allowed.
#
# tools:
#   default: allow     # "allow" (allowlist optional) or "deny" (allowlist required)
#
#   # Deny list: these tools are always blocked (checked first).
#   # Supports fnmatch globs: "delete_*", "drop_*"
#   deny:
#     - "delete_*"
#     - "send_email"
#
#   # Allow list: when default=deny, only these tools are permitted.
#   allow:
#     - "read_*"
#     - "search"
#
#   # Per-tool constraints: rate limits and argument filters.
#   constraints:
#     web_fetch:
#       max_calls: 10
#     execute_query:
#       max_calls: 50
#       deny_patterns:
#         - "DROP TABLE"
#         - "DELETE FROM"

# Session budget (optional)
#
# budget:
#   max_tool_calls: 100          # per session
#   max_wall_time_sec: 300       # per session (not enforced yet)
"""

    out_path.write_text(policy_content, encoding="utf-8")

    if output_json:
        _output_json(
            {
                "command": "mcp policy init",
                "status": "ok",
                "output": str(out_path),
                "server_id": sid,
            }
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]MCP policy file created[/]\n\n"
            f"File:       {out_path}\n"
            f"Server ID:  {sid}\n"
            f"Privacy:    args hashed, results hashed (default)\n"
            f"Auto-pack:  enabled",
            title="assay mcp policy init",
        )
    )
    console.print()
    console.print("Next:")
    console.print(f"  1. Edit [bold]{out_path}[/] to customize tool restrictions")
    console.print(f"  2. Validate: [bold]assay mcp policy validate {out_path}[/]")
    console.print(
        f"  3. Start proxy: [bold]assay mcp-proxy --policy {out_path} -- python my_server.py[/]"
    )
    console.print()


@mcp_policy_app.command("validate")
def mcp_policy_validate_cmd(
    policy_file: str = typer.Argument(..., help="Path to MCP policy file"),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Validate an MCP policy file.

    Checks that the file exists, is valid YAML, and conforms to the v1
    policy schema. Reports mode, tool rules, constraints, and budget.

    Examples:
      assay mcp policy validate assay.mcp-policy.yaml
      assay mcp policy validate custom-policy.yaml --json
    """
    from pathlib import Path as P

    from assay.mcp_policy import PolicyLoadError, load_policy

    path = P(policy_file)
    try:
        policy = load_policy(path)
    except PolicyLoadError as exc:
        if output_json:
            _output_json(
                {
                    "command": "mcp policy validate",
                    "status": "error",
                    "error": str(exc),
                },
                exit_code=1,
            )
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1)

    # Gather summary
    n_deny = len(policy.tools.deny)
    n_allow = len(policy.tools.allow)
    n_constraints = len(policy.tools.constraints)
    budget_str = (
        str(policy.budget.max_tool_calls)
        if policy.budget.max_tool_calls
        else "unlimited"
    )

    if output_json:
        _output_json(
            {
                "command": "mcp policy validate",
                "status": "ok",
                "file": str(path),
                "hash": policy.source_hash,
                "version": policy.version,
                "server_id": policy.server_id,
                "mode": policy.mode,
                "tools_default": policy.tools.default,
                "deny_rules": n_deny,
                "allow_rules": n_allow,
                "constraints": n_constraints,
                "max_tool_calls": policy.budget.max_tool_calls,
            }
        )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Policy valid[/]\n\n"
            f"File:        {path}\n"
            f"Hash:        {policy.source_hash}\n"
            f"Version:     {policy.version}\n"
            f"Server ID:   {policy.server_id or '(none)'}\n"
            f"Mode:        [bold]{policy.mode}[/]\n"
            f"Default:     {policy.tools.default}\n"
            f"Deny rules:  {n_deny}\n"
            f"Allow rules: {n_allow}\n"
            f"Constraints: {n_constraints}\n"
            f"Budget:      {budget_str} calls/session",
            title="assay mcp policy validate",
        )
    )
    console.print()


@assay_app.command(
    "mcp-proxy",
    context_settings={"allow_extra_args": True, "allow_interspersed_args": False},
    rich_help_panel="MCP",
)
def mcp_proxy_cmd(
    ctx: typer.Context,
    audit_dir: str = typer.Option(
        ".assay/mcp", "--audit-dir", help="Directory for receipts and packs"
    ),
    server_id: Optional[str] = typer.Option(
        None, "--server-id", help="Server identifier for receipts"
    ),
    store_args: bool = typer.Option(
        False,
        "--store-args",
        help="Store tool arguments in cleartext (default: hash-only)",
    ),
    store_results: bool = typer.Option(
        False,
        "--store-results",
        help="Store tool results in cleartext (default: hash-only)",
    ),
    no_auto_pack: bool = typer.Option(
        False, "--no-auto-pack", help="Disable auto-pack on session end"
    ),
    output_json: bool = typer.Option(
        False, "--json", help="JSON output for status messages"
    ),
    policy: Optional[str] = typer.Option(
        None, "--policy", help="Path to assay.mcp-policy.yaml (fail-closed if missing)"
    ),
):
    """MCP Notary Proxy: receipt every tool call.

    Transparent stdio proxy between an MCP client and server.
    Intercepts tools/call requests, emits MCPToolCallReceipt per
    invocation, and auto-builds a proof pack on session end.

    With --policy, evaluates tool calls against the policy file.
    In enforce mode, denied calls are blocked before reaching the server.
    Missing or invalid policy file: fail-closed (exit 1).

    Usage:

        assay mcp-proxy -- python my_server.py
        assay mcp-proxy --policy assay.mcp-policy.yaml -- python my_server.py

    In your MCP client config (e.g. claude_desktop_config.json):

        {"command": "assay", "args": ["mcp-proxy", "--policy", "assay.mcp-policy.yaml", "--", "python", "my_server.py"]}
    """
    from assay.mcp_proxy import run_proxy

    upstream_cmd = ctx.args
    if not upstream_cmd:
        if output_json:
            _output_json(
                {
                    "command": "mcp-proxy",
                    "status": "error",
                    "error": "no_server_command_provided",
                    "fixes": [
                        "assay mcp-proxy -- python my_server.py",
                        '{"command": "assay", "args": ["mcp-proxy", "--", "python", "my_server.py"]}',
                    ],
                },
                exit_code=3,
            )
        console.print(
            "[red]Error:[/] No server command provided.\n"
            "\n"
            "[bold]Fix:[/]\n"
            "  1. Start proxy:           [bold]assay mcp-proxy -- python my_server.py[/]\n"
            '  2. Claude Desktop config: [bold]{"command": "assay", "args": ["mcp-proxy", "--", "python", "my_server.py"]}[/]\n'
            "  3. Keep the [bold]--[/] separator before the upstream command."
        )
        raise typer.Exit(3)

    # Fail-closed: if --policy given but file is bad, exit 1
    if policy is not None:
        from pathlib import Path as P

        from assay.mcp_policy import PolicyLoadError

        try:
            # Validate early so we get a clear error before starting the server
            from assay.mcp_policy import load_policy

            load_policy(P(policy))
        except PolicyLoadError as exc:
            if output_json:
                _output_json(
                    {"command": "mcp-proxy", "status": "error", "error": str(exc)},
                    exit_code=1,
                )
            console.print(f"[red]Error:[/] Failed to load policy: {exc}")
            raise typer.Exit(1)

    exit_code = run_proxy(
        upstream_cmd,
        audit_dir=audit_dir,
        server_id=server_id,
        store_args=store_args,
        store_results=store_results,
        auto_pack=not no_auto_pack,
        json_output=output_json,
        policy_path=policy,
    )
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# audit subcommands -- auditor handoff tools
# ---------------------------------------------------------------------------

_VERIFY_INSTRUCTIONS_MD = """\
# How to Verify This Evidence Bundle

## Prerequisites

```bash
python3 -m pip install assay-ai
```

## Step 1: Extract the bundle

```bash
tar xzf <bundle>.tar.gz
cd <extracted>/
```

## Step 2: Verify integrity

```bash
assay verify-pack .
```

Exit codes:
- **0** = Integrity PASS (evidence is authentic and untampered)
- **1** = Claim gate failed (evidence is authentic but behavioral checks failed)
- **2** = Integrity FAIL (evidence has been tampered with)

## Step 3: Read the summary

Open `PACK_SUMMARY.md` for a human-readable explanation of what this evidence proves.

## Step 4: Check the signer

```bash
assay verify-signer .
```

Or compare against an expected signer:

```bash
assay verify-signer . --expected <signer_id>
assay verify-signer . --fingerprint <hex_prefix>
```

## What is in this bundle?

| File | Purpose |
|------|---------|
| `pack_manifest.json` | Signed manifest (hashes, attestation, signature) |
| `pack_signature.sig` | Detached Ed25519 signature |
| `receipt_pack.jsonl` | Canonical receipts |
| `verify_report.json` | Machine-readable verification results |
| `verify_transcript.md` | Human-readable verification transcript |
| `PACK_SUMMARY.md` | Plain-English summary |
| `SIGNER_INFO.json` | Signer identity and public key |
| `VERIFY_INSTRUCTIONS.md` | This file |
| `VERIFY_RESULT.json` | Pre-bundle verification result |
"""

audit_app = typer.Typer(
    name="audit",
    help="Auditor handoff: bundle and verify evidence packs",
    no_args_is_help=True,
)
assay_app.add_typer(
    audit_app, name="audit", hidden=True, rich_help_panel="Compliance & Audit"
)


@audit_app.command("bundle")
def audit_bundle_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: audit_bundle_{pack_id}.tar.gz)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output metadata as JSON"),
):
    """Create a self-contained evidence bundle for auditor handoff.

    Verifies the pack first, then creates a tar.gz containing all pack files
    plus SIGNER_INFO.json, VERIFY_INSTRUCTIONS.md, and VERIFY_RESULT.json.

    Exit codes:
      0 = bundle created successfully
      3 = bad input or verification failed
    """
    import io
    import tarfile
    import time as _time
    from pathlib import Path

    from assay.explain import explain_pack, render_md
    from assay.keystore import get_default_keystore
    from assay.proof_pack import verify_proof_pack

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not pack_path.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "audit bundle",
                    "status": "error",
                    "error": f"Not a directory: {pack_dir}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not manifest_path.exists():
        if output_json:
            _output_json(
                {
                    "command": "audit bundle",
                    "status": "error",
                    "error": "pack_manifest.json not found",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(3)

    manifest = json.loads(manifest_path.read_text())

    # Verify before bundling -- refuse to bundle tampered evidence
    ks = get_default_keystore()
    vr = verify_proof_pack(manifest, pack_path, ks)
    if not vr.passed:
        if output_json:
            _output_json(
                {
                    "command": "audit bundle",
                    "status": "error",
                    "error": "verification_failed",
                    "details": vr.to_dict(),
                },
                exit_code=3,
            )
        console.print(
            "[red]Error:[/] Pack verification failed. Cannot bundle tampered evidence."
        )
        for err in vr.errors:
            console.print(f"  [red]{err.code}[/]: {err.message}")
        raise typer.Exit(3)

    pack_id = manifest.get("pack_id", "unknown")
    out_path = Path(output) if output else Path(f"audit_bundle_{pack_id}.tar.gz")

    # Build supplementary files
    signer_info_bytes = json.dumps(
        {
            "signer_id": manifest.get("signer_id", "unknown"),
            "signer_pubkey": manifest.get("signer_pubkey"),
            "signer_pubkey_sha256": manifest.get("signer_pubkey_sha256"),
            "signature_alg": manifest.get("signature_alg", "ed25519"),
        },
        indent=2,
    ).encode("utf-8")

    try:
        info = explain_pack(pack_path)
        summary_bytes = render_md(info).encode("utf-8")
    except Exception:
        summary_bytes = b"# Pack Summary\n\nCould not generate summary.\n"

    instructions_bytes = _VERIFY_INSTRUCTIONS_MD.encode("utf-8")

    verify_result_bytes = json.dumps(
        {
            "verified_at_bundle_time": True,
            **vr.to_dict(),
        },
        indent=2,
    ).encode("utf-8")

    # Generated file names to skip from pack dir (we supply fresh versions)
    generated_names = {
        "SIGNER_INFO.json",
        "PACK_SUMMARY.md",
        "VERIFY_INSTRUCTIONS.md",
        "VERIFY_RESULT.json",
    }

    with tarfile.open(str(out_path), "w:gz") as tar:
        for file_path in sorted(pack_path.rglob("*")):
            if not file_path.is_file():
                continue
            rel_path = file_path.relative_to(pack_path)
            if len(rel_path.parts) == 1 and rel_path.name in generated_names:
                continue
            tar.add(str(file_path), arcname=str(rel_path))

        now = int(_time.time())
        for name, data in [
            ("SIGNER_INFO.json", signer_info_bytes),
            ("PACK_SUMMARY.md", summary_bytes),
            ("VERIFY_INSTRUCTIONS.md", instructions_bytes),
            ("VERIFY_RESULT.json", verify_result_bytes),
        ]:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = now
            tar.addfile(ti, io.BytesIO(data))

    bundle_size = out_path.stat().st_size
    file_count = sum(
        1
        for f in pack_path.rglob("*")
        if f.is_file()
        and not (len(f.relative_to(pack_path).parts) == 1 and f.name in generated_names)
    ) + len(generated_names)

    if output_json:
        _output_json(
            {
                "command": "audit bundle",
                "status": "ok",
                "pack_id": pack_id,
                "bundle_path": str(out_path),
                "bundle_bytes": bundle_size,
                "file_count": file_count,
                "signer_id": manifest.get("signer_id"),
                "verification_passed": True,
            },
            exit_code=0,
        )

    console.print()
    from rich.panel import Panel

    console.print(
        Panel.fit(
            f"[bold green]AUDIT BUNDLE CREATED[/]\n\n"
            f"Pack ID:    {pack_id}\n"
            f"Signer:     {manifest.get('signer_id')}\n"
            f"Files:      {file_count}\n"
            f"Size:       {bundle_size:,} bytes\n"
            f"Output:     {out_path}",
            title="assay audit bundle",
        )
    )
    console.print()
    console.print(f"[dim]Hand off [bold]{out_path}[/bold] to the auditor.[/]")
    console.print(
        f"[dim]Auditor verifies with:[/] python3 -m pip install assay-ai && tar xzf {out_path.name} && assay verify-pack ."
    )
    console.print()


# ---------------------------------------------------------------------------
# flow subcommands -- executable guided workflows
# ---------------------------------------------------------------------------

flow_app = typer.Typer(
    name="flow",
    help="Executable guided workflows (no more copy-paste)",
    no_args_is_help=True,
)
assay_app.add_typer(flow_app, name="flow", hidden=True, rich_help_panel="Workflows")


@flow_app.command("try")
def flow_try_cmd(
    apply: bool = typer.Option(
        False, "--apply", help="Execute steps (default: dry-run)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """See Assay in action: demo packs + verify."""
    from assay.flow import (
        build_flow_try,
        render_flow_dry_run,
        render_flow_result,
        run_flow,
    )

    flow = build_flow_try()
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json(
            {"command": "flow try", **result.to_dict()},
            exit_code=1 if result.failed_step else 0,
        )
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("adopt")
def flow_adopt_cmd(
    path: str = typer.Argument(".", help="Project directory"),
    run_command: str = typer.Option(
        "python app.py",
        "--run-command",
        help="Command to wrap with assay run",
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Execute steps (default: dry-run)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Instrument your project: scan -> patch -> run -> verify -> explain."""
    from assay.flow import (
        build_flow_adopt,
        render_flow_dry_run,
        render_flow_result,
        run_flow,
    )

    flow = build_flow_adopt(run_command=run_command, path=path)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json(
            {"command": "flow adopt", **result.to_dict()},
            exit_code=1 if result.failed_step else 0,
        )
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("ci")
def flow_ci_cmd(
    run_command: str = typer.Option(
        "python app.py",
        "--run-command",
        help="Command Assay should wrap in CI",
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Execute steps (default: dry-run)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Set up CI evidence gating: lock -> ci init -> baseline."""
    from assay.flow import (
        build_flow_ci,
        render_flow_dry_run,
        render_flow_result,
        run_flow,
    )

    flow = build_flow_ci(run_command=run_command)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json(
            {"command": "flow ci", **result.to_dict()},
            exit_code=1 if result.failed_step else 0,
        )
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("mcp")
def flow_mcp_cmd(
    server_command: Optional[str] = typer.Option(
        None,
        "--server-command",
        help="MCP server startup command",
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Execute steps (default: dry-run)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Set up MCP tool call auditing: policy init + proxy guidance."""
    from assay.flow import (
        build_flow_mcp,
        render_flow_dry_run,
        render_flow_result,
        run_flow,
    )

    flow = build_flow_mcp(server_command=server_command)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json(
            {"command": "flow mcp", **result.to_dict()},
            exit_code=1 if result.failed_step else 0,
        )
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("audit")
def flow_audit_cmd(
    pack_dir: str = typer.Argument(
        "./proof_pack_*/", help="Path to proof pack directory"
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Execute steps (default: dry-run)"
    ),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Auditor handoff: verify -> explain -> bundle."""
    from assay.flow import (
        build_flow_audit,
        render_flow_dry_run,
        render_flow_result,
        run_flow,
    )

    flow = build_flow_audit(pack_dir=pack_dir)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json(
            {"command": "flow audit", **result.to_dict()},
            exit_code=1 if result.failed_step else 0,
        )
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# compliance: framework-specific evidence assessment
# ---------------------------------------------------------------------------

compliance_app = typer.Typer(
    name="compliance",
    help="Compliance assessment: map evidence packs to regulatory frameworks",
    no_args_is_help=True,
)
assay_app.add_typer(
    compliance_app, name="compliance", hidden=True, rich_help_panel="Compliance & Audit"
)


@compliance_app.command("report")
def compliance_report_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory"),
    framework: str = typer.Option(
        "eu-ai-act",
        "--framework",
        "-f",
        help="Framework: eu-ai-act, soc2, iso42001, nist-ai-rmf, all",
    ),
    output_format: str = typer.Option(
        "text", "--format", help="Output: text, md, json"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a compliance report mapping evidence to regulatory controls.

    Evaluates a proof pack against a specific compliance framework and
    produces a per-control PASS/FAIL/UNKNOWN verdict. Covers EU AI Act
    Articles 12 & 19, SOC 2 CC7.2, ISO 42001, and NIST AI RMF.

    Exit codes:
      0 = report generated
      3 = bad input (invalid directory, missing manifest, unknown framework)

    Examples:
      assay compliance report ./proof_pack_*/
      assay compliance report ./proof_pack_*/ --framework soc2
      assay compliance report ./proof_pack_*/ --framework all --json
      assay compliance report ./proof_pack_*/ --format md
    """
    from pathlib import Path

    from assay.compliance import (
        ALL_FRAMEWORK_IDS,
        evaluate_compliance,
        render_compliance_md,
        render_compliance_text,
    )

    pd = Path(pack_dir)
    if not pd.is_dir():
        if output_json or output_format == "json":
            _output_json(
                {
                    "command": "compliance report",
                    "status": "error",
                    "error": f"Not a directory: {pack_dir}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    manifest_path = pd / "pack_manifest.json"
    if not manifest_path.exists():
        if output_json or output_format == "json":
            _output_json(
                {
                    "command": "compliance report",
                    "status": "error",
                    "error": "pack_manifest.json not found",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(3)

    # Determine frameworks to evaluate
    if framework == "all":
        framework_ids = list(ALL_FRAMEWORK_IDS)
    else:
        if framework not in ALL_FRAMEWORK_IDS:
            if output_json or output_format == "json":
                _output_json(
                    {
                        "command": "compliance report",
                        "status": "error",
                        "error": f"Unknown framework: {framework}",
                        "supported": ALL_FRAMEWORK_IDS,
                    },
                    exit_code=3,
                )
            console.print(
                f"[red]Error:[/] Unknown framework: {framework}. "
                f"Supported: {', '.join(ALL_FRAMEWORK_IDS)}"
            )
            raise typer.Exit(3)
        framework_ids = [framework]

    reports = []
    for fid in framework_ids:
        reports.append(evaluate_compliance(pd, fid))

    if output_json or output_format == "json":
        if len(reports) == 1:
            payload = {
                "command": "compliance report",
                "status": "ok",
                **reports[0].to_dict(),
            }
        else:
            payload = {
                "command": "compliance report",
                "status": "ok",
                "frameworks": [r.to_dict() for r in reports],
            }
        _output_json(payload, exit_code=0)
        return

    if output_format == "md":
        for report in reports:
            console.print(render_compliance_md(report))
        return

    # Default: text
    for report in reports:
        console.print()
        console.print(render_compliance_text(report))


# ---------------------------------------------------------------------------
# Incident forensics
# ---------------------------------------------------------------------------

incident_app = typer.Typer(
    name="incident",
    help="Incident forensics and timeline analysis",
    no_args_is_help=True,
)
assay_app.add_typer(
    incident_app, name="incident", hidden=True, rich_help_panel="Compliance & Audit"
)


@incident_app.command("timeline")
def incident_timeline_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory"),
    against: Optional[str] = typer.Option(
        None, "--against", help="Baseline pack for divergence detection"
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f", help="Output: text, md, json"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Build an incident timeline from a proof pack.

    Shows a canonical chronology of events with severity markers,
    identifies critical incidents, and traces causal chains backward
    to likely root causes.

    With --against, detects the first divergence point from a baseline pack.

    Examples:
      assay incident timeline ./proof_pack_*/
      assay incident timeline ./proof_pack_*/ --against ./baseline_pack/
      assay incident timeline ./proof_pack_*/ --json
    """
    from pathlib import Path

    from assay.incident import (
        build_comparative_timeline,
        build_timeline,
        render_timeline_md,
        render_timeline_text,
    )

    pd = Path(pack_dir)
    if not pd.is_dir():
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    manifest_path = pd / "pack_manifest.json"
    if not manifest_path.exists():
        console.print(f"[red]Error:[/] No pack_manifest.json in {pack_dir}")
        raise typer.Exit(3)

    try:
        if against:
            baseline_path = Path(against)
            if not baseline_path.is_dir():
                console.print(f"[red]Error:[/] Baseline {against} is not a directory")
                raise typer.Exit(3)
            timeline = build_comparative_timeline(pd, baseline_path)
        else:
            timeline = build_timeline(pd)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json or output_format == "json":
        _output_json(
            {
                "command": "incident timeline",
                "status": "ok",
                **timeline.to_dict(),
            }
        )
        return

    if output_format == "md":
        console.print(render_timeline_md(timeline))
        return

    console.print()
    console.print(render_timeline_text(timeline))


@incident_app.command("replay")
def incident_replay_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory"),
    policy: str = typer.Option(
        ..., "--policy", "-p", help="Candidate policy YAML file"
    ),
    current_policy: Optional[str] = typer.Option(
        None, "--current-policy", help="Current policy for delta comparison"
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f", help="Output: text, md, json"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Replay historical evidence against a candidate policy.

    Given a proof pack and a candidate MCP policy file, evaluates what
    WOULD have changed: which tool calls would be newly denied or allowed.

    This is the Policy Time Machine -- test policy changes before deploying them.

    Examples:
      assay incident replay ./proof_pack_*/ -p candidate.yaml
      assay incident replay ./proof_pack_*/ -p strict.yaml --current-policy current.yaml
      assay incident replay ./proof_pack_*/ -p candidate.yaml --json
    """
    from pathlib import Path

    from assay.time_machine import render_impact_md, render_impact_text, replay_policy

    pd = Path(pack_dir)
    pp = Path(policy)

    if not pd.is_dir():
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not pp.exists():
        console.print(f"[red]Error:[/] Policy file not found: {policy}")
        raise typer.Exit(3)

    cp = Path(current_policy) if current_policy else None

    try:
        impact = replay_policy(pd, pp, current_policy=cp)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)
    except ValueError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    if output_json or output_format == "json":
        _output_json(
            {
                "command": "incident replay",
                "status": "ok",
                **impact.to_dict(),
            }
        )
        return

    if output_format == "md":
        console.print(render_impact_md(impact))
        return

    console.print()
    console.print(render_impact_text(impact))


# ---------------------------------------------------------------------------
# Policy management
# ---------------------------------------------------------------------------

policy_app = typer.Typer(
    name="policy",
    help="Policy management and impact analysis",
    no_args_is_help=True,
)
assay_app.add_typer(
    policy_app, name="policy", hidden=True, rich_help_panel="Compliance & Audit"
)


@policy_app.command("impact")
def policy_impact_cmd(
    policy_new: str = typer.Option(
        ..., "--policy-new", help="Candidate policy YAML file"
    ),
    packs: str = typer.Option(
        ..., "--packs", help="Directory containing pack subdirectories"
    ),
    policy_old: Optional[str] = typer.Option(
        None, "--policy-old", help="Current/baseline policy YAML"
    ),
    fail_if_newly_denied: Optional[int] = typer.Option(
        None, "--fail-if-newly-denied", help="Fail if newly denied > N"
    ),
    fail_if_risk_delta: Optional[float] = typer.Option(
        None, "--fail-if-risk-delta", help="Fail if risk delta > X"
    ),
    do_emit_receipt: bool = typer.Option(
        False, "--emit-receipt", help="Emit PolicyImpactReceipt to trace"
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f", help="Output: text, md, json"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Analyze the impact of a policy change on historical evidence.

    Replays all packs in a directory against a candidate policy, computes
    aggregate impact (newly denied / allowed / risk delta), and evaluates
    CI thresholds.

    This is the Policy Merge Guard -- test policy changes before deploying them.

    Examples:
      assay policy impact --policy-new strict.yaml --packs ./proof_packs/
      assay policy impact --policy-new new.yaml --policy-old old.yaml --packs ./packs/ --fail-if-newly-denied 0
      assay policy impact --policy-new candidate.yaml --packs ./packs/ --emit-receipt --json
    """
    from pathlib import Path

    from assay.policy_guard import (
        aggregate_policy_impact,
        emit_policy_impact_receipt,
        evaluate_thresholds,
        render_impact_md,
        render_impact_text,
    )

    pn = Path(policy_new)
    pd = Path(packs)
    po = Path(policy_old) if policy_old else None

    if not pn.exists():
        console.print(f"[red]Error:[/] Candidate policy not found: {policy_new}")
        raise typer.Exit(3)

    if not pd.exists():
        console.print(f"[red]Error:[/] Packs directory not found: {packs}")
        raise typer.Exit(3)

    try:
        impact = aggregate_policy_impact(pd, pn, policy_old=po)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)
    except ValueError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    # Evaluate thresholds
    verdict, reason = evaluate_thresholds(
        impact,
        fail_if_newly_denied=fail_if_newly_denied,
        fail_if_risk_delta=fail_if_risk_delta,
    )

    # Emit receipt if requested
    if do_emit_receipt:
        thresholds = {
            "fail_if_newly_denied": fail_if_newly_denied,
            "fail_if_risk_delta": fail_if_risk_delta,
        }
        try:
            emit_policy_impact_receipt(impact, verdict, reason, thresholds)
        except Exception:
            pass  # Best-effort emission

    exit_code = 0 if verdict == "pass" else 1

    if output_json or output_format == "json":
        payload = {
            "command": "policy impact",
            "status": "ok",
            "ci_verdict": verdict,
            "ci_verdict_reason": reason,
            **impact.to_dict(),
        }
        _output_json(payload, exit_code=exit_code)
        return

    if output_format == "md":
        console.print(render_impact_md(impact, verdict=verdict, verdict_reason=reason))
        raise typer.Exit(exit_code)

    console.print()
    console.print(render_impact_text(impact, verdict=verdict, verdict_reason=reason))
    raise typer.Exit(exit_code)


@policy_app.command("recommend")
def policy_recommend_cmd(
    store_dir: Optional[str] = typer.Option(
        None, "--store-dir", help="Assay store directory (default: ~/.assay/)"
    ),
    window: int = typer.Option(7, "--window", "-w", help="Window size in days"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Analyze receipt history and generate policy recommendations.

    Aggregates signals (deny rate, failure rate, timeouts, trends) from
    recent receipts and generates deterministic recommendations.

    Examples:
      assay policy recommend
      assay policy recommend --window 14 --json
      assay policy recommend --store-dir /path/to/store --window 30
    """
    from pathlib import Path

    from assay.policy_loop import analyze_receipt_history, render_text
    from assay.store import assay_home

    sdir = Path(store_dir) if store_dir else assay_home()

    if not sdir.exists():
        console.print(f"[red]Error:[/] Store directory not found: {sdir}")
        raise typer.Exit(3)

    result = analyze_receipt_history(sdir, window_days=window)

    exit_code = 1 if result.has_critical else 0

    if output_json:
        payload = {
            "command": "policy recommend",
            "status": "ok",
            **result.to_dict(),
        }
        _output_json(payload, exit_code=exit_code)
        return

    console.print()
    console.print(render_text(result))
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# Pilot orchestration
# ---------------------------------------------------------------------------

pilot_app = typer.Typer(
    name="pilot",
    help="End-to-end pilot run, verify, and closeout",
    no_args_is_help=True,
)
assay_app.add_typer(pilot_app, name="pilot", hidden=True, rich_help_panel="Workflows")


@pilot_app.command("run")
def pilot_run_cmd(
    repo: str = typer.Argument(".", help="Repository directory"),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to pilot.yaml"
    ),
    test_cmd: Optional[str] = typer.Option(
        None, "--test-cmd", "-t", help="Test command (overrides config)"
    ),
    mode: Optional[str] = typer.Option(
        None, "--mode", "-m", help="Scan mode: high-only or high+medium"
    ),
    output: str = typer.Option(
        "pilot_bundle", "--output", "-o", help="Bundle output directory"
    ),
    allow_empty: bool = typer.Option(
        False, "--allow-empty", help="Allow empty receipt packs"
    ),
    allow_dirty: bool = typer.Option(
        False, "--allow-dirty", help="Allow dirty working tree"
    ),
    patch: bool = typer.Option(False, "--patch", help="Run assay patch before test"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate without executing"),
    resume: bool = typer.Option(False, "--resume", help="Resume from last checkpoint"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Run the 9-step pilot pipeline: scan, score, run, verify, bundle.

    Reads pilot.yaml for configuration. CLI flags override config values.

    Examples:
      assay pilot run . --test-cmd "pytest tests/ -q"
      assay pilot run /path/to/repo --config pilot.yaml --json
      assay pilot run . --dry-run
    """
    from pathlib import Path

    from assay.pilot import PilotError, load_pilot_config, run_pilot

    repo_path = Path(repo).resolve()
    if not repo_path.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "pilot run",
                    "status": "error",
                    "error": f"Directory not found: {repo}",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] Directory not found: {repo}")
        raise typer.Exit(3)

    cli_overrides: dict = {}
    if test_cmd is not None:
        cli_overrides["test_cmd"] = test_cmd
    if mode is not None:
        cli_overrides["mode"] = mode
    if output != "pilot_bundle":
        cli_overrides["output"] = output
    if allow_empty:
        cli_overrides["allow_empty"] = True
    if allow_dirty:
        cli_overrides["allow_dirty"] = True
    if patch:
        cli_overrides["patch"] = True

    try:
        pilot_config = load_pilot_config(config, repo_path, cli_overrides=cli_overrides)
    except PilotError as e:
        if output_json:
            _output_json(
                {"command": "pilot run", "status": "error", "error": str(e)},
                exit_code=1,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    # Apply output override
    if output != "pilot_bundle":
        pilot_config.output = output

    try:
        result = run_pilot(repo_path, pilot_config, dry_run=dry_run, resume=resume)
    except PilotError as e:
        if output_json:
            _output_json(
                {"command": "pilot run", "status": "error", "error": str(e)},
                exit_code=1,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if output_json:
        _output_json(
            {
                "command": "pilot run",
                "status": "ok",
                "output_dir": result["output_dir"],
                "steps_completed": result["steps_completed"],
                "dry_run": dry_run,
            }
        )

    console.print(f"[green]Pilot run complete.[/] Bundle: {result['output_dir']}")
    console.print(f"Steps: {', '.join(result['steps_completed'])}")
    raise typer.Exit(0)


@pilot_app.command("verify")
def pilot_verify_cmd(
    bundle: str = typer.Argument(..., help="Path to pilot bundle directory"),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="Verification profile: score-delta, integrity-only, otel-bridge",
    ),
    self_test: bool = typer.Option(False, "--self-test", help="Run tamper self-test"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a pilot bundle's integrity and claims.

    Three verification layers: structural, integrity (SHA256), claims (profile-aware).

    Exit codes: 0=pass, 1=claims_fail, 2=integrity_fail, 3=malformed.

    Examples:
      assay pilot verify pilot_bundle/
      assay pilot verify pilot_bundle/ --profile otel-bridge
      assay pilot verify pilot_bundle/ --self-test --json
    """
    from pathlib import Path

    from assay.pilot import CLAIM_HINTS, _run_self_test, verify_pilot_bundle

    bundle_path = Path(bundle).resolve()
    if not bundle_path.is_dir():
        if output_json:
            _output_json(
                {
                    "command": "pilot verify",
                    "status": "error",
                    "error": "Bundle path does not exist",
                },
                exit_code=3,
            )
        console.print(f"[red]Error:[/] Bundle path does not exist: {bundle}")
        raise typer.Exit(3)

    exit_code, errors, warnings = verify_pilot_bundle(bundle_path, profile=profile)

    if output_json:
        status_map = {0: "ok", 1: "claims_fail", 2: "integrity_fail", 3: "malformed"}
        payload = {
            "command": "pilot verify",
            "status": status_map.get(exit_code, "error"),
            "exit_code": exit_code,
            "errors": errors,
            "warnings": warnings,
            "warning_count": len(warnings),
            "profile": profile,
        }
        if self_test and exit_code == 0:
            st_code, st_errors = _run_self_test(bundle_path)
            payload["self_test"] = {"exit_code": st_code, "errors": st_errors}
        _output_json(payload, exit_code=exit_code)

    if warnings:
        for wcode in warnings:
            hint = CLAIM_HINTS.get(wcode, "")
            console.print(f"[dim yellow]WARN({wcode}):[/] {hint}")

    if exit_code == 0:
        console.print("[green]VERIFY_PASS:[/] bundle integrity and claims verified")
    elif exit_code == 1:
        console.print(f"[yellow]VERIFY_CLAIMS_FAIL:[/] {','.join(errors)}")
        for code in errors:
            hint = CLAIM_HINTS.get(code)
            if hint:
                console.print(f"  HINT({code}): {hint}")
    else:
        for err in errors:
            console.print(f"[red]{err}[/]")
        labels = {2: "INTEGRITY_FAIL", 3: "MALFORMED"}
        console.print(
            f"[red]VERIFY_{labels.get(exit_code, 'FAIL')}:[/] exit {exit_code}"
        )

    if self_test and exit_code == 0:
        st_code, st_errors = _run_self_test(bundle_path)
        if st_code != 0:
            for err in st_errors:
                console.print(f"SELF_TEST: {err}")
            console.print("[red]SELF_TEST_FAIL[/]")
        else:
            console.print("[green]SELF_TEST_PASS:[/] all mutation checks passed")

    raise typer.Exit(exit_code)


@pilot_app.command("closeout")
def pilot_closeout_cmd(
    bundle: str = typer.Argument(..., help="Path to pilot bundle directory"),
    repo: Optional[str] = typer.Option(None, "--repo", help="Repository identifier"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Validate without writing logs"
    ),
    json_output_path: Optional[str] = typer.Option(
        None, "--json-output", help="Write closeout row JSON to this path"
    ),
    log_path: Optional[str] = typer.Option(
        None, "--log", help="JSONL replication log path"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Run closeout pipeline: verify, self-test, build closeout row.

    Extracts metadata from bundle, verifies integrity, runs self-test,
    and optionally writes to a JSONL replication log.

    Examples:
      assay pilot closeout pilot_bundle/ --dry-run
      assay pilot closeout pilot_bundle/ --json-output closeout.json
      assay pilot closeout pilot_bundle/ --log replication.jsonl --json
    """
    from pathlib import Path

    from assay.pilot import PilotError, run_pilot_closeout

    bundle_path = Path(bundle).resolve()

    try:
        row = run_pilot_closeout(
            bundle_path,
            repo=repo,
            dry_run=dry_run,
            json_output=Path(json_output_path) if json_output_path else None,
            log_path=Path(log_path) if log_path else None,
        )
    except PilotError as e:
        if output_json:
            _output_json(
                {"command": "pilot closeout", "status": "error", "error": str(e)},
                exit_code=1,
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if output_json:
        _output_json(
            {
                "command": "pilot closeout",
                "status": "ok",
                **row,
            }
        )

    delta_str = (
        f"{row.get('score_delta', 'N/A'):+.1f}"
        if isinstance(row.get("score_delta"), (int, float))
        else "N/A"
    )
    tamper_str = str(row.get("tamper_exit", "N/A"))
    console.print(
        f"[green]CLOSEOUT_OK:[/] {row.get('repo', 'unknown')} "
        f"| verify={row.get('verify_exit', '?')} "
        f"| tamper={tamper_str} "
        f"| delta={delta_str}"
    )
    raise typer.Exit(0)


@assay_app.command("decision", hidden=True)
def decision_validate_cmd(
    receipt_path: str = typer.Argument(
        ..., help="Path to a Decision Receipt JSON file"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Validate a Decision Receipt against constitutional invariants.

    Checks structural integrity, verdict-disposition coherence,
    authority constraints, evidence sufficiency, proof-tier monotonicity,
    provenance self-consistency, and forbidden states.

    Exit 0 = valid. Exit 1 = invalid.
    """
    from pathlib import Path as _Path

    from assay.decision_receipt import validate_decision_receipt

    path = _Path(receipt_path)
    if not path.exists():
        if output_json:
            _output_json(
                {
                    "command": "decision",
                    "status": "error",
                    "error": f"File not found: {receipt_path}",
                },
                exit_code=1,
            )
        console.print(f"[red]Error:[/] {receipt_path} not found")
        raise typer.Exit(1)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        if output_json:
            _output_json(
                {
                    "command": "decision",
                    "status": "error",
                    "error": f"Cannot parse: {e}",
                },
                exit_code=1,
            )
        console.print(f"[red]Error:[/] Cannot parse {receipt_path}: {e}")
        raise typer.Exit(1)

    result = validate_decision_receipt(data)
    verdict = data.get("verdict", "?")
    decision_type = data.get("decision_type", "?")
    subject = data.get("decision_subject", "?")
    authority = data.get("authority_id", "?")

    if output_json:
        out = {
            "command": "decision",
            "status": "ok" if result.valid else "invalid",
            "verdict": verdict,
            "decision_type": decision_type,
            "decision_subject": subject,
            **result.to_dict(),
        }
        _output_json(out, exit_code=0 if result.valid else 1)

    if result.valid:
        reason = data.get("verdict_reason", "")
        disposition = data.get("disposition", "?")
        confidence = data.get("confidence", "?")
        ev_suff = data.get("evidence_sufficient", "?")
        policy = data.get("policy_id", "?")

        console.print()
        console.print(
            Panel.fit(
                f"[bold green]Decision Receipt: VALID[/]\n\n"
                f"Verdict:     [bold]{verdict}[/]\n"
                f"Subject:     {subject}\n"
                f"Type:        {decision_type}\n"
                f"Authority:   {authority}\n"
                f"Disposition: {disposition}\n"
                f"Confidence:  {confidence}\n"
                f"Evidence:    {'sufficient' if ev_suff else 'insufficient'}\n"
                f"Policy:      {policy}\n" + (f"\nReason: {reason}" if reason else ""),
                title="assay decision",
            )
        )
    else:
        console.print()
        console.print(
            Panel.fit(
                f"[bold red]Decision Receipt: INVALID[/]\n\n"
                f"Verdict:  {verdict}\n"
                f"Subject:  {subject}\n"
                f"Errors:   {len(result.errors)}",
                title="assay decision",
            )
        )
        for err in result.errors:
            field_str = f" ({err.field})" if err.field else ""
            console.print(
                f"  [{err.layer}] [red]{err.rule}[/]{field_str}: {err.message}"
            )

    console.print()
    raise typer.Exit(0 if result.valid else 1)


@assay_app.command("why", rich_help_panel="Operate")
def why_cmd(
    receipt_id: str = typer.Argument(..., help="Receipt ID to explain"),
    output_json: bool = typer.Option(False, "--json", help="Structured JSON output"),
    trace: bool = typer.Option(
        False,
        "--trace",
        help="Show full backward chain through parent_receipt_id links",
    ),
):
    """Explain why a decision was made.

    Traces a Decision Receipt backward through supersession and obligation
    links, answering: what happened, why, under what authority, and what
    obligations remain.

    This is a constitutional interrogation surface — it shows execution-why
    (what rule fired) and constitutional-why (what prior judgments made this
    permissible or impermissible).

    Examples:
      assay why r_abc123def456
      assay why r_abc123def456 --json
      assay why r_abc123def456 --trace
    """
    from assay.why import explain_why, render_text

    trace_depth = 10 if trace else 1
    result = explain_why(receipt_id, trace_depth=trace_depth)

    if output_json:
        _output_json(
            {
                "command": "why",
                "status": "ok",
                **result.to_dict(),
            }
        )
        return

    text = render_text(result)
    console.print(text)

    if result.missing_links:
        raise typer.Exit(1)
    raise typer.Exit(0)


# ---------------------------------------------------------------------------
# Compiled Packet commands
# ---------------------------------------------------------------------------

packet_app = typer.Typer(
    name="packet",
    help="Compiled reviewer-ready evidence packets.",
    no_args_is_help=True,
)
assay_app.add_typer(packet_app, name="packet", rich_help_panel="Compliance & Audit")


@packet_app.command("init")
def packet_init_cmd(
    questionnaire: str = typer.Option(
        ..., "--questionnaire", "-q", help="Path to questionnaire (JSON or CSV)"
    ),
    packs: List[str] = typer.Option(
        ..., "--packs", "-p", help="Path(s) to proof pack directories"
    ),
    output: str = typer.Option(
        "./packet_draft", "--output", "-o", help="Output directory for draft"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Scaffold a packet workdir with stub bindings for every questionnaire item."""
    from pathlib import Path

    from assay.compiled_packet import init_packet

    q_path = Path(questionnaire)
    from_csv = q_path.suffix.lower() == ".csv"
    pack_dirs = [Path(p) for p in packs]

    try:
        result = init_packet(
            questionnaire_path=q_path,
            pack_dirs=pack_dirs,
            output_dir=Path(output),
            from_csv=from_csv,
        )
    except Exception as e:
        if output_json:
            console.print(json.dumps({"status": "error", "error": str(e)}))
            raise typer.Exit(1)
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if output_json:
        console.print(json.dumps(result, indent=2))
    else:
        console.print(f"[green]Packet draft initialized[/] at {result['output_dir']}")
        console.print(f"  Questionnaire items: {result['questionnaire_items']}")
        console.print(f"  Stub bindings: {result['stub_bindings']}")
        console.print(f"  Pack references: {result['pack_references']}")
        console.print(
            f"\n[dim]Next: edit {result['output_dir']}/claim_bindings.jsonl to author claim bindings.[/]"
        )
        console.print(
            f"[dim]Then: assay packet compile --draft {result['output_dir']} --packs {' '.join(packs)}[/]"
        )
    raise typer.Exit(0)


@packet_app.command("compile")
def packet_compile_cmd(
    draft: str = typer.Option(
        ..., "--draft", "-d", help="Path to packet draft directory"
    ),
    packs: List[str] = typer.Option(
        ..., "--packs", "-p", help="Path(s) to proof pack directories"
    ),
    output: str = typer.Option(
        "./compiled_packet", "--output", "-o", help="Output directory"
    ),
    bundle: bool = typer.Option(
        True, "--bundle/--no-bundle", help="Bundle proof packs into output"
    ),
    signer: str = typer.Option("assay-local", "--signer", "-s", help="Signer ID"),
    subject_type: str = typer.Option(
        ..., "--subject-type", help="Subject type: artifact, run, or decision"
    ),
    subject_id: str = typer.Option(
        ..., "--subject-id", help="Stable human-readable subject identifier"
    ),
    subject_digest: str = typer.Option(
        ...,
        "--subject-digest",
        help="SHA-256 content digest: 'sha256:<64hex>' or bare 64 hex chars",
    ),
    subject_uri: Optional[str] = typer.Option(
        None, "--subject-uri", help="Optional locator URI"
    ),
    source_commit: Optional[str] = typer.Option(
        None,
        "--source-commit",
        help="Source commit provenance bound into the manifest and packet root; required for artifact packets",
    ),
    policy_id: str = typer.Option(
        "default", "--policy-id", help="Policy identifier for admissibility"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Validate, canonicalize, sign, and package a compiled packet with subject binding."""
    # Validate and normalize subject_digest to canonical sha256:<64hex> form.
    # Only bare 64-char lowercase hex is auto-prefixed. Everything else must
    # be explicit or is rejected with a diagnostic message.
    import re
    from pathlib import Path

    from assay.compiled_packet import compile_packet

    normalized_digest = subject_digest
    if normalized_digest.startswith("sha256:"):
        pass  # already canonical form
    elif re.fullmatch(r"[0-9a-f]{64}", normalized_digest):
        normalized_digest = f"sha256:{normalized_digest}"
    elif re.fullmatch(r"[0-9a-fA-F]{64}", normalized_digest):
        normalized_digest = f"sha256:{normalized_digest.lower()}"
    elif re.fullmatch(r"[0-9a-f]{40}", normalized_digest):
        console.print(
            "[red]Error:[/] --subject-digest looks like a 40-char Git SHA-1 object ID.\n"
            "  Assay requires a SHA-256 content digest (64 hex chars).\n"
            "  To get a SHA-256 digest of a file: sha256sum <file> | cut -d' ' -f1\n"
            "  To get a SHA-256 of a git tree: git hash-object --stdin < <file>"
        )
        raise typer.Exit(1)
    else:
        console.print(
            f"[red]Error:[/] --subject-digest must be 'sha256:<64 hex chars>' or bare 64 hex chars.\n"
            f"  Got: {normalized_digest[:60]}{'...' if len(normalized_digest) > 60 else ''}"
        )
        raise typer.Exit(1)

    subject = {
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_digest": normalized_digest,
    }
    if subject_uri:
        subject["subject_uri"] = subject_uri

    try:
        result = compile_packet(
            draft_dir=Path(draft),
            pack_dirs=[Path(p) for p in packs],
            output_dir=Path(output),
            bundle=bundle,
            signer_id=signer,
            subject=subject,
            source_commit=source_commit,
            policy_id=policy_id,
        )
    except Exception as e:
        if output_json:
            console.print(json.dumps({"status": "error", "error": str(e)}))
            raise typer.Exit(1)
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if output_json:
        console.print(json.dumps(result, indent=2))
    else:
        console.print(f"[green]Packet compiled[/] → {result['output_dir']}")
        console.print(f"  Packet ID: {result['packet_id']}")
        console.print(f"  Root: {result['packet_root_sha256'][:16]}...")
        if result.get("source_commit"):
            console.print(f"  Source commit: {result['source_commit']}")
        console.print(f"  Bindings: {result['bindings_count']}")
        console.print(f"  Bundle: {result['bundle_mode']}")
        cov = result.get("coverage", {})
        if cov.get("unbound_items"):
            console.print(f"  [yellow]Unbound items: {len(cov['unbound_items'])}[/]")
        console.print(f"\n[dim]Verify: assay packet verify {result['output_dir']}[/]")
    raise typer.Exit(0)


@packet_app.command("verify")
def packet_verify_cmd(
    packet_dir: str = typer.Argument(..., help="Path to compiled packet directory"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a compiled packet independently."""
    from pathlib import Path

    from assay.compiled_packet import verify_packet

    result = verify_packet(Path(packet_dir))

    if output_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        verdict_color = {
            "PASS": "green",
            "PARTIAL": "yellow",
            "DEGRADED": "yellow",
            "TAMPERED": "red",
            "INVALID": "red",
        }.get(result.verdict, "white")

        integrity_color = {
            "INTACT": "green",
            "DEGRADED": "yellow",
            "TAMPERED": "red",
            "INVALID": "red",
        }.get(result.integrity_verdict, "white")
        completeness_color = {
            "COMPLETE": "green",
            "PARTIAL": "yellow",
            "INCOMPLETE": "red",
        }.get(result.completeness_verdict, "white")

        adm_color = "green" if result.admissible else "red"
        console.print(f"Verdict: [{verdict_color}]{result.verdict}[/{verdict_color}]")
        console.print(
            f"  Integrity:    [{integrity_color}]{result.integrity_verdict}[/{integrity_color}]"
        )
        console.print(
            f"  Completeness: [{completeness_color}]{result.completeness_verdict}[/{completeness_color}]"
        )
        console.print(f"  Admissible:   [{adm_color}]{result.admissible}[/{adm_color}]")
        if result.subject:
            s = result.subject
            console.print(
                f"Subject: {s.get('subject_type', '?')}:{s.get('subject_id', '?')} [{s.get('subject_digest', '?')[:16]}...]"
            )
        if getattr(result, "source_commit", ""):
            console.print(f"Source commit: {result.source_commit}")
        console.print(f"Packet: {result.packet_id}")
        console.print(
            f"Root: {result.packet_root_sha256[:16]}..."
            if result.packet_root_sha256
            else "Root: none"
        )

        if result.pack_results:
            console.print("\nPack results:")
            for pr in result.pack_results:
                status = pr.get("pack_integrity", "?")
                color = (
                    "green"
                    if status == "PASS"
                    else "red"
                    if status in ("FAIL", "MISSING")
                    else "dim"
                )
                console.print(f"  [{color}]{pr['pack_id']}: {status}[/{color}]")

        if result.coverage:
            cov = result.coverage
            console.print(
                f"\nCoverage: {cov.get('total_bindings', 0)}/{cov.get('total_questionnaire_items', 0)} items bound"
            )
            if cov.get("status_counts"):
                for s, c in sorted(cov["status_counts"].items()):
                    console.print(f"  {s}: {c}")

        if result.warnings:
            console.print(f"\n[yellow]Warnings ({len(result.warnings)}):[/]")
            for w in result.warnings:
                console.print(f"  - {w}")

        if result.errors:
            console.print(f"\n[red]Errors ({len(result.errors)}):[/]")
            for e in result.errors:
                console.print(f"  [{e.code}] {e.message}")

    # Exit code reflects verification integrity, not admissibility policy.
    # Exit 0 = INTACT (packet is structurally sound; PARTIAL coverage is honest, not a failure).
    # Exit 1 = structural problem (TAMPERED, DEGRADED, INVALID).
    # Admissibility is available in the JSON output for callers that need it (e.g. assay-gate.sh).
    raise typer.Exit(0 if result.integrity_verdict == "INTACT" else 1)


# ---------------------------------------------------------------------------
# assay compare — contract-based comparability evaluation
# ---------------------------------------------------------------------------


@assay_app.command("compare", rich_help_panel="Governance")
def compare_cmd(
    baseline: str = typer.Argument(
        ..., help="Baseline evidence bundle file or pack directory"
    ),
    candidate: str = typer.Argument(
        ..., help="Candidate evidence bundle file or pack directory"
    ),
    contract: Optional[str] = typer.Option(
        None,
        "--contract",
        "-c",
        help="Path to comparability contract (YAML/JSON). Defaults to bundled judge-comparability-v1.",
    ),
    claim_summary: Optional[str] = typer.Option(
        None, "--claim", help="Claim under test (e.g. 'candidate scores 11% higher')"
    ),
    claim_metric: Optional[str] = typer.Option(
        None, "--metric", help="Metric name (e.g. 'mean_helpfulness_score')"
    ),
    claim_delta: Optional[float] = typer.Option(None, "--delta", help="Score delta"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Evaluate whether two evidence bundles may be validly compared.

    Loads a comparability contract and two evidence bundles, runs the
    denial engine, and produces a constitutional diff — the verdict,
    mismatches, and consequence.

    The system does not tell you what is true. It tells you what is
    validly comparable and therefore what claims are allowed.

    Exit codes:
      0  SATISFIED — comparison valid, claims may proceed
      1  DENIED or DOWNGRADED — comparison invalid or weakened
      2  UNDETERMINED — evidence incomplete, cannot evaluate
      3  Bad input

    Examples:
      assay compare baseline.json candidate.json --contract contracts/judge-comparability-v1.yaml
      assay compare baseline.json candidate.json -c contracts/judge-comparability-v1.yaml --claim "11% improvement"
      assay compare baseline.json candidate.json -c contract.yaml --json
    """
    from pathlib import Path as P

    from assay.comparability.bundle import find_bundle, load_bundle
    from assay.comparability.contract import ContractValidationError, load_contract
    from assay.comparability.engine import evaluate
    from assay.comparability.types import (
        ClaimUnderTest,
    )

    # Load contract (resolve bundled default if not specified)
    from assay.contracts import resolve_contract_path

    contract_path = resolve_contract_path(contract)
    try:
        ctr = load_contract(contract_path)
    except ContractValidationError as e:
        if output_json:
            _output_json(
                {"command": "compare", "status": "error", "error": str(e)}, exit_code=3
            )
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(3)

    # Resolve and load bundles (accept files or pack directories)
    def _resolve(path_str: str, label: str):
        p = P(path_str)
        if p.is_dir():
            found = find_bundle(p)
            if found is None:
                msg = (
                    f"No evidence bundle found in directory {p}. "
                    f"Expected one of: evidence_bundle.json, evidence_bundle.yaml, "
                    f"judge_evidence.json, judge_evidence.yaml"
                )
                if output_json:
                    _output_json(
                        {
                            "command": "compare",
                            "status": "error",
                            "error": f"{label}: {msg}",
                        },
                        exit_code=3,
                    )
                console.print(f"[red]Error:[/] {label}: {msg}")
                raise typer.Exit(3)
            p = found
        try:
            return load_bundle(p)
        except (FileNotFoundError, ValueError, IsADirectoryError) as e:
            msg = str(e)
            if output_json:
                _output_json(
                    {
                        "command": "compare",
                        "status": "error",
                        "error": f"{label}: {msg}",
                    },
                    exit_code=3,
                )
            console.print(f"[red]Error:[/] {label}: {msg}")
            raise typer.Exit(3)

    baseline_bundle = _resolve(baseline, "baseline")
    candidate_bundle = _resolve(candidate, "candidate")

    # Build claim if provided
    claim = None
    if claim_summary:
        claim = ClaimUnderTest(
            claim_type="improvement",
            summary=claim_summary,
            metric=claim_metric or "",
            delta=claim_delta,
        )

    # Run denial engine
    diff = evaluate(ctr, baseline_bundle, candidate_bundle, claim=claim)

    # Emit comparability receipt (all verdicts, not only denials)
    from assay.comparability.receipt import emit_comparability_receipt

    try:
        emit_comparability_receipt(diff, source="assay compare")
    except Exception as e:
        import warnings

        warnings.warn(
            f"assay compare: receipt emission failed: {e}",
            RuntimeWarning,
            stacklevel=1,
        )

    # JSON output
    if output_json:
        payload = {"command": "compare", "status": "ok", **diff.to_dict()}
        _output_json(payload, exit_code=diff.exit_code)
        return

    # Rich console output
    _render_constitutional_diff(diff, ctr)
    raise typer.Exit(diff.exit_code)


def _render_constitutional_diff(diff, contract) -> None:
    """Render a constitutional diff to console with Rich formatting."""
    from assay.comparability.types import (
        InstrumentContinuity,
        Severity,
        Verdict,
    )

    console.print()

    # Verdict banner
    verdict_colors = {
        Verdict.SATISFIED: "bold green",
        Verdict.DOWNGRADED: "bold yellow",
        Verdict.DENIED: "bold red",
        Verdict.UNDETERMINED: "bold blue",
    }
    color = verdict_colors.get(diff.verdict, "bold")

    console.print(
        Panel(
            f"[{color}]COMPARABILITY VERDICT: {diff.verdict.value}[/]",
            border_style=color.replace("bold ", ""),
            expand=True,
        )
    )

    # Claim under test
    if diff.claim:
        console.print("\n  Claim under test:")
        console.print(f'    "{diff.claim.summary}"')
        if diff.claim.delta is not None:
            console.print(f"    delta: {diff.claim.delta:+.2f} ({diff.claim.metric})")

    # Entity labels
    if diff.baseline_label or diff.candidate_label:
        console.print(f"\n  Baseline: {diff.baseline_label or diff.baseline_ref}")
        console.print(f"  Candidate: {diff.candidate_label or diff.candidate_ref}")

    # Instrument continuity
    if diff.instrument_continuity == InstrumentContinuity.BROKEN:
        console.print("\n  [red]Instrument continuity: BROKEN[/]")
        console.print("  The measurement instrument changed between runs.")
    elif diff.instrument_continuity == InstrumentContinuity.UNKNOWN:
        console.print("\n  [yellow]Instrument continuity: UNKNOWN[/]")
        console.print("  Instrument identity fields are missing from evidence.")

    # Mismatches
    if diff.mismatches:
        console.print()
        invalidating = [
            m for m in diff.mismatches if m.severity == Severity.INVALIDATING
        ]
        degrading = [m for m in diff.mismatches if m.severity == Severity.DEGRADING]

        if invalidating:
            console.print("  [bold red]INVALIDATING mismatches:[/]")
            console.print()
            for m in invalidating:
                console.print(f"    [red]X[/] {m.field}")
                console.print(f"      baseline: {m.baseline_value}")
                console.print(f"      candidate: {m.candidate_value}")
                console.print(f"      rule: {m.rule}")
                console.print(f"      [dim]{m.explanation}[/]")
                console.print()

        if degrading:
            console.print("  [bold yellow]DEGRADING mismatches:[/]")
            console.print()
            for m in degrading:
                console.print(f"    [yellow]~[/] {m.field}")
                console.print(f"      baseline: {m.baseline_value}")
                console.print(f"      candidate: {m.candidate_value}")
                console.print(f"      [dim]{m.explanation}[/]")
                console.print()

    # Satisfied fields — denominator includes all contract parity fields
    n_contract_fields = len(contract.parity_fields)
    n_missing = n_contract_fields - len(diff.satisfied_fields) - len(diff.mismatches)
    if diff.satisfied_fields:
        console.print(
            f"  Matched fields ({len(diff.satisfied_fields)}/{n_contract_fields}):"
        )
        line = "    " + "  ".join(f"[green]V[/] {f}" for f in diff.satisfied_fields)
        console.print(line)
    if n_missing > 0:
        # Collect missing field names from both bundles' completeness
        missing_names: list[str] = []
        for comp in (diff.baseline_completeness, diff.candidate_completeness):
            if comp:
                for f in comp.missing_fields:
                    if f not in missing_names:
                        missing_names.append(f)
        console.print(
            f"  [yellow]Missing required ({len(missing_names)}):[/] "
            + ", ".join(missing_names)
        )

    # Bundle completeness
    for label, comp in [
        ("Baseline", diff.baseline_completeness),
        ("Candidate", diff.candidate_completeness),
    ]:
        if comp and comp.status == "INCOMPLETE":
            console.print(f"\n  [yellow]{label} bundle: INCOMPLETE[/]")
            console.print(f"    Missing: {', '.join(comp.missing_fields)}")

    # Consequence
    if diff.consequence:
        console.print()
        consequence_panel_lines = [
            f"  Claim status: [bold]{diff.consequence.claim_status.value}[/]",
        ]
        if diff.consequence.blocked_actions:
            consequence_panel_lines.append("")
            consequence_panel_lines.append("  Blocked:")
            for a in diff.consequence.blocked_actions:
                consequence_panel_lines.append(f"    - {a}")
        if diff.consequence.required_actions:
            consequence_panel_lines.append("")
            consequence_panel_lines.append("  Required:")
            for a in diff.consequence.required_actions:
                consequence_panel_lines.append(f"    -> {a}")
        if diff.contract_id:
            consequence_panel_lines.append(
                f"\n  Contract: {diff.contract_id} (v{diff.contract_version})"
            )

        console.print(
            Panel(
                "\n".join(consequence_panel_lines),
                title="CONSEQUENCE",
                border_style="dim",
            )
        )

    console.print()


def main():
    """Entrypoint for assay CLI."""
    assay_app()


__all__ = ["assay_app", "main"]
