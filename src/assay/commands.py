"""
Assay CLI commands: Tamper-evident audit trails for AI systems.

Commands:
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
  assay start demo    - See Assay in action (quickstart flow)
  assay start ci      - Set up CI evidence gating
  assay start mcp     - Set up MCP tool call auditing
  assay version       - Show version info
"""

import json
from collections import Counter
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

assay_app = typer.Typer(
    name="assay",
    help="Tamper-evident audit trails for AI systems",
    no_args_is_help=True,
)


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


@assay_app.command("validate", hidden=True)
def validate_action(
    action: str = typer.Argument(..., help="Action to validate (e.g., 'shell:rm -rf /')"),
    coherence_delta: float = typer.Option(0.0, "--coherence", "-c", help="Expected coherence change (-1 to 1)"),
    dignity_delta: float = typer.Option(0.0, "--dignity", "-d", help="Expected dignity impact (-1 to 1)"),
    emit_receipt: bool = typer.Option(True, "--receipt/--no-receipt", help="Emit validation receipt"),
    persist: bool = typer.Option(True, "--persist/--no-persist", help="Persist receipts to disk"),
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
    from assay.guardian import no_coherence_by_dignity_debt, no_action_without_receipt
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
        console.print(f"[red]-[/] No coherence by dignity debt: FAIL ({verdict1.reason})")
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
    coherence: float = typer.Option(0.8, "--coherence", "-c", help="Current coherence (0-1)"),
    tension: float = typer.Option(0.2, "--tension", "-t", help="Current tension (0-1)"),
    tension_delta: float = typer.Option(-0.01, "--tension-delta", help="Tension rate of change"),
    dignity: float = typer.Option(0.3, "--dignity", "-d", help="Current dignity (0-1)"),
    volatility: float = typer.Option(0.1, "--volatility", "-v", help="Current volatility (0-1)"),
    stateful: bool = typer.Option(False, "--stateful", help="Use hysteresis tracker (persists state)"),
    trace_id: Optional[str] = typer.Option(None, "--trace", help="Trace ID for stateful mode"),
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
    from assay.health import check_grace_status, format_grace_status, GraceConfig, GraceTracker, clamp
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
        in_grace = tracker.update(coherence, tension, tension_delta, dignity, volatility)

        # Persist this check
        store.append_dict({
            "type": "grace_check",
            "coherence": coherence,
            "tension": tension,
            "tension_delta": tension_delta,
            "dignity": dignity,
            "volatility": volatility,
            "in_grace": in_grace,
            "history": tracker.history,
            "stateful": True,
        })

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

        console.print(Panel(
            panel_content,
            title=f"[{'green' if in_grace else 'yellow'} bold]{status_text}[/]",
            border_style="green" if in_grace else "yellow",
        ))
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
            _output_json({
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
            })

        # Display with colors
        if status.in_grace:
            console.print(Panel(
                format_grace_status(status).replace("[+]", "[green]+[/]").replace("[-]", "[red]-[/]"),
                title="[green bold]GRACE WINDOW[/]",
                border_style="green",
            ))
        else:
            console.print(Panel(
                format_grace_status(status).replace("[+]", "[green]+[/]").replace("[-]", "[red]-[/]"),
                title="[yellow bold]NOT IN GRACE[/]",
                border_style="yellow",
            ))

    # Show config
    console.print(f"\n[dim]Thresholds: C>={cfg.c_hi} T<={cfg.t_lo} D>={cfg.d_floor} V<={cfg.v_max}[/]")


@assay_app.command("demo", hidden=True)
def run_demo(
    scenario: str = typer.Option("all", "--scenario", "-s", help="Demo scenario: all, incomplete, contradiction, paradox, guardian"),
    persist: bool = typer.Option(True, "--persist/--no-persist", help="Persist receipts to disk"),
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
        console.print("Tamper-evident audit trails for AI systems")
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
        console.print(f"  Claim A ({receipt.claim_a_confidence:.0%}): {receipt.claim_a}")
        console.print(f"  Claim B ({receipt.claim_b_confidence:.0%}): {receipt.claim_b}")
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
        store.append_dict({
            "type": "guardian_verdict",
            "rule": "no_coherence_by_dignity_debt",
            "coherence_delta": coherence_delta,
            "dignity_delta": dignity_delta,
            "dignity_composite": 0.65,
            "allowed": verdict.allowed,
            "reason": verdict.reason,
            "clause0_violation": verdict.clause0_violation,
        })

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
            _output_json({
                "command": "show",
                "trace_id": trace_id,
                "status": "error",
                "errors": [f"Trace not found: {trace_id}"],
            })
        console.print(f"[red]Trace not found:[/] {trace_id}")
        raise typer.Exit(1)

    if output_json:
        _output_json({
            "command": "show",
            "trace_id": trace_id,
            "status": "ok",
            "entry_count": len(entries),
            "entries": entries,
        })

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
        _output_json({
            "command": "list",
            "status": "ok",
            "count": len(traces),
            "traces": traces,
        })

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
        size = f"{t['size_bytes']} B" if t['size_bytes'] < 1024 else f"{t['size_bytes']//1024} KB"
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
    strict: bool = typer.Option(False, "--strict", help="Enable strict mode (check hashes/signatures)"),
    policy_override: Optional[List[str]] = typer.Option(None, "--policy-override", help="Override policy values (repeatable, e.g., dignity_floor=0.5)"),
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
            _output_json({
                "command": "verify",
                "trace_id": trace_id,
                "status": "error",
                "errors": [f"Trace not found: {trace_id}"],
            })
        console.print(f"[red]Trace not found:[/] {trace_id}")
        raise typer.Exit(1)

    # Parse policy overrides
    overrides: Dict[str, float] = {}
    if policy_override:
        for override in policy_override:
            if "=" not in override:
                if output_json:
                    _output_json({
                        "command": "verify",
                        "trace_id": trace_id,
                        "status": "error",
                        "errors": [f"Invalid policy override format: {override} (expected key=value)"],
                    })
                console.print(f"[red]Invalid policy override format:[/] {override}")
                console.print("[dim]Expected format: key=value (e.g., dignity_floor=0.5)[/]")
                raise typer.Exit(1)
            key, value = override.split("=", 1)
            try:
                overrides[key.strip()] = float(value.strip())
            except ValueError:
                if output_json:
                    _output_json({
                        "command": "verify",
                        "trace_id": trace_id,
                        "status": "error",
                        "errors": [f"Invalid policy override value: {value} (expected float)"],
                    })
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
                errors.append(f"Entry {entry_num}: temporal ordering violation (_stored_at goes backwards)")
        prev_stored_at = stored_at

        # Check parent references (if present)
        # ParadoxReceipt has contradiction_id, other receipts may have parent_receipt_id
        parent_id = entry.get("parent_receipt_id") or entry.get("contradiction_id")
        if parent_id and parent_id not in all_receipt_ids:
            warnings.append(f"Entry {entry_num}: parent reference '{parent_id}' not found in trace")

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
                            policy_violations.append({
                                "entry": entry_num,
                                "receipt_id": receipt_id,
                                "field": "dignity_composite",
                                "value": dignity_val,
                                "floor": floor,
                            })
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
                            policy_violations.append({
                                "entry": entry_num,
                                "receipt_id": receipt_id,
                                "field": "coherence",
                                "value": coherence_val,
                                "floor": floor,
                            })
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
            content_hash = proof.get("hash") or entry.get("content_hash") or entry.get("hash")

            if entry_type and "Receipt" in str(entry_type):
                if not content_hash:
                    warnings.append(f"Entry {entry_num}: receipt has no content_hash (strict)")
                else:
                    # Verify hash matches content
                    try:
                        from assay._receipts.canonicalize import compute_payload_hash

                        # Exclude proof and trace metadata for hash computation
                        payload = {k: v for k, v in entry.items()
                                   if k not in ("proof", "_trace_id", "_stored_at")}
                        # compute_payload_hash already returns "sha256:..." prefixed
                        computed_hash = compute_payload_hash(payload, algorithm="sha256")

                        # Normalize stored hash to have prefix for comparison
                        hash_to_check = content_hash
                        if ":" not in hash_to_check:
                            hash_to_check = f"sha256:{hash_to_check}"

                        if hash_to_check != computed_hash:
                            errors.append(f"Entry {entry_num}: hash mismatch (computed {computed_hash[:25]}..., got {hash_to_check[:25]}...)")
                    except ImportError:
                        warnings.append(f"Entry {entry_num}: cannot verify hash (canonicalize not available)")
                    except Exception as e:
                        warnings.append(f"Entry {entry_num}: hash verification error: {e}")

                # Verify receipt_hash if present
                receipt_hash = entry.get("receipt_hash")
                if receipt_hash:
                    try:
                        from assay._receipts.canonicalize import compute_payload_hash

                        payload = {k: v for k, v in entry.items()
                                   if k not in ("proof", "_trace_id", "_stored_at", "receipt_hash")}
                        computed_receipt_hash = compute_payload_hash(payload, algorithm="sha256")

                        hash_to_check = receipt_hash
                        if ":" not in hash_to_check:
                            hash_to_check = f"sha256:{hash_to_check}"

                        if hash_to_check != computed_receipt_hash:
                            errors.append(
                                f"Entry {entry_num}: receipt_hash mismatch "
                                f"(computed {computed_receipt_hash[:25]}..., got {hash_to_check[:25]}...)"
                            )
                    except ImportError:
                        warnings.append(f"Entry {entry_num}: cannot verify receipt_hash (canonicalize not available)")
                    except Exception as e:
                        warnings.append(f"Entry {entry_num}: receipt_hash verification error: {e}")

                # Check signature if present
                signature = proof.get("producer_signature")
                if signature:
                    try:
                        # Signature verification requires the verify key
                        # For now, just note that signature is present
                        warnings.append(f"Entry {entry_num}: signature present but key not configured for verification")
                    except Exception as e:
                        warnings.append(f"Entry {entry_num}: signature check error: {e}")

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

    console.print(f"\n[dim]Checked: {len(entries)} entries, {len(all_receipt_ids)} receipts[/]")

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
    from assay.store import get_default_store
    from collections import Counter

    store = get_default_store()
    entries_a = store.read_trace(trace_a)
    entries_b = store.read_trace(trace_b)

    if not entries_a:
        if output_json:
            _output_json({
                "command": "diff",
                "trace_a": trace_a,
                "trace_b": trace_b,
                "status": "error",
                "errors": [f"Trace not found: {trace_a}"],
            })
        console.print(f"[red]Trace not found:[/] {trace_a}")
        raise typer.Exit(1)
    if not entries_b:
        if output_json:
            _output_json({
                "command": "diff",
                "trace_a": trace_a,
                "trace_b": trace_b,
                "status": "error",
                "errors": [f"Trace not found: {trace_b}"],
            })
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
        type_table = Table(show_header=True, header_style="bold", title="Type Distribution")
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
        console.print(f"\n[dim]IDs only in A: {', '.join(list(only_a)[:5])}{'...' if len(only_a) > 5 else ''}[/]")
    if only_b:
        console.print(f"[dim]IDs only in B: {', '.join(list(only_b)[:5])}{'...' if len(only_b) > 5 else ''}[/]")


@assay_app.command("pack", hidden=True)
def create_pack(
    trace_id: str = typer.Argument(..., help="Trace ID to package"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output zip path (default: evidence_pack_<trace_id>.zip)"),
    include_source: bool = typer.Option(False, "--include-source", help="Include relevant source files"),
    forensic: bool = typer.Option(False, "--forensic", help="Preserve raw trace bytes (forensic fidelity)"),
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
            _output_json({
                "command": "pack",
                "status": "error",
                "trace_id": trace_id,
                "errors": [str(e)],
            })
            return  # _output_json raises, but be explicit
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
    except Exception as e:
        if output_json:
            _output_json({
                "command": "pack",
                "status": "error",
                "trace_id": trace_id,
                "errors": [str(e)],
            })
            return  # _output_json raises, but be explicit
        console.print(f"[red]Unexpected error:[/] {e}")
        raise typer.Exit(1)

    # JSON output mode - emit and exit
    if output_json:
        _output_json({
            "command": "pack",
            "status": "ok",
            "trace_id": trace_id,
            "output_path": str(result_path),
            "include_source": include_source,
            "forensic_mode": forensic,
        })
        return  # _output_json raises, but be explicit

    # Console output mode
    console.print(f"[green bold]Evidence pack created:[/] {result_path}")
    console.print(f"\n[dim]Trace: {trace_id}[/]")
    console.print(f"[dim]Source files: {include_source}, Forensic mode: {forensic}[/]")


@assay_app.command("launch-check", hidden=True)
def launch_check(
    emit: bool = typer.Option(False, "--emit", help="Persist LaunchReadinessReceipt to disk"),
    artifacts_dir: Optional[str] = typer.Option(None, "--artifacts-dir", help="Directory for stdout/stderr captures"),
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
        artifact_path = Path.home() / ".assay" / "artifacts" / "launch-check" / timestamp
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

    def run_check(name: str, cmd: List[str], expect_trace: bool = False) -> Dict[str, Any]:
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
                error_msg = result.stderr[:500] if result.stderr else f"Exit code {result.returncode}"

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
    checks.append(run_check("assay_demo", ["python", "-m", "assay.cli", "demo"], expect_trace=True))

    # 3. Validate
    console.print("  [dim]3/7[/] assay validate")
    checks.append(run_check("assay_validate", [
        "python", "-m", "assay.cli", "validate",
        "test action", "--coherence", "0.8", "--dignity", "0.7", "--receipt"
    ]))

    # 4. Health
    console.print("  [dim]4/7[/] assay health")
    checks.append(run_check("assay_health", ["python", "-m", "assay.cli", "health"]))

    # 5. Assay tests
    console.print("  [dim]5/7[/] pytest tests/assay/")
    checks.append(run_check("assay_tests", ["python", "-m", "pytest", "tests/assay/", "-v", "--tb=short"]))

    # 6. Patent receipt tests
    console.print("  [dim]6/7[/] pytest tests/receipts/test_patent_receipts.py")
    checks.append(run_check("patent_tests", ["python", "-m", "pytest", "tests/receipts/test_patent_receipts.py", "-v", "--tb=short"]))

    # 7. Evidence pack (only if demo succeeded and we have a trace_id)
    console.print("  [dim]7/7[/] evidence pack generation")
    if demo_trace_id:
        pack_output = artifact_path / f"evidence_pack_{demo_trace_id}.zip"
        checks.append(run_check("evidence_pack", [
            "python", "-m", "assay.cli", "pack",
            demo_trace_id, "-o", str(pack_output)
        ]))
    else:
        checks.append({
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
        })

    console.print()

    # Create check result objects
    check_results = []
    for c in checks:
        check_results.append(CheckResult(
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
        ))

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
        receipt_path.write_text(json.dumps(receipt.model_dump(mode="json"), indent=2, default=str))

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
    table = Table(title="Launch Readiness Checks", show_header=True, header_style="bold")
    table.add_column("Check", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Details")

    for c in check_results:
        status = "[green]PASS[/]" if c.passed else "[red]FAIL[/]"
        duration = f"{c.duration_ms}ms"
        details = c.error_message[:50] + "..." if c.error_message and len(c.error_message) > 50 else (c.error_message or "")
        table.add_row(c.name, status, duration, details)

    console.print(table)
    console.print()

    # Summary
    summary = receipt.component_summary
    if receipt.overall_passed:
        console.print(f"[green bold]LAUNCH READINESS: PASSED[/] ({summary.passed}/{summary.total} checks)")
    else:
        console.print(f"[red bold]LAUNCH READINESS: FAILED[/] ({summary.failed}/{summary.total} checks failed)")

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
        console.print(f"\n[bold]LAUNCH_READINESS: {'PASSED' if receipt.overall_passed else 'FAILED'} path={receipt_path} receipt_id={receipt.receipt_id}[/]")

    if not receipt.overall_passed:
        raise typer.Exit(2)


@assay_app.command("version")
def show_version(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show Assay version and configuration."""
    from assay import __version__
    from assay.store import get_default_store

    store = get_default_store()

    if output_json:
        _output_json({
            "command": "version",
            "status": "ok",
            "version": __version__,
            "storage_dir": str(store.base_dir),
            "components": {
                "guardian_rules": ["no_coherence_by_dignity_debt", "no_action_without_receipt"],
                "health_checks": ["grace_window"],
                "blockage_receipts": ["incompleteness", "contradiction", "paradox"],
            },
        })

    console.print(f"[bold]Assay {__version__}[/]")
    console.print("Tamper-evident audit trails for AI systems")
    console.print()
    console.print("Capabilities:")
    console.print("  - Scan: find uninstrumented LLM call sites")
    console.print("  - Instrument: OpenAI, Anthropic, LangChain (2 lines)")
    console.print("  - Proof packs: receipts + manifest + Ed25519 signature")
    console.print("  - Verify: exit 0/1/2/3 (pass / honest failure / tampered / bad input)")
    console.print()
    console.print(f"Storage: {store.base_dir}")


@assay_app.command("status")
def status_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """One-screen operational dashboard: is Assay ready here?"""
    import os
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
        checks["key"] = {"signer": None, "has_key": False, "fingerprint": None, "total_signers": 0}

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
        [d for d in Path(".").iterdir()
         if d.is_dir() and d.name.startswith("proof_pack") and (d / "pack_manifest.json").exists()],
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
            checks["latest_pack"] = {"path": str(latest), "pack_id": "?", "receipts": "?", "age": "?"}
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
        table.add_row("Latest pack", f"{lp['path']}  ({lp['receipts']} receipts, {lp['age']})")
    else:
        table.add_row("Latest pack", "[dim]none in cwd[/]")

    # MCP proxy
    table.add_row("MCP proxy", "ready")

    console.print(Panel(table, title="assay status", border_style="blue"))

    # Overall verdict
    ok = key["has_key"]
    if ok:
        console.print("\n  [green]OPERATIONAL[/]  Ready to produce and verify evidence.\n")
    else:
        console.print("\n  [yellow]SETUP NEEDED[/]  Run: assay quickstart\n")


@assay_app.command("score")
def score_cmd(
    path: str = typer.Argument(".", help="Repository directory to score"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compute an Evidence Readiness Score (0-100, A-F) for a repository.

    This is a readiness signal, not a security guarantee.
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

    header = (
        f"[bold]Evidence Readiness Score[/]\n\n"
        f"Repo:    {root}\n"
        f"Score:   [bold]{score['score']:.1f}[/] / 100\n"
        f"Grade:   [{grade_style}][bold]{score['grade']}[/]\n"
        f"Version: {score['score_version']}"
    )
    console.print(Panel.fit(header, title="assay score", border_style="blue"))

    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Component")
    table.add_column("Points", justify="right")
    table.add_column("Weight", justify="right")
    table.add_column("Status")
    table.add_column("Note")
    for key in ("coverage", "lockfile", "ci_gate", "receipts", "key_setup"):
        comp = score["breakdown"][key]
        table.add_row(
            key,
            f"{comp['points']:.1f}",
            str(comp["weight"]),
            comp["status"],
            comp["note"],
        )
    console.print(table)

    if score["caps_applied"]:
        caps_lines = []
        for cap in score["caps_applied"]:
            caps_lines.append(
                f"- {cap['id']}: {cap['reason']} ({cap['before']['grade']} -> {cap['after']['grade']})"
            )
        console.print(Panel("\n".join(caps_lines), title="Caps Applied", border_style="yellow"))

    console.print("\n[bold]Next actions:[/]")
    for idx, action in enumerate(score["next_actions"], 1):
        console.print(f"  {idx}. {action}")

    console.print(f"\n[dim]{score['disclaimer']}[/]\n")


# ---------------------------------------------------------------------------
# assay start -- guided entrypoints
# ---------------------------------------------------------------------------

start_app = typer.Typer(
    name="start",
    help="Guided setup for your use case",
    no_args_is_help=True,
)
assay_app.add_typer(start_app, name="start")


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
    console.print("    [dim]Auto-discovers baseline, traces regressions to root cause.[/]\n")


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


@assay_app.command("proof-pack")
def proof_pack_cmd(
    trace_id: str = typer.Argument(..., help="Trace ID to package"),
    output_dir: str = typer.Option(None, "--output", "-o", help="Output directory"),
    mode: str = typer.Option("shadow", "--mode", "-m", help="Mode: shadow|enforced|breakglass"),
    run_card: Optional[List[str]] = typer.Option(
        None, "--run-card", "-c",
        help="Run card: builtin name or path to JSON file (repeatable)",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Build a signed Proof Pack (5-file kernel) from a trace."""
    from pathlib import Path

    from assay.proof_pack import build_proof_pack
    from assay.run_cards import collect_claims_from_cards, get_builtin_card, load_run_card

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
        result_dir = build_proof_pack(trace_id, output_dir=out, mode=mode, claims=claims)
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
        _output_json({
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
        })

    console.print()
    claim_line = f"Claims:     {att.get('claim_check', 'N/A')}\n" if claims else ""
    console.print(Panel.fit(
        f"[bold green]Proof Pack Built[/]\n\n"
        f"Pack ID:    {att.get('pack_id')}\n"
        f"Trace:      {trace_id}\n"
        f"Integrity:  {att.get('receipt_integrity')}\n"
        f"{claim_line}"
        f"Receipts:   {att.get('n_receipts')}\n"
        f"Mode:       {att.get('mode')}\n"
        f"Output:     {result_dir}/",
        title="assay proof-pack",
    ))

    # List files
    for f in sorted(result_dir.iterdir()):
        size = f.stat().st_size
        console.print(f"  {f.name:30s} {size:>8,} bytes")

    console.print()
    console.print(f"Next: [bold]assay verify-pack {result_dir}[/]")


@assay_app.command("verify-pack")
def verify_pack_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    require_claim_pass: bool = typer.Option(
        False, "--require-claim-pass",
        help="Fail (exit 1) if claim_check is not PASS. For CI gating.",
    ),
    lock: Optional[str] = typer.Option(
        None, "--lock",
        help="Path to assay.lock file. Enforces locked verification semantics.",
    ),
    coverage_contract: Optional[str] = typer.Option(
        None, "--coverage-contract",
        help="Path to coverage contract JSON. Checks receipt callsite coverage.",
    ),
    min_coverage: float = typer.Option(
        0.8, "--min-coverage",
        help="Minimum coverage threshold (0.0-1.0). Used with --coverage-contract.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify a Proof Pack's integrity (manifest, signatures, file hashes)."""
    from pathlib import Path

    from assay.integrity import verify_pack_manifest
    from assay.keystore import get_default_keystore

    if not 0.0 <= min_coverage <= 1.0:
        if output_json:
            _output_json({"command": "verify-pack", "status": "error", "error": f"--min-coverage must be between 0.0 and 1.0, got {min_coverage}"})
        console.print(f"[red]Error:[/] --min-coverage must be between 0.0 and 1.0, got {min_coverage}")
        raise typer.Exit(3)

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not manifest_path.exists():
        if output_json:
            _output_json({"command": "verify-pack", "status": "error", "error": "pack_manifest.json not found"})
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(1)

    manifest = json.loads(manifest_path.read_text())

    # Schema validation (verify-time enforcement)
    from assay.manifest_schema import validate_manifest
    schema_errors = validate_manifest(manifest)
    if schema_errors:
        if output_json:
            _output_json({
                "command": "verify-pack", "status": "error",
                "error": "schema_validation_failed", "details": schema_errors,
            })
        console.print("[red]Schema validation failed:[/]")
        for se in schema_errors[:10]:
            console.print(f"  {se}")
        raise typer.Exit(1)

    ks = get_default_keystore()
    result = verify_pack_manifest(manifest, pack_path, ks)

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
                _output_json({
                    "command": "verify-pack", "status": "error",
                    "error": "lockfile_invalid", "details": lock_issues,
                })
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
                _output_json({"command": "verify-pack", "status": "error", "error": f"Coverage contract not found: {coverage_contract}"})
            console.print(f"[red]Error:[/] Coverage contract not found: {coverage_contract}")
            raise typer.Exit(2)

        try:
            contract = CoverageContract.load(cc_path)
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            if output_json:
                _output_json({"command": "verify-pack", "status": "error", "error": f"Invalid coverage contract: {e}"})
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

    overall_status = "ok"
    if not result.passed:
        overall_status = "failed"
    elif lock_failed:
        overall_status = "lock_mismatch"
    elif claim_gate_failed:
        overall_status = "claim_gate_failed"
    elif coverage_failed:
        overall_status = "coverage_below_threshold"

    if output_json:
        out = {
            "command": "verify-pack",
            "status": overall_status,
            "claim_check": claim_check,
            **result.to_dict(),
        }
        if claim_gate_failed:
            out["claim_gate"] = f"--require-claim-pass: claim_check is '{claim_check}'"
        if lock_failed:
            out["lock_errors"] = [str(e) for e in lock_errors]
        if coverage_result is not None:
            out["coverage"] = coverage_result
        _output_json(out)

    if lock_failed:
        console.print()
        console.print(Panel.fit(
            f"[bold red]LOCK MISMATCH[/]\n\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Lock file:  {lock}\n"
            f"Mismatches: {len(lock_errors)}",
            title="assay verify-pack",
        ))
        for le in lock_errors:
            console.print(f"  [red]{le.field}[/]: expected {le.expected}, got {le.actual}")
        console.print()
        raise typer.Exit(2)

    if result.passed and not claim_gate_failed and not coverage_failed:
        lock_line = f"\nLock:       PASS ({lock})" if lock else ""
        cov_line = ""
        if coverage_result is not None:
            pct = coverage_result["coverage_pct"]
            cov_line = f"\nCoverage:   {pct:.0%} ({coverage_result['covered_count']}/{coverage_result['total_count']})"
        console.print()
        console.print(Panel.fit(
            f"[bold green]VERIFICATION PASSED[/]\n\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Integrity:  PASS\n"
            f"Claims:     {claim_check}\n"
            f"Receipts:   {result.receipt_count}\n"
            f"Head Hash:  {result.head_hash or 'N/A'}\n"
            f"Errors:     0\n"
            f"Warnings:   {len(result.warnings)}"
            f"{lock_line}"
            f"{cov_line}",
            title="assay verify-pack",
        ))
    elif result.passed and claim_gate_failed:
        console.print()
        console.print(Panel.fit(
            f"[bold yellow]CLAIM GATE FAILED[/]\n\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Integrity:  PASS\n"
            f"Claims:     {claim_check}\n"
            f"Receipts:   {result.receipt_count}\n\n"
            f"--require-claim-pass was set but claim_check is '{claim_check}'",
            title="assay verify-pack",
        ))
    elif result.passed and coverage_failed and coverage_result is not None:
        pct = coverage_result["coverage_pct"]
        console.print()
        console.print(Panel.fit(
            f"[bold yellow]COVERAGE BELOW THRESHOLD[/]\n\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Integrity:  PASS\n"
            f"Claims:     {claim_check}\n"
            f"Coverage:   {pct:.0%} ({coverage_result['covered_count']}/{coverage_result['total_count']})\n"
            f"Threshold:  {min_coverage:.0%}\n"
            f"Uncovered:  {len(coverage_result.get('uncovered_ids', []))} site(s)",
            title="assay verify-pack",
        ))
    else:
        console.print()
        console.print(Panel.fit(
            f"[bold red]VERIFICATION FAILED[/]\n\n"
            f"Pack ID:    {att.get('pack_id')}\n"
            f"Errors:     {len(result.errors)}",
            title="assay verify-pack",
        ))
        for err in result.errors:
            console.print(f"  [red]{err.code}[/]: {err.message}")

    if result.warnings:
        for w in result.warnings:
            console.print(f"  [yellow]Warning:[/] {w}")

    console.print()

    if result.passed and not claim_gate_failed and not coverage_failed and not lock:
        console.print("Next: [bold]assay lock init[/]")
        console.print()

    if not result.passed:
        raise typer.Exit(2)
    if claim_gate_failed:
        raise typer.Exit(1)
    if coverage_failed:
        raise typer.Exit(1)


@assay_app.command("verify-signer")
def verify_signer_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    expected: Optional[str] = typer.Option(
        None, "--expected",
        help="Expected signer_id. Fail (exit 1) if pack signer doesn't match.",
    ),
    fingerprint: Optional[str] = typer.Option(
        None, "--fingerprint",
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
            _output_json({"command": "verify-signer", "status": "error", "error": f"Not a directory: {pack_dir}"}, exit_code=3)
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not manifest_path.exists():
        if output_json:
            _output_json({"command": "verify-signer", "status": "error", "error": "pack_manifest.json not found"}, exit_code=3)
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
        console.print(Panel.fit(
            f"[bold green]SIGNER VERIFIED[/]\n\n"
            f"Signer ID:       {signer_id}\n"
            f"Fingerprint:     {fp_display}\n"
            f"Algorithm:       {signature_alg}\n"
            f"In keystore:     {local_badge}\n"
            f"Local FP match:  {fp_badge}",
            title="assay verify-signer",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]SIGNER MISMATCH[/]\n\n"
            f"Signer ID:       {signer_id}\n"
            f"Fingerprint:     {fp_display}\n"
            f"Algorithm:       {signature_alg}\n"
            f"In keystore:     {local_badge}\n\n"
            f"[red]{mismatch_reason}[/]",
            title="assay verify-signer",
        ))
    console.print()

    if not match_ok:
        raise typer.Exit(1)


@assay_app.command("demo-pack")
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
            _output_json({
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
            })

        # Output
        console.print()
        console.print("[bold]ASSAY DEMO PACK[/]")
        console.print()

        console.print("[dim]Step 1:[/] Created 5 synthetic receipts")
        for r in receipts:
            console.print(f"  {r['type']:20s} seq={r['seq']}  {r['receipt_id']}")

        console.print()
        console.print("[dim]Step 2:[/] Built Proof Pack A (4 claims, all should pass)")
        console.print(Panel.fit(
            f"Pack ID:    {att_a['pack_id']}\n"
            f"Integrity:  [green]{att_a['receipt_integrity']}[/]\n"
            f"Claims:     [green]{att_a['claim_check']}[/]\n"
            f"Receipts:   {att_a['n_receipts']}\n"
            f"Verified:   [green]{'PASS' if result_a.passed else 'FAIL'}[/]",
            title="Pack A: all claims pass",
        ))

        console.print("[dim]Step 3:[/] Built Pack B (same receipts, stricter claim: need 100 receipts)")
        console.print(Panel.fit(
            f"Pack ID:    {att_b['pack_id']}\n"
            f"Integrity:  [green]{att_b['receipt_integrity']}[/]  (same receipts = same integrity)\n"
            f"Claims:     [red]{att_b['claim_check']}[/]  (5 receipts < 100 required)\n"
            f"Receipts:   {att_b['n_receipts']}",
            title="Pack B: claim fails honestly",
        ))

        console.print()
        console.print("[bold]Key insight:[/] Same evidence, different claims, different outcomes.")
        console.print("Integrity PASS + Claim FAIL = honest failure report, not a cover-up.")
        console.print()
        console.print("[dim]Files in each pack:[/]")
        for f in sorted(out_a.iterdir()):
            console.print(f"  {f.name}")
        console.print()
        console.print("Next steps:")
        console.print("  Emit receipts from your code:  [bold]from assay import emit_receipt[/]")
        console.print("  Wrap a command:                [bold]assay run -- python my_agent.py[/]")
        console.print("  Verify a pack:                 [bold]assay verify-pack <dir>[/]")
        console.print("  CI gate:                       [bold]assay verify-pack <dir> --require-claim-pass[/]")


@assay_app.command("run", context_settings={"allow_extra_args": True, "allow_interspersed_args": False})
def run_cmd(
    ctx: typer.Context,
    run_card: Optional[List[str]] = typer.Option(
        None, "--run-card", "-c",
        help="Run card: builtin name or path to JSON file (repeatable)",
    ),
    output_dir: str = typer.Option(None, "--output", "-o", help="Output directory for proof pack"),
    mode: str = typer.Option("shadow", "--mode", "-m", help="Mode: shadow|enforced|breakglass"),
    allow_empty: bool = typer.Option(
        False, "--allow-empty",
        help="Allow empty receipt packs (default: fail if no receipts emitted)",
    ),
    no_generate_key: bool = typer.Option(
        False, "--no-generate-key",
        help="Fail if signing key doesn't exist instead of auto-generating",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Run a command and build a Proof Pack from emitted receipts.

    Usage: assay run [OPTIONS] -- <command> [args...]

    The command's receipts are captured and packaged into a signed Proof Pack.
    """
    import subprocess
    import sys
    import shutil
    from pathlib import Path

    from assay.claim_verifier import ClaimSpec
    from assay.keystore import get_default_keystore
    from assay.proof_pack import ProofPack
    from assay.run_cards import collect_claims_from_cards, get_builtin_card, load_run_card
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
                        "pip install assay-ai[openai]",
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
            "  3. Missing SDK extra:     [bold]pip install assay-ai\\[openai][/]\n"
            "     (or assay-ai\\[anthropic], assay-ai\\[all])\n"
            "  4. Missing separator:     [bold]assay run -- python app.py[/] (note the --)\n"
            "  5. Full diagnostic:       [bold]assay doctor[/]\n"
            "  6. Then re-run:           [bold]assay run -- <your command>[/]\n"
            "\n"
            "Use --allow-empty to build an empty pack anyway."
        )
        raise typer.Exit(1)
    if not entries:
        console.print("[yellow]Warning:[/] No receipts emitted. Building empty pack (--allow-empty).")
        entries = []

    pack = ProofPack(
        run_id=trace_id,
        entries=entries,
        signer_id=signer_id,
        claims=claims,
        mode=mode,
    )

    try:
        result_dir = pack.build(out, keystore=ks)
    except Exception as e:
        console.print(f"[red]Error building pack:[/] {e}")
        raise typer.Exit(1)

    manifest = json.loads((result_dir / "pack_manifest.json").read_text())
    att = manifest.get("attestation", {})

    if output_json:
        _output_json({
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
        })

    claim_line = f"Claims:     {att.get('claim_check', 'N/A')}\n" if claims else ""
    console.print()
    console.print(Panel.fit(
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
    ))

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
assay_app.add_typer(key_app, name="key")


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
        console.print(Panel.fit(
            "[yellow]No signer keys found.[/]\n\n"
            "A key is auto-generated on first [bold]assay run[/].\n"
            "Create one now with:\n"
            "  [bold]assay run --allow-empty -- python -c \"pass\"[/]",
            title="assay key list",
        ))
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
            _output_json({"command": "key set-active", "status": "error", "error": str(e)}, exit_code=3)
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
    console.print(Panel.fit(
        f"[bold green]Active signer updated[/]\n\n"
        f"Signer:      {signer_id}\n"
        f"Fingerprint: {fp[:16]}...",
        title="assay key set-active",
    ))
    console.print()


@key_app.command("rotate")
def key_rotate_cmd(
    signer: Optional[str] = typer.Option(
        None, "--signer",
        help="Existing signer to rotate from (default: active signer)",
    ),
    new_signer: Optional[str] = typer.Option(
        None, "--new-signer",
        help="Signer ID for new key (default: <signer>-YYYYMMDDHHMMSS)",
    ),
    set_active: bool = typer.Option(
        True, "--set-active/--no-set-active",
        help="Set new signer as active after generation",
    ),
    lock: Optional[str] = typer.Option(
        None, "--lock",
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
            f"Create it first with `assay run --allow-empty -- python -c \"pass\"` "
            f"or pick an existing signer from `assay key list`."
        )
        if output_json:
            _output_json({"command": "key rotate", "status": "error", "error": msg}, exit_code=3)
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    if new_signer is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        new_signer = f"{old_signer}-{ts}"

    if ks.has_key(new_signer):
        msg = f"Signer already exists: {new_signer}"
        if output_json:
            _output_json({"command": "key rotate", "status": "error", "error": msg}, exit_code=3)
        console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(3)

    lock_path: Optional[Path] = None
    if lock:
        lock_path = Path(lock)
        if not lock_path.exists():
            msg = f"Lock file not found: {lock_path}"
            if output_json:
                _output_json({"command": "key rotate", "status": "error", "error": msg}, exit_code=3)
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


# ---------------------------------------------------------------------------
# Lock subcommands
# ---------------------------------------------------------------------------

lock_app = typer.Typer(
    name="lock",
    help="Manage verifier lockfile (assay.lock)",
    no_args_is_help=True,
)
assay_app.add_typer(lock_app, name="lock")


@lock_app.command("write")
def lock_write_cmd(
    cards: str = typer.Option(
        ..., "--cards", "-c",
        help="Comma-separated RunCard IDs (e.g. receipt_completeness,guardian_enforcement)",
    ),
    signer: Optional[str] = typer.Option(
        None, "--signer",
        help="Comma-separated signer pubkey SHA-256 fingerprints for allowlist policy",
    ),
    output: str = typer.Option(
        "assay.lock", "--output", "-o",
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
        _output_json({
            "command": "lock write",
            "status": "ok",
            "output": output,
            "run_cards": len(card_ids),
            "composite_hash": lockfile["run_cards_composite_hash"],
        })
    else:
        console.print()
        console.print(Panel.fit(
            f"[bold green]Lockfile written[/]\n\n"
            f"Path:       {output}\n"
            f"RunCards:    {', '.join(card_ids)}\n"
            f"Composite:  {lockfile['run_cards_composite_hash'][:16]}...\n"
            f"Signer:     {lockfile['signer_policy']['mode']}",
            title="assay lock write",
        ))
        console.print()
        console.print("Next: [bold]assay verify-pack <pack_dir> --lock assay.lock --require-claim-pass[/]")
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
            _output_json({"command": "lock check", "status": "error", "error": f"Not found: {path}"})
        console.print(f"[red]Error:[/] {path} not found")
        raise typer.Exit(1)

    issues = check_lockfile(lock_path)

    if output_json:
        _output_json({
            "command": "lock check",
            "status": "ok" if not issues else "failed",
            "issues": issues,
        })
    elif issues:
        console.print()
        console.print(Panel.fit(
            f"[bold red]Lockfile invalid[/]\n\n"
            f"Path:    {path}\n"
            f"Issues:  {len(issues)}",
            title="assay lock check",
        ))
        for issue in issues:
            console.print(f"  [red]{issue}[/]")
        console.print()
        raise typer.Exit(1)
    else:
        console.print()
        console.print(Panel.fit(
            f"[bold green]Lockfile valid[/]\n\n"
            f"Path:  {path}",
            title="assay lock check",
        ))
        console.print()


@lock_app.command("init")
def lock_init_cmd(
    output: str = typer.Option(
        "assay.lock", "--output", "-o",
        help="Output path for lockfile",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Create a lockfile with sane defaults (receipt_completeness card)."""
    from pathlib import Path

    from assay.lockfile import write_lockfile

    card_ids = ["receipt_completeness"]
    out_path = Path(output)

    if out_path.exists():
        if output_json:
            _output_json({"command": "lock init", "status": "error", "error": f"Already exists: {output} (use 'assay lock write' to overwrite)"})
        console.print(f"[red]Error:[/] {output} already exists. Use [bold]assay lock write[/] to overwrite.")
        raise typer.Exit(1)

    try:
        lockfile = write_lockfile(card_ids, output_path=out_path)
    except ValueError as e:
        if output_json:
            _output_json({"command": "lock init", "status": "error", "error": str(e)})
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if output_json:
        _output_json({
            "command": "lock init",
            "status": "ok",
            "output": output,
            "run_cards": card_ids,
            "composite_hash": lockfile["run_cards_composite_hash"],
        })
    else:
        console.print()
        console.print(Panel.fit(
            f"[bold green]Lockfile created[/]\n\n"
            f"Path:       {output}\n"
            f"RunCards:    {', '.join(card_ids)}\n"
            f"Composite:  {lockfile['run_cards_composite_hash'][:16]}...\n"
            f"Signer:     {lockfile['signer_policy']['mode']}",
            title="assay lock init",
        ))
        console.print()
        console.print("Next: [bold]assay ci init github --run-command \"python your_app.py\"[/]")
        console.print()


ci_app = typer.Typer(
    name="ci",
    help="Generate CI workflows for Assay verification",
    no_args_is_help=True,
)
assay_app.add_typer(ci_app, name="ci")


# ---------------------------------------------------------------------------
# baseline subcommands
# ---------------------------------------------------------------------------

baseline_app = typer.Typer(
    name="baseline",
    help="Manage the diff baseline pack pointer (.assay/baseline.json)",
    no_args_is_help=True,
)
assay_app.add_typer(baseline_app, name="baseline")


@baseline_app.command("set")
def baseline_set_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory to use as baseline"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Save a proof pack as the diff baseline."""
    from pathlib import Path

    from assay.diff import save_baseline

    p = Path(pack_dir)
    if not p.is_dir():
        if output_json:
            _output_json({"command": "baseline set", "status": "error", "error": f"Not a directory: {pack_dir}"})
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not (p / "pack_manifest.json").exists():
        if output_json:
            _output_json({"command": "baseline set", "status": "error", "error": f"No pack_manifest.json in {pack_dir}"})
        console.print(f"[red]Error:[/] No pack_manifest.json found in {pack_dir}")
        raise typer.Exit(3)

    bf = save_baseline(p)
    if output_json:
        _output_json({"command": "baseline set", "status": "ok", "pack_path": str(p.resolve()), "baseline_file": str(bf)})
    else:
        console.print()
        console.print(Panel.fit(
            f"[bold green]Baseline set[/]\n\n"
            f"Pack:      {p}\n"
            f"Stored in: {bf}",
            title="assay baseline set",
        ))
        console.print()
        console.print(f"Next: [bold]assay diff <new_pack> --against-previous[/]")
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
            _output_json({"command": "baseline get", "status": "none", "pack_path": None})
        else:
            console.print("No baseline set. Use [bold]assay baseline set <pack_dir>[/]")
        return

    if output_json:
        _output_json({"command": "baseline get", "status": "ok", "pack_path": str(baseline)})
    else:
        console.print(f"Baseline: [bold]{baseline}[/]")


# ---------------------------------------------------------------------------
# cards subcommands
# ---------------------------------------------------------------------------

cards_app = typer.Typer(
    name="cards",
    help="Inspect built-in and custom run cards",
    no_args_is_help=True,
)
assay_app.add_typer(cards_app, name="cards")


@cards_app.command("list")
def cards_list_cmd(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List all built-in run cards."""
    from assay.run_cards import get_all_builtin_cards

    cards = get_all_builtin_cards()

    if output_json:
        _output_json({
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
        })

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
    card_id: str = typer.Argument(help="Card ID to display (e.g. receipt_completeness)"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show details of a specific run card, including its claims."""
    from assay.run_cards import get_builtin_card

    card = get_builtin_card(card_id)
    if card is None:
        from assay.run_cards import BUILTIN_CARDS
        valid = ", ".join(sorted(BUILTIN_CARDS.keys()))
        if output_json:
            _output_json({"command": "cards show", "status": "error",
                          "error": f"Unknown card: {card_id}", "valid_cards": valid},
                         exit_code=3)
        console.print(f"[red]Unknown card:[/] {card_id}")
        console.print(f"[dim]Valid cards: {valid}[/]")
        raise typer.Exit(3)

    if output_json:
        _output_json({
            "command": "cards show",
            "status": "ok",
            **card.to_dict(),
            "claim_set_hash": card.claim_set_hash(),
        })

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
        table.add_row(cl.claim_id, cl.check, f"[{sev_style}]{cl.severity}[/]", cl.description)

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
    force: bool = typer.Option(False, "--force", help="Overwrite existing workflow file"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a CI workflow for Proof Pack generation + verification."""
    from pathlib import Path

    from assay import __version__

    provider_norm = provider.strip().lower()
    if provider_norm != "github":
        if output_json:
            _output_json({
                "command": "ci init",
                "status": "error",
                "error": f"Unsupported provider '{provider}'. Supported: github",
            })
        console.print(f"[red]Error:[/] Unsupported provider '{provider}'. Supported: github")
        raise typer.Exit(1)

    run_command = " ".join(run_command.strip().split())
    if not run_command:
        if output_json:
            _output_json({"command": "ci init", "status": "error", "error": "run_command cannot be empty"})
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
            _output_json({
                "command": "ci init",
                "status": "error",
                "error": f"{output} already exists (use --force to overwrite)",
            })
        console.print(f"[red]Error:[/] {output} already exists. Use --force to overwrite.")
        raise typer.Exit(1)

    workflow_path.parent.mkdir(parents=True, exist_ok=True)

    workflow = f"""name: Assay Verify

on:
  pull_request:
  push:
    branches: [main]

jobs:
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
          pip install "assay-ai=={__version__}"

      # Install your project dependencies before this step if needed.
      - name: Generate Proof Pack
        run: |
          assay run {card_flags} -- {run_command}{"  # TODO: replace with your actual run command" if is_placeholder else ""}

      - name: Verify Proof Pack
        uses: Haserjian/assay-verify-action@v1
        with:
          pack-path: "proof_pack_*/"
          require-claim-pass: true
          comment-on-pr: true
          upload-artifact: true

      # Optional: regression gate against previous pack
      # Uncomment and set a baseline pack path to enable.
      # - name: Regression Gate
      #   run: |
      #     assay diff ./baseline_pack/ ./proof_pack_*/ \\
      #       --gate-cost-pct 25 --gate-errors 0 --gate-strict \\
      #       --report ./diff_report/

      # - name: Upload Diff Report
      #   if: always()
      #   uses: actions/upload-artifact@v4
      #   with:
      #     name: assay-diff-report
      #     path: diff_report/
"""

    workflow_path.write_text(workflow, encoding="utf-8")

    if output_json:
        _output_json({
            "command": "ci init",
            "status": "ok",
            "provider": "github",
            "output": str(workflow_path),
            "run_command": run_command,
            "cards": [c.strip() for c in cards.split(",") if c.strip()],
        })

    console.print()
    console.print(Panel.fit(
        f"[bold green]CI workflow generated[/]\n\n"
        f"Provider:   github\n"
        f"Output:     {workflow_path}\n"
        f"Run:        {run_command}\n"
        f"RunCards:   {cards}",
        title="assay ci init github",
    ))
    if is_placeholder:
        console.print("[yellow]Warning:[/] Using placeholder command 'python my_app.py'.")
        console.print(f"  Edit [bold]{workflow_path}[/] and replace with your actual run command.")
        console.print(f"  Or re-run: assay ci init github --run-command \"python your_app.py\" --force")
        console.print()
    console.print("Next:")
    console.print(f"  1. Review [bold]{workflow_path}[/]")
    console.print("  2. Commit and push")
    console.print("  3. Open a PR to see Assay verification in checks")
    console.print()


@ci_app.command("doctor")
def ci_doctor_cmd(
    lock: Optional[str] = typer.Option(None, "--lock", help="Path to lockfile"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as failures"),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
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
        _output_json(report.to_dict(), exit_code=report.exit_code_strict() if strict else report.exit_code)
        return

    _render_doctor_report(report, strict)


@assay_app.command("onboard")
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
    skip_doctor: bool = typer.Option(False, "--skip-doctor", help="Skip assay doctor preflight"),
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
            _output_json({"command": "onboard", "status": "error", "error": f"Directory not found: {path}"})
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
        next_steps.append(f"Add to your entrypoint ({selected_entrypoint}): {patch_line}")
    else:
        next_steps.append("No SDK patterns detected; add manual emission: from assay import emit_receipt")
    next_steps.append(
        f"Generate first Proof Pack: assay run -c receipt_completeness -- {selected_run}"
    )
    next_steps.append("Verify + explain: assay verify-pack ./proof_pack_*/ && assay explain ./proof_pack_*/ --format md")
    next_steps.append("Lock baseline: assay lock init")
    next_steps.append("Enable CI: assay ci init github --run-command \"" + selected_run + "\"")

    if output_json:
        _output_json({
            "command": "onboard",
            "status": "ok",
            "path": str(root),
            "doctor": None if doctor_report is None else {
                "status": doctor_report.overall_status,
                "summary": doctor_report.summary,
            },
            "scan_summary": summary,
            "top_paths": top_paths,
            "entrypoint": selected_entrypoint,
            "run_command": selected_run,
            "patch_line": patch_line,
            "next_steps": next_steps,
        })

    console.print()
    console.print(Panel.fit(
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
    ))
    console.print()
    console.print("[bold]Next 5 moves:[/]")
    for i, step in enumerate(next_steps, 1):
        console.print(f"  {i}. {step}")
    console.print()


@assay_app.command("patch")
def patch_cmd(
    path: str = typer.Argument(".", help="Directory to scan and patch"),
    entrypoint: Optional[str] = typer.Option(
        None, "--entrypoint", help="File to patch (auto-detected if omitted)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show diff without writing"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply without confirmation"),
    backup: bool = typer.Option(True, "--backup/--no-backup", help="Back up original file before patching"),
    undo: bool = typer.Option(False, "--undo", help="Restore from backup (reverses a previous patch)"),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Auto-insert SDK integration patches into your entrypoint."""
    from pathlib import Path as P

    from assay.patcher import apply_patch, generate_diff, plan_patch, undo_patch
    from assay.scanner import scan_directory

    root = P(path).resolve()
    if not root.exists() or not root.is_dir():
        if output_json:
            _output_json({"command": "patch", "status": "error", "error": f"Directory not found: {path}"})
        console.print(f"[red]Error:[/] Directory not found: {path}")
        raise typer.Exit(3)

    # Undo mode: restore from backup
    if undo:
        if entrypoint is None:
            bak_files = list(root.glob("**/*.assay.bak"))
            if not bak_files:
                if output_json:
                    _output_json({"command": "patch", "status": "error", "error": "No .assay.bak files found"})
                console.print("[red]No .assay.bak files found.[/] Nothing to undo.")
                raise typer.Exit(1)
            # Derive entrypoint from first .bak file
            bak = bak_files[0]
            entrypoint = str(bak.relative_to(root)).replace(".assay.bak", "")
        success = undo_patch(root, entrypoint)
        if output_json:
            _output_json({
                "command": "patch", "action": "undo",
                "status": "ok" if success else "error",
                "entrypoint": entrypoint,
            }, exit_code=0 if success else 1)
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
            _output_json({"command": "patch", "status": "ok", "message": "No uninstrumented call sites found"})
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
        msg = f"Already patched: {', '.join(plan.already_patched)}" if plan.already_patched else "Nothing to patch"
        if output_json:
            _output_json({"command": "patch", "status": "ok", "message": msg, **plan.to_dict()})
        console.print(f"[green]{msg}[/]")
        if plan.langchain_note:
            console.print(f"\n[yellow]Note:[/] {plan.langchain_note}")
        raise typer.Exit(0)

    # Show diff
    diff = generate_diff(plan, root)

    if output_json and dry_run:
        _output_json({
            "command": "patch",
            "status": "dry_run",
            "diff": diff,
            **plan.to_dict(),
        }, exit_code=0)
        # _output_json raises typer.Exit(exit_code)

    if output_json:
        # Apply first, then report
        apply_patch(plan, root, backup=backup)
        _output_json({
            "command": "patch",
            "status": "applied",
            "diff": diff,
            **plan.to_dict(),
        }, exit_code=0)
        # _output_json raises typer.Exit(exit_code)

    console.print(f"\n[bold]Scanning...[/] found {len(uninstrumented)} uninstrumented call sites")
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
    console.print(f"[green]Patched {plan.entrypoint}[/] with {len(plan.lines_to_insert)} integration line(s).")

    # Check if other files still have uninstrumented call sites
    other_files = {f.path for f in uninstrumented if f.path != plan.entrypoint}
    if other_files:
        console.print(f"\n[dim]Note: {len(other_files)} other file(s) have uninstrumented call sites.")
        console.print("  If your app has multiple entrypoints/processes, run assay patch again.[/]")

    console.print(f"\nNext: [bold]assay run -c receipt_completeness -- python {plan.entrypoint}[/]")


@assay_app.command("scan")
def scan_cmd(
    path: str = typer.Argument(".", help="Directory to scan"),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
    ci: bool = typer.Option(False, "--ci", help="CI mode (non-zero exit on uninstrumented sites)"),
    fail_on: str = typer.Option(
        "high", "--fail-on",
        help="Minimum confidence to fail on in CI mode: high, medium, low",
    ),
    include: Optional[str] = typer.Option(
        None, "--include",
        help="Comma-separated glob patterns to include (e.g. 'src/**/*.py')",
    ),
    exclude: Optional[str] = typer.Option(
        None, "--exclude",
        help="Comma-separated glob patterns to exclude (e.g. 'tests/**')",
    ),
    report: bool = typer.Option(
        False, "--report",
        help="Generate a self-contained HTML evidence gap report",
    ),
    report_path: Optional[str] = typer.Option(
        None, "--report-path",
        help="Output path for HTML report (default: evidence_gap_report.html)",
    ),
    emit_contract: Optional[str] = typer.Option(
        None, "--emit-contract",
        help="Write a coverage contract JSON file from scan results. "
             "LangChain/LiteLLM sites are excluded by default (no runtime callsite_id support).",
    ),
    include_low: bool = typer.Option(
        False, "--include-low",
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

    include_pats = [p.strip() for p in include.split(",") if p.strip()] if include else None
    exclude_pats = [p.strip() for p in exclude.split(",") if p.strip()] if exclude else None

    try:
        result = scan_directory(P(path), include=include_pats, exclude=exclude_pats)
    except Exception as e:
        if output_json:
            _output_json({"tool": "assay-scan", "status": "error", "error": str(e)}, exit_code=2)
        else:
            console.print(f"[red]Scan error:[/] {e}")
        raise typer.Exit(2)

    # Emit coverage contract if requested
    if emit_contract:
        from assay.coverage import CoverageContract

        try:
            contract = CoverageContract.from_scan_result(
                result, include_low=include_low, project_root=str(P(path).resolve()),
            )
            # Count excluded framework sites for user visibility
            full_contract = CoverageContract.from_scan_result(
                result, include_low=include_low, include_all_frameworks=True,
                project_root=str(P(path).resolve()),
            )
            n_excluded = len(full_contract.call_sites) - len(contract.call_sites)

            contract_path = P(emit_contract)
            contract.write(contract_path)
            if not output_json:
                n = len(contract.call_sites)
                exc_note = f", {n_excluded} excluded (LangChain/LiteLLM)" if n_excluded else ""
                console.print(
                    f"  [bold green]Coverage contract written:[/] {contract_path} "
                    f"({n} site{'s' if n != 1 else ''}{exc_note})"
                )
                console.print()
        except Exception as e:
            if output_json:
                _output_json({"tool": "assay-scan", "status": "error", "error": f"contract emission failed: {e}"}, exit_code=2)
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
                _output_json({"tool": "assay-scan", "status": "error", "error": f"report generation failed: {e}"}, exit_code=2)
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
            threshold = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}.get(fail_on, Confidence.HIGH)
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
        console.print("    1. If you use wrappers, add manual receipt emission near your model call:")
        console.print("       from assay import emit_receipt")
        console.print("       emit_receipt('model_call', {'provider': '...', 'model_id': '...'})")
        console.print("    2. Run a first pack anyway:")
        console.print("       assay run --allow-empty -- python your_app.py")
        console.print("    3. Verify + demo confidence model:")
        console.print("       assay verify-pack ./proof_pack_*/")
        console.print("       assay demo-incident")
        console.print()
        raise typer.Exit(0)

    # Header
    console.print(f"  [bold]Found {s['sites_total']} LLM call site{'s' if s['sites_total'] != 1 else ''}:[/]")
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
        console.print(f"  {conf} {finding.path}:{finding.line:<6} {finding.call:<45} {status}")

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
        threshold = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}.get(fail_on, Confidence.HIGH)
        if threshold == Confidence.HIGH and s["high"] > 0:
            raise typer.Exit(1)
        elif threshold == Confidence.MEDIUM and (s["high"] + s["medium"]) > 0:
            raise typer.Exit(1)
        elif threshold == Confidence.LOW and s["uninstrumented"] > 0:
            raise typer.Exit(1)

    raise typer.Exit(0)


@assay_app.command("doctor")
def doctor_cmd(
    profile: str = typer.Option(
        "local", "--profile", "-p",
        help="Check profile: local, ci, release, ledger",
    ),
    pack: Optional[str] = typer.Option(
        None, "--pack",
        help="Path to Proof Pack directory to check",
    ),
    lock: Optional[str] = typer.Option(
        None, "--lock",
        help="Path to lockfile to check",
    ),
    strict: bool = typer.Option(
        False, "--strict",
        help="Treat warnings as failures",
    ),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
    fix: bool = typer.Option(
        False, "--fix",
        help="Apply safe automatic fixes (generate key, write lockfile)",
    ),
):
    """Check if Assay is installed, configured, and ready to use.

    Answers four questions in under 2 seconds:
    1. Is Assay installed and runnable here?
    2. Can this machine create and verify packs?
    3. Is this repo configured for your claimed workflow?
    4. What is the single next command to become "green"?
    """
    from pathlib import Path

    from assay.doctor import Profile, CheckStatus, run_doctor

    # Parse profile
    try:
        prof = Profile(profile.lower())
    except ValueError:
        console.print(f"[red]Error:[/] Unknown profile '{profile}'. Use: local, ci, release, ledger")
        raise typer.Exit(3)

    pack_dir = Path(pack) if pack else None
    lock_path = Path(lock) if lock else None

    # Run checks
    report = run_doctor(prof, pack_dir=pack_dir, lock_path=lock_path, strict=strict)

    # Apply fixes if requested
    if fix:
        for check in report.checks:
            if check.status in (CheckStatus.WARN, CheckStatus.FAIL) and check.fix:
                if check.id == "DOCTOR_KEY_001" and check.status == CheckStatus.WARN:
                    try:
                        from assay.keystore import DEFAULT_SIGNER_ID, get_default_keystore
                        ks = get_default_keystore()
                        ks.generate_key(DEFAULT_SIGNER_ID)
                        check.status = CheckStatus.PASS
                        check.message += " (fixed: key generated)"
                        if not output_json:
                            console.print(f"  [green]Fixed:[/] Generated signing key")
                    except Exception as e:
                        if not output_json:
                            console.print(f"  [red]Fix failed:[/] {e}")

                elif check.id == "DOCTOR_LOCK_001" and check.status in (CheckStatus.WARN, CheckStatus.FAIL):
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
        _output_json(report.to_dict(), exit_code=report.exit_code_strict() if strict else report.exit_code)
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


@assay_app.command("explain")
def explain_cmd(
    pack_dir: str = typer.Argument(..., help="Path to proof pack directory"),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text, md, json"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON (same as --format json)"),
):
    """Explain a proof pack in plain English.

    Reads a proof pack and outputs a human-readable summary covering:
    what happened, integrity status, claim results, what the pack proves,
    and what it does NOT prove.

    Designed for non-engineers: compliance officers, auditors, executives.

    Examples:
      assay explain ./proof_pack_*/
      assay explain ./proof_pack_*/ --format md
      assay explain ./proof_pack_abc123/ --json
    """
    from pathlib import Path

    from assay.explain import explain_pack, render_md, render_text

    pd = Path(pack_dir)
    if not pd.is_dir():
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(1)

    info = explain_pack(pd)

    if output_json or output_format == "json":
        _output_json({
            "command": "explain",
            "status": "ok",
            **info,
        })
        return

    if output_format == "md":
        console.print(render_md(info))
        return

    console.print()
    console.print(render_text(info))


@assay_app.command("demo-incident")
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
    from assay.explain import explain_pack, render_text
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
            _output_json({
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
            })

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
        console.print(f"  3 receipts: 2 model_call (gpt-4) + 1 guardian_verdict")
        console.print()
        console.print(Panel.fit(
            f"Integrity:  [green]{att_good['receipt_integrity']}[/]\n"
            f"Claims:     [green]{att_good['claim_check']}[/]\n"
            f"  has_model_calls:    [green]PASS[/]\n"
            f"  guardian_enforced:  [green]PASS[/]\n"
            f"  no_breakglass:     [green]PASS[/]",
            title="Act 1: PASS / PASS",
            border_style="green",
        ))

        console.print()
        console.print("[bold]ACT 2: Someone cuts corners[/]")
        console.print("  Model swapped to gpt-3.5-turbo (cheaper, less capable).")
        console.print("  Guardian check removed entirely.")
        console.print(f"  2 receipts: 2 model_call (gpt-3.5-turbo), no guardian_verdict")
        console.print()
        console.print(Panel.fit(
            f"Integrity:  [green]{att_bad['receipt_integrity']}[/]  (evidence is authentic)\n"
            f"Claims:     [red]{att_bad['claim_check']}[/]  (policy violated)\n"
            f"  has_model_calls:    [green]PASS[/]\n"
            f"  guardian_enforced:  [red]FAIL[/]  -- no guardian_verdict receipt\n"
            f"  no_breakglass:     [green]PASS[/]",
            title="Act 2: PASS / FAIL",
            border_style="red",
        ))

        console.print()
        console.print("[bold]THE EVIDENCE[/]")
        console.print()
        console.print("  Act 1 receipts show: gpt-4, guardian approved")
        console.print("  Act 2 receipts show: gpt-3.5-turbo, no guardian")
        console.print()
        console.print("  The model was swapped. The guardian was removed.")
        console.print("  The evidence is cryptographic. Nobody can argue about what happened.")
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


@assay_app.command("quickstart")
def quickstart_cmd(
    path: str = typer.Argument(".", help="Project directory to explore"),
    skip_demo: bool = typer.Option(False, "--skip-demo", help="Skip demo-challenge generation"),
    output_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
    force: bool = typer.Option(False, "--force", help="Bypass the large-directory guard"),
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
            _output_json({"command": "quickstart", "status": "error", "error": f"Directory not found: {path}"}, exit_code=3)
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
            _output_json({"command": "quickstart", "status": "error", "error": msg}, exit_code=3)
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
                _output_json({"command": "quickstart", "status": "error", "error": msg}, exit_code=3)
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
                    {"receipt_id": "r_chal_001", "type": "model_call",
                     "timestamp": f"{ts_base}0Z", "schema_version": "3.0", "seq": 0,
                     "model_id": "gpt-4", "provider": "openai",
                     "total_tokens": 2500, "input_tokens": 1800, "output_tokens": 700,
                     "latency_ms": 1100, "finish_reason": "stop"},
                    {"receipt_id": "r_chal_002", "type": "guardian_verdict",
                     "timestamp": f"{ts_base}1Z", "schema_version": "3.0", "seq": 1,
                     "verdict": "allow", "action": "generate_summary",
                     "reason": "Content is within policy bounds"},
                ]
                claims = [
                    ClaimSpec(claim_id="has_model_calls", description="At least one model_call receipt",
                              check="receipt_type_present", params={"receipt_type": "model_call"}),
                ]

                pack = ProofPack(run_id="quickstart-run", entries=receipts,
                                 signer_id="challenge", claims=claims, mode="shadow")
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
                    data[idx + 1:idx + 6] = b"gpt-5"
                receipt_file.write_bytes(bytes(data))

            _print(f"  [green]Created[/] {demo_dir}/ (good + tampered packs)")
            results["steps"].append({"step": "demo", "status": "ok", "dir": str(demo_dir)})
            next_steps.append(f"Verify good pack:     assay verify-pack {demo_dir}/good/")
            next_steps.append(f"Verify tampered pack: assay verify-pack {demo_dir}/tampered/")
        except Exception as e:
            _print(f"  [yellow]Skipped:[/] {e}")
            results["steps"].append({"step": "demo", "status": "skipped", "error": str(e)})
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
        _print(f"  Found {s['sites_total']} call site(s): "
               f"[green]{s['instrumented']} instrumented[/], "
               f"[{'red' if uninstrumented else 'green'}]{uninstrumented} uninstrumented[/]")

        results["steps"].append({
            "step": "scan", "status": "ok",
            "sites_total": s["sites_total"],
            "instrumented": s["instrumented"],
            "uninstrumented": uninstrumented,
        })

        # Generate report if there are findings (skip in JSON mode)
        if scan_result.findings and not output_json:
            from assay.reporting.evidence_gap import build_report, render_html, write_report
            report_file = root / "assay_quickstart_report.html"
            gap_report = build_report(scan_result.to_dict(), root)
            html = render_html(gap_report)
            write_report(html, report_file)
            _print(f"  [green]Report:[/] {report_file}")
            results["steps"][-1]["report"] = str(report_file)

        if uninstrumented > 0:
            next_steps.append(f"Patch entrypoint:     assay patch {path}")
        next_steps.append(f"Run with receipts:    assay run -c receipt_completeness -- python your_app.py")
        next_steps.append(f"Lock baseline:        assay lock init")
        next_steps.append(f"Enable CI:            assay ci init github")

    except Exception as e:
        _print(f"  [yellow]Scan error:[/] {e}")
        results["steps"].append({"step": "scan", "status": "error", "error": str(e)})

    # Step 3: Next steps
    _print()
    scan_cmd = f"assay scan {path} --report"
    if not next_steps:
        _print("[dim]No AI call sites found.[/] Add SDK integrations and re-scan:")
        _print()
        _print(f"  pip install assay-ai[openai]")
        _print(f"  # Add to your entrypoint:")
        _print(f"  # from assay.integrations.openai import patch; patch()")
        _print()
        _print(f"  Then re-run: [bold]{scan_cmd}[/]")
        results["next_steps"] = [f"Install SDK: pip install assay-ai[openai]", f"Re-scan: {scan_cmd}"]
    else:
        next_steps.insert(0, f"View gap report:      {scan_cmd}")
        _print("[bold]Next steps:[/]")
        _print()
        for i, step in enumerate(next_steps, 1):
            _print(f"  {i}. {step}")
        results["next_steps"] = next_steps
    _print()

    if output_json:
        results["status"] = "ok"
        _output_json(results, exit_code=0)


@assay_app.command("demo-challenge")
def demo_challenge_cmd(
    output_dir: str = typer.Option("./challenge_pack", "--output", "-o", help="Output directory"),
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
            data[idx + 1:idx + 6] = b"gpt-5"
        receipt_file.write_bytes(bytes(data))

    # Generate SHA256 sums
    sha_lines = []
    for subdir in ["good", "tampered"]:
        for f in sorted((out / subdir).iterdir()):
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
        "pip install assay-ai\n"
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
        _output_json({
            "command": "demo-challenge",
            "status": "ok",
            "output_dir": str(out),
            "good_pack": str(good_out),
            "tampered_pack": str(tampered_out),
            "good_result": "PASS" if good_result.passed else "FAIL",
            "tampered_result": "PASS" if tampered_result.passed else "FAIL",
        })

    console.print()
    console.print("[bold]ASSAY CHALLENGE PACK[/]")
    console.print()
    console.print(f"  Created two proof packs. One is authentic. One has been tampered with.")
    console.print(f"  One byte changed in the receipts. Can your machine tell?")
    console.print()

    # Good pack result
    console.print(Panel.fit(
        f"[bold green]VERIFICATION PASSED[/]\n\n"
        f"Pack ID:    {good_att['pack_id']}\n"
        f"Integrity:  [green]PASS[/]\n"
        f"Claims:     [green]PASS[/]\n"
        f"Receipts:   {good_att['n_receipts']}\n"
        f"Head Hash:  {good_att.get('head_hash', 'N/A')[:16]}...\n"
        f"Signature:  Ed25519 [green]valid[/]",
        title=f"good/ -- assay verify-pack {good_out}/",
        border_style="green",
    ))
    console.print()

    # Tampered pack result
    err_msg = tampered_result.errors[0].message if tampered_result.errors else "unknown error"
    console.print(Panel.fit(
        f"[bold red]VERIFICATION FAILED[/]\n\n"
        f"Pack ID:    {good_att['pack_id']}\n"
        f"Integrity:  [red]FAIL[/]\n"
        f"Error:      [red]{err_msg}[/]",
        title=f"tampered/ -- assay verify-pack {tampered_out}/",
        border_style="red",
    ))

    console.print()
    console.print("  [bold]What happened:[/]")
    console.print("  The tampered pack changed [bold]\"gpt-4\"[/] to [bold]\"gpt-5\"[/] in the receipts.")
    console.print("  The manifest hash no longer matches. Verification fails.")
    console.print("  No server access needed. No trust required. Just math.")
    console.print()
    console.print("  [dim]To dig deeper:[/]")
    console.print(f"    assay explain {good_out}/")
    console.print(f"    assay explain {tampered_out}/")
    console.print()


@assay_app.command("analyze")
def analyze_cmd(
    pack_dir: Optional[str] = typer.Argument(None, help="Path to proof pack directory"),
    history: bool = typer.Option(False, "--history", help="Analyze local trace history instead of a pack"),
    since: int = typer.Option(7, "--since", help="Days of history to analyze (with --history)"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Analyze receipts for cost, latency, and error breakdowns.

    Reads model_call receipts from a proof pack or local trace history
    and computes token usage, estimated cost, latency percentiles,
    error rates, and per-model/per-provider breakdowns.

    Pricing estimates are approximate.

    Examples:
      assay analyze ./proof_pack_*/
      assay analyze --history
      assay analyze --history --since 30
      assay analyze ./proof_pack_*/ --json
    """
    from pathlib import Path

    from assay.analyze import (
        AnalysisResult,
        analyze_receipts,
        load_history_receipts,
        load_pack_receipts,
    )

    if not pack_dir and not history:
        console.print("[red]Error:[/] Provide a pack directory or use --history")
        raise typer.Exit(3)

    if pack_dir and history:
        console.print("[red]Error:[/] Provide either a pack directory or --history, not both")
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
                integrity = str(att.get("receipt_integrity") or att.get("integrity") or "").upper()
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

    if output_json:
        _output_json({"command": "analyze", "status": "ok", **result.to_dict()}, exit_code=0)
        return

    # Rich table output
    _render_analysis(result)


def _render_analysis(result) -> None:
    """Render analysis result to console with Rich tables."""
    console.print()

    if result.model_calls == 0:
        console.print("[yellow]No model_call receipts found.[/]")
        if result.total_receipts > 0:
            console.print(f"  ({result.total_receipts} total receipts, but none were model_call type)")
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
            model_table.add_row(model_id, str(b["calls"]), f"{b['total_tokens']:,}", f"${b['cost_usd']:.4f}", err_str)
        console.print(Panel(model_table, title="By Model", border_style="green"))

    # By provider
    if len(result.by_provider) > 1:
        prov_table = Table(box=None, padding=(0, 1))
        prov_table.add_column("Provider", style="bold")
        prov_table.add_column("Calls", justify="right")
        prov_table.add_column("Tokens", justify="right")
        prov_table.add_column("Cost", justify="right")
        for prov, b in sorted(result.by_provider.items()):
            prov_table.add_row(prov, str(b["calls"]), f"{b['total_tokens']:,}", f"${b['cost_usd']:.4f}")
        console.print(Panel(prov_table, title="By Provider", border_style="magenta"))

    # Finish reasons
    if result.finish_reasons:
        fr_parts = [f"{reason}: {count}" for reason, count in sorted(result.finish_reasons.items(), key=lambda x: str(x[0]))]
        console.print(f"  [dim]Finish reasons:[/] {', '.join(fr_parts)}")

    console.print()
    raise typer.Exit(0)


@assay_app.command("diff")
def diff_cmd(
    pack_a: str = typer.Argument(..., help="Baseline pack directory (or current pack with --against-previous)"),
    pack_b: Optional[str] = typer.Argument(None, help="Current pack directory"),
    against_previous: bool = typer.Option(False, "--against-previous", help="Auto-find baseline pack from same directory"),
    why: bool = typer.Option(False, "--why", help="Explain regressions with receipt-level detail"),
    report: Optional[str] = typer.Option(None, "--report", help="Write a self-contained diff report (.html or .json)"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip integrity verification"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    gate_cost_pct: float = typer.Option(None, "--gate-cost-pct", help="Max allowed cost increase (percent, e.g. 20)"),
    gate_p95_pct: float = typer.Option(None, "--gate-p95-pct", help="Max allowed p95 latency increase (percent)"),
    gate_errors: int = typer.Option(None, "--gate-errors", help="Max allowed error count in pack B"),
    gate_strict: bool = typer.Option(False, "--gate-strict", help="Fail gates when data is missing (instead of skip)"),
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

    from assay.diff import diff_packs, evaluate_gates, explain_why, find_previous_pack, load_baseline

    # Resolve pack paths
    if against_previous:
        if pack_b is not None:
            console.print("[red]Error:[/] --against-previous takes one pack argument, not two")
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
            console.print("[red]Error:[/] Two pack arguments required (or use --against-previous)")
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
    has_gates = gate_cost_pct is not None or gate_p95_pct is not None or gate_errors is not None
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
            write_json as write_diff_report_json,
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
                _output_json({"command": "diff", "status": "error", "error": f"report generation failed: {e}"}, exit_code=3)
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

    _render_diff(result, gate_eval=gate_eval, exit_code=exit_code, why_results=why_results)


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


def _render_diff(result, *, gate_eval=None, exit_code: int | None = None, why_results=None) -> None:
    """Render diff result to console with Rich panels."""
    from assay.diff import DiffResult

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
    console.print(f"[bold]assay diff[/]")
    console.print()
    console.print(f"  Pack A: {a.path}  ({a.n_receipts} receipts, {a.timestamp_start[:10] if a.timestamp_start else '?'})")
    console.print(f"  Pack B: {b.path}  ({b.n_receipts} receipts, {b.timestamp_start[:10] if b.timestamp_start else '?'})")

    # Warnings
    if result.signer_changed:
        console.print(f"  [yellow]Signer changed:[/] {a.signer_id} -> {b.signer_id}")
    if result.version_changed:
        console.print(f"  [yellow]Verifier version changed:[/] {a.verifier_version} -> {b.verifier_version}")
    if not result.same_claim_set:
        console.print(f"  [yellow]Claim sets differ[/] (different cards or card versions)")
    console.print()

    # Claims
    if result.claim_deltas:
        claims_table = Table(show_header=False, box=None, padding=(0, 2))
        claims_table.add_column("claim")
        claims_table.add_column("change")
        for cd in result.claim_deltas:
            a_str = "[green]PASS[/]" if cd.a_passed else ("[red]FAIL[/]" if cd.a_passed is False else "[dim]--[/]")
            b_str = "[green]PASS[/]" if cd.b_passed else ("[red]FAIL[/]" if cd.b_passed is False else "[dim]--[/]")
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

        summary.add_row("Model calls", str(aa.model_calls), "->", str(ba.model_calls),
                         _fmt_delta(aa.model_calls, ba.model_calls))
        summary.add_row("Total tokens", f"{aa.total_tokens:,}", "->", f"{ba.total_tokens:,}",
                         _fmt_delta(aa.total_tokens, ba.total_tokens))
        summary.add_row("Est. cost", f"${aa.cost_usd:.4f}", "->", f"${ba.cost_usd:.4f}",
                         _fmt_delta(aa.cost_usd, ba.cost_usd, fmt="cost"))

        err_color_a = "[red]" if aa.errors else ""
        err_color_b = "[red]" if ba.errors else ""
        err_end_a = "[/]" if aa.errors else ""
        err_end_b = "[/]" if ba.errors else ""
        summary.add_row("Errors",
                         f"{err_color_a}{aa.errors}{err_end_a}", "->",
                         f"{err_color_b}{ba.errors}{err_end_b}",
                         _fmt_delta(aa.errors, ba.errors))

        if aa.latencies and ba.latencies:
            summary.add_row("Latency p50", f"{aa.latency_p50}ms", "->", f"{ba.latency_p50}ms",
                             _fmt_delta(aa.latency_p50 or 0, ba.latency_p50 or 0, fmt="ms"))
            summary.add_row("Latency p95", f"{aa.latency_p95}ms", "->", f"{ba.latency_p95}ms",
                             _fmt_delta(aa.latency_p95 or 0, ba.latency_p95 or 0, fmt="ms"))

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
                    gate_table.add_row(g.name, "[red]FAIL[/]  [dim]missing data (strict mode)[/]")
            elif g.passed:
                actual_str = f"{g.actual:.1f}%" if g.unit == "pct" and g.actual is not None else str(int(g.actual)) if g.actual is not None else "?"
                gate_table.add_row(g.name, f"[green]PASS[/]  {actual_str} <= {_fmt_threshold(g.threshold, g.unit)}")
            else:
                actual_str = f"{g.actual:.1f}%" if g.unit == "pct" and g.actual is not None else str(int(g.actual)) if g.actual is not None else "inf"
                gate_table.add_row(g.name, f"[red]FAIL[/]  {actual_str} > {_fmt_threshold(g.threshold, g.unit)}")

        n_passed = sum(1 for g in gate_eval.results if g.passed and not g.skipped)
        n_failed = sum(1 for g in gate_eval.results if not g.passed)
        n_skipped = sum(1 for g in gate_eval.results if g.passed and g.skipped)
        gate_table.add_row("", f"[dim]{n_passed} passed, {n_failed} failed, {n_skipped} skipped[/]")

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

        console.print(Panel(
            "\n".join(why_lines).rstrip(),
            title="Why (receipt-level forensics)",
            border_style="yellow",
        ))

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
assay_app.add_typer(mcp_app, name="mcp")

mcp_policy_app = typer.Typer(
    help="MCP policy file management.",
    no_args_is_help=True,
)
mcp_app.add_typer(mcp_policy_app, name="policy")


@mcp_policy_app.command("init")
def mcp_policy_init_cmd(
    output: str = typer.Option("assay.mcp-policy.yaml", "-o", "--output", help="Output file path"),
    server_id: Optional[str] = typer.Option(None, "--server-id", help="Server identifier to pre-fill"),
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
            _output_json({
                "command": "mcp policy init",
                "status": "error",
                "error": f"File already exists: {output}",
                "fix": f"assay mcp policy init --force",
            }, exit_code=1)
        console.print(f"[red]Error:[/] {output} already exists. Use --force to overwrite.")
        raise typer.Exit(1)

    sid = server_id or "my-server"
    policy_content = f"""\
# Assay MCP Policy
# Generated by: assay mcp policy init
# Docs: https://github.com/Haserjian/assay
#
# This file configures the Assay MCP proxy for tool-call auditing.
# Pass it to the proxy with:
#   assay mcp-proxy --policy assay.mcp-policy.yaml -- python my_server.py

# Server identification
server_id: "{sid}"

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
# Uncomment to restrict which tools are audited or allowed.
#
# tools:
#   # Only audit these tools (others are forwarded without receipts).
#   # Omit this section to audit ALL tools.
#   audit_only:
#     - "search"
#     - "execute_query"
#
#   # Deny list: block these tools entirely (proxy returns an error).
#   # Use for tools that should never run in this environment.
#   deny:
#     - "delete_database"
#     - "send_email"

# Budget thresholds (optional, not enforced in v0)
# These values are recorded in receipts for downstream gates.
#
# budget:
#   max_tool_calls: 100          # per session
#   max_wall_time_sec: 300       # per session
"""

    out_path.write_text(policy_content, encoding="utf-8")

    if output_json:
        _output_json({
            "command": "mcp policy init",
            "status": "ok",
            "output": str(out_path),
            "server_id": sid,
        })

    console.print()
    console.print(Panel.fit(
        f"[bold green]MCP policy file created[/]\n\n"
        f"File:       {out_path}\n"
        f"Server ID:  {sid}\n"
        f"Privacy:    args hashed, results hashed (default)\n"
        f"Auto-pack:  enabled",
        title="assay mcp policy init",
    ))
    console.print()
    console.print("Next:")
    console.print(f"  1. Edit [bold]{out_path}[/] to customize tool restrictions")
    console.print(f"  2. Start proxy: [bold]assay mcp-proxy -- python my_server.py[/]")
    console.print()


@assay_app.command("mcp-proxy", context_settings={"allow_extra_args": True, "allow_interspersed_args": False})
def mcp_proxy_cmd(
    ctx: typer.Context,
    audit_dir: str = typer.Option(".assay/mcp", "--audit-dir", help="Directory for receipts and packs"),
    server_id: Optional[str] = typer.Option(None, "--server-id", help="Server identifier for receipts"),
    store_args: bool = typer.Option(False, "--store-args", help="Store tool arguments in cleartext (default: hash-only)"),
    store_results: bool = typer.Option(False, "--store-results", help="Store tool results in cleartext (default: hash-only)"),
    no_auto_pack: bool = typer.Option(False, "--no-auto-pack", help="Disable auto-pack on session end"),
    output_json: bool = typer.Option(False, "--json", help="JSON output for status messages"),
):
    """MCP Notary Proxy: receipt every tool call.

    Transparent stdio proxy between an MCP client and server.
    Intercepts tools/call requests, emits MCPToolCallReceipt per
    invocation, and auto-builds a proof pack on session end.

    Usage:

        assay mcp-proxy -- python my_server.py

    In your MCP client config (e.g. claude_desktop_config.json):

        {"command": "assay", "args": ["mcp-proxy", "--", "python", "my_server.py"]}
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
            "  2. Claude Desktop config: [bold]{\"command\": \"assay\", \"args\": [\"mcp-proxy\", \"--\", \"python\", \"my_server.py\"]}[/]\n"
            "  3. Keep the [bold]--[/] separator before the upstream command."
        )
        raise typer.Exit(3)

    exit_code = run_proxy(
        upstream_cmd,
        audit_dir=audit_dir,
        server_id=server_id,
        store_args=store_args,
        store_results=store_results,
        auto_pack=not no_auto_pack,
        json_output=output_json,
    )
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# audit subcommands -- auditor handoff tools
# ---------------------------------------------------------------------------

_VERIFY_INSTRUCTIONS_MD = """\
# How to Verify This Evidence Bundle

## Prerequisites

```bash
pip install assay-ai
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
assay_app.add_typer(audit_app, name="audit")


@audit_app.command("bundle")
def audit_bundle_cmd(
    pack_dir: str = typer.Argument(..., help="Path to Proof Pack directory"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
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
    from assay.integrity import verify_pack_manifest
    from assay.keystore import get_default_keystore

    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack_manifest.json"

    if not pack_path.is_dir():
        if output_json:
            _output_json({"command": "audit bundle", "status": "error", "error": f"Not a directory: {pack_dir}"}, exit_code=3)
        console.print(f"[red]Error:[/] {pack_dir} is not a directory")
        raise typer.Exit(3)

    if not manifest_path.exists():
        if output_json:
            _output_json({"command": "audit bundle", "status": "error", "error": "pack_manifest.json not found"}, exit_code=3)
        console.print(f"[red]Error:[/] {manifest_path} not found")
        raise typer.Exit(3)

    manifest = json.loads(manifest_path.read_text())

    # Verify before bundling -- refuse to bundle tampered evidence
    ks = get_default_keystore()
    vr = verify_pack_manifest(manifest, pack_path, ks)
    if not vr.passed:
        if output_json:
            _output_json({
                "command": "audit bundle", "status": "error",
                "error": "verification_failed",
                "details": vr.to_dict(),
            }, exit_code=3)
        console.print("[red]Error:[/] Pack verification failed. Cannot bundle tampered evidence.")
        for err in vr.errors:
            console.print(f"  [red]{err.code}[/]: {err.message}")
        raise typer.Exit(3)

    pack_id = manifest.get("pack_id", "unknown")
    out_path = Path(output) if output else Path(f"audit_bundle_{pack_id}.tar.gz")

    # Build supplementary files
    signer_info_bytes = json.dumps({
        "signer_id": manifest.get("signer_id", "unknown"),
        "signer_pubkey": manifest.get("signer_pubkey"),
        "signer_pubkey_sha256": manifest.get("signer_pubkey_sha256"),
        "signature_alg": manifest.get("signature_alg", "ed25519"),
    }, indent=2).encode("utf-8")

    try:
        info = explain_pack(pack_path)
        summary_bytes = render_md(info).encode("utf-8")
    except Exception:
        summary_bytes = b"# Pack Summary\n\nCould not generate summary.\n"

    instructions_bytes = _VERIFY_INSTRUCTIONS_MD.encode("utf-8")

    verify_result_bytes = json.dumps({
        "verified_at_bundle_time": True,
        **vr.to_dict(),
    }, indent=2).encode("utf-8")

    # Generated file names to skip from pack dir (we supply fresh versions)
    generated_names = {"SIGNER_INFO.json", "PACK_SUMMARY.md", "VERIFY_INSTRUCTIONS.md", "VERIFY_RESULT.json"}

    with tarfile.open(str(out_path), "w:gz") as tar:
        for file_path in sorted(pack_path.iterdir()):
            if file_path.is_file() and file_path.name not in generated_names:
                tar.add(str(file_path), arcname=file_path.name)

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
    file_count = sum(1 for f in pack_path.iterdir() if f.is_file() and f.name not in generated_names) + len(generated_names)

    if output_json:
        _output_json({
            "command": "audit bundle",
            "status": "ok",
            "pack_id": pack_id,
            "bundle_path": str(out_path),
            "bundle_bytes": bundle_size,
            "file_count": file_count,
            "signer_id": manifest.get("signer_id"),
            "verification_passed": True,
        }, exit_code=0)

    console.print()
    from rich.panel import Panel
    console.print(Panel.fit(
        f"[bold green]AUDIT BUNDLE CREATED[/]\n\n"
        f"Pack ID:    {pack_id}\n"
        f"Signer:     {manifest.get('signer_id')}\n"
        f"Files:      {file_count}\n"
        f"Size:       {bundle_size:,} bytes\n"
        f"Output:     {out_path}",
        title="assay audit bundle",
    ))
    console.print()
    console.print(f"[dim]Hand off [bold]{out_path}[/bold] to the auditor.[/]")
    console.print(f"[dim]Auditor verifies with:[/] pip install assay-ai && tar xzf {out_path.name} && assay verify-pack .")
    console.print()


# ---------------------------------------------------------------------------
# flow subcommands -- executable guided workflows
# ---------------------------------------------------------------------------

flow_app = typer.Typer(
    name="flow",
    help="Executable guided workflows (no more copy-paste)",
    no_args_is_help=True,
)
assay_app.add_typer(flow_app, name="flow")


@flow_app.command("try")
def flow_try_cmd(
    apply: bool = typer.Option(False, "--apply", help="Execute steps (default: dry-run)"),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """See Assay in action: demo packs + verify."""
    from assay.flow import build_flow_try, render_flow_dry_run, render_flow_result, run_flow

    flow = build_flow_try()
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json({"command": "flow try", **result.to_dict()}, exit_code=1 if result.failed_step else 0)
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
        "python app.py", "--run-command",
        help="Command to wrap with assay run",
    ),
    apply: bool = typer.Option(False, "--apply", help="Execute steps (default: dry-run)"),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Instrument your project: scan -> patch -> run -> verify -> explain."""
    from assay.flow import build_flow_adopt, render_flow_dry_run, render_flow_result, run_flow

    flow = build_flow_adopt(run_command=run_command, path=path)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json({"command": "flow adopt", **result.to_dict()}, exit_code=1 if result.failed_step else 0)
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("ci")
def flow_ci_cmd(
    run_command: str = typer.Option(
        "python app.py", "--run-command",
        help="Command Assay should wrap in CI",
    ),
    apply: bool = typer.Option(False, "--apply", help="Execute steps (default: dry-run)"),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Set up CI evidence gating: lock -> ci init -> baseline."""
    from assay.flow import build_flow_ci, render_flow_dry_run, render_flow_result, run_flow

    flow = build_flow_ci(run_command=run_command)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json({"command": "flow ci", **result.to_dict()}, exit_code=1 if result.failed_step else 0)
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("mcp")
def flow_mcp_cmd(
    server_command: Optional[str] = typer.Option(
        None, "--server-command",
        help="MCP server startup command",
    ),
    apply: bool = typer.Option(False, "--apply", help="Execute steps (default: dry-run)"),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Set up MCP tool call auditing: policy init + proxy guidance."""
    from assay.flow import build_flow_mcp, render_flow_dry_run, render_flow_result, run_flow

    flow = build_flow_mcp(server_command=server_command)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json({"command": "flow mcp", **result.to_dict()}, exit_code=1 if result.failed_step else 0)
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


@flow_app.command("audit")
def flow_audit_cmd(
    pack_dir: str = typer.Argument("./proof_pack_*/", help="Path to proof pack directory"),
    apply: bool = typer.Option(False, "--apply", help="Execute steps (default: dry-run)"),
    output_json: bool = typer.Option(False, "--json", help="Structured output"),
):
    """Auditor handoff: verify -> explain -> bundle."""
    from assay.flow import build_flow_audit, render_flow_dry_run, render_flow_result, run_flow

    flow = build_flow_audit(pack_dir=pack_dir)
    result = run_flow(flow, apply=apply, json_mode=output_json)

    if output_json:
        _output_json({"command": "flow audit", **result.to_dict()}, exit_code=1 if result.failed_step else 0)
    elif apply:
        render_flow_result(result, console)
    else:
        render_flow_dry_run(flow, console)

    if result.failed_step is not None:
        raise typer.Exit(1)


def main():
    """Entrypoint for assay CLI."""
    assay_app()


__all__ = ["assay_app", "main"]
