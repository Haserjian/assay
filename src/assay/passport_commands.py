"""Passport CLI commands.

Typer group registered via assay_app.add_typer(passport_app, name="passport")
in commands.py.

Commands:
  assay passport show      — Rich terminal summary
  assay passport verify    — Signature + lifecycle verification
  assay passport sign      — Sign a passport with Ed25519
  assay passport render    — Render HTML visual
  assay passport xray      — Structural diagnostic + grading
  assay passport mint      — Mint draft from proof pack
  assay passport challenge — Issue a challenge receipt
  assay passport supersede — Link old → new passport
  assay passport revoke    — Revoke a passport
  assay passport diff      — Compare two passports
  assay passport demo      — Full lifecycle demo
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

passport_app = typer.Typer(
    name="passport",
    help="Passport lifecycle: sign, verify, render, diagnose, challenge, supersede, diff.",
    no_args_is_help=True,
)


def _output_json(data: dict, exit_code: int = 0) -> None:
    """Print JSON and exit."""
    console.print_json(json.dumps(data, default=str))
    raise typer.Exit(exit_code)


def _display_path(path: Path) -> str:
    """Return a user-facing path string."""
    return str(path)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@passport_app.command("show")
def passport_show_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Display a Rich terminal summary of a passport.

    Shows subject, state, reliance class, claims, and coverage at a glance.
    """
    path = Path(passport_file)
    if not path.exists():
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/] Malformed JSON: {exc}")
        raise typer.Exit(3)

    if output_json:
        _output_json({"command": "passport show", "status": "ok", "passport": data})

    # Subject
    subject = data.get("subject", {})
    status = data.get("status", {})
    reliance = data.get("reliance", {})
    trust = data.get("trust_posture", {})
    coverage = data.get("coverage", {})
    claims = data.get("claims", [])

    state = status.get("state", "UNKNOWN")
    state_colors = {
        "FRESH": "green", "STALE": "yellow", "CHALLENGED": "yellow",
        "SUPERSEDED": "dim", "REVOKED": "red",
    }
    state_color = state_colors.get(state, "white")

    # Header panel
    console.print(Panel.fit(
        f"[bold]{subject.get('name', 'Unknown')}[/]\n"
        f"System: {subject.get('system_id', '')}  |  Owner: {subject.get('owner', '')}\n"
        f"State: [bold {state_color}]{state}[/]  |  "
        f"Reliance: [bold]{reliance.get('class', '?')}[/] ({reliance.get('label', '')})\n"
        f"Issued: {data.get('issued_at', '?')}  |  Valid until: {data.get('valid_until', '?')}",
        title="Assay Passport",
    ))

    # Trust posture
    if trust:
        table = Table(title="Trust Posture", show_header=False, padding=(0, 2))
        table.add_column("Key", style="dim")
        table.add_column("Value")
        for k, v in trust.items():
            table.add_row(k.replace("_", " ").title(), str(v))
        console.print(table)

    # Claims summary
    if claims:
        table = Table(title=f"Claims ({len(claims)})")
        table.add_column("ID", style="bold")
        table.add_column("Topic")
        table.add_column("Result")
        table.add_column("Type")
        for c in claims:
            result = c.get("result", "?")
            result_colors = {"pass": "green", "fail": "red", "partial": "yellow", "present": "cyan"}
            color = result_colors.get(result, "white")
            table.add_row(
                c.get("claim_id", ""),
                c.get("topic", ""),
                f"[{color}]{result}[/{color}]",
                c.get("evidence_type", ""),
            )
        console.print(table)

    # Coverage
    if coverage:
        cov_total = coverage.get("identified_total", 0)
        cov_covered = coverage.get("covered_total", 0)
        cov_pct = coverage.get("coverage_pct", 0)
        console.print(f"\n[bold]Coverage:[/] {cov_covered}/{cov_total} call sites ({cov_pct}%)")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@passport_app.command("verify")
def passport_verify_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    check_expiry: bool = typer.Option(False, "--check-expiry", help="Exit 1 if expired"),
    require_fresh: bool = typer.Option(False, "--require-fresh", help="Exit 1 if not FRESH state"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Verify passport signature, content-addressed ID, and lifecycle state.

    Exit codes:
      0 = valid
      1 = invalid, stale, or challenged
      2 = tampered (signature or ID mismatch)
    """
    path = Path(passport_file)
    if not path.exists():
        if output_json:
            _output_json({"command": "passport verify", "status": "error",
                         "error": f"File not found: {passport_file}"}, exit_code=3)
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    from assay.lifecycle_receipt import derive_governance_dimensions
    from assay.passport_lifecycle import PassportState, _is_stale
    from assay.passport_sign import verify_passport_signature

    # Signature verification
    vr = verify_passport_signature(path)

    # Lifecycle state from verified receipts
    data = json.loads(path.read_text(encoding="utf-8"))
    gov = derive_governance_dimensions(
        path.parent,
        passport=data,
        target_passport_id=data.get("passport_id"),
    )

    # Build PassportState from governance dimensions
    _gov_state_map = {
        "revoked": ("REVOKED", "Passport has been revoked"),
        "superseded": ("SUPERSEDED", "Passport has been superseded"),
        "challenged": ("CHALLENGED", "Passport is under active challenge"),
    }
    from datetime import datetime, timezone as _tz

    checked_at = datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    gs = gov["governance_status"]
    if gs in _gov_state_map:
        st_name, st_reason = _gov_state_map[gs]
        challenges = [r for r in gov["receipts"]
                      if (r.get("event_type") or r.get("type")) == "challenge"]
        state = PassportState(
            state=st_name, reason=st_reason, checked_at=checked_at,
            challenges=challenges,
        )
    elif _is_stale(data):
        state = PassportState(
            state="STALE",
            reason=f"Passport expired (valid_until: {data.get('valid_until', 'unknown')})",
            checked_at=checked_at,
        )
    else:
        state = PassportState(
            state="FRESH",
            reason="Valid, no active challenges, not superseded.",
            checked_at=checked_at,
        )

    # Determine exit code
    exit_code = 0
    if not vr.get("signature_valid", False) and data.get("signature"):
        exit_code = 2  # tampered
    elif not vr.get("id_valid", False) and data.get("passport_id"):
        exit_code = 2  # tampered
    elif check_expiry and state.state == "STALE":
        exit_code = 1
    elif require_fresh and state.state != "FRESH":
        exit_code = 1
    elif state.state in ("REVOKED",):
        exit_code = 1

    if output_json:
        _output_json({
            "command": "passport verify",
            "status": "ok" if exit_code == 0 else "fail",
            "signature_valid": vr.get("signature_valid"),
            "id_valid": vr.get("id_valid"),
            "key_id": vr.get("key_id"),
            "state": state.to_dict(),
            "exit_code": exit_code,
        }, exit_code=exit_code)

    # Human output
    sig_ok = vr.get("signature_valid", False)
    id_ok = vr.get("id_valid", False)

    sig_icon = "[green]VALID[/]" if sig_ok else "[red]INVALID[/]"
    id_icon = "[green]VALID[/]" if id_ok else "[red]INVALID[/]"

    if not data.get("signature"):
        sig_icon = "[dim]UNSIGNED[/]"
    if not data.get("passport_id"):
        id_icon = "[dim]NONE[/]"

    state_color = {
        "FRESH": "green", "STALE": "yellow", "CHALLENGED": "yellow",
        "SUPERSEDED": "dim", "REVOKED": "red",
    }.get(state.state, "white")

    console.print(Panel.fit(
        f"Signature: {sig_icon}  |  ID: {id_icon}\n"
        f"State: [bold {state_color}]{state.state}[/] — {state.reason}\n"
        f"Key: {vr.get('key_id', 'n/a')}",
        title="Passport Verification",
    ))

    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

@passport_app.command("sign")
def passport_sign_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    signer_id: Optional[str] = typer.Option(None, "--signer", help="Signer key ID"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Sign a passport with Ed25519. Writes signature in place."""
    path = Path(passport_file)
    if not path.exists():
        if output_json:
            _output_json({"command": "passport sign", "status": "error",
                         "error": f"File not found: {passport_file}"}, exit_code=3)
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    from assay.passport_sign import PassportSignError, sign_passport

    try:
        signed = sign_passport(path, signer_id=signer_id)
    except PassportSignError as exc:
        if output_json:
            _output_json({"command": "passport sign", "status": "error",
                         "error": str(exc)}, exit_code=1)
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1)

    if output_json:
        _output_json({
            "command": "passport sign",
            "status": "ok",
            "passport_id": signed.get("passport_id", ""),
            "key_id": signed.get("signature", {}).get("key_id", ""),
            "signed_at": signed.get("signature", {}).get("signed_at", ""),
        })

    console.print(Panel.fit(
        f"Passport signed.\n"
        f"ID: [bold]{signed.get('passport_id', '')}[/]\n"
        f"Key: {signed.get('signature', {}).get('key_id', '')}\n"
        f"At: {signed.get('signature', {}).get('signed_at', '')}",
        title="[green]Signed[/]",
    ))


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

@passport_app.command("render")
def passport_render_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    output: str = typer.Option("passport.html", "--output", "-o", help="Output HTML path"),
    verify: bool = typer.Option(False, "--verify", help="Verify signature before rendering"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Render passport as self-contained HTML."""
    path = Path(passport_file)
    if not path.exists():
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    from assay.passport_render import render_passport_html

    verification_result = None
    if verify:
        from assay.passport_sign import verify_passport_signature
        verification_result = verify_passport_signature(path)

    html_text = render_passport_html(path, verification_result=verification_result)
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_text, encoding="utf-8")

    if output_json:
        _output_json({
            "command": "passport render",
            "status": "ok",
            "output": str(out_path),
            "size_bytes": len(html_text),
        })

    console.print(f"[green]Rendered:[/] {out_path} ({len(html_text):,} bytes)")


# ---------------------------------------------------------------------------
# status (reliance verdict)
# ---------------------------------------------------------------------------

@passport_app.command("status")
def passport_status_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    mode: str = typer.Option("permissive", "--mode", "-m",
                             help="Policy mode: permissive, buyer-safe, strict"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Compute reliance verdict for a passport under a policy mode.

    Separates object integrity (verify) from reliance posture (status).

    Policy modes:
      permissive  — FAIL only on integrity failure or revocation
      buyer-safe  — FAIL on revocation, challenged, stale
      strict      — FAIL on anything except clean, signed, fresh

    Exit codes:
      0 = PASS
      1 = WARN
      2 = FAIL
      3 = input error
    """
    path = Path(passport_file)
    if not path.exists():
        if output_json:
            _output_json({"command": "passport status", "status": "error",
                         "error": f"File not found: {passport_file}"}, exit_code=3)
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    if mode not in ("permissive", "buyer-safe", "strict"):
        console.print(f"[red]Error:[/] Invalid mode: {mode}. Use permissive, buyer-safe, or strict.")
        raise typer.Exit(3)

    data = json.loads(path.read_text(encoding="utf-8"))

    from assay.lifecycle_receipt import derive_governance_dimensions
    from assay.passport_sign import verify_passport_signature
    from assay.verdict import compute_verdict, extract_dimensions

    # Verify signature
    sig_result = verify_passport_signature(path)

    # Derive governance from verified receipts
    gov = derive_governance_dimensions(
        path.parent,
        passport=data,
        target_passport_id=data.get("passport_id"),
    )

    # Extract dimensions (freshness handled internally by extract_dimensions)
    dims = extract_dimensions(
        data,
        signature_result=sig_result,
        governance_status=gov["governance_status"],
        event_integrity=gov["event_integrity"],
    )

    # Compute verdict
    result = compute_verdict(dims, policy_mode=mode)

    if output_json:
        out = result.to_dict()
        out["command"] = "passport status"
        # Governance ingestion evidence — makes the status path inspectable
        out["governance_evidence"] = {
            "source": "verified_lifecycle_receipts",
            "signed_total": gov["signed_total"],
            "signed_valid": gov["signed_valid"],
            "unsigned_demo": sum(
                1 for r in gov["receipts"] if not r.get("_verified")
            ),
            "effective_events": sorted(set(
                (r.get("event_type") or r.get("type", "unknown"))
                for r in gov["receipts"]
            )),
        }
        _output_json(out, exit_code=result.exit_code)

    # Human output
    verdict_colors = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}
    vc = verdict_colors.get(result.verdict, "white")

    console.print(Panel.fit(
        f"Verdict: [bold {vc}]{result.verdict}[/]\n"
        f"Mode: {mode}\n"
        f"Reason: {result.reason}\n\n"
        f"[dim]Verify checks artifact integrity. Status answers whether to rely on it under this policy.[/]\n\n"
        f"Signature: {dims.signature_valid}  |  Schema: {dims.schema_valid}\n"
        f"Content ID: {dims.content_hash_valid}  |  Freshness: {dims.freshness_status}\n"
        f"Governance: {dims.governance_status}  |  Events: {dims.event_integrity}\n\n"
        f"[bold]Compare:[/] assay passport verify {_display_path(path)}",
        title="Passport Status",
    ))

    raise typer.Exit(result.exit_code)


# ---------------------------------------------------------------------------
# xray
# ---------------------------------------------------------------------------

@passport_app.command("xray")
def passport_xray_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    report: Optional[str] = typer.Option(None, "--report", "-r", help="Output HTML report path"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Run X-Ray diagnostic on a passport. Shows grade (A-F) and findings.

    Exit codes:
      0 = grade A or B
      1 = grade C or D
      2 = grade F
    """
    from assay.xray import xray_passport

    result = xray_passport(Path(passport_file), verify=True)

    if report:
        from assay.reporting.xray_report import render_xray_html
        html_text = render_xray_html(result)
        rpath = Path(report)
        rpath.parent.mkdir(parents=True, exist_ok=True)
        rpath.write_text(html_text, encoding="utf-8")

    if output_json:
        _output_json(result.to_dict(), exit_code=result.exit_code)

    # Human output
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "yellow", "F": "red"}
    gc = grade_colors.get(result.overall_grade, "white")

    console.print(Panel.fit(
        f"Grade: [bold {gc}]{result.overall_grade}[/]\n"
        f"State: {result.state.state if result.state else 'UNKNOWN'}\n"
        f"Findings: {sum(1 for f in result.findings if f.severity == 'pass')} pass, "
        f"{sum(1 for f in result.findings if f.severity == 'warn')} warn, "
        f"{sum(1 for f in result.findings if f.severity == 'fail')} fail\n\n"
        f"[dim]X-Ray is a diagnostic grade, not a separate integrity verdict. A weak grade can still be a valid signed artifact.[/]",
        title="Passport X-Ray",
    ))

    # Findings table
    table = Table()
    table.add_column("Sev", width=6)
    table.add_column("Category", width=12)
    table.add_column("Finding")
    table.add_column("Remediation", style="dim")
    for f in result.findings:
        sev_colors = {"pass": "green", "warn": "yellow", "fail": "red", "info": "dim"}
        sc = sev_colors.get(f.severity, "white")
        table.add_row(
            f"[{sc}]{f.severity.upper()}[/{sc}]",
            f.category,
            f.title,
            f.remediation or "",
        )
    console.print(table)

    if result.missing_for_next_grade:
        console.print(f"\n[bold]To improve from {result.overall_grade}:[/]")
        for m in result.missing_for_next_grade:
            console.print(f"  - {m}")

    if report:
        console.print(f"\n[green]Report:[/] {report}")

    raise typer.Exit(result.exit_code)


# ---------------------------------------------------------------------------
# mint
# ---------------------------------------------------------------------------

@passport_app.command("mint")
def passport_mint_cmd(
    pack: Optional[str] = typer.Option(None, "--pack", help="Proof pack directory"),
    subject_name: str = typer.Option(..., "--subject-name", help="System/subject name"),
    system_id: str = typer.Option(..., "--system-id", help="System identifier"),
    owner: str = typer.Option(..., "--owner", help="System owner"),
    valid_days: int = typer.Option(30, "--valid-days", help="Validity period in days"),
    output: str = typer.Option("passport.json", "--output", "-o", help="Output path"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Mint an unsigned passport draft from a proof pack.

    Creates a passport skeleton with claims extracted from the proof pack's
    verify_report.json. Sign with 'assay passport sign' after review.
    """
    from assay.passport_mint import PassportMintError, mint_passport_draft

    try:
        passport = mint_passport_draft(
            proof_pack_dir=Path(pack) if pack else None,
            subject_name=subject_name,
            subject_system_id=system_id,
            subject_owner=owner,
            valid_days=valid_days,
        )
    except PassportMintError as exc:
        if output_json:
            _output_json({"command": "passport mint", "status": "error",
                         "error": str(exc)}, exit_code=3)
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(3)

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(passport, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if output_json:
        _output_json({
            "command": "passport mint",
            "status": "ok",
            "output": str(out_path),
            "claims": len(passport.get("claims", [])),
            "reliance_class": passport.get("reliance", {}).get("class", ""),
        })

    console.print(Panel.fit(
        f"Draft passport written to [bold]{out_path}[/]\n"
        f"Claims: {len(passport.get('claims', []))}\n"
        f"Reliance: {passport.get('reliance', {}).get('class', '?')}\n\n"
        f"[dim]Next: review and sign with[/] assay passport sign {out_path}",
        title="[green]Passport Minted[/]",
    ))


# ---------------------------------------------------------------------------
# challenge
# ---------------------------------------------------------------------------

@passport_app.command("challenge")
def passport_challenge_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    reason: str = typer.Option(..., "--reason", help="Challenge reason"),
    reason_code: str = typer.Option("other", "--reason-code", help="Reason code"),
    signer: Optional[str] = typer.Option(None, "--signer", help="Signer key ID"),
    evidence_ref: Optional[str] = typer.Option(None, "--evidence-ref", help="Evidence reference"),
    demo: bool = typer.Option(False, "--demo", help="Use unsigned demo mode"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Issue a signed challenge receipt against a passport.

    Creates a signed challenge receipt in the passport's directory.
    The passport state becomes CHALLENGED on next verification.
    Use --demo for unsigned receipts (not for production).
    """
    path = Path(passport_file)
    if not path.exists():
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    data = json.loads(path.read_text(encoding="utf-8"))
    passport_id = data.get("passport_id", "")

    if demo:
        from assay.passport_lifecycle import create_demo_challenge_receipt

        receipt_path = create_demo_challenge_receipt(
            data,
            reason=reason,
            challenger_id=signer or "anonymous",
            evidence_ref=evidence_ref,
            output_dir=path.parent,
        )
    else:
        from assay.lifecycle_receipt import (
            create_signed_challenge_receipt,
            write_lifecycle_receipt,
        )

        receipt = create_signed_challenge_receipt(
            target_passport_id=passport_id,
            reason_code=reason_code,
            reason_summary=reason,
            signer_id=signer,
            evidence_refs=[evidence_ref] if evidence_ref else None,
        )
        receipt_path = write_lifecycle_receipt(receipt, path.parent)

    if output_json:
        _output_json({
            "command": "passport challenge",
            "status": "ok",
            "receipt": str(receipt_path),
            "passport_id": passport_id,
            "reason": reason,
            "signed": not demo,
        })

    console.print(Panel.fit(
        f"Challenge issued{' (signed)' if not demo else ' (demo/unsigned)'}.\n"
        f"Receipt: [bold]{receipt_path.name}[/]\n"
        f"Reason: {reason}\n"
        f"Passport: {passport_id or 'unsigned'}\n\n"
        f"[bold]Next:[/] assay passport verify {_display_path(path)} --require-fresh\n"
        f"[bold]Policy view:[/] assay passport status {_display_path(path)} --mode buyer-safe",
        title="[yellow]Challenged[/]",
    ))


# ---------------------------------------------------------------------------
# supersede
# ---------------------------------------------------------------------------

@passport_app.command("supersede")
def passport_supersede_cmd(
    old_file: str = typer.Argument(..., help="Path to old passport.json"),
    new_file: str = typer.Argument(..., help="Path to new passport.json"),
    reason: str = typer.Option(..., "--reason", help="Supersession reason"),
    reason_code: str = typer.Option("remediation", "--reason-code", help="Reason code"),
    signer: Optional[str] = typer.Option(None, "--signer", help="Signer key ID"),
    demo: bool = typer.Option(False, "--demo", help="Use unsigned demo mode"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Supersede an old passport with a new one.

    Creates a signed supersession receipt in the old passport's directory.
    Updates relationships.superseded_by in old and relationships.supersedes in new.
    Use --demo for unsigned receipts (not for production).
    """
    old_path = Path(old_file)
    new_path = Path(new_file)
    for p, label in [(old_path, "Old"), (new_path, "New")]:
        if not p.exists():
            console.print(f"[red]Error:[/] {label} passport not found: {p}")
            raise typer.Exit(3)

    old_data = json.loads(old_path.read_text(encoding="utf-8"))
    new_data = json.loads(new_path.read_text(encoding="utf-8"))
    old_passport_id = old_data.get("passport_id", "")
    new_passport_id = new_data.get("passport_id", "")

    if demo:
        from assay.passport_lifecycle import create_demo_supersession_receipt

        receipt_path = create_demo_supersession_receipt(
            old_data, new_data,
            reason=reason,
            output_dir=old_path.parent,
        )
    else:
        from assay.lifecycle_receipt import (
            create_signed_supersession_receipt,
            write_lifecycle_receipt,
        )

        receipt = create_signed_supersession_receipt(
            target_passport_id=old_passport_id,
            new_passport_id=new_passport_id,
            reason_code=reason_code,
            reason_summary=reason,
            signer_id=signer,
        )
        receipt_path = write_lifecycle_receipt(receipt, old_path.parent)

    # Update relationship fields only on unsigned passports.
    # Signed passports must not be mutated — doing so breaks the signature
    # and content-addressed ID. The supersession receipt is the canonical
    # source of chain linkage, not the passport body.
    old_is_signed = bool(old_data.get("signature"))
    new_is_signed = bool(new_data.get("signature"))
    mutated_files = []

    if not old_is_signed:
        if "relationships" not in old_data:
            old_data["relationships"] = {}
        old_data["relationships"]["superseded_by"] = new_passport_id
        old_path.write_text(
            json.dumps(old_data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        mutated_files.append("old")

    if not new_is_signed:
        if "relationships" not in new_data:
            new_data["relationships"] = {}
        new_data["relationships"]["supersedes"] = old_passport_id
        new_path.write_text(
            json.dumps(new_data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        mutated_files.append("new")

    if output_json:
        _output_json({
            "command": "passport supersede",
            "status": "ok",
            "receipt": str(receipt_path),
            "old_passport_id": old_passport_id,
            "new_passport_id": new_passport_id,
            "signed": not demo,
        })

    sig_note = ""
    skipped = []
    if old_is_signed and "old" not in mutated_files:
        skipped.append("old (signed)")
    if new_is_signed and "new" not in mutated_files:
        skipped.append("new (signed)")
    if skipped:
        sig_note = f"\n[dim]Relationship fields not written to {', '.join(skipped)} — signature preserved.[/]"

    console.print(Panel.fit(
        f"Supersession recorded{' (signed)' if not demo else ' (demo/unsigned)'}.\n"
        f"Old: {old_passport_id or old_path.name}\n"
        f"New: {new_passport_id or new_path.name}\n"
        f"Receipt: {receipt_path.name}\n"
        f"Reason: {reason}{sig_note}\n\n"
        f"[bold]Next:[/] assay passport verify {_display_path(old_path)}\n"
        f"[bold]Inspect the change:[/] assay passport diff {_display_path(old_path)} {_display_path(new_path)}",
        title="[dim]Superseded[/]",
    ))


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

@passport_app.command("revoke")
def passport_revoke_cmd(
    passport_file: str = typer.Argument(..., help="Path to passport.json"),
    reason: str = typer.Option(..., "--reason", help="Revocation reason"),
    reason_code: str = typer.Option("issuer_withdrawal", "--reason-code", help="Reason code"),
    signer: Optional[str] = typer.Option(None, "--signer", help="Signer key ID"),
    demo: bool = typer.Option(False, "--demo", help="Use unsigned demo mode"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Revoke a passport. Creates a signed revocation receipt.

    The passport state becomes REVOKED on next verification.
    Use --demo for unsigned receipts (not for production).
    """
    path = Path(passport_file)
    if not path.exists():
        console.print(f"[red]Error:[/] File not found: {passport_file}")
        raise typer.Exit(3)

    data = json.loads(path.read_text(encoding="utf-8"))
    passport_id = data.get("passport_id", "")

    if demo:
        from assay.passport_lifecycle import create_demo_revocation_receipt

        receipt_path = create_demo_revocation_receipt(
            data,
            reason=reason,
            output_dir=path.parent,
        )
    else:
        from assay.lifecycle_receipt import (
            create_signed_revocation_receipt,
            write_lifecycle_receipt,
        )

        receipt = create_signed_revocation_receipt(
            target_passport_id=passport_id,
            reason_code=reason_code,
            reason_summary=reason,
            signer_id=signer,
        )
        receipt_path = write_lifecycle_receipt(receipt, path.parent)

    if output_json:
        _output_json({
            "command": "passport revoke",
            "status": "ok",
            "receipt": str(receipt_path),
            "passport_id": passport_id,
            "signed": not demo,
        })

    console.print(Panel.fit(
        f"Passport revoked{' (signed)' if not demo else ' (demo/unsigned)'}.\n"
        f"Receipt: [bold]{receipt_path.name}[/]\n"
        f"Reason: {reason}",
        title="[red]Revoked[/]",
    ))


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

@passport_app.command("diff")
def passport_diff_cmd(
    file_a: str = typer.Argument(..., help="Path to baseline passport (A)"),
    file_b: str = typer.Argument(..., help="Path to current passport (B)"),
    report: Optional[str] = typer.Option(None, "--report", "-r", help="Output HTML report path"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Compare two passports. Show what changed.

    Exit codes:
      0 = no regression
      1 = regression detected
      2 = integrity failure
    """
    from assay.passport_diff import diff_passports

    result = diff_passports(Path(file_a), Path(file_b))

    if report:
        from assay.reporting.passport_diff_report import render_passport_diff_html
        html_text = render_passport_diff_html(result)
        rpath = Path(report)
        rpath.parent.mkdir(parents=True, exist_ok=True)
        rpath.write_text(html_text, encoding="utf-8")

    if output_json:
        _output_json(result.to_dict(), exit_code=result.exit_code)

    # Human output
    if result.integrity_error:
        console.print(f"[red]Integrity failure:[/] {result.integrity_error}")
    elif result.has_regression:
        console.print("[red]Regression detected[/]")
    else:
        console.print("[green]No regression[/]")

    if result.reliance_changed:
        console.print(f"Reliance: {result.reliance_a} → {result.reliance_b}")

    if result.claim_deltas:
        table = Table(title="Claim Deltas")
        table.add_column("Claim")
        table.add_column("A")
        table.add_column("B")
        table.add_column("Status")
        for d in result.claim_deltas:
            sc = {"improved": "green", "regressed": "red", "new": "cyan",
                  "removed": "red", "unchanged": "dim"}.get(d.status, "white")
            table.add_row(
                d.claim_id,
                d.a_result or "—",
                d.b_result or "—",
                f"[{sc}]{d.status}[/{sc}]",
            )
        console.print(table)

    if result.coverage_delta:
        cd = result.coverage_delta
        console.print(
            f"Coverage: {cd.a_covered}/{cd.a_total} → {cd.b_covered}/{cd.b_total} "
            f"({cd.status})"
        )

    if result.is_supersession:
        console.print("[dim]Supersession chain detected[/]")

    if report:
        console.print(f"\n[green]Report:[/] {report}")

    raise typer.Exit(result.exit_code)


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

@passport_app.command("demo")
def passport_demo_cmd(
    output_dir: str = typer.Option("passport_demo", "--output-dir", "-o", help="Output directory"),
) -> None:
    """Run the full passport lifecycle demo (10 steps).

    Demonstrates: mint → sign → render → xray → challenge → verify →
    mint v2 → supersede → diff.
    """
    import shutil
    import tempfile

    from assay.keystore import AssayKeyStore

    demo_dir = Path(output_dir)
    demo_dir.mkdir(parents=True, exist_ok=True)

    console.print("[bold]Assay Passport Demo[/]\n")
    console.print("[dim]This demo shows the full lifecycle on seeded artifacts. Verify checks integrity; status checks reliance posture; X-Ray explains artifact quality.[/]\n")

    # Set up a temporary keystore
    tmp_keys = Path(tempfile.mkdtemp(prefix="assay_demo_keys_"))
    ks = AssayKeyStore(keys_dir=tmp_keys)
    ks.generate_key("demo-signer")

    try:
        _run_demo(demo_dir, ks)
    finally:
        shutil.rmtree(tmp_keys, ignore_errors=True)


def _run_demo(demo_dir: Path, ks: "AssayKeyStore") -> None:
    from assay.lifecycle_receipt import (
        create_signed_challenge_receipt,
        create_signed_supersession_receipt,
        derive_governance_dimensions,
        write_lifecycle_receipt,
    )
    from assay.passport_diff import diff_passports
    from assay.passport_mint import mint_passport_draft
    from assay.passport_render import render_passport_html
    from assay.passport_sign import sign_passport, verify_passport_signature
    from assay.xray import xray_passport

    # Step 1: Mint draft
    console.print("[bold]Step 1:[/] Mint passport draft")
    passport = mint_passport_draft(
        subject_name="DemoApp",
        subject_system_id="demo.app.v1",
        subject_owner="Demo Inc.",
        valid_days=30,
    )
    p1_path = demo_dir / "passport_v1.json"
    p1_path.write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")
    console.print(f"  → {p1_path}")

    # Step 2: Sign
    console.print("[bold]Step 2:[/] Sign passport")
    signed = sign_passport(p1_path, keystore=ks, signer_id="demo-signer")
    console.print(f"  → ID: {signed.get('passport_id', '')[:40]}...")

    # Step 3: Render HTML
    console.print("[bold]Step 3:[/] Render HTML")
    vr = verify_passport_signature(p1_path, keystore=ks)
    html_text = render_passport_html(p1_path, verification_result=vr)
    html_path = demo_dir / "passport_v1.html"
    html_path.write_text(html_text, encoding="utf-8")
    console.print(f"  → {html_path} ({len(html_text):,} bytes)")

    # Step 4: X-Ray
    console.print("[bold]Step 4:[/] X-Ray diagnostic")
    xr = xray_passport(p1_path, keystore=ks, verify=True)
    console.print(
        f"  → Grade: {xr.overall_grade} ({len(xr.findings)} findings). "
        "This is diagnostic quality, not a separate signature check."
    )

    # Step 5: Challenge (signed)
    console.print("[bold]Step 5:[/] Challenge passport (signed)")
    data1 = json.loads(p1_path.read_text(encoding="utf-8"))
    challenge_receipt = create_signed_challenge_receipt(
        target_passport_id=data1.get("passport_id", ""),
        reason_code="coverage_gap",
        reason_summary="Missing admin override coverage",
        keystore=ks,
        signer_id="demo-signer",
    )
    challenge_path = write_lifecycle_receipt(challenge_receipt, demo_dir)
    console.print(f"  → {challenge_path.name} (signed, event_id: {challenge_receipt['event_id'][:30]}...)")

    # Step 6: Verify (should show CHALLENGED via verified receipt ingestion)
    console.print("[bold]Step 6:[/] Verify (expect CHALLENGED)")
    data1 = json.loads(p1_path.read_text(encoding="utf-8"))
    gov = derive_governance_dimensions(demo_dir, passport=data1,
                                       target_passport_id=data1.get("passport_id"))
    console.print(f"  → Governance: {gov['governance_status']} "
                  f"(integrity: {gov['event_integrity']}, "
                  f"verified: {gov['signed_valid']}/{gov['signed_total']})")
    console.print("  → If this were a live handoff, verify would now fail --require-fresh and status would warn or fail depending on policy.")

    # Step 7: Mint v2 (address the challenge by adding coverage claim)
    console.print("[bold]Step 7:[/] Mint v2 (address challenge)")
    passport_v2 = mint_passport_draft(
        subject_name="DemoApp",
        subject_system_id="demo.app.v1",
        subject_owner="Demo Inc.",
        valid_days=30,
    )
    # v2 addresses the challenge: add a coverage claim that v1 lacked
    passport_v2["claims"].append({
        "claim_id": "C-DEMO-001",
        "topic": "Admin override coverage",
        "claim_type": "coverage",
        "applies_to": "admin_override_path",
        "assertion": "Admin override code path is instrumented and verified.",
        "result": "pass",
        "evidence_type": "machine_verified",
        "proof_tier": "core",
        "evidence_refs": ["demo/admin_override_coverage"],
        "qualification": None,
        "boundary": None,
    })
    passport_v2["evidence_summary"]["total_claims"] = len(passport_v2["claims"])
    passport_v2["evidence_summary"]["machine_verified"] = len(passport_v2["claims"])
    passport_v2["evidence_summary"]["core_claims_passed"] = f"{len(passport_v2['claims'])}/{len(passport_v2['claims'])}"
    p2_path = demo_dir / "passport_v2.json"
    p2_path.write_text(json.dumps(passport_v2, indent=2) + "\n", encoding="utf-8")
    console.print(f"  → {p2_path} (added admin override coverage claim)")

    # Step 8: Sign v2
    console.print("[bold]Step 8:[/] Sign v2")
    signed_v2 = sign_passport(p2_path, keystore=ks, signer_id="demo-signer")
    console.print(f"  → ID: {signed_v2.get('passport_id', '')[:40]}...")

    # Step 9: Supersede (signed)
    console.print("[bold]Step 9:[/] Supersede v1 → v2 (signed)")
    data1 = json.loads(p1_path.read_text(encoding="utf-8"))
    data2 = json.loads(p2_path.read_text(encoding="utf-8"))
    sup_receipt = create_signed_supersession_receipt(
        target_passport_id=data1.get("passport_id", ""),
        new_passport_id=data2.get("passport_id", ""),
        reason_code="remediation",
        reason_summary="Addressed coverage gap",
        keystore=ks,
        signer_id="demo-signer",
    )
    sup_path = write_lifecycle_receipt(sup_receipt, demo_dir)
    console.print(f"  → {sup_path.name} (signed)")

    # Step 10: Diff
    console.print("[bold]Step 10:[/] Trust Diff")
    diff_result = diff_passports(p1_path, p2_path)
    diff_html_path = demo_dir / "trust_diff.html"

    from assay.reporting.passport_diff_report import render_passport_diff_html
    diff_html = render_passport_diff_html(diff_result)
    diff_html_path.write_text(diff_html, encoding="utf-8")
    console.print(f"  → {diff_html_path} (regression: {diff_result.has_regression})")

    console.print(f"\n[bold green]Demo complete.[/] Output in {demo_dir}/")
    console.print("[dim]A successful run should leave you with: a signed v1 passport, a signed challenge, a signed supersession, a signed v2 passport, and a trust diff you can inspect offline.[/]")
    console.print(f"  passport_v1.json, passport_v1.html")
    console.print(f"  passport_v2.json")
    console.print(f"  {challenge_path.name} (signed challenge)")
    console.print(f"  {sup_path.name} (signed supersession)")
    console.print(f"  trust_diff.html")
    console.print(f"\n[bold]Try next:[/] assay passport status {_display_path(p1_path)} --mode buyer-safe")
    console.print(f"[bold]Then compare:[/] assay passport diff {_display_path(p1_path)} {_display_path(p2_path)}")
