"""Plain-English proof pack explanation.

Reads a proof pack directory and produces a human-readable summary
covering what happened, integrity status, claim results, what the
pack proves, and what it does NOT prove.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay.keystore import get_default_keystore


def _load_json_object(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Load a JSON object from disk and surface parse failures as strings."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, f"Cannot read {path.name}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON in {path.name}: {exc.msg}"

    if not isinstance(payload, dict):
        return None, f"{path.name} must contain a JSON object"
    return payload, None


def _load_receipts(path: Path) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Load receipts from JSONL without crashing explain on malformed content."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return [], f"Cannot read {path.name}: {exc}"

    receipts: List[Dict[str, Any]] = []
    if not text:
        return receipts, None

    for line_no, line in enumerate(text.split("\n"), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            return [], f"Invalid JSON in {path.name} at line {line_no}: {exc.msg}"
        if not isinstance(payload, dict):
            return [], f"{path.name} line {line_no} must contain a JSON object"
        receipts.append(payload)

    return receipts, None


def _derive_verification_state(
    integrity_pass: bool,
    claims_declared: bool,
    claims_pass: Optional[bool],
) -> Tuple[str, str]:
    """Collapse pack truth into a small user-facing state machine."""
    if not integrity_pass:
        return "TAMPERED", "Tampered or structurally invalid"
    if claims_declared and claims_pass is False:
        return "HONEST_FAIL", "Honest failure"
    if claims_declared and claims_pass is True:
        return "CREDIBLE_PASS", "Credible pass"
    return "INTEGRITY_ONLY", "Integrity verified"


def _derive_trust_posture(
    has_witness: bool,
    witness_info: Optional[Dict[str, Any]],
) -> Tuple[str, str]:
    """Return an honest trust-posture summary for current explain surfaces."""
    if not has_witness:
        return (
            "T0_SELF_SIGNED",
            "T0 self-signed: integrity can be verified, but origin is not independently witnessed.",
        )

    witness = witness_info or {}
    witness_type = str(witness.get("witness_type") or "external witness")
    return (
        "WITNESS_BUNDLE_PRESENT",
        f"Witness bundle present ({witness_type}); verify the witness details separately before claiming higher-trust anchoring.",
    )


def explain_pack(pack_dir: Path) -> Dict[str, Any]:
    """Analyse a proof pack and return a structured explanation.

    Returns a dict with sections that can be rendered as text, markdown, or JSON.
    """
    pack_dir = Path(pack_dir)
    manifest_path = pack_dir / "pack_manifest.json"
    report_path = pack_dir / "verify_report.json"
    receipt_path = pack_dir / "receipt_pack.jsonl"

    manifest: Dict[str, Any] = {}
    attestation: Dict[str, Any] = {}
    manifest_error: Optional[str] = None
    if manifest_path.exists():
        loaded_manifest, manifest_error = _load_json_object(manifest_path)
        if loaded_manifest is not None:
            manifest = loaded_manifest
            attestation = manifest.get("attestation", {})
        else:
            manifest = {}
            manifest_error = manifest_error or "pack_manifest.json could not be loaded"
    else:
        manifest_error = "pack_manifest.json not found"

    errors: List[Dict[str, Any]] = []
    integrity_pass = False
    if manifest:
        try:
            from assay.proof_pack import verify_proof_pack

            verify_result = verify_proof_pack(
                manifest, pack_dir, get_default_keystore()
            )
            integrity_pass = verify_result.passed
            errors = [error.to_dict() for error in verify_result.errors]
        except Exception as exc:
            errors = [
                {
                    "code": "E_EXPLAIN_VERIFY",
                    "message": f"Explain could not re-verify this proof pack: {exc}",
                }
            ]
    else:
        errors = [
            {
                "code": "E_MANIFEST_TAMPER",
                "message": manifest_error,
                "field": "pack_manifest.json",
            }
        ]

    report: Dict[str, Any] = {}
    if integrity_pass and report_path.exists():
        loaded_report, report_error = _load_json_object(report_path)
        if loaded_report is not None:
            report = loaded_report
        elif report_error:
            errors.append(
                {
                    "code": "E_EXPLAIN_REPORT",
                    "message": report_error,
                    "field": "verify_report.json",
                }
            )

    receipts: List[Dict[str, Any]] = []
    if receipt_path.exists():
        receipts, receipt_error = _load_receipts(receipt_path)
        if receipt_error:
            errors.append(
                {
                    "code": "E_EXPLAIN_RECEIPTS",
                    "message": receipt_error,
                    "field": "receipt_pack.jsonl",
                }
            )

    # Analyse receipts
    type_counts: Counter[str] = Counter()
    providers: set[str] = set()
    models: set[str] = set()
    total_tokens = 0
    for r in receipts:
        type_counts[r.get("type", "unknown")] += 1
        if r.get("provider"):
            providers.add(r["provider"])
        if r.get("model_id"):
            models.add(r["model_id"])
        if r.get("total_tokens"):
            total_tokens += r["total_tokens"]

    # Build explanation
    pack_id = attestation.get("pack_id", manifest.get("pack_id", "unknown"))
    run_id = attestation.get("run_id", manifest.get("run_id", "unknown"))
    n_receipts = len(receipts)
    timestamp_start = attestation.get("timestamp_start", "unknown")
    timestamp_end = attestation.get("timestamp_end", "unknown")
    integrity_status = "PASSED" if integrity_pass else "FAILED"

    # Claims
    claim_check = str(attestation.get("claim_check") or "N/A")
    claim_verification = report.get("claim_verification") if integrity_pass else None
    claims_declared = claim_check != "N/A" or claim_verification is not None
    claims_present = claim_verification is not None
    claims_pass: Optional[bool]
    claims_status: str
    claim_results: List[Dict[str, Any]] = []
    if not claims_declared:
        claims_pass = None
        claims_status = "NONE"
    elif not integrity_pass:
        claims_pass = None
        claims_status = "UNTRUSTED"
    else:
        claims_pass = (
            claim_verification.get("passed", False)
            if claims_present
            else claim_check == "PASS"
        )
        claims_status = "PASSED" if claims_pass else "FAILED"
    if integrity_pass and claims_present:
        claim_results = claim_verification.get("results", [])

    # Signer
    signer_id = manifest.get("signer_id", "unknown")

    # Witness
    witness_path = pack_dir / "witness_bundle.json"
    has_witness = witness_path.exists()
    witness_info: Optional[Dict[str, Any]] = None
    if has_witness:
        try:
            witness_info = json.loads(witness_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            has_witness = False

    verification_state, verification_label = _derive_verification_state(
        integrity_pass,
        claims_declared,
        claims_pass,
    )
    trust_posture_code, trust_posture_summary = _derive_trust_posture(
        has_witness,
        witness_info,
    )

    return {
        "pack_id": pack_id,
        "run_id": run_id,
        "verification_state": verification_state,
        "verification_label": verification_label,
        "n_receipts": n_receipts,
        "timestamp_start": timestamp_start,
        "timestamp_end": timestamp_end,
        "type_counts": dict(type_counts),
        "providers": sorted(providers),
        "models": sorted(models),
        "total_tokens": total_tokens,
        "integrity_status": integrity_status,
        "integrity_pass": integrity_pass,
        "errors": errors,
        "claims_declared": claims_declared,
        "claims_present": claims_present,
        "claims_status": claims_status,
        "claims_pass": claims_pass,
        "claim_results": claim_results,
        "signer_id": signer_id,
        "pack_dir": str(pack_dir),
        "has_witness": has_witness,
        "witness_info": witness_info,
        "trust_posture_code": trust_posture_code,
        "trust_posture_summary": trust_posture_summary,
    }


def render_text(info: Dict[str, Any]) -> str:
    """Render explanation as plain text."""
    lines: List[str] = []

    lines.append(f"Proof Pack: {info['pack_id']}")
    lines.append(f"Run ID:     {info['run_id']}")
    lines.append(f"Outcome:    {info['verification_label']}")
    lines.append("")

    # What happened
    lines.append("WHAT HAPPENED")
    if not info["integrity_pass"]:
        lines.append(
            "  Receipt contents below are untrusted because integrity verification failed."
        )
    receipt_parts = []
    for rtype, count in sorted(info["type_counts"].items()):
        receipt_parts.append(f"{count} {rtype}")
    if receipt_parts:
        lines.append(
            f"  {info['n_receipts']} receipts recorded: {', '.join(receipt_parts)}"
        )
    else:
        lines.append(f"  {info['n_receipts']} receipts recorded")

    if info["providers"]:
        lines.append(f"  Providers: {', '.join(info['providers'])}")
    if info["models"]:
        lines.append(f"  Models: {', '.join(info['models'])}")
    if info["total_tokens"] > 0:
        lines.append(f"  Total tokens: {info['total_tokens']:,}")
    lines.append(f"  Time window: {info['timestamp_start']} to {info['timestamp_end']}")
    lines.append(f"  Signed by: {info['signer_id']}")
    lines.append(f"  Trust posture: {info['trust_posture_summary']}")
    lines.append("")

    # Integrity
    lines.append("INTEGRITY CHECK")
    if info["integrity_pass"]:
        lines.append("  PASSED")
        lines.append("  All file hashes match. The Ed25519 signature is valid.")
        lines.append("  This evidence has not been tampered with since creation.")
    else:
        lines.append("  FAILED")
        lines.append(
            "  Treat cached claim results and parsed receipt details as untrusted until the pack is re-issued."
        )
        for err in info["errors"]:
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            lines.append(f"  Error: {msg}")
    lines.append("")

    # Claims
    lines.append("CLAIM CHECKS")
    if not info["claims_declared"]:
        lines.append("  No claims were declared for this pack.")
    elif info["claims_status"] == "UNTRUSTED":
        lines.append(
            "  Untrusted: integrity failed, so cached claim results are not authoritative."
        )
    elif info["claims_pass"]:
        lines.append("  PASSED")
        for cr in info["claim_results"]:
            status = "PASS" if cr.get("passed") else "FAIL"
            lines.append(
                f"  [{status}] {cr.get('claim_id', '?')}: {cr.get('expected', '')}"
            )
    else:
        lines.append("  FAILED")
        for cr in info["claim_results"]:
            status = "PASS" if cr.get("passed") else "FAIL"
            lines.append(
                f"  [{status}] {cr.get('claim_id', '?')}: {cr.get('expected', '')} (actual: {cr.get('actual', '?')})"
            )
    lines.append("")

    # What this proves
    lines.append("WHAT THIS PROVES")
    if info["integrity_pass"]:
        lines.append("  The recorded evidence is authentic (signed, hash-verified).")
    if info["verification_state"] == "CREDIBLE_PASS":
        lines.append(
            "  This is a credible pass: the evidence is authentic, and the declared checks passed."
        )
    elif info["verification_state"] == "HONEST_FAIL":
        lines.append(
            "  This is an honest failure: the evidence is authentic, and it proves the run did not meet the declared standards."
        )
    elif info["claims_declared"] and info["claims_pass"]:
        lines.append("  The declared behavioral checks all passed.")
    elif info["claims_declared"] and info["integrity_pass"]:
        lines.append("  Some declared behavioral checks failed (see above).")
        lines.append("  This is an honest failure: the evidence is authentic,")
        lines.append("  and it proves the run did not meet the declared standards.")
    lines.append("")

    # What this does NOT prove
    lines.append("WHAT THIS DOES NOT PROVE")
    lines.append(
        "  - That every action was recorded (only recorded actions are in the pack)"
    )
    lines.append("  - That model outputs are correct or safe")
    lines.append(
        "  - That receipts were honestly created (tamper-evidence, not source attestation)"
    )
    if info.get("has_witness"):
        witness = info.get("witness_info") or {}
        tsa = witness.get("tsa_url", "TSA")
        wtype = witness.get("witness_type", "rfc3161").upper()
        lines.append(
            f"  - Timestamps are externally anchored via {wtype} witness ({tsa})"
        )
    else:
        lines.append(
            "  - That timestamps are externally anchored (local clock was used)"
        )
    lines.append("  - That the signer key was not compromised")
    lines.append("")

    # How to verify
    lines.append("VERIFY INDEPENDENTLY")
    lines.append(
        f"  python3 -m pip install assay-ai && assay verify-pack {info['pack_dir']}"
    )
    lines.append("")

    return "\n".join(lines)


def render_md(info: Dict[str, Any]) -> str:
    """Render explanation as markdown (suitable for PACK_SUMMARY.md)."""
    lines: List[str] = []

    lines.append("# Proof Pack Summary")
    lines.append("")
    lines.append(f"**Pack ID:** `{info['pack_id']}`")
    lines.append(f"**Run ID:** `{info['run_id']}`")
    lines.append(f"**Signed by:** `{info['signer_id']}`")
    lines.append(f"**Outcome:** {info['verification_label']}")
    lines.append(f"**Trust posture:** {info['trust_posture_summary']}")
    lines.append("")

    # Verdicts
    integrity_icon = "PASS" if info["integrity_pass"] else "FAIL"
    lines.append("## Verdicts")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|-------|--------|")
    lines.append(f"| Outcome | **{info['verification_label']}** |")
    lines.append(f"| Integrity | **{integrity_icon}** |")
    lines.append(f"| Claims | **{info['claims_status']}** |")
    lines.append("")

    if info["verification_state"] == "CREDIBLE_PASS":
        lines.append(
            "> **Credible pass**: the evidence is authentic (not tampered with),"
        )
        lines.append("> and the declared checks passed.")
        lines.append("")
    if info["verification_state"] == "HONEST_FAIL":
        lines.append(
            "> **Honest failure**: the evidence is authentic (not tampered with),"
        )
        lines.append("> and it proves this run violated the declared standards.")
        lines.append("")
    if info["verification_state"] == "TAMPERED":
        lines.append(
            "> **Tampered or invalid**: integrity failed, so cached claim results and parsed"
        )
        lines.append("> receipt details are not trustworthy evidence.")
        lines.append("")

    # What happened
    lines.append("## What Happened")
    lines.append("")
    if not info["integrity_pass"]:
        lines.append(
            "- **Warning:** parsed receipt contents are untrusted because integrity verification failed"
        )
    receipt_parts = []
    for rtype, count in sorted(info["type_counts"].items()):
        receipt_parts.append(f"{count} {rtype}")
    if receipt_parts:
        lines.append(
            f"- **{info['n_receipts']} receipts** recorded: {', '.join(receipt_parts)}"
        )
    else:
        lines.append(f"- **{info['n_receipts']} receipts** recorded")
    if info["providers"]:
        lines.append(f"- **Providers:** {', '.join(info['providers'])}")
    if info["models"]:
        lines.append(f"- **Models:** {', '.join(info['models'])}")
    if info["total_tokens"] > 0:
        lines.append(f"- **Total tokens:** {info['total_tokens']:,}")
    lines.append(
        f"- **Time window:** {info['timestamp_start']} to {info['timestamp_end']}"
    )
    lines.append("")

    # Integrity details
    lines.append("## Integrity Check")
    lines.append("")
    if info["integrity_pass"]:
        lines.append("All file hashes match. The Ed25519 signature is valid.")
        lines.append("This evidence has not been tampered with since creation.")
    else:
        lines.append("**FAILED**")
        lines.append("")
        for err in info["errors"]:
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            lines.append(f"- {msg}")
    lines.append("")

    # Claims details
    lines.append("## Claim Checks")
    lines.append("")
    if not info["claims_declared"]:
        lines.append("No claims were declared for this pack.")
    elif info["claims_status"] == "UNTRUSTED":
        lines.append("Integrity failed, so cached claim results are not authoritative.")
    else:
        lines.append("| Claim | Result |")
        lines.append("|-------|--------|")
        for cr in info["claim_results"]:
            status = "PASS" if cr.get("passed") else "FAIL"
            claim_id = cr.get("claim_id", "?")
            lines.append(f"| `{claim_id}` | **{status}** |")
    lines.append("")

    # What this proves / doesn't prove
    lines.append("## What This Proves")
    lines.append("")
    if info["integrity_pass"]:
        lines.append("- The recorded evidence is authentic (signed, hash-verified)")
    if info["verification_state"] == "CREDIBLE_PASS":
        lines.append(
            "- This is a credible pass: authentic evidence and declared checks passed"
        )
    elif info["verification_state"] == "HONEST_FAIL":
        lines.append(
            "- This is an honest failure: authentic evidence of a standards violation"
        )
    elif info["claims_declared"] and info["claims_pass"]:
        lines.append("- All declared behavioral checks passed")
    elif info["claims_declared"] and info["integrity_pass"]:
        lines.append("- Some declared behavioral checks failed (see above)")
        lines.append(
            "- This is an honest failure: authentic evidence of a standards violation"
        )
    lines.append("")

    lines.append("## What This Does NOT Prove")
    lines.append("")
    lines.append(
        "- That every action was recorded (only recorded actions are in the pack)"
    )
    lines.append("- That model outputs are correct or safe")
    lines.append(
        "- That receipts were honestly created (tamper-evidence, not source attestation)"
    )
    if info.get("has_witness"):
        witness = info.get("witness_info") or {}
        tsa = witness.get("tsa_url", "TSA")
        wtype = witness.get("witness_type", "rfc3161").upper()
        lines.append(
            f"- Timestamps are externally anchored via {wtype} witness ({tsa})"
        )
    else:
        lines.append("- That timestamps are externally anchored (local clock was used)")
    lines.append("- That the signer key was not compromised")
    lines.append("")

    # Verify
    lines.append("## Verify Independently")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 -m pip install assay-ai && assay verify-pack ./proof_pack/")
    lines.append("```")
    lines.append("")
    lines.append(
        "Or [verify in your browser](https://haserjian.github.io/assay-proof-gallery/verify.html) — no install, no account."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by [Assay](https://github.com/Haserjian/assay) — signed evidence for tool-using AI."
    )
    lines.append("")

    return "\n".join(lines)
