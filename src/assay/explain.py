"""Plain-English proof pack explanation.

Reads a proof pack directory and produces a human-readable summary
covering what happened, integrity status, claim results, what the
pack proves, and what it does NOT prove.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional


def explain_pack(pack_dir: Path) -> Dict[str, Any]:
    """Analyse a proof pack and return a structured explanation.

    Returns a dict with sections that can be rendered as text, markdown, or JSON.
    """
    pack_dir = Path(pack_dir)
    manifest_path = pack_dir / "pack_manifest.json"
    report_path = pack_dir / "verify_report.json"
    receipt_path = pack_dir / "receipt_pack.jsonl"

    # Load manifest
    manifest: Dict[str, Any] = {}
    attestation: Dict[str, Any] = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        attestation = manifest.get("attestation", {})

    # Load verify report
    report: Dict[str, Any] = {}
    if report_path.exists():
        report = json.loads(report_path.read_text())

    # Load receipts
    receipts: List[Dict[str, Any]] = []
    if receipt_path.exists():
        text = receipt_path.read_text().strip()
        if text:
            for line in text.split("\n"):
                line = line.strip()
                if line:
                    receipts.append(json.loads(line))

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
    run_id = attestation.get("run_id", report.get("run_id", "unknown"))
    n_receipts = len(receipts)
    timestamp_start = attestation.get("timestamp_start", "unknown")
    timestamp_end = attestation.get("timestamp_end", "unknown")

    # Integrity
    integrity_pass = report.get("passed", False)
    integrity_status = "PASSED" if integrity_pass else "FAILED"
    errors = report.get("errors", [])

    # Claims
    claim_verification = report.get("claim_verification")
    claims_present = claim_verification is not None
    claims_pass = claim_verification.get("passed", False) if claims_present else None
    claims_status = "PASSED" if claims_pass else ("FAILED" if claims_present else "NONE")
    claim_results: List[Dict[str, Any]] = []
    if claims_present:
        claim_results = claim_verification.get("results", [])

    # Signer
    signer_id = manifest.get("signer_id", "unknown")

    return {
        "pack_id": pack_id,
        "run_id": run_id,
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
        "claims_present": claims_present,
        "claims_status": claims_status,
        "claims_pass": claims_pass,
        "claim_results": claim_results,
        "signer_id": signer_id,
        "pack_dir": str(pack_dir),
    }


def render_text(info: Dict[str, Any]) -> str:
    """Render explanation as plain text."""
    lines: List[str] = []

    lines.append(f"Proof Pack: {info['pack_id']}")
    lines.append(f"Run ID:     {info['run_id']}")
    lines.append("")

    # What happened
    lines.append("WHAT HAPPENED")
    receipt_parts = []
    for rtype, count in sorted(info["type_counts"].items()):
        receipt_parts.append(f"{count} {rtype}")
    if receipt_parts:
        lines.append(f"  {info['n_receipts']} receipts recorded: {', '.join(receipt_parts)}")
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
    lines.append("")

    # Integrity
    lines.append("INTEGRITY CHECK")
    if info["integrity_pass"]:
        lines.append("  PASSED")
        lines.append("  All file hashes match. The Ed25519 signature is valid.")
        lines.append("  This evidence has not been tampered with since creation.")
    else:
        lines.append("  FAILED")
        for err in info["errors"]:
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            lines.append(f"  Error: {msg}")
    lines.append("")

    # Claims
    lines.append("CLAIM CHECKS")
    if not info["claims_present"]:
        lines.append("  No claims were declared for this pack.")
    elif info["claims_pass"]:
        lines.append("  PASSED")
        for cr in info["claim_results"]:
            status = "PASS" if cr.get("passed") else "FAIL"
            lines.append(f"  [{status}] {cr.get('claim_id', '?')}: {cr.get('expected', '')}")
    else:
        lines.append("  FAILED")
        for cr in info["claim_results"]:
            status = "PASS" if cr.get("passed") else "FAIL"
            lines.append(f"  [{status}] {cr.get('claim_id', '?')}: {cr.get('expected', '')} (actual: {cr.get('actual', '?')})")
    lines.append("")

    # What this proves
    lines.append("WHAT THIS PROVES")
    lines.append("  The recorded evidence is authentic (signed, hash-verified).")
    if info["claims_present"] and info["claims_pass"]:
        lines.append("  The declared behavioral checks all passed.")
    elif info["claims_present"]:
        lines.append("  Some declared behavioral checks failed (see above).")
        lines.append("  This is an honest failure: the evidence is authentic,")
        lines.append("  and it proves the run did not meet the declared standards.")
    lines.append("")

    # What this does NOT prove
    lines.append("WHAT THIS DOES NOT PROVE")
    lines.append("  - That every action was recorded (only recorded actions are in the pack)")
    lines.append("  - That model outputs are correct or safe")
    lines.append("  - That receipts were honestly created (tamper-evidence, not source attestation)")
    lines.append("  - That timestamps are externally anchored (local clock was used)")
    lines.append("  - That the signer key was not compromised")
    lines.append("")

    # How to verify
    lines.append("VERIFY INDEPENDENTLY")
    lines.append(f"  pip install assay-ai && assay verify-pack {info['pack_dir']}")
    lines.append("")

    return "\n".join(lines)
