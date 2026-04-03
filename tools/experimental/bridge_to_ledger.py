#!/usr/bin/env python3
"""Bridge: Receipt pack → Assay Proof Pack → Ledger entry.

Takes a receipt_pack.jsonl (from Loom or any source), builds an Assay proof pack,
verifies it, and produces a ledger entry suitable for appending to assay-ledger.

This is the missing Connection 3 in the vertical proof path:
  Maestro → TurnLedger → Receipt/EventStore → [THIS BRIDGE] → Assay-ledger

Usage:
    python3 tools/experimental/bridge_to_ledger.py /tmp/vertical_proof_001
    python3 tools/experimental/bridge_to_ledger.py /tmp/vertical_proof_001 --ledger ~/assay-ledger/ledger.jsonl
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from assay.proof_pack import ProofPack, verify_proof_pack


def compute_prev_entry_hash(ledger_path: Path) -> str:
    """Compute prev_entry_hash from the last line of the existing ledger."""
    genesis = hashlib.sha256(b"assay-ledger-genesis-v1").hexdigest()

    if not ledger_path.exists():
        return genesis

    lines = ledger_path.read_text().strip().splitlines()
    if not lines:
        return genesis

    last_line = lines[-1]
    return hashlib.sha256(last_line.encode("utf-8")).hexdigest()


def build_ledger_entry(
    *,
    pack_manifest: Dict[str, Any],
    verify_passed: bool,
    n_receipts: int,
    source_repo: str,
    prev_entry_hash: str,
    mode: str = "shadow",
    witness_status: str = "unwitnessed",
) -> Dict[str, Any]:
    """Build a ledger entry from a verified proof pack."""
    attestation = pack_manifest.get("attestation", {})

    entry = {
        "schema_version": 1,
        "pack_root_sha256": attestation.get("pack_root_sha256", pack_manifest.get("pack_root_sha256", "")),
        "pack_id": attestation.get("pack_id", "unknown"),
        "receipt_integrity": attestation.get("receipt_integrity", "PASS" if verify_passed else "FAIL"),
        "claim_check": attestation.get("claim_check", "N/A"),
        "n_receipts": n_receipts,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "source_repo": source_repo,
        "witness_status": witness_status,
        "prev_entry_hash": prev_entry_hash,
    }

    # Optional fields
    ts_start = attestation.get("timestamp_start")
    ts_end = attestation.get("timestamp_end")
    if ts_start:
        entry["timestamp_start"] = ts_start
    if ts_end:
        entry["timestamp_end"] = ts_end
    if mode:
        entry["mode"] = mode
    entry["assurance_level"] = "L0"

    signer = attestation.get("signer_pubkey_sha256")
    if signer:
        entry["signer_pubkey_sha256"] = signer

    entry["verifier_version"] = "1.19.0"

    return entry


def main(
    proof_dir: Path,
    ledger_path: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Bridge a receipt pack into a ledger entry."""
    proof_dir = Path(proof_dir)

    # Read receipt pack
    receipt_pack_path = proof_dir / "receipt_pack.jsonl"
    if not receipt_pack_path.exists():
        print(f"ERROR: {receipt_pack_path} not found", file=sys.stderr)
        sys.exit(1)

    receipts = []
    for line in receipt_pack_path.read_text().splitlines():
        line = line.strip()
        if line:
            receipts.append(json.loads(line))

    if not receipts:
        print("ERROR: receipt_pack.jsonl is empty", file=sys.stderr)
        sys.exit(1)

    # Read metadata if present
    metadata_path = proof_dir / "proof_metadata.json"
    metadata = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())

    source_repo = metadata.get("source_repo", "Haserjian/Loom")
    run_id = metadata.get("run_id") or metadata.get("trace_id") or "unknown"

    print(f"Bridge: {len(receipts)} receipts from {source_repo}")
    print(f"  run_id: {run_id}")

    # Build proof pack
    pack_output = proof_dir / "assay_pack"
    pack = ProofPack(
        run_id=run_id,
        entries=receipts,
        signer_id="vertical_proof_bridge",
        mode="shadow",
    )
    pack_dir = pack.build(pack_output)
    print(f"  Proof pack built: {pack_dir}")

    # Read manifest
    manifest_path = pack_dir / "pack_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    attestation = manifest.get("attestation", {})
    print(f"  pack_id: {attestation.get('pack_id')}")
    print(f"  receipt_integrity: {attestation.get('receipt_integrity')}")
    print(f"  pack_root_sha256: {attestation.get('pack_root_sha256', '')[:16]}...")

    # Verify proof pack
    result = verify_proof_pack(manifest, pack_dir)
    print(f"  Verification: {'PASS' if result.passed else 'FAIL'}")
    if result.errors:
        for err in result.errors:
            print(f"    ERROR: {err.message}")
    if result.warnings:
        for warn in result.warnings:
            print(f"    WARN: {warn.message}")

    # Compute prev_entry_hash
    if ledger_path:
        prev_hash = compute_prev_entry_hash(Path(ledger_path))
    else:
        prev_hash = hashlib.sha256(b"assay-ledger-genesis-v1").hexdigest()

    # Build ledger entry
    entry = build_ledger_entry(
        pack_manifest=manifest,
        verify_passed=result.passed,
        n_receipts=len(receipts),
        source_repo=source_repo,
        prev_entry_hash=prev_hash,
        mode="shadow",
        witness_status="unwitnessed",
    )

    # Output
    entry_json = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    print(f"\n--- Ledger entry ---")
    print(json.dumps(entry, indent=2))

    entry_hash = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()
    print(f"\nEntry hash (for next prev_entry_hash): {entry_hash}")

    # Write to proof dir
    entry_path = proof_dir / "ledger_entry.json"
    with open(entry_path, "w") as f:
        json.dump(entry, f, indent=2)
    print(f"Written to: {entry_path}")

    # Write compact JSONL line for append
    entry_jsonl_path = proof_dir / "ledger_entry.jsonl"
    with open(entry_jsonl_path, "w") as f:
        f.write(entry_json + "\n")
    print(f"JSONL line: {entry_jsonl_path}")

    if not dry_run and ledger_path:
        ledger_path = Path(ledger_path)
        if ledger_path.exists():
            with open(ledger_path, "a") as f:
                f.write(entry_json + "\n")
            print(f"\nAppended to: {ledger_path}")
        else:
            print(f"\nLedger not found: {ledger_path} (dry run only)")

    return entry


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bridge receipt pack to assay-ledger entry")
    parser.add_argument("proof_dir", type=Path, help="Directory containing receipt_pack.jsonl")
    parser.add_argument("--ledger", type=Path, default=None, help="Path to ledger.jsonl (for hash chain)")
    parser.add_argument("--append", action="store_true", help="Actually append to ledger (default: dry run)")
    args = parser.parse_args()

    main(args.proof_dir, ledger_path=args.ledger, dry_run=not args.append)
