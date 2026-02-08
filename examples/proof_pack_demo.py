#!/usr/bin/env python3
"""
Assay Proof Pack Demo

Demonstrates the complete Proof Pack v0 flow in ~30 seconds:
1. Create receipts (no API key needed)
2. Build a signed Proof Pack with claims
3. Verify the pack
4. Show how different claims produce different outcomes

Run:
    PYTHONPATH=src python examples/proof_pack_demo.py

Or if installed:
    python examples/proof_pack_demo.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from assay.claim_verifier import ClaimSpec
from assay.integrity import verify_pack_manifest
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.run_cards import get_all_builtin_cards


def make_receipt(receipt_type: str, seq: int, **extra):
    """Create a minimal valid receipt."""
    r = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": receipt_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
        "seq": seq,
    }
    r.update(extra)
    return r


def main():
    print("=" * 60)
    print("ASSAY PROOF PACK DEMO")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        keys_dir = Path(tmpdir) / "keys"
        ks = AssayKeyStore(keys_dir=keys_dir)
        ks.generate_key("demo-signer")

        # --- Step 1: Create receipts ---
        print("\n[1] Creating receipts...")
        receipts = [
            make_receipt("model_call", 0, model_id="gpt-4", total_tokens=57),
            make_receipt("model_call", 1, model_id="gpt-4", total_tokens=217),
            make_receipt("model_call", 2, model_id="gpt-4", total_tokens=89),
            make_receipt("guardian_verdict", 3, verdict="allow", tool="web_search"),
            make_receipt("model_call", 4, model_id="gpt-4", total_tokens=156),
        ]
        print(f"   Created {len(receipts)} receipts")
        for r in receipts:
            print(f"   - {r['type']:20s} seq={r['seq']} id={r['receipt_id']}")

        # --- Step 2: Define claims ---
        print("\n[2] Defining claims...")
        claims = [
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
                claim_id="timestamps_ok",
                description="Timestamps are monotonic",
                check="timestamps_monotonic",
            ),
            ClaimSpec(
                claim_id="no_breakglass",
                description="No override receipts",
                check="no_receipt_type",
                params={"receipt_type": "breakglass"},
            ),
        ]
        for c in claims:
            print(f"   - {c.claim_id}: {c.description}")

        # --- Step 3: Build Proof Pack ---
        print("\n[3] Building Proof Pack...")
        pack_dir = Path(tmpdir) / "demo_pack"
        pack = ProofPack(
            run_id="demo-run-001",
            entries=receipts,
            signer_id="demo-signer",
            claims=claims,
            mode="shadow",
        )
        out = pack.build(pack_dir, keystore=ks)

        print(f"   Output: {out}/")
        for f in sorted(out.iterdir()):
            print(f"   - {f.name:30s} {f.stat().st_size:>6,} bytes")

        # --- Step 4: Read attestation ---
        print("\n[4] Attestation summary:")
        manifest = json.loads((out / "pack_manifest.json").read_text())
        att = manifest["attestation"]
        print(f"   Pack ID:    {att['pack_id']}")
        print(f"   Integrity:  {att['receipt_integrity']}")
        print(f"   Claims:     {att['claim_check']}")
        print(f"   Receipts:   {att['n_receipts']}")
        print(f"   Mode:       {att['mode']}")
        print(f"   Fingerprint: {att['discrepancy_fingerprint'][:16]}...")

        # --- Step 5: Verify ---
        print("\n[5] Verifying pack...")
        result = verify_pack_manifest(manifest, out, ks)
        status = "PASSED" if result.passed else "FAILED"
        print(f"   Verification: {status}")
        if result.warnings:
            for w in result.warnings:
                print(f"   Warning: {w}")

        # --- Step 6: P1 Demo -- same receipts, stricter claims ---
        print("\n[6] P1 Demo: Same receipts, stricter claims...")
        strict_claims = [
            ClaimSpec(
                claim_id="need_100_receipts",
                description="At least 100 receipts",
                check="receipt_count_ge",
                params={"min_count": 100},
                severity="critical",
            ),
        ]
        strict_dir = Path(tmpdir) / "strict_pack"
        strict_pack = ProofPack(
            run_id="demo-run-001-strict",
            entries=receipts,  # same receipts
            signer_id="demo-signer",
            claims=strict_claims,
            mode="shadow",
        )
        strict_out = strict_pack.build(strict_dir, keystore=ks)
        strict_manifest = json.loads((strict_out / "pack_manifest.json").read_text())
        strict_att = strict_manifest["attestation"]

        print(f"   Integrity:  {strict_att['receipt_integrity']}  (same receipts)")
        print(f"   Claims:     {strict_att['claim_check']}  (stricter claims)")
        print("   -> Integrity PASS + Claim FAIL = honest failure report")

        # --- Step 7: Built-in RunCards ---
        print("\n[7] Built-in RunCards:")
        for card in get_all_builtin_cards():
            print(f"   - {card.card_id}: {card.description}")

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("\nCLI equivalents:")
    print("  assay proof-pack <trace_id>")
    print("  assay proof-pack <trace_id> -c guardian_enforcement -c no_breakglass")
    print("  assay verify-pack ./proof_pack_<trace_id>/")
    print("  assay verify-pack ./proof_pack_<trace_id>/ --require-claim-pass")


if __name__ == "__main__":
    main()
