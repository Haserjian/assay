#!/usr/bin/env python3
"""Build a minimal proof pack for VendorQ demo.

Usage:
    python examples/vendorq/build_demo_pack.py

Produces: examples/vendorq/demo_pack/
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

DEMO_DIR = Path(__file__).resolve().parent
PACK_DIR = DEMO_DIR / "demo_pack"
KEYS_DIR = DEMO_DIR / ".keys"


def main() -> None:
    ks = AssayKeyStore(keys_dir=KEYS_DIR)
    ks.generate_key("vendorq-demo")

    ts = datetime.now(timezone.utc).isoformat()
    receipts = [
        {
            "receipt_id": f"r{i}",
            "type": "model_call",
            "timestamp": ts,
            "schema_version": "3.0",
            "seq": i,
            "model_id": "gpt-4o",
            "provider": "openai",
            "input_tokens": 120 + i * 10,
            "output_tokens": 45 + i * 5,
            "total_tokens": 165 + i * 15,
        }
        for i in range(1, 6)
    ]

    pack = ProofPack(
        run_id="vendorq-demo-run",
        entries=receipts,
        signer_id="vendorq-demo",
    )
    pack_dir = pack.build(PACK_DIR, keystore=ks)
    print(f"Pack built: {pack_dir}")


if __name__ == "__main__":
    main()
