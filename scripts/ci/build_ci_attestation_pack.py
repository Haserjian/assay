#!/usr/bin/env python3
"""Build a minimal CI-bound proof pack signed by the active signer."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from assay.trust.ci_org_bootstrap import build_ci_smoke_pack


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a minimal proof pack for ci-org trust gating.",
    )
    parser.add_argument(
        "--output-dir",
        default="ci_org_smoke_pack",
        help="Directory to write the proof pack into",
    )
    parser.add_argument(
        "--signer",
        default=None,
        help="Signer ID to use (defaults to active signer)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result_dir = build_ci_smoke_pack(
        output_dir=Path(args.output_dir),
        signer_id=args.signer,
    )
    payload = {"status": "ok", "pack_dir": str(result_dir)}
    if args.json:
        print(json.dumps(payload))
    else:
        print(f"pack_dir={result_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
