#!/usr/bin/env python3
"""Import a ci-org signer and create a temporary trust-policy overlay for CI."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from assay.trust.ci_org_bootstrap import bootstrap_ci_org_signer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bootstrap a ci-org signer into the local Assay keystore.",
    )
    parser.add_argument("--policy-dir", default="trust", help="Source trust policy directory")
    parser.add_argument("--output-dir", required=True, help="Temporary overlay policy directory")
    parser.add_argument("--signer", default="ci-org-main", help="Signer ID to import and activate")
    parser.add_argument("--pub-file", required=True, help="Path to signer public key .pub.b64")
    parser.add_argument("--key-file", required=True, help="Path to signer private key .key.b64")
    parser.add_argument(
        "--expected-fingerprint",
        default=None,
        help="Expected SHA-256 fingerprint for the imported public key",
    )
    parser.add_argument(
        "--github-output",
        default=None,
        help="Optional GitHub Actions output file to populate",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = bootstrap_ci_org_signer(
        policy_dir=Path(args.policy_dir),
        output_dir=Path(args.output_dir),
        signer_id=args.signer,
        pub_b64=Path(args.pub_file).read_text(encoding="utf-8"),
        key_b64=Path(args.key_file).read_text(encoding="utf-8"),
        expected_fingerprint=args.expected_fingerprint,
    )

    payload = {
        "status": "ok",
        "signer_id": result.signer_id,
        "fingerprint": result.fingerprint,
        "policy_dir": str(result.policy_dir),
    }

    if args.github_output:
        output_path = Path(args.github_output)
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(f"signer_id={result.signer_id}\n")
            handle.write(f"fingerprint={result.fingerprint}\n")
            handle.write(f"policy_dir={result.policy_dir}\n")

    if args.json:
        print(json.dumps(payload))
    else:
        print(
            f"bootstrapped signer={result.signer_id} "
            f"fingerprint={result.fingerprint} "
            f"policy_dir={result.policy_dir}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
