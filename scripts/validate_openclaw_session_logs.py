#!/usr/bin/env python3
"""Validate real exported OpenClaw session logs against the current importer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from assay.openclaw_validation import (
    DEFAULT_ALLOWLIST,
    DEFAULT_OPENCLAW_HOME,
    render_openclaw_live_validation,
    validate_openclaw_session_logs,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Import real exported OpenClaw session logs if they exist locally, "
            "or return an explicit blocker if no real runtime data is available."
        )
    )
    parser.add_argument(
        "--openclaw-home",
        type=Path,
        default=DEFAULT_OPENCLAW_HOME,
        help="OpenClaw runtime home to inspect (default: ~/.openclaw).",
    )
    parser.add_argument(
        "--session-log",
        action="append",
        dest="session_logs",
        type=Path,
        help="Validate this exported session log directly. May be provided multiple times.",
    )
    parser.add_argument(
        "--allowlist",
        action="append",
        default=None,
        help=(
            "Browser allowlist pattern used during import. Defaults to '*' so "
            "shape-fit validation does not turn every browser row into a policy denial."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = validate_openclaw_session_logs(
        openclaw_home=args.openclaw_home,
        session_log_paths=args.session_logs,
        allowlist=args.allowlist or DEFAULT_ALLOWLIST,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(render_openclaw_live_validation(result))

    if result.status == "blocked":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
