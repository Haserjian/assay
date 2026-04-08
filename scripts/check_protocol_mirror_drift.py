#!/usr/bin/env python3
"""
Drift guard for protocol mirrors.

Assay's verifier and runtime work mirrors a small set of normative files from
``Haserjian/assay-protocol`` (canonical) into this repository. The mirror can
silently drift from the canonical source. This script makes that drift
detectable in CI.

Modes
-----
``--mode=check`` (default)
    For every mirror entry in the manifest, fetch the canonical file from
    ``Haserjian/assay-protocol`` at the pinned commit, apply the declared
    transform, and byte-compare the result against the checked-in mirror.
    Exit 1 on any drift.

``--mode=refresh``
    For every mirror entry, fetch + transform as above, then **write** the
    result to the mirror path. Used by maintainers to deliberately bump the
    pin and re-sync the mirror. The script does not commit; that's a separate
    deliberate human action.

Manifest format
---------------
JSON file with this shape:

.. code-block:: json

    {
      "canonical_repo": "Haserjian/assay-protocol",
      "canonical_ref": "<full commit sha>",
      "mirrors": [
        {
          "canonical_path": "schemas/rce_episode_contract.schema.json",
          "mirror_path":    "src/assay/schemas/rce_episode_contract.schema.json",
          "transform":      "rewrite_schema_id",
          "transform_args": {
            "from_url": "https://github.com/Haserjian/assay-protocol/schemas/rce_episode_contract.schema.json",
            "to_url":   "https://github.com/Haserjian/assay/schemas/rce_episode_contract.schema.json"
          }
        }
      ]
    }

The pin must be a full commit SHA. Tags or moving refs like ``main`` are
forbidden because they break the determinism premise.

Refresh ritual
--------------
1. Bump ``canonical_ref`` in the manifest to the new commit SHA.
2. Run ``python scripts/check_protocol_mirror_drift.py --mode=refresh
   tools/protocol_mirror/manifest.json``.
3. Commit both the manifest bump and the updated mirror file in one PR.
4. CI re-runs the check on the new state.

Network
-------
Uses ``gh api`` for canonical fetches. In CI, the default ``GITHUB_TOKEN``
is sufficient because ``Haserjian/assay-protocol`` is public.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Transforms
# ---------------------------------------------------------------------------

TRANSFORMS: dict[str, Callable[..., bytes]] = {}


def _register(name: str) -> Callable[[Callable[..., bytes]], Callable[..., bytes]]:
    def decorator(fn: Callable[..., bytes]) -> Callable[..., bytes]:
        TRANSFORMS[name] = fn
        return fn

    return decorator


@_register("identity")
def _identity(content: bytes, **_: Any) -> bytes:
    """Return content unchanged."""
    return content


@_register("rewrite_schema_id")
def _rewrite_schema_id(content: bytes, *, from_url: str, to_url: str, **_: Any) -> bytes:
    """Replace ``from_url`` with ``to_url`` in the canonical bytes.

    The canonical schema's ``$id`` field points at the protocol repo's URL
    space; the mirror legitimately serves the same schema under the assay
    repo's URL space. This transform swaps that one substring and leaves
    every other byte intact.

    Fails loudly if ``from_url`` is not present in the canonical content,
    so a stale or mis-targeted manifest entry is caught immediately rather
    than silently passing.
    """
    from_bytes = from_url.encode("utf-8")
    to_bytes = to_url.encode("utf-8")
    if from_bytes not in content:
        raise ValueError(
            f"transform 'rewrite_schema_id' could not find from_url={from_url!r} "
            "in canonical content (manifest is stale or mis-targeted)"
        )
    return content.replace(from_bytes, to_bytes)


# ---------------------------------------------------------------------------
# Canonical fetch
# ---------------------------------------------------------------------------


def fetch_canonical(repo: str, ref: str, path: str) -> bytes:
    """Fetch a file from a public GitHub repo at a pinned ref via ``gh api``.

    Returns the raw file bytes (base64-decoded from the contents API
    response). Raises ``subprocess.CalledProcessError`` on API failure.

    Uses the query-string form ``?ref=<sha>`` because the GitHub contents
    API ignores form-field arguments on GET requests for this endpoint.
    """
    endpoint = f"repos/{repo}/contents/{path}?ref={ref}"
    cmd = ["gh", "api", endpoint, "--jq", ".content"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return base64.b64decode(result.stdout)


def apply_transform(canonical: bytes, entry: dict[str, Any]) -> bytes:
    name = entry["transform"]
    if name not in TRANSFORMS:
        raise KeyError(f"unknown transform: {name!r} (known: {sorted(TRANSFORMS)})")
    args = entry.get("transform_args") or {}
    return TRANSFORMS[name](canonical, **args)


# ---------------------------------------------------------------------------
# Diff reporting
# ---------------------------------------------------------------------------


def report_drift(entry: dict[str, Any], expected: bytes, actual: bytes, manifest: dict[str, Any]) -> None:
    """Print a human-readable drift report for a single mirror entry."""
    print(f"DRIFT: {entry['mirror_path']}")
    print(f"  canonical: {manifest['canonical_repo']}@{manifest['canonical_ref'][:8]}:{entry['canonical_path']}")
    print(f"  transform: {entry['transform']}")
    print(f"  expected size: {len(expected)} bytes")
    print(f"  actual size:   {len(actual)} bytes")
    if not actual:
        print("  (mirror file is missing or empty)")
        return

    # Try to give a useful first-difference hint without dumping the whole file.
    try:
        expected_lines = expected.decode("utf-8").splitlines()
        actual_lines = actual.decode("utf-8").splitlines()
        for i, (e, a) in enumerate(zip(expected_lines, actual_lines)):
            if e != a:
                print(f"  first differing line: {i + 1}")
                print(f"    expected: {e[:120]}")
                print(f"    actual:   {a[:120]}")
                break
        else:
            if len(expected_lines) != len(actual_lines):
                print(f"  line counts differ: expected={len(expected_lines)}, actual={len(actual_lines)}")
    except UnicodeDecodeError:
        print("  (binary diff — line-level summary skipped)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Drift guard for protocol mirrors. Compares checked-in mirror files "
        "against canonical sources at a pinned ref.",
    )
    parser.add_argument("manifest", type=Path, help="Path to manifest JSON file.")
    parser.add_argument(
        "--mode",
        choices=["check", "refresh"],
        default="check",
        help="check (default): fail on drift. refresh: rewrite mirror files from canonical.",
    )
    args = parser.parse_args()

    manifest_path = args.manifest if args.manifest.is_absolute() else REPO_ROOT / args.manifest
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text())
    canonical_repo = manifest["canonical_repo"]
    canonical_ref = manifest["canonical_ref"]

    if len(canonical_ref) != 40 or not all(c in "0123456789abcdef" for c in canonical_ref):
        print(
            f"ERROR: canonical_ref must be a full 40-char commit SHA, got {canonical_ref!r}. "
            "Tags or moving refs like 'main' are forbidden.",
            file=sys.stderr,
        )
        return 2

    print(f"Manifest: {manifest_path.relative_to(REPO_ROOT)}")
    print(f"Canonical: {canonical_repo}@{canonical_ref[:8]}")
    print(f"Mode: {args.mode}")
    print()

    failed = False
    for entry in manifest["mirrors"]:
        canonical_path = entry["canonical_path"]
        mirror_path = REPO_ROOT / entry["mirror_path"]

        try:
            canonical_bytes = fetch_canonical(canonical_repo, canonical_ref, canonical_path)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: failed to fetch {canonical_repo}:{canonical_path}@{canonical_ref[:8]}", file=sys.stderr)
            print(f"  gh api stderr: {e.stderr}", file=sys.stderr)
            failed = True
            continue

        try:
            expected = apply_transform(canonical_bytes, entry)
        except (ValueError, KeyError) as e:
            print(f"ERROR: transform failed for {entry['mirror_path']}: {e}", file=sys.stderr)
            failed = True
            continue

        if args.mode == "refresh":
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            mirror_path.write_bytes(expected)
            print(f"REFRESH: wrote {entry['mirror_path']} ({len(expected)} bytes) "
                  f"from {canonical_repo}@{canonical_ref[:8]}:{canonical_path}")
            continue

        # check mode
        actual = mirror_path.read_bytes() if mirror_path.exists() else b""
        if expected != actual:
            report_drift(entry, expected, actual, manifest)
            failed = True
        else:
            print(f"OK: {entry['mirror_path']} byte-equals expected ({len(expected)} bytes)")

    if failed:
        print()
        print(
            "Mirror drift detected. To reconcile, run:",
            file=sys.stderr,
        )
        print(
            f"  python scripts/check_protocol_mirror_drift.py --mode=refresh {args.manifest}",
            file=sys.stderr,
        )
        print(
            "Then review the changes and commit the manifest pin and the updated mirror file together.",
            file=sys.stderr,
        )
        return 1

    print()
    print("All mirrors byte-equal expected. No drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
