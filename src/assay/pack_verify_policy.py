"""Policy helpers for proof-pack verification."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from assay.manifest_schema import validate_manifest

_ALLOWED_SUPPLEMENTARY_DIRS = frozenset({"_unsigned"})
_ALLOWED_LEGACY_ROOT_SIDECARS = frozenset({"PACK_SUMMARY.md", "decision_credential.json"})


def validate_signed_manifest(manifest: Dict[str, Any]) -> List[str]:
    """Return schema validation errors for a signed manifest, failing closed."""
    try:
        return validate_manifest(manifest)
    except FileNotFoundError as exc:
        return [f"Manifest schema validation unavailable: {exc}"]


def inspect_pack_entries(manifest: Dict[str, Any], pack_dir: Path) -> List[str]:
    """Warn on non-kernel top-level entries outside the allowed supplementary namespace."""
    expected_files = set(manifest.get("expected_files") or [])
    warnings: List[str] = []

    for entry in sorted(pack_dir.iterdir(), key=lambda path: path.name):
        name = entry.name
        if name in expected_files:
            continue
        if entry.is_dir() and name in _ALLOWED_SUPPLEMENTARY_DIRS:
            continue
        if entry.is_file() and name in _ALLOWED_LEGACY_ROOT_SIDECARS:
            warnings.append(f"Legacy unsigned sidecar at pack root: {name}")
            continue
        warnings.append(f"Unexpected top-level pack entry ignored: {name}")

    return warnings