"""
Receipt schema version registry.

Tracks known schema versions and their field definitions.
Provides compatibility checks for mixed-version packs.

v0: Defines the registry pattern.  3.0 is the only version.
    parent_receipt_id is an optional field in 3.0 (backward-compatible).
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Version registry
# ---------------------------------------------------------------------------

CURRENT_VERSION = "3.0"

# Required fields for basic receipt validity (any version).
CORE_FIELDS: FrozenSet[str] = frozenset({"receipt_id", "type", "timestamp"})

# Per-version field definitions.
# "required" = must be present for the receipt to be valid at that version.
# "optional" = recognized fields (won't cause warnings in strict validation).
_VERSIONS: Dict[str, Dict[str, FrozenSet[str]]] = {
    "3.0": {
        "required": CORE_FIELDS,
        "optional": frozenset({
            "schema_version",
            "seq",
            "parent_receipt_id",
            "model",
            "provider",
            "store_prompts",
            "store_responses",
            "token_count",
            "cost",
            "latency_ms",
            "domain",
            "receipt_type",
            "ts",
            "verdict",
            "tool",
            "dignity_composite",
            # Trace metadata (added by store)
            "_trace_id",
            "_stored_at",
        }),
    },
}

KNOWN_VERSIONS: FrozenSet[str] = frozenset(_VERSIONS.keys())


def _parse_version(v: str) -> Tuple[int, int]:
    """Parse 'major.minor' into (major, minor)."""
    parts = v.split(".")
    if len(parts) != 2:
        raise ValueError(f"Invalid schema version format: {v!r} (expected 'major.minor')")
    return int(parts[0]), int(parts[1])


def is_compatible(receipt_version: str, expected_version: str) -> bool:
    """Check if a receipt version is compatible with an expected version.

    Compatibility rule: same major version, receipt minor <= expected minor.
    e.g. receipt 3.0 is compatible with expected 3.0 or 3.1.
         receipt 3.1 is NOT compatible with expected 3.0 (newer features).
         receipt 4.0 is NOT compatible with expected 3.0 (major bump).
    """
    if receipt_version == expected_version:
        return True
    try:
        r_major, r_minor = _parse_version(receipt_version)
        e_major, e_minor = _parse_version(expected_version)
    except (ValueError, IndexError):
        return False
    return r_major == e_major and r_minor <= e_minor


def required_fields(version: str) -> FrozenSet[str]:
    """Return required fields for a schema version."""
    v = _VERSIONS.get(version)
    if v is None:
        return CORE_FIELDS  # Unknown version: fall back to core
    return v["required"]


def optional_fields(version: str) -> FrozenSet[str]:
    """Return recognized optional fields for a schema version."""
    v = _VERSIONS.get(version)
    if v is None:
        return frozenset()
    return v["optional"]


def validate_receipt_fields(
    receipt: Dict[str, Any],
    version: Optional[str] = None,
) -> List[str]:
    """Validate receipt fields against its declared schema version.

    Returns a list of error messages (empty = valid).
    """
    errors: List[str] = []
    v = version or receipt.get("schema_version", CURRENT_VERSION)

    for field in required_fields(v):
        if field not in receipt:
            errors.append(f"Missing required field: {field}")

    return errors


__all__ = [
    "CURRENT_VERSION",
    "CORE_FIELDS",
    "KNOWN_VERSIONS",
    "is_compatible",
    "required_fields",
    "optional_fields",
    "validate_receipt_fields",
]
