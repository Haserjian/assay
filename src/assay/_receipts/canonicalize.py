"""
JCS (JSON Canonicalization Scheme) helpers for receipts.

This module implements RFC 8785 canonicalization for deterministic hashing.

Critical properties:
- Identical data → identical bytes (always)
- No whitespace ambiguity
- Sorted keys
- IEEE 754 exact float representation
- Frozen container unwrapping

Usage:
    from assay._receipts.canonicalize import to_jcs_bytes, compute_payload_hash

    receipt = ProphecyStone(...)
    canonical_bytes = to_jcs_bytes(receipt)
    payload_hash = compute_payload_hash(receipt)
"""

import hashlib
from typing import Any

from .merkle import compute_merkle_root
from assay._receipts.jcs import canonicalize as _jcs_canonicalize
from assay._receipts.compat.pyd import unwrap_frozen, strip_signatures
try:
    # Prefer normal package import within the project
    from .compatibility import normalize_legacy_fields  # type: ignore
except Exception:
    # Fallback: load compatibility module directly from package directory to
    # avoid collisions with a top-level `receipts` package installed on the
    # system or present on PYTHONPATH. This ensures we always use the
    # repository-local adapter.
    from importlib.machinery import SourceFileLoader
    from importlib.util import spec_from_loader, module_from_spec
    from pathlib import Path

    _compat_path = Path(__file__).resolve().parent / "compatibility.py"
    if _compat_path.exists():
        _loader = SourceFileLoader("_repo_receipts_compat", str(_compat_path))
        _spec = spec_from_loader(_loader.name, _loader)
        _mod = module_from_spec(_spec) if _spec is not None else None
        if _mod is not None:
            _loader.exec_module(_mod)
            normalize_legacy_fields = getattr(_mod, "normalize_legacy_fields")
        else:
            def normalize_legacy_fields(x):
                return x
    else:
        def normalize_legacy_fields(x):
            return x


def to_jcs_bytes(obj: Any) -> bytes:
    """
    Serialize object to JCS (RFC 8785) canonical bytes.
    """
    normalized = _prepare_for_canonicalization(obj)
    return _jcs_canonicalize(normalized)


def _prepare_for_canonicalization(obj: Any) -> Any:
    """Normalize payloads before canonicalization/hashing."""
    if hasattr(obj, "model_dump"):
        data = obj.model_dump(mode="json")
    elif hasattr(obj, "dict"):
        data = obj.dict()
    elif isinstance(obj, dict):
        data = obj
    else:
        data = obj

    unwrapped = unwrap_frozen(data)

    # Layer 3 (normalize_legacy_fields) verified vestigial 2026-03-25:
    # compatibility.py does not exist, function is always identity,
    # zero external callers, zero test dependencies.
    # Bypassed in proof-critical path — do not re-add without evidence.

    try:
        unwrapped = strip_signatures(unwrapped)
    except Exception:
        pass

    return unwrapped


# ---------------------------------------------------------------------------
# Layer 2: Explicit receipt projection for hashing/signing
# ---------------------------------------------------------------------------

# Versioned signature field exclusion sets.  Single source of truth for
# which fields are stripped before hashing.  v0 matches the historical
# strip_signatures() behaviour in compat/pyd.py.
_SIGNATURE_FIELD_SETS: dict[str, frozenset[str]] = {
    "v0": frozenset({
        "signatures",
        "signature",
        "cose_signature",
        "receipt_hash",
        "anchor",
    }),
}


def prepare_receipt_for_hashing(receipt: Any, *, version: str = "v0") -> dict:
    """Layer 2: project a receipt into a plain dict suitable for hashing.

    1. Converts Pydantic models to plain dicts (``model_dump`` / ``.dict()``).
    2. Recursively unwraps frozen containers.
    3. Strips signature-related fields per the versioned exclusion set.

    No legacy normalization is performed (Layer 3 is vestigial).
    No silent ``except`` passes — failures are raised to the caller.

    Args:
        receipt: Receipt object (Pydantic model, dict, or dict-like).
        version: Exclusion-set version (currently only ``"v0"``).

    Returns:
        Plain dict with signature fields removed, ready for
        ``jcs.canonicalize()``.

    Raises:
        ValueError: If *version* is unknown.
        TypeError: If *receipt* cannot be converted to a dict.
    """
    exclusions = _SIGNATURE_FIELD_SETS.get(version)
    if exclusions is None:
        raise ValueError(
            f"Unknown signature strip version: {version!r}. "
            f"Known: {sorted(_SIGNATURE_FIELD_SETS)}"
        )

    if hasattr(receipt, "model_dump"):
        data = receipt.model_dump(mode="json")
    elif hasattr(receipt, "dict") and not isinstance(receipt, dict):
        data = receipt.dict()
    elif isinstance(receipt, dict):
        data = receipt
    else:
        raise TypeError(
            f"Cannot convert {type(receipt).__name__} to dict for hashing"
        )

    data = unwrap_frozen(data)
    return {k: v for k, v in data.items() if k not in exclusions}


def compute_payload_hash(obj: Any, algorithm: str = "sha256") -> str:
    """
    Compute payload hash (excludes signature fields).

    This is the hash used for signing receipts. Signatures are added
    AFTER computing this hash (detached signature pattern).

    Args:
        obj: Receipt object
        algorithm: Hash algorithm (default: sha256)

    Returns:
        Hex-encoded hash string
    """
    canonical_bytes = _jcs_canonicalize(_prepare_for_canonicalization(obj))

    if algorithm == "sha256":
        h = hashlib.sha256(canonical_bytes)
    elif algorithm == "sha512":
        h = hashlib.sha512(canonical_bytes)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Return algorithm-prefixed digest for clarity/stability across environments
    return f"{algorithm}:{h.hexdigest()}"


def compute_payload_hash_hex(obj: Any, algorithm: str = "sha256") -> str:
    """
    Convenience shim returning the raw hex digest (no algorithm prefix).

    Some callers historically expect a plain hex digest; this helper
    preserves that contract while the canonical prefixed form remains
    the canonical API.
    """
    pref = compute_payload_hash(obj, algorithm=algorithm)
    if ":" in pref:
        return pref.split(":", 1)[1]
    return pref


def verify_jcs_stability(obj: Any) -> bool:
    """
    Verify JCS stability: same object → same bytes (twice).

    Args:
        obj: Object to verify

    Returns:
        True if stable (canonical bytes identical across 2 serializations)
    """
    bytes1 = to_jcs_bytes(obj)
    bytes2 = to_jcs_bytes(obj)
    return bytes1 == bytes2


# canonicalize.compute_merkle_root is delegated to the centralized
# receipts.merkle.compute_merkle_root implementation to avoid drift.


__all__ = [
    "to_jcs_bytes",
    "prepare_receipt_for_hashing",
    "compute_payload_hash",
    "verify_jcs_stability",
    "compute_merkle_root",
]
