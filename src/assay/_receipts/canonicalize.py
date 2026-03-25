"""
JCS (JSON Canonicalization Scheme) helpers for receipts.

This module provides the layered canonicalization API:

- **Layer 1** (``jcs.canonicalize``): pure RFC 8785 serialization.
- **Layer 2** (``prepare_receipt_for_hashing``): explicit projection that
  strips top-level signature fields per a versioned exclusion set.
- **Layer 3**: removed 2026-03-25 (was vestigial legacy normalization).

Usage:
    from assay._receipts.canonicalize import prepare_receipt_for_hashing
    from assay._receipts.jcs import canonicalize as jcs_canonicalize

    prepared = prepare_receipt_for_hashing(receipt)
    canonical_bytes = jcs_canonicalize(prepared)
"""

import hashlib
from typing import Any

from .merkle import compute_merkle_root
from assay._receipts.jcs import canonicalize as _jcs_canonicalize
from assay._receipts.compat.pyd import unwrap_frozen


# ---------------------------------------------------------------------------
# Layer 2: Explicit receipt projection for hashing/signing
# ---------------------------------------------------------------------------

# Versioned signature field exclusion sets.  Single source of truth for
# which top-level fields are stripped before hashing.  Root-level only:
# nested structures are payload, not signature-bearing.  v0 matches the
# historical strip_signatures() behaviour in compat/pyd.py.
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
    3. Strips top-level signature-related fields per the versioned exclusion
       set.  Root-level only — nested structures are payload.

    No legacy normalization is performed (Layer 3 is vestigial).
    No silent ``except`` passes — failures are raised to the caller.

    Args:
        receipt: Receipt object (Pydantic model, dict, or dict-like).
        version: Exclusion-set version (currently only ``"v0"``).

    Returns:
        Plain dict with top-level signature fields removed, ready for
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
    canonical_bytes = _jcs_canonicalize(prepare_receipt_for_hashing(obj))

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
    bytes1 = _jcs_canonicalize(prepare_receipt_for_hashing(obj))
    bytes2 = _jcs_canonicalize(prepare_receipt_for_hashing(obj))
    return bytes1 == bytes2


# canonicalize.compute_merkle_root is delegated to the centralized
# receipts.merkle.compute_merkle_root implementation to avoid drift.


__all__ = [
    "prepare_receipt_for_hashing",
    "compute_payload_hash",
    "compute_payload_hash_hex",
    "verify_jcs_stability",
    "compute_merkle_root",
]
