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
from assay._receipts.compat.pyd import unwrap_frozen, strip_signatures
try:
    from tools import proofkit as proofkit_module
except Exception:  # pragma: no cover - fallback when proofkit is unavailable
    from assay._receipts.jcs import canonicalize as _jcs_canonicalize

    class _FallbackProofkit:
        @staticmethod
        def canonicalize_json(payload: Any) -> bytes:
            return _jcs_canonicalize(payload)
    proofkit_module = _FallbackProofkit()
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
    Serialize object to JCS (RFC 8785) canonical bytes using ProofKit.
    """
    normalized = _prepare_for_canonicalization(obj)
    return proofkit_module.canonicalize_json(normalized)


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

    try:
        unwrapped = normalize_legacy_fields(unwrapped)
    except Exception:
        pass

    try:
        unwrapped = strip_signatures(unwrapped)
    except Exception:
        pass

    return unwrapped


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
    canonical_bytes = proofkit_module.canonicalize_json(_prepare_for_canonicalization(obj))

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
    "compute_payload_hash",
    "verify_jcs_stability",
    "compute_merkle_root",
]
