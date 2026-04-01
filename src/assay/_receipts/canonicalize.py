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

--- Exclusion set architecture ---

Three distinct signing/projection contracts exist in this codebase.
They are intentionally separate because they serve different wire formats.

1. _SIGNATURE_FIELD_SETS["v0"]  (this file)
   Generic receipt signing exclusion. Used by prepare_receipt_for_hashing().
   Covers the historical signing contract for pack manifests and general
   receipt hashing.

2. _PROJECTION_EXCLUSIONS["receipt-core-v2"]  (this file)
   v2 normative projection exclusion. Used by canonical_projection() only.
   Defines what is attested in a v2 receipt: excludes verification_bundle,
   signatures, trust_anchors, and deprecated v1 root signature fields.
   verification_profile and verification_policy ARE attested (included by
   not being excluded).

3. _SIGNING_EXCLUDED in decision_receipt_verify.py  (separate file)
   CCIO Decision Receipt v0.1.x wire format contract. Must match CCIO's
   build.py exactly, including additional normalization (None-stripping,
   list deduplication/sorting) that contracts 1 and 2 do not perform.
   Do NOT merge into this file without auditing CCIO build.py first.
"""

import hashlib
import json
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

# ---------------------------------------------------------------------------
# v2 canonical projection — single source of truth for receipt-core-v2
# ---------------------------------------------------------------------------
# Attested fields (included in digest):
#   receipt_id, type, timestamp, payload, verification_profile,
#   verification_policy — and any other receipt field NOT in this set.
# Excluded fields (not attested):
#   verification_bundle  — the digest descriptor itself is not self-attesting
#   signatures           — witnesses over the digest, not part of the content
#   trust_anchors        — resolution metadata, not part of attested content
#   signature / signer_id / signer_pubkey_sha256  — deprecated v1 root fields
#   cose_signature / receipt_hash / anchor        — legacy carry-forward
_V2_PROJECTION_EXCLUSIONS = frozenset({
    "verification_bundle",
    "signatures",
    "trust_anchors",
    # deprecated v1 root signature fields (signer info moves to signatures[])
    "signature",
    "signer_id",
    "signer_pubkey_sha256",
    # legacy (carry-forward from v0)
    "cose_signature",
    "receipt_hash",
    "anchor",
})

_PROJECTION_EXCLUSIONS: dict[str, frozenset[str]] = {
    "receipt-core-v2": _V2_PROJECTION_EXCLUSIONS,
}

# Public alias — use this in tests and external code that needs to verify
# completeness invariants against the live exclusion set.
PROJECTION_EXCLUSIONS: dict[str, frozenset[str]] = _PROJECTION_EXCLUSIONS


# ---------------------------------------------------------------------------
# Projection Doctrine — machine-readable constitutional law
# ---------------------------------------------------------------------------
# AUTHORITATIVE LOCATION. This constant describes the law that
# _V2_PROJECTION_EXCLUSIONS and canonical_projection() implement.
# Co-located here so the law and its description share one home.
#
# Import path for other modules:
#   from assay._receipts.canonicalize import PROJECTION_DOCTRINE
#
# Completeness invariant (tested in tests/assay/test_v2_sign.py):
#   set(PROJECTION_DOCTRINE["excluded"]["fields"])
#   == PROJECTION_EXCLUSIONS["receipt-core-v2"]
# If these diverge, the doctrine is lying about the code.

PROJECTION_DOCTRINE: dict = {
    "projection_id": "receipt-core-v2",
    "normative_function": "assay._receipts.canonicalize.canonical_projection",
    "signing_target": (
        "canonical_bytes = jcs(canonical_projection(receipt, projection_id)); "
        "sign(canonical_bytes). "
        "bundle_digest = sha256(canonical_bytes) stored as fingerprint only."
    ),
    "attested": {
        "description": (
            "Fields included in canonical_projection(). Changing any of these "
            "changes bundle_digest. Policy/profile changes require reissuance."
        ),
        "standard_fields": [
            "receipt_id",
            "type",
            "timestamp",
            "payload",
            "verification_profile",
            "verification_policy",
        ],
        "custom_fields_rule": (
            "Any field NOT in the excluded set is attested by default. "
            "Custom fields are governed law, not free metadata. "
            "Ask: 'Is this a claim I am committing to?' If no, exclude it."
        ),
    },
    "excluded": {
        "description": (
            "Fields stripped by canonical_projection() before signing. "
            "These are operational metadata — they do not affect bundle_digest. "
            "MUST equal PROJECTION_EXCLUSIONS['receipt-core-v2'] exactly."
        ),
        "fields": [
            "verification_bundle",   # digest descriptor; not self-attesting
            "signatures",            # witnesses over the digest, not the content
            "trust_anchors",         # resolution metadata
            "signature",             # deprecated v1 root field
            "signer_id",             # deprecated v1 root field (moves to signatures[])
            "signer_pubkey_sha256",  # deprecated v1 root field
            "cose_signature",        # legacy carry-forward
            "receipt_hash",          # legacy carry-forward
            "anchor",                # legacy carry-forward
        ],
    },
    "covers_order": (
        "sorted alphabetically (Python sorted()). "
        "Deterministic for human review and diff stability. "
        "Cryptographically irrelevant — verifier recomputes projection independently."
    ),
    "mint_rejection_rules": [
        "Reject if base_receipt already contains non-empty signatures[]",
        "Reject if base_receipt already contains verification_bundle",
        "Reject if 'type' is missing or empty",
        "Reject if projection_id is unknown",
    ],
    "helper_status": {
        "build_v2_base_receipt": "ERGONOMIC ONLY — not normative. emit_v2_receipt() is the center.",
        "default_v2_policy":     "ERGONOMIC ONLY — standard cases. Custom policy dicts are valid.",
    },
    "amendment_rule": (
        "emit_v2_receipt() MINTS only. "
        "Adding a second signature to an existing receipt requires cosign_v2_receipt() "
        "(documented extension, not yet implemented). "
        "Policy corrections require a new receipt — not an amendment."
    ),
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

    # OCD-1 resolved: raw hex everywhere.  The algorithm is declared at
    # the manifest level (hash_alg field), not per-value.
    return h.hexdigest()


def compute_payload_hash_hex(obj: Any, algorithm: str = "sha256") -> str:
    """Alias for compute_payload_hash (both now return raw hex).

    Retained for backward compatibility.  OCD-1 resolved: compute_payload_hash
    now returns raw hex directly, so this function is a trivial passthrough.
    """
    return compute_payload_hash(obj, algorithm=algorithm)


def _reject_duplicate_keys(pairs: list) -> dict:
    """object_pairs_hook for json.loads that rejects duplicate keys."""
    keys = [k for k, _ in pairs]
    duplicates = {k for k in keys if keys.count(k) > 1}
    if duplicates:
        raise ValueError(
            f"Receipt JSON contains duplicate object member names (I-JSON violation): "
            f"{sorted(duplicates)}"
        )
    return dict(pairs)


def parse_ijson_receipt(json_str: str) -> dict:
    """Parse receipt JSON with I-JSON compliance: reject duplicate object member names.

    JCS (RFC 8785) is defined over I-JSON. I-JSON forbids duplicate object member
    names. Standard json.loads() silently overwrites earlier members on collision,
    which means duplicate-key violations pass undetected into normal dicts.

    This function MUST be used at the ingestion boundary for any receipt that will
    be passed to canonical_projection() or compute_bundle_digest(). Once a receipt
    is materialized as a plain dict, duplicate-key information is irretrievably lost.

    Args:
        json_str: Raw receipt JSON string.

    Returns:
        Plain dict with I-JSON compliance verified.

    Raises:
        ValueError: If json_str contains duplicate object member names.
        json.JSONDecodeError: If json_str is not valid JSON.
    """
    return json.loads(json_str, object_pairs_hook=_reject_duplicate_keys)


def canonical_projection(receipt: Any, projection_id: str = "receipt-core-v2") -> dict:
    """Return the canonical attested projection of a v2 receipt.

    This is the normative function for what gets hashed and signed in v2:

        bundle_digest = sha256(jcs(canonical_projection(receipt)))

    Pre-condition: receipt must be valid I-JSON (no duplicate object member
    names; numbers within IEEE 754 double range). Callers MUST validate
    before calling — this function does not re-validate.

    The projection works by exclusion. Fields NOT in the exclusion set for
    projection_id are included. covers in VerificationBundle is explanatory
    metadata that documents which fields are included — the verifier
    recomputes this independently and does not trust the covers list.

    Args:
        receipt: Receipt object (Pydantic model, dict, or dict-like).
        projection_id: Named projection version. Currently: "receipt-core-v2".

    Returns:
        Plain dict containing only attested fields, ready for
        jcs.canonicalize().

    Raises:
        ValueError: If projection_id is unknown (returns unsupported_projection
            status in verifier context — callers should catch and translate).
        TypeError: If receipt cannot be converted to a dict.
    """
    exclusions = _PROJECTION_EXCLUSIONS.get(projection_id)
    if exclusions is None:
        raise ValueError(
            f"Unknown projection_id: {projection_id!r}. "
            f"Known: {sorted(_PROJECTION_EXCLUSIONS)}"
        )

    if hasattr(receipt, "model_dump"):
        data = receipt.model_dump(mode="json")
    elif hasattr(receipt, "dict") and not isinstance(receipt, dict):
        data = receipt.dict()
    elif isinstance(receipt, dict):
        data = receipt
    else:
        raise TypeError(
            f"Cannot convert {type(receipt).__name__} to dict for projection"
        )

    data = unwrap_frozen(data)
    return {k: v for k, v in data.items() if k not in exclusions}


def compute_bundle_digest(
    receipt: Any,
    *,
    projection_id: str = "receipt-core-v2",
    algorithm: str = "sha256",
) -> str:
    """Compute verification_bundle.bundle_digest for a v2 receipt.

    Implements the normative digest rule:

        bundle_digest = sha256(jcs(canonical_projection(receipt, projection_id)))

    Returns a prefixed hex digest: "sha256:hexhash"

    Args:
        receipt: Receipt object (Pydantic model, dict, or dict-like).
        projection_id: Named projection version. Default: "receipt-core-v2".
        algorithm: Hash algorithm. Supported: "sha256", "sha3-256".

    Returns:
        Prefixed hex digest string, e.g. "sha256:abc123..."

    Raises:
        ValueError: If projection_id or algorithm is unsupported.
    """
    projected = canonical_projection(receipt, projection_id=projection_id)
    canonical_bytes = _jcs_canonicalize(projected)

    if algorithm == "sha256":
        digest = hashlib.sha256(canonical_bytes).hexdigest()
    elif algorithm == "sha3-256":
        digest = hashlib.sha3_256(canonical_bytes).hexdigest()
    else:
        raise ValueError(
            f"Unsupported algorithm: {algorithm!r}. Supported: sha256, sha3-256"
        )

    return f"{algorithm}:{digest}"


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
    # v2
    "parse_ijson_receipt",
    "canonical_projection",
    "compute_bundle_digest",
    # v2 doctrine
    "PROJECTION_DOCTRINE",
    "PROJECTION_EXCLUSIONS",
]
