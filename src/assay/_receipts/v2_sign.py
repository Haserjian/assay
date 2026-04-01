"""
ReceiptV2 signing path (Slice 3).

Minting a v2 receipt:

    1. Build base_receipt with attested fields only
       (receipt_id, type, timestamp, payload, verification_profile,
        verification_policy — plus any caller-supplied custom fields)
    2. canonical_projection(base_receipt)     → projected dict
    3. jcs(projected)                        → canonical_bytes
    4. sha256(canonical_bytes)               → bundle_digest
    5. sign(canonical_bytes, signing_key)    → sig_bytes
    6. Attach verification_bundle + signatures[] to copy of base_receipt
    7. Return assembled receipt dict

What is signed: canonical_bytes — the raw JCS output of the projected
receipt. bundle_digest is a stored fingerprint of those bytes for fast
integrity checking; it is not itself the signing target.

Constitutional boundary:
    emit_v2_receipt() is a MINT operation.
    It rejects receipts that already carry signatures[] or verification_bundle.
    Adding a second signature to an existing receipt is cosign_v2_receipt()
    (separate function, not in this slice).

New fields are attested by default:
    Any field in base_receipt that is not in _V2_PROJECTION_EXCLUSIONS will
    appear in the canonical projection and thus in bundle_digest. Custom fields
    are attested unless explicitly excluded. This is by design — see covers.

Ergonomic helpers:
    default_v2_policy(profile)   — standard policy dict for common profiles
    build_v2_base_receipt(...)   — convenience constructor (NOT the conceptual
                                   center; emit_v2_receipt is)
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone
from typing import Any, List, Optional

from assay._receipts.canonicalize import PROJECTION_DOCTRINE, canonical_projection
from assay._receipts.jcs import canonicalize as jcs_canonicalize

# PROJECTION_DOCTRINE is the machine-readable constitutional law for v2 receipts.
# Authoritative location: assay._receipts.canonicalize (co-located with the
# projection code it describes). Re-exported here for import convenience.
# Do not inline a copy — one source of truth.


# ---------------------------------------------------------------------------
# Default policy helpers
# ---------------------------------------------------------------------------

def default_v2_policy(profile: str = "operational-v1") -> dict:
    """Return the standard verification_policy dict for a named profile.

    This is a convenience helper for common cases. Advanced callers may
    construct verification_policy directly.

    Profiles:
        "operational-v1"   — Ed25519 minimum; satisfies today's verifiers.
        "archival-v1"      — Ed25519 (operational) + ML-DSA-65 (archival);
                             satisfies long-lived compliance horizon.

    The returned dict is part of the attested projection. Policy changes
    require reissuance — the policy cannot be amended after signing.
    """
    if profile == "operational-v1":
        return {
            "schema_version": "1",
            "operational_requires": {
                "min_signatures": 1,
                "algorithms": ["ed25519"],
            },
        }
    if profile == "archival-v1":
        return {
            "schema_version": "1",
            "operational_requires": {
                "min_signatures": 1,
                "algorithms": ["ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
            },
            "archival_requires": {
                "min_signatures": 1,
                "algorithms": ["ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128s"],
            },
        }
    raise ValueError(
        f"Unknown profile: {profile!r}. Known: 'operational-v1', 'archival-v1'"
    )


# ---------------------------------------------------------------------------
# Ergonomic base receipt constructor
# ---------------------------------------------------------------------------

def build_v2_base_receipt(
    receipt_type: str,
    payload: Optional[dict] = None,
    *,
    receipt_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    verification_profile: str = "operational-v1",
    verification_policy: Optional[dict] = None,
    **extra_attested_fields: Any,
) -> dict:
    """Convenience constructor for a v2 base receipt (attested fields only).

    This is a helper — NOT the conceptual center of the signing path.
    emit_v2_receipt() is the normative minting operation. This helper exists
    to reduce boilerplate for callers who don't want to construct the dict
    manually.

    Args:
        receipt_type:           Value for the "type" field (required).
        payload:                Attested payload dict. Defaults to {}.
        receipt_id:             Explicit receipt_id. Auto-generated if absent.
        timestamp:              ISO 8601 UTC timestamp. UTC now if absent.
        verification_profile:   Profile string. Default: "operational-v1".
        verification_policy:    Policy dict. Derived from profile if absent.
        **extra_attested_fields: Any additional fields to attest. These will
                                 appear in the projection and affect bundle_digest.

    Returns:
        Plain dict containing only attested fields, ready to pass to
        emit_v2_receipt().

    Note:
        extra_attested_fields must not include fields that are in the
        projection exclusion set (verification_bundle, signatures, etc.).
        Callers are responsible for not including excluded fields; if they
        do, canonical_projection() will strip them silently.
    """
    if not receipt_type:
        raise ValueError("receipt_type is required")

    base = {
        "receipt_id": receipt_id or _generate_receipt_id(),
        "type": receipt_type,
        "timestamp": timestamp or _utc_now_iso(),
        "payload": payload if payload is not None else {},
        "verification_profile": verification_profile,
        "verification_policy": (
            verification_policy
            if verification_policy is not None
            else default_v2_policy(verification_profile)
        ),
    }
    base.update(extra_attested_fields)
    return base


# ---------------------------------------------------------------------------
# Main minting function
# ---------------------------------------------------------------------------

def emit_v2_receipt(
    base_receipt: dict,
    *,
    signing_key: Any,
    signer_id: str,
    trust_anchors: Optional[List[dict]] = None,
    projection_id: str = "receipt-core-v2",
    add_signed_at: bool = True,
) -> dict:
    """Mint a signed v2 receipt from attested base fields.

    MINT CONTRACT: base_receipt must NOT already carry signatures[] or
    verification_bundle. If it does, raise ValueError — amendment and
    co-signing are separate operations, not this function.

    Constitutional boundary:
        emit_v2_receipt() = mint a fresh receipt
        cosign_v2_receipt() = add a second signature to existing receipt
        (cosign is a documented extension point, not yet implemented)

    Args:
        base_receipt:    Dict containing attested fields. Required keys depend
                         on the verification_profile, but at minimum "type"
                         must be present. Excluded fields (verification_bundle,
                         signatures, trust_anchors, signature, signer_id,
                         signer_pubkey_sha256) will be stripped by the
                         projection before signing.
        signing_key:     PyNaCl SigningKey (or any object with .sign(bytes)
                         returning an object with .signature bytes, and
                         .verify_key.encode() returning 32-byte pubkey).
        signer_id:       Logical identity of the signer.
        trust_anchors:   Optional list of trust anchor descriptors. These
                         are NOT attested (excluded from projection).
        projection_id:   Named projection version. Default: "receipt-core-v2".
        add_signed_at:   Include signed_at in the SigEntry (UTC now). Set
                         False for deterministic testing.

    Returns:
        Plain dict — the assembled receipt with:
          - All attested base fields
          - verification_bundle (bundle_digest, bundle_algorithm,
            canonicalization, projection_id, covers)
          - signatures[] with one SigEntry
          - trust_anchors (if provided)

    Raises:
        ValueError: If base_receipt already has signatures[] or
                    verification_bundle (mint vs. cosign violation).
        ValueError: If "type" is missing from base_receipt.
        ValueError: If projection_id is unknown.

    Signing mechanics:
        What is signed: canonical_bytes = jcs(canonical_projection(base_receipt))
        That is the raw JCS-serialized bytes of the attested projection.
        bundle_digest = sha256(canonical_bytes) is stored as a fingerprint.
        The verifier recomputes canonical_bytes, checks digest matches, then
        runs verify(canonical_bytes, sig_bytes).
    """
    # --- Mint contract: reject preexisting envelopes ---
    if "signatures" in base_receipt and base_receipt["signatures"]:
        raise ValueError(
            "emit_v2_receipt() is a mint operation. base_receipt already has "
            "signatures[]. To add a second signature to an existing receipt, "
            "use cosign_v2_receipt() (documented extension, not yet implemented)."
        )
    if "verification_bundle" in base_receipt and base_receipt["verification_bundle"]:
        raise ValueError(
            "emit_v2_receipt() is a mint operation. base_receipt already has "
            "verification_bundle. Cannot re-mint a receipt that has already "
            "been sealed."
        )

    # --- Required attested field check ---
    if "type" not in base_receipt or not base_receipt["type"]:
        raise ValueError(
            '"type" is a required attested field and must be present in base_receipt.'
        )

    # --- Step 1: compute canonical projection ---
    # This is the normative projection for this projection_id.
    # ValueError from canonical_projection on unknown projection_id propagates.
    projected = canonical_projection(base_receipt, projection_id=projection_id)

    # --- Step 2: JCS-canonicalize the projection ---
    canonical_bytes: bytes = jcs_canonicalize(projected)

    # --- Step 3: compute bundle_digest ---
    raw_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    bundle_digest = f"sha256:{raw_sha256}"

    # --- Step 4: sign canonical_bytes ---
    # We sign the BYTES, not the digest string. The verifier recomputes the
    # bytes independently and calls verify(canonical_bytes, sig_bytes).
    signed = signing_key.sign(canonical_bytes)
    sig_bytes: bytes = signed.signature
    sig_value: str = base64.b64encode(sig_bytes).decode("ascii")

    # --- Step 5: compute pubkey fingerprint ---
    pubkey_bytes: bytes = signing_key.verify_key.encode()
    pubkey_sha256: str = hashlib.sha256(pubkey_bytes).hexdigest()

    # --- Step 6: build SigEntry ---
    sig_entry: dict = {
        "algorithm": "ed25519",
        "signer_id": signer_id,
        "signer_pubkey_sha256": pubkey_sha256,
        "value": sig_value,
    }
    if add_signed_at:
        sig_entry["signed_at"] = _utc_now_iso()

    # --- Step 7: build verification_bundle ---
    # covers = sorted keys actually in the projection — observational, not normative.
    covers = sorted(projected.keys())
    verification_bundle: dict = {
        "projection_id": projection_id,
        "bundle_digest": bundle_digest,
        "bundle_algorithm": "sha256",
        "canonicalization": "jcs-rfc8785",
        "covers": covers,
    }

    # --- Step 8: assemble and return ---
    receipt = dict(base_receipt)
    receipt["verification_bundle"] = verification_bundle
    receipt["signatures"] = [sig_entry]
    if trust_anchors is not None:
        receipt["trust_anchors"] = trust_anchors
    return receipt


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _generate_receipt_id() -> str:
    """Generate a short random receipt ID in the organism convention."""
    return "rcpt-" + os.urandom(4).hex()


def _utc_now_iso() -> str:
    """Current UTC time as ISO 8601 string (seconds precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PROJECTION_DOCTRINE",
    "emit_v2_receipt",
    "default_v2_policy",
    "build_v2_base_receipt",
]
