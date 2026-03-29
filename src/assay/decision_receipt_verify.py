"""Decision Receipt signature verification for Assay consumers.

Standalone verification — does NOT import ccio. Uses JCS/RFC 8785
canonicalization to verify Ed25519 signatures on Decision Receipt
v0.1.0 dicts. This matches CCIO's signing path which uses JCS via
proofkit_module.canonicalize_json().

Canonical byte contract:
- Exclude: content_hash, signature, signer_pubkey_sha256
- Strip None-valued fields
- Dedupe + sort verdict_reason_codes
- Sort evidence_refs by JCS canonical form
- JCS/RFC 8785 canonicalization (NOT json.dumps)
"""
from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from assay._receipts.jcs import canonicalize as jcs_canonicalize

# Signing-excluded fields (must match CCIO's build.py contract)
_SIGNING_EXCLUDED = frozenset({"content_hash", "signature", "signer_pubkey_sha256"})


def _canonical_bytes(receipt: Dict[str, Any]) -> bytes:
    """Extract canonical byte sequence for verification.

    Uses JCS/RFC 8785, matching the CCIO signing path.
    """
    hashable = {
        k: v for k, v in receipt.items()
        if k not in _SIGNING_EXCLUDED and v is not None
    }

    if "verdict_reason_codes" in hashable and isinstance(hashable["verdict_reason_codes"], list):
        hashable["verdict_reason_codes"] = sorted(set(hashable["verdict_reason_codes"]))

    if "evidence_refs" in hashable and isinstance(hashable["evidence_refs"], list):
        hashable["evidence_refs"] = sorted(
            hashable["evidence_refs"],
            key=lambda r: jcs_canonicalize(r).decode("utf-8"),
        )

    return jcs_canonicalize(hashable)


class VerificationKeyRequired(TypeError):
    """Raised when verification is attempted without providing a public key.

    Decision Receipt verification requires an Ed25519 public key.
    Use make_verifier_with_key(pubkey_bytes) to create a verifier,
    or pass verify_signature= to classify_trust() directly.
    """


def verify_decision_receipt(receipt: Dict[str, Any]) -> bool:
    """Verify an Ed25519 signature on a Decision Receipt.

    Raises VerificationKeyRequired because verification cannot proceed
    without a public key. The SHA-256 fingerprint embedded in the receipt
    identifies which key was used, but the actual key bytes must be
    provided out-of-band.

    Use make_verifier_with_key(pubkey_bytes) to create a working verifier.

    Raises:
        VerificationKeyRequired: Always. This function cannot verify
            without key material.
    """
    raise VerificationKeyRequired(
        "Decision Receipt verification requires an Ed25519 public key. "
        "Use make_verifier_with_key(pubkey_bytes) to create a verifier."
    )


def make_verifier_with_key(pubkey_bytes: bytes) -> callable:
    """Create a verifier with a known Ed25519 public key.

    Args:
        pubkey_bytes: 32-byte Ed25519 public key.

    Returns:
        A callable compatible with classify_trust(verify_signature=...).
    """
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        def _no_nacl(receipt: Dict[str, Any]) -> bool:
            return False
        return _no_nacl

    vk = VerifyKey(pubkey_bytes)

    def _verify(receipt: Dict[str, Any]) -> bool:
        sig_b64 = receipt.get("signature")
        if not sig_b64 or not isinstance(sig_b64, str):
            return False
        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception:
            return False
        canonical = _canonical_bytes(receipt)
        try:
            vk.verify(canonical, sig_bytes)
            return True
        except BadSignatureError:
            return False
        except Exception:
            return False

    return _verify


__all__ = [
    "VerificationKeyRequired",
    "verify_decision_receipt",
    "make_verifier_with_key",
]
