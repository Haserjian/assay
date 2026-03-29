"""Shared trust evaluator for Decision Receipts.

One source of truth for trust-state classification. The renderer,
CLI, API, and verification pipeline all consume this — none of them
define trust semantics independently.

Evidence-to-state mapping:

    State          Evidence required
    ─────────────  ──────────────────────────────────────────────────
    VERIFIED       signature present + signer key available + verification passed
    UNSIGNED       receipt valid, content_hash present, no signature
    UNVERIFIABLE   signature present but verification key unavailable
    INVALID        schema/invariant validation failed, signature mismatch,
                   or content_hash mismatch
    MISSING        no receipt present

Classification truth table:

    Condition                                     → State
    ───────────────────────────────────────────────────────────
    receipt is None                               → MISSING
    signature absent, structurally sound          → UNSIGNED
    signature present, key/verifier unavailable   → UNVERIFIABLE
    signature present, verification fails         → INVALID
    signature present, verification passes        → VERIFIED
    schema/invariant validation fails (unsigned)  → INVALID
    signed + key missing + also malformed         → UNVERIFIABLE (policy)

Classification priority (first match wins):
    1. MISSING      — receipt is None
    2. UNVERIFIABLE — signature present, key unavailable (checked before
                      validation because schema I-7 would flag this as invalid)
    3. INVALID      — schema/invariant validation fails, or signature mismatch
    4. VERIFIED     — signature present, key available, verification passed
    5. UNSIGNED     — no signature, structurally sound

Policy note: UNVERIFIABLE takes priority over INVALID when signature is
present but key material is missing. This is a deliberate choice: the
dominant signal is "we cannot discharge the proof obligation," not
"the receipt is structurally defective." The structural defect may be
an artifact of incomplete transmission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class DecisionReceiptTrustState(str, Enum):
    """Five-state trust model for Decision Receipts.

    These are formal constitutional states, not UI labels.
    """
    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    UNVERIFIABLE = "unverifiable"
    INVALID = "invalid"
    MISSING = "missing"


@dataclass(frozen=True)
class TrustClassification:
    """Result of trust classification — state + supporting detail."""
    state: DecisionReceiptTrustState
    errors: tuple[str, ...] = ()
    reason: str = ""

    @property
    def is_trustworthy(self) -> bool:
        """Only VERIFIED receipts are fully trustworthy."""
        return self.state == DecisionReceiptTrustState.VERIFIED

    @property
    def is_well_formed(self) -> bool:
        """VERIFIED and UNSIGNED receipts are structurally well-formed.

        This means the receipt has valid structure and fields. It does NOT
        mean the receipt has cryptographic proof — use is_cryptographically_verified
        for that distinction.
        """
        return self.state in (
            DecisionReceiptTrustState.VERIFIED,
            DecisionReceiptTrustState.UNSIGNED,
        )

    @property
    def is_cryptographically_verified(self) -> bool:
        """Only VERIFIED receipts have confirmed cryptographic proof."""
        return self.state == DecisionReceiptTrustState.VERIFIED

    @property
    def is_structurally_sound(self) -> bool:
        """Deprecated alias for is_well_formed. Use is_well_formed instead."""
        return self.is_well_formed


# Sentinel for "no receipt"
MISSING = TrustClassification(
    state=DecisionReceiptTrustState.MISSING,
    reason="No Decision Receipt present",
)


def classify_trust(
    receipt: Optional[Dict[str, Any]],
    *,
    validator: Optional[Callable[[Dict[str, Any]], Any]] = None,
    verify_signature: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> TrustClassification:
    """Classify a Decision Receipt into one of 5 trust states.

    Args:
        receipt: The receipt dict, or None if absent.
        validator: Optional schema+invariant validator. Must return an
            object with `.valid: bool` and `.errors: list` attributes.
            If None, schema validation is skipped (receipt assumed valid).
        verify_signature: Optional signature verification function.
            Returns True if signature is valid, False if invalid.
            If None and signature is present, state is UNVERIFIABLE.

    Returns:
        TrustClassification with state + supporting detail.
    """
    # 1. MISSING — no receipt
    if receipt is None:
        return MISSING

    raw_sig = receipt.get("signature")
    pubkey = receipt.get("signer_pubkey_sha256")

    # Normalize: empty/whitespace-only signature is not a meaningful proof claim.
    # It's malformed proof material → will be caught as INVALID below.
    sig = raw_sig if isinstance(raw_sig, str) and raw_sig.strip() else None
    sig_field_present_but_empty = raw_sig is not None and sig is None

    if sig_field_present_but_empty:
        return TrustClassification(
            state=DecisionReceiptTrustState.INVALID,
            errors=("Signature field is present but empty or whitespace-only",),
            reason="Malformed proof material",
        )

    # 2. UNVERIFIABLE — check before validation because schema invariant I-7
    #    flags "signature present, pubkey null" as invalid. But that is exactly
    #    the condition UNVERIFIABLE exists for: the receipt may be fine,
    #    we just can't prove it with available key material.
    if sig is not None and (verify_signature is None or pubkey is None):
        return TrustClassification(
            state=DecisionReceiptTrustState.UNVERIFIABLE,
            reason="Signature present, verification key unavailable",
        )

    # 3. INVALID — schema/invariant validation fails
    if validator is not None:
        result = validator(receipt)
        if not result.valid:
            error_msgs = tuple(
                f"{e.rule}: {e.message}"
                for e in getattr(result, "errors", [])
            )
            return TrustClassification(
                state=DecisionReceiptTrustState.INVALID,
                errors=error_msgs,
                reason="Schema or invariant validation failed",
            )

    # 4. Signature present with key and verifier — attempt verification
    #    (UNVERIFIABLE cases already handled above)
    if sig is not None:
        # At this point we know verify_signature is not None and pubkey is not None
        try:
            sig_valid = verify_signature(receipt)
        except Exception as exc:
            return TrustClassification(
                state=DecisionReceiptTrustState.INVALID,
                errors=(f"Signature verification error: {exc}",),
                reason="Signature verification raised an exception",
            )

        if sig_valid:
            return TrustClassification(
                state=DecisionReceiptTrustState.VERIFIED,
                reason="Signature verified successfully",
            )
        else:
            return TrustClassification(
                state=DecisionReceiptTrustState.INVALID,
                errors=("Signature verification failed: content may have been tampered",),
                reason="Signature mismatch",
            )

    # 5. UNSIGNED — no signature, structurally sound
    content_hash = receipt.get("content_hash")
    reason = (
        "Receipt is structurally sound but unsigned"
        if content_hash
        else "Receipt is unsigned and has no content hash"
    )
    return TrustClassification(
        state=DecisionReceiptTrustState.UNSIGNED,
        reason=reason,
    )


__all__ = [
    "DecisionReceiptTrustState",
    "TrustClassification",
    "classify_trust",
    "MISSING",
]
