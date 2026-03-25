"""Signed lifecycle receipts for Assay Passports.

Creates and verifies challenge, supersession, and revocation events
as first-class signed receipts with content-addressed identity.

Follows the same integrity posture as passport signing:
  - JCS canonicalization (RFC 8785)
  - Ed25519 signatures
  - SHA-256 content-addressed event_id

See docs/specs/LIFECYCLE_RECEIPT_SPEC_V0_1.md for the full spec.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.keystore import AssayKeyStore, get_default_keystore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECEIPT_VERSION = "0.1"

VALID_EVENT_TYPES = ("challenge", "supersession", "revocation")

CHALLENGE_REASON_CODES = (
    "coverage_gap", "stale_evidence", "claim_dispute",
    "scope_mismatch", "integrity_concern", "other",
)
SUPERSESSION_REASON_CODES = (
    "coverage_improvement", "claim_update", "evidence_refresh",
    "scope_expansion", "remediation", "scheduled_renewal",
)
REVOCATION_REASON_CODES = (
    "key_compromise", "false_claim", "subject_decommissioned",
    "issuer_withdrawal", "authority_directive",
)

# Issuer roles
ROLE_CHALLENGER = "challenger"
ROLE_ISSUER = "issuer"
ROLE_AUTHORITY = "authority"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class LifecycleReceiptError(ValueError):
    """Raised when receipt creation or verification fails."""


# ---------------------------------------------------------------------------
# Receipt creation
# ---------------------------------------------------------------------------

def _build_issuer_block(
    keystore: AssayKeyStore,
    signer_id: str,
    role: str,
) -> Dict[str, Any]:
    """Build the issuer block with embedded public key."""
    vk = keystore.get_verify_key(signer_id)
    pubkey_bytes = vk.encode()
    return {
        "id": signer_id,
        "fingerprint": hashlib.sha256(pubkey_bytes).hexdigest(),
        "role": role,
        "pubkey": base64.b64encode(pubkey_bytes).decode("ascii"),
    }


def _sign_receipt(
    body: Dict[str, Any],
    keystore: AssayKeyStore,
    signer_id: str,
) -> Dict[str, Any]:
    """Compute event_id and sign a receipt body.

    1. event_id = "sha256:" + SHA-256(JCS(body without event_id/signature))
    2. signing_body = body + event_id (no signature)
    3. signature = Ed25519.sign(JCS(signing_body))
    """
    # Step 1: content-addressed identity
    id_body = {k: v for k, v in body.items() if k not in ("event_id", "signature")}
    canonical_for_id = jcs_canonicalize(id_body)
    event_id = "sha256:" + hashlib.sha256(canonical_for_id).hexdigest()
    body["event_id"] = event_id

    # Step 2: sign
    sign_body = {k: v for k, v in body.items() if k != "signature"}
    canonical_for_signing = jcs_canonicalize(sign_body)
    signature_b64 = keystore.sign_b64(canonical_for_signing, signer_id)

    # Step 3: attach signature block
    body["signature"] = {
        "algorithm": "Ed25519",
        "signature": signature_b64,
        "key_id": signer_id,
        "key_fingerprint": keystore.signer_fingerprint(signer_id),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "scope": "jcs_rfc8785_without_signature",
    }

    return body


def create_signed_challenge_receipt(
    *,
    target_passport_id: str,
    reason_code: str,
    reason_summary: str,
    keystore: Optional[AssayKeyStore] = None,
    signer_id: Optional[str] = None,
    target_system_id: str = "",
    evidence_refs: Optional[List[str]] = None,
    prior_event_refs: Optional[List[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Create a signed challenge receipt.

    Any identified actor may challenge. The receipt is signed with
    the challenger's key.
    """
    ks = keystore or get_default_keystore()
    sid = signer_id or ks.get_active_signer()
    ks.ensure_key(sid)
    now = now or datetime.now(timezone.utc)

    body: Dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "event_type": "challenge",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "issuer": _build_issuer_block(ks, sid, ROLE_CHALLENGER),
        "target": {
            "passport_id": target_passport_id,
            "subject_system_id": target_system_id,
        },
        "reason": {
            "code": reason_code,
            "summary": reason_summary,
        },
        "evidence_refs": evidence_refs or [],
        "prior_event_refs": prior_event_refs or [],
    }

    return _sign_receipt(body, ks, sid)


def create_signed_supersession_receipt(
    *,
    target_passport_id: str,
    new_passport_id: str,
    reason_code: str,
    reason_summary: str,
    keystore: Optional[AssayKeyStore] = None,
    signer_id: Optional[str] = None,
    target_system_id: str = "",
    challenge_refs_addressed: Optional[List[str]] = None,
    evidence_refs: Optional[List[str]] = None,
    prior_event_refs: Optional[List[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Create a signed supersession receipt.

    Only the passport issuer (or authorized delegate) may supersede.
    """
    if target_passport_id == new_passport_id:
        raise LifecycleReceiptError("A passport cannot supersede itself")

    ks = keystore or get_default_keystore()
    sid = signer_id or ks.get_active_signer()
    ks.ensure_key(sid)
    now = now or datetime.now(timezone.utc)

    body: Dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "event_type": "supersession",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "issuer": _build_issuer_block(ks, sid, ROLE_ISSUER),
        "target": {
            "passport_id": target_passport_id,
            "subject_system_id": target_system_id,
        },
        "reason": {
            "code": reason_code,
            "summary": reason_summary,
        },
        "evidence_refs": evidence_refs or [],
        "prior_event_refs": prior_event_refs or [],
        "supersession": {
            "new_passport_id": new_passport_id,
            "challenge_refs_addressed": challenge_refs_addressed or [],
        },
    }

    return _sign_receipt(body, ks, sid)


def create_signed_revocation_receipt(
    *,
    target_passport_id: str,
    reason_code: str,
    reason_summary: str,
    keystore: Optional[AssayKeyStore] = None,
    signer_id: Optional[str] = None,
    target_system_id: str = "",
    evidence_refs: Optional[List[str]] = None,
    prior_event_refs: Optional[List[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Create a signed revocation receipt.

    Only the passport issuer or designated authority may revoke.
    """
    ks = keystore or get_default_keystore()
    sid = signer_id or ks.get_active_signer()
    ks.ensure_key(sid)
    now = now or datetime.now(timezone.utc)

    body: Dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "event_type": "revocation",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "issuer": _build_issuer_block(ks, sid, ROLE_ISSUER),
        "target": {
            "passport_id": target_passport_id,
            "subject_system_id": target_system_id,
        },
        "reason": {
            "code": reason_code,
            "summary": reason_summary,
        },
        "evidence_refs": evidence_refs or [],
        "prior_event_refs": prior_event_refs or [],
    }

    return _sign_receipt(body, ks, sid)


# ---------------------------------------------------------------------------
# Receipt verification
# ---------------------------------------------------------------------------

def verify_lifecycle_receipt(
    receipt: Dict[str, Any],
    *,
    keystore: Optional[AssayKeyStore] = None,
) -> Dict[str, Any]:
    """Verify a signed lifecycle receipt.

    Returns:
        {
            "valid": bool,
            "signature_valid": bool,
            "id_valid": bool,
            "event_type": str,
            "event_id": str,
            "issuer_id": str,
            "issuer_role": str,
            "target_passport_id": str,
            "error": str | None,
        }

    Verification procedure:
    1. Check event_id = SHA-256(JCS(body without event_id/signature))
    2. Verify Ed25519 signature over JCS(body without signature)
    3. Signature is verified against embedded pubkey (not keystore lookup)
    """
    event_type = receipt.get("event_type", "unknown")
    event_id = receipt.get("event_id", "")
    issuer = receipt.get("issuer", {})
    target = receipt.get("target", {})
    sig_block = receipt.get("signature")

    base_result = {
        "valid": False,
        "signature_valid": False,
        "id_valid": False,
        "event_type": event_type,
        "event_id": event_id,
        "issuer_id": issuer.get("id", ""),
        "issuer_role": issuer.get("role", ""),
        "target_passport_id": target.get("passport_id", ""),
        "error": None,
    }

    # Check required fields
    if event_type not in VALID_EVENT_TYPES:
        base_result["error"] = f"Unknown event_type: {event_type}"
        return base_result

    if not sig_block or not isinstance(sig_block, dict):
        base_result["error"] = "No signature block present"
        return base_result

    # Step 1: verify content-addressed ID
    # Exclude event_id, signature, and internal metadata (underscore-prefixed keys)
    id_body = {
        k: v for k, v in receipt.items()
        if k not in ("event_id", "signature") and not k.startswith("_")
    }
    canonical_for_id = jcs_canonicalize(id_body)
    expected_id = "sha256:" + hashlib.sha256(canonical_for_id).hexdigest()
    id_valid = event_id == expected_id
    base_result["id_valid"] = id_valid

    if not id_valid:
        base_result["error"] = "Content-addressed ID mismatch"
        return base_result

    # Step 2: verify signature using embedded pubkey
    pubkey_b64 = issuer.get("pubkey", "")
    sig_b64 = sig_block.get("signature", "")

    if not pubkey_b64:
        base_result["error"] = "No embedded public key in issuer block"
        return base_result

    try:
        from nacl.signing import VerifyKey
        pubkey_bytes = base64.b64decode(pubkey_b64)
        vk = VerifyKey(pubkey_bytes)

        sign_body = {
            k: v for k, v in receipt.items()
            if k != "signature" and not k.startswith("_")
        }
        canonical_for_signing = jcs_canonicalize(sign_body)
        sig_bytes = base64.b64decode(sig_b64)
        vk.verify(canonical_for_signing, sig_bytes)
        base_result["signature_valid"] = True
    except Exception as exc:
        base_result["error"] = f"Signature verification failed: {exc}"
        return base_result

    # Step 3: verify issuer fingerprint matches embedded pubkey
    expected_fingerprint = hashlib.sha256(pubkey_bytes).hexdigest()
    if issuer.get("fingerprint") != expected_fingerprint:
        base_result["error"] = "Issuer fingerprint does not match embedded pubkey"
        base_result["signature_valid"] = False
        return base_result

    base_result["valid"] = True
    return base_result


def check_issuer_authority(
    receipt: Dict[str, Any],
    passport: Dict[str, Any],
) -> Dict[str, Any]:
    """Check whether the receipt issuer has authority for the event type.

    Returns:
        {
            "authorized": bool,
            "reason": str,
        }

    Authority rules:
    - challenge: any identified actor (role=challenger)
    - supersession: issuer fingerprint must match passport's signing key
    - revocation: issuer fingerprint must match passport's signing key
    """
    event_type = receipt.get("event_type", "")
    issuer = receipt.get("issuer", {})
    issuer_fingerprint = issuer.get("fingerprint", "")
    role = issuer.get("role", "")

    # Challenges: any identified actor
    if event_type == "challenge":
        if role != ROLE_CHALLENGER:
            return {"authorized": False, "reason": f"Expected role=challenger, got {role}"}
        return {"authorized": True, "reason": "Any identified actor may challenge"}

    # Supersession and revocation: must be issuer
    passport_sig = passport.get("signature", {})
    passport_issuer_fp = passport_sig.get("key_fingerprint", "")
    chain_issuer_fp = passport.get("chain", {}).get("issuer_fingerprint", "")

    if event_type == "supersession":
        if role != ROLE_ISSUER:
            return {"authorized": False, "reason": f"Expected role=issuer, got {role}"}
        if issuer_fingerprint in (passport_issuer_fp, chain_issuer_fp):
            return {"authorized": True, "reason": "Issuer fingerprint matches passport signer"}
        return {
            "authorized": False,
            "reason": "Issuer fingerprint does not match passport signer or chain issuer",
        }

    if event_type == "revocation":
        if role not in (ROLE_ISSUER, ROLE_AUTHORITY):
            return {"authorized": False, "reason": f"Expected role=issuer or authority, got {role}"}
        if issuer_fingerprint in (passport_issuer_fp, chain_issuer_fp):
            return {"authorized": True, "reason": "Issuer fingerprint matches passport signer"}
        # Future: check authority_keys list
        return {
            "authorized": False,
            "reason": "Issuer fingerprint does not match passport signer",
        }

    return {"authorized": False, "reason": f"Unknown event_type: {event_type}"}


# ---------------------------------------------------------------------------
# Governance derivation
# ---------------------------------------------------------------------------

def derive_governance_dimensions(
    passport_dir: Path,
    passport: Optional[Dict[str, Any]] = None,
    *,
    target_passport_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Derive governance_status and event_integrity from receipts on disk.

    Performs verified ingestion: signed receipts are checked, tampered ones
    are counted against event_integrity. Unsigned demo receipts are accepted
    but do not count toward integrity.

    Returns:
        {
            "governance_status": "none" | "challenged" | "superseded" | "revoked",
            "event_integrity": "no_events" | "all_valid" | "some_invalid",
            "receipts": [...],  # accepted receipts
            "signed_total": int,
            "signed_valid": int,
        }
    """
    if not passport_dir.is_dir():
        return {
            "governance_status": "none",
            "event_integrity": "no_events",
            "receipts": [],
            "signed_total": 0,
            "signed_valid": 0,
        }

    all_files: List[Path] = []
    for prefix in ("challenge_", "supersession_", "revocation_"):
        all_files.extend(sorted(passport_dir.glob(f"{prefix}*.json")))

    if not all_files:
        return {
            "governance_status": "none",
            "event_integrity": "no_events",
            "receipts": [],
            "signed_total": 0,
            "signed_valid": 0,
        }

    signed_total = 0
    signed_valid = 0
    accepted: List[Dict[str, Any]] = []
    seen_ids: set = set()

    for f in all_files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        # Filter by target passport
        if target_passport_id:
            target_pid = (
                data.get("target", {}).get("passport_id", "")
                or data.get("passport_id", "")
            )
            if target_pid and target_pid != target_passport_id:
                continue

        # Dedup by event_id
        eid = data.get("event_id", "")
        if eid:
            if eid in seen_ids:
                continue
            seen_ids.add(eid)

        is_signed = bool(data.get("signature") and data.get("event_id"))

        if is_signed:
            signed_total += 1
            vr = verify_lifecycle_receipt(data)
            if vr["valid"]:
                signed_valid += 1
                data["_verified"] = True
                # Authority check if passport provided
                if passport:
                    auth = check_issuer_authority(data, passport)
                    data["_authority_checked"] = auth["authorized"]
                else:
                    data["_authority_checked"] = False
                accepted.append(data)
            # Invalid signed receipts are NOT accepted but counted
        else:
            # Unsigned demo receipt — accepted without verification
            data["_verified"] = False
            data["_authority_checked"] = False
            accepted.append(data)

    # Governance status from accepted receipts (priority: revoked > superseded > challenged)
    def _event_type(r: Dict[str, Any]) -> str:
        return r.get("event_type", "") or r.get("type", "")

    has_revocation = any(_event_type(r) == "revocation" for r in accepted)
    has_supersession = any(_event_type(r) == "supersession" for r in accepted)
    has_challenge = any(_event_type(r) == "challenge" for r in accepted)

    if has_revocation:
        governance_status: str = "revoked"
    elif has_supersession:
        governance_status = "superseded"
    elif has_challenge:
        governance_status = "challenged"
    else:
        governance_status = "none"

    # Event integrity
    if signed_total == 0:
        event_integrity: str = "no_events"
    elif signed_valid == signed_total:
        event_integrity = "all_valid"
    else:
        event_integrity = "some_invalid"

    return {
        "governance_status": governance_status,
        "event_integrity": event_integrity,
        "receipts": accepted,
        "signed_total": signed_total,
        "signed_valid": signed_valid,
    }


# ---------------------------------------------------------------------------
# Receipt I/O
# ---------------------------------------------------------------------------

def write_lifecycle_receipt(receipt: Dict[str, Any], output_dir: Path) -> Path:
    """Write a signed lifecycle receipt to disk.

    Filename: {event_type}_{timestamp}_{hash8}.json
    """
    event_type = receipt.get("event_type", "event")
    issued_at = receipt.get("issued_at", "")
    ts = issued_at.replace(":", "").replace("-", "").replace("+", "")[:15]
    event_id = receipt.get("event_id", "")
    hash8 = event_id.replace("sha256:", "")[:8] if event_id else "00000000"
    filename = f"{event_type}_{ts}_{hash8}.json"

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def load_lifecycle_receipts(
    passport_dir: Path,
    *,
    target_passport_id: Optional[str] = None,
    verify: bool = True,
    passport: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Load and optionally verify all lifecycle receipts from a directory.

    Args:
        passport_dir: Directory containing receipt files.
        target_passport_id: If set, only load receipts targeting this passport.
        verify: If True (receipt mode), verify signatures and authority.
                If False (demo mode), accept unsigned receipts.
        passport: Required for authority checks in receipt mode.

    Returns:
        List of verified (or accepted) receipt dicts, each with:
        - _verified: bool (whether signature was checked and passed)
        - _authority_checked: bool
        - _source_file: str
    """
    if not passport_dir.is_dir():
        return []

    results: List[Dict[str, Any]] = []
    seen_ids: set = set()

    for prefix in ("challenge_", "supersession_", "revocation_"):
        for f in sorted(passport_dir.glob(f"{prefix}*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            data["_source_file"] = f.name

            # Filter by target
            if target_passport_id:
                target_pid = data.get("target", {}).get("passport_id", "")
                # Also support old-format receipts that use passport_id directly
                if not target_pid:
                    target_pid = data.get("passport_id", "")
                if target_pid and target_pid != target_passport_id:
                    continue

            if verify and data.get("signature"):
                # Receipt mode: verify signature
                vr = verify_lifecycle_receipt(data)
                data["_verified"] = vr.get("valid", False)
                if not vr["valid"]:
                    continue  # discard invalid receipts

                # Authority check
                if passport:
                    auth = check_issuer_authority(data, passport)
                    data["_authority_checked"] = auth["authorized"]
                    if not auth["authorized"]:
                        continue  # discard unauthorized receipts
                else:
                    data["_authority_checked"] = False
            else:
                # Demo mode: accept unsigned
                data["_verified"] = False
                data["_authority_checked"] = False

            # Dedup by event_id
            eid = data.get("event_id", "")
            if eid and eid in seen_ids:
                continue
            if eid:
                seen_ids.add(eid)

            results.append(data)

    return results
