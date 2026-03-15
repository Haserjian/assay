"""Sign and verify Assay Passport JSON files.

Uses the same Ed25519 keystore and JCS canonicalization as proof packs
and ADC credentials. Signing follows the detached-signature pattern:

  1. Remove "signature" and "passport_id" from body
  2. Compute passport_id = SHA-256(JCS(body_without_signature_or_id))
  3. Sign JCS(body_with_passport_id, without_signature)
  4. Attach signature block
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from assay._receipts.canonicalize import to_jcs_bytes
from assay.keystore import AssayKeyStore, get_default_keystore


class PassportSignError(ValueError):
    """Raised when signing or verification fails."""


def sign_passport(
    passport_path: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
    signer_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign a passport.json in place. Returns the signed passport dict.

    Steps:
      1. Load passport, strip existing signature
      2. Compute content-addressed passport_id = sha256:hex(JCS(body))
      3. Sign JCS(body_with_id) → base64 Ed25519 signature
      4. Attach signature block with algorithm, key fingerprint, signed_at
      5. Write back to passport_path
    """
    passport_path = Path(passport_path)
    if not passport_path.exists():
        raise PassportSignError(f"Passport not found: {passport_path}")

    data = json.loads(passport_path.read_text(encoding="utf-8"))

    ks = keystore or get_default_keystore()
    sid = signer_id or ks.get_active_signer()
    ks.ensure_key(sid)

    # Step 1: strip signature AND passport_id for ID computation
    body = {k: v for k, v in data.items() if k not in ("signature", "passport_id")}

    # Step 2: content-addressed ID = SHA-256(JCS(body without signature or passport_id))
    canonical_for_id = to_jcs_bytes(body)
    passport_id = "sha256:" + hashlib.sha256(canonical_for_id).hexdigest()
    body["passport_id"] = passport_id

    # Step 3: sign JCS(body with passport_id, without signature)
    canonical_for_signing = to_jcs_bytes(body)
    signature_b64 = ks.sign_b64(canonical_for_signing, sid)

    # Step 4: attach signature block
    from datetime import datetime, timezone
    body["signature"] = {
        "algorithm": "Ed25519",
        "signature": signature_b64,
        "key_id": sid,
        "key_fingerprint": ks.signer_fingerprint(sid),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "scope": "jcs_rfc8785_without_signature",
    }

    # Step 5: write back
    passport_path.write_text(
        json.dumps(body, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return body


def verify_passport_signature(
    passport_path: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
) -> Dict[str, Any]:
    """Verify a passport's signature and content-addressed ID.

    Returns a dict with:
      signature_valid: bool
      id_valid: bool
      key_id: str
      key_fingerprint: str
      error: str | None
    """
    passport_path = Path(passport_path)
    data = json.loads(passport_path.read_text(encoding="utf-8"))

    sig_block = data.get("signature")
    if not sig_block or not isinstance(sig_block, dict):
        return {
            "signature_valid": False,
            "id_valid": False,
            "key_id": None,
            "key_fingerprint": None,
            "error": "No signature block present",
        }

    ks = keystore or get_default_keystore()
    key_id = sig_block.get("key_id", "")
    sig_b64 = sig_block.get("signature", "")

    # Reconstruct ID-computation body (no signature, no passport_id)
    id_body = {k: v for k, v in data.items() if k not in ("signature", "passport_id")}
    canonical_for_id = to_jcs_bytes(id_body)
    expected_id = "sha256:" + hashlib.sha256(canonical_for_id).hexdigest()
    id_valid = data.get("passport_id") == expected_id

    # Reconstruct signing body (no signature, but WITH passport_id)
    sign_body = {k: v for k, v in data.items() if k != "signature"}
    canonical_for_signing = to_jcs_bytes(sign_body)
    try:
        sig_valid = ks.verify_b64(canonical_for_signing, sig_b64, key_id)
    except Exception as exc:
        return {
            "signature_valid": False,
            "id_valid": id_valid,
            "key_id": key_id,
            "key_fingerprint": sig_block.get("key_fingerprint"),
            "error": str(exc),
        }

    return {
        "signature_valid": sig_valid,
        "id_valid": id_valid,
        "key_id": key_id,
        "key_fingerprint": sig_block.get("key_fingerprint"),
        "error": None,
    }
