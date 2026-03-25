"""
Acceptance Receipt: signed artifact-of-artifacts for pilot closeout.

An acceptance receipt references a verified Proof Pack by hash and records
the verification verdict in a single signed JSON file. It is the stable
"contract closure" artifact: verify this one file, everything else is
referenced by hash.

Usage:
    receipt = generate_acceptance_receipt(manifest, verify_result, keystore)
    # -> dict, also writes ACCEPTANCE_RECEIPT.json

    result = verify_acceptance_receipt(receipt, keystore)
    # -> AcceptanceVerifyResult
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.keystore import AssayKeyStore, get_default_keystore
from nacl.signing import VerifyKey

SCHEMA_VERSION = "1.0.0"


@dataclass
class AcceptanceVerifyResult:
    """Result of verifying an acceptance receipt."""
    passed: bool
    errors: List[str]


def generate_acceptance_receipt(
    manifest: Dict[str, Any],
    *,
    integrity_passed: bool,
    claims_verdict: str = "N/A",
    exit_code: int = 0,
    keystore: Optional[AssayKeyStore] = None,
    signer_id: Optional[str] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Generate a signed acceptance receipt from a verified pack manifest.

    Args:
        manifest: The signed pack_manifest.json dict.
        integrity_passed: Whether pack integrity verification passed.
        claims_verdict: "PASS", "FAIL", or "N/A".
        exit_code: Assay exit code (0, 1, or 2).
        keystore: Key store for signing. Defaults to ~/.assay/keys/.
        signer_id: Signer to use. Defaults to active signer.
        output_path: If provided, write ACCEPTANCE_RECEIPT.json here.

    Returns:
        The signed acceptance receipt dict.
    """
    ks = keystore or get_default_keystore()
    if signer_id is None:
        signer_id = ks.get_active_signer()

    att = manifest.get("attestation", {})

    # Build unsigned receipt body
    receipt: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "pack_id": att.get("pack_id", ""),
        "pack_root_sha256": manifest.get("pack_root_sha256", ""),
        "attestation_sha256": manifest.get("attestation_sha256", ""),
        "claim_set_hash": att.get("claim_set_hash", ""),
        "verification": {
            "integrity": "PASS" if integrity_passed else "FAIL",
            "claims": claims_verdict,
            "exit_code": exit_code,
        },
        "ci_binding": att.get("ci_binding"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "signer": {
            "signer_id": signer_id,
            "signer_pubkey": base64.b64encode(ks.get_verify_key(signer_id).encode()).decode("ascii"),
            "pubkey_fingerprint": ks.signer_fingerprint(signer_id),
            "signature": "",  # placeholder, replaced after signing
        },
    }

    # Sign: JCS-canonicalize the receipt with empty signature, then sign
    signable = copy.deepcopy(receipt)
    signable["signer"]["signature"] = ""
    canonical_bytes = jcs_canonicalize(signable)
    signature_b64 = ks.sign_b64(canonical_bytes, signer_id)
    receipt["signer"]["signature"] = signature_b64

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(receipt, indent=2) + "\n")

    return receipt


def verify_acceptance_receipt(
    receipt: Dict[str, Any],
    keystore: Optional[AssayKeyStore] = None,
    *,
    expected_pack_root: Optional[str] = None,
) -> AcceptanceVerifyResult:
    """Verify an acceptance receipt's signature and optionally check pack reference.

    Args:
        receipt: The acceptance receipt dict.
        keystore: Key store for signature verification.
        expected_pack_root: If provided, verify receipt references this pack.

    Returns:
        AcceptanceVerifyResult with passed/errors.
    """
    errors: List[str] = []

    # Schema version check
    if receipt.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"Unknown schema_version: {receipt.get('schema_version')!r} "
            f"(expected {SCHEMA_VERSION!r})"
        )

    # D12 invariant: pack_root_sha256 == attestation_sha256
    pack_root = receipt.get("pack_root_sha256", "")
    att_sha = receipt.get("attestation_sha256", "")
    if pack_root and att_sha and pack_root != att_sha:
        errors.append(
            f"D12 invariant violated: pack_root_sha256 ({pack_root[:16]}...) "
            f"!= attestation_sha256 ({att_sha[:16]}...)"
        )

    # Optional: check expected pack reference
    if expected_pack_root and pack_root != expected_pack_root:
        errors.append(
            f"Pack reference mismatch: receipt references {pack_root[:16]}..., "
            f"expected {expected_pack_root[:16]}..."
        )

    # Signature verification
    signer_block = receipt.get("signer", {})
    signer_id = signer_block.get("signer_id", "")
    signer_pubkey_b64 = signer_block.get("signer_pubkey", "")
    signature_b64 = signer_block.get("signature", "")
    claimed_fp = signer_block.get("pubkey_fingerprint", "")

    if not signature_b64:
        errors.append("Missing signer.signature")
    else:
        # Reconstruct the signable form (signature = "")
        signable = copy.deepcopy(receipt)
        signable["signer"]["signature"] = ""
        canonical_bytes = jcs_canonicalize(signable)

        verified = False

        # Primary path: embedded public key (portable verification)
        if signer_pubkey_b64:
            try:
                pubkey_bytes = base64.b64decode(signer_pubkey_b64)
                actual_fp = hashlib.sha256(pubkey_bytes).hexdigest()
                if claimed_fp and actual_fp != claimed_fp:
                    errors.append(
                        f"Fingerprint mismatch: signer_pubkey hashes to {actual_fp[:16]}..., "
                        f"receipt claims {claimed_fp[:16]}..."
                    )
                else:
                    vk = VerifyKey(pubkey_bytes)
                    vk.verify(canonical_bytes, base64.b64decode(signature_b64))
                    verified = True
            except Exception as e:
                errors.append(f"Embedded signer_pubkey verification failed: {e}")

        # Fallback path: local keystore by signer_id (backward compatibility)
        elif signer_id:
            ks = keystore or get_default_keystore()
            try:
                valid = ks.verify_b64(canonical_bytes, signature_b64, signer_id)
                if valid:
                    verified = True
                else:
                    errors.append("Signature verification failed: invalid signature")
            except FileNotFoundError:
                errors.append(f"Signer key not found: {signer_id}")
            except Exception as e:
                errors.append(f"Signature verification error: {e}")
        else:
            errors.append("Missing signer.signer_id and signer.signer_pubkey")

        if not verified and not errors:
            errors.append("Signature verification failed")

    return AcceptanceVerifyResult(passed=len(errors) == 0, errors=errors)


__all__ = [
    "SCHEMA_VERSION",
    "AcceptanceVerifyResult",
    "generate_acceptance_receipt",
    "verify_acceptance_receipt",
]
