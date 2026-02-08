"""
Core Integrity Verifier for Assay Proof Packs.

Design constraints (from spec):
  - < 500 LOC
  - < 5 dependencies (hashlib, json, dataclasses, pathlib, typing)
  - Never shells out
  - No business logic, no policy interpretation
  - Deterministic error codes

Verifies:
  - Receipt field presence and format
  - JCS canonicalization stability
  - Pack manifest file hashes
  - Pack manifest signature
  - Receipt count (omission resistance)
  - Attestation hash binding
"""
from __future__ import annotations

import hashlib
import json
import base64
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nacl.signing import VerifyKey

from assay._receipts.canonicalize import to_jcs_bytes

# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

E_CANON_MISMATCH = "E_CANON_MISMATCH"
E_SCHEMA_UNKNOWN = "E_SCHEMA_UNKNOWN"
E_SIG_INVALID = "E_SIG_INVALID"
E_SIG_MISSING = "E_SIG_MISSING"
E_POLICY_MISSING = "E_POLICY_MISSING"
E_CHAIN_BROKEN = "E_CHAIN_BROKEN"
E_PACK_SIG_INVALID = "E_PACK_SIG_INVALID"
E_PACK_OMISSION_DETECTED = "E_PACK_OMISSION_DETECTED"
E_MANIFEST_TAMPER = "E_MANIFEST_TAMPER"
E_TIMESTAMP_INVALID = "E_TIMESTAMP_INVALID"
E_DUPLICATE_ID = "E_DUPLICATE_ID"

@dataclass
class VerifyError:
    """A single verification error."""

    code: str
    message: str
    receipt_index: Optional[int] = None
    field: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.receipt_index is not None:
            d["receipt_index"] = self.receipt_index
        if self.field is not None:
            d["field"] = self.field
        return d


@dataclass
class VerifyResult:
    """Aggregate verification result."""

    passed: bool
    errors: List[VerifyError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    receipt_count: int = 0
    head_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": self.warnings,
            "receipt_count": self.receipt_count,
            "head_hash": self.head_hash,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Try to parse an ISO 8601 timestamp. Return None on failure."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Receipt-level verification
# ---------------------------------------------------------------------------

REQUIRED_RECEIPT_FIELDS = ("receipt_id", "type", "timestamp")


def verify_receipt(
    receipt: Dict[str, Any],
    *,
    index: Optional[int] = None,
    strict: bool = False,
) -> List[VerifyError]:
    """Verify a single receipt's integrity.

    Checks (always):
      - Required fields present (receipt_id, type, timestamp)
      - Timestamp is valid ISO 8601
      - JCS canonicalization is stable (round-trip)

    Checks (strict=True only):
      - schema_version present
      - policy_hash or governance_hash present (E_POLICY_MISSING)
      - Receipt-level signature or payload_hash present (E_SIG_MISSING)
    """
    errors: List[VerifyError] = []

    # Required fields
    for f in REQUIRED_RECEIPT_FIELDS:
        if not receipt.get(f):
            errors.append(VerifyError(
                code=E_SCHEMA_UNKNOWN,
                message=f"Missing required field: {f}",
                receipt_index=index,
                field=f,
            ))

    # Timestamp validity
    ts = receipt.get("timestamp")
    if ts is not None:
        if _parse_timestamp(str(ts)) is None:
            errors.append(VerifyError(
                code=E_TIMESTAMP_INVALID,
                message=f"Invalid timestamp: {ts}",
                receipt_index=index,
                field="timestamp",
            ))

    # Strict-mode checks
    if strict:
        if not receipt.get("schema_version"):
            errors.append(VerifyError(
                code=E_SCHEMA_UNKNOWN,
                message="Missing schema_version (required in strict mode)",
                receipt_index=index,
                field="schema_version",
            ))

        has_policy = receipt.get("policy_hash") or receipt.get("governance_hash")
        if not has_policy:
            errors.append(VerifyError(
                code=E_POLICY_MISSING,
                message="Missing policy_hash or governance_hash",
                receipt_index=index,
                field="policy_hash",
            ))

        has_sig = receipt.get("signature") or receipt.get("payload_hash")
        if not has_sig:
            errors.append(VerifyError(
                code=E_SIG_MISSING,
                message="Missing receipt-level signature or payload_hash",
                receipt_index=index,
                field="signature",
            ))

    # Canonicalization stability
    try:
        canonical_bytes = to_jcs_bytes(receipt)
        roundtrip = json.loads(canonical_bytes.decode("utf-8"))
        canonical_bytes_2 = to_jcs_bytes(roundtrip)
        if canonical_bytes != canonical_bytes_2:
            errors.append(VerifyError(
                code=E_CANON_MISMATCH,
                message="JCS canonicalization is not stable (round-trip mismatch)",
                receipt_index=index,
            ))
    except (ValueError, TypeError, RuntimeError) as exc:
        errors.append(VerifyError(
            code=E_CANON_MISMATCH,
            message=f"Canonicalization failed: {exc}",
            receipt_index=index,
        ))

    return errors


# ---------------------------------------------------------------------------
# Receipt-pack-level verification
# ---------------------------------------------------------------------------

def verify_receipt_pack(
    receipts: List[Dict[str, Any]],
    *,
    strict: bool = False,
) -> VerifyResult:
    """Verify a list of receipts: individual integrity + duplicate detection.

    Args:
        receipts: List of receipt dicts.
        strict: When True, also enforce policy_hash and signature presence.

    Returns a VerifyResult with aggregate status.
    """
    all_errors: List[VerifyError] = []
    warnings: List[str] = []
    seen_ids: set = set()
    head_hash: Optional[str] = None

    for i, receipt in enumerate(receipts):
        errors = verify_receipt(receipt, index=i, strict=strict)
        all_errors.extend(errors)

        # Duplicate receipt_id
        rid = receipt.get("receipt_id")
        if rid:
            if rid in seen_ids:
                all_errors.append(VerifyError(
                    code=E_DUPLICATE_ID,
                    message=f"Duplicate receipt_id: {rid}",
                    receipt_index=i,
                    field="receipt_id",
                ))
            seen_ids.add(rid)

        # Compute running head hash (last receipt's canonical hash)
        try:
            head_hash = _sha256_hex(to_jcs_bytes(receipt))
        except Exception:
            pass

    return VerifyResult(
        passed=len(all_errors) == 0,
        errors=all_errors,
        warnings=warnings,
        receipt_count=len(receipts),
        head_hash=head_hash,
    )


# ---------------------------------------------------------------------------
# Pack manifest verification
# ---------------------------------------------------------------------------

def verify_pack_manifest(
    manifest: Dict[str, Any],
    pack_dir: Path,
    keystore: Any,
) -> VerifyResult:
    """Verify pack_manifest.json integrity.

    Checks:
      1. File hashes match files on disk
      2. Receipt count matches receipt_pack.jsonl
      3. Attestation hash matches embedded attestation
      4. Manifest signature is valid
    """
    errors: List[VerifyError] = []
    warnings: List[str] = []

    # 1. Verify file hashes
    files_list = manifest.get("files", [])
    for file_entry in files_list:
        file_path = pack_dir / file_entry["path"]
        expected_hash = file_entry.get("sha256")
        expected_bytes = file_entry.get("bytes")

        if not file_path.exists():
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"File missing: {file_entry['path']}",
                field=file_entry["path"],
            ))
            continue

        actual_data = file_path.read_bytes()
        actual_hash = _sha256_hex(actual_data)

        if expected_hash and actual_hash != expected_hash:
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"Hash mismatch for {file_entry['path']}: "
                        f"expected {expected_hash[:16]}..., got {actual_hash[:16]}...",
                field=file_entry["path"],
            ))

        if expected_bytes is not None and len(actual_data) != expected_bytes:
            warnings.append(
                f"Size mismatch for {file_entry['path']}: "
                f"expected {expected_bytes}, got {len(actual_data)}"
            )

    # 1b. Verify expected files completeness
    for name in manifest.get("expected_files") or []:
        if not (pack_dir / name).exists() and not any(e.field == name for e in errors):
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"Expected file missing: {name}",
                field=name,
            ))

    # 2. Parse receipt_pack.jsonl, recompute integrity, cross-check attestation
    receipt_pack_path = pack_dir / "receipt_pack.jsonl"
    parsed: List[Dict[str, Any]] = []
    if receipt_pack_path.exists():
        parsed = [json.loads(ln) for ln in receipt_pack_path.read_text().splitlines() if ln.strip()]
    receipt_count_expected = manifest.get("receipt_count_expected")
    if receipt_count_expected is not None and len(parsed) != receipt_count_expected:
        errors.append(VerifyError(
            code=E_PACK_OMISSION_DETECTED,
            message=f"Receipt count mismatch: manifest says {receipt_count_expected}, "
                    f"file has {len(parsed)}",
        ))
    recomputed = verify_receipt_pack(parsed)
    attestation = manifest.get("attestation") or {}
    claimed_integrity = attestation.get("receipt_integrity")
    if claimed_integrity and ("PASS" if recomputed.passed else "FAIL") != claimed_integrity:
        errors.append(VerifyError(
            code=E_MANIFEST_TAMPER,
            message=f"Recomputed receipt_integrity is {'PASS' if recomputed.passed else 'FAIL'}, "
                    f"attestation claims {claimed_integrity}",
            field="receipt_integrity",
        ))
    claimed_head = attestation.get("head_hash")
    if claimed_head and recomputed.head_hash and claimed_head != recomputed.head_hash:
        errors.append(VerifyError(
            code=E_MANIFEST_TAMPER,
            message="Recomputed head_hash does not match attestation",
            field="head_hash",
        ))

    # 3. Attestation hash
    attestation_sha256 = manifest.get("attestation_sha256")
    if attestation and attestation_sha256:
        if _sha256_hex(to_jcs_bytes(attestation)) != attestation_sha256:
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message="Attestation hash mismatch in manifest",
                field="attestation_sha256",
            ))

    # 4. Manifest signature verification
    signature = manifest.get("signature")
    signer_id = manifest.get("signer_id")
    signer_pubkey_b64 = manifest.get("signer_pubkey")
    signer_pubkey_sha256 = manifest.get("signer_pubkey_sha256")

    signature_bytes: Optional[bytes] = None
    if not signature:
        errors.append(VerifyError(
            code=E_PACK_SIG_INVALID,
            message="Manifest has no signature",
        ))
    else:
        try:
            signature_bytes = base64.b64decode(signature)
        except Exception:
            errors.append(VerifyError(
                code=E_PACK_SIG_INVALID,
                message="Manifest signature is not valid base64",
                field="signature",
            ))

    if signature:
        # 4a. Detached signature must match manifest signature bytes
        sig_path = pack_dir / "pack_signature.sig"
        if not sig_path.exists():
            errors.append(VerifyError(
                code=E_PACK_SIG_INVALID,
                message="Detached signature file missing: pack_signature.sig",
                field="pack_signature.sig",
            ))
        elif signature_bytes is not None:
            sig_from_file = sig_path.read_bytes()
            if sig_from_file != signature_bytes:
                errors.append(VerifyError(
                    code=E_PACK_SIG_INVALID,
                    message="Detached signature does not match manifest signature bytes",
                    field="pack_signature.sig",
                ))

    # 4b. Reconstruct unsigned manifest (remove post-signing fields)
    unsigned = {
        k: v for k, v in manifest.items()
        if k not in ("signature", "pack_root_sha256")
    }
    canonical_bytes = to_jcs_bytes(unsigned)

    # 4c. Verify Ed25519 signature.
    #
    # Primary path (portable): verify with signer_pubkey embedded in manifest.
    # Fallback path (compat): verify via local keystore for older packs.
    if signature and signature_bytes is not None:
        verified = False

        if signer_pubkey_b64:
            try:
                pubkey_bytes = base64.b64decode(signer_pubkey_b64)
                actual_embedded_fp = _sha256_hex(pubkey_bytes)
                if (
                    signer_pubkey_sha256
                    and actual_embedded_fp != signer_pubkey_sha256
                ):
                    errors.append(VerifyError(
                        code=E_PACK_SIG_INVALID,
                        message=(
                            "Embedded signer_pubkey does not match "
                            "signer_pubkey_sha256"
                        ),
                        field="signer_pubkey_sha256",
                    ))
                else:
                    vk = VerifyKey(pubkey_bytes)
                    vk.verify(canonical_bytes, signature_bytes)
                    verified = True
            except Exception:
                errors.append(VerifyError(
                    code=E_PACK_SIG_INVALID,
                    message="Manifest signature verification failed against embedded signer_pubkey",
                    field="signer_pubkey",
                ))

        elif keystore and signer_id:
            if keystore.verify_b64(canonical_bytes, signature, signer_id):
                verified = True
            else:
                errors.append(VerifyError(
                    code=E_PACK_SIG_INVALID,
                    message="Manifest signature verification failed",
                ))
        else:
            errors.append(VerifyError(
                code=E_PACK_SIG_INVALID,
                message="Cannot verify signature: missing signer_pubkey and no keystore fallback",
            ))

        if verified and keystore and signer_id and signer_pubkey_sha256:
            # Optional operator check: if local key for signer_id exists, flag drift.
            try:
                local_vk = keystore.get_verify_key(signer_id)
                local_fp = _sha256_hex(local_vk.encode())
                if local_fp != signer_pubkey_sha256:
                    warnings.append(
                        "Local keystore key fingerprint differs from embedded signer_pubkey_sha256"
                    )
            except Exception:
                pass

    # 4d. Verify pack_root_sha256 = attestation_sha256 (D12)
    pack_root = manifest.get("pack_root_sha256")
    if pack_root and attestation_sha256 and pack_root != attestation_sha256:
        errors.append(VerifyError(
            code=E_MANIFEST_TAMPER,
            message="pack_root_sha256 does not match attestation_sha256",
            field="pack_root_sha256",
        ))

    return VerifyResult(
        passed=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        receipt_count=len(parsed),
        head_hash=recomputed.head_hash,
    )


__all__ = [
    "E_CANON_MISMATCH",
    "E_SCHEMA_UNKNOWN",
    "E_SIG_INVALID",
    "E_SIG_MISSING",
    "E_POLICY_MISSING",
    "E_CHAIN_BROKEN",
    "E_PACK_SIG_INVALID",
    "E_PACK_OMISSION_DETECTED",
    "E_MANIFEST_TAMPER",
    "E_TIMESTAMP_INVALID",
    "E_DUPLICATE_ID",
    "VerifyError",
    "VerifyResult",
    "verify_receipt",
    "verify_receipt_pack",
    "verify_pack_manifest",
]
