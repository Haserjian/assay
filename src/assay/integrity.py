"""Core integrity verifier for Assay Proof Packs."""
from __future__ import annotations

import hashlib
import json
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from nacl.signing import VerifyKey

from assay._receipts.canonicalize import to_jcs_bytes
from assay.pack_verify_policy import inspect_pack_entries, validate_signed_manifest

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
E_PACK_STALE = "E_PACK_STALE"
E_CI_BINDING_MISSING = "E_CI_BINDING_MISSING"
E_CI_BINDING_MISMATCH = "E_CI_BINDING_MISMATCH"
E_PATH_ESCAPE = "E_PATH_ESCAPE"


@dataclass
class VerifyError:
    """A single verification error."""

    code: str
    message: str
    receipt_index: Optional[int] = None
    field: Optional[str] = None
    failure_mechanism: Optional[str] = None

    def __post_init__(self):
        if self.failure_mechanism is None:
            from assay.failure_mechanisms import mechanism_for_code
            self.failure_mechanism = mechanism_for_code(self.code)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.receipt_index is not None:
            d["receipt_index"] = self.receipt_index
        if self.field is not None:
            d["field"] = self.field
        if self.failure_mechanism is not None:
            d["failure_mechanism"] = self.failure_mechanism
        return d
@dataclass
class VerifyResult:
    """Aggregate verification result."""

    passed: bool
    errors: List[VerifyError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    receipt_count: int = 0
    head_hash: Optional[str] = None

    @property
    def failure_mechanisms(self) -> Dict[str, int]:
        """Count of errors grouped by failure mechanism family."""
        c: Dict[str, int] = {}
        for e in self.errors:
            if e.failure_mechanism:
                c[e.failure_mechanism] = c.get(e.failure_mechanism, 0) + 1
        return c

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"passed": self.passed, "errors": [e.to_dict() for e in self.errors],
                              "warnings": self.warnings, "receipt_count": self.receipt_count,
                              "head_hash": self.head_hash}
        if self.failure_mechanisms:
            d["failure_mechanisms"] = self.failure_mechanisms
        return d
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Try to parse an ISO 8601 timestamp. Return None on failure."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _check_containment(file_path: Path, pack_dir: Path) -> bool:
    """Return True if file_path resolves to a location under pack_dir."""
    try:
        file_path.resolve().relative_to(pack_dir.resolve())
        return True
    except ValueError:
        return False


REQUIRED_RECEIPT_FIELDS = ("receipt_id", "type", "timestamp")


def verify_receipt(
    receipt: Dict[str, Any], *, index: Optional[int] = None, strict: bool = False,
) -> List[VerifyError]:
    """Verify a single receipt's integrity (fields, timestamp, JCS stability)."""
    errors: List[VerifyError] = []

    for f in REQUIRED_RECEIPT_FIELDS:
        if not receipt.get(f):
            errors.append(VerifyError(code=E_SCHEMA_UNKNOWN,
                message=f"Missing required field: {f}", receipt_index=index, field=f))

    ts = receipt.get("timestamp")
    if ts is not None and _parse_timestamp(str(ts)) is None:
        errors.append(VerifyError(code=E_TIMESTAMP_INVALID,
            message=f"Invalid timestamp: {ts}", receipt_index=index, field="timestamp"))

    if strict:
        if not receipt.get("schema_version"):
            errors.append(VerifyError(code=E_SCHEMA_UNKNOWN,
                message="Missing schema_version (required in strict mode)",
                receipt_index=index, field="schema_version"))
        if not (receipt.get("policy_hash") or receipt.get("governance_hash")):
            errors.append(VerifyError(code=E_POLICY_MISSING,
                message="Missing policy_hash or governance_hash",
                receipt_index=index, field="policy_hash"))
        if not (receipt.get("signature") or receipt.get("payload_hash")):
            errors.append(VerifyError(code=E_SIG_MISSING,
                message="Missing receipt-level signature or payload_hash",
                receipt_index=index, field="signature"))

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

        # Compute running head hash (last receipt's canonical hash).
        # On failure, record it explicitly — do not silently retain
        # the previous receipt's hash.  A None head_hash will trigger
        # an explicit comparison failure downstream (not a silent skip).
        try:
            head_hash = _sha256_hex(to_jcs_bytes(receipt))
        except Exception:
            head_hash = None

    return VerifyResult(
        passed=len(all_errors) == 0,
        errors=all_errors,
        warnings=warnings,
        receipt_count=len(receipts),
        head_hash=head_hash,
    )
def verify_pack_manifest(
    manifest: Dict[str, Any],
    pack_dir: Path,
    keystore: Any,
    *,
    max_age_hours: Optional[float] = None,
    now: Optional[datetime] = None,
    require_ci_binding: bool = False,
    expected_commit_sha: Optional[str] = None,
) -> VerifyResult:
    """Verify pack_manifest.json integrity.

    Checks:
      0. Manifest passes schema validation (fail closed)
      0b. Expected kernel files are present; `_unsigned/` is an allowed supplementary namespace
      1. File hashes match files on disk
      2. Receipt count matches receipt_pack.jsonl
      3. Attestation hash matches embedded attestation
      4. Manifest signature is valid
    """
    pack_dir = Path(pack_dir)
    errors: List[VerifyError] = []
    warnings: List[str] = []

    schema_errors = validate_signed_manifest(manifest)
    if schema_errors:
        return VerifyResult(
            passed=False,
            errors=[
                VerifyError(
                    code=E_MANIFEST_TAMPER,
                    message=f"Manifest schema validation failed: {error}",
                    field="pack_manifest.json",
                )
                for error in schema_errors
            ],
            warnings=warnings,
            receipt_count=0,
            head_hash=None,
        )

    warnings.extend(inspect_pack_entries(manifest, pack_dir))

    # 1. Verify file hashes
    files_list = manifest.get("files", [])
    for file_entry in files_list:
        file_path = pack_dir / file_entry["path"]
        if not _check_containment(file_path, pack_dir):
            errors.append(VerifyError(
                code=E_PATH_ESCAPE, message=f"Path escapes pack directory: {file_entry['path']}",
                field=file_entry["path"]))
            continue
        expected_hash = file_entry.get("sha256")
        expected_bytes = file_entry.get("bytes")

        if not file_path.exists():
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"File missing: {file_entry['path']}",
                field=file_entry["path"],
            ))
            continue

        try:
            actual_data = file_path.read_bytes()
        except OSError as exc:
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"Cannot read {file_entry['path']}: {exc}",
                field=file_entry["path"],
            ))
            continue
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
        if not _check_containment(pack_dir / name, pack_dir):
            errors.append(VerifyError(code=E_PATH_ESCAPE,
                message=f"Expected file path escapes pack directory: {name}", field=name))
            continue
        if not (pack_dir / name).exists() and not any(e.field == name for e in errors):
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"Expected file missing: {name}",
                field=name,
            ))

    # 2. Parse receipt_pack.jsonl, recompute integrity, cross-check attestation
    receipt_pack_path = pack_dir / "receipt_pack.jsonl"
    parsed: List[Dict[str, Any]] = []
    parse_failed = False
    if receipt_pack_path.exists():
        try:
            lines = receipt_pack_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            parse_failed = True
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message=f"Cannot parse receipt_pack.jsonl: {exc}",
                field="receipt_pack.jsonl",
            ))
            lines = []
        if not parse_failed:
            for line_no, ln in enumerate(lines, start=1):
                if not ln.strip():
                    continue
                try:
                    parsed.append(json.loads(ln))
                except json.JSONDecodeError as exc:
                    parse_failed = True
                    errors.append(VerifyError(
                        code=E_MANIFEST_TAMPER,
                        message=f"Invalid JSON in receipt_pack.jsonl at line {line_no}: {exc.msg}",
                        field="receipt_pack.jsonl",
                    ))
                    break
    receipt_count_expected = manifest.get("receipt_count_expected")
    if (
        receipt_count_expected is not None
        and not parse_failed
        and len(parsed) != receipt_count_expected
    ):
        errors.append(VerifyError(
            code=E_PACK_OMISSION_DETECTED,
            message=f"Receipt count mismatch: manifest says {receipt_count_expected}, "
                    f"file has {len(parsed)}",
        ))
    recomputed = (
        verify_receipt_pack(parsed)
        if not parse_failed
        else VerifyResult(
            passed=False,
            errors=[],
            warnings=["receipt_pack.jsonl parse failed"],
            receipt_count=len(parsed),
            head_hash=None,
        )
    )
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
    if claimed_head:
        # Empty packs: builder uses SHA256(b"empty") as sentinel when
        # there are no receipts.  Verifier recomputes the same sentinel
        # so empty-pack head_hash still round-trips.
        _EMPTY_PACK_HEAD_HASH = _sha256_hex(b"empty")
        effective_recomputed = recomputed.head_hash
        if effective_recomputed is None and recomputed.receipt_count == 0:
            effective_recomputed = _EMPTY_PACK_HEAD_HASH

        if effective_recomputed is None:
            # Attestation claims a head_hash but verifier could not
            # recompute it (non-empty pack, last receipt failed
            # canonicalization).  This is an explicit failure, not a
            # silent skip.  Constitutional rule: if an attestation claims
            # a value, inability to verify it is a verification error.
            errors.append(VerifyError(
                code=E_MANIFEST_TAMPER,
                message="Attestation claims head_hash but verifier could not "
                        "recompute it (last receipt failed canonicalization)",
                field="head_hash",
            ))
        elif claimed_head != effective_recomputed:
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
            try:
                sig_from_file = sig_path.read_bytes()
            except OSError as exc:
                errors.append(VerifyError(
                    code=E_PACK_SIG_INVALID,
                    message=f"Cannot read pack_signature.sig: {exc}",
                    field="pack_signature.sig",
                ))
                sig_from_file = None
            if sig_from_file is not None and sig_from_file != signature_bytes:
                errors.append(VerifyError(
                    code=E_PACK_SIG_INVALID,
                    message="Detached signature does not match manifest signature bytes",
                    field="pack_signature.sig",
                ))

    # 4b. Reconstruct unsigned manifest (remove post-signing fields).
    # NORMATIVE: The signing base is JCS(manifest excluding {"signature",
    # "pack_root_sha256"}).  Do NOT derive this exclusion set from the
    # manifest's "signature_scope" field — that field is descriptive only
    # and older packs carry a legacy value that omits pack_root_sha256.
    _MANIFEST_SIGNING_EXCLUSIONS = ("signature", "pack_root_sha256")
    unsigned = {
        k: v for k, v in manifest.items()
        if k not in _MANIFEST_SIGNING_EXCLUSIONS
    }
    canonical_bytes = to_jcs_bytes(unsigned)

    # 4c. Verify Ed25519 signature (embedded pubkey preferred, keystore fallback).
    if signature and signature_bytes is not None:
        verified = False

        if signer_pubkey_b64:
            try:
                pubkey_bytes = base64.b64decode(signer_pubkey_b64)
                actual_embedded_fp = _sha256_hex(pubkey_bytes)
                if signer_pubkey_sha256 and actual_embedded_fp != signer_pubkey_sha256:
                    errors.append(VerifyError(
                        code=E_PACK_SIG_INVALID,
                        message="Embedded signer_pubkey does not match signer_pubkey_sha256",
                        field="signer_pubkey_sha256",
                    ))
                else:
                    vk = VerifyKey(pubkey_bytes)
                    vk.verify(canonical_bytes, signature_bytes)
                    verified = True
            except Exception:
                errors.append(VerifyError(code=E_PACK_SIG_INVALID,
                    message="Manifest signature verification failed against embedded signer_pubkey",
                    field="signer_pubkey"))

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

    # 5. Optional freshness check (replay/staleness mitigation)
    if max_age_hours is not None:
        att_ts = attestation.get("timestamp_end") or attestation.get("timestamp_start")
        parsed_ts = _parse_timestamp(str(att_ts)) if att_ts else None
        if parsed_ts is None:
            errors.append(VerifyError(
                code=E_TIMESTAMP_INVALID,
                message="Freshness check failed: attestation timestamp_end/start missing or invalid",
                field="timestamp_end",
            ))
        else:
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            now_ts = now or datetime.now(timezone.utc)
            if now_ts.tzinfo is None:
                now_ts = now_ts.replace(tzinfo=timezone.utc)
            age_hours = (now_ts - parsed_ts).total_seconds() / 3600.0
            if age_hours > max_age_hours:
                errors.append(VerifyError(
                    code=E_PACK_STALE,
                    message=(
                        f"Pack is stale: age {age_hours:.2f}h exceeds "
                        f"max_age_hours {max_age_hours:.2f}h"
                    ),
                    field="timestamp_end",
                ))

    # 6. Optional CI binding verification
    attestation = manifest.get("attestation", {})
    ci_binding = attestation.get("ci_binding")
    if require_ci_binding and not ci_binding:
        errors.append(VerifyError(
            code=E_CI_BINDING_MISSING,
            message="CI binding required but attestation has no ci_binding block",
            field="ci_binding",
        ))
    if expected_commit_sha and ci_binding:
        pack_sha = ci_binding.get("commit_sha", "")
        if pack_sha != expected_commit_sha:
            errors.append(VerifyError(
                code=E_CI_BINDING_MISMATCH,
                message=f"CI binding commit_sha mismatch: pack has {pack_sha!r}, expected {expected_commit_sha!r}",
                field="ci_binding.commit_sha",
            ))
    elif expected_commit_sha and not ci_binding and not require_ci_binding:
        errors.append(VerifyError(
            code=E_CI_BINDING_MISSING,
            message=f"Expected commit_sha {expected_commit_sha!r} but attestation has no ci_binding block",
            field="ci_binding",
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
    "E_PACK_STALE",
    "E_CI_BINDING_MISSING",
    "E_CI_BINDING_MISMATCH",
    "E_PATH_ESCAPE",
    "VerifyError",
    "VerifyResult",
    "verify_receipt",
    "verify_receipt_pack",
    "verify_pack_manifest",
]
