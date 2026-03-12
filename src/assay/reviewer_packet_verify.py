"""Verify reviewer-facing packets built around an Assay proof pack."""
from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nacl.signing import VerifyKey

from assay._receipts.canonicalize import to_jcs_bytes
from assay.integrity import VerifyResult, verify_pack_manifest
from assay.keystore import get_default_keystore
from assay.reviewer_packet_compile import (
    _PACKET_INPUTS_FILE,
    _PACKET_MANIFEST_FILE,
    _PACKET_SIGNATURE_FILE,
    _add_period_days,
    _build_scope_manifest,
    _derive_regression_state_from_baseline_state,
    _derive_settlement_state,
    _evaluate_question,
    _freshness_state,
)
from assay.vendorq_models import VendorQInputError, now_utc_iso, parse_iso8601, resolve_pointer

_ALLOWED_SETTLEMENT_STATES = {
    "VERIFIED",
    "VERIFIED_WITH_GAPS",
    "INCOMPLETE_EVIDENCE",
    "EVIDENCE_REGRESSION",
    "TAMPERED",
    "OUT_OF_SCOPE",
}
_ALLOWED_INTEGRITY_STATES = {"PASS", "FAIL"}
_ALLOWED_CLAIM_STATES = {"PASS", "FAIL"}
_ALLOWED_SCOPE_STATES = {"BOUNDED", "OUT_OF_SCOPE"}
_ALLOWED_FRESHNESS_STATES = {"FRESH", "STALE"}
_ALLOWED_REGRESSION_STATES = {"NONE", "REGRESSED"}
_ALLOWED_COVERAGE_STATUSES = {
    "EVIDENCED",
    "PARTIAL",
    "FAILED",
    "HUMAN_ATTESTED",
    "OUT_OF_SCOPE",
}
_COVERAGE_STATUSES_REQUIRING_EVIDENCE_REFS = {
    "EVIDENCED",
    "PARTIAL",
    "FAILED",
}
_COVERAGE_COLUMNS = ["Claim / Question", "Status", "Evidence", "Scope", "Notes"]
_PACKET_REQUIRED_FILES = (
    "SETTLEMENT.json",
    "SCOPE_MANIFEST.json",
    "COVERAGE_MATRIX.md",
    _PACKET_INPUTS_FILE,
    _PACKET_MANIFEST_FILE,
)


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise VendorQInputError(f"file_not_found: {path}")
    except json.JSONDecodeError as exc:
        raise VendorQInputError(f"invalid_json: {path}: {exc.msg}")


def _load_required_packet_files(packet_dir: Path) -> Tuple[Dict[str, Any], Dict[str, Any], str, Dict[str, Any], Dict[str, Any]]:
    for file_name in _PACKET_REQUIRED_FILES:
        if not (packet_dir / file_name).exists():
            raise VendorQInputError(f"reviewer_packet_missing_file: {packet_dir / file_name}")

    settlement = _load_json(packet_dir / "SETTLEMENT.json")
    scope_manifest = _load_json(packet_dir / "SCOPE_MANIFEST.json")
    coverage_matrix = (packet_dir / "COVERAGE_MATRIX.md").read_text(encoding="utf-8")
    packet_inputs = _load_json(packet_dir / _PACKET_INPUTS_FILE)
    packet_manifest = _load_json(packet_dir / _PACKET_MANIFEST_FILE)
    return settlement, scope_manifest, coverage_matrix, packet_inputs, packet_manifest


def _resolve_proof_pack_dir(packet_dir: Path, settlement_payload: Dict[str, Any]) -> Path:
    rel = Path(str(settlement_payload.get("proof_pack_path") or "./proof_pack"))
    if rel.is_absolute() or ".." in rel.parts:
        raise VendorQInputError(f"invalid_proof_pack_path: {rel}")
    proof_pack_dir = (packet_dir / rel).resolve()
    if not proof_pack_dir.is_dir():
        raise VendorQInputError(f"proof_pack_dir_not_found: {proof_pack_dir}")
    return proof_pack_dir


def _parse_markdown_row(line: str) -> List[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise VendorQInputError("invalid_coverage_matrix_row")
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _parse_coverage_matrix(markdown: str) -> List[Dict[str, str]]:
    lines = [line.strip() for line in markdown.splitlines() if line.strip()]
    header_idx: Optional[int] = None
    for idx, line in enumerate(lines):
        if line.startswith("|") and _parse_markdown_row(line) == _COVERAGE_COLUMNS:
            header_idx = idx
            break

    if header_idx is None:
        raise VendorQInputError("coverage_matrix_missing_header")
    if header_idx + 2 >= len(lines):
        raise VendorQInputError("coverage_matrix_has_no_rows")

    rows: List[Dict[str, str]] = []
    for line in lines[header_idx + 2 :]:
        if not line.startswith("|"):
            continue
        cells = _parse_markdown_row(line)
        if len(cells) != len(_COVERAGE_COLUMNS):
            raise VendorQInputError("coverage_matrix_wrong_column_count")
        rows.append(dict(zip(_COVERAGE_COLUMNS, cells)))

    if not rows:
        raise VendorQInputError("coverage_matrix_has_no_rows")
    return rows


def _validate_settlement_payload(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    required_fields = [
        "packet_id",
        "packet_version",
        "artifact_type",
        "settlement_state",
        "integrity_state",
        "claim_state",
        "scope_state",
        "freshness_state",
        "regression_state",
        "generated_at",
        "valid_for",
        "expires_at",
        "pack_manifest_sha256",
        "proof_pack_path",
        "settlement_basis",
        "signer",
        "trust_tier",
    ]
    for field in required_fields:
        if field not in payload:
            errors.append(f"SETTLEMENT.json missing field: {field}")

    if payload.get("artifact_type") != "reviewer_packet":
        errors.append("SETTLEMENT.json artifact_type must be reviewer_packet")
    if str(payload.get("settlement_state")) not in _ALLOWED_SETTLEMENT_STATES:
        errors.append(f"SETTLEMENT.json has unknown settlement_state: {payload.get('settlement_state')}")
    if str(payload.get("integrity_state")) not in _ALLOWED_INTEGRITY_STATES:
        errors.append(f"SETTLEMENT.json has unknown integrity_state: {payload.get('integrity_state')}")
    if str(payload.get("claim_state")) not in _ALLOWED_CLAIM_STATES:
        errors.append(f"SETTLEMENT.json has unknown claim_state: {payload.get('claim_state')}")
    if str(payload.get("scope_state")) not in _ALLOWED_SCOPE_STATES:
        errors.append(f"SETTLEMENT.json has unknown scope_state: {payload.get('scope_state')}")
    if str(payload.get("freshness_state")) not in _ALLOWED_FRESHNESS_STATES:
        errors.append(f"SETTLEMENT.json has unknown freshness_state: {payload.get('freshness_state')}")
    if str(payload.get("regression_state")) not in _ALLOWED_REGRESSION_STATES:
        errors.append(f"SETTLEMENT.json has unknown regression_state: {payload.get('regression_state')}")
    if parse_iso8601(str(payload.get("generated_at") or "")) is None:
        errors.append("SETTLEMENT.json generated_at must be ISO-8601")
    if parse_iso8601(str(payload.get("expires_at") or "")) is None:
        errors.append("SETTLEMENT.json expires_at must be ISO-8601")

    pack_hash = str(payload.get("pack_manifest_sha256") or "")
    if len(pack_hash) != 64 or any(ch not in "0123456789abcdef" for ch in pack_hash):
        errors.append("SETTLEMENT.json pack_manifest_sha256 must be a 64-char lowercase hex SHA-256")

    settlement_basis = payload.get("settlement_basis")
    if not isinstance(settlement_basis, list) or not settlement_basis or not all(isinstance(item, str) and item for item in settlement_basis):
        errors.append("SETTLEMENT.json settlement_basis must be a non-empty list of strings")

    signer = payload.get("signer")
    if not isinstance(signer, dict):
        errors.append("SETTLEMENT.json signer must be an object")
    else:
        for key in ("mode", "identity", "fingerprint"):
            if not signer.get(key):
                errors.append(f"SETTLEMENT.json signer missing field: {key}")

    if not payload.get("trust_tier"):
        errors.append("SETTLEMENT.json trust_tier must be non-empty")
    return errors


def _validate_scope_manifest(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    required_fields = ["questions_mapped", "questions_out_of_scope", "signed_at", "signed_by"]
    for field in required_fields:
        if field not in payload:
            errors.append(f"SCOPE_MANIFEST.json missing field: {field}")

    if parse_iso8601(str(payload.get("signed_at") or "")) is None:
        errors.append("SCOPE_MANIFEST.json signed_at must be ISO-8601")
    if not payload.get("signed_by"):
        errors.append("SCOPE_MANIFEST.json signed_by must be non-empty")

    for key in ("questions_mapped", "questions_out_of_scope"):
        value = payload.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            errors.append(f"SCOPE_MANIFEST.json {key} must be a list of strings")
    return errors


def _split_evidence_refs(cell: str) -> List[str]:
    if not cell or cell == "None":
        return []
    refs: List[str] = []
    for segment in cell.split(";"):
        for item in segment.split(" and "):
            ref = item.strip().strip("`")
            if ref:
                refs.append(ref)
    return refs


def _validate_coverage_rows(
    rows: List[Dict[str, str]],
    *,
    packet_dir: Path,
    scope_manifest: Dict[str, Any],
) -> Tuple[List[str], Counter]:
    errors: List[str] = []
    counts: Counter = Counter()
    json_cache: Dict[Path, Dict[str, Any]] = {}

    mapped_questions = set(str(item) for item in scope_manifest.get("questions_mapped", []))
    out_of_scope_questions = set(str(item) for item in scope_manifest.get("questions_out_of_scope", []))

    for row in rows:
        status = row["Status"]
        counts[status] += 1
        if status not in _ALLOWED_COVERAGE_STATUSES:
            errors.append(f"COVERAGE_MATRIX.md has unknown row status: {status}")
            continue

        question = row["Claim / Question"]
        if status == "OUT_OF_SCOPE":
            if out_of_scope_questions and question not in out_of_scope_questions:
                errors.append(f"COVERAGE_MATRIX.md out-of-scope row not declared in SCOPE_MANIFEST.json: {question}")
        elif mapped_questions and question not in mapped_questions:
            errors.append(f"COVERAGE_MATRIX.md in-scope row not declared in SCOPE_MANIFEST.json: {question}")

        if status not in _COVERAGE_STATUSES_REQUIRING_EVIDENCE_REFS:
            continue

        for ref in _split_evidence_refs(row["Evidence"]):
            if "#" in ref:
                file_part, pointer = ref.split("#", 1)
            else:
                file_part, pointer = ref, ""
            file_path = packet_dir / file_part
            if not file_path.exists():
                errors.append(f"COVERAGE_MATRIX.md evidence target missing: {file_part}")
                continue
            if pointer and file_path.suffix == ".json":
                payload = json_cache.get(file_path)
                if payload is None:
                    payload = _load_json(file_path)
                    json_cache[file_path] = payload
                ok, _ = resolve_pointer(payload, pointer)
                if not ok:
                    errors.append(f"COVERAGE_MATRIX.md evidence pointer not found: {ref}")

    return errors, counts


def _derive_claim_state(proof_pack_dir: Path) -> str:
    verify_report = _load_json(proof_pack_dir / "verify_report.json")
    claim_verification = verify_report.get("claim_verification")
    if isinstance(claim_verification, dict):
        return "PASS" if bool(claim_verification.get("passed")) else "FAIL"

    manifest = _load_json(proof_pack_dir / "pack_manifest.json")
    attestation = manifest.get("attestation") or {}
    return "PASS" if str(attestation.get("claim_check") or "PASS") == "PASS" else "FAIL"


def _verify_packet_manifest(
    packet_dir: Path,
    packet_manifest: Dict[str, Any],
    *,
    keystore: Any | None,
) -> Tuple[List[str], List[str], bool, bool]:
    errors: List[str] = []
    warnings: List[str] = []
    signed = bool(packet_manifest.get("signature"))
    verified = True

    for entry in packet_manifest.get("files", []):
        rel_path = str(entry.get("path") or "")
        file_path = packet_dir / rel_path
        if not file_path.exists():
            errors.append(f"PACKET_MANIFEST.json referenced file missing: {rel_path}")
            verified = False
            continue
        actual_sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_sha256 != entry.get("sha256"):
            errors.append(f"PACKET_MANIFEST.json file hash mismatch: {rel_path}")
            verified = False

    if not signed:
        warnings.append("PACKET_MANIFEST.json is unsigned; packet integrity is only hash-checked, not cryptographically attested.")
        return errors, warnings, verified, signed

    signature = str(packet_manifest.get("signature") or "")
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception:
        errors.append("PACKET_MANIFEST.json signature is not valid base64")
        return errors, warnings, False, signed

    sig_path = packet_dir / _PACKET_SIGNATURE_FILE
    if not sig_path.exists():
        errors.append(f"Missing detached packet signature: {_PACKET_SIGNATURE_FILE}")
        return errors, warnings, False, signed
    if sig_path.read_bytes() != signature_bytes:
        errors.append(f"Detached packet signature does not match {_PACKET_MANIFEST_FILE} signature")
        return errors, warnings, False, signed

    unsigned_manifest = {k: v for k, v in packet_manifest.items() if k != "signature"}
    canonical_bytes = to_jcs_bytes(unsigned_manifest)
    signer_pubkey_b64 = str(packet_manifest.get("signer_pubkey") or "")
    signer_pubkey_sha256 = str(packet_manifest.get("signer_pubkey_sha256") or "")
    signer_id = str(packet_manifest.get("signer_id") or "")

    if signer_pubkey_b64:
        try:
            pubkey_bytes = base64.b64decode(signer_pubkey_b64)
            actual_fp = hashlib.sha256(pubkey_bytes).hexdigest()
            if signer_pubkey_sha256 and actual_fp != signer_pubkey_sha256:
                errors.append("Embedded packet signer_pubkey does not match signer_pubkey_sha256")
                return errors, warnings, False, signed
            VerifyKey(pubkey_bytes).verify(canonical_bytes, signature_bytes)
        except Exception:
            errors.append("PACKET_MANIFEST.json signature verification failed")
            return errors, warnings, False, signed
    elif keystore and signer_id:
        try:
            if not keystore.verify_b64(canonical_bytes, signature, signer_id):
                errors.append("PACKET_MANIFEST.json signature verification failed")
                return errors, warnings, False, signed
        except Exception:
            errors.append("PACKET_MANIFEST.json signature verification failed")
            return errors, warnings, False, signed
    else:
        errors.append("PACKET_MANIFEST.json cannot be verified: missing embedded signer_pubkey and no keystore fallback")
        return errors, warnings, False, signed

    return errors, warnings, verified, signed


def _derive_effective_freshness_state(
    *,
    generated_at: str,
    expires_at: str,
    evidence_time: str,
    stale_after: Optional[str],
    now: datetime,
) -> str:
    if parse_iso8601(generated_at) is None:
        return "STALE"
    if parse_iso8601(evidence_time) is None:
        return "STALE"
    evidence_freshness = _freshness_state(generated_at, evidence_time, stale_after)
    expires_at_dt = parse_iso8601(expires_at)
    if evidence_freshness == "STALE":
        return "STALE"
    if expires_at_dt is not None and now > expires_at_dt:
        return "STALE"
    return "FRESH"


def _build_proof_pack_context(proof_pack_dir: Path) -> Dict[str, Any]:
    manifest = _load_json(proof_pack_dir / "pack_manifest.json")
    verify_report = _load_json(proof_pack_dir / "verify_report.json")
    attestation = dict(manifest.get("attestation") or {})
    return {
        "manifest": manifest,
        "attestation": attestation,
        "verify_report": verify_report,
        "timestamp_end": str(attestation.get("timestamp_end") or verify_report.get("verified_at") or now_utc_iso()),
    }


def _append_failure_reason(
    failure_reasons: List[Dict[str, str]],
    seen: set[str],
    *,
    code: str,
    message: str,
) -> None:
    if code in seen:
        return
    seen.add(code)
    failure_reasons.append({"code": code, "message": message})


def verify_reviewer_packet(
    packet_dir: Path,
    *,
    keystore: Any | None = None,
) -> Dict[str, Any]:
    packet_dir = Path(packet_dir)
    if not packet_dir.exists() or not packet_dir.is_dir():
        raise VendorQInputError(f"reviewer_packet_dir_not_found: {packet_dir}")

    settlement, scope_manifest, coverage_matrix, packet_inputs, packet_manifest = _load_required_packet_files(packet_dir)
    proof_pack_dir = _resolve_proof_pack_dir(packet_dir, settlement)
    coverage_rows = _parse_coverage_matrix(coverage_matrix)
    proof_pack_local = _build_proof_pack_context(proof_pack_dir)
    boundary_payload = dict(packet_inputs.get("boundary_payload") or {})
    mapping_payload = dict(packet_inputs.get("mapping_payload") or {})
    baseline_state = packet_inputs.get("baseline_settlement_state")
    packet_time = str(settlement.get("generated_at") or "")
    valid_for = str(boundary_payload.get("freshness_policy", {}).get("valid_for") or settlement.get("valid_for") or "P30D")
    stale_after = boundary_payload.get("freshness_policy", {}).get("stale_after")
    signed_by = str(scope_manifest.get("signed_by") or boundary_payload.get("signed_by") or "assay reviewer-packet compiler")
    expected_scope_manifest = _build_scope_manifest(
        boundary_payload=boundary_payload,
        mapping_payload=mapping_payload,
        packet_time=packet_time,
        signed_by=signed_by,
    )
    expected_coverage_rows = [
        _evaluate_question(question, proof_pack_local, boundary_payload)
        for question in mapping_payload.get("questions", [])
    ]
    coverage_counts = Counter(row["Status"] for row in expected_coverage_rows)

    errors = _validate_settlement_payload(settlement)
    errors.extend(_validate_scope_manifest(scope_manifest))
    coverage_errors, _ = _validate_coverage_rows(
        coverage_rows,
        packet_dir=packet_dir,
        scope_manifest=scope_manifest,
    )
    errors.extend(coverage_errors)

    manifest_path = proof_pack_dir / "pack_manifest.json"
    proof_pack_manifest = _load_json(manifest_path)
    actual_manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    proof_pack_result: VerifyResult = verify_pack_manifest(
        proof_pack_manifest,
        proof_pack_dir,
        keystore or get_default_keystore(),
    )
    actual_integrity_state = "PASS" if proof_pack_result.passed else "FAIL"
    actual_claim_state = _derive_claim_state(proof_pack_dir)

    packet_manifest_errors, packet_manifest_warnings, packet_manifest_verified, packet_manifest_signed = _verify_packet_manifest(
        packet_dir,
        packet_manifest,
        keystore=keystore,
    )
    errors.extend(packet_manifest_errors)

    scope_manifest_matches = scope_manifest == expected_scope_manifest
    if not scope_manifest_matches:
        errors.append("SCOPE_MANIFEST.json does not match the derived packet scope manifest")

    coverage_rows_match = coverage_rows == expected_coverage_rows
    if not coverage_rows_match:
        errors.append("COVERAGE_MATRIX.md does not match the derived coverage rows")

    expected_expires_at: Optional[str] = None
    if parse_iso8601(packet_time) is not None:
        expected_expires_at = _add_period_days(packet_time, valid_for)
    valid_for_matches = settlement.get("valid_for") == valid_for
    if not valid_for_matches:
        errors.append(
            f"SETTLEMENT.json valid_for={settlement.get('valid_for')} does not match derived valid_for={valid_for}"
        )
    expires_at_matches = expected_expires_at is None or settlement.get("expires_at") == expected_expires_at
    if not expires_at_matches:
        errors.append(
            f"SETTLEMENT.json expires_at={settlement.get('expires_at')} does not match derived expires_at={expected_expires_at}"
        )

    effective_freshness_state = _derive_effective_freshness_state(
        generated_at=packet_time,
        expires_at=str(settlement.get("expires_at") or expected_expires_at or ""),
        evidence_time=str(proof_pack_local.get("timestamp_end") or packet_time),
        stale_after=str(stale_after) if stale_after else None,
        now=datetime.now(timezone.utc),
    )
    actual_regression_state = _derive_regression_state_from_baseline_state(expected_coverage_rows, str(baseline_state) if baseline_state is not None else None)

    pack_manifest_sha_matches = settlement.get("pack_manifest_sha256") == actual_manifest_sha256
    if not pack_manifest_sha_matches:
        errors.append("SETTLEMENT.json pack_manifest_sha256 does not match proof_pack/pack_manifest.json")

    integrity_matches = settlement.get("integrity_state") == actual_integrity_state
    if not integrity_matches:
        errors.append(
            f"SETTLEMENT.json integrity_state={settlement.get('integrity_state')} "
            f"does not match nested proof pack integrity_state={actual_integrity_state}"
        )

    claim_matches = settlement.get("claim_state") == actual_claim_state
    if not claim_matches:
        errors.append(
            f"SETTLEMENT.json claim_state={settlement.get('claim_state')} "
            f"does not match nested proof pack claim_state={actual_claim_state}"
        )

    freshness_matches = settlement.get("freshness_state") == effective_freshness_state
    if not freshness_matches:
        errors.append(
            f"SETTLEMENT.json freshness_state={settlement.get('freshness_state')} "
            f"does not match derived freshness_state={effective_freshness_state}"
        )

    regression_matches = settlement.get("regression_state") == actual_regression_state
    if not regression_matches:
        errors.append(
            f"SETTLEMENT.json regression_state={settlement.get('regression_state')} "
            f"does not match derived regression_state={actual_regression_state}"
        )

    effective_integrity_state = "PASS" if actual_integrity_state == "PASS" and packet_manifest_verified else "FAIL"

    derived_settlement_state, derived_reason = _derive_settlement_state(
        integrity_state=effective_integrity_state,
        claim_state=actual_claim_state,
        coverage_rows=expected_coverage_rows,
        freshness_state=effective_freshness_state,
        regression_state=actual_regression_state,
    )

    expected_scope_state = "OUT_OF_SCOPE" if derived_settlement_state == "OUT_OF_SCOPE" else "BOUNDED"
    scope_state_matches = settlement.get("scope_state") == expected_scope_state
    if not scope_state_matches:
        errors.append(
            f"SETTLEMENT.json scope_state={settlement.get('scope_state')} "
            f"does not match derived scope_state={expected_scope_state}"
        )

    provided_settlement_state = str(settlement.get("settlement_state") or "")
    settlement_matches = provided_settlement_state == derived_settlement_state
    if not settlement_matches:
        errors.append(
            f"SETTLEMENT.json settlement_state={provided_settlement_state} "
            f"does not match derived settlement_state={derived_settlement_state}"
        )

    basis = settlement.get("settlement_basis") or []
    basis_matches = not basis or basis[0] == derived_reason
    if not basis_matches:
        errors.append("SETTLEMENT.json settlement_basis[0] does not match the derived settlement interpretation")

    if not proof_pack_result.passed:
        for err in proof_pack_result.errors:
            errors.append(f"Nested proof pack verification failed: {err.code}: {err.message}")

    warnings = list(proof_pack_result.warnings) + packet_manifest_warnings
    packet_verified = len(errors) == 0 and derived_settlement_state != "TAMPERED"
    packet_manifest_signer_id = str(packet_manifest.get("signer_id") or "") or None
    packet_manifest_signer_fingerprint = str(packet_manifest.get("signer_pubkey_sha256") or "") or None

    metadata_match_map = {
        "pack_manifest_sha256": pack_manifest_sha_matches,
        "valid_for": valid_for_matches,
        "expires_at": expires_at_matches,
        "integrity_state": integrity_matches,
        "claim_state": claim_matches,
        "freshness_state": freshness_matches,
        "regression_state": regression_matches,
        "scope_state": scope_state_matches,
        "settlement_state": settlement_matches,
        "settlement_basis": basis_matches,
        "scope_manifest": scope_manifest_matches,
        "coverage_matrix": coverage_rows_match,
    }
    metadata_mismatches = [name for name, matched in metadata_match_map.items() if not matched]

    failure_reasons: List[Dict[str, str]] = []
    seen_failure_codes: set[str] = set()
    packet_layer_tamper = bool(packet_manifest_errors) or not scope_manifest_matches or not coverage_rows_match
    if packet_layer_tamper:
        _append_failure_reason(
            failure_reasons,
            seen_failure_codes,
            code="packet_layer_tamper",
            message="Packet-layer files or derived packet views do not match the attested reviewer packet.",
        )
    if not proof_pack_result.passed:
        _append_failure_reason(
            failure_reasons,
            seen_failure_codes,
            code="nested_proof_pack_failure",
            message="Nested proof pack verification failed.",
        )
    if effective_freshness_state == "STALE":
        _append_failure_reason(
            failure_reasons,
            seen_failure_codes,
            code="stale_packet",
            message="Packet evidence is stale under the declared freshness policy.",
        )
    if metadata_mismatches:
        _append_failure_reason(
            failure_reasons,
            seen_failure_codes,
            code="provided_metadata_mismatch",
            message="Provided packet metadata does not match the recomputed verification result.",
        )
    if errors and not failure_reasons:
        _append_failure_reason(
            failure_reasons,
            seen_failure_codes,
            code="invalid_packet_format",
            message="Reviewer packet validation failed.",
        )
    primary_failure_reason = failure_reasons[0]["code"] if failure_reasons else None

    return {
        "packet_id": str(settlement.get("packet_id") or packet_dir.name),
        "packet_verified": packet_verified,
        "provided_settlement_state": provided_settlement_state,
        "settlement_state": derived_settlement_state,
        "settlement_reason": derived_reason,
        "integrity_state": actual_integrity_state,
        "claim_state": actual_claim_state,
        "scope_state": expected_scope_state,
        "freshness_state": effective_freshness_state,
        "regression_state": actual_regression_state,
        "coverage_summary": dict(coverage_counts),
        "errors": errors,
        "warnings": warnings,
        "primary_failure_reason": primary_failure_reason,
        "failure_reasons": failure_reasons,
        "settlement_verification": {
            "recomputed": True,
            "matches_provided": settlement_matches,
            "provided_metadata_matches": len(metadata_mismatches) == 0,
            "metadata_mismatches": metadata_mismatches,
            "basis_matches": basis_matches,
            "provided_state": provided_settlement_state,
            "derived_state": derived_settlement_state,
        },
        "packet_manifest": {
            "path": str(packet_dir / _PACKET_MANIFEST_FILE),
            "signed": packet_manifest_signed,
            "verified": packet_manifest_verified,
            "signer_identity": packet_manifest_signer_id,
            "signer_fingerprint": packet_manifest_signer_fingerprint,
        },
        "proof_pack": {
            "path": str(proof_pack_dir),
            "verified": proof_pack_result.passed,
            "receipt_count": proof_pack_result.receipt_count,
            "head_hash": proof_pack_result.head_hash,
            "errors": [err.to_dict() for err in proof_pack_result.errors],
            "warnings": proof_pack_result.warnings,
        },
    }


__all__ = ["verify_reviewer_packet"]
