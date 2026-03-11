"""Compile reviewer-facing packets from an Assay proof pack plus declarative packet inputs."""
from __future__ import annotations

import base64
import json
import shutil
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from assay._receipts.canonicalize import to_jcs_bytes
from assay.keystore import AssayKeyStore
from assay.vendorq_models import VendorQInputError, now_utc_iso, resolve_pointer, write_json

_PACKET_INPUTS_FILE = "PACKET_INPUTS.json"
_PACKET_MANIFEST_FILE = "PACKET_MANIFEST.json"
_PACKET_SIGNATURE_FILE = "PACKET_SIGNATURE.sig"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_period_days(period: str) -> int:
    value = str(period).strip().upper()
    if not value.startswith("P") or not value.endswith("D"):
        raise VendorQInputError(f"unsupported_period: {period}")
    number = value[1:-1]
    if not number.isdigit():
        raise VendorQInputError(f"unsupported_period: {period}")
    return int(number)


def _add_period_days(ts: str, period: str) -> str:
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed + timedelta(days=_parse_period_days(period))).isoformat()


def _freshness_state(packet_time: str, evidence_time: str, stale_after: Optional[str]) -> str:
    if not stale_after:
        return "FRESH"
    packet_dt = datetime.fromisoformat(packet_time.replace("Z", "+00:00"))
    evidence_dt = datetime.fromisoformat(evidence_time.replace("Z", "+00:00"))
    if packet_dt.tzinfo is None:
        packet_dt = packet_dt.replace(tzinfo=timezone.utc)
    if evidence_dt.tzinfo is None:
        evidence_dt = evidence_dt.replace(tzinfo=timezone.utc)
    return "STALE" if packet_dt - evidence_dt > timedelta(days=_parse_period_days(stale_after)) else "FRESH"


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise VendorQInputError(f"file_not_found: {path}")
    except json.JSONDecodeError as exc:
        raise VendorQInputError(f"invalid_json: {path}: {exc.msg}")


def _load_pack_local(pack_dir: Path) -> Dict[str, Any]:
    if not pack_dir.exists() or not pack_dir.is_dir():
        raise VendorQInputError(f"pack_dir_not_found: {pack_dir}")

    required_files = [
        "receipt_pack.jsonl",
        "pack_manifest.json",
        "pack_signature.sig",
        "verify_report.json",
        "verify_transcript.md",
    ]
    for file_name in required_files:
        if not (pack_dir / file_name).exists():
            raise VendorQInputError(f"pack_missing_file: {pack_dir / file_name}")

    manifest = _load_json(pack_dir / "pack_manifest.json")
    receipts = []
    for line in (pack_dir / "receipt_pack.jsonl").read_text().splitlines():
        line = line.strip()
        if line:
            receipts.append(json.loads(line))
    verify_report = _load_json(pack_dir / "verify_report.json")
    verify_transcript = (pack_dir / "verify_transcript.md").read_text(encoding="utf-8")
    attestation = dict(manifest.get("attestation") or {})

    return {
        "pack_id": str(attestation.get("pack_id") or manifest.get("pack_id") or pack_dir.name),
        "run_id": str(attestation.get("run_id") or verify_report.get("run_id") or "unknown"),
        "manifest": manifest,
        "attestation": attestation,
        "receipts": receipts,
        "verify_report": verify_report,
        "verify_transcript": verify_transcript,
        "timestamp_end": str(attestation.get("timestamp_end") or verify_report.get("verified_at") or now_utc_iso()),
        "manifest_file_sha256": hashlib.sha256((pack_dir / "pack_manifest.json").read_bytes()).hexdigest(),
    }


def _baseline_settlement_state(baseline_packet_dir: Optional[Path]) -> Optional[str]:
    if baseline_packet_dir is None:
        return None
    baseline_settlement_path = baseline_packet_dir / "SETTLEMENT.json"
    if not baseline_settlement_path.exists():
        raise VendorQInputError(f"baseline_missing_settlement: {baseline_settlement_path}")
    baseline = _load_json(baseline_settlement_path)
    return str(baseline.get("settlement_state", ""))


def _read_source(source_type: str, path: str, pack: Dict[str, Any], boundary: Dict[str, Any]) -> Any:
    if source_type == "verify_report_field":
        ok, value = resolve_pointer(pack["verify_report"], path)
    elif source_type == "attestation_field":
        ok, value = resolve_pointer(pack["attestation"], path)
    elif source_type == "manifest_field":
        ok, value = resolve_pointer(pack["manifest"], path)
    elif source_type == "boundary_field":
        ok, value = resolve_pointer(boundary, path)
    else:
        raise VendorQInputError(f"unsupported_mapping_source: {source_type}")
    if not ok:
        raise VendorQInputError(f"mapping_pointer_not_found: {source_type}:{path}")
    return value


def _render_evidence_ref(source_type: str, path: str) -> str:
    if source_type == "verify_report_field":
        return f"proof_pack/verify_report.json#{path}"
    if source_type == "attestation_field":
        return f"proof_pack/pack_manifest.json#attestation.{path}"
    if source_type == "manifest_field":
        return f"proof_pack/pack_manifest.json#{path}"
    if source_type == "boundary_field":
        return f"SCOPE_MANIFEST.json#{path}"
    return f"unknown:{source_type}:{path}"


def _evaluate_question(question: Dict[str, Any], pack: Dict[str, Any], boundary: Dict[str, Any]) -> Dict[str, str]:
    prompt = str(question.get("prompt") or question.get("question_id") or "Unnamed question")
    scope = str(question.get("scope") or boundary.get("workflow_name") or "packet")
    status_rule = str(question.get("status_rule", "OUT_OF_SCOPE"))
    in_scope = bool(question.get("in_scope", True))

    if not in_scope or status_rule == "OUT_OF_SCOPE":
        return {
            "Claim / Question": prompt,
            "Status": "OUT_OF_SCOPE",
            "Evidence": "None",
            "Scope": scope,
            "Notes": str(question.get("out_of_scope_note") or "Question exceeds the declared packet boundary."),
        }

    if status_rule == "ALL_EVIDENCE_REQUIRED":
        evidence_items = list(question.get("evidence", []))
        if not evidence_items:
            raise VendorQInputError(f"mapping_missing_evidence: {prompt}")
        values: List[Any] = []
        refs: List[str] = []
        for item in evidence_items:
            source_type = str(item.get("type", ""))
            path = str(item.get("path", ""))
            values.append(_read_source(source_type, path, pack, boundary))
            refs.append(_render_evidence_ref(source_type, path))
        status = "EVIDENCED" if all(bool(value) for value in values) else "FAILED"
        notes = str(question.get("notes") or ("All required evidence fields are present and truthy." if status == "EVIDENCED" else "One or more required evidence fields is missing or false."))
        return {
            "Claim / Question": prompt,
            "Status": status,
            "Evidence": "; ".join(refs),
            "Scope": scope,
            "Notes": notes,
        }

    if status_rule == "PARTIAL_IF_RATIO_LT_1":
        numerator = int(_read_source("boundary_field", str(question.get("numerator_field", "")), pack, boundary))
        denominator = int(_read_source("boundary_field", str(question.get("denominator_field", "")), pack, boundary))
        if denominator <= 0:
            raise VendorQInputError(f"invalid_ratio_denominator: {prompt}")
        status = "EVIDENCED" if numerator >= denominator else "PARTIAL"
        notes = str(question.get("notes") or ("Coverage is complete for the declared boundary." if status == "EVIDENCED" else f"Coverage is partial: {numerator} of {denominator} identified items are covered."))
        return {
            "Claim / Question": prompt,
            "Status": status,
            "Evidence": f"SCOPE_MANIFEST.json#{question.get('numerator_field')} and SCOPE_MANIFEST.json#{question.get('denominator_field')}",
            "Scope": scope,
            "Notes": notes,
        }

    if status_rule == "HUMAN_ATTESTED":
        return {
            "Claim / Question": prompt,
            "Status": "HUMAN_ATTESTED",
            "Evidence": str(question.get("evidence_label") or "Human attestation required"),
            "Scope": scope,
            "Notes": str(question.get("notes") or "This claim depends on human review or organizational policy outside machine-verifiable proof."),
        }

    raise VendorQInputError(f"unsupported_status_rule: {status_rule}")


def _derive_integrity_state(pack: Dict[str, Any]) -> str:
    attestation_integrity = str(pack["attestation"].get("receipt_integrity") or "PASS")
    verify_errors = pack["verify_report"].get("errors", [])
    if attestation_integrity != "PASS":
        return "FAIL"
    for err in verify_errors:
        code = str(err.get("code", ""))
        if code.startswith("E_PACK") or code.startswith("E_SIG"):
            return "FAIL"
    return "PASS"


def _derive_claim_state(pack: Dict[str, Any]) -> str:
    claim_verification = pack["verify_report"].get("claim_verification")
    if claim_verification is not None:
        return "PASS" if bool(claim_verification.get("passed")) else "FAIL"
    return "PASS" if str(pack["attestation"].get("claim_check") or "PASS") == "PASS" else "FAIL"


def _derive_regression_state_from_baseline_state(
    current_rows: List[Dict[str, str]],
    baseline_state: Optional[str],
) -> str:
    if baseline_state is None:
        return "NONE"
    current_has_gap = any(row["Status"] in {"PARTIAL", "FAILED", "HUMAN_ATTESTED"} for row in current_rows)
    if baseline_state in {"VERIFIED", "VERIFIED_WITH_GAPS"} and current_has_gap and baseline_state == "VERIFIED":
        return "REGRESSED"
    return "NONE"


def _derive_regression_state(current_rows: List[Dict[str, str]], baseline_packet_dir: Optional[Path]) -> str:
    return _derive_regression_state_from_baseline_state(
        current_rows,
        _baseline_settlement_state(baseline_packet_dir),
    )


def _derive_settlement_state(
    *,
    integrity_state: str,
    claim_state: str,
    coverage_rows: List[Dict[str, str]],
    freshness_state: str,
    regression_state: str,
) -> Tuple[str, str]:
    if integrity_state != "PASS":
        return "TAMPERED", "Integrity verification failed for the nested proof pack."

    in_scope_rows = [row for row in coverage_rows if row["Status"] != "OUT_OF_SCOPE"]
    if not in_scope_rows:
        return "OUT_OF_SCOPE", "All mapped questions are outside the declared packet scope."

    if regression_state == "REGRESSED":
        return "EVIDENCE_REGRESSION", "Evidence quality or coverage regressed compared with the baseline packet."

    if claim_state != "PASS":
        return "INCOMPLETE_EVIDENCE", "The proof pack is authentic, but its declared claims do not pass."

    if any(row["Status"] in {"PARTIAL", "HUMAN_ATTESTED"} for row in in_scope_rows):
        return "VERIFIED_WITH_GAPS", "The packet is authentic and useful, but some in-scope coverage remains partial or human-attested."

    if any(row["Status"] == "FAILED" for row in in_scope_rows):
        return "INCOMPLETE_EVIDENCE", "The packet is authentic, but one or more in-scope mapped claims is not fully supported."

    if freshness_state == "STALE":
        return "VERIFIED_WITH_GAPS", "Evidence is authentic but stale relative to the packet freshness policy."

    return "VERIFIED", "The packet is authentic and all in-scope mapped claims are fully evidenced."


def _render_coverage_matrix(rows: List[Dict[str, str]]) -> str:
    lines = ["# Coverage Matrix", "", "| Claim / Question | Status | Evidence | Scope | Notes |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        lines.append(
            f"| {row['Claim / Question']} | {row['Status']} | {row['Evidence']} | {row['Scope']} | {row['Notes']} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_reviewer_guide(settlement_state: str, workflow_name: str) -> str:
    return (
        "# Reviewer Guide\n\n"
        "This Reviewer Packet is a buyer-facing wrapper around a signed Assay proof pack.\n\n"
        "Assay produces the proof pack. The Reviewer Packet makes that proof usable across an organizational boundary.\n\n"
        f"## Workflow\n\n{workflow_name}\n\n"
        "## What this packet proves\n\n"
        "- The nested proof pack can be verified independently\n"
        "- The packet scope and coverage boundary are stated explicitly\n"
        f"- The current packet settlement is `{settlement_state}`\n\n"
        "## What this packet does not prove\n\n"
        "- That every action in the system was recorded\n"
        "- That model outputs are correct or safe\n"
        "- That source code or instrumentation was honest\n"
        "- That the artifact establishes legal compliance\n"
    )


def _render_executive_summary(settlement_state: str, settlement_reason: str, boundary: Dict[str, Any]) -> str:
    workflow_name = str(boundary.get("workflow_name") or "Unnamed workflow")
    return (
        "# Executive Summary\n\n"
        f"- Workflow in scope: {workflow_name}\n"
        f"- Packet state: `{settlement_state}`\n"
        f"- Main interpretation: {settlement_reason}\n\n"
        "For technical verification, use `assay verify-pack ./proof_pack`. For scope and caveats, review `SCOPE_MANIFEST.json` and `COVERAGE_MATRIX.md`.\n"
    )


def _render_verify() -> str:
    return (
        "# Verify\n\n"
        "The trust root remains the nested Assay proof pack.\n\n"
        "```bash\n"
        "assay verify-pack ./proof_pack\n"
        "```\n"
    )


def _render_challenge(settlement_state: str) -> str:
    return (
        "# Challenge\n\n"
        "1. Verify the nested proof pack with `assay verify-pack ./proof_pack`.\n"
        "2. Inspect `SCOPE_MANIFEST.json` and `COVERAGE_MATRIX.md` for declared boundaries and gaps.\n"
        "3. Tamper with a nested proof-pack file and confirm verification fails.\n\n"
        f"Current settlement: `{settlement_state}`. If integrity fails, settlement becomes `TAMPERED`.\n"
    )


def _build_scope_manifest(
    *,
    boundary_payload: Dict[str, Any],
    mapping_payload: Dict[str, Any],
    packet_time: str,
    signed_by: str,
) -> Dict[str, Any]:
    return {
        "workflow_name": boundary_payload.get("workflow_name"),
        "workflow_description": boundary_payload.get("workflow_description"),
        "repo_or_system_in_scope": boundary_payload.get("repo_or_system_in_scope"),
        "entrypoints_in_scope": boundary_payload.get("entrypoints_in_scope", []),
        "callsites_identified": boundary_payload.get("callsites_identified"),
        "callsites_instrumented": boundary_payload.get("callsites_instrumented"),
        "controls_declared": boundary_payload.get("controls_declared", []),
        "questions_mapped": [q.get("prompt") for q in mapping_payload.get("questions", []) if q.get("in_scope", True)],
        "questions_out_of_scope": [
            q.get("prompt")
            for q in mapping_payload.get("questions", [])
            if not q.get("in_scope", True) or q.get("status_rule") == "OUT_OF_SCOPE"
        ],
        "excluded_components": boundary_payload.get("excluded_components", []),
        "boundary_notes": boundary_payload.get("boundary_notes", []),
        "signed_at": packet_time,
        "signed_by": signed_by,
    }


def _build_packet_inputs(
    *,
    boundary_payload: Dict[str, Any],
    mapping_payload: Dict[str, Any],
    baseline_settlement_state: Optional[str],
) -> Dict[str, Any]:
    return {
        "boundary_payload": boundary_payload,
        "mapping_payload": mapping_payload,
        "baseline_settlement_state": baseline_settlement_state,
    }


def _packet_file_entries(out_dir: Path) -> List[Dict[str, Any]]:
    file_names = [
        "SETTLEMENT.json",
        "SCOPE_MANIFEST.json",
        "COVERAGE_MATRIX.md",
        "REVIEWER_GUIDE.md",
        "EXECUTIVE_SUMMARY.md",
        "VERIFY.md",
        "CHALLENGE.md",
        _PACKET_INPUTS_FILE,
    ]
    entries: List[Dict[str, Any]] = []
    for file_name in file_names:
        payload = (out_dir / file_name).read_bytes()
        entries.append(
            {
                "path": file_name,
                "sha256": _sha256_hex(payload),
                "bytes": len(payload),
            }
        )
    return entries


def _build_packet_manifest(
    *,
    out_dir: Path,
    packet_id: str,
    packet_version: str,
    packet_time: str,
    settlement_payload: Dict[str, Any],
    boundary_payload: Dict[str, Any],
    mapping_payload: Dict[str, Any],
    proof_pack_manifest_sha256: str,
    baseline_settlement_state: Optional[str],
    keystore: AssayKeyStore | None,
    packet_signer_id: Optional[str],
) -> Tuple[Dict[str, Any], bool]:
    file_entries = _packet_file_entries(out_dir)
    unsigned_manifest: Dict[str, Any] = {
        "packet_id": packet_id,
        "packet_version": packet_version,
        "manifest_version": "1.0.0",
        "artifact_type": "reviewer_packet_manifest",
        "hash_alg": "sha256",
        "attestation": {
            "generated_at": packet_time,
            "proof_pack_manifest_sha256": proof_pack_manifest_sha256,
            "settlement_state": settlement_payload["settlement_state"],
            "integrity_state": settlement_payload["integrity_state"],
            "claim_state": settlement_payload["claim_state"],
            "scope_state": settlement_payload["scope_state"],
            "freshness_state": settlement_payload["freshness_state"],
            "regression_state": settlement_payload["regression_state"],
            "valid_for": settlement_payload["valid_for"],
            "expires_at": settlement_payload["expires_at"],
            "boundary_hash": _sha256_hex(to_jcs_bytes(boundary_payload)),
            "mapping_hash": _sha256_hex(to_jcs_bytes(mapping_payload)),
            "baseline_settlement_state": baseline_settlement_state,
        },
        "files": file_entries,
        "expected_files": [entry["path"] for entry in file_entries],
    }

    signer_id = packet_signer_id if keystore and packet_signer_id and keystore.has_key(packet_signer_id) else None
    if signer_id is None and keystore:
        candidate = str(settlement_payload.get("signer", {}).get("identity") or "")
        if candidate and keystore.has_key(candidate):
            signer_id = candidate

    if not signer_id or not keystore:
        return unsigned_manifest, False

    pubkey_bytes = keystore.get_verify_key(signer_id).encode()
    unsigned_manifest.update(
        {
            "signer_id": signer_id,
            "signer_pubkey": base64.b64encode(pubkey_bytes).decode("ascii"),
            "signer_pubkey_sha256": _sha256_hex(pubkey_bytes),
            "signature_alg": "ed25519",
            "signature_scope": "JCS(packet_manifest_without_signature)",
        }
    )
    signature_b64 = keystore.sign_b64(to_jcs_bytes(unsigned_manifest), signer_id)
    signed_manifest = {
        **unsigned_manifest,
        "signature": signature_b64,
    }
    (out_dir / _PACKET_SIGNATURE_FILE).write_bytes(base64.b64decode(signature_b64))
    return signed_manifest, True


def compile_reviewer_packet(
    *,
    proof_pack_dir: Path,
    boundary_payload: Dict[str, Any],
    mapping_payload: Dict[str, Any],
    out_dir: Path,
    baseline_packet_dir: Optional[Path] = None,
    packet_overrides: Optional[Dict[str, Any]] = None,
    keystore: AssayKeyStore | None = None,
    packet_signer_id: Optional[str] = None,
) -> Dict[str, Any]:
    pack = _load_pack_local(proof_pack_dir)
    overrides = packet_overrides or {}
    packet_time = str(overrides.get("generated_at") or boundary_payload.get("generated_at") or now_utc_iso())
    freshness_policy = dict(boundary_payload.get("freshness_policy") or {})
    valid_for = str(freshness_policy.get("valid_for") or overrides.get("valid_for") or "P30D")
    stale_after = freshness_policy.get("stale_after")

    coverage_rows = [_evaluate_question(question, pack, boundary_payload) for question in mapping_payload.get("questions", [])]
    integrity_state = _derive_integrity_state(pack)
    claim_state = _derive_claim_state(pack)
    freshness_state = _freshness_state(packet_time, str(pack.get("timestamp_end") or packet_time), str(stale_after) if stale_after else None)
    baseline_state = _baseline_settlement_state(baseline_packet_dir)
    regression_state = _derive_regression_state_from_baseline_state(coverage_rows, baseline_state)
    settlement_state, settlement_reason = _derive_settlement_state(
        integrity_state=integrity_state,
        claim_state=claim_state,
        coverage_rows=coverage_rows,
        freshness_state=freshness_state,
        regression_state=regression_state,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    proof_pack_out = out_dir / "proof_pack"
    shutil.copytree(proof_pack_dir, proof_pack_out, dirs_exist_ok=True)

    signed_by = str(overrides.get("signed_by") or boundary_payload.get("signed_by") or "assay reviewer-packet compiler")
    scope_manifest = _build_scope_manifest(
        boundary_payload=boundary_payload,
        mapping_payload=mapping_payload,
        packet_time=packet_time,
        signed_by=signed_by,
    )

    settlement_payload: Dict[str, Any] = {
        "packet_id": str(overrides.get("packet_id") or f"rp_{pack['pack_id']}"),
        "packet_version": "1.0",
        "artifact_type": "reviewer_packet",
        "settlement_state": settlement_state,
        "integrity_state": integrity_state,
        "claim_state": claim_state,
        "scope_state": "OUT_OF_SCOPE" if settlement_state == "OUT_OF_SCOPE" else "BOUNDED",
        "freshness_state": freshness_state,
        "regression_state": regression_state,
        "generated_at": packet_time,
        "valid_for": valid_for,
        "expires_at": _add_period_days(packet_time, valid_for),
        "source_commit": str(overrides.get("source_commit") or boundary_payload.get("source_commit") or pack["run_id"]),
        "pack_manifest_sha256": pack["manifest_file_sha256"],
        "proof_pack_path": "./proof_pack",
        "settlement_basis": [
            settlement_reason,
            f"Nested proof pack integrity: {integrity_state}",
            f"Nested proof pack claims: {claim_state}",
        ],
        "signer": {
            "mode": str(overrides.get("signer_mode") or "local_key"),
            "identity": str(pack["manifest"].get("signer_id") or "unknown"),
            "fingerprint": str(pack["manifest"].get("signer_pubkey_sha256") or "unknown"),
        },
        "trust_tier": str(pack["attestation"].get("assurance_level") or "L0"),
    }

    packet_inputs = _build_packet_inputs(
        boundary_payload=boundary_payload,
        mapping_payload=mapping_payload,
        baseline_settlement_state=baseline_state,
    )

    write_json(out_dir / "SETTLEMENT.json", settlement_payload)
    write_json(out_dir / "SCOPE_MANIFEST.json", scope_manifest)
    (out_dir / "COVERAGE_MATRIX.md").write_text(_render_coverage_matrix(coverage_rows), encoding="utf-8")
    (out_dir / "REVIEWER_GUIDE.md").write_text(
        _render_reviewer_guide(settlement_state, str(boundary_payload.get("workflow_name") or "Unnamed workflow")),
        encoding="utf-8",
    )
    (out_dir / "EXECUTIVE_SUMMARY.md").write_text(
        _render_executive_summary(settlement_state, settlement_reason, boundary_payload),
        encoding="utf-8",
    )
    (out_dir / "VERIFY.md").write_text(_render_verify(), encoding="utf-8")
    (out_dir / "CHALLENGE.md").write_text(_render_challenge(settlement_state), encoding="utf-8")
    write_json(out_dir / _PACKET_INPUTS_FILE, packet_inputs)

    packet_manifest, packet_manifest_signed = _build_packet_manifest(
        out_dir=out_dir,
        packet_id=settlement_payload["packet_id"],
        packet_version=settlement_payload["packet_version"],
        packet_time=packet_time,
        settlement_payload=settlement_payload,
        boundary_payload=boundary_payload,
        mapping_payload=mapping_payload,
        proof_pack_manifest_sha256=pack["manifest_file_sha256"],
        baseline_settlement_state=baseline_state,
        keystore=keystore,
        packet_signer_id=packet_signer_id,
    )
    write_json(out_dir / _PACKET_MANIFEST_FILE, packet_manifest)

    return {
        "packet_id": settlement_payload["packet_id"],
        "settlement_state": settlement_state,
        "integrity_state": integrity_state,
        "claim_state": claim_state,
        "freshness_state": freshness_state,
        "regression_state": regression_state,
        "coverage_rows": coverage_rows,
        "packet_manifest_signed": packet_manifest_signed,
        "output_dir": str(out_dir),
    }
