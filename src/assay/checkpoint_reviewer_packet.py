"""Compile reviewer packets for resolved outbound checkpoint attempts."""
from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from assay.checkpoint_views import (
    build_outbound_email_checkpoint_attempt_view,
    load_outbound_email_checkpoint_attempt_artifacts,
    _select_evaluation_for_attempt_view,
)
from assay.checkpoints import (
    CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
    DECISION_REQUIRED_OUTCOMES,
    CheckpointValidationError,
)
from assay.keystore import AssayKeyStore
from assay.reviewer_packet_compile import (
    _PACKET_INPUTS_FILE,
    _PACKET_MANIFEST_FILE,
    _add_period_days,
    _build_packet_manifest,
    _derive_claim_state,
    _derive_integrity_state,
    _freshness_state,
    _load_pack_local,
    _render_challenge,
    _render_coverage_matrix,
    _render_executive_summary,
    _render_reviewer_guide,
    _sha256_hex,
)
from assay.vendorq_models import VendorQInputError, now_utc_iso, write_json


CHECKPOINT_REVIEWER_PACKET_PROFILE = "checkpoint.outbound_action.send_email.v0.1"
DEFAULT_PACKET_VALID_FOR = "P30D"
DEFAULT_PACKET_SIGNED_BY = "assay checkpoint reviewer-packet compiler"

ATTEMPTED_CROSSING_PROMPT = "Was one concrete governed boundary crossing attempted?"
ELIGIBLE_POSTURE_PROMPT = "Which evaluation was actually carried forward into the terminal resolution?"
AUTHORITY_DECISION_PROMPT = "Is the authority decision layer evidenced by canonical Decision Receipts or only by trace wrappers?"
ACTUAL_OUTCOME_PROMPT = "What terminal operational state did the checkpoint attempt reach?"


def _checkpoint_machine_coverage_ratio(coverage_rows: Sequence[Dict[str, str]]) -> Dict[str, float | int]:
    counts = Counter(row["Status"] for row in coverage_rows)
    numerator = int(counts.get("EVIDENCED", 0))
    denominator = numerator + int(counts.get("PARTIAL", 0)) + int(counts.get("FAILED", 0))
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": (numerator / denominator) if denominator else 0.0,
    }


def derive_checkpoint_claim_state(pack: Dict[str, Any]) -> str:
    """Checkpoint packets treat missing external claim sets as neutral, not failing."""
    verify_report = dict(pack.get("verify_report") or {})
    claim_verification = verify_report.get("claim_verification")
    if isinstance(claim_verification, dict):
        return "PASS" if bool(claim_verification.get("passed")) else "FAIL"

    attestation = dict(pack.get("attestation") or {})
    claim_set_id = str(attestation.get("claim_set_id") or "")
    claim_check = str(attestation.get("claim_check") or "")
    if claim_set_id in {"", "none"} or claim_check in {"", "N/A"}:
        return "PASS"
    return _derive_claim_state(pack)


def _dedupe(items: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _decision_file_name(receipt: Dict[str, Any], index: int) -> str:
    receipt_id = str(receipt.get("receipt_id") or f"decision_{index + 1}")
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in receipt_id)
    return f"{safe}.json"


def _planned_decision_receipt_rel_paths(decision_receipts: Sequence[Dict[str, Any]]) -> List[str]:
    used_names: set[str] = set()
    rel_paths: List[str] = []
    for index, receipt in enumerate(decision_receipts):
        file_name = _decision_file_name(receipt, index)
        stem = Path(file_name).stem
        suffix = Path(file_name).suffix
        candidate = file_name
        dedupe = 2
        while candidate in used_names:
            candidate = f"{stem}_{dedupe}{suffix}"
            dedupe += 1
        used_names.add(candidate)
        rel_paths.append(f"decision_receipts/{candidate}")
    return rel_paths


def load_packaged_decision_receipts(
    packet_dir: Path,
    *,
    rel_paths: Optional[Sequence[str]] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Load packaged canonical Decision Receipts from a reviewer packet directory."""
    if rel_paths is None:
        decision_dir = packet_dir / "decision_receipts"
        rel_paths = (
            sorted(str(path.relative_to(packet_dir)) for path in decision_dir.glob("*.json"))
            if decision_dir.is_dir()
            else []
        )

    receipts: List[Dict[str, Any]] = []
    normalized_rel_paths: List[str] = []
    for rel_path in rel_paths:
        path = packet_dir / rel_path
        if not path.is_file():
            raise VendorQInputError(f"decision_receipt_file_not_found: {path}")
        try:
            receipts.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise VendorQInputError(f"invalid_json: {path}: {exc.msg}") from exc
        normalized_rel_paths.append(str(Path(rel_path)))

    return receipts, normalized_rel_paths


def _build_checkpoint_scope_manifest(
    *,
    checkpoint_attempt_id: str,
    view: Any,
    selected_evaluation: Dict[str, Any],
    resolution: Dict[str, Any],
    packet_time: str,
    signed_by: str,
    limitations: Sequence[str],
    authority_mode: str,
) -> Dict[str, Any]:
    action_target = view.attempted_crossing["attempt"]["action_target"]
    prompts = [
        ATTEMPTED_CROSSING_PROMPT,
        ELIGIBLE_POSTURE_PROMPT,
        AUTHORITY_DECISION_PROMPT,
        ACTUAL_OUTCOME_PROMPT,
    ]
    controls_declared = [
        "Signed proof pack",
        "Checkpoint lifecycle verification",
    ]
    if authority_mode == "canonical_decision_receipts":
        controls_declared.append("Canonical Decision Receipts packaged")
    elif authority_mode == "trace_wrappers_only":
        controls_declared.append("Authority layer available only through checkpoint.decision_recorded trace wrappers")
    elif authority_mode == "missing":
        controls_declared.append("Authority linkage required but not sufficiently evidenced")
    else:
        controls_declared.append("No authority decision required for the terminal outcome")

    return {
        "workflow_name": f"Checkpoint review: {view.checkpoint_type}",
        "workflow_description": "Resolved outbound checkpoint attempt packaged for counterparty review.",
        "repo_or_system_in_scope": action_target["system"],
        "entrypoints_in_scope": [f"{view.checkpoint_type}:{action_target['system']}.{action_target['operation']}"],
        "callsites_identified": 1,
        "callsites_instrumented": 1,
        "controls_declared": controls_declared,
        "questions_mapped": prompts,
        "questions_out_of_scope": [],
        "excluded_components": [],
        "boundary_notes": list(limitations),
        "checkpoint_attempt_id": checkpoint_attempt_id,
        "checkpoint_type": view.checkpoint_type,
        "trace_id": view.trace_id,
        "request_id": view.attempted_crossing["request_id"],
        "carried_forward_evaluation_id": selected_evaluation["evaluation_id"],
        "resolution_id": resolution["resolution_id"],
        "resolution_outcome": resolution["resolution_outcome"],
        "decision_layer_mode": authority_mode,
        "signed_at": packet_time,
        "signed_by": signed_by,
    }


def _build_checkpoint_packet_inputs(
    *,
    checkpoint_attempt_id: str,
    checkpoint_type: str,
    decision_receipt_rel_paths: Sequence[str],
) -> Dict[str, Any]:
    return {
        "packet_profile": CHECKPOINT_REVIEWER_PACKET_PROFILE,
        "checkpoint_profile_inputs": {
            "checkpoint_attempt_id": checkpoint_attempt_id,
            "checkpoint_type": checkpoint_type,
            "decision_receipt_files": list(decision_receipt_rel_paths),
        },
    }


def _build_checkpoint_verify_markdown() -> str:
    return (
        "# Verify\n\n"
        "The trust root remains the nested Assay proof pack.\n\n"
        "```bash\n"
        "assay verify-pack ./proof_pack\n"
        "assay reviewer verify .\n"
        "```\n"
    )


def _authority_mode(
    *,
    resolution: Dict[str, Any],
    view: Any,
    has_canonical_decisions: bool,
    has_decision_trace_entries: bool,
) -> str:
    if has_canonical_decisions:
        return "canonical_decision_receipts"
    if view.authority_decisions and has_decision_trace_entries:
        return "trace_wrappers_only"
    if resolution["resolution_outcome"] in DECISION_REQUIRED_OUTCOMES:
        return "missing"
    return "not_required"


def _build_checkpoint_coverage_rows(
    *,
    scope_manifest: Dict[str, Any],
    resolution: Dict[str, Any],
    view: Any,
    legacy_final_evaluation_fallback: bool,
    authority_mode: str,
    decision_receipt_rel_paths: Sequence[str],
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = [
        {
            "Claim / Question": ATTEMPTED_CROSSING_PROMPT,
            "Status": "EVIDENCED",
            "Evidence": "proof_pack/receipt_pack.jsonl; SCOPE_MANIFEST.json#checkpoint_attempt_id",
            "Scope": scope_manifest["workflow_name"],
            "Notes": "The proof pack contains one checkpoint request for the declared checkpoint attempt.",
        }
    ]

    posture_status = "PARTIAL" if legacy_final_evaluation_fallback else "EVIDENCED"
    posture_notes = (
        "Resolution omits final_evaluation_id; the carried-forward posture was inferred from evaluation_id for compatibility."
        if legacy_final_evaluation_fallback
        else "The terminal resolution explicitly names the evaluation carried forward into the attempt outcome."
    )
    rows.append(
        {
            "Claim / Question": ELIGIBLE_POSTURE_PROMPT,
            "Status": posture_status,
            "Evidence": "proof_pack/receipt_pack.jsonl; SCOPE_MANIFEST.json#carried_forward_evaluation_id",
            "Scope": scope_manifest["workflow_name"],
            "Notes": posture_notes,
        }
    )

    if authority_mode == "canonical_decision_receipts":
        authority_status = "EVIDENCED"
        authority_evidence = "; ".join(sorted(decision_receipt_rel_paths))
        authority_notes = "Canonical Decision Receipts are packaged and used for full authority-layer verification."
    elif authority_mode == "trace_wrappers_only":
        authority_status = "PARTIAL"
        authority_evidence = "proof_pack/receipt_pack.jsonl; SCOPE_MANIFEST.json#decision_layer_mode"
        authority_notes = "Authority decisions are inferable only from checkpoint.decision_recorded trace wrappers."
    elif authority_mode == "missing":
        authority_status = "FAILED"
        authority_evidence = "SCOPE_MANIFEST.json#decision_layer_mode"
        authority_notes = "The terminal outcome depends on authority linkage that is not sufficiently evidenced in the packet."
    else:
        authority_status = "EVIDENCED"
        authority_evidence = "SCOPE_MANIFEST.json#decision_layer_mode"
        authority_notes = f"No binding authority decision was required for terminal outcome `{resolution['resolution_outcome']}`."
    rows.append(
        {
            "Claim / Question": AUTHORITY_DECISION_PROMPT,
            "Status": authority_status,
            "Evidence": authority_evidence,
            "Scope": scope_manifest["workflow_name"],
            "Notes": authority_notes,
        }
    )

    outcome_note = (
        f"Terminal outcome `{view.actual_outcome['resolution_outcome']}` is recorded in the checkpoint resolution artifact."
    )
    rows.append(
        {
            "Claim / Question": ACTUAL_OUTCOME_PROMPT,
            "Status": "EVIDENCED",
            "Evidence": "proof_pack/receipt_pack.jsonl; SCOPE_MANIFEST.json#resolution_outcome",
            "Scope": scope_manifest["workflow_name"],
            "Notes": outcome_note,
        }
    )
    return rows


def _derive_checkpoint_settlement_state(
    *,
    integrity_state: str,
    claim_state: str,
    freshness_state: str,
    view: Any,
    coverage_rows: Sequence[Dict[str, str]],
    limitations: Sequence[str],
) -> Tuple[str, str]:
    if integrity_state != "PASS":
        return "TAMPERED", "Integrity verification failed for the nested proof pack."
    if claim_state != "PASS":
        return "INCOMPLETE_EVIDENCE", "The proof pack is authentic, but its declared claims do not pass."
    if view.verification["status"] == "failed":
        return "INCOMPLETE_EVIDENCE", "The resolved checkpoint lifecycle is present, but lifecycle verification failed."
    if any(row["Status"] == "FAILED" for row in coverage_rows):
        return "INCOMPLETE_EVIDENCE", "The resolved checkpoint lifecycle is present, but required authority linkage is incomplete."
    if freshness_state == "STALE":
        return "VERIFIED_WITH_GAPS", "Checkpoint evidence is authentic but stale relative to the packet freshness policy."
    if view.verification["status"] == "degraded" or any(row["Status"] == "PARTIAL" for row in coverage_rows) or limitations:
        return "VERIFIED_WITH_GAPS", "The checkpoint attempt is authentic and readable, but some lifecycle layers remain degraded."
    return "VERIFIED", "The checkpoint attempt is authentic and all in-scope lifecycle layers are fully evidenced."


def derive_checkpoint_reviewer_packet(
    *,
    proof_pack_dir: Path,
    checkpoint_attempt_id: str,
    decision_receipts: Optional[Sequence[Dict[str, Any]]] = None,
    decision_receipt_rel_paths: Optional[Sequence[str]] = None,
    packet_time: Optional[str] = None,
    signed_by: str = DEFAULT_PACKET_SIGNED_BY,
    integrity_state_override: Optional[str] = None,
    claim_state_override: Optional[str] = None,
    freshness_state_override: Optional[str] = None,
) -> Dict[str, Any]:
    pack = _load_pack_local(proof_pack_dir)
    try:
        artifact_set = load_outbound_email_checkpoint_attempt_artifacts(
            pack["receipts"],
            checkpoint_attempt_id=checkpoint_attempt_id,
        )
    except CheckpointValidationError as exc:
        raise VendorQInputError(str(exc)) from exc

    if artifact_set.checkpoint_type != CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL:
        raise VendorQInputError(f"unsupported_checkpoint_type: {artifact_set.checkpoint_type}")
    if artifact_set.resolution is None:
        raise VendorQInputError(f"checkpoint_attempt_unresolved: {checkpoint_attempt_id}")

    selected_evaluation = _select_evaluation_for_attempt_view(
        artifact_set.evaluations,
        artifact_set.resolution,
    )
    view = build_outbound_email_checkpoint_attempt_view(
        artifact_set.request,
        selected_evaluation,
        artifact_set.resolution,
        decision_receipts=decision_receipts,
        decision_trace_entries=artifact_set.decision_trace_entries,
        trace_id=artifact_set.trace_id,
    )

    packet_timestamp = packet_time or now_utc_iso()
    limitations = list(view.limitations)
    legacy_final_evaluation_fallback = not bool(artifact_set.resolution.get("final_evaluation_id"))
    if legacy_final_evaluation_fallback:
        limitations.append("final_evaluation_id_missing_used_evaluation_id_compatibility_fallback")
    limitations = sorted(_dedupe(limitations))

    authority_mode = _authority_mode(
        resolution=artifact_set.resolution,
        view=view,
        has_canonical_decisions=bool(decision_receipts),
        has_decision_trace_entries=bool(artifact_set.decision_trace_entries),
    )

    scope_manifest = _build_checkpoint_scope_manifest(
        checkpoint_attempt_id=checkpoint_attempt_id,
        view=view,
        selected_evaluation=selected_evaluation,
        resolution=artifact_set.resolution,
        packet_time=packet_timestamp,
        signed_by=signed_by,
        limitations=limitations,
        authority_mode=authority_mode,
    )
    coverage_rows = _build_checkpoint_coverage_rows(
        scope_manifest=scope_manifest,
        resolution=artifact_set.resolution,
        view=view,
        legacy_final_evaluation_fallback=legacy_final_evaluation_fallback,
        authority_mode=authority_mode,
        decision_receipt_rel_paths=list(decision_receipt_rel_paths or []),
    )

    integrity_state = integrity_state_override or _derive_integrity_state(pack)
    claim_state = claim_state_override or derive_checkpoint_claim_state(pack)
    freshness_state = freshness_state_override or _freshness_state(
        packet_timestamp,
        str(pack.get("timestamp_end") or packet_timestamp),
        None,
    )
    settlement_state, settlement_reason = _derive_checkpoint_settlement_state(
        integrity_state=integrity_state,
        claim_state=claim_state,
        freshness_state=freshness_state,
        view=view,
        coverage_rows=coverage_rows,
        limitations=limitations,
    )

    return {
        "pack": pack,
        "artifact_set": artifact_set,
        "view": view,
        "selected_evaluation": selected_evaluation,
        "scope_manifest": scope_manifest,
        "coverage_rows": coverage_rows,
        "limitations": limitations,
        "authority_mode": authority_mode,
        "integrity_state": integrity_state,
        "claim_state": claim_state,
        "freshness_state": freshness_state,
        "regression_state": "NONE",
        "settlement_state": settlement_state,
        "settlement_reason": settlement_reason,
        "packet_time": packet_timestamp,
        "signed_by": signed_by,
    }


def compile_checkpoint_reviewer_packet(
    *,
    proof_pack_dir: Path,
    checkpoint_attempt_id: str,
    out_dir: Path,
    decision_receipts: Optional[Sequence[Dict[str, Any]]] = None,
    packet_overrides: Optional[Dict[str, Any]] = None,
    keystore: AssayKeyStore | None = None,
    packet_signer_id: Optional[str] = None,
) -> Dict[str, Any]:
    overrides = packet_overrides or {}
    packet_time = str(overrides.get("generated_at") or now_utc_iso())
    valid_for = str(overrides.get("valid_for") or DEFAULT_PACKET_VALID_FOR)
    signed_by = str(overrides.get("signed_by") or DEFAULT_PACKET_SIGNED_BY)
    decision_receipt_list = list(decision_receipts or [])
    decision_receipt_rel_paths = _planned_decision_receipt_rel_paths(decision_receipt_list)

    derived = derive_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=checkpoint_attempt_id,
        decision_receipts=decision_receipt_list or None,
        decision_receipt_rel_paths=decision_receipt_rel_paths,
        packet_time=packet_time,
        signed_by=signed_by,
    )
    pack = derived["pack"]

    out_dir.mkdir(parents=True, exist_ok=True)
    proof_pack_out = out_dir / "proof_pack"
    shutil.copytree(proof_pack_dir, proof_pack_out, dirs_exist_ok=True)

    if decision_receipt_list:
        decision_dir = out_dir / "decision_receipts"
        decision_dir.mkdir(parents=True, exist_ok=True)
        for rel_path, receipt in zip(decision_receipt_rel_paths, decision_receipt_list):
            write_json(out_dir / rel_path, dict(receipt))

    settlement_payload: Dict[str, Any] = {
        "packet_id": str(overrides.get("packet_id") or f"rp_{checkpoint_attempt_id}"),
        "packet_version": "1.0",
        "packet_profile": CHECKPOINT_REVIEWER_PACKET_PROFILE,
        "artifact_type": "reviewer_packet",
        "settlement_state": derived["settlement_state"],
        "integrity_state": derived["integrity_state"],
        "claim_state": derived["claim_state"],
        "scope_state": "BOUNDED",
        "freshness_state": derived["freshness_state"],
        "regression_state": "NONE",
        "generated_at": packet_time,
        "valid_for": valid_for,
        "expires_at": _add_period_days(packet_time, valid_for),
        "source_commit": str(overrides.get("source_commit") or pack["run_id"]),
        "pack_manifest_sha256": pack["manifest_file_sha256"],
        "proof_pack_path": "./proof_pack",
        "settlement_basis": [
            derived["settlement_reason"],
            f"Nested proof pack integrity: {derived['integrity_state']}",
            f"Nested proof pack claims: {derived['claim_state']}",
            *(f"Limitation: {item}" for item in derived["limitations"]),
        ],
        "signer": {
            "mode": str(overrides.get("signer_mode") or "local_key"),
            "identity": str(pack["manifest"].get("signer_id") or "unknown"),
            "fingerprint": str(pack["manifest"].get("signer_pubkey_sha256") or "unknown"),
        },
        "trust_tier": str(pack["attestation"].get("assurance_level") or "L0"),
        "checkpoint_attempt_id": checkpoint_attempt_id,
        "checkpoint_type": derived["view"].checkpoint_type,
    }

    packet_inputs = _build_checkpoint_packet_inputs(
        checkpoint_attempt_id=checkpoint_attempt_id,
        checkpoint_type=derived["view"].checkpoint_type,
        decision_receipt_rel_paths=decision_receipt_rel_paths,
    )

    write_json(out_dir / "SETTLEMENT.json", settlement_payload)
    write_json(out_dir / "SCOPE_MANIFEST.json", derived["scope_manifest"])
    (out_dir / "COVERAGE_MATRIX.md").write_text(_render_coverage_matrix(derived["coverage_rows"]), encoding="utf-8")
    (out_dir / "REVIEWER_GUIDE.md").write_text(
        _render_reviewer_guide(derived["settlement_state"], derived["scope_manifest"]["workflow_name"]),
        encoding="utf-8",
    )
    (out_dir / "EXECUTIVE_SUMMARY.md").write_text(
        _render_executive_summary(derived["settlement_state"], derived["settlement_reason"], derived["scope_manifest"]),
        encoding="utf-8",
    )
    (out_dir / "VERIFY.md").write_text(_build_checkpoint_verify_markdown(), encoding="utf-8")
    (out_dir / "CHALLENGE.md").write_text(_render_challenge(derived["settlement_state"]), encoding="utf-8")
    write_json(out_dir / _PACKET_INPUTS_FILE, packet_inputs)

    packet_manifest, packet_manifest_signed = _build_packet_manifest(
        out_dir=out_dir,
        packet_id=settlement_payload["packet_id"],
        packet_version=settlement_payload["packet_version"],
        packet_time=packet_time,
        settlement_payload=settlement_payload,
        boundary_payload=derived["scope_manifest"],
        mapping_payload=packet_inputs,
        proof_pack_manifest_sha256=pack["manifest_file_sha256"],
        baseline_settlement_state=None,
        keystore=keystore,
        packet_signer_id=packet_signer_id,
        extra_rel_paths=decision_receipt_rel_paths,
    )
    write_json(out_dir / _PACKET_MANIFEST_FILE, packet_manifest)

    return {
        "packet_id": settlement_payload["packet_id"],
        "packet_profile": CHECKPOINT_REVIEWER_PACKET_PROFILE,
        "checkpoint_attempt_id": checkpoint_attempt_id,
        "settlement_state": derived["settlement_state"],
        "integrity_state": derived["integrity_state"],
        "claim_state": derived["claim_state"],
        "freshness_state": derived["freshness_state"],
        "regression_state": "NONE",
        "coverage_rows": derived["coverage_rows"],
        "packet_manifest_signed": packet_manifest_signed,
        "output_dir": str(out_dir),
        "limitations": derived["limitations"],
        "verification_status": derived["view"].verification["status"],
        "machine_coverage": _checkpoint_machine_coverage_ratio(derived["coverage_rows"]),
    }


__all__ = [
    "CHECKPOINT_REVIEWER_PACKET_PROFILE",
    "compile_checkpoint_reviewer_packet",
    "derive_checkpoint_reviewer_packet",
    "derive_checkpoint_claim_state",
    "load_packaged_decision_receipts",
]
