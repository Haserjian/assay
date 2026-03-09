"""Deterministic replay judgment for Assay proof packs.

This module compares an original proof pack plus ADC against a replayed
proof pack plus ADC and emits two additive artifacts:

- replay judgment: signed, portable receipt describing reproducibility
- explanation trace: receipt-safe projection of the drivers of the verdict

The v0.1 contract is intentionally narrow. It answers only:
"Can this decision be replayed faithfully, and if not, why not?"
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import referencing
from jsonschema import Draft202012Validator

from assay._receipts.canonicalize import to_jcs_bytes
from assay.keystore import AssayKeyStore, DEFAULT_SIGNER_ID, get_default_keystore


_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_JUDGMENT_SCHEMA = "replay_judgment_v0.1.schema.json"
_TRACE_SCHEMA = "replay_explanation_trace_v0.1.schema.json"

_judgment_validator: Optional[Draft202012Validator] = None
_trace_validator: Optional[Draft202012Validator] = None

_VERDICT_REPRODUCIBLE = "reproducible"
_VERDICT_DRIFTED = "drifted"
_VERDICT_UNVERIFIABLE = "unverifiable"

_REASON_MISSING_DECISION_CREDENTIAL = "missing_decision_credential"
_REASON_MISSING_PACK_ROOT = "missing_pack_root"
_REASON_EVIDENCE_BINDING_MISMATCH = "evidence_binding_mismatch"
_REASON_POLICY_MISMATCH = "policy_mismatch"
_REASON_CLAIM_BINDING_MISMATCH = "claim_binding_mismatch"
_REASON_INTEGRITY_RESULT_MISMATCH = "integrity_result_mismatch"
_REASON_OVERALL_RESULT_MISMATCH = "overall_result_mismatch"
_REASON_CLAIM_RESULTS_MISMATCH = "claim_results_mismatch"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_schema_validator(schema_name: str) -> Draft202012Validator:
    schema_path = _SCHEMA_DIR / schema_name
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    registry = referencing.Registry().with_resource(
        schema["$id"], referencing.Resource.from_contents(schema)
    )
    return Draft202012Validator(schema, registry=registry)


def validate_replay_judgment(judgment: Dict[str, Any]) -> List[str]:
    """Validate a replay judgment against its JSON schema."""
    global _judgment_validator
    if _judgment_validator is None:
        _judgment_validator = _load_schema_validator(_JUDGMENT_SCHEMA)

    errors = []
    for error in sorted(_judgment_validator.iter_errors(judgment), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


def validate_explanation_trace(trace: Dict[str, Any]) -> List[str]:
    """Validate a replay explanation trace against its JSON schema."""
    global _trace_validator
    if _trace_validator is None:
        _trace_validator = _load_schema_validator(_TRACE_SCHEMA)

    errors = []
    for error in sorted(_trace_validator.iter_errors(trace), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return _load_json(path)


def _unsigned_digest(payload: Dict[str, Any], *, id_field: str) -> str:
    body = {k: v for k, v in payload.items() if k not in (id_field, "signature")}
    return _sha256_hex(to_jcs_bytes(body))


def _semantic_claim_results(adc: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = adc.get("claim_results") or []
    return sorted(
        [
            {
                "claim_id": result.get("claim_id", ""),
                "result": result.get("result", ""),
                "severity": result.get("severity"),
            }
            for result in results
        ],
        key=lambda item: item["claim_id"],
    )


def _semantic_adc_view(adc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "claim_namespace": adc.get("claim_namespace"),
        "claim_ids": list(adc.get("claim_ids") or []),
        "policy_id": adc.get("policy_id"),
        "policy_hash": adc.get("policy_hash"),
        "integrity_result": adc.get("integrity_result"),
        "overall_result": adc.get("overall_result"),
        "claim_results": _semantic_claim_results(adc),
    }


def _artifact_summary(
    manifest: Dict[str, Any],
    adc: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    attestation = manifest.get("attestation", {})
    summary: Dict[str, Any] = {
        "pack_id": manifest.get("pack_id", attestation.get("pack_id", "")),
        "pack_root_sha256": manifest.get("pack_root_sha256"),
        "policy_hash": attestation.get("policy_hash"),
        "claim_set_hash": manifest.get("claim_set_hash"),
        "signer_pubkey_sha256": manifest.get("signer_pubkey_sha256"),
        "receipt_integrity": attestation.get("receipt_integrity"),
        "adc_credential_id": None,
        "adc_unsigned_sha256": None,
        "semantic_sha256": None,
        "claim_namespace": None,
        "claim_ids": [],
        "overall_result": None,
        "integrity_result": None,
    }
    if adc is None:
        return summary

    semantic = _semantic_adc_view(adc)
    summary.update(
        {
            "adc_credential_id": adc.get("credential_id"),
            "adc_unsigned_sha256": _unsigned_digest(adc, id_field="credential_id"),
            "semantic_sha256": _sha256_hex(to_jcs_bytes(semantic)),
            "claim_namespace": semantic["claim_namespace"],
            "claim_ids": semantic["claim_ids"],
            "overall_result": semantic["overall_result"],
            "integrity_result": semantic["integrity_result"],
        }
    )
    return summary


def _collect_divergences(
    original_manifest: Dict[str, Any],
    replay_manifest: Dict[str, Any],
    original_adc: Optional[Dict[str, Any]],
    replay_adc: Optional[Dict[str, Any]],
    *,
    require_decision_credential: bool,
) -> Tuple[List[str], List[Dict[str, Any]], bool, bool]:
    reasons: List[str] = []
    details: List[Dict[str, Any]] = []
    byte_equivalent = False
    logically_equivalent = False

    if require_decision_credential:
        if original_adc is None:
            reasons.append(_REASON_MISSING_DECISION_CREDENTIAL)
            details.append({"field": "original.decision_credential", "reason": _REASON_MISSING_DECISION_CREDENTIAL})
        if replay_adc is None:
            reasons.append(_REASON_MISSING_DECISION_CREDENTIAL)
            details.append({"field": "replay.decision_credential", "reason": _REASON_MISSING_DECISION_CREDENTIAL})
        if original_adc is None or replay_adc is None:
            return sorted(set(reasons)), details, byte_equivalent, logically_equivalent

    if original_adc is None or replay_adc is None:
        return sorted(set(reasons)), details, byte_equivalent, logically_equivalent

    original_root = original_manifest.get("pack_root_sha256")
    replay_root = replay_manifest.get("pack_root_sha256")
    if not original_root:
        reasons.append(_REASON_MISSING_PACK_ROOT)
        details.append({"field": "original.pack_root_sha256", "reason": _REASON_MISSING_PACK_ROOT})
    if not replay_root:
        reasons.append(_REASON_MISSING_PACK_ROOT)
        details.append({"field": "replay.pack_root_sha256", "reason": _REASON_MISSING_PACK_ROOT})

    if original_root and original_adc.get("evidence_manifest_sha256") != original_root:
        reasons.append(_REASON_EVIDENCE_BINDING_MISMATCH)
        details.append({
            "field": "original.evidence_manifest_sha256",
            "reason": _REASON_EVIDENCE_BINDING_MISMATCH,
            "original": original_adc.get("evidence_manifest_sha256"),
            "expected": original_root,
        })
    if replay_root and replay_adc.get("evidence_manifest_sha256") != replay_root:
        reasons.append(_REASON_EVIDENCE_BINDING_MISMATCH)
        details.append({
            "field": "replay.evidence_manifest_sha256",
            "reason": _REASON_EVIDENCE_BINDING_MISMATCH,
            "original": replay_adc.get("evidence_manifest_sha256"),
            "expected": replay_root,
        })

    original_policy_hash = original_adc.get("policy_hash") or original_manifest.get("attestation", {}).get("policy_hash")
    replay_policy_hash = replay_adc.get("policy_hash") or replay_manifest.get("attestation", {}).get("policy_hash")
    if original_policy_hash != replay_policy_hash:
        reasons.append(_REASON_POLICY_MISMATCH)
        details.append({
            "field": "policy_hash",
            "reason": _REASON_POLICY_MISMATCH,
            "original": original_policy_hash,
            "replay": replay_policy_hash,
        })

    if original_adc.get("claim_namespace") != replay_adc.get("claim_namespace") or list(original_adc.get("claim_ids") or []) != list(replay_adc.get("claim_ids") or []):
        reasons.append(_REASON_CLAIM_BINDING_MISMATCH)
        details.append({
            "field": "claim_binding",
            "reason": _REASON_CLAIM_BINDING_MISMATCH,
            "original": {
                "claim_namespace": original_adc.get("claim_namespace"),
                "claim_ids": list(original_adc.get("claim_ids") or []),
            },
            "replay": {
                "claim_namespace": replay_adc.get("claim_namespace"),
                "claim_ids": list(replay_adc.get("claim_ids") or []),
            },
        })

    if original_adc.get("integrity_result") != replay_adc.get("integrity_result"):
        reasons.append(_REASON_INTEGRITY_RESULT_MISMATCH)
        details.append({
            "field": "integrity_result",
            "reason": _REASON_INTEGRITY_RESULT_MISMATCH,
            "original": original_adc.get("integrity_result"),
            "replay": replay_adc.get("integrity_result"),
        })

    if original_adc.get("overall_result") != replay_adc.get("overall_result"):
        reasons.append(_REASON_OVERALL_RESULT_MISMATCH)
        details.append({
            "field": "overall_result",
            "reason": _REASON_OVERALL_RESULT_MISMATCH,
            "original": original_adc.get("overall_result"),
            "replay": replay_adc.get("overall_result"),
        })

    original_claim_results = _semantic_claim_results(original_adc)
    replay_claim_results = _semantic_claim_results(replay_adc)
    if original_claim_results != replay_claim_results:
        reasons.append(_REASON_CLAIM_RESULTS_MISMATCH)
        details.append({
            "field": "claim_results",
            "reason": _REASON_CLAIM_RESULTS_MISMATCH,
            "original": original_claim_results,
            "replay": replay_claim_results,
        })

    byte_equivalent = _unsigned_digest(original_adc, id_field="credential_id") == _unsigned_digest(replay_adc, id_field="credential_id")
    logically_equivalent = _semantic_adc_view(original_adc) == _semantic_adc_view(replay_adc)
    return sorted(set(reasons)), details, byte_equivalent, logically_equivalent


def _determine_verdict(reasons: List[str], logically_equivalent: bool) -> str:
    unverifiable_reasons = {
        _REASON_MISSING_DECISION_CREDENTIAL,
        _REASON_MISSING_PACK_ROOT,
        _REASON_EVIDENCE_BINDING_MISMATCH,
        _REASON_POLICY_MISMATCH,
        _REASON_CLAIM_BINDING_MISMATCH,
    }
    if any(reason in unverifiable_reasons for reason in reasons):
        return _VERDICT_UNVERIFIABLE
    if logically_equivalent:
        return _VERDICT_REPRODUCIBLE
    return _VERDICT_DRIFTED


def build_replay_judgment(
    *,
    original_manifest: Dict[str, Any],
    replay_manifest: Dict[str, Any],
    original_adc: Optional[Dict[str, Any]],
    replay_adc: Optional[Dict[str, Any]],
    judge_id: str,
    signer_pubkey: str,
    signer_pubkey_sha256: str,
    issued_at: str,
    sign_fn: Callable[[bytes], str],
    require_decision_credential: bool = True,
) -> Dict[str, Any]:
    """Build a signed replay judgment artifact."""
    reasons, details, byte_equivalent, logically_equivalent = _collect_divergences(
        original_manifest,
        replay_manifest,
        original_adc,
        replay_adc,
        require_decision_credential=require_decision_credential,
    )
    verdict = _determine_verdict(reasons, logically_equivalent)

    body: Dict[str, Any] = {
        "judgment_version": "0.1.0",
        "judgment_type": "replay_judgment",
        "issued_at": issued_at,
        "judge_id": judge_id,
        "signer_pubkey": signer_pubkey,
        "signer_pubkey_sha256": signer_pubkey_sha256,
        "original": _artifact_summary(original_manifest, original_adc),
        "replay": _artifact_summary(replay_manifest, replay_adc),
        "comparison": {
            "byte_equivalent": byte_equivalent,
            "logical_equivalent": logically_equivalent,
            "policy_consistent": _REASON_POLICY_MISMATCH not in reasons,
            "divergence_fields": [detail["field"] for detail in details],
        },
        "verdict": verdict,
        "divergence_reasons": reasons,
        "divergence_details": details,
        "signature_scope": "jcs_rfc8785_without_signature",
        "canon_version": "jcs-rfc8785",
    }

    judgment_id = _sha256_hex(to_jcs_bytes(body))
    body["judgment_id"] = judgment_id
    body["signature"] = sign_fn(to_jcs_bytes(body))

    errors = validate_replay_judgment(body)
    if errors:
        raise ValueError(f"Built replay judgment fails schema validation: {errors[0]}")
    return body


def build_explanation_trace(judgment: Dict[str, Any]) -> Dict[str, Any]:
    """Build a receipt-safe explanation trace from a replay judgment."""
    original = judgment.get("original", {})
    replay = judgment.get("replay", {})
    divergence_reasons = list(judgment.get("divergence_reasons") or [])
    divergence_fields = list(judgment.get("comparison", {}).get("divergence_fields") or [])
    verdict = judgment.get("verdict", _VERDICT_UNVERIFIABLE)

    if verdict == _VERDICT_REPRODUCIBLE:
        summary = "Replay reproduced the original decision under the same claim and policy bindings."
    elif verdict == _VERDICT_DRIFTED:
        summary = "Replay executed under compatible bindings but materially diverged from the original decision."
    else:
        summary = "Replay judgment is unverifiable because required artifacts or bindings were missing or inconsistent."

    trace = {
        "trace_version": "0.1.0",
        "trace_type": "replay_explanation_trace",
        "generated_at": judgment.get("issued_at"),
        "judgment_id": judgment.get("judgment_id"),
        "verdict": verdict,
        "summary": summary,
        "drivers": {
            "claim_namespace": original.get("claim_namespace") or replay.get("claim_namespace"),
            "claim_ids": list(original.get("claim_ids") or replay.get("claim_ids") or []),
            "policy_hashes": {
                "original": original.get("policy_hash"),
                "replay": replay.get("policy_hash"),
            },
            "overall_results": {
                "original": original.get("overall_result"),
                "replay": replay.get("overall_result"),
            },
            "integrity_results": {
                "original": original.get("integrity_result"),
                "replay": replay.get("integrity_result"),
            },
            "pack_roots": {
                "original": original.get("pack_root_sha256"),
                "replay": replay.get("pack_root_sha256"),
            },
            "divergence_reasons": divergence_reasons,
            "divergence_fields": divergence_fields,
        },
    }
    errors = validate_explanation_trace(trace)
    if errors:
        raise ValueError(f"Built explanation trace fails schema validation: {errors[0]}")
    return trace


def judge_replay(
    original_pack_dir: Path,
    replay_pack_dir: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
    signer_id: str = DEFAULT_SIGNER_ID,
    issued_at: Optional[str] = None,
    require_decision_credential: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Judge whether a replayed proof pack reproduces the original decision."""
    original_pack_dir = Path(original_pack_dir)
    replay_pack_dir = Path(replay_pack_dir)
    ks = keystore or get_default_keystore()
    verify_key = ks.get_verify_key(signer_id)
    pubkey_bytes = verify_key.encode()

    original_manifest = _load_json(original_pack_dir / "pack_manifest.json")
    replay_manifest = _load_json(replay_pack_dir / "pack_manifest.json")
    original_adc = _load_optional_json(original_pack_dir / "decision_credential.json")
    replay_adc = _load_optional_json(replay_pack_dir / "decision_credential.json")

    judgment = build_replay_judgment(
        original_manifest=original_manifest,
        replay_manifest=replay_manifest,
        original_adc=original_adc,
        replay_adc=replay_adc,
        judge_id=signer_id,
        signer_pubkey=base64.b64encode(pubkey_bytes).decode("ascii"),
        signer_pubkey_sha256=_sha256_hex(pubkey_bytes),
        issued_at=issued_at or datetime.now(timezone.utc).isoformat(),
        sign_fn=lambda data: ks.sign_b64(data, signer_id),
        require_decision_credential=require_decision_credential,
    )
    trace = build_explanation_trace(judgment)
    return judgment, trace


__all__ = [
    "build_explanation_trace",
    "build_replay_judgment",
    "judge_replay",
    "validate_explanation_trace",
    "validate_replay_judgment",
]