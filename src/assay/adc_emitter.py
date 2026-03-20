"""
AI Decision Credential (ADC) v0.1 Emitter.

Builds a signed ADC credential from proof pack data. The ADC sits above
the 5-file proof pack kernel as a portable, self-contained credential
envelope suitable for cross-system exchange.

Called from ProofPack.build() after step 8 (signing), using data already
computed during the pack build. No additional I/O or external dependencies
beyond what proof_pack.py already imports.

Spec: schemas/adc_v0.1.schema.json
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, List, Optional

from assay._receipts.canonicalize import to_jcs_bytes
from assay.claim_verifier import ClaimSetResult


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _derive_overall_result(
    integrity_passed: bool,
    claim_result: Optional[ClaimSetResult],
) -> str:
    """Derive ADC overall_result from integrity + claim verification.

    Maps to Assay exit codes: PASS=0, HONEST_FAIL=1, TAMPERED=2.
    """
    if not integrity_passed:
        return "TAMPERED"
    if claim_result is None:
        return "PASS"
    if claim_result.passed:
        return "PASS"
    return "HONEST_FAIL"


def _derive_claim_results(
    claim_result: Optional[ClaimSetResult],
) -> Optional[List[Dict[str, Any]]]:
    """Convert ClaimSetResult to ADC claim_results array."""
    if claim_result is None:
        return None
    results = []
    for cr in claim_result.results:
        entry: Dict[str, Any] = {
            "claim_id": cr.claim_id,
            "result": "PASS" if cr.passed else "FAIL",
        }
        if not cr.passed:
            sev = cr.severity if cr.severity in ("info", "warning", "error", "critical") else "error"
            entry["severity"] = sev
        results.append(entry)
    return results


def refresh_adc_witness_state(
    adc: Dict[str, Any],
    *,
    time_authority: str,
    witness_status: str,
    sign_fn: Callable[[bytes], str],
) -> Dict[str, Any]:
    """Return a re-signed ADC with updated witness state.

    This is intended for post-hoc witness amendment after a valid witness
    bundle has been generated and verified. The credential body is updated,
    rehashed, and re-signed so downstream readers see the amended witness
    truth instead of the stale emission-time defaults.
    """
    body = {k: v for k, v in adc.items() if k not in ("credential_id", "signature")}
    body["time_authority"] = time_authority
    body["witness_status"] = witness_status

    credential_id = _sha256_hex(to_jcs_bytes(body))
    body["credential_id"] = credential_id

    canonical_for_signing = to_jcs_bytes(body)
    body["signature"] = sign_fn(canonical_for_signing)
    return body


def build_adc(
    *,
    # Issuer
    issuer_id: str,
    signer_pubkey: str,
    signer_pubkey_sha256: str,
    # Claim binding
    claim_namespace: str,
    claim_ids: List[str],
    claim_summary: Optional[str] = None,
    # Evidence binding
    evidence_manifest_sha256: str,
    evidence_pack_id: str,
    evidence_n_receipts: int,
    evidence_head_hash: Optional[str] = None,
    # Policy binding
    policy_id: Optional[str] = None,
    policy_hash: Optional[str] = None,
    governance_framework: Optional[str] = None,
    # Results
    integrity_passed: bool,
    claim_result: Optional[ClaimSetResult] = None,
    # Time
    issued_at: str,
    evidence_observed_at: Optional[str] = None,
    evaluated_at: Optional[str] = None,
    valid_until: Optional[str] = None,
    # Challenge
    challenge_window_seconds: Optional[int] = None,
    supersedes: Optional[str] = None,
    # Signing
    sign_fn: Callable[[bytes], str],
) -> Dict[str, Any]:
    """Build a signed ADC v0.1 credential.

    Args:
        sign_fn: Takes canonical bytes, returns base64 Ed25519 signature.
                 Typically ``lambda data: ks.sign_b64(data, signer_id)``.

    Returns:
        Complete signed ADC credential dict, ready to write as JSON.

    credential_id computation:
        1. Build credential body (all fields except credential_id and signature)
        2. credential_id = SHA-256(JCS(body))
        3. signature = Sign(JCS(body + credential_id))
    """
    overall_result = _derive_overall_result(integrity_passed, claim_result)
    adc_claim_results = _derive_claim_results(claim_result)

    # Build credential body — everything except credential_id and signature.
    body: Dict[str, Any] = {
        "credential_version": "0.1.0",
        "credential_type": "ai_decision_credential",
        "issued_at": issued_at,
        "issuer_id": issuer_id,
        "signer_pubkey": signer_pubkey,
        "signer_pubkey_sha256": signer_pubkey_sha256,
        "claim_namespace": claim_namespace,
        "claim_ids": claim_ids,
        "evidence_manifest_sha256": evidence_manifest_sha256,
        "evidence_pack_id": evidence_pack_id,
        "integrity_result": "PASS" if integrity_passed else "FAIL",
        "overall_result": overall_result,
        "evaluated_at": evaluated_at or issued_at,
        "signature_scope": "jcs_rfc8785_without_signature",
        "canon_version": "jcs-rfc8785",
    }

    # Optional fields — only include when provided
    if claim_summary is not None:
        body["claim_summary"] = claim_summary
    if evidence_n_receipts is not None:
        body["evidence_n_receipts"] = evidence_n_receipts
    if evidence_head_hash is not None:
        body["evidence_head_hash"] = evidence_head_hash
    if policy_id is not None:
        body["policy_id"] = policy_id
    if policy_hash is not None:
        body["policy_hash"] = policy_hash
    if governance_framework is not None:
        body["governance_framework"] = governance_framework
    if adc_claim_results is not None:
        body["claim_results"] = adc_claim_results
    if evidence_observed_at is not None:
        body["evidence_observed_at"] = evidence_observed_at

    # Time semantics
    body["valid_from"] = issued_at
    body["valid_until"] = valid_until
    body["time_authority"] = "local_clock"

    # Challenge semantics
    body["challenge_window_seconds"] = challenge_window_seconds
    body["challenge_endpoint"] = None
    body["supersedes"] = supersedes
    body["superseded_by"] = None

    # Witness defaults at emission time. The witness command may later
    # reissue this credential once valid external witness material exists.
    body["witness_status"] = "unwitnessed"
    body["ledger_entry_hash"] = None
    body["transparency_log_id"] = None

    # Step 2: credential_id = SHA-256(JCS(body))
    credential_id = _sha256_hex(to_jcs_bytes(body))
    body["credential_id"] = credential_id

    # Step 3: signature = Sign(JCS(body + credential_id))
    canonical_for_signing = to_jcs_bytes(body)
    signature_b64 = sign_fn(canonical_for_signing)
    body["signature"] = signature_b64

    return body


__all__ = ["build_adc", "refresh_adc_witness_state"]
