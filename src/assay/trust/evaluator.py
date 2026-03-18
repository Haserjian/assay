"""Trust evaluator: compose classify → verify → authorize → accept.

This module does not modify the verifier. It consumes verification results
and computes trust decisions. Enforcement is a caller choice.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from assay.trust.acceptance import AcceptanceMatrix
from assay.trust.registry import SignerEntry, SignerRegistry
from assay.trust.types import (
    AcceptanceDecision,
    ArtifactClassification,
    AuthorizationDecision,
    TrustEvaluation,
    VerificationFacts,
)


# ---------------------------------------------------------------------------
# Stage 1: Classify
# ---------------------------------------------------------------------------

def classify_pack_manifest(manifest: Dict[str, Any]) -> ArtifactClassification:
    """Classify a proof pack manifest."""
    attestation = manifest.get("attestation", {})
    ci_binding = attestation.get("ci_binding")

    if ci_binding:
        purpose = "ci_attestation"
    elif attestation.get("mode") == "shadow":
        purpose = "internal_evidence"
    else:
        purpose = "unknown"

    provenance: Dict[str, Any] = {}
    if ci_binding:
        for key in ("provider", "repo", "ref", "commit_sha"):
            val = ci_binding.get(key)
            if val:
                provenance[key] = val
    verifier_version = attestation.get("verifier_version")
    if verifier_version:
        provenance["verifier_version"] = verifier_version

    return ArtifactClassification(
        artifact_class="proof_pack",
        schema_version=manifest.get("pack_version", "unknown"),
        declared_purpose=purpose,
        provenance=provenance,
    )


# ---------------------------------------------------------------------------
# Stage 2: Extract verification facts from VerifyResult + manifest
# ---------------------------------------------------------------------------

def extract_verification_facts(
    verify_result: Any,
    manifest: Dict[str, Any],
) -> VerificationFacts:
    """Extract judgment-free facts from a VerifyResult and manifest.

    Args:
        verify_result: assay.integrity.VerifyResult
        manifest: signed pack_manifest.json dict
    """
    error_codes = [e.code for e in verify_result.errors]
    warning_codes = list(verify_result.warnings)

    # Determine signature validity from error codes
    sig_error_codes = {"E_PACK_SIG_INVALID", "E_SIG_INVALID"}
    has_signature = bool(manifest.get("signature"))
    if not has_signature:
        signature_valid = None
    elif any(c in sig_error_codes for c in error_codes):
        signature_valid = False
    else:
        signature_valid = True

    return VerificationFacts(
        integrity_passed=verify_result.passed,
        signature_valid=signature_valid,
        signer_id=manifest.get("signer_id"),
        signer_fingerprint=manifest.get("signer_pubkey_sha256"),
        embedded_pubkey=bool(manifest.get("signer_pubkey")),
        schema_recognized=manifest.get("manifest_version") in ("1.0.0",),
        error_codes=error_codes,
        warning_codes=warning_codes,
    )


# ---------------------------------------------------------------------------
# Stage 3: Authorize signer
# ---------------------------------------------------------------------------

def authorize_signer(
    facts: VerificationFacts,
    classification: ArtifactClassification,
    registry: Optional[SignerRegistry],
) -> AuthorizationDecision:
    """Determine signer authorization status.

    Without a registry, returns status="not_evaluated".
    """
    if registry is None:
        return AuthorizationDecision(
            subject_signer_id=facts.signer_id,
            subject_fingerprint=facts.signer_fingerprint,
            status="not_evaluated",
            lifecycle_state=None,
            reason_codes=["NO_REGISTRY"],
        )

    entry = registry.lookup(
        signer_id=facts.signer_id,
        fingerprint=facts.signer_fingerprint,
    )

    if entry is None:
        return AuthorizationDecision(
            subject_signer_id=facts.signer_id,
            subject_fingerprint=facts.signer_fingerprint,
            status="unrecognized",
            lifecycle_state=None,
            reason_codes=["SIGNER_NOT_IN_REGISTRY"],
        )

    if entry.lifecycle == "revoked":
        return AuthorizationDecision(
            subject_signer_id=entry.signer_id,
            subject_fingerprint=entry.fingerprint,
            status="revoked",
            lifecycle_state="revoked",
            reason_codes=["SIGNER_REVOKED"],
        )

    # Check grants (wave 1: match on artifact_class + purpose only)
    matched: List[Dict[str, Any]] = []
    for grant in entry.grants:
        class_match = grant.artifact_class in (classification.artifact_class, "*")
        purpose_match = grant.purpose in (classification.declared_purpose, "*")
        if class_match and purpose_match:
            matched.append({
                "artifact_class": grant.artifact_class,
                "purpose": grant.purpose,
            })

    if matched:
        return AuthorizationDecision(
            subject_signer_id=entry.signer_id,
            subject_fingerprint=entry.fingerprint,
            status="authorized",
            lifecycle_state=entry.lifecycle,
            matched_grants=matched,
        )

    return AuthorizationDecision(
        subject_signer_id=entry.signer_id,
        subject_fingerprint=entry.fingerprint,
        status="recognized",
        lifecycle_state=entry.lifecycle,
        reason_codes=["NO_MATCHING_GRANT"],
    )


# ---------------------------------------------------------------------------
# Stage 4: Evaluate acceptance
# ---------------------------------------------------------------------------

def _verification_level(facts: VerificationFacts) -> str:
    """Derive verification level from facts."""
    if facts.signature_valid is True and facts.integrity_passed:
        return "signature_verified"
    if facts.integrity_passed:
        return "hash_verified"
    return "unverified"


def evaluate_acceptance(
    classification: ArtifactClassification,
    facts: VerificationFacts,
    authorization: AuthorizationDecision,
    matrix: Optional[AcceptanceMatrix],
    target: str,
) -> AcceptanceDecision:
    """Evaluate acceptance for a specific policy target.

    Without a matrix, returns decision="not_evaluated".
    """
    if matrix is None:
        return AcceptanceDecision(
            decision="not_evaluated",
            target=target,
            rationale="no acceptance policy loaded",
            reason_codes=["NO_POLICY"],
        )

    level = _verification_level(facts)
    decision, rationale, reason_codes = matrix.evaluate(
        artifact_class=classification.artifact_class,
        verification_level=level,
        authorization_status=authorization.status,
        target=target,
    )

    return AcceptanceDecision(
        decision=decision,
        target=target,
        rationale=rationale,
        reason_codes=reason_codes,
    )


# ---------------------------------------------------------------------------
# Composed evaluation
# ---------------------------------------------------------------------------

def evaluate_trust(
    verify_result: Any,
    manifest: Dict[str, Any],
    *,
    registry: Optional[SignerRegistry] = None,
    acceptance_policy: Optional[AcceptanceMatrix] = None,
    target: str = "local_verify",
) -> TrustEvaluation:
    """Run all four trust evaluation stages on a proof pack.

    Args:
        verify_result: assay.integrity.VerifyResult from verify_pack_manifest
        manifest: the signed pack_manifest.json dict
        registry: optional signer registry (None → authorization not evaluated)
        acceptance_policy: optional acceptance matrix (None → acceptance not evaluated)
        target: policy target to evaluate acceptance against

    Returns a TrustEvaluation with all four stage results.
    """
    classification = classify_pack_manifest(manifest)
    facts = extract_verification_facts(verify_result, manifest)
    authorization = authorize_signer(facts, classification, registry)
    acceptance = evaluate_acceptance(
        classification, facts, authorization, acceptance_policy, target,
    )
    return TrustEvaluation(
        classification=classification,
        facts=facts,
        authorization=authorization,
        acceptance=acceptance,
    )
