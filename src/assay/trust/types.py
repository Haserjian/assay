"""Trust evaluation result types.

All types are serializable to JSON for logging, receipts, and CLI output.
Verification facts are descriptive only — no judgment words.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ArtifactClassification:
    """Stage 1: What kind of artifact is this?"""

    artifact_class: str  # proof_pack, witness_envelope, ledger_entry, adc
    schema_version: str  # declared format version
    declared_purpose: str  # ci_attestation, publication, internal_evidence, unknown
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_class": self.artifact_class,
            "schema_version": self.schema_version,
            "declared_purpose": self.declared_purpose,
            "provenance": self.provenance,
        }


@dataclass
class VerificationFacts:
    """Stage 2: Judgment-free observations from the verifier."""

    integrity_passed: bool
    signature_valid: Optional[bool]  # None if no signature material
    signer_id: Optional[str]
    signer_fingerprint: Optional[str]  # SHA-256 of pubkey
    embedded_pubkey: bool
    schema_recognized: bool
    error_codes: List[str] = field(default_factory=list)
    warning_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "integrity_passed": self.integrity_passed,
            "signature_valid": self.signature_valid,
            "signer_id": self.signer_id,
            "signer_fingerprint": self.signer_fingerprint,
            "embedded_pubkey": self.embedded_pubkey,
            "schema_recognized": self.schema_recognized,
            "error_codes": self.error_codes,
            "warning_codes": self.warning_codes,
        }


@dataclass
class AuthorizationDecision:
    """Stage 3: Is the signer recognized and granted permission?"""

    subject_signer_id: Optional[str]
    subject_fingerprint: Optional[str]
    status: str  # authorized, recognized, unrecognized, revoked
    lifecycle_state: Optional[str]  # active, rotated, revoked
    matched_grants: List[Dict[str, Any]] = field(default_factory=list)
    reason_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": {
                "signer_id": self.subject_signer_id,
                "fingerprint": self.subject_fingerprint,
            },
            "status": self.status,
            "lifecycle_state": self.lifecycle_state,
            "matched_grants": self.matched_grants,
            "reason_codes": self.reason_codes,
        }


@dataclass
class AcceptanceDecision:
    """Stage 4: Is this artifact acceptable for a specific target?"""

    decision: str  # accept, warn, reject
    target: str  # local_verify, ci_gate, publication
    rationale: str
    reason_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "target": self.target,
            "rationale": self.rationale,
            "reason_codes": self.reason_codes,
        }


@dataclass
class TrustEvaluation:
    """Composed result of all four stages."""

    classification: ArtifactClassification
    facts: VerificationFacts
    authorization: AuthorizationDecision
    acceptance: AcceptanceDecision

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.to_dict(),
            "facts": self.facts.to_dict(),
            "authorization": self.authorization.to_dict(),
            "acceptance": self.acceptance.to_dict(),
        }
