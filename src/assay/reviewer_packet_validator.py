"""Reviewer Packet validator -- catches inflation, missing evidence, and inconsistency.

Five failure modes (the commercial differentiator):
  E_MISSING_EVIDENCE        ANSWERED question has no evidence refs
  E_AUTHORITY_INFLATED      machine_evidenced but no machine-generated receipt
  E_UNRESOLVED_RELABELED    was INSUFFICIENT_EVIDENCE, inflated to ANSWERED without evidence
  E_MACHINE_CLAIM_NO_RECEIPT  machine_evidenced but only human attestation refs
  E_VERIFICATION_MISMATCH   packet says proof_pack_verified=true but re-verification fails
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from assay.reviewer_packet import (
    ANSWER_STATUSES,
    AUTHORITY_CLASSES,
    ReviewerPacket,
)

# Error codes
E_MISSING_EVIDENCE = "E_MISSING_EVIDENCE"
E_AUTHORITY_INFLATED = "E_AUTHORITY_INFLATED"
E_UNRESOLVED_RELABELED = "E_UNRESOLVED_RELABELED"
E_MACHINE_CLAIM_NO_RECEIPT = "E_MACHINE_CLAIM_NO_RECEIPT"
E_VERIFICATION_MISMATCH = "E_VERIFICATION_MISMATCH"
E_INVALID_STATUS = "E_INVALID_STATUS"
E_INVALID_AUTHORITY = "E_INVALID_AUTHORITY"
E_NO_QUESTIONS = "E_NO_QUESTIONS"
E_EVIDENCE_REF_ORPHANED = "E_EVIDENCE_REF_ORPHANED"
E_ARTIFACT_PATH_MISSING = "E_ARTIFACT_PATH_MISSING"
E_ARTIFACT_PATH_ESCAPE = "E_ARTIFACT_PATH_ESCAPE"

# Receipt types that constitute machine-generated evidence
MACHINE_RECEIPT_TYPES = frozenset({
    "model_call",
    "guardian_verdict",
    "guardian_decision",
    "claim_verification",
    "claim_extraction",
    "packet_compiled",
    "verification_result",
})


@dataclass
class PacketValidationError:
    code: str
    message: str
    question_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.question_id is not None:
            d["question_id"] = self.question_id
        return d


@dataclass
class PacketValidationResult:
    passed: bool
    errors: List[PacketValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": self.warnings,
        }


def validate_packet(
    packet: ReviewerPacket,
    *,
    receipt_ids_on_disk: Optional[Set[str]] = None,
    require_unresolved: bool = True,
    proof_pack_dir: Optional[Path] = None,
) -> PacketValidationResult:
    """Validate a ReviewerPacket for evidence completeness and honesty.

    Args:
        packet: The packet to validate.
        receipt_ids_on_disk: Set of receipt_ids present in the proof pack.
            When provided, evidence refs are checked for orphaned references.
        require_unresolved: When True (default), at least one question must
            be INSUFFICIENT_EVIDENCE. This is the anti-inflation guardrail.
        proof_pack_dir: When provided, re-verify the proof pack and check
            consistency with packet.proof_pack_verified.
    """
    errors: List[PacketValidationError] = []
    warnings: List[str] = []

    # Structural: must have questions
    if not packet.questions:
        errors.append(PacketValidationError(
            code=E_NO_QUESTIONS,
            message="Packet has no questions",
        ))
        return PacketValidationResult(passed=False, errors=errors, warnings=warnings)

    has_unresolved = False

    for q in packet.questions:
        # Valid status
        if q.status not in ANSWER_STATUSES:
            errors.append(PacketValidationError(
                code=E_INVALID_STATUS,
                message=f"Invalid status '{q.status}' (must be one of {sorted(ANSWER_STATUSES)})",
                question_id=q.question_id,
            ))

        # Valid authority class
        if q.authority_class not in AUTHORITY_CLASSES:
            errors.append(PacketValidationError(
                code=E_INVALID_AUTHORITY,
                message=f"Invalid authority_class '{q.authority_class}' (must be one of {sorted(AUTHORITY_CLASSES)})",
                question_id=q.question_id,
            ))

        if q.status == "INSUFFICIENT_EVIDENCE":
            has_unresolved = True

        # --- Core anti-inflation checks ---

        if q.status == "ANSWERED":
            # Check 1: ANSWERED must have evidence
            if not q.evidence_refs:
                errors.append(PacketValidationError(
                    code=E_MISSING_EVIDENCE,
                    message=f"Question is ANSWERED but has no evidence refs",
                    question_id=q.question_id,
                ))

            # Check 2: machine_evidenced must have at least one machine receipt
            if q.authority_class == "machine_evidenced" and q.evidence_refs:
                has_machine = any(
                    ref.receipt_type in MACHINE_RECEIPT_TYPES
                    for ref in q.evidence_refs
                )
                if not has_machine:
                    errors.append(PacketValidationError(
                        code=E_MACHINE_CLAIM_NO_RECEIPT,
                        message=f"Claims machine_evidenced but no machine-generated receipt type found",
                        question_id=q.question_id,
                    ))

            # Check 3: mixed must have both machine and human evidence
            if q.authority_class == "mixed" and q.evidence_refs:
                has_machine = any(
                    ref.authority_class == "machine_evidenced"
                    for ref in q.evidence_refs
                )
                has_human = any(
                    ref.authority_class == "human_attested"
                    for ref in q.evidence_refs
                )
                if not (has_machine and has_human):
                    warnings.append(
                        f"{q.question_id}: mixed authority but evidence refs "
                        f"don't include both machine and human sources"
                    )

        # Check 4: authority inflation — insufficient authority with ANSWERED status
        if q.status == "ANSWERED" and q.authority_class == "insufficient":
            errors.append(PacketValidationError(
                code=E_AUTHORITY_INFLATED,
                message=f"ANSWERED with 'insufficient' authority class is contradictory",
                question_id=q.question_id,
            ))

        # Check 5: unresolved relabeled — ANSWERED with machine_evidenced but
        # evidence refs are empty (the tamper-B scenario)
        if (
            q.status == "ANSWERED"
            and q.authority_class == "machine_evidenced"
            and not q.evidence_refs
        ):
            errors.append(PacketValidationError(
                code=E_UNRESOLVED_RELABELED,
                message=f"Appears to be an inflated unresolved question: "
                        f"ANSWERED + machine_evidenced but no evidence",
                question_id=q.question_id,
            ))

        # Check 6: orphaned evidence refs
        if receipt_ids_on_disk is not None:
            for ref in q.evidence_refs:
                if ref.receipt_id not in receipt_ids_on_disk:
                    errors.append(PacketValidationError(
                        code=E_EVIDENCE_REF_ORPHANED,
                        message=f"Evidence ref '{ref.receipt_id}' not found in proof pack",
                        question_id=q.question_id,
                    ))

        # Check 7: artifact_path existence and containment
        if proof_pack_dir is not None:
            packet_root = proof_pack_dir.parent
            root_resolved = packet_root.resolve()
            for ref in q.evidence_refs:
                if ref.artifact_path is not None:
                    target = (packet_root / ref.artifact_path).resolve()
                    # Semantic path containment (not string prefix).
                    # relative_to raises ValueError if target is not
                    # under root_resolved, catching both traversal
                    # and sibling-prefix attacks.
                    try:
                        target.relative_to(root_resolved)
                    except ValueError:
                        errors.append(PacketValidationError(
                            code=E_ARTIFACT_PATH_ESCAPE,
                            message=f"artifact_path '{ref.artifact_path}' escapes packet root",
                            question_id=q.question_id,
                        ))
                        continue
                    if not target.exists():
                        errors.append(PacketValidationError(
                            code=E_ARTIFACT_PATH_MISSING,
                            message=f"artifact_path '{ref.artifact_path}' does not exist on disk",
                            question_id=q.question_id,
                        ))

    # Anti-inflation guardrail: require at least one honest gap
    if require_unresolved and not has_unresolved:
        warnings.append(
            "No INSUFFICIENT_EVIDENCE questions. A packet claiming 100% "
            "coverage may indicate inflation."
        )

    # Proof pack re-verification
    if proof_pack_dir is not None:
        _check_proof_pack_consistency(packet, proof_pack_dir, errors)

    return PacketValidationResult(
        passed=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def _check_proof_pack_consistency(
    packet: ReviewerPacket,
    proof_pack_dir: Path,
    errors: List[PacketValidationError],
) -> None:
    """Re-verify the nested proof pack and check consistency."""
    manifest_path = proof_pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        errors.append(PacketValidationError(
            code=E_VERIFICATION_MISMATCH,
            message="Proof pack manifest not found at expected path",
        ))
        return

    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(PacketValidationError(
            code=E_VERIFICATION_MISMATCH,
            message=f"Cannot read proof pack manifest: {exc}",
        ))
        return

    from assay.integrity import verify_pack_manifest
    from assay.keystore import AssayKeyStore

    result = verify_pack_manifest(manifest, proof_pack_dir, None)

    if packet.proof_pack_verified and not result.passed:
        errors.append(PacketValidationError(
            code=E_VERIFICATION_MISMATCH,
            message="Packet claims proof_pack_verified=true but re-verification failed: "
                    + (result.errors[0].message if result.errors else "unknown error"),
        ))
    elif not packet.proof_pack_verified and result.passed:
        # Not an error, but worth noting
        pass


def validate_packet_dict(
    packet_dict: Dict[str, Any],
    **kwargs: Any,
) -> PacketValidationResult:
    """Validate a packet from its dict representation.

    Convenience for validating packet.json loaded from disk.
    """
    from assay.reviewer_packet import EvidenceRef, QuestionAnswer, ReviewerPacket

    questions = []
    for qd in packet_dict.get("questions", []):
        refs = [
            EvidenceRef(
                receipt_id=r["receipt_id"],
                receipt_type=r["receipt_type"],
                authority_class=r["authority_class"],
                description=r["description"],
                artifact_path=r.get("artifact_path"),
            )
            for r in qd.get("evidence_refs", [])
        ]
        questions.append(QuestionAnswer(
            question_id=qd["question_id"],
            question_text=qd["question_text"],
            status=qd["status"],
            authority_class=qd["authority_class"],
            evidence_refs=refs,
            answer_text=qd.get("answer_text"),
            notes=qd.get("notes"),
        ))

    packet = ReviewerPacket(
        packet_id=packet_dict["packet_id"],
        workflow_name=packet_dict["workflow_name"],
        workflow_description=packet_dict["workflow_description"],
        questions=questions,
        proof_pack_path=packet_dict["proof_pack_path"],
        proof_pack_id=packet_dict["proof_pack_id"],
        proof_pack_verified=packet_dict["proof_pack_verified"],
        signer_id=packet_dict["signer_id"],
        signer_fingerprint=packet_dict["signer_fingerprint"],
        generated_at=packet_dict["generated_at"],
    )

    return validate_packet(packet, **kwargs)


__all__ = [
    "E_ARTIFACT_PATH_ESCAPE",
    "E_ARTIFACT_PATH_MISSING",
    "E_AUTHORITY_INFLATED",
    "E_EVIDENCE_REF_ORPHANED",
    "E_INVALID_AUTHORITY",
    "E_INVALID_STATUS",
    "E_MACHINE_CLAIM_NO_RECEIPT",
    "E_MISSING_EVIDENCE",
    "E_NO_QUESTIONS",
    "E_UNRESOLVED_RELABELED",
    "E_VERIFICATION_MISMATCH",
    "MACHINE_RECEIPT_TYPES",
    "PacketValidationError",
    "PacketValidationResult",
    "validate_packet",
    "validate_packet_dict",
]
