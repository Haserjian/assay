"""AuthorityChain validator (v0).

Deterministic, no-model, no-network membrane that decides whether a candidate
AuthorityChain is legitimate, provisional, downgraded, revoked, or
illegitimate. v0 validates the *shape* of legitimacy: artifact presence,
binding, role separation, scope monotonicity, freshness, revocation, and
adjudication-move closure. v1 will validate *content* legitimacy by
dereferencing authoritative documents (Charter, Invariant Library,
ReceiptDecayPolicy) and substituting real DSSE/Sigstore/Rekor verification
for the structural hooks here.

This module deliberately avoids:
  - model calls
  - network calls
  - probabilistic behavior
  - free-text truth-bearing fields
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ChainStatus(str, Enum):
    LEGITIMATE = "legitimate"
    PROVISIONAL = "provisional"
    DOWNGRADED = "downgraded"
    REVOKED = "revoked"
    ILLEGITIMATE = "illegitimate"


class ReasonCode(str, Enum):
    OK = "ok"
    MISSING_ARTIFACT = "missing_artifact"
    NONCANONICAL_ARTIFACT = "noncanonical_artifact"
    INVALID_SIGNATURE = "invalid_signature"
    MISSING_LOG_INCLUSION = "missing_log_inclusion"
    ROLE_ISOLATION_VIOLATION = "role_isolation_violation"
    SELF_SIGNED_FORBIDDEN = "self_signed_forbidden"
    CLAIM_TYPE_MISSING = "claim_type_missing"
    NORMALIZATION_MISSING = "normalization_missing"
    NORMALIZATION_AMBIGUOUS = "normalization_ambiguous"
    NON_STRICT_CLAIMTYPE_SELECTED = "non_strict_claimtype_selected"
    CHARTER_UNAUTHORIZED = "charter_unauthorized"
    CONTRACT_UNBOUND = "contract_unbound"
    RECEIPT_UNBOUND = "receipt_unbound"
    RECEIPT_SCOPE_EXCEEDED = "receipt_scope_exceeded"
    SCOPE_COMPOSITION_EXTRAPOLATED = "scope_composition_extrapolated"
    STALE_RECEIPT = "stale_receipt"
    TOO_EARLY_FOR_FINAL_ADJUDICATION = "too_early_for_final_adjudication"
    REVOKED_ARTIFACT_USED = "revoked_artifact_used"
    INVALID_ADJUDICATION_MOVE = "invalid_adjudication_move"
    CLAIM_EXCEEDS_EVIDENCE = "claim_exceeds_evidence"
    ACTION_WITHOUT_ROLLBACK = "action_without_rollback"


# Closed enum of adjudication moves. Truth-bearing field of an
# AdjudicationReceipt must be one of these.
VALID_MOVES: Set[str] = {
    "concept_underspecified",
    "contract_uncompilable",
    "receipt_insufficient",
    "proxy_match",
    "partial",
    "mismatch",
    "match",
    "refuse",
    "tier_downgrade",
}

# Tier ladder for the "claim may not exceed evidence" invariant.
TIER_RANK: Dict[str, int] = {
    "none": 0,
    "hypothesis": 1,
    "C": 2,
    "B": 3,
    "A": 4,
}


@dataclass
class ValidationFinding:
    reason: ReasonCode
    message: str
    artifact_ref: Optional[str] = None


@dataclass
class ValidationResult:
    status: ChainStatus
    reason: ReasonCode
    findings: List[ValidationFinding] = field(default_factory=list)

    def add(
        self,
        reason: ReasonCode,
        message: str,
        artifact_ref: Optional[str] = None,
    ) -> None:
        self.findings.append(ValidationFinding(reason, message, artifact_ref))


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def _tier_rank(tier: Optional[str]) -> int:
    return TIER_RANK.get(tier or "none", -1)


class AuthorityChainValidator:
    """Deterministic v0 validator for AuthorityChain objects.

    Crypto and transparency-log verification live behind explicit hooks so
    v0 can run against fixtures while v1 substitutes real verification.
    """

    REQUIRED_CHAIN_REFS = (
        "claim_ref",
        "normalization_receipt_ref",
        "claim_type_ref",
        "charter_clause_ref",
        "invariant_library_ref",
        "verifier_contract_ref",
        "adjudication_receipt_ref",
    )

    def __init__(self, now: Optional[datetime] = None) -> None:
        self.now = now or datetime.now(timezone.utc)

    # ------------------------------------------------------------------ entry

    def validate(self, chain: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult(status=ChainStatus.LEGITIMATE, reason=ReasonCode.OK)
        artifacts: Dict[str, Any] = chain.get("artifacts", {}) or {}

        for ref_field in self.REQUIRED_CHAIN_REFS:
            if not chain.get(ref_field):
                result.add(
                    ReasonCode.MISSING_ARTIFACT,
                    f"Missing chain field: {ref_field}",
                )

        self._validate_artifact_integrity(chain, artifacts, result)
        self._validate_role_isolation(chain, artifacts, result)
        self._validate_normalization(chain, artifacts, result)
        self._validate_contract_binding(chain, artifacts, result)
        self._validate_receipts(chain, artifacts, result)
        self._validate_scope_composition(chain, artifacts, result)
        self._validate_adjudication(chain, artifacts, result)
        self._validate_freshness_and_time_locks(chain, artifacts, result)
        self._validate_revocations(chain, artifacts, result)
        self._validate_authority_and_rollback(chain, artifacts, result)

        return self._finalize(result)

    # --------------------------------------------------------------- internals

    def _get(
        self, artifacts: Dict[str, Any], ref: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        if not ref:
            return None
        return artifacts.get(ref)

    def _all_chain_refs(self, chain: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        for key, value in chain.items():
            if key.endswith("_ref") and isinstance(value, str):
                refs.append(value)
            elif key.endswith("_refs") and isinstance(value, list):
                refs.extend([v for v in value if isinstance(v, str)])
        proofs = chain.get("log_inclusion_proofs") or {}
        if isinstance(proofs, dict):
            refs.extend(proofs.keys())
        return sorted(set(refs))

    # --------------------------------------------------------- artifact shape

    def _validate_artifact_integrity(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        for ref in self._all_chain_refs(chain):
            artifact = artifacts.get(ref)
            if artifact is None:
                result.add(
                    ReasonCode.MISSING_ARTIFACT,
                    f"Artifact not found: {ref}",
                    ref,
                )
                continue
            if not artifact.get("schema_version") or not artifact.get(
                "canonical_hash"
            ):
                result.add(
                    ReasonCode.NONCANONICAL_ARTIFACT,
                    "Artifact lacks schema_version or canonical_hash",
                    ref,
                )
            if not self.verify_signature(artifact):
                result.add(
                    ReasonCode.INVALID_SIGNATURE,
                    "Signature verification failed",
                    ref,
                )
            if artifact.get("requires_log_inclusion", True):
                if not self.verify_log_inclusion(ref, artifact, chain):
                    result.add(
                        ReasonCode.MISSING_LOG_INCLUSION,
                        "Missing or invalid transparency log inclusion proof",
                        ref,
                    )

    # ----------------------------------------------------------- role hygiene

    def _validate_role_isolation(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        # v1 TODO: do not read artifact["role"] directly. Resolve role from a
        # Charter signer->role registry; the role of an artifact is a property
        # of the key that signed it, not of a field the artifact asserts about
        # itself.
        signer_roles: Dict[str, Set[str]] = {}
        for ref in self._all_chain_refs(chain):
            artifact = artifacts.get(ref)
            if not artifact:
                continue
            signer = artifact.get("signed_by")
            role = artifact.get("role")
            if signer and role:
                signer_roles.setdefault(signer, set()).add(role)
        for signer, roles in signer_roles.items():
            if len(roles) > 1:
                result.add(
                    ReasonCode.ROLE_ISOLATION_VIOLATION,
                    f"Signer used across multiple runtime roles: "
                    f"{signer} -> {sorted(roles)}",
                )

        # No simulator-role artifact may occupy a verifier/adjudicator/contract
        # slot. The simulator must never certify the role it performed.
        forbidden_self_signed = (
            ("verifier_receipt_refs", "simulator"),
            ("adjudication_receipt_ref", "simulator"),
            ("verifier_contract_ref", "simulator"),
        )
        for field_name, forbidden_role in forbidden_self_signed:
            values: Any = chain.get(field_name) or []
            if isinstance(values, str):
                values = [values]
            for ref in values:
                artifact = artifacts.get(ref)
                if artifact and artifact.get("role") == forbidden_role:
                    result.add(
                        ReasonCode.SELF_SIGNED_FORBIDDEN,
                        f"{field_name} cannot be produced by role "
                        f"{forbidden_role}",
                        ref,
                    )

    # --------------------------------------------------------- normalization

    def _validate_normalization(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        norm = self._get(artifacts, chain.get("normalization_receipt_ref"))
        chain_claim_type = chain.get("claim_type_ref")
        if not norm:
            result.add(
                ReasonCode.NORMALIZATION_MISSING,
                "Missing NormalizationReceipt",
            )
            return
        candidates = norm.get("candidate_claim_types") or []
        selected = norm.get("selected")
        ambiguity_flag = bool(norm.get("ambiguity_flag"))

        if not selected or selected != chain_claim_type:
            result.add(
                ReasonCode.CLAIM_TYPE_MISSING,
                "Selected ClaimType does not match chain claim_type_ref",
                chain.get("normalization_receipt_ref"),
            )

        if ambiguity_flag and not norm.get("escalated"):
            result.add(
                ReasonCode.NORMALIZATION_AMBIGUOUS,
                "Ambiguity flag set without escalation",
                chain.get("normalization_receipt_ref"),
            )

        viable = [c for c in candidates if c.get("viable")]
        if viable:
            strictest = max(
                viable, key=lambda c: c.get("strictness_rank", 0)
            )
            if selected != strictest.get("claim_type_ref"):
                # v0 TODO: charter override is honored as a flag value on the
                # NormalizationReceipt. v1 should dereference the actual
                # Charter clause and verify that it authorizes the looser
                # ClaimType for this action class.
                charter_allows_looser = (
                    norm.get("selection_authority") == "charter_clause"
                )
                if not charter_allows_looser:
                    result.add(
                        ReasonCode.NON_STRICT_CLAIMTYPE_SELECTED,
                        "Selected ClaimType is not the strictest viable "
                        "candidate",
                        chain.get("normalization_receipt_ref"),
                    )

    # --------------------------------------------------- contract / receipts

    def _validate_contract_binding(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        contract = self._get(artifacts, chain.get("verifier_contract_ref"))
        if not contract:
            return
        if contract.get("claim_type_ref") != chain.get("claim_type_ref"):
            result.add(
                ReasonCode.CONTRACT_UNBOUND,
                "VerifierContract not bound to selected ClaimType",
                chain.get("verifier_contract_ref"),
            )
        if contract.get("invariant_library_ref") != chain.get(
            "invariant_library_ref"
        ):
            result.add(
                ReasonCode.CONTRACT_UNBOUND,
                "VerifierContract not bound to chain InvariantLibrary",
                chain.get("verifier_contract_ref"),
            )
        # The deterministic compiler marker is a v0 stand-in. v1 will require
        # the contract to be signed by a key that the Charter registers as
        # the compiler, removing the need for a string marker.
        if contract.get("compiled_by") != "deterministic_contract_compiler":
            result.add(
                ReasonCode.CONTRACT_UNBOUND,
                "VerifierContract was not produced by the deterministic "
                "compiler",
                chain.get("verifier_contract_ref"),
            )

    def _validate_receipts(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        contract_ref = chain.get("verifier_contract_ref")
        contract = self._get(artifacts, contract_ref)
        required_receipt_kinds: Set[str] = (
            set(contract.get("required_receipts") or [])
            if contract
            else set()
        )
        seen_kinds: Set[str] = set()
        for receipt_ref in chain.get("verifier_receipt_refs") or []:
            receipt = artifacts.get(receipt_ref)
            if not receipt:
                result.add(
                    ReasonCode.MISSING_ARTIFACT,
                    "Missing VerifierReceipt",
                    receipt_ref,
                )
                continue
            if receipt.get("contract_ref") != contract_ref:
                result.add(
                    ReasonCode.RECEIPT_UNBOUND,
                    "VerifierReceipt not bound to VerifierContract",
                    receipt_ref,
                )
            if receipt.get("claim_ref") != chain.get("claim_ref"):
                result.add(
                    ReasonCode.RECEIPT_UNBOUND,
                    "VerifierReceipt not bound to claim",
                    receipt_ref,
                )
            if not receipt.get("question_shape"):
                result.add(
                    ReasonCode.RECEIPT_UNBOUND,
                    "VerifierReceipt lacks question_shape",
                    receipt_ref,
                )
            kind = receipt.get("receipt_kind")
            if kind:
                seen_kinds.add(kind)
            if receipt.get("scope_exceeds_contract"):
                result.add(
                    ReasonCode.RECEIPT_SCOPE_EXCEEDED,
                    "VerifierReceipt scope exceeds contract scope",
                    receipt_ref,
                )
        for missing_kind in sorted(required_receipt_kinds - seen_kinds):
            result.add(
                ReasonCode.MISSING_ARTIFACT,
                f"Missing required receipt kind: {missing_kind}",
                contract_ref,
            )

    def _validate_scope_composition(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        # v1 TODO: do not read monotone / composite_scope_exceeds_union as
        # flags on the proof. Take typed scopes from the input receipts and
        # compute composite_scope here; verify composite ⊆ union(inputs).
        receipt_refs = chain.get("verifier_receipt_refs") or []
        if len(receipt_refs) <= 1:
            return
        proof_ref = chain.get("scope_composition_proof_ref")
        proof = self._get(artifacts, proof_ref)
        if not proof:
            result.add(
                ReasonCode.SCOPE_COMPOSITION_EXTRAPOLATED,
                "Composite receipt set lacks scope_composition_proof",
                proof_ref,
            )
            return
        if not proof.get("monotone", False):
            result.add(
                ReasonCode.SCOPE_COMPOSITION_EXTRAPOLATED,
                "Scope composition proof is not monotone",
                proof_ref,
            )
        if proof.get("composite_scope_exceeds_union", False):
            result.add(
                ReasonCode.SCOPE_COMPOSITION_EXTRAPOLATED,
                "Composite scope exceeds union of input scopes",
                proof_ref,
            )

    # ------------------------------------------------------ adjudication / time

    def _validate_adjudication(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        adj = self._get(artifacts, chain.get("adjudication_receipt_ref"))
        if not adj:
            return
        move = adj.get("move")
        if move not in VALID_MOVES:
            result.add(
                ReasonCode.INVALID_ADJUDICATION_MOVE,
                f"Invalid adjudication move: {move!r}",
                chain.get("adjudication_receipt_ref"),
            )
        if adj.get("truth_bearing_free_text", False):
            result.add(
                ReasonCode.INVALID_ADJUDICATION_MOVE,
                "Adjudication contains truth-bearing free text",
                chain.get("adjudication_receipt_ref"),
            )
        if adj.get("claim_ref") != chain.get("claim_ref"):
            result.add(
                ReasonCode.RECEIPT_UNBOUND,
                "AdjudicationReceipt not bound to claim",
                chain.get("adjudication_receipt_ref"),
            )

        authority = chain.get("authority") or {}
        claim_tier = authority.get("claim_tier")
        evidence_tier = authority.get("evidence_tier")
        if _tier_rank(claim_tier) > _tier_rank(evidence_tier):
            result.add(
                ReasonCode.CLAIM_EXCEEDS_EVIDENCE,
                f"Claim tier {claim_tier!r} exceeds evidence tier "
                f"{evidence_tier!r}",
                chain.get("adjudication_receipt_ref"),
            )

    def _validate_freshness_and_time_locks(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        # v1 TODO: do not read tier_demotion_at / refusal_at off the receipt.
        # Compute decay from (receipt.timestamp, claim_type.domain) against
        # the ReceiptDecayPolicy carried in the InvariantLibrary.
        for receipt_ref in chain.get("verifier_receipt_refs") or []:
            receipt = artifacts.get(receipt_ref)
            if not receipt:
                continue
            expires_at = self._parse_time_field(
                receipt.get("tier_demotion_at"),
                result,
                receipt_ref,
                "tier_demotion_at",
            )
            refusal_at = self._parse_time_field(
                receipt.get("refusal_at"),
                result,
                receipt_ref,
                "refusal_at",
            )
            if refusal_at and self.now >= refusal_at:
                result.add(
                    ReasonCode.STALE_RECEIPT,
                    "Receipt past refusal_at",
                    receipt_ref,
                )
            elif expires_at and self.now >= expires_at:
                result.add(
                    ReasonCode.STALE_RECEIPT,
                    "Receipt past tier_demotion_at",
                    receipt_ref,
                )

        adj = self._get(artifacts, chain.get("adjudication_receipt_ref"))
        if adj:
            earliest = self._parse_time_field(
                adj.get("earliest_adjudicable_at"),
                result,
                chain.get("adjudication_receipt_ref"),
                "earliest_adjudicable_at",
            )
            final = bool(adj.get("final", False))
            if final and earliest and self.now < earliest:
                result.add(
                    ReasonCode.TOO_EARLY_FOR_FINAL_ADJUDICATION,
                    "Final adjudication before earliest_adjudicable_at",
                    chain.get("adjudication_receipt_ref"),
                )

    def _validate_revocations(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        revoked_refs: Set[str] = set(chain.get("revoked_artifact_refs") or [])
        for ref in self._all_chain_refs(chain):
            artifact = artifacts.get(ref)
            if ref in revoked_refs or (artifact and artifact.get("revoked")):
                result.add(
                    ReasonCode.REVOKED_ARTIFACT_USED,
                    "AuthorityChain uses revoked artifact",
                    ref,
                )

    def _validate_authority_and_rollback(
        self,
        chain: Dict[str, Any],
        artifacts: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        # v1 TODO: do not trust authority.action_domain_authorized as a flag.
        # Resolve the Charter clause and verify it covers (action_domain,
        # claim_tier, blast_radius) and is currently in force.
        authority = chain.get("authority") or {}
        if not authority.get("action_domain_authorized", False):
            result.add(
                ReasonCode.CHARTER_UNAUTHORIZED,
                "Action domain not authorized by Charter clause",
                chain.get("charter_clause_ref"),
            )

        action_ref = chain.get("action_receipt_ref")
        rollback_ref = chain.get("rollback_contract_ref")
        if action_ref and not rollback_ref:
            action = self._get(artifacts, action_ref)
            irreversible_allowed = bool(
                action and action.get("charter_allows_irreversible")
            )
            if not irreversible_allowed:
                result.add(
                    ReasonCode.ACTION_WITHOUT_ROLLBACK,
                    "ActionReceipt present without RollbackContract",
                    action_ref,
                )

    def _parse_time_field(
        self,
        value: Optional[str],
        result: ValidationResult,
        artifact_ref: Optional[str],
        field_name: str,
    ) -> Optional[datetime]:
        if not value:
            return None
        parsed = _parse_time(value)
        if parsed is None:
            result.add(
                ReasonCode.NONCANONICAL_ARTIFACT,
                f"Invalid ISO-8601 timestamp in {field_name}",
                artifact_ref,
            )
        return parsed

    # ------------------------------------------------------------ crypto hooks

    def verify_signature(self, artifact: Dict[str, Any]) -> bool:
        """v0 hook: structural signature presence check.

        v1 should substitute DSSE / Sigstore / local-key verification, and
        bind the signature to the canonical_hash of the artifact body.
        """
        return bool(artifact.get("signature") and artifact.get("signed_by"))

    def verify_log_inclusion(
        self,
        ref: str,
        artifact: Dict[str, Any],
        chain: Dict[str, Any],
    ) -> bool:
        """v0 hook: structural transparency-log proof presence check.

        v1 should substitute Rekor / Sigstore inclusion verification against
        the artifact's signing-time epoch. For v0, presence of log_index and
        integrated_time is required, and if the proof carries a body_hash it
        must match the artifact's canonical_hash so the proof is at least
        bound to the artifact body it claims to attest.
        """
        proofs = chain.get("log_inclusion_proofs") or {}
        proof = proofs.get(ref) if isinstance(proofs, dict) else None
        if not proof:
            return False
        if not (proof.get("log_index") and proof.get("integrated_time")):
            return False
        proof_hash = proof.get("body_hash")
        artifact_hash = artifact.get("canonical_hash")
        if (
            proof_hash is not None
            and artifact_hash is not None
            and proof_hash != artifact_hash
        ):
            return False
        return True

    # ---------------------------------------------------------- finalization

    _ILLEGITIMATE_REASONS: Set[ReasonCode] = {
        ReasonCode.MISSING_ARTIFACT,
        ReasonCode.NONCANONICAL_ARTIFACT,
        ReasonCode.INVALID_SIGNATURE,
        ReasonCode.MISSING_LOG_INCLUSION,
        ReasonCode.ROLE_ISOLATION_VIOLATION,
        ReasonCode.SELF_SIGNED_FORBIDDEN,
        ReasonCode.CLAIM_TYPE_MISSING,
        ReasonCode.NORMALIZATION_MISSING,
        ReasonCode.NON_STRICT_CLAIMTYPE_SELECTED,
        ReasonCode.CHARTER_UNAUTHORIZED,
        ReasonCode.CONTRACT_UNBOUND,
        ReasonCode.RECEIPT_UNBOUND,
        ReasonCode.RECEIPT_SCOPE_EXCEEDED,
        ReasonCode.SCOPE_COMPOSITION_EXTRAPOLATED,
        ReasonCode.INVALID_ADJUDICATION_MOVE,
        ReasonCode.CLAIM_EXCEEDS_EVIDENCE,
        ReasonCode.ACTION_WITHOUT_ROLLBACK,
    }

    def _finalize(self, result: ValidationResult) -> ValidationResult:
        if not result.findings:
            return result
        reasons = {f.reason for f in result.findings}

        if ReasonCode.REVOKED_ARTIFACT_USED in reasons:
            result.status = ChainStatus.REVOKED
            result.reason = ReasonCode.REVOKED_ARTIFACT_USED
            return result

        intersection = reasons & self._ILLEGITIMATE_REASONS
        if intersection:
            result.status = ChainStatus.ILLEGITIMATE
            for finding in result.findings:
                if finding.reason in intersection:
                    result.reason = finding.reason
                    return result

        if ReasonCode.STALE_RECEIPT in reasons:
            result.status = ChainStatus.DOWNGRADED
            result.reason = ReasonCode.STALE_RECEIPT
            return result

        if ReasonCode.TOO_EARLY_FOR_FINAL_ADJUDICATION in reasons:
            result.status = ChainStatus.PROVISIONAL
            result.reason = ReasonCode.TOO_EARLY_FOR_FINAL_ADJUDICATION
            return result

        if ReasonCode.NORMALIZATION_AMBIGUOUS in reasons:
            result.status = ChainStatus.PROVISIONAL
            result.reason = ReasonCode.NORMALIZATION_AMBIGUOUS
            return result

        result.status = ChainStatus.ILLEGITIMATE
        result.reason = result.findings[0].reason
        return result
