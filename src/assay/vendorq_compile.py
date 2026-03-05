"""Compile VendorQ answers from normalized questions + evidence index."""
from __future__ import annotations

import importlib
import os
from typing import Any, Dict, List, Optional

from assay.vendorq_index import make_manifest_evidence_ref, make_receipt_evidence_ref
from assay.vendorq_models import (
    SCHEMA_VERSION_ANSWER,
    VENDORQ_COMPILE_PROMPT,
    VendorQInputError,
    canonical_sha256,
    infer_claim_type,
    is_yes_no_question,
    now_utc_iso,
    policy_profile,
    validate_vendorq_schema,
)


def _load_provider_from_env() -> Optional[Any]:
    spec = os.environ.get("ASSAY_VENDORQ_PROVIDER", "").strip()
    if not spec:
        return None
    if ":" not in spec:
        raise VendorQInputError(
            "invalid_provider_spec: ASSAY_VENDORQ_PROVIDER must be module:Class"
        )
    module_name, class_name = spec.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except Exception as e:
        raise VendorQInputError(f"provider_import_failed: {module_name}: {e}")
    if not hasattr(module, class_name):
        raise VendorQInputError(f"provider_class_not_found: {spec}")
    cls = getattr(module, class_name)
    try:
        return cls()
    except Exception as e:
        raise VendorQInputError(f"provider_init_failed: {spec}: {e}")


def _default_review_owner(claim_type: str) -> str:
    if claim_type in {"LEGAL"}:
        return "LEGAL"
    if claim_type in {"INCIDENT", "TECH_CONTROL"}:
        return "SECURITY"
    if claim_type in {"COMMITMENT"}:
        return "ENG"
    return "NONE"


def _risk_flags(claim_type: str) -> List[str]:
    if claim_type == "LEGAL":
        return ["LEGAL_REVIEW"]
    if claim_type in {"INCIDENT", "TECH_CONTROL"}:
        return ["SECURITY_REVIEW"]
    if claim_type == "COMMITMENT":
        return ["LEGAL_REVIEW", "SECURITY_REVIEW"]
    return ["NONE"]


def _compile_single_answer(
    q: Dict[str, Any],
    evidence_index: Dict[str, Any],
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    question_id = str(q["question_id"])
    question_text = str(q["question_text"])

    claim_type = infer_claim_type(question_text)
    answer_mode = "POLICY_ONLY" if claim_type == "LEGAL" else "EVIDENCE_PLUS_EXPLANATION"

    status = "INSUFFICIENT_EVIDENCE"
    answer_bool: Optional[bool] = None
    answer_value: Optional[Any] = None
    details = "Insufficient direct evidence in provided proof packs."
    confidence = 0.2
    evidence_refs: List[Dict[str, Any]] = []
    missing = ["Provide direct artifact backing this claim (policy, report, or control evidence)."]

    packs = [evidence_index["by_pack"][p["pack_id"]] for p in evidence_index.get("packs", [])]
    first_pack = packs[0] if packs else None

    if claim_type == "METRIC" and first_pack is not None:
        n_receipts = int(first_pack["attestation"].get("n_receipts", len(first_pack["receipts"])))
        evidence_refs = [make_manifest_evidence_ref(first_pack, "attestation.n_receipts")]
        status = "ANSWERED"
        answer_value = n_receipts
        details = f"Observed {n_receipts} receipts in the evidence pack attestation."
        confidence = 0.95
        missing = []
        if is_yes_no_question(question_text):
            answer_bool = n_receipts > 0

    elif claim_type in {"PROCESS", "TECH_CONTROL", "INCIDENT"} and first_pack is not None and first_pack["receipts"]:
        receipt = first_pack["receipts"][0]
        evidence_refs = [make_receipt_evidence_ref(first_pack, receipt, "type")]
        status = "PARTIAL"
        details = "Receipts show operational activity, but direct control attestation is not explicit."
        confidence = 0.6
        missing = [
            "Provide explicit control-policy artifact mapped to this questionnaire item.",
            "Provide ownership and review cadence evidence for this control.",
        ]

    elif claim_type == "LEGAL":
        status = "PARTIAL"
        answer_mode = "POLICY_ONLY"
        details = "Legal/compliance response requires human legal review before final submission."
        confidence = 0.45
        missing = ["Legal-approved wording for this clause."]

    elif claim_type == "COMMITMENT":
        if policy.get("allow_commitments"):
            status = "PARTIAL"
            details = "Commitment language requires explicit authority and legal approval."
            confidence = 0.35
            missing = [
                "Provide authorized commitment owner and approval receipt.",
                "Attach policy allowing this commitment.",
            ]
        else:
            details = "Policy profile disallows commitment claims without explicit allowlist."
            confidence = 0.1
            missing = ["Switch to balanced policy or remove commitment phrasing."]

    elif claim_type == "CERTIFICATION":
        details = "No direct certification artifact found in provided evidence packs."
        confidence = 0.15
        missing = ["Provide certification artifact and auditor-issued evidence."]

    if status == "INSUFFICIENT_EVIDENCE":
        answer_bool = None

    review_owner = _default_review_owner(claim_type)
    review_required = review_owner != "NONE"

    answer = {
        "question_id": question_id,
        "answer_id": f"ans_{question_id}",
        "status": status,
        "answer_mode": answer_mode,
        "claim_type": claim_type,
        "answer_bool": answer_bool,
        "answer_value": answer_value,
        "details": details,
        "confidence": confidence,
        "evidence_refs": evidence_refs,
        "review_required": review_required,
        "review_reason": "Human review required for legal/security-sensitive content." if review_required else "",
        "review_owner_hint": review_owner,
        "risk_flags": _risk_flags(claim_type),
        "missing_evidence_requests": missing,
    }
    return answer


def compile_answers_payload(
    questions_payload: Dict[str, Any],
    evidence_index: Dict[str, Any],
    policy_profile_name: str,
    org_profile: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    policy = policy_profile(policy_profile_name)
    questions = list(questions_payload.get("questions", []))
    provider = _load_provider_from_env()

    answers: List[Dict[str, Any]] = []
    for q in questions:
        answer: Optional[Dict[str, Any]] = None
        if provider is not None and hasattr(provider, "compile_answer"):
            answer = provider.compile_answer(
                question=q,
                evidence_index=evidence_index,
                policy=policy,
                org_profile=org_profile,
            )
        if answer is None:
            answer = _compile_single_answer(q, evidence_index, policy)
        answers.append(answer)

    warnings: List[str] = []
    if not evidence_index.get("packs"):
        warnings.append("No evidence packs provided; all factual claims should remain INSUFFICIENT_EVIDENCE.")
    elif len(evidence_index.get("packs", [])) > 1:
        warnings.append("v1 compile currently prioritizes a primary pack for non-metric defaults; verify resolves all referenced packs.")
    if org_profile is None:
        warnings.append("No org profile provided; organizational claims were not attempted.")
    if provider is not None:
        warnings.append(f"Provider override active via ASSAY_VENDORQ_PROVIDER={provider.__class__.__module__}:{provider.__class__.__name__}")

    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION_ANSWER,
        "prompt_contract": VENDORQ_COMPILE_PROMPT,
        "policy_profile": policy["name"],
        "policy_fingerprint": str(policy["fingerprint"]),
        "questions_hash": questions_payload.get("questions_hash") or canonical_sha256(questions),
        "generated_at": now_utc_iso(),
        "answers": answers,
        "global_warnings": warnings,
    }

    validate_vendorq_schema("vendorq.answer.v1.schema.json", payload)
    return payload
