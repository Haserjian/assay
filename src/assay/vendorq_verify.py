"""Deterministic verifier for VendorQ answer payloads."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from assay.vendorq_index import (
    evidence_supports_affirmative,
    extract_numeric_value,
    resolve_evidence_ref,
)
from assay.vendorq_models import (
    SCHEMA_VERSION_VERIFY_REPORT,
    VendorQInputError,
    factual_claim_required,
    now_utc_iso,
    parse_iso8601,
    policy_profile,
    stable_answers_hash,
    validate_payload,
    validate_vendorq_schema,
)


@dataclass
class VerifyIssue:
    code: str
    message: str
    question_id: str
    answer_id: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "question_id": self.question_id,
            "answer_id": self.answer_id,
        }


def _contains_prohibited_commitment(details: str, prohibited_terms: List[str]) -> bool:
    d = details.lower()
    return any(term.lower() in d for term in prohibited_terms)


def _age_days(ts: str) -> Optional[float]:
    parsed = parse_iso8601(ts)
    if parsed is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds() / 86400.0)


def verify_answers_payload(
    answers_payload: Dict[str, Any],
    evidence_index: Dict[str, Any],
    *,
    policy_name: str,
    strict: bool,
    lock_payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    errors: List[VerifyIssue] = []
    warnings: List[VerifyIssue] = []
    evidence_navigation: List[Dict[str, Any]] = []

    schema_errors = validate_payload("vendorq.answer.v1.schema.json", answers_payload)
    if schema_errors:
        errors.append(VerifyIssue("VQ007_SCHEMA_INVALID", " | ".join(schema_errors[:5]), "", ""))
        report = {
            "schema_version": SCHEMA_VERSION_VERIFY_REPORT,
            "verified_at": now_utc_iso(),
            "status": "failed",
            "strict": bool(strict),
            "summary": {
                "total_answers": 0,
                "errors": len(errors),
                "warnings": len(warnings),
            },
            "errors": [e.to_dict() for e in errors],
            "warnings": [w.to_dict() for w in warnings],
            "evidence_navigation": evidence_navigation,
        }
        validate_vendorq_schema("vendorq.verify_report.v1.schema.json", report)
        return report

    policy = policy_profile(policy_name)
    freshness_days = int(policy["freshness_window_days"])

    answers = list(answers_payload.get("answers", []))

    def add_error(code: str, message: str, qid: str, aid: str) -> None:
        errors.append(VerifyIssue(code, message, qid, aid))

    def add_warning(code: str, message: str, qid: str, aid: str) -> None:
        warnings.append(VerifyIssue(code, message, qid, aid))

    for ans in answers:
        qid = str(ans.get("question_id", ""))
        aid = str(ans.get("answer_id", ""))
        status = str(ans.get("status", ""))
        answer_mode = str(ans.get("answer_mode", ""))
        claim_type = str(ans.get("claim_type", ""))
        answer_bool = ans.get("answer_bool")
        details = str(ans.get("details", ""))
        refs = list(ans.get("evidence_refs", []))
        missing_requests = list(ans.get("missing_evidence_requests", []))

        factual_required = factual_claim_required(claim_type, answer_mode)

        if factual_required and status in {"ANSWERED", "PARTIAL"} and len(refs) == 0:
            add_error("VQ001_MISSING_CITATION", "Factual ANSWERED/PARTIAL claim has no evidence refs.", qid, aid)

        if status == "ANSWERED" and missing_requests:
            add_error("VQ008_ANSWER_STATUS_INVALID_FOR_CONTENT", "ANSWERED status cannot include missing evidence requests.", qid, aid)

        if status == "INSUFFICIENT_EVIDENCE" and answer_bool is True:
            add_error("VQ008_ANSWER_STATUS_INVALID_FOR_CONTENT", "INSUFFICIENT_EVIDENCE cannot assert answer_bool=true.", qid, aid)

        if claim_type == "COMMITMENT" and claim_type not in set(policy["allowed_claim_types"]):
            add_error("VQ010_CLAIM_TYPE_POLICY_VIOLATION", "Claim type COMMITMENT is not allowed by policy profile.", qid, aid)

        if claim_type == "COMMITMENT" and _contains_prohibited_commitment(details, list(policy["prohibited_commitment_terms"])):
            add_error("VQ005_PROHIBITED_COMMITMENT", "Commitment language uses prohibited term.", qid, aid)

        numeric_support = False
        affirmative_support = False

        for ref in refs:
            ok, _value, msg, pack = resolve_evidence_ref(evidence_index, ref)
            if not ok or pack is None:
                add_error("VQ002_EVIDENCE_REF_NOT_FOUND", f"Evidence ref unresolved: {msg}", qid, aid)
                continue

            receipt_ptr = f"{ref.get('pack_id', '')}:{ref.get('receipt_id', '')}"
            evidence_navigation.append(
                {
                    "question_id": qid,
                    "answer_id": aid,
                    "evidence_ref": ref,
                    "receipt_pointer": receipt_ptr,
                    "pack_digest": str(pack["digest"]),
                    "verify_command": f"assay verify-pack {pack['path']}",
                }
            )

            ts = str(ref.get("evidence_timestamp", ""))
            age = _age_days(ts)
            if claim_type in {"PROCESS", "INCIDENT"} and age is not None and age > freshness_days:
                msg = f"Evidence older than freshness window ({age:.1f}d > {freshness_days}d)."
                if strict:
                    add_error("VQ006_STALE_EVIDENCE", msg, qid, aid)
                else:
                    add_warning("VQ006_STALE_EVIDENCE", msg, qid, aid)

            has_num, _num = extract_numeric_value(evidence_index, ref)
            if has_num:
                numeric_support = True
            if evidence_supports_affirmative(evidence_index, ref):
                affirmative_support = True

        if claim_type == "METRIC" and not numeric_support:
            add_error("VQ004_NUMERIC_CLAIM_NO_NUMERIC_SOURCE", "Metric claim has no numeric evidence path.", qid, aid)

        if answer_bool is True and not affirmative_support:
            add_error("VQ009_YES_WITHOUT_SUPPORT", "answer_bool=true without affirmative evidence support.", qid, aid)

    # Lock checks are all mapped to pack/hash mismatch class.
    if lock_payload is not None:
        locked_pack_map = {str(p["pack_id"]): str(p["digest"]) for p in lock_payload.get("pack_digests", [])}
        current_pack_map = {str(p["pack_id"]): str(p["digest"]) for p in evidence_index.get("packs", [])}
        if locked_pack_map != current_pack_map:
            errors.append(VerifyIssue("VQ003_PACK_HASH_MISMATCH", "Pack digest set does not match lockfile.", "", ""))

        if str(lock_payload.get("questions_hash", "")) != str(answers_payload.get("questions_hash", "")):
            errors.append(VerifyIssue("VQ003_PACK_HASH_MISMATCH", "questions_hash mismatch against lockfile.", "", ""))

        answers_hash_now = stable_answers_hash(answers)
        if str(lock_payload.get("answers_hash", "")) != answers_hash_now:
            errors.append(VerifyIssue("VQ003_PACK_HASH_MISMATCH", "answers_hash mismatch against lockfile.", "", ""))

        if str(lock_payload.get("policy_profile", "")) != str(answers_payload.get("policy_profile", "")):
            errors.append(VerifyIssue("VQ003_PACK_HASH_MISMATCH", "policy_profile mismatch against lockfile.", "", ""))

        if str(lock_payload.get("policy_fingerprint", "")) != str(answers_payload.get("policy_fingerprint", "")):
            errors.append(VerifyIssue("VQ003_PACK_HASH_MISMATCH", "policy_fingerprint mismatch against lockfile.", "", ""))

    report = {
        "schema_version": SCHEMA_VERSION_VERIFY_REPORT,
        "verified_at": now_utc_iso(),
        "status": "ok" if not errors else "failed",
        "strict": bool(strict),
        "summary": {
            "total_answers": len(answers),
            "errors": len(errors),
            "warnings": len(warnings),
        },
        "errors": [e.to_dict() for e in errors],
        "warnings": [w.to_dict() for w in warnings],
        "evidence_navigation": evidence_navigation,
    }
    validate_vendorq_schema("vendorq.verify_report.v1.schema.json", report)
    return report


def verify_or_raise_schema(lock_payload: Dict[str, Any]) -> None:
    errors = validate_payload("vendorq.lock.v1.schema.json", lock_payload)
    if errors:
        raise VendorQInputError("schema_validation_failed: " + " | ".join(errors[:10]))
