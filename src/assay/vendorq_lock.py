"""VendorQ lockfile write/load helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from assay import __version__ as assay_version
from assay.vendorq_models import (
    SCHEMA_VERSION_ANSWER,
    SCHEMA_VERSION_EVIDENCE_REF,
    SCHEMA_VERSION_LOCK,
    SCHEMA_VERSION_QUESTION,
    SCHEMA_VERSION_VERIFY_REPORT,
    VendorQInputError,
    canonical_sha256,
    load_json,
    now_utc_iso,
    stable_answers_hash,
    validate_vendorq_schema,
    write_json,
)


def write_vendorq_lock(
    answers_payload: Dict[str, Any],
    evidence_index: Dict[str, Any],
    out_path: Path,
) -> Dict[str, Any]:
    validate_vendorq_schema("vendorq.answer.v1.schema.json", answers_payload)

    answers_hash = stable_answers_hash(list(answers_payload.get("answers", [])))
    questions_hash = str(answers_payload.get("questions_hash", ""))
    if not questions_hash:
        raise VendorQInputError("answers_payload_missing_questions_hash")

    pack_digests = [
        {
            "pack_id": p["pack_id"],
            "digest": p["digest"],
            "path": p["path"],
        }
        for p in evidence_index.get("packs", [])
    ]
    pack_digests.sort(key=lambda x: x["pack_id"])
    if not pack_digests:
        raise VendorQInputError("cannot_write_lock_without_pack_digests")

    lock_payload: Dict[str, Any] = {
        "lock_version": "1.0",
        "questions_hash": questions_hash,
        "answers_hash": answers_hash,
        "policy_profile": str(answers_payload.get("policy_profile", "")),
        "policy_fingerprint": str(answers_payload.get("policy_fingerprint", "")),
        "pack_digests": pack_digests,
        "schema_versions": {
            "question": SCHEMA_VERSION_QUESTION,
            "answer": SCHEMA_VERSION_ANSWER,
            "evidence_ref": SCHEMA_VERSION_EVIDENCE_REF,
            "verify_report": SCHEMA_VERSION_VERIFY_REPORT,
        },
        "created_at": now_utc_iso(),
        "created_by_assay_version": assay_version,
    }

    validate_vendorq_schema("vendorq.lock.v1.schema.json", lock_payload)
    write_json(out_path, lock_payload)
    return lock_payload


def load_vendorq_lock(path: Path) -> Dict[str, Any]:
    data = load_json(path)
    validate_vendorq_schema("vendorq.lock.v1.schema.json", data)
    return data


def lock_fingerprint(lock_payload: Dict[str, Any]) -> str:
    return canonical_sha256(lock_payload)
