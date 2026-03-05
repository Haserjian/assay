"""Shared models, schemas, and policy helpers for VendorQ."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import referencing
from jsonschema import Draft202012Validator

from assay._receipts.canonicalize import to_jcs_bytes

SCHEMA_VERSION_QUESTION = "vendorq.question.v1"
SCHEMA_VERSION_ANSWER = "vendorq.answer.v1"
SCHEMA_VERSION_EVIDENCE_REF = "vendorq.evidence_ref.v1"
SCHEMA_VERSION_LOCK = "vendorq.lock.v1"
SCHEMA_VERSION_VERIFY_REPORT = "vendorq.verify_report.v1"

STATUS_VALUES = {"ANSWERED", "PARTIAL", "INSUFFICIENT_EVIDENCE", "OUT_OF_SCOPE"}
ANSWER_MODE_VALUES = {"EVIDENCE_ONLY", "EVIDENCE_PLUS_EXPLANATION", "POLICY_ONLY"}
CLAIM_TYPE_VALUES = {
    "CERTIFICATION",
    "PROCESS",
    "TECH_CONTROL",
    "INCIDENT",
    "METRIC",
    "COMMITMENT",
    "LEGAL",
}
REVIEW_OWNER_VALUES = {"LEGAL", "SECURITY", "PRIVACY", "ENG", "NONE"}

VENDORQ_COMPILE_PROMPT = (
    "You are VendorQ-Compiler. Produce only schema-valid JSON.\n"
    "If evidence is insufficient, return status=INSUFFICIENT_EVIDENCE.\n"
    "Never infer certifications, incidents, metrics, or commitments.\n"
    "Every factual claim requires at least one evidence_ref.\n"
    "For yes/no questions, set answer_bool explicitly.\n"
    "If answer_bool=true without direct support, output PARTIAL or INSUFFICIENT_EVIDENCE.\n"
    "Do not output hidden reasoning."
)

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_VENDORQ_SCHEMA_FILES = (
    "vendorq.evidence_ref.v1.schema.json",
    "vendorq.question.v1.schema.json",
    "vendorq.answer.v1.schema.json",
    "vendorq.lock.v1.schema.json",
    "vendorq.verify_report.v1.schema.json",
)

_VALIDATORS: Dict[str, Draft202012Validator] = {}


class VendorQError(Exception):
    """Base VendorQ exception."""


class VendorQInputError(VendorQError):
    """Bad input file/path/schema."""


class VendorQVerificationError(VendorQError):
    """Verification failure with rule code."""


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(to_jcs_bytes(obj)).hexdigest()


def parse_iso8601(ts: str) -> Optional[datetime]:
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if t.tzinfo is None:
            return t.replace(tzinfo=timezone.utc)
        return t
    except Exception:
        return None


def _load_validators() -> Dict[str, Draft202012Validator]:
    if _VALIDATORS:
        return _VALIDATORS

    schemas: Dict[str, Dict[str, Any]] = {}
    for name in _VENDORQ_SCHEMA_FILES:
        path = _SCHEMA_DIR / name
        if not path.exists():
            raise FileNotFoundError(f"VendorQ schema missing: {path}")
        schemas[name] = json.loads(path.read_text())

    registry = referencing.Registry().with_resources([
        (schema["$id"], referencing.Resource.from_contents(schema))
        for schema in schemas.values()
    ])

    for name, schema in schemas.items():
        _VALIDATORS[name] = Draft202012Validator(schema, registry=registry)

    return _VALIDATORS


def validate_payload(schema_file: str, payload: Dict[str, Any]) -> List[str]:
    validators = _load_validators()
    if schema_file not in validators:
        raise ValueError(f"Unknown VendorQ schema: {schema_file}")

    errors: List[str] = []
    for err in sorted(validators[schema_file].iter_errors(payload), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{path}: {err.message}")
    return errors


def load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise VendorQInputError(f"file_not_found: {path}")
    except json.JSONDecodeError as e:
        raise VendorQInputError(f"invalid_json: {path}: {e.msg}")


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def is_yes_no_question(text: str) -> bool:
    t = text.strip().lower()
    return t.startswith(("do ", "does ", "is ", "are ", "can ", "will ", "have ", "has "))


def infer_claim_type(question_text: str) -> str:
    q = question_text.lower()
    if any(k in q for k in ("soc 2", "iso", "certif", "attest")):
        return "CERTIFICATION"
    if any(k in q for k in ("incident", "breach", "outage", "security event")):
        return "INCIDENT"
    if any(k in q for k in ("metric", "count", "number", "latency", "token", "cost")):
        return "METRIC"
    if any(k in q for k in ("commit", "roadmap", "guarantee", "promise")):
        return "COMMITMENT"
    if any(k in q for k in ("gdpr", "dpa", "legal", "contract", "privacy law")):
        return "LEGAL"
    if any(k in q for k in ("process", "policy", "procedure", "review")):
        return "PROCESS"
    return "TECH_CONTROL"


def policy_profile(name: str) -> Dict[str, Any]:
    n = name.strip().lower()
    if n not in {"conservative", "balanced"}:
        raise VendorQInputError(f"unknown_policy_profile: {name}")

    allow_commitments = n == "balanced"
    allowed_claim_types = sorted(CLAIM_TYPE_VALUES if allow_commitments else (CLAIM_TYPE_VALUES - {"COMMITMENT"}))

    profile = {
        "name": n,
        "freshness_window_days": 365,
        "allow_commitments": allow_commitments,
        "allowed_claim_types": allowed_claim_types,
        "prohibited_commitment_terms": [
            "guarantee",
            "always",
            "never",
            "will ensure",
        ],
    }
    profile["fingerprint"] = canonical_sha256(profile)
    return profile


def factual_claim_required(claim_type: str, answer_mode: str) -> bool:
    # Legal policy-only answers can be declarative guidance with no hard factual claim.
    return not (claim_type == "LEGAL" and answer_mode == "POLICY_ONLY")


def validate_vendorq_schema(schema_file: str, payload: Dict[str, Any]) -> None:
    errors = validate_payload(schema_file, payload)
    if errors:
        raise VendorQInputError("schema_validation_failed: " + " | ".join(errors[:10]))


def stable_answers_hash(answers: List[Dict[str, Any]]) -> str:
    ordered = sorted(answers, key=lambda a: (str(a.get("question_id", "")), str(a.get("answer_id", ""))))
    return canonical_sha256(ordered)


def resolve_pointer(obj: Any, pointer: str) -> Tuple[bool, Any]:
    if not pointer:
        return True, obj
    cur = obj
    if pointer.startswith("/"):
        parts = [p for p in pointer.split("/") if p != ""]
    else:
        parts = [p for p in pointer.split(".") if p != ""]

    for raw in parts:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            if not token.isdigit():
                return False, None
            i = int(token)
            if i < 0 or i >= len(cur):
                return False, None
            cur = cur[i]
        elif isinstance(cur, dict):
            if token not in cur:
                return False, None
            cur = cur[token]
        else:
            return False, None
    return True, cur
