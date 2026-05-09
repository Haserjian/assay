"""Assay Immunity Packs.

Assay Immunity Packs convert honest failures and near misses into portable,
offline-verifiable caution artifacts. The v0 contract is intentionally narrow:
classification is deterministic, IDs are content-addressed, and derived markers
can only reduce authority or add verification friction.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from jsonschema import Draft202012Validator

from assay.derived.hashing import canonical_hash, sha256_file, stable_id
from assay.manifest_schema import parse_rfc3339_datetime

IMMUNITY_SCHEMA_VERSION = "0.1"
INOCULATION_PACK_ARTIFACT_TYPE = "assay.inoculation_pack"
EPIGENETIC_MARKER_ARTIFACT_TYPE = "assay.epigenetic_marker"
GUARDIAN_CAUTION_SIGNAL_TYPE = "assay.guardian_caution_signal"

FAILURE_CLASSES = frozenset(
    {
        "dignity_boundary_near_miss",
        "memory_poisoning_risk",
        "receipt_lineage_conflict",
        "provider_disagreement",
        "unsafe_tool_call_attempt",
        "evidence_gap",
        "policy_conflict",
        "overconfidence_trap",
        "stale_truth_detected",
    }
)

MARKER_TYPES = FAILURE_CLASSES

GUARDIAN_ACTIONS = frozenset(
    {
        "require_review",
        "require_stronger_proof",
        "reduce_blast_radius",
        "block",
        "defer",
        "route_to_safe_provider",
        "emit_honest_failure",
        "add_regression_test",
    }
)

AUTHORITY_INCREASING_ACTIONS = frozenset(
    {
        "grant_tool_permission",
        "grant_permission",
        "raise_trust",
        "bypass_policy",
        "skip_verification",
        "suppress_failure_reporting",
        "authorize_stronger_execution",
        "increase_authority",
    }
)

AUTHORITY_GRANT_FIELDS = frozenset(
    {
        "grants",
        "grant_permissions",
        "granted_permissions",
        "new_permissions",
        "tool_permissions",
        "trust_delta",
        "policy_bypass",
        "verification_bypass",
    }
)

SEVERITIES = frozenset({"low", "medium", "high", "critical"})
DEFAULT_REVIEW_AFTER = "90d"
DEFAULT_ROLLBACK_POINTER = "policy:manual-review"

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_IMMUNITY_VALIDATORS: dict[str, Draft202012Validator] = {}

_REQUIRED_NORMALIZED_FIELDS = (
    "source_failure_id",
    "trigger_shape",
    "minimal_replay_case",
)


class ImmunityValidationError(ValueError):
    """Raised when an immunity pack or marker violates the v0 contract."""


@dataclass(frozen=True)
class ImmunityVerificationResult:
    artifact_type: str
    artifact_id: Optional[str]
    valid: bool
    schema_valid: bool
    identity_valid: bool
    source_bound: bool
    stale: bool
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ImmunitySignalResult:
    signal: dict[str, Any]
    pack_verification: ImmunityVerificationResult
    marker_verification: ImmunityVerificationResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "pack_verification": self.pack_verification.to_dict(),
            "marker_verification": self.marker_verification.to_dict(),
        }


@dataclass(frozen=True)
class EpigeneticMarker:
    marker_id: str
    marker_type: str
    source_pack_id: str
    trigger_shape: str
    recommended_guardian_action: str
    authority_delta: int
    confidence: float
    expires_after: Optional[str]
    expires_at: Optional[str]
    rollback_pointer: str
    rationale: str
    evidence_hash: str
    schema_version: str = IMMUNITY_SCHEMA_VERSION
    artifact_type: str = EPIGENETIC_MARKER_ARTIFACT_TYPE

    def __post_init__(self) -> None:
        validate_marker_safety(self)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InoculationPack:
    pack_id: str
    created_at: str
    source_failure_id: str
    source_proof_pack_id: Optional[str]
    failure_class: str
    severity: str
    trigger_shape: str
    dignity_floor_context: Optional[dict[str, Any]]
    delta_c_snapshot: Optional[Any]
    omega_h_snapshot: Optional[Any]
    guardian_decision: Optional[Any]
    minimal_replay_case: dict[str, Any]
    recommended_markers: list[dict[str, Any]]
    regression_tests: list[dict[str, Any]]
    evidence_hashes: dict[str, str]
    signing_verification_metadata: dict[str, Any]
    review_after: Optional[str]
    expires_at: Optional[str]
    rollback_pointer: str
    schema_version: str = IMMUNITY_SCHEMA_VERSION
    artifact_type: str = INOCULATION_PACK_ARTIFACT_TYPE

    def __post_init__(self) -> None:
        validate_inoculation_pack(self)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_failure_artifact(path: Path) -> dict[str, Any]:
    """Load a failure artifact JSON file or normalize a proof-pack directory."""
    if path.is_dir():
        return _load_proof_pack_directory(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ImmunityValidationError(f"invalid JSON artifact: {exc}") from exc
    if not isinstance(payload, dict):
        raise ImmunityValidationError("input artifact must be a JSON object")
    return payload


def load_immunity_artifact(path: Path) -> dict[str, Any]:
    """Load a JSON immunity artifact from disk."""
    if path.is_dir():
        raise ImmunityValidationError(
            "immunity verify expects a JSON file, not a directory"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ImmunityValidationError(f"invalid JSON artifact: {exc}") from exc
    if not isinstance(payload, dict):
        raise ImmunityValidationError("input artifact must be a JSON object")
    return payload


def derive_inoculation_pack(input_artifact: Mapping[str, Any]) -> InoculationPack:
    """Derive a deterministic InoculationPack from a failure/proof-pack artifact."""
    artifact = normalize_failure_artifact(input_artifact)
    _require_fields(artifact, _REQUIRED_NORMALIZED_FIELDS)

    failure_class = classify_failure(artifact)
    severity = _severity_for(artifact, failure_class)
    trigger_shape = str(artifact["trigger_shape"])
    evidence_hashes = _evidence_hashes_for(artifact)
    source_failure_id = str(artifact["source_failure_id"])
    source_proof_pack_id = _optional_str(artifact.get("source_proof_pack_id"))
    review_after = _optional_str(artifact.get("review_after")) or DEFAULT_REVIEW_AFTER
    expires_at = _optional_str(artifact.get("expires_at"))
    rollback_pointer = (
        _optional_str(artifact.get("rollback_pointer")) or DEFAULT_ROLLBACK_POINTER
    )

    recommended_markers = [
        _recommended_marker_spec(
            failure_class=failure_class,
            trigger_shape=trigger_shape,
            confidence=_confidence_for(artifact),
            review_after=review_after,
            expires_at=expires_at,
            rollback_pointer=rollback_pointer,
            evidence_hash=_primary_evidence_hash(evidence_hashes),
        )
    ]
    regression_tests = _regression_tests_for(
        artifact,
        failure_class=failure_class,
        trigger_shape=trigger_shape,
    )

    pack_seed = {
        "schema_version": IMMUNITY_SCHEMA_VERSION,
        "source_failure_id": source_failure_id,
        "source_proof_pack_id": source_proof_pack_id,
        "failure_class": failure_class,
        "severity": severity,
        "trigger_shape": trigger_shape,
        "minimal_replay_case": artifact["minimal_replay_case"],
        "recommended_markers": recommended_markers,
        "regression_tests": regression_tests,
        "evidence_hashes": evidence_hashes,
        "review_after": review_after,
        "expires_at": expires_at,
        "rollback_pointer": rollback_pointer,
    }
    pack_id = stable_id("ipack", pack_seed)

    return InoculationPack(
        pack_id=pack_id,
        created_at=_created_at_for(artifact),
        source_failure_id=source_failure_id,
        source_proof_pack_id=source_proof_pack_id,
        failure_class=failure_class,
        severity=severity,
        trigger_shape=trigger_shape,
        dignity_floor_context=_optional_dict(artifact.get("dignity_floor_context")),
        delta_c_snapshot=artifact.get("delta_c_snapshot"),
        omega_h_snapshot=artifact.get("omega_h_snapshot"),
        guardian_decision=artifact.get("guardian_decision"),
        minimal_replay_case=dict(artifact["minimal_replay_case"]),
        recommended_markers=recommended_markers,
        regression_tests=regression_tests,
        evidence_hashes=evidence_hashes,
        signing_verification_metadata=_signing_metadata_for(artifact),
        review_after=review_after,
        expires_at=expires_at,
        rollback_pointer=rollback_pointer,
    )


def derive_epigenetic_markers(pack: InoculationPack) -> list[EpigeneticMarker]:
    """Derive safety-checked EpigeneticMarkers from an InoculationPack."""
    markers: list[EpigeneticMarker] = []
    for spec in pack.recommended_markers:
        marker_payload = {
            "schema_version": IMMUNITY_SCHEMA_VERSION,
            "source_pack_id": pack.pack_id,
            "marker_type": spec["marker_type"],
            "trigger_shape": pack.trigger_shape,
            "recommended_guardian_action": spec["recommended_guardian_action"],
            "authority_delta": int(spec["authority_delta"]),
            "confidence": float(spec["confidence"]),
            "expires_after": spec.get("expires_after"),
            "expires_at": spec.get("expires_at"),
            "rollback_pointer": spec["rollback_pointer"],
            "rationale": spec["rationale"],
            "evidence_hash": spec["evidence_hash"],
        }
        marker_id = stable_id("emarker", marker_payload)
        markers.append(EpigeneticMarker(marker_id=marker_id, **marker_payload))
    return markers


def verify_immunity_artifact(
    artifact: Mapping[str, Any],
    *,
    source_pack_dir: Optional[Path] = None,
) -> ImmunityVerificationResult:
    """Verify an immunity artifact offline using schema and runtime rules."""
    payload = dict(artifact)
    inferred_type = _infer_immunity_artifact_type(payload)
    raw_artifact_type = payload.get("artifact_type")
    artifact_type = (
        str(raw_artifact_type)
        if isinstance(raw_artifact_type, str) and raw_artifact_type
        else (inferred_type or "unknown")
    )
    artifact_id = _artifact_id_for(artifact_type, payload)

    errors: list[str] = []
    schema_errors = _schema_errors_for(artifact_type, payload)
    errors.extend(schema_errors)

    identity_errors = _identity_errors_for(artifact_type, payload)
    errors.extend(identity_errors)

    source_errors: list[str] = []
    if source_pack_dir is not None:
        source_errors = _source_binding_errors_for(artifact_type, payload, source_pack_dir)
        errors.extend(source_errors)

    stale = False
    if artifact_type == INOCULATION_PACK_ARTIFACT_TYPE:
        runtime_error = _validation_error(validate_inoculation_pack, payload)
        if runtime_error:
            errors.append(runtime_error)
        stale = _append_expiry_error(payload, errors)
    elif artifact_type == EPIGENETIC_MARKER_ARTIFACT_TYPE:
        runtime_error = _validation_error(validate_marker_safety, payload)
        if runtime_error:
            errors.append(runtime_error)
        stale = _append_expiry_error(payload, errors)
    else:
        errors.append(f"unsupported immunity artifact type: {artifact_type}")

    return ImmunityVerificationResult(
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        valid=not errors,
        schema_valid=not schema_errors,
        identity_valid=not identity_errors,
        source_bound=source_pack_dir is not None and not source_errors,
        stale=stale,
        errors=_dedupe(errors),
    )


def verify_immunity_artifact_file(
    path: Path,
    *,
    source_pack_dir: Optional[Path] = None,
) -> ImmunityVerificationResult:
    """Load and verify an immunity artifact from disk."""
    return verify_immunity_artifact(
        load_immunity_artifact(path),
        source_pack_dir=source_pack_dir,
    )


def build_guardian_caution_signal(
    pack_artifact: Mapping[str, Any],
    marker_artifact: Mapping[str, Any],
    *,
    source_pack_dir: Path,
) -> ImmunitySignalResult:
    """Build a source-bound caution-only signal for future Guardian/Receiptor use."""
    pack_payload = dict(pack_artifact)
    marker_payload = dict(marker_artifact)
    pack_result = verify_immunity_artifact(
        pack_payload,
        source_pack_dir=source_pack_dir,
    )
    marker_result = verify_immunity_artifact(marker_payload)
    if not pack_result.valid:
        raise ImmunityValidationError(
            "cannot build caution signal from invalid InoculationPack: "
            + "; ".join(pack_result.errors)
        )
    if not marker_result.valid:
        raise ImmunityValidationError(
            "cannot build caution signal from invalid EpigeneticMarker: "
            + "; ".join(marker_result.errors)
        )
    if pack_payload.get("artifact_type") != INOCULATION_PACK_ARTIFACT_TYPE:
        raise ImmunityValidationError("signal requires an InoculationPack artifact")
    if marker_payload.get("artifact_type") != EPIGENETIC_MARKER_ARTIFACT_TYPE:
        raise ImmunityValidationError("signal requires an EpigeneticMarker artifact")

    pack_id = pack_payload.get("pack_id")
    marker_source_pack_id = marker_payload.get("source_pack_id")
    if marker_source_pack_id != pack_id:
        raise ImmunityValidationError(
            "marker source_pack_id does not match InoculationPack pack_id: "
            f"expected {pack_id}, got {marker_source_pack_id}"
        )
    if marker_payload.get("trigger_shape") != pack_payload.get("trigger_shape"):
        raise ImmunityValidationError(
            "marker trigger_shape does not match InoculationPack trigger_shape"
        )

    signal_seed = {
        "signal_type": GUARDIAN_CAUTION_SIGNAL_TYPE,
        "schema_version": IMMUNITY_SCHEMA_VERSION,
        "source_proof_pack_id": pack_payload.get("source_proof_pack_id"),
        "inoculation_pack_id": pack_id,
        "marker_id": marker_payload.get("marker_id"),
        "marker_type": marker_payload.get("marker_type"),
        "trigger_shape": marker_payload.get("trigger_shape"),
        "recommended_action": marker_payload.get("recommended_guardian_action"),
        "authority_delta": marker_payload.get("authority_delta"),
        "confidence": marker_payload.get("confidence"),
        "rollback_pointer": marker_payload.get("rollback_pointer"),
        "expires_after": marker_payload.get("expires_after"),
        "expires_at": marker_payload.get("expires_at"),
        "evidence_hash": marker_payload.get("evidence_hash"),
    }
    signal = {
        "signal_id": stable_id("gsignal", signal_seed),
        **signal_seed,
        "may_increase_authority": False,
        "source_bound": pack_result.source_bound,
        "identity_valid": pack_result.identity_valid and marker_result.identity_valid,
        "intended_consumers": ["guardian", "receiptor"],
        "producer": "assay.immunity",
    }
    return ImmunitySignalResult(
        signal=signal,
        pack_verification=pack_result,
        marker_verification=marker_result,
    )


def validate_marker_safety(marker: EpigeneticMarker | Mapping[str, Any]) -> None:
    """Enforce the hard invariant: markers can only add caution, never authority."""
    payload = marker.to_dict() if isinstance(marker, EpigeneticMarker) else dict(marker)

    action = str(payload.get("recommended_guardian_action", ""))
    if action in AUTHORITY_INCREASING_ACTIONS:
        raise ImmunityValidationError(
            f"authority-increasing guardian action is forbidden: {action}"
        )
    if action not in GUARDIAN_ACTIONS:
        raise ImmunityValidationError(f"invalid guardian action: {action}")

    authority_delta = payload.get("authority_delta")
    if not isinstance(authority_delta, int) or isinstance(authority_delta, bool):
        raise ImmunityValidationError("authority_delta must be an integer")
    if authority_delta > 0:
        raise ImmunityValidationError("authority_delta must be <= 0")

    marker_type = str(payload.get("marker_type", ""))
    if marker_type not in MARKER_TYPES:
        raise ImmunityValidationError(f"invalid marker_type: {marker_type}")

    confidence = payload.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        raise ImmunityValidationError("confidence must be a number in [0, 1]")
    if confidence < 0 or confidence > 1:
        raise ImmunityValidationError("confidence must be in [0, 1]")

    for field_name in AUTHORITY_GRANT_FIELDS:
        if field_name in payload and payload[field_name]:
            raise ImmunityValidationError(
                f"authority-granting marker field is forbidden: {field_name}"
            )

    if not payload.get("rollback_pointer"):
        raise ImmunityValidationError("rollback_pointer is required")
    if not (payload.get("expires_after") or payload.get("expires_at")):
        raise ImmunityValidationError("expiration metadata is required")
    if not payload.get("evidence_hash"):
        raise ImmunityValidationError("evidence_hash is required")


def validate_inoculation_pack(pack: InoculationPack | Mapping[str, Any]) -> None:
    payload = pack.to_dict() if isinstance(pack, InoculationPack) else dict(pack)
    _require_fields(
        payload,
        (
            "pack_id",
            "schema_version",
            "source_failure_id",
            "failure_class",
            "severity",
            "trigger_shape",
            "minimal_replay_case",
            "recommended_markers",
            "regression_tests",
            "evidence_hashes",
            "rollback_pointer",
        ),
    )
    if payload["failure_class"] not in FAILURE_CLASSES:
        raise ImmunityValidationError(
            f"invalid failure_class: {payload['failure_class']}"
        )
    if payload["severity"] not in SEVERITIES:
        raise ImmunityValidationError(f"invalid severity: {payload['severity']}")
    if not isinstance(payload["minimal_replay_case"], dict):
        raise ImmunityValidationError("minimal_replay_case must be an object")
    if (
        not isinstance(payload["evidence_hashes"], dict)
        or not payload["evidence_hashes"]
    ):
        raise ImmunityValidationError("evidence_hashes must be a non-empty object")
    if not (payload.get("review_after") or payload.get("expires_at")):
        raise ImmunityValidationError("review_after or expires_at is required")
    for spec in payload["recommended_markers"]:
        validate_marker_safety(spec)


def normalize_failure_artifact(input_artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize accepted failure-artifact field aliases into the v0 shape."""
    artifact = dict(input_artifact)
    if "source_failure_id" not in artifact:
        for key in ("failure_id", "honest_failure_id", "receipt_id", "incident_id"):
            if artifact.get(key):
                artifact["source_failure_id"] = str(artifact[key])
                break
    if "source_proof_pack_id" not in artifact:
        for key in ("proof_pack_id", "pack_id", "source_pack_id"):
            if artifact.get(key):
                artifact["source_proof_pack_id"] = str(artifact[key])
                break
    if "trigger_shape" not in artifact:
        for key in ("trigger", "triggering_claim", "requested_action", "action"):
            if artifact.get(key):
                artifact["trigger_shape"] = str(artifact[key])
                break
    return artifact


def classify_failure(input_artifact: Mapping[str, Any]) -> str:
    """Classify a failure with stable rules and no LLM dependency."""
    explicit = input_artifact.get("failure_class") or input_artifact.get("marker_type")
    if explicit and str(explicit) in FAILURE_CLASSES:
        return str(explicit)

    haystack = _search_text(input_artifact)
    if any(
        token in haystack
        for token in ("dignity", "clause0", "clause-0", "coherence_by_dignity_debt")
    ):
        return "dignity_boundary_near_miss"
    if any(
        token in haystack
        for token in ("memory poisoning", "poisoned memory", "memory_poisoning")
    ):
        return "memory_poisoning_risk"
    if any(
        token in haystack
        for token in (
            "receipt_lineage_conflict",
            "lineage conflict",
            "hash conflict",
            "chain broken",
            "e_chain_broken",
            "e_manifest_tamper",
            "e_pack_omission_detected",
            "tamper",
        )
    ):
        return "receipt_lineage_conflict"
    if any(
        token in haystack
        for token in (
            "unsafe tool",
            "tool call",
            "tool_call",
            "rm -rf",
            "exfiltrate",
            "delete production",
            "send_email",
            "permission escalation",
        )
    ):
        return "unsafe_tool_call_attempt"
    if any(
        token in haystack
        for token in (
            "provider disagreement",
            "provider_disagreement",
            "conflicting provider",
        )
    ):
        return "provider_disagreement"
    if any(
        token in haystack
        for token in (
            "stale",
            "outdated",
            "known fact",
            "e_pack_stale",
            "e_timestamp_invalid",
        )
    ):
        return "stale_truth_detected"
    if any(
        token in haystack
        for token in (
            "policy conflict",
            "policy_conflict",
            "e_policy_missing",
            "policy violation",
        )
    ):
        return "policy_conflict"
    if any(
        token in haystack
        for token in ("overconfidence", "unsupported confidence", "calibration failure")
    ):
        return "overconfidence_trap"
    return "evidence_gap"


def write_immunity_artifacts(
    pack: InoculationPack,
    markers: list[EpigeneticMarker],
    out_dir: Path,
) -> dict[str, Path]:
    """Write pack and marker JSON to the deterministic immunity artifact layout."""
    markers_dir = out_dir / "markers"
    markers_dir.mkdir(parents=True, exist_ok=True)
    pack_path = out_dir / f"inoculation_pack_{pack.pack_id}.json"
    pack_path.write_text(
        json.dumps(pack.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    marker_paths: dict[str, Path] = {}
    for marker in markers:
        marker_path = markers_dir / f"{marker.marker_id}.json"
        marker_path.write_text(
            json.dumps(marker.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        marker_paths[marker.marker_id] = marker_path
    return {"pack": pack_path, **marker_paths}


def _load_proof_pack_directory(path: Path) -> dict[str, Any]:
    manifest_path = path / "pack_manifest.json"
    if not manifest_path.exists():
        raise ImmunityValidationError(
            f"proof-pack directory is missing {manifest_path.name}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ImmunityValidationError(f"invalid pack_manifest.json: {exc}") from exc

    verify_report_path = path / "verify_report.json"
    verify_report: Optional[dict[str, Any]] = None
    if verify_report_path.exists():
        try:
            loaded = json.loads(verify_report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ImmunityValidationError(f"invalid verify_report.json: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ImmunityValidationError("verify_report.json must be a JSON object")
        verify_report = loaded

    pack_id = str(
        manifest.get("pack_id") or manifest.get("id") or stable_id("pack", manifest)
    )
    evidence_hashes: dict[str, str] = {"pack_manifest": sha256_file(manifest_path)}
    for file_entry in manifest.get("files", []):
        if not isinstance(file_entry, dict):
            continue
        file_path = file_entry.get("path")
        sha256 = file_entry.get("sha256")
        if file_path and sha256:
            evidence_hashes[str(file_path)] = f"sha256:{sha256}"
    if verify_report_path.exists():
        evidence_hashes["verify_report"] = sha256_file(verify_report_path)

    signature = manifest.get("signature")
    signature_alg = manifest.get("signature_alg")
    if not signature_alg and isinstance(signature, Mapping):
        signature_alg = signature.get("alg")

    return {
        "source_failure_id": stable_id(
            "failure",
            {
                "source_proof_pack_id": pack_id,
                "verify_report": verify_report or {},
                "manifest_hash": evidence_hashes["pack_manifest"],
            },
        ),
        "source_proof_pack_id": pack_id,
        "trigger_shape": "proof_pack_verification",
        "failure_class": _class_from_verify_report(verify_report),
        "severity": "high" if verify_report else "medium",
        "minimal_replay_case": {
            "kind": "proof_pack_directory",
            "source_proof_pack_id": pack_id,
            "command": "assay verify-pack <proof-pack-dir>",
        },
        "evidence_hashes": evidence_hashes,
        "signing_verification_metadata": {
            "source": "proof_pack_manifest",
            "signature_alg": signature_alg,
            "signer_id": manifest.get("signer_id")
            or manifest.get("attestation", {}).get("signer_id"),
        },
        "created_at": manifest.get("created_at")
        or manifest.get("timestamp")
        or "1970-01-01T00:00:00Z",
        "review_after": DEFAULT_REVIEW_AFTER,
        "rollback_pointer": DEFAULT_ROLLBACK_POINTER,
        "verify_report": verify_report,
    }


def _class_from_verify_report(verify_report: Optional[Mapping[str, Any]]) -> str:
    if not verify_report:
        return "evidence_gap"
    return classify_failure({"verify_report": verify_report})


def _get_immunity_validator(artifact_type: str) -> Optional[Draft202012Validator]:
    if artifact_type in _IMMUNITY_VALIDATORS:
        return _IMMUNITY_VALIDATORS[artifact_type]

    schema_name = {
        INOCULATION_PACK_ARTIFACT_TYPE: "inoculation_pack.v0.1.schema.json",
        EPIGENETIC_MARKER_ARTIFACT_TYPE: "epigenetic_marker.v0.1.schema.json",
    }.get(artifact_type)
    if schema_name is None:
        return None

    schema_path = _SCHEMA_DIR / schema_name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    _IMMUNITY_VALIDATORS[artifact_type] = validator
    return validator


def _schema_errors_for(artifact_type: str, payload: Mapping[str, Any]) -> list[str]:
    validator = _get_immunity_validator(artifact_type)
    if validator is None:
        return []

    errors = []
    for error in sorted(
        validator.iter_errors(payload), key=lambda item: list(item.path)
    ):
        path = ".".join(str(part) for part in error.absolute_path) or "(root)"
        errors.append(f"{path}: {error.message}")
    return errors


def _infer_immunity_artifact_type(payload: Mapping[str, Any]) -> Optional[str]:
    artifact_type = payload.get("artifact_type")
    if artifact_type in {
        INOCULATION_PACK_ARTIFACT_TYPE,
        EPIGENETIC_MARKER_ARTIFACT_TYPE,
    }:
        return str(artifact_type)
    if payload.get("marker_id") or payload.get("source_pack_id"):
        return EPIGENETIC_MARKER_ARTIFACT_TYPE
    if payload.get("pack_id") or payload.get("recommended_markers"):
        return INOCULATION_PACK_ARTIFACT_TYPE
    return None


def _artifact_id_for(artifact_type: str, payload: Mapping[str, Any]) -> Optional[str]:
    if artifact_type == INOCULATION_PACK_ARTIFACT_TYPE:
        return _optional_str(payload.get("pack_id"))
    if artifact_type == EPIGENETIC_MARKER_ARTIFACT_TYPE:
        return _optional_str(payload.get("marker_id"))
    return None


def _validation_error(
    validator: Any,
    payload: Mapping[str, Any],
) -> Optional[str]:
    try:
        validator(payload)
    except ImmunityValidationError as exc:
        return str(exc)
    return None


def _identity_errors_for(artifact_type: str, payload: Mapping[str, Any]) -> list[str]:
    if artifact_type == INOCULATION_PACK_ARTIFACT_TYPE:
        required = (
            "source_failure_id",
            "source_proof_pack_id",
            "failure_class",
            "severity",
            "trigger_shape",
            "minimal_replay_case",
            "recommended_markers",
            "regression_tests",
            "evidence_hashes",
            "review_after",
            "expires_at",
            "rollback_pointer",
        )
        if any(field_name not in payload for field_name in required):
            return []
        expected = stable_id(
            "ipack",
            {
                "schema_version": IMMUNITY_SCHEMA_VERSION,
                "source_failure_id": payload.get("source_failure_id"),
                "source_proof_pack_id": payload.get("source_proof_pack_id"),
                "failure_class": payload.get("failure_class"),
                "severity": payload.get("severity"),
                "trigger_shape": payload.get("trigger_shape"),
                "minimal_replay_case": payload.get("minimal_replay_case"),
                "recommended_markers": payload.get("recommended_markers"),
                "regression_tests": payload.get("regression_tests"),
                "evidence_hashes": payload.get("evidence_hashes"),
                "review_after": payload.get("review_after"),
                "expires_at": payload.get("expires_at"),
                "rollback_pointer": payload.get("rollback_pointer"),
            },
        )
        actual = payload.get("pack_id")
        if actual != expected:
            return [f"pack_id mismatch: expected {expected}, got {actual}"]
        return []

    if artifact_type == EPIGENETIC_MARKER_ARTIFACT_TYPE:
        required = (
            "schema_version",
            "source_pack_id",
            "marker_type",
            "trigger_shape",
            "recommended_guardian_action",
            "authority_delta",
            "confidence",
            "expires_after",
            "expires_at",
            "rollback_pointer",
            "rationale",
            "evidence_hash",
        )
        if any(field_name not in payload for field_name in required):
            return []
        expected = stable_id(
            "emarker",
            {
                "schema_version": payload.get("schema_version"),
                "source_pack_id": payload.get("source_pack_id"),
                "marker_type": payload.get("marker_type"),
                "trigger_shape": payload.get("trigger_shape"),
                "recommended_guardian_action": payload.get(
                    "recommended_guardian_action"
                ),
                "authority_delta": payload.get("authority_delta"),
                "confidence": payload.get("confidence"),
                "expires_after": payload.get("expires_after"),
                "expires_at": payload.get("expires_at"),
                "rollback_pointer": payload.get("rollback_pointer"),
                "rationale": payload.get("rationale"),
                "evidence_hash": payload.get("evidence_hash"),
            },
        )
        actual = payload.get("marker_id")
        if actual != expected:
            return [f"marker_id mismatch: expected {expected}, got {actual}"]
    return []


def _source_binding_errors_for(
    artifact_type: str,
    payload: Mapping[str, Any],
    source_pack_dir: Path,
) -> list[str]:
    if artifact_type != INOCULATION_PACK_ARTIFACT_TYPE:
        return [
            "source binding requires an InoculationPack artifact; "
            "EpigeneticMarkers only point to immunity packs"
        ]

    source_pack_dir = Path(source_pack_dir)
    try:
        source_artifact = load_failure_artifact(source_pack_dir)
    except ImmunityValidationError as exc:
        return [f"source proof pack invalid: {exc}"]

    errors: list[str] = []
    source_proof_pack_id = source_artifact.get("source_proof_pack_id")
    if payload.get("source_proof_pack_id") != source_proof_pack_id:
        errors.append(
            "source_proof_pack_id mismatch: "
            f"expected {source_proof_pack_id}, got {payload.get('source_proof_pack_id')}"
        )

    source_failure_id = source_artifact.get("source_failure_id")
    if payload.get("source_failure_id") != source_failure_id:
        errors.append(
            "source_failure_id mismatch: "
            f"expected {source_failure_id}, got {payload.get('source_failure_id')}"
        )

    actual_hashes = source_artifact.get("evidence_hashes")
    claimed_hashes = payload.get("evidence_hashes")
    if not isinstance(actual_hashes, Mapping) or not isinstance(claimed_hashes, Mapping):
        errors.append("source binding requires evidence_hashes objects")
        return errors

    for key, actual_hash in sorted(actual_hashes.items()):
        claimed_hash = claimed_hashes.get(key)
        if claimed_hash is None:
            errors.append(f"missing source evidence hash: {key}")
        elif claimed_hash != actual_hash:
            errors.append(
                f"source evidence hash mismatch for {key}: "
                f"expected {actual_hash}, got {claimed_hash}"
            )

    try:
        expected_pack = derive_inoculation_pack(source_artifact)
    except ImmunityValidationError as exc:
        errors.append(f"source proof pack cannot derive immunity pack: {exc}")
        return errors

    if payload.get("pack_id") != expected_pack.pack_id:
        errors.append(
            f"source-derived pack_id mismatch: expected {expected_pack.pack_id}, "
            f"got {payload.get('pack_id')}"
        )

    return errors


def _append_expiry_error(payload: Mapping[str, Any], errors: list[str]) -> bool:
    expires_at = payload.get("expires_at")
    if not expires_at:
        return False
    try:
        expires_at_dt = parse_rfc3339_datetime(expires_at)
    except ValueError as exc:
        errors.append(f"invalid expires_at: {exc}")
        return False
    if expires_at_dt.astimezone(timezone.utc) < datetime.now(timezone.utc):
        errors.append("artifact is stale: expires_at is in the past")
        return True
    return False


def _dedupe(errors: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for error in errors:
        if error not in seen:
            seen.add(error)
            ordered.append(error)
    return ordered


def _require_fields(payload: Mapping[str, Any], fields: tuple[str, ...]) -> None:
    missing = [field_name for field_name in fields if not payload.get(field_name)]
    if missing:
        raise ImmunityValidationError(
            "missing required field(s): " + ", ".join(sorted(missing))
        )


def _evidence_hashes_for(artifact: Mapping[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    supplied = artifact.get("evidence_hashes")
    if isinstance(supplied, Mapping):
        hashes.update({str(key): str(value) for key, value in supplied.items()})
    if "input_artifact" not in hashes:
        hashes["input_artifact"] = canonical_hash(dict(artifact))
    if "minimal_replay_case" not in hashes:
        hashes["minimal_replay_case"] = canonical_hash(artifact["minimal_replay_case"])
    return dict(sorted(hashes.items()))


def _primary_evidence_hash(evidence_hashes: Mapping[str, str]) -> str:
    if "input_artifact" in evidence_hashes:
        return evidence_hashes["input_artifact"]
    first_key = sorted(evidence_hashes)[0]
    return evidence_hashes[first_key]


def _recommended_marker_spec(
    *,
    failure_class: str,
    trigger_shape: str,
    confidence: float,
    review_after: Optional[str],
    expires_at: Optional[str],
    rollback_pointer: str,
    evidence_hash: str,
) -> dict[str, Any]:
    action = _guardian_action_for(failure_class)
    return {
        "marker_type": failure_class,
        "trigger_shape": trigger_shape,
        "recommended_guardian_action": action,
        "authority_delta": _authority_delta_for(action),
        "confidence": confidence,
        "expires_after": None if expires_at else (review_after or DEFAULT_REVIEW_AFTER),
        "expires_at": expires_at,
        "rollback_pointer": rollback_pointer,
        "rationale": _rationale_for(failure_class, action),
        "evidence_hash": evidence_hash,
    }


def _guardian_action_for(failure_class: str) -> str:
    return {
        "dignity_boundary_near_miss": "require_review",
        "memory_poisoning_risk": "require_stronger_proof",
        "receipt_lineage_conflict": "require_stronger_proof",
        "provider_disagreement": "route_to_safe_provider",
        "unsafe_tool_call_attempt": "block",
        "evidence_gap": "require_stronger_proof",
        "policy_conflict": "require_review",
        "overconfidence_trap": "reduce_blast_radius",
        "stale_truth_detected": "require_stronger_proof",
    }[failure_class]


def _authority_delta_for(action: str) -> int:
    if action == "block":
        return -3
    if action in {"reduce_blast_radius", "route_to_safe_provider"}:
        return -2
    if action in {
        "require_review",
        "require_stronger_proof",
        "defer",
        "emit_honest_failure",
    }:
        return -1
    return 0


def _rationale_for(failure_class: str, action: str) -> str:
    return (
        f"Prior failure classified as {failure_class}; future matching episodes "
        f"should {action.replace('_', ' ')} before continuing."
    )


def _regression_tests_for(
    artifact: Mapping[str, Any],
    *,
    failure_class: str,
    trigger_shape: str,
) -> list[dict[str, Any]]:
    supplied = artifact.get("regression_tests")
    if isinstance(supplied, list) and supplied:
        return [
            dict(item) if isinstance(item, Mapping) else {"case": item}
            for item in supplied
        ]
    test_seed = {
        "failure_class": failure_class,
        "trigger_shape": trigger_shape,
        "minimal_replay_case": artifact["minimal_replay_case"],
    }
    return [
        {
            "test_id": stable_id("regression", test_seed),
            "failure_class": failure_class,
            "trigger_shape": trigger_shape,
            "minimal_replay_case": artifact["minimal_replay_case"],
            "expected_guardian_action": _guardian_action_for(failure_class),
        }
    ]


def _signing_metadata_for(artifact: Mapping[str, Any]) -> dict[str, Any]:
    supplied = artifact.get("signing_verification_metadata")
    if isinstance(supplied, Mapping):
        return dict(supplied)
    return {
        "source": "input_artifact",
        "canonicalization": "jcs-rfc8785",
        "hash_algorithm": "sha256",
    }


def _severity_for(artifact: Mapping[str, Any], failure_class: str) -> str:
    supplied = artifact.get("severity")
    if isinstance(supplied, str) and supplied.lower() in SEVERITIES:
        return supplied.lower()
    if failure_class in {
        "unsafe_tool_call_attempt",
        "receipt_lineage_conflict",
        "dignity_boundary_near_miss",
    }:
        return "high"
    if failure_class in {
        "policy_conflict",
        "provider_disagreement",
        "stale_truth_detected",
    }:
        return "medium"
    return "medium"


def _confidence_for(artifact: Mapping[str, Any]) -> float:
    supplied = artifact.get("confidence")
    if isinstance(supplied, (int, float)) and not isinstance(supplied, bool):
        return max(0.0, min(1.0, float(supplied)))
    return 0.8


def _created_at_for(artifact: Mapping[str, Any]) -> str:
    for key in ("created_at", "timestamp", "observed_at"):
        if artifact.get(key):
            return str(artifact[key])
    return "1970-01-01T00:00:00Z"


def _search_text(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str).lower()
    except (TypeError, ValueError):
        return str(value).lower()


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _optional_dict(value: Any) -> Optional[dict[str, Any]]:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ImmunityValidationError("dignity_floor_context must be an object")
    return dict(value)


__all__ = [
    "AUTHORITY_INCREASING_ACTIONS",
    "EPIGENETIC_MARKER_ARTIFACT_TYPE",
    "FAILURE_CLASSES",
    "GUARDIAN_CAUTION_SIGNAL_TYPE",
    "GUARDIAN_ACTIONS",
    "IMMUNITY_SCHEMA_VERSION",
    "INOCULATION_PACK_ARTIFACT_TYPE",
    "EpigeneticMarker",
    "ImmunityValidationError",
    "ImmunitySignalResult",
    "ImmunityVerificationResult",
    "InoculationPack",
    "build_guardian_caution_signal",
    "classify_failure",
    "derive_epigenetic_markers",
    "derive_inoculation_pack",
    "load_failure_artifact",
    "load_immunity_artifact",
    "validate_inoculation_pack",
    "validate_marker_safety",
    "verify_immunity_artifact",
    "verify_immunity_artifact_file",
    "write_immunity_artifacts",
]
