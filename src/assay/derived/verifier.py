"""Verification for receipted derived context."""

from __future__ import annotations

import json
from json import JSONDecodeError
from typing import Any, Dict, List, Optional

from assay.derived.hashing import sha256_text
from assay.derived.models import (
    DERIVATION_LEVELS,
    RECEIPT_KINDS,
    RECEIPT_SCHEMA_VERSION,
    DerivationReceipt,
    DerivedArtifact,
    VerificationResult,
)
from assay.derived.receipts import receipt_id_for_payload
from assay.derived.store import DerivedStore
from assay.derived.transforms import DEFAULT_MAX_LINES, chunk_lines


REQUIRED_RECEIPT_FIELDS = (
    "receipt_id",
    "kind",
    "subject_id",
    "source_snapshot_ids",
    "input_artifact_ids",
    "transform_id",
    "output_hash",
    "derivation_verification_level",
    "status",
    "created_at",
    "metadata",
)


def verify_receipt(store: DerivedStore, receipt_id: str) -> VerificationResult:
    record = store.get_receipt_record(receipt_id)
    if record is None:
        return VerificationResult(
            receipt_id=receipt_id,
            subject_id="",
            ok=False,
            derivation_verification_level="DV0",
            status="missing",
            errors=("receipt not found",),
        )

    data, decode_errors = _decode_receipt_json(record["receipt_json"])
    if decode_errors:
        return _failed_record_result(receipt_id, record, decode_errors)

    structural_errors = _validate_receipt_record(record, data)
    receipt = _receipt_from_data(data)
    if receipt is None:
        return _failed_record_result(receipt_id, record, structural_errors)

    structural_errors.extend(_validate_lineage(store, receipt))
    if structural_errors:
        return VerificationResult(
            receipt_id=receipt_id,
            subject_id=receipt.subject_id,
            ok=False,
            derivation_verification_level="DV0",
            status="failed",
            errors=tuple(structural_errors),
            expected_output_hash=receipt.output_hash,
        )

    if receipt.kind == "derived.artifact.created":
        return _verify_created_artifact(store, receipt)

    if receipt.kind in {"derived.artifact.staled", "derived.artifact.tombstoned"}:
        return _verify_structural_receipt(store, receipt)

    return VerificationResult(
        receipt_id=receipt.receipt_id,
        subject_id=receipt.subject_id,
        ok=False,
        derivation_verification_level="DV0",
        status="failed",
        errors=(f"unknown receipt kind: {receipt.kind}",),
        expected_output_hash=receipt.output_hash,
    )


def _verify_created_artifact(
    store: DerivedStore, receipt: DerivationReceipt
) -> VerificationResult:
    errors: List[str] = []
    artifact = store.get_artifact(receipt.subject_id)
    if artifact is None:
        errors.append("subject artifact not found")
        return _result(receipt, errors)

    if artifact.receipt_id != receipt.receipt_id:
        errors.append("artifact receipt_id does not match receipt")
    if artifact.output_hash != receipt.output_hash:
        errors.append("artifact output_hash does not match receipt")
    if artifact.transform_id != receipt.transform_id:
        errors.append("artifact transform_id does not match receipt")
    if (
        artifact.source_snapshot_id is not None
        and artifact.source_snapshot_id not in receipt.source_snapshot_ids
    ):
        errors.append("artifact source snapshot not present in receipt")
    if tuple(artifact.input_artifact_ids) != tuple(receipt.input_artifact_ids):
        errors.append("artifact input_artifact_ids do not match receipt")
    _verify_claimed_transform(store, receipt, errors)

    if artifact.artifact_type != "source_chunk":
        return VerificationResult(
            receipt_id=receipt.receipt_id,
            subject_id=receipt.subject_id,
            ok=not errors,
            derivation_verification_level="DV1" if not errors else "DV0",
            status="verified" if not errors else "failed",
            errors=tuple(errors),
            expected_output_hash=artifact.output_hash,
            actual_output_hash=artifact.output_hash,
        )

    actual_output_hash = _recompute_artifact_output_hash(store, artifact, errors)
    expected_output_hash = artifact.output_hash
    if actual_output_hash and actual_output_hash != artifact.output_hash:
        errors.append("recomputed output hash does not match artifact")

    return VerificationResult(
        receipt_id=receipt.receipt_id,
        subject_id=receipt.subject_id,
        ok=not errors,
        derivation_verification_level="DV2" if not errors else "DV1",
        status="verified" if not errors else "failed",
        errors=tuple(errors),
        expected_output_hash=expected_output_hash,
        actual_output_hash=actual_output_hash,
    )


def _verify_structural_receipt(
    store: DerivedStore, receipt: DerivationReceipt
) -> VerificationResult:
    errors: List[str] = []
    artifact = store.get_artifact(receipt.subject_id)
    if artifact is None:
        errors.append("subject artifact not found")
    elif artifact.artifact_id != receipt.subject_id:
        errors.append("receipt subject does not match artifact")
    elif artifact.output_hash != receipt.output_hash:
        errors.append("artifact output_hash does not match receipt")
    _verify_claimed_transform(store, receipt, errors)
    return VerificationResult(
        receipt_id=receipt.receipt_id,
        subject_id=receipt.subject_id,
        ok=not errors,
        derivation_verification_level="DV1" if not errors else "DV0",
        status="verified" if not errors else "failed",
        errors=tuple(errors),
        expected_output_hash=receipt.output_hash,
        actual_output_hash=artifact.output_hash if artifact else None,
    )


def _recompute_artifact_output_hash(
    store: DerivedStore, artifact: DerivedArtifact, errors: List[str]
) -> Optional[str]:
    if artifact.artifact_type != "source_chunk":
        errors.append(
            f"unsupported artifact_type for recompute: {artifact.artifact_type}"
        )
        return None
    if not artifact.source_snapshot_id:
        errors.append("artifact has no source_snapshot_id")
        return None
    snapshot = store.get_snapshot(artifact.source_snapshot_id)
    if snapshot is None:
        errors.append("source snapshot not found")
        return None
    content_text = snapshot.metadata.get("content_text")
    if not isinstance(content_text, str):
        errors.append("source snapshot does not contain recomputable content_text")
        return None
    if sha256_text(content_text) != snapshot.content_hash:
        errors.append("source snapshot content_text hash does not match content_hash")
        return None

    transform = store.get_transform(artifact.transform_id)
    if transform is None:
        errors.append("transform not found")
        return None
    if transform.name != "line_chunker":
        errors.append(f"unsupported transform for recompute: {transform.name}")
        return None

    transform_config = artifact.metadata.get("transform_config", {})
    max_lines = int(transform_config.get("max_lines", DEFAULT_MAX_LINES))
    chunk_index = int(artifact.metadata.get("chunk_index", -1))
    chunks = chunk_lines(content_text, max_lines=max_lines)
    if chunk_index < 0 or chunk_index >= len(chunks):
        errors.append("artifact chunk_index is outside recomputed chunk range")
        return None
    return chunks[chunk_index].output_hash


def _decode_receipt_json(raw: str) -> tuple[Dict[str, Any], List[str]]:
    try:
        data = json.loads(raw)
    except JSONDecodeError as exc:
        return {}, [f"receipt_json is malformed JSON: {exc.msg}"]
    if not isinstance(data, dict):
        return {}, ["receipt_json must decode to an object"]
    return data, []


def _validate_receipt_record(record: Dict[str, Any], data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    missing = [field for field in REQUIRED_RECEIPT_FIELDS if field not in data]
    if missing:
        errors.append("receipt_json missing fields: " + ", ".join(sorted(missing)))
        return errors

    if data["receipt_id"] != record["receipt_id"]:
        errors.append("receipt_json receipt_id does not match receipts row")
    if data["kind"] != record["kind"]:
        errors.append("receipt_json kind does not match receipts row")
    if data["subject_id"] != record["subject_id"]:
        errors.append("receipt_json subject_id does not match receipts row")
    if data["derivation_verification_level"] != record["derivation_verification_level"]:
        errors.append(
            "receipt_json derivation_verification_level does not match receipts row"
        )
    if data["status"] != record["status"]:
        errors.append("receipt_json status does not match receipts row")
    if data["created_at"] != record["created_at"]:
        errors.append("receipt_json created_at does not match receipts row")

    if data["kind"] not in RECEIPT_KINDS:
        errors.append(f"unknown receipt kind: {data['kind']}")
    if data["derivation_verification_level"] not in DERIVATION_LEVELS:
        errors.append(
            "unknown derivation_verification_level: "
            + str(data["derivation_verification_level"])
        )

    metadata = data["metadata"]
    if not isinstance(metadata, dict):
        errors.append("receipt metadata must be an object")
    elif metadata.get("receipt_schema_version") != RECEIPT_SCHEMA_VERSION:
        errors.append(
            "unsupported receipt_schema_version: "
            + str(metadata.get("receipt_schema_version"))
        )

    for list_field in ("source_snapshot_ids", "input_artifact_ids"):
        if not isinstance(data[list_field], list) or not all(
            isinstance(item, str) for item in data[list_field]
        ):
            errors.append(f"{list_field} must be a list of strings")

    try:
        recomputed_receipt_id = receipt_id_for_payload(data)
    except Exception as exc:
        errors.append(f"receipt_id could not be recomputed: {exc}")
    else:
        if recomputed_receipt_id != record["receipt_id"]:
            errors.append("receipt_id does not match canonical receipt payload")
    return errors


def _receipt_from_data(data: Dict[str, Any]) -> Optional[DerivationReceipt]:
    try:
        return DerivationReceipt(
            receipt_id=data["receipt_id"],
            kind=data["kind"],
            subject_id=data["subject_id"],
            source_snapshot_ids=tuple(data["source_snapshot_ids"]),
            input_artifact_ids=tuple(data["input_artifact_ids"]),
            transform_id=data["transform_id"],
            output_hash=data["output_hash"],
            derivation_verification_level=data["derivation_verification_level"],
            status=data["status"],
            created_at=data["created_at"],
            metadata=data["metadata"],
        )
    except (KeyError, TypeError):
        return None


def _validate_lineage(store: DerivedStore, receipt: DerivationReceipt) -> List[str]:
    errors: List[str] = []
    if store.get_artifact(receipt.subject_id) is None:
        errors.append("subject artifact not found")
    for snapshot_id in receipt.source_snapshot_ids:
        if store.get_snapshot(snapshot_id) is None:
            errors.append(f"source snapshot not found: {snapshot_id}")
    for input_id in receipt.input_artifact_ids:
        if store.get_artifact(input_id) is None:
            errors.append(f"input artifact not found: {input_id}")
        elif not store.artifact_is_admissible(input_id):
            errors.append(f"input artifact is not admissible: {input_id}")
    if store.get_transform(receipt.transform_id) is None:
        errors.append("transform not found")
    return errors


def _verify_claimed_transform(
    store: DerivedStore, receipt: DerivationReceipt, errors: List[str]
) -> None:
    claimed = receipt.metadata.get("transform")
    if claimed is None:
        return
    transform = store.get_transform(receipt.transform_id)
    if transform is None:
        errors.append("transform not found")
        return
    actual = transform.to_dict()
    for key in ("transform_id", "name", "version", "code_hash", "config_hash"):
        if claimed.get(key) != actual.get(key):
            errors.append(f"receipt transform {key} does not match committed transform")
    if claimed.get("runtime_hash") != actual.get("runtime_hash"):
        errors.append(
            "receipt transform runtime_hash does not match committed transform"
        )


def _failed_record_result(
    receipt_id: str, record: Dict[str, Any], errors: List[str]
) -> VerificationResult:
    return VerificationResult(
        receipt_id=receipt_id,
        subject_id=str(record.get("subject_id", "")),
        ok=False,
        derivation_verification_level="DV0",
        status="failed",
        errors=tuple(errors),
    )


def _result(receipt: DerivationReceipt, errors: List[str]) -> VerificationResult:
    return VerificationResult(
        receipt_id=receipt.receipt_id,
        subject_id=receipt.subject_id,
        ok=not errors,
        derivation_verification_level="DV2" if not errors else "DV1",
        status="verified" if not errors else "failed",
        errors=tuple(errors),
        expected_output_hash=receipt.output_hash,
    )
