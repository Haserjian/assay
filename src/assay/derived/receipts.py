"""Receipt construction helpers for derived context."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Sequence

from assay.derived.hashing import stable_id
from assay.derived.models import DerivationReceipt, RECEIPT_SCHEMA_VERSION


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_derivation_receipt(
    *,
    kind: str,
    subject_id: str,
    source_snapshot_ids: Sequence[str],
    input_artifact_ids: Sequence[str],
    transform_id: str,
    output_hash: str,
    derivation_verification_level: str,
    status: str,
    created_at: str,
    metadata: Dict[str, Any],
) -> DerivationReceipt:
    """Build a receipt with a deterministic ID that excludes timestamps."""

    metadata = dict(metadata)
    metadata.setdefault("receipt_schema_version", RECEIPT_SCHEMA_VERSION)
    receipt_id = receipt_id_for_payload(
        {
            "kind": kind,
            "subject_id": subject_id,
            "source_snapshot_ids": list(source_snapshot_ids),
            "input_artifact_ids": list(input_artifact_ids),
            "transform_id": transform_id,
            "output_hash": output_hash,
            "derivation_verification_level": derivation_verification_level,
            "status": status,
            "metadata": metadata,
        }
    )
    return DerivationReceipt(
        receipt_id=receipt_id,
        kind=kind,
        subject_id=subject_id,
        source_snapshot_ids=tuple(source_snapshot_ids),
        input_artifact_ids=tuple(input_artifact_ids),
        transform_id=transform_id,
        output_hash=output_hash,
        derivation_verification_level=derivation_verification_level,
        status=status,
        created_at=created_at,
        metadata=metadata,
    )


def receipt_id_for_payload(payload: Dict[str, Any]) -> str:
    id_payload = {
        "kind": payload["kind"],
        "subject_id": payload["subject_id"],
        "source_snapshot_ids": list(payload.get("source_snapshot_ids", [])),
        "input_artifact_ids": list(payload.get("input_artifact_ids", [])),
        "transform_id": payload.get("transform_id", ""),
        "output_hash": payload.get("output_hash", ""),
        "derivation_verification_level": payload["derivation_verification_level"],
        "status": payload["status"],
        "metadata": payload.get("metadata", {}),
    }
    return stable_id("drcpt", id_payload)
