"""Planner for native receipted derived context."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from assay.derived.hashing import canonical_hash, stable_id
from assay.derived.models import (
    DerivedArtifact,
    IndexUpdatePlan,
    Source,
    TransformSpec,
)
from assay.derived.receipts import make_derivation_receipt, now_iso
from assay.derived.scanner import ScannedSnapshot, scan_repository
from assay.derived.store import DerivedStore
from assay.derived.transforms import (
    DEFAULT_MAX_LINES,
    TextChunk,
    chunk_lines,
    line_chunk_transform_spec,
)


TIME_KEYS = {
    "created_at",
    "observed_at",
    "first_seen_at",
    "last_seen_at",
    "tombstoned_at",
}


def artifact_id_for_chunk(snapshot_id: str, transform_id: str, chunk: TextChunk) -> str:
    return stable_id(
        "art",
        {
            "artifact_type": "source_chunk",
            "source_snapshot_id": snapshot_id,
            "transform_id": transform_id,
            "chunk_index": chunk.chunk_index,
            "output_hash": chunk.output_hash,
        },
    )


def plan_derived_context(
    root: Path,
    store: DerivedStore,
    *,
    transform: Optional[TransformSpec] = None,
    max_lines: int = DEFAULT_MAX_LINES,
) -> IndexUpdatePlan:
    """Build a staged derived-context plan without mutating committed artifacts."""

    root = Path(root).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"derived scan root does not exist: {root}")

    transform_spec = transform or line_chunk_transform_spec(max_lines=max_lines)
    created_at = now_iso()
    scanned = scan_repository(root, observed_at=created_at)
    active_records = store.list_active_artifacts_with_sources()
    active_ids = {record["artifact"].artifact_id for record in active_records}

    operations: List[Dict[str, Any]] = []
    proposed_artifacts: List[DerivedArtifact] = []
    proposed_ids: Set[str] = set()
    scanned_source_ids = {item.snapshot.source_id for item in scanned}

    if not store.has_transform(transform_spec.transform_id):
        operations.append(
            {"type": "add_transform", "transform": transform_spec.to_dict()}
        )

    for item in scanned:
        source = _source_for_scanned(item, store, created_at)
        operations.append({"type": "upsert_source", "source": source.to_dict()})
        if not store.has_snapshot(item.snapshot.snapshot_id):
            operations.append(
                {"type": "add_snapshot", "snapshot": item.snapshot.to_dict()}
            )
        for artifact in _artifacts_for_snapshot(
            item, transform_spec, max_lines=max_lines, created_at=created_at
        ):
            proposed_artifacts.append(artifact)
            proposed_ids.add(artifact.artifact_id)
            if artifact.artifact_id not in active_ids:
                operations.append(
                    {
                        "type": "add_artifact",
                        "artifact": artifact.to_dict(),
                        "inputs": [],
                        "receipt": _creation_receipt(
                            artifact, item, transform_spec, created_at
                        ).to_dict(),
                    }
                )

    for record in active_records:
        artifact = record["artifact"]
        if artifact.artifact_id in proposed_ids:
            continue
        if record["source_id"] not in scanned_source_ids:
            receipt = _tombstone_receipt(artifact, created_at)
            operations.append(
                {
                    "type": "tombstone_artifact",
                    "artifact_id": artifact.artifact_id,
                    "tombstone": {
                        "artifact_id": artifact.artifact_id,
                        "reason": "source_disappeared",
                        "tombstoned_at": created_at,
                        "receipt_id": receipt.receipt_id,
                    },
                    "receipt": receipt.to_dict(),
                }
            )
        else:
            receipt = _stale_receipt(artifact, created_at)
            operations.append(
                {
                    "type": "stale_artifact",
                    "artifact_id": artifact.artifact_id,
                    "receipt": receipt.to_dict(),
                }
            )

    previous_state_hash = _state_hash([record["artifact"] for record in active_records])
    proposed_state_hash = _state_hash(proposed_artifacts)
    identity_payload = {
        "root": str(root),
        "previous_state_hash": previous_state_hash,
        "proposed_state_hash": proposed_state_hash,
        "operations": [_strip_times(operation) for operation in operations],
    }
    plan_id = stable_id("dplan", identity_payload)
    return IndexUpdatePlan(
        plan_id=plan_id,
        previous_state_hash=previous_state_hash,
        proposed_state_hash=proposed_state_hash,
        added_count=sum(1 for op in operations if op["type"] == "add_artifact"),
        updated_count=sum(1 for op in operations if op["type"] == "stale_artifact"),
        deleted_count=sum(1 for op in operations if op["type"] == "tombstone_artifact"),
        created_at=created_at,
        root=str(root),
        transform_id=transform_spec.transform_id,
        operations=operations,
    )


def apply_derived_context(
    root: Path,
    store: DerivedStore,
    *,
    transform: Optional[TransformSpec] = None,
    max_lines: int = DEFAULT_MAX_LINES,
    fail_after_operations: Optional[int] = None,
) -> IndexUpdatePlan:
    plan = plan_derived_context(root, store, transform=transform, max_lines=max_lines)
    store.apply_plan(plan, fail_after_operations=fail_after_operations)
    return plan


def _source_for_scanned(
    item: ScannedSnapshot, store: DerivedStore, observed_at: str
) -> Source:
    existing = store.get_source(item.snapshot.source_id)
    return Source(
        source_id=item.snapshot.source_id,
        source_type=item.source_type,
        uri=item.uri,
        first_seen_at=existing.first_seen_at if existing else observed_at,
        last_seen_at=observed_at,
    )


def _artifacts_for_snapshot(
    item: ScannedSnapshot,
    transform: TransformSpec,
    *,
    max_lines: int,
    created_at: str,
) -> List[DerivedArtifact]:
    content = item.snapshot.metadata.get("content_text", "")
    artifacts: List[DerivedArtifact] = []
    for chunk in chunk_lines(content, max_lines=max_lines):
        artifact_id = artifact_id_for_chunk(
            item.snapshot.snapshot_id, transform.transform_id, chunk
        )
        metadata = {
            "relative_path": item.relative_path,
            "chunk_index": chunk.chunk_index,
            "start_line": chunk.start_line,
            "end_line": chunk.end_line,
            "text": chunk.text,
            "transform_config": {"max_lines": max_lines},
        }
        receipt = make_derivation_receipt(
            kind="derived.artifact.created",
            subject_id=artifact_id,
            source_snapshot_ids=[item.snapshot.snapshot_id],
            input_artifact_ids=[],
            transform_id=transform.transform_id,
            output_hash=chunk.output_hash,
            derivation_verification_level="DV1",
            status="committed",
            created_at=created_at,
            metadata={
                "artifact_type": "source_chunk",
                "relative_path": item.relative_path,
                "chunk_index": chunk.chunk_index,
                "transform_config": {"max_lines": max_lines},
                "transform": transform.to_dict(),
            },
        )
        artifacts.append(
            DerivedArtifact(
                artifact_id=artifact_id,
                artifact_type="source_chunk",
                source_snapshot_id=item.snapshot.snapshot_id,
                input_artifact_ids=(),
                transform_id=transform.transform_id,
                output_hash=chunk.output_hash,
                receipt_id=receipt.receipt_id,
                derivation_verification_level="DV1",
                status="active",
                created_at=created_at,
                metadata=metadata,
            )
        )
    return artifacts


def _creation_receipt(
    artifact: DerivedArtifact,
    item: ScannedSnapshot,
    transform: TransformSpec,
    created_at: str,
):
    return make_derivation_receipt(
        kind="derived.artifact.created",
        subject_id=artifact.artifact_id,
        source_snapshot_ids=[item.snapshot.snapshot_id],
        input_artifact_ids=[],
        transform_id=artifact.transform_id,
        output_hash=artifact.output_hash,
        derivation_verification_level="DV1",
        status="committed",
        created_at=created_at,
        metadata={
            "artifact_type": artifact.artifact_type,
            "relative_path": item.relative_path,
            "chunk_index": artifact.metadata.get("chunk_index"),
            "transform_config": artifact.metadata.get("transform_config", {}),
            "transform": transform.to_dict(),
        },
    )


def _stale_receipt(artifact: DerivedArtifact, created_at: str):
    return make_derivation_receipt(
        kind="derived.artifact.staled",
        subject_id=artifact.artifact_id,
        source_snapshot_ids=(
            [artifact.source_snapshot_id] if artifact.source_snapshot_id else []
        ),
        input_artifact_ids=artifact.input_artifact_ids,
        transform_id=artifact.transform_id,
        output_hash=artifact.output_hash,
        derivation_verification_level="DV1",
        status="committed",
        created_at=created_at,
        metadata={
            "reason": "source_snapshot_or_transform_changed",
            "previous_status": artifact.status,
        },
    )


def _tombstone_receipt(artifact: DerivedArtifact, created_at: str):
    return make_derivation_receipt(
        kind="derived.artifact.tombstoned",
        subject_id=artifact.artifact_id,
        source_snapshot_ids=(
            [artifact.source_snapshot_id] if artifact.source_snapshot_id else []
        ),
        input_artifact_ids=artifact.input_artifact_ids,
        transform_id=artifact.transform_id,
        output_hash=artifact.output_hash,
        derivation_verification_level="DV1",
        status="committed",
        created_at=created_at,
        metadata={"reason": "source_disappeared", "previous_status": artifact.status},
    )


def _state_hash(artifacts: Sequence[DerivedArtifact]) -> str:
    records = []
    for artifact in sorted(artifacts, key=lambda item: item.artifact_id):
        records.append(
            {
                "artifact_id": artifact.artifact_id,
                "artifact_type": artifact.artifact_type,
                "source_snapshot_id": artifact.source_snapshot_id,
                "input_artifact_ids": list(artifact.input_artifact_ids),
                "transform_id": artifact.transform_id,
                "output_hash": artifact.output_hash,
                "derivation_verification_level": artifact.derivation_verification_level,
                "status": artifact.status,
            }
        )
    return canonical_hash(records)


def _strip_times(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_times(item)
            for key, item in value.items()
            if key not in TIME_KEYS
        }
    if isinstance(value, list):
        return [_strip_times(item) for item in value]
    return value
