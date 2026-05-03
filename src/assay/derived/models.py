"""Data models for Assay receipted derived context."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


DERIVED_SCHEMA_VERSION = "1"
RECEIPT_SCHEMA_VERSION = "1"
DERIVATION_LEVELS = ("DV0", "DV1", "DV2", "DV3", "DV4")
RECEIPT_KINDS = (
    "derived.artifact.created",
    "derived.artifact.staled",
    "derived.artifact.tombstoned",
)


@dataclass(frozen=True)
class Source:
    source_id: str
    source_type: str
    uri: str
    first_seen_at: str
    last_seen_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceSnapshot:
    snapshot_id: str
    source_id: str
    content_hash: str
    size_bytes: int
    observed_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TransformSpec:
    transform_id: str
    name: str
    version: str
    code_hash: str
    config_hash: str
    runtime_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ArtifactInput:
    artifact_id: str
    input_artifact_id: str
    input_role: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DerivedArtifact:
    artifact_id: str
    artifact_type: str
    source_snapshot_id: Optional[str]
    input_artifact_ids: Tuple[str, ...]
    transform_id: str
    output_hash: str
    receipt_id: str
    derivation_verification_level: str
    status: str
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["input_artifact_ids"] = list(self.input_artifact_ids)
        return data


@dataclass(frozen=True)
class DerivationReceipt:
    receipt_id: str
    kind: str
    subject_id: str
    source_snapshot_ids: Tuple[str, ...]
    input_artifact_ids: Tuple[str, ...]
    transform_id: str
    output_hash: str
    derivation_verification_level: str
    status: str
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["source_snapshot_ids"] = list(self.source_snapshot_ids)
        data["input_artifact_ids"] = list(self.input_artifact_ids)
        return data


@dataclass(frozen=True)
class ArtifactTombstone:
    artifact_id: str
    reason: str
    tombstoned_at: str
    receipt_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IndexUpdatePlan:
    plan_id: str
    previous_state_hash: Optional[str]
    proposed_state_hash: str
    added_count: int
    updated_count: int
    deleted_count: int
    created_at: str
    root: str
    transform_id: str
    operations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerificationResult:
    receipt_id: str
    subject_id: str
    ok: bool
    derivation_verification_level: str
    status: str
    errors: Tuple[str, ...] = ()
    expected_output_hash: Optional[str] = None
    actual_output_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["errors"] = list(self.errors)
        return data
