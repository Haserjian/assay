"""Backend contract for receipted derived context."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from assay.derived.models import IndexUpdatePlan, SourceSnapshot, VerificationResult
from assay.derived.planner import apply_derived_context, plan_derived_context
from assay.derived.scanner import scan_repository
from assay.derived.store import DerivedStore
from assay.derived.transforms import (
    DEFAULT_CHUNKER_VERSION,
    DEFAULT_MAX_LINES,
    line_chunk_transform_spec,
)
from assay.derived.verifier import verify_receipt


@runtime_checkable
class DerivedBackend(Protocol):
    """Contract that any derived-context engine must satisfy."""

    def scan(self, root: Path) -> List[SourceSnapshot]: ...

    def plan(self, root: Path) -> IndexUpdatePlan: ...

    def apply(self, root: Path) -> IndexUpdatePlan: ...

    def explain(self, artifact_id: str) -> Optional[Dict[str, Any]]: ...

    def verify(self, receipt_id: str) -> VerificationResult: ...


IndexBackend = DerivedBackend


class NativeAssayBackend:
    """Native deterministic backend for the Assay receipt contract.

    TODO: evaluate CocoIndex later as a DerivedBackend implementation. It must
    export receipt-grade lineage and remain a proposal engine, not authority.
    """

    def __init__(
        self,
        store: DerivedStore,
        *,
        chunk_lines: int = DEFAULT_MAX_LINES,
        chunker_version: str = DEFAULT_CHUNKER_VERSION,
    ) -> None:
        self.store = store
        self.chunk_lines = chunk_lines
        self.chunker_version = chunker_version

    def scan(self, root: Path) -> List[SourceSnapshot]:
        return [item.snapshot for item in scan_repository(Path(root))]

    def plan(self, root: Path) -> IndexUpdatePlan:
        transform = line_chunk_transform_spec(
            version=self.chunker_version, max_lines=self.chunk_lines
        )
        return plan_derived_context(
            Path(root),
            self.store,
            transform=transform,
            max_lines=self.chunk_lines,
        )

    def apply(self, root: Path) -> IndexUpdatePlan:
        transform = line_chunk_transform_spec(
            version=self.chunker_version, max_lines=self.chunk_lines
        )
        return apply_derived_context(
            Path(root),
            self.store,
            transform=transform,
            max_lines=self.chunk_lines,
        )

    def explain(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        return self.store.explain_artifact(artifact_id)

    def verify(self, receipt_id: str) -> VerificationResult:
        return verify_receipt(self.store, receipt_id)
