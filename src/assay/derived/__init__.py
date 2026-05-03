"""Receipted Derived Context for Assay.

This package is intentionally native-first. CocoIndex and similar systems may
later implement the backend contract, but they are not authority here.
"""

from assay.derived.models import (
    ArtifactInput,
    ArtifactTombstone,
    DerivationReceipt,
    DerivedArtifact,
    IndexUpdatePlan,
    Source,
    SourceSnapshot,
    TransformSpec,
    VerificationResult,
)
from assay.derived.backends import DerivedBackend, IndexBackend, NativeAssayBackend

__all__ = [
    "ArtifactInput",
    "ArtifactTombstone",
    "DerivationReceipt",
    "DerivedArtifact",
    "IndexUpdatePlan",
    "Source",
    "SourceSnapshot",
    "TransformSpec",
    "VerificationResult",
    "DerivedBackend",
    "IndexBackend",
    "NativeAssayBackend",
]
