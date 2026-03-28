"""Comparability engine: governed comparison and claim admissibility.

This module governs whether two evidence bundles may be validly compared
and enforces consequences when they may not. It does not govern truth —
it governs which statements are allowed to present themselves as
evidence-based claims.

Core objects:
  - ComparabilityContract: defines what must match for comparison to be valid
  - EvidenceBundle: declared metadata from an evaluation run
  - ConstitutionalDiff: the product artifact — verdict + mismatches + consequence
  - evaluate(): the denial engine
"""
from assay.comparability.types import (
    BundleCompleteness,
    ClaimStatus,
    ClaimUnderTest,
    Consequence,
    ConstitutionalDiff,
    FieldSource,
    InstrumentContinuity,
    Mismatch,
    ParityFieldGroup,
    Severity,
    Verdict,
)
from assay.comparability.engine import evaluate

__all__ = [
    "BundleCompleteness",
    "ClaimStatus",
    "ClaimUnderTest",
    "Consequence",
    "ConstitutionalDiff",
    "FieldSource",
    "InstrumentContinuity",
    "Mismatch",
    "ParityFieldGroup",
    "Severity",
    "Verdict",
    "evaluate",
]
