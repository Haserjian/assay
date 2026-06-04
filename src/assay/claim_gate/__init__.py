"""Claim Gate: deterministic detection of unsupported claim drift."""

from assay.claim_gate.cli import run_claim_gate_diff
from assay.claim_gate.models import (
    ClaimBoundaryTransition,
    DiffCollection,
    DiffPair,
    NonClaim,
    TextSpan,
)

__all__ = [
    "ClaimBoundaryTransition",
    "DiffCollection",
    "DiffPair",
    "NonClaim",
    "TextSpan",
    "run_claim_gate_diff",
]
