"""Failure mechanism families — higher-level grouping of verification error codes.

Maps individual error codes to mechanism types for structured failure reporting.
Buyers see these in JSON output to understand *what kind* of failure occurred,
not just *which check* failed.
"""
from __future__ import annotations

from typing import Dict

FM_STALE_EVIDENCE = "stale_evidence"
FM_SCHEMA_MISMATCH = "schema_mismatch"
FM_WITNESS_GAP = "witness_gap"
FM_TAMPER_DETECTED = "tamper_detected"
FM_POLICY_CONFLICT = "policy_conflict"

# Lazy import to avoid circular dependency — codes are string constants
ERROR_TO_MECHANISM: Dict[str, str] = {
    "E_PACK_STALE": FM_STALE_EVIDENCE,
    "E_TIMESTAMP_INVALID": FM_STALE_EVIDENCE,
    "E_SCHEMA_UNKNOWN": FM_SCHEMA_MISMATCH,
    "E_CANON_MISMATCH": FM_SCHEMA_MISMATCH,
    "E_DUPLICATE_ID": FM_SCHEMA_MISMATCH,
    "E_SIG_MISSING": FM_WITNESS_GAP,
    "E_CHAIN_BROKEN": FM_WITNESS_GAP,
    "E_MANIFEST_TAMPER": FM_TAMPER_DETECTED,
    "E_PACK_OMISSION_DETECTED": FM_TAMPER_DETECTED,
    "E_PACK_SIG_INVALID": FM_TAMPER_DETECTED,
    "E_SIG_INVALID": FM_TAMPER_DETECTED,
    "E_POLICY_MISSING": FM_POLICY_CONFLICT,
    "E_CI_BINDING_MISSING": FM_POLICY_CONFLICT,
    "E_CI_BINDING_MISMATCH": FM_POLICY_CONFLICT,
}


def mechanism_for_code(code: str) -> str | None:
    """Return the failure mechanism family for a given error code."""
    return ERROR_TO_MECHANISM.get(code)


__all__ = [
    "FM_STALE_EVIDENCE",
    "FM_SCHEMA_MISMATCH",
    "FM_WITNESS_GAP",
    "FM_TAMPER_DETECTED",
    "FM_POLICY_CONFLICT",
    "ERROR_TO_MECHANISM",
    "mechanism_for_code",
]
