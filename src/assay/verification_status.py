"""Canonical verdict classification for verification results.

Single source of truth for the PASS / HONEST_FAIL / TAMPERED taxonomy.
Used by badge, HTML, terminal output, and any future rendering surface.

Policy:
    PASS        — integrity valid, all claims pass (or no claims)
    HONEST_FAIL — integrity valid, but one or more claims fail
    TAMPERED    — signature, hash, manifest, or file integrity failure
"""
from __future__ import annotations

from typing import Literal

VerificationVerdict = Literal["PASS", "HONEST_FAIL", "TAMPERED"]

# Display labels keyed by verdict
VERDICT_LABELS: dict[str, str] = {
    "PASS": "Pack verified",
    "HONEST_FAIL": "Pack verified, claims failed",
    "TAMPERED": "Pack integrity compromised",
}

VERDICT_COLORS: dict[str, str] = {
    "PASS": "#4c1",
    "HONEST_FAIL": "#fe7d37",
    "TAMPERED": "#e05d44",
}


def classify_verdict(
    *,
    integrity_passed: bool,
    claim_check: str,
) -> VerificationVerdict:
    """Map raw verification result to canonical verdict.

    Args:
        integrity_passed: True if manifest signature and file hashes are valid.
        claim_check: The attestation claim_check value ("PASS", "FAIL", "N/A").
    """
    if not integrity_passed:
        return "TAMPERED"
    if claim_check == "FAIL":
        return "HONEST_FAIL"
    return "PASS"
