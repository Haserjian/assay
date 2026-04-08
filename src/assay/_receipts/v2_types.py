"""
ReceiptV2 type definitions.

Schema-agile signature and verification model for v2 receipts.
Additive — v1 receipts continue to verify through the compatibility shim
in the verifier (see decision_receipt_verify.py).

Spec lock: projection_id="receipt-core-v2"
Core rule: signatures[] entries cover verification_bundle.bundle_digest only.
           No per-field signing. No JSON-path subsets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# SigEntry — one entry in a v2 signatures[] array
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigEntry:
    """One cryptographic signature entry.

    All entries cover verification_bundle.bundle_digest. That is the single
    normative signing target — not the receipt blob, not a field list.

    algorithm: identifier from the controlled vocabulary below.
        Ed25519 (classical): "ed25519"
        ML-DSA (FIPS 204):   "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87"
        SLH-DSA (FIPS 205):  "slh-dsa-sha2-128s" | "slh-dsa-sha2-128f" | ...

    signed_at: signer-supplied metadata. NOT trusted for temporal proof
        unless backed by a trusted timestamp/log/TSA receipt. Omit when
        external timestamping is not available.
    """

    algorithm: str
    signer_id: str
    value: str  # base64url-encoded signature bytes
    signer_pubkey_sha256: Optional[str] = None
    signed_at: Optional[str] = None  # ISO 8601; advisory only, not authoritative


# ---------------------------------------------------------------------------
# VerificationBundle — normative digest descriptor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationBundle:
    """Normative digest descriptor stored in a v2 receipt.

    bundle_digest is the single value that all signatures[] entries sign:

        bundle_digest = sha256(jcs(canonical_projection(receipt, projection_id)))

    where canonical_projection() in _receipts/canonicalize.py is the single
    source of truth for the projection rule. covers is explanatory metadata
    only — the verifier recomputes the projection independently and never
    trusts the covers list.

    covers: tuple of field names included in the projection at issuance.
        Explanatory only. Mismatch between covers and actual projection
        produces a verifier warning, not a failure.
    """

    bundle_digest: str  # "sha256:hexhash" or "sha3-256:hexhash"
    bundle_algorithm: str  # "sha256"
    canonicalization: str  # "jcs-rfc8785"
    projection_id: str = "receipt-core-v2"
    covers: tuple = ()  # explanatory only — see docstring
    schema_version: str = "1"


# ---------------------------------------------------------------------------
# VerificationPolicy — acceptance policy embedded in the receipt
# ---------------------------------------------------------------------------


@dataclass
class PolicyRequires:
    """Minimum signature requirements for one validity predicate."""

    min_signatures: int
    algorithms: List[str] = field(default_factory=list)


@dataclass
class VerificationPolicy:
    """Acceptance policy for a v2 receipt.

    Included in the canonical projection (attested). This means:
    - The policy under which a receipt was issued is part of its evidentiary
      meaning. Auditors can verify "issued under these exact rules."
    - Policy changes require reissuance — a receipt cannot be retroactively
      re-interpreted under updated policy language.
    - verification_profile gates which policy branch the verifier applies.

    archival_requires=None means no archival policy declared; verifier will
    return archival_valid=None (not assessed), not archival_valid=False.
    """

    operational_requires: PolicyRequires
    archival_requires: Optional[PolicyRequires] = None
    schema_version: str = "1"


# ---------------------------------------------------------------------------
# Algorithm classification — verifier-side only, not stored in receipts
# ---------------------------------------------------------------------------

# Status table for verifier logic. Not part of the receipt schema.
# Keys: algorithm identifier strings matching SigEntry.algorithm.
ALGORITHM_STATUS: Dict[str, str] = {
    "ed25519": "classical_signing",
    "ml-dsa-44": "pq_signing",
    "ml-dsa-65": "pq_signing",
    "ml-dsa-87": "pq_signing",
    "slh-dsa-sha2-128s": "backup_signing",
    "slh-dsa-sha2-128f": "backup_signing",
    "slh-dsa-sha2-192s": "backup_signing",
    "slh-dsa-sha2-256s": "backup_signing",
}

OPERATIONAL_ALGORITHMS: frozenset = frozenset(
    {
        "ed25519",
        # PQ algorithms (ml-dsa-*, slh-dsa-*) are in UNSUPPORTED_ALGORITHMS until
        # cryptographic verification is implemented. Do not add them here first.
        # INV-04: ambiguous dual-membership (operational + unsupported) is the bug.
    }
)

ARCHIVAL_ALGORITHMS: frozenset = frozenset(
    {
        "ml-dsa-44",
        "ml-dsa-65",
        "ml-dsa-87",
        "slh-dsa-sha2-128s",
        "slh-dsa-sha2-128f",
        "slh-dsa-sha2-192s",
        "slh-dsa-sha2-256s",
    }
)

# Algorithms recognized by this spec but not implemented in this build.
# Verifier MUST return status="unsupported_algorithm" for these,
# not a cryptographic failure.
UNSUPPORTED_ALGORITHMS: frozenset = frozenset(
    {
        "ml-dsa-44",
        "ml-dsa-65",
        "ml-dsa-87",
        "slh-dsa-sha2-128s",
        "slh-dsa-sha2-128f",
        "slh-dsa-sha2-192s",
        "slh-dsa-sha2-256s",
    }
)


__all__ = [
    "SigEntry",
    "VerificationBundle",
    "PolicyRequires",
    "VerificationPolicy",
    "ALGORITHM_STATUS",
    "OPERATIONAL_ALGORITHMS",
    "ARCHIVAL_ALGORITHMS",
    "UNSUPPORTED_ALGORITHMS",
]
