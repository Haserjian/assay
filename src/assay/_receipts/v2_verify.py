"""
ReceiptV2 structured verifier.

Slice 2 of the ReceiptV2 implementation: SigResult, VerifyResultV2, verify_v2().

Three-layer result model:
  1. Artifact identity — digest_valid, digest_status
  2. Witnesses        — signature_results (per-signature SigResult)
  3. Acceptance       — operational_valid, archival_valid, policy_satisfied

Does NOT handle CCIO Decision Receipts (decision_receipt_verify.py).

v1 compatibility shim: receipts with a flat signature field and no signatures[]
are shimmed transparently — the verifier synthesizes a signatures[] entry from
the flat fields. Shim only lifts facts present in the receipt; it never invents
metadata (signer_id absent → None in synthesized entry, signed_at omitted).

Key resolver interface:
    key_resolver(signer_id: str, pubkey_sha256: Optional[str]) -> Optional[bytes]

    Returns 32-byte Ed25519 public key bytes, or None if unknown/untrusted.
    Callers supply their own resolver (wrapping signers.json, keystore, etc.).
    If no key_resolver is provided, all signatures return trusted_signer=False.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from assay._receipts.canonicalize import canonical_projection
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay._receipts.v2_types import (
    ARCHIVAL_ALGORITHMS,
    OPERATIONAL_ALGORITHMS,
    UNSUPPORTED_ALGORITHMS,
)


# ---------------------------------------------------------------------------
# SigResult — per-signature verification result
# ---------------------------------------------------------------------------

@dataclass
class SigResult:
    """Per-signature verification result.

    Three independent predicates — each may be True independently:
      cryptographically_valid: signature math verifies against canonical bytes
      trusted_signer:          signer_id in registry, key fingerprint matches
      algorithm_acceptable:    algorithm is in at least one policy-allowed set

    status is the canonical aggregate (check this first):
      "valid"                 — all three predicates True
      "invalid"               — cryptographic verification failed
      "untrusted_signer"      — crypto ok but signer unknown or key mismatch
      "unsupported_algorithm" — algorithm not implemented in this verifier build
      "policy_rejected"       — algorithm known but outside all policy-allowed sets

    error: human-readable reason when status != "valid", None otherwise.
    """
    algorithm: str
    signer_id: str
    cryptographically_valid: bool
    trusted_signer: bool
    algorithm_acceptable: bool
    status: str
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# VerifyResultV2 — full structured verifier output
# ---------------------------------------------------------------------------

@dataclass
class VerifyResultV2:
    """Structured output from verify_v2().

    Upstream gating rule:
      digest_valid=False → operational_valid=False and archival_valid=None
      (digest failed before archival assessment was reachable)

    archival_valid tri-state:
      None  — no PQ signature present, or digest invalid: not assessed
      False — PQ signature(s) present but none passed archival policy
      True  — at least min_signatures PQ signatures passed archival policy

    policy_satisfied:
      True iff operational policy is met AND (archival policy is met OR
      no archival policy was declared in verification_policy).
    """
    digest_valid: bool
    digest_status: str  # "matched" | "mismatch" | "missing_bundle" | "unsupported_projection" | "canonicalization_error"
    signature_results: List[SigResult] = field(default_factory=list)
    operational_valid: bool = False
    archival_valid: Optional[bool] = None
    policy_satisfied: bool = False
    distinct_signer_ids: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_canonical_bytes(
    receipt: Dict[str, Any], projection_id: str
) -> tuple:
    """Returns (canonical_bytes_or_None, digest_status_string)."""
    try:
        projected = canonical_projection(receipt, projection_id=projection_id)
        canonical = jcs_canonicalize(projected)
        return canonical, "ok"
    except ValueError as exc:
        if "Unknown projection_id" in str(exc):
            return None, "unsupported_projection"
        return None, "canonicalization_error"
    except Exception:
        return None, "canonicalization_error"


def _shim_v1_signatures(receipt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return signatures[] — synthesized from v1 flat fields when absent.

    Shim rule: only lift facts present in the receipt. Never invent metadata.
    - signer_id absent  → entry has signer_id=None
    - signed_at         → omitted (not present in v1 receipts)
    - algorithm         → "ed25519" (v1 was always Ed25519)
    """
    if "signatures" in receipt:
        sigs = receipt["signatures"]
        return sigs if isinstance(sigs, list) else []
    if "signature" not in receipt:
        return []
    return [{
        "algorithm": "ed25519",
        "signer_id": receipt.get("signer_id"),        # may be None
        "value": receipt["signature"],
        "signer_pubkey_sha256": receipt.get("signer_pubkey_sha256"),  # may be None
    }]


def _verify_ed25519(pubkey_bytes: bytes, message: bytes, sig_bytes: bytes) -> bool:
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        vk = VerifyKey(pubkey_bytes)
        vk.verify(message, sig_bytes)
        return True
    except Exception:
        return False


def _verify_single_sig(
    sig_dict: Dict[str, Any],
    canonical_bytes: bytes,
    key_resolver: Optional[Callable],
    all_acceptable_algorithms: frozenset,
) -> SigResult:
    """Verify one signature entry. Returns a SigResult."""
    algorithm = sig_dict.get("algorithm") or ""
    signer_id = sig_dict.get("signer_id") or ""
    value = sig_dict.get("value") or ""
    pubkey_sha256 = sig_dict.get("signer_pubkey_sha256")

    # 1. Algorithm known-but-unsupported in this build
    if algorithm in UNSUPPORTED_ALGORITHMS:
        return SigResult(
            algorithm=algorithm, signer_id=signer_id,
            cryptographically_valid=False, trusted_signer=False,
            algorithm_acceptable=True,  # recognized by spec
            status="unsupported_algorithm",
            error=f"Algorithm {algorithm!r} is recognized but not implemented in this build",
        )

    # 2. Algorithm not in any policy-allowed set (unknown or rejected)
    algorithm_acceptable = algorithm in all_acceptable_algorithms
    if not algorithm_acceptable:
        return SigResult(
            algorithm=algorithm, signer_id=signer_id,
            cryptographically_valid=False, trusted_signer=False,
            algorithm_acceptable=False,
            status="policy_rejected",
            error=f"Algorithm {algorithm!r} is not in the allowed algorithm set",
        )

    # 3. Resolve public key
    pubkey_bytes: Optional[bytes] = None
    trusted_signer = False
    if key_resolver is not None and signer_id:
        pubkey_bytes = key_resolver(signer_id, pubkey_sha256)
        trusted_signer = pubkey_bytes is not None

    if pubkey_bytes is None:
        return SigResult(
            algorithm=algorithm, signer_id=signer_id,
            cryptographically_valid=False, trusted_signer=False,
            algorithm_acceptable=algorithm_acceptable,
            status="untrusted_signer",
            error=f"Public key not available for signer {signer_id!r}",
        )

    # 4. Decode signature bytes
    try:
        sig_bytes = base64.b64decode(value)
    except Exception:
        return SigResult(
            algorithm=algorithm, signer_id=signer_id,
            cryptographically_valid=False, trusted_signer=trusted_signer,
            algorithm_acceptable=algorithm_acceptable,
            status="invalid",
            error="Signature value is not valid base64",
        )

    # 5. Cryptographic verification
    if algorithm == "ed25519":
        crypto_valid = _verify_ed25519(pubkey_bytes, canonical_bytes, sig_bytes)
    else:
        # PQ algorithms recognized but not yet cryptographically verified
        return SigResult(
            algorithm=algorithm, signer_id=signer_id,
            cryptographically_valid=False, trusted_signer=trusted_signer,
            algorithm_acceptable=algorithm_acceptable,
            status="unsupported_algorithm",
            error=f"Algorithm {algorithm!r} cryptographic verification not yet implemented",
        )

    if not crypto_valid:
        return SigResult(
            algorithm=algorithm, signer_id=signer_id,
            cryptographically_valid=False, trusted_signer=trusted_signer,
            algorithm_acceptable=algorithm_acceptable,
            status="invalid",
            error="Signature verification failed",
        )

    return SigResult(
        algorithm=algorithm, signer_id=signer_id,
        cryptographically_valid=True, trusted_signer=trusted_signer,
        algorithm_acceptable=algorithm_acceptable,
        status="valid",
    )


# ---------------------------------------------------------------------------
# verify_v2 — main entry point
# ---------------------------------------------------------------------------

def verify_v2(
    receipt: Dict[str, Any],
    *,
    key_resolver: Optional[Callable[[str, Optional[str]], Optional[bytes]]] = None,
    projection_id: str = "receipt-core-v2",
) -> VerifyResultV2:
    """Verify a v2 receipt. Returns a structured VerifyResultV2.

    Verification steps:
      1. Recompute canonical bytes from receipt projection
      2. Check bundle_digest matches recomputed hash
      3. Verify each signature in signatures[] over canonical bytes
      4. Evaluate operational/archival policy
      5. Return structured result

    Args:
        receipt: Receipt dict (v1 or v2 format).
        key_resolver: Callable(signer_id, pubkey_sha256) → pubkey_bytes or None.
            Provides public key material for signature verification.
            If None, all signatures return trusted_signer=False.
        projection_id: Named projection version. Default: "receipt-core-v2".

    Returns:
        VerifyResultV2 with full structured result.
    """
    # --- Step 1: Canonical bytes ---
    canonical_bytes, status_prep = _extract_canonical_bytes(receipt, projection_id)
    if canonical_bytes is None:
        return VerifyResultV2(
            digest_valid=False,
            digest_status=status_prep,
        )

    # --- Step 2: Bundle digest check ---
    stored_bundle = receipt.get("verification_bundle")
    if stored_bundle is None:
        return VerifyResultV2(
            digest_valid=False,
            digest_status="missing_bundle",
        )

    if not isinstance(stored_bundle, dict):
        return VerifyResultV2(
            digest_valid=False,
            digest_status="missing_bundle",
        )

    stored_digest = stored_bundle.get("bundle_digest", "")
    stored_algorithm = stored_bundle.get("bundle_algorithm", "sha256")

    # Recompute actual digest
    if stored_algorithm == "sha256":
        actual_digest = f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"
    elif stored_algorithm == "sha3-256":
        actual_digest = f"sha3-256:{hashlib.sha3_256(canonical_bytes).hexdigest()}"
    else:
        return VerifyResultV2(
            digest_valid=False,
            digest_status="unsupported_projection",
        )

    digest_valid = (actual_digest == stored_digest)
    digest_status = "matched" if digest_valid else "mismatch"

    if not digest_valid:
        # Upstream gating: archival_valid=None (not False) — assessment not reached
        return VerifyResultV2(
            digest_valid=False,
            digest_status=digest_status,
        )

    # --- Step 3: Verify signatures ---
    sig_dicts = _shim_v1_signatures(receipt)

    # Determine accepted algorithm sets from verification_policy (or defaults)
    policy_raw = receipt.get("verification_policy")
    policy = policy_raw if isinstance(policy_raw, dict) else {}

    op_req = policy.get("operational_requires") or {}
    arch_req = policy.get("archival_requires")  # None means no archival policy declared

    op_algorithms = frozenset(op_req.get("algorithms", [])) or OPERATIONAL_ALGORITHMS
    op_min_sigs = int(op_req.get("min_signatures", 1)) if op_req else 1

    if arch_req is not None:
        arch_algorithms = frozenset(arch_req.get("algorithms", [])) or ARCHIVAL_ALGORITHMS
        arch_min_sigs = int(arch_req.get("min_signatures", 1))
    else:
        arch_algorithms = ARCHIVAL_ALGORITHMS
        arch_min_sigs = 1

    all_acceptable = op_algorithms | arch_algorithms

    sig_results: List[SigResult] = []
    for sig_dict in sig_dicts:
        result = _verify_single_sig(
            sig_dict, canonical_bytes, key_resolver, all_acceptable
        )
        sig_results.append(result)

    # --- Step 4: Policy evaluation ---
    valid_results = [r for r in sig_results if r.status == "valid"]

    # operational_valid: enough valid signatures using operational algorithms
    op_valid_count = sum(1 for r in valid_results if r.algorithm in op_algorithms)
    operational_valid = op_valid_count >= op_min_sigs

    # archival_valid tri-state
    pq_sig_dicts = [s for s in sig_dicts if (s.get("algorithm") or "") in ARCHIVAL_ALGORITHMS]
    if not pq_sig_dicts:
        archival_valid: Optional[bool] = None   # no PQ signatures present — not assessed
    else:
        pq_valid_count = sum(
            1 for r in valid_results if r.algorithm in arch_algorithms
        )
        archival_valid = pq_valid_count >= arch_min_sigs

    # policy_satisfied: operational met AND (archival met OR no archival policy declared)
    if arch_req is None:
        policy_satisfied = operational_valid
    else:
        policy_satisfied = operational_valid and (archival_valid is True)

    distinct_signer_ids = sorted(set(r.signer_id for r in valid_results if r.signer_id))

    return VerifyResultV2(
        digest_valid=True,
        digest_status="matched",
        signature_results=sig_results,
        operational_valid=operational_valid,
        archival_valid=archival_valid,
        policy_satisfied=policy_satisfied,
        distinct_signer_ids=distinct_signer_ids,
    )


__all__ = [
    "SigResult",
    "VerifyResultV2",
    "verify_v2",
]
