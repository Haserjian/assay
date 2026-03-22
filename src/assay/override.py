"""Override receipt builder — overriding Decision Receipts.

Design compression (intentional, not eternal doctrine):
An override is represented as a Decision Receipt with authority_class=OVERRIDING,
not as a separate first-class receipt type. This is a deliberate reuse of the
existing schema to prove constitutional circulation without inventing new nouns.

The override receipt:
  - supersedes the original refusal receipt
  - declares OVERRIDING authority with delegated_from
  - creates obligations (referenced by real obligation IDs, not descriptive strings)
  - carries justification, actor identity, and timestamp

This module is product-layer: it consumes CCIO constitutional constraints
(via the Decision Receipt schema) but does not invent new doctrine.

Temporary simplification (P0): delegated_from names the authority seat whose
decision is being overridden. In reality, override authority may come from a
higher human emergency authority, not delegation from the overridden seat.
This distinction is deferred to P1.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from assay.decision_receipt import validate_decision_receipt

# Minimum justification length (matches CCIO governance.py OverrideReceipt)
MIN_JUSTIFICATION_LENGTH = 20


def build_override_decision_receipt(
    *,
    superseded_receipt: Dict[str, Any],
    actor_id: str,
    justification: str,
    obligation_ids: List[str],
    episode_id: Optional[str] = None,
    receipt_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    override_class: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an overriding Decision Receipt that supersedes a prior refusal.

    Args:
        superseded_receipt: The original refusal Decision Receipt being overridden.
        actor_id: Identity of the human performing the override.
        justification: Free-text justification (min 20 chars).
        obligation_ids: Real obligation IDs (e.g., ["OB-abc123"]) created by this
            override. Must be non-empty — overrides always create review debt.
        episode_id: Episode context. Defaults to superseded receipt's episode_id.
        receipt_id: Override receipt ID. Auto-generated if not provided.
        timestamp: ISO-8601 timestamp. Defaults to now.
        override_class: Optional classification code (e.g., "emergency",
            "administrative", "delegated", "test"). Stored in verdict_reason_codes
            for later filtering. Not a taxonomy — just a seam for future use.

    Returns:
        Dict conforming to decision_receipt_v0.1.0 schema with
        authority_class=OVERRIDING.

    Raises:
        ValueError: If justification is too short, obligation_ids is empty,
            or the superseded receipt is not a refusal.
    """
    # --- Input validation ---
    if len(justification) < MIN_JUSTIFICATION_LENGTH:
        raise ValueError(
            f"Override justification must be >= {MIN_JUSTIFICATION_LENGTH} chars, "
            f"got {len(justification)}"
        )

    if not obligation_ids:
        raise ValueError(
            "Override must create at least one obligation (obligation_ids empty). "
            "Overrides without review debt are governance fraud."
        )

    superseded_id = superseded_receipt.get("receipt_id")
    if not superseded_id:
        raise ValueError("Superseded receipt must have a receipt_id")

    superseded_verdict = superseded_receipt.get("verdict")
    if superseded_verdict not in ("REFUSE", "DEFER", "CONFLICT"):
        raise ValueError(
            f"Can only override REFUSE/DEFER/CONFLICT verdicts, "
            f"got {superseded_verdict!r}"
        )

    # --- Build override receipt ---
    now = timestamp or datetime.now(timezone.utc).isoformat()
    rid = receipt_id or f"r_{uuid.uuid4().hex[:12]}"
    ep_id = episode_id or superseded_receipt.get("episode_id", "unknown")

    # Authority: inherits scope from the superseded receipt's authority
    superseded_authority = superseded_receipt.get("authority_id", "unknown")
    superseded_scope = superseded_receipt.get("authority_scope", "unknown")

    # Reason codes: include override classification if provided
    reason_codes = [
        f"override:supersedes:{superseded_id}",
        f"override:actor:{actor_id}",
    ]
    if override_class:
        reason_codes.append(f"override:class:{override_class}")

    # Policy: inherit from superseded receipt (same policy context)
    policy_id = superseded_receipt.get("policy_id", "unknown")
    policy_hash = superseded_receipt.get("policy_hash", "0" * 64)

    receipt: Dict[str, Any] = {
        "receipt_id": rid,
        "receipt_type": "decision_v1",
        "receipt_version": "0.1.0",
        "timestamp": now,
        "decision_type": "human_authority_override",
        "decision_subject": superseded_receipt.get("decision_subject", "unknown"),
        "verdict": "APPROVE",
        "verdict_reason": justification[:500],
        "verdict_reason_codes": sorted(reason_codes),
        "authority_id": f"human:{actor_id}",
        "authority_class": "OVERRIDING",
        "authority_scope": superseded_scope,
        "delegated_from": superseded_authority,
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "episode_id": ep_id,
        "disposition": "execute",
        "evidence_sufficient": True,
        "provenance_complete": True,
        "supersedes": superseded_id,
        "obligations_created": obligation_ids,
        "source_organ": superseded_receipt.get("source_organ"),
        "confidence": "high",
    }

    # Include reference to the superseded receipt as evidence
    receipt["evidence_refs"] = [
        {
            "ref_type": "receipt",
            "ref_id": superseded_id,
            "ref_role": "superseded",
        }
    ]

    # Carry forward RCV if present in superseded receipt
    rcv = superseded_receipt.get("runtime_condition_vector")
    if rcv:
        receipt["runtime_condition_vector"] = rcv

    return receipt


def validate_override_receipt(receipt: Dict[str, Any]) -> List[str]:
    """Validate an override receipt beyond standard schema checks.

    Returns list of errors (empty = valid). Runs standard Decision Receipt
    validation first, then override-specific checks.
    """
    errors: List[str] = []

    # Standard validation
    result = validate_decision_receipt(receipt)
    if not result.valid:
        errors.extend(e.message for e in result.errors)

    # Override-specific checks
    if receipt.get("authority_class") != "OVERRIDING":
        errors.append("Override receipt must have authority_class=OVERRIDING")

    if receipt.get("decision_type") != "human_authority_override":
        errors.append("Override receipt must have decision_type=human_authority_override")

    if not receipt.get("supersedes"):
        errors.append("Override receipt must supersede a prior receipt")

    obligations = receipt.get("obligations_created") or []
    if not obligations:
        errors.append("Override receipt must create at least one obligation")

    # Check obligation ID format (must be real IDs, not descriptive strings)
    for ob_id in obligations:
        if not ob_id.startswith("OB-"):
            errors.append(f"Obligation ID must start with 'OB-', got: {ob_id!r}")

    justification = receipt.get("verdict_reason") or ""
    if len(justification) < MIN_JUSTIFICATION_LENGTH:
        errors.append(
            f"Override justification must be >= {MIN_JUSTIFICATION_LENGTH} chars"
        )

    return errors


__all__ = [
    "build_override_decision_receipt",
    "validate_override_receipt",
    "MIN_JUSTIFICATION_LENGTH",
]
