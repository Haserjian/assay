"""Receipt succession law — Stage 4, Row 3 enforcement.

Encodes the governance-sensitive subset of the succession allowlist as a
Python dict consulted at write time. This is the boring shape: one dict,
one guard, one hook point.

Scope (P0): only pairs where the successor is ``decision_v1``.  Non-governance
successors are out of scope for Stage 4.  The settlement state machine already
enforces its own succession via ``LEGAL_TRANSITIONS`` in transitions.py — that
enforcement is left untouched.

The allowlist is keyed by ``(predecessor_kind, successor_kind)`` where
``predecessor_kind`` is ``None`` if no predecessor exists (empty episode trace).

All predecessor strings are verified emitted ``receipt_type`` values:
  - ``"refusal"``             — confirmed at ccio engine/pipeline/common.py
  - ``"contradiction.resolved"`` — confirmed in contradiction_detector.py
  - ``"episode.opened"``      — confirmed in episode.py _emit_lifecycle
  - ``"checkpoint.sealed"``   — confirmed in checkpoints.py
  - ``"contradiction.registered"`` — confirmed in contradiction_detector.py
  - ``None``                  — sentinel for empty trace (no predecessor)

Row 3 Stage 4.  Follows ReceiptSuppressionError(RuntimeError) and
TierEscalationError(ValueError) naming pattern.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Tuple


# ---------------------------------------------------------------------------
# Sentinel set — only these successors are enforced by this module
# ---------------------------------------------------------------------------

GOVERNANCE_SENSITIVE_SUCCESSORS: FrozenSet[str] = frozenset({"decision_v1"})


# ---------------------------------------------------------------------------
# Allowlist — (predecessor_kind, successor_kind) -> bool
#
# True  = explicitly allowed
# False = explicitly denied
# Absent = UNKNOWN → fail closed (treated as denied)
#
# Only ``decision_v1`` successor pairs are present.
# ---------------------------------------------------------------------------

RECEIPT_SUCCESSION_ALLOWLIST: Dict[Tuple[Optional[str], str], bool] = {
    # Authorized predecessor paths → decision_v1
    ("refusal", "decision_v1"): True,
    ("contradiction.resolved", "decision_v1"): True,
    # Explicitly denied: direct emission without a qualifying predecessor
    (None, "decision_v1"): False,
    ("episode.opened", "decision_v1"): False,
    ("checkpoint.sealed", "decision_v1"): False,
    ("contradiction.registered", "decision_v1"): False,
}


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class ReceiptSuccessionError(ValueError):
    """Raised when a receipt emission violates the succession allowlist.

    A ``decision_v1`` receipt may only follow a qualifying predecessor
    (``refusal`` or ``contradiction.resolved``).  Direct emission after an
    unqualified predecessor — or from an empty trace — is a constitutional
    violation.

    Row 3 Stage 4.  Follows TierEscalationError(ValueError) naming pattern
    (Stage 2).
    """


# ---------------------------------------------------------------------------
# Policy lookup — tri-state
# ---------------------------------------------------------------------------

def lookup_successor_policy(
    predecessor_kind: Optional[str],
    successor_kind: str,
) -> Optional[bool]:
    """Return the allowlist policy for this pair, or None if unknown.

    Returns:
        True   — explicitly allowed
        False  — explicitly denied
        None   — not present in allowlist (unknown)

    Unknown means the allowlist has no opinion on this pair.  Callers that
    enforce governance constraints MUST treat None as denied (fail closed).
    Unknown is NOT a safe default — it is the absence of a policy declaration.
    """
    return RECEIPT_SUCCESSION_ALLOWLIST.get((predecessor_kind, successor_kind))


# ---------------------------------------------------------------------------
# Write-time guard
# ---------------------------------------------------------------------------

def require_allowed_successor(
    predecessor_kind: Optional[str],
    successor_kind: str,
) -> None:
    """Raise ReceiptSuccessionError if this succession is not explicitly allowed.

    Only enforced for governance-sensitive successors (currently ``decision_v1``).
    Non-sensitive successors pass unconditionally — this guard is scoped to
    the governance layer, not every receipt pair in the system.

    For governance-sensitive successors the tri-state policy applies:
      - True  → allowed, return
      - False → denied, raise
      - None  → unknown, raise (fail closed — unknown ≠ allowed)

    Args:
        predecessor_kind: ``receipt_type`` of the immediately preceding receipt
            in the episode trace, or ``None`` if the trace is empty.
        successor_kind: ``receipt_type`` about to be emitted.

    Raises:
        ReceiptSuccessionError: If the succession is denied or unknown.
    """
    if successor_kind not in GOVERNANCE_SENSITIVE_SUCCESSORS:
        return  # out of scope for Stage 4

    policy = lookup_successor_policy(predecessor_kind, successor_kind)

    if policy is True:
        return  # explicitly allowed

    if policy is False:
        raise ReceiptSuccessionError(
            f"Receipt succession denied: {predecessor_kind!r} → {successor_kind!r} "
            f"is not an authorized path to {successor_kind!r}. "
            f"Authorized predecessors: {_authorized_predecessors(successor_kind)}. "
            "(Row 3 Stage 4 — aggregation does not create authority.)"
        )

    # policy is None — unknown pair, fail closed
    raise ReceiptSuccessionError(
        f"Receipt succession unknown: {predecessor_kind!r} → {successor_kind!r} "
        f"has no declared policy. Unknown is not allowed (fail closed). "
        f"Authorized predecessors: {_authorized_predecessors(successor_kind)}. "
        "(Row 3 Stage 4 — unknown authority_class cannot be assumed inapplicable.)"
    )


def _authorized_predecessors(successor_kind: str) -> list:
    """Return the list of explicitly allowed predecessor kinds for a successor."""
    return sorted(
        str(pred) for (pred, succ), allowed in RECEIPT_SUCCESSION_ALLOWLIST.items()
        if succ == successor_kind and allowed is True
    )


__all__ = [
    "GOVERNANCE_SENSITIVE_SUCCESSORS",
    "RECEIPT_SUCCESSION_ALLOWLIST",
    "ReceiptSuccessionError",
    "lookup_successor_policy",
    "require_allowed_successor",
]
