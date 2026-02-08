"""
Assay Guardian rules.

Core principle: No coherence gain by dignity debt.

You cannot increase system coherence (internal consistency, goal achievement)
by pushing harm onto others. This is the "externality prohibition" for AI systems.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GuardianVerdict:
    """
    Result of a Guardian rule check.

    Attributes:
        allowed: Whether the action is permitted
        reason: Human-readable explanation
        clause0_violation: Whether this violates the fundamental dignity clause
    """
    allowed: bool
    reason: str = "OK"
    clause0_violation: bool = False


def no_coherence_by_dignity_debt(
    coherence_delta: float,
    dignity_delta: float,
) -> GuardianVerdict:
    """
    Forbidden move: increasing coherence by pushing hidden suffering.

    This is the core invariant that prevents AI systems from gaming
    their own metrics by externalizing harm. In Loom terms:
    "Delta-C cannot be purchased with Clause-0 violations."

    Args:
        coherence_delta: Change in system coherence (positive = more coherent)
        dignity_delta: Change in dignity score (negative = harm externalized)

    Returns:
        GuardianVerdict indicating whether the move is allowed

    Examples:
        >>> no_coherence_by_dignity_debt(0.1, -0.05)  # Coherence up, dignity down
        GuardianVerdict(allowed=False, reason='COHERENCE_BY_DIGNITY_DEBT', clause0_violation=True)

        >>> no_coherence_by_dignity_debt(0.1, 0.0)  # Coherence up, dignity neutral
        GuardianVerdict(allowed=True, reason='OK', clause0_violation=False)

        >>> no_coherence_by_dignity_debt(-0.1, -0.05)  # Both down - allowed (not gaming)
        GuardianVerdict(allowed=True, reason='OK', clause0_violation=False)
    """
    if coherence_delta > 0 and dignity_delta < 0:
        return GuardianVerdict(
            allowed=False,
            reason="COHERENCE_BY_DIGNITY_DEBT",
            clause0_violation=True,
        )
    return GuardianVerdict(allowed=True)


def no_action_without_receipt(
    has_receipt: bool,
    action_type: str,
) -> GuardianVerdict:
    """
    Every action must emit a receipt.

    The "No Action Without Receipt" invariant ensures auditability.
    Actions without receipts are invisible to governance.

    Args:
        has_receipt: Whether a receipt will be emitted
        action_type: Type of action being attempted

    Returns:
        GuardianVerdict indicating whether the action is allowed
    """
    if not has_receipt:
        return GuardianVerdict(
            allowed=False,
            reason=f"NO_RECEIPT_FOR_{action_type.upper()}",
            clause0_violation=False,
        )
    return GuardianVerdict(allowed=True)


__all__ = [
    "GuardianVerdict",
    "no_coherence_by_dignity_debt",
    "no_action_without_receipt",
]
