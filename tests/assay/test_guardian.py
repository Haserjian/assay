"""
Tests for Assay Guardian rules.
"""
from __future__ import annotations


from assay.guardian import (
    no_coherence_by_dignity_debt,
    no_action_without_receipt,
)


class TestNoCoherenceByDignityDebt:
    """Tests for the core dignity invariant."""

    def test_blocks_coherence_gain_with_dignity_loss(self) -> None:
        """Positive coherence delta + negative dignity delta = BLOCKED."""
        verdict = no_coherence_by_dignity_debt(
            coherence_delta=0.1,
            dignity_delta=-0.05,
        )

        assert verdict.allowed is False
        assert verdict.reason == "COHERENCE_BY_DIGNITY_DEBT"
        assert verdict.clause0_violation is True

    def test_allows_coherence_gain_with_neutral_dignity(self) -> None:
        """Positive coherence delta + zero dignity delta = ALLOWED."""
        verdict = no_coherence_by_dignity_debt(
            coherence_delta=0.1,
            dignity_delta=0.0,
        )

        assert verdict.allowed is True
        assert verdict.clause0_violation is False

    def test_allows_coherence_gain_with_dignity_gain(self) -> None:
        """Positive coherence delta + positive dignity delta = ALLOWED."""
        verdict = no_coherence_by_dignity_debt(
            coherence_delta=0.1,
            dignity_delta=0.05,
        )

        assert verdict.allowed is True

    def test_allows_coherence_loss_with_dignity_loss(self) -> None:
        """Negative coherence delta + negative dignity delta = ALLOWED (not gaming)."""
        verdict = no_coherence_by_dignity_debt(
            coherence_delta=-0.1,
            dignity_delta=-0.05,
        )

        assert verdict.allowed is True

    def test_allows_neutral_coherence(self) -> None:
        """Zero coherence delta = ALLOWED regardless of dignity."""
        verdict = no_coherence_by_dignity_debt(
            coherence_delta=0.0,
            dignity_delta=-0.1,
        )

        assert verdict.allowed is True


class TestNoActionWithoutReceipt:
    """Tests for the auditability invariant."""

    def test_blocks_action_without_receipt(self) -> None:
        """Action without receipt = BLOCKED."""
        verdict = no_action_without_receipt(
            has_receipt=False,
            action_type="shell",
        )

        assert verdict.allowed is False
        assert "NO_RECEIPT" in verdict.reason
        assert verdict.clause0_violation is False

    def test_allows_action_with_receipt(self) -> None:
        """Action with receipt = ALLOWED."""
        verdict = no_action_without_receipt(
            has_receipt=True,
            action_type="shell",
        )

        assert verdict.allowed is True
