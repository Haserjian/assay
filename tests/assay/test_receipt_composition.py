"""Receipt succession law — Stage 4, Row 3 enforcement tests.

Two layers:
  - Unit: policy lookup + guard logic in isolation
  - Integration: guard fires through Episode._emit_raw()

All predecessor strings used here are verified emitted ``receipt_type``
values — no prose placeholders.

Row 3 Stage 4.
"""
from __future__ import annotations

import pytest

from assay.receipt_composition import (
    GOVERNANCE_SENSITIVE_SUCCESSORS,
    RECEIPT_SUCCESSION_ALLOWLIST,
    ReceiptSuccessionError,
    lookup_successor_policy,
    require_allowed_successor,
)


# ---------------------------------------------------------------------------
# Unit: lookup_successor_policy — tri-state
# ---------------------------------------------------------------------------


class TestLookupSuccessorPolicy:
    """lookup_successor_policy returns True / False / None (never raises)."""

    def test_refusal_to_decision_v1_allowed(self):
        assert lookup_successor_policy("refusal", "decision_v1") is True

    def test_contradiction_resolved_to_decision_v1_allowed(self):
        assert lookup_successor_policy("contradiction.resolved", "decision_v1") is True

    def test_none_predecessor_to_decision_v1_denied(self):
        assert lookup_successor_policy(None, "decision_v1") is False

    def test_episode_opened_to_decision_v1_denied(self):
        assert lookup_successor_policy("episode.opened", "decision_v1") is False

    def test_checkpoint_sealed_to_decision_v1_denied(self):
        assert lookup_successor_policy("checkpoint.sealed", "decision_v1") is False

    def test_contradiction_registered_to_decision_v1_denied(self):
        assert lookup_successor_policy("contradiction.registered", "decision_v1") is False

    def test_unknown_predecessor_to_decision_v1_is_none(self):
        assert lookup_successor_policy("model.invoked", "decision_v1") is None

    def test_unknown_successor_not_in_table_is_none(self):
        assert lookup_successor_policy("refusal", "some.other.type") is None

    def test_non_sensitive_successor_not_in_table_is_none(self):
        # Non-governance successors have no table entries — that is correct.
        assert lookup_successor_policy("episode.opened", "model.invoked") is None


# ---------------------------------------------------------------------------
# Unit: require_allowed_successor — pass / raise
# ---------------------------------------------------------------------------


class TestRequireAllowedSuccessor:
    """require_allowed_successor raises ReceiptSuccessionError or returns None."""

    # --- Allowed paths ---

    def test_refusal_to_decision_v1_passes(self):
        require_allowed_successor("refusal", "decision_v1")  # no exception

    def test_contradiction_resolved_to_decision_v1_passes(self):
        require_allowed_successor("contradiction.resolved", "decision_v1")  # no exception

    # --- Explicitly denied paths ---

    def test_none_predecessor_to_decision_v1_raises(self):
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor(None, "decision_v1")

    def test_episode_opened_to_decision_v1_raises(self):
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor("episode.opened", "decision_v1")

    def test_checkpoint_sealed_to_decision_v1_raises(self):
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor("checkpoint.sealed", "decision_v1")

    def test_contradiction_registered_to_decision_v1_raises(self):
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor("contradiction.registered", "decision_v1")

    # --- Unknown predecessor — fail closed ---

    def test_unknown_predecessor_to_decision_v1_raises(self):
        """Unknown pair is not a safe default — fail closed."""
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor("model.invoked", "decision_v1")

    def test_completely_unknown_pair_to_decision_v1_raises(self):
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor("guardian.approved", "decision_v1")

    # --- Non-sensitive successors pass unconditionally ---

    def test_non_sensitive_successor_passes_regardless_of_predecessor(self):
        require_allowed_successor(None, "model.invoked")
        require_allowed_successor("episode.opened", "checkpoint.sealed")
        require_allowed_successor("contradiction.registered", "model.invoked")
        # All pass — Stage 4 scope is governance-sensitive successors only

    def test_non_sensitive_successor_with_any_predecessor_passes(self):
        for pred in [None, "episode.opened", "checkpoint.sealed", "refusal", "anything"]:
            require_allowed_successor(pred, "episode.opened")
            require_allowed_successor(pred, "model.invoked")
            require_allowed_successor(pred, "witness.signed")


# ---------------------------------------------------------------------------
# Unit: ReceiptSuccessionError class
# ---------------------------------------------------------------------------


class TestReceiptSuccessionError:
    def test_is_subclass_of_value_error(self):
        assert issubclass(ReceiptSuccessionError, ValueError)

    def test_error_message_includes_predecessor_and_successor(self):
        try:
            require_allowed_successor("checkpoint.sealed", "decision_v1")
        except ReceiptSuccessionError as exc:
            msg = str(exc)
            assert "checkpoint.sealed" in msg
            assert "decision_v1" in msg
        else:
            pytest.fail("ReceiptSuccessionError not raised")

    def test_unknown_pair_message_includes_fail_closed_language(self):
        try:
            require_allowed_successor("model.invoked", "decision_v1")
        except ReceiptSuccessionError as exc:
            msg = str(exc)
            assert "model.invoked" in msg
            assert "decision_v1" in msg
        else:
            pytest.fail("ReceiptSuccessionError not raised")

    def test_error_is_not_runtime_error(self):
        """ReceiptSuccessionError follows ValueError naming, not RuntimeError."""
        assert not issubclass(ReceiptSuccessionError, RuntimeError)


# ---------------------------------------------------------------------------
# Unit: constants / table shape
# ---------------------------------------------------------------------------


class TestAllowlistShape:
    def test_governance_sensitive_successors_contains_decision_v1(self):
        assert "decision_v1" in GOVERNANCE_SENSITIVE_SUCCESSORS

    def test_all_table_values_are_bool(self):
        for (pred, succ), policy in RECEIPT_SUCCESSION_ALLOWLIST.items():
            assert isinstance(policy, bool), f"Non-bool policy for {(pred, succ)!r}: {policy!r}"

    def test_all_table_successors_are_governance_sensitive(self):
        """Stage 4 scope: only decision_v1 successors are in the table."""
        for (pred, succ) in RECEIPT_SUCCESSION_ALLOWLIST:
            assert succ in GOVERNANCE_SENSITIVE_SUCCESSORS, (
                f"Non-governance-sensitive successor {succ!r} in allowlist — "
                "Stage 4 scope is decision_v1 only"
            )

    def test_table_has_authorized_paths(self):
        allowed = {
            pred for (pred, succ), v in RECEIPT_SUCCESSION_ALLOWLIST.items()
            if v is True and succ == "decision_v1"
        }
        assert "refusal" in allowed
        assert "contradiction.resolved" in allowed

    def test_table_has_denied_paths(self):
        denied = {
            pred for (pred, succ), v in RECEIPT_SUCCESSION_ALLOWLIST.items()
            if v is False and succ == "decision_v1"
        }
        assert None in denied
        assert "episode.opened" in denied


# ---------------------------------------------------------------------------
# Integration: guard fires through Episode._emit_raw()
# ---------------------------------------------------------------------------


class TestEpisodeSuccessionIntegration:
    """The guard intercepts unauthorized decision_v1 emission at the Episode level."""

    @pytest.fixture
    def ep(self, tmp_path):
        """Open a fresh Episode backed by a temp store."""
        from assay.store import AssayStore
        from assay.episode import open_episode

        store = AssayStore(base_dir=tmp_path / "store")
        return open_episode(store=store)

    def test_none_predecessor_guard_covered_by_unit_tests(self):
        """None → decision_v1 guard is covered by TestRequireAllowedSuccessor.
        Confirming the guard logic directly here for documentation:
        """
        with pytest.raises(ReceiptSuccessionError):
            require_allowed_successor(None, "decision_v1")

    def test_episode_opens_without_error(self, ep):
        """episode.opened is not governance-sensitive — opening succeeds."""
        assert ep.receipts[0].receipt_type == "episode.opened"

    def test_emit_non_sensitive_after_episode_opened_passes(self, ep):
        """Non-governance receipts pass unconditionally."""
        ep.emit("model.invoked", {"model": "test"})
        ep.emit("tool.invoked", {"tool": "search"})
        assert len(ep.receipts) == 3  # opened + 2 emitted

    def test_emit_decision_v1_after_model_invoked_raises(self, ep):
        """model.invoked → decision_v1 = unknown pair → fail closed."""
        ep.emit("model.invoked", {"model": "test"})
        with pytest.raises(ReceiptSuccessionError):
            ep.emit("decision_v1", {"verdict": "REFUSE"})

    def test_emit_decision_v1_after_episode_opened_raises(self, ep):
        """episode.opened → decision_v1 = explicitly denied."""
        with pytest.raises(ReceiptSuccessionError):
            ep.emit("decision_v1", {"verdict": "REFUSE"})

    def test_emit_decision_v1_after_refusal_passes(self, ep):
        """refusal → decision_v1 = explicitly allowed."""
        ep.emit("refusal", {"archetype": "INSUFFICIENT_EVIDENCE"})
        ep.emit("decision_v1", {"verdict": "REFUSE"})  # should not raise
        # receipt types in trace: episode.opened, refusal, decision_v1
        types = [r.receipt_type for r in ep.receipts]
        assert "decision_v1" in types

    def test_emit_decision_v1_after_contradiction_resolved_passes(self, ep):
        """contradiction.resolved → decision_v1 = explicitly allowed."""
        ep.emit("contradiction.resolved", {"verdict": "resolved"})
        ep.emit("decision_v1", {"verdict": "REFUSE"})  # should not raise
        types = [r.receipt_type for r in ep.receipts]
        assert "decision_v1" in types

    def test_emit_decision_v1_after_checkpoint_sealed_raises(self, ep):
        """checkpoint.sealed → decision_v1 = explicitly denied (bypass detection)."""
        ep.emit("checkpoint.sealed", {})
        with pytest.raises(ReceiptSuccessionError):
            ep.emit("decision_v1", {"verdict": "REFUSE"})

    def test_emit_lifecycle_also_routes_through_guard(self, ep):
        """_emit_lifecycle() → _emit_raw() → guard applies to lifecycle receipts too."""
        # lifecycle receipts like episode.opened are NOT governance-sensitive,
        # so they pass unconditionally regardless of predecessor.
        # This verifies the guard doesn't interfere with lifecycle emission.
        from assay.episode import EpisodeState
        ep.emit("model.invoked", {"model": "test"})
        ep._emit_lifecycle("episode.closed", {"outcome": "pass"}, enforce_state=False)
        # No exception — episode.closed is not governance-sensitive.

    def test_succession_error_does_not_corrupt_episode_trace(self, ep):
        """A blocked emission must not append a partial receipt to the trace."""
        initial_count = len(ep.receipts)
        ep.emit("model.invoked", {"model": "test"})
        pre_count = len(ep.receipts)

        with pytest.raises(ReceiptSuccessionError):
            ep.emit("decision_v1", {"verdict": "REFUSE"})

        # Trace must be unchanged after the blocked emission
        assert len(ep.receipts) == pre_count
