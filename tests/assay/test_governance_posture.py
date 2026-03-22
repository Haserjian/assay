"""Governance posture — evaluation, snapshot embedding, and divergence tests.

Tests the second leverage seam: governance posture as artifact truth that
travels with evidence and is surfaced at trust boundaries.

Two distinct truths tested:
  - Production posture: what was governance state when evidence was produced?
  - Current posture: what is governance state now?
  - Divergence: do they differ, and what does that mean?
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from assay.governance_posture import (
    POSTURE_RECEIPT_TYPE,
    DivergenceType,
    GovernancePostureSnapshot,
    PostureDivergence,
    PostureState,
    compute_divergence,
    evaluate_posture,
    extract_production_posture,
)
from assay.obligation import (
    ObligationStore,
    create_override_obligation,
    discharge_obligation,
)


@pytest.fixture
def tmp_store(tmp_path):
    store_dir = tmp_path / ".assay"
    store_dir.mkdir()
    return {
        "obligation_store": ObligationStore(base_dir=store_dir),
        "store_dir": store_dir,
    }


# ---------------------------------------------------------------------------
# Posture evaluation
# ---------------------------------------------------------------------------

class TestPostureEvaluation:
    def test_clean_when_no_obligations(self, tmp_store):
        snapshot = evaluate_posture(obligation_store=tmp_store["obligation_store"])
        assert snapshot.posture == PostureState.CLEAN.value
        assert snapshot.open_count == 0
        assert snapshot.overdue_count == 0
        assert snapshot.obligation_ids == []
        assert snapshot.evaluated_at  # non-empty
        assert snapshot.policy_version  # non-empty
        assert snapshot.derivation_scope == "local_obligation_store"

    def test_debt_outstanding_when_open_not_overdue(self, tmp_store):
        ob = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            due_days=30,
        )
        tmp_store["obligation_store"].save(ob)

        snapshot = evaluate_posture(obligation_store=tmp_store["obligation_store"])
        assert snapshot.posture == PostureState.DEBT_OUTSTANDING.value
        assert snapshot.open_count == 1
        assert snapshot.overdue_count == 0
        assert ob.obligation_id in snapshot.obligation_ids

    def test_debt_overdue_when_past_due(self, tmp_store):
        ob = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            due_days=-1,  # already past
        )
        tmp_store["obligation_store"].save(ob)

        snapshot = evaluate_posture(obligation_store=tmp_store["obligation_store"])
        assert snapshot.posture == PostureState.DEBT_OVERDUE.value
        assert snapshot.overdue_count >= 1

    def test_unknown_on_store_failure(self):
        class BrokenStore:
            def list_pending(self):
                raise RuntimeError("store broken")

        snapshot = evaluate_posture(obligation_store=BrokenStore())
        assert snapshot.posture == PostureState.UNKNOWN.value
        assert "unavailable" in snapshot.derivation_basis.lower()


# ---------------------------------------------------------------------------
# Snapshot receipt format
# ---------------------------------------------------------------------------

class TestSnapshotReceipt:
    def test_receipt_dict_has_required_fields(self, tmp_store):
        snapshot = evaluate_posture(obligation_store=tmp_store["obligation_store"])
        d = snapshot.to_receipt_dict()

        assert d["type"] == POSTURE_RECEIPT_TYPE
        assert d["schema_version"] == "0.1.0"
        assert d["posture"] == "CLEAN"
        assert "evaluated_at" in d
        assert "policy_version" in d
        assert "derivation_scope" in d
        assert "derivation_basis" in d

    def test_round_trip_through_dict(self):
        original = GovernancePostureSnapshot(
            posture="DEBT_OUTSTANDING",
            evaluated_at="2026-03-21T14:00:00Z",
            obligation_ids=["OB-test1", "OB-test2"],
            open_count=2,
            overdue_count=0,
        )
        d = original.to_dict()
        restored = GovernancePostureSnapshot.from_dict(d)
        assert restored.posture == original.posture
        assert restored.obligation_ids == original.obligation_ids
        assert restored.open_count == original.open_count


# ---------------------------------------------------------------------------
# Extract production posture from pack entries
# ---------------------------------------------------------------------------

class TestExtractProductionPosture:
    def test_extract_from_entries(self):
        entries = [
            {"type": "model_call", "receipt_id": "r_1"},
            {
                "type": POSTURE_RECEIPT_TYPE,
                "posture": "CLEAN",
                "evaluated_at": "2026-03-21T14:00:00Z",
                "obligation_ids": [],
                "open_count": 0,
                "overdue_count": 0,
                "policy_version": "governance.obligation.v1",
                "derivation_scope": "local_obligation_store",
                "derivation_basis": "all open obligations at evaluation time",
            },
            {"type": "checkpoint.sealed", "receipt_id": "r_2"},
        ]
        posture = extract_production_posture(entries)
        assert posture is not None
        assert posture.posture == "CLEAN"
        assert posture.open_count == 0

    def test_returns_none_for_old_packs(self):
        entries = [
            {"type": "model_call", "receipt_id": "r_1"},
            {"type": "checkpoint.sealed", "receipt_id": "r_2"},
        ]
        posture = extract_production_posture(entries)
        assert posture is None

    def test_latest_snapshot_wins(self):
        entries = [
            {
                "type": POSTURE_RECEIPT_TYPE,
                "posture": "CLEAN",
                "evaluated_at": "2026-03-21T10:00:00Z",
                "obligation_ids": [],
                "open_count": 0,
                "overdue_count": 0,
            },
            {
                "type": POSTURE_RECEIPT_TYPE,
                "posture": "DEBT_OUTSTANDING",
                "evaluated_at": "2026-03-21T14:00:00Z",
                "obligation_ids": ["OB-new"],
                "open_count": 1,
                "overdue_count": 0,
            },
        ]
        posture = extract_production_posture(entries)
        assert posture.posture == "DEBT_OUTSTANDING"
        assert posture.obligation_ids == ["OB-new"]


# ---------------------------------------------------------------------------
# Divergence detection
# ---------------------------------------------------------------------------

class TestDivergence:

    def _snap(self, posture, **kw):
        return GovernancePostureSnapshot(
            posture=posture,
            evaluated_at=kw.get("evaluated_at", "2026-03-21T14:00:00Z"),
            obligation_ids=kw.get("obligation_ids", []),
            open_count=kw.get("open_count", 0),
            overdue_count=kw.get("overdue_count", 0),
        )

    def test_none_clean_to_clean(self):
        div = compute_divergence(self._snap("CLEAN"), self._snap("CLEAN"))
        assert not div.diverged
        assert div.divergence_type == DivergenceType.NONE.value

    def test_debt_resolved(self):
        div = compute_divergence(
            self._snap("DEBT_OVERDUE", obligation_ids=["OB-1"], overdue_count=1),
            self._snap("CLEAN"),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.DEBT_RESOLVED.value
        assert "resolved" in div.detail.lower()

    def test_debt_resolved_from_outstanding(self):
        div = compute_divergence(
            self._snap("DEBT_OUTSTANDING", obligation_ids=["OB-1"], open_count=1),
            self._snap("CLEAN"),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.DEBT_RESOLVED.value

    def test_debt_accrued(self):
        div = compute_divergence(
            self._snap("CLEAN"),
            self._snap("DEBT_OUTSTANDING", obligation_ids=["OB-new"], open_count=1),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.DEBT_ACCRUED.value
        assert "accrued" in div.detail.lower()

    def test_debt_accrued_to_overdue(self):
        div = compute_divergence(
            self._snap("CLEAN"),
            self._snap("DEBT_OVERDUE", overdue_count=1),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.DEBT_ACCRUED.value

    def test_debt_worsened(self):
        div = compute_divergence(
            self._snap("DEBT_OUTSTANDING", open_count=1),
            self._snap("DEBT_OVERDUE", overdue_count=1),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.DEBT_WORSENED.value
        assert "overdue" in div.detail.lower()

    def test_debt_improved(self):
        div = compute_divergence(
            self._snap("DEBT_OVERDUE", overdue_count=1),
            self._snap("DEBT_OUTSTANDING", open_count=1),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.DEBT_IMPROVED.value

    def test_store_unavailable(self):
        div = compute_divergence(
            self._snap("CLEAN"),
            self._snap("UNKNOWN"),
        )
        assert div.diverged
        assert div.divergence_type == DivergenceType.STORE_UNAVAILABLE.value
        assert "unavailable" in div.detail.lower()

    def test_production_unavailable_clean_current(self):
        div = compute_divergence(None, self._snap("CLEAN"))
        assert not div.diverged  # CLEAN current = not notable
        assert div.divergence_type == DivergenceType.PRODUCTION_UNAVAILABLE.value
        assert div.production_posture == "UNAVAILABLE"

    def test_production_unavailable_debt_current(self):
        div = compute_divergence(None, self._snap("DEBT_OVERDUE", overdue_count=1))
        assert div.diverged
        assert div.divergence_type == DivergenceType.PRODUCTION_UNAVAILABLE.value

    def test_serialization_includes_divergence_type(self):
        div = PostureDivergence(
            production_posture="CLEAN",
            current_posture="DEBT_OUTSTANDING",
            diverged=True,
            divergence_type=DivergenceType.DEBT_ACCRUED.value,
            production_evaluated_at="2026-03-21T10:00:00Z",
            current_evaluated_at="2026-03-21T14:00:00Z",
            detail="Governance debt accrued after pack was produced",
        )
        d = div.to_dict()
        assert d["diverged"] is True
        assert d["divergence_type"] == "DEBT_ACCRUED"
        assert d["detail"] is not None

    def test_same_debt_state_no_divergence(self):
        div = compute_divergence(
            self._snap("DEBT_OUTSTANDING", open_count=1),
            self._snap("DEBT_OUTSTANDING", open_count=2),
        )
        assert not div.diverged
        assert div.divergence_type == DivergenceType.NONE.value


# ---------------------------------------------------------------------------
# Posture emission in seal_checkpoint (integration)
# ---------------------------------------------------------------------------

class TestPostureInSealCheckpoint:
    def test_seal_emits_posture_receipt(self, tmp_path, monkeypatch):
        """seal_checkpoint should emit a governance_posture_snapshot receipt."""
        import assay.obligation as ob_mod
        from assay.episode import open_episode
        from assay.store import AssayStore

        store_dir = tmp_path / ".assay"
        store_dir.mkdir()
        ob_store = ObligationStore(base_dir=store_dir)
        store = AssayStore(base_dir=store_dir)

        # Make ObligationStore() construct with our temp dir
        monkeypatch.setattr(ob_mod, "assay_home", lambda: store_dir)

        ep = open_episode(store=store)
        ep.emit("model_call", {"model": "test", "tokens": 100})

        cp = ep.seal_checkpoint("test posture embedding", output_dir=tmp_path / "pack")
        ep.close()

        # Read the trace and find the posture receipt
        entries = store.read_trace(store.trace_id)
        posture_entries = [e for e in entries if e.get("type") == POSTURE_RECEIPT_TYPE]

        assert len(posture_entries) >= 1
        pe = posture_entries[-1]
        assert pe["posture"] == "CLEAN"
        assert "evaluated_at" in pe

    def test_seal_emits_debt_posture_when_obligations_exist(self, tmp_path, monkeypatch):
        import assay.obligation as ob_mod
        from assay.episode import open_episode
        from assay.store import AssayStore

        store_dir = tmp_path / ".assay"
        store_dir.mkdir()
        ob_store = ObligationStore(base_dir=store_dir)
        store = AssayStore(base_dir=store_dir)

        # Create an open obligation
        ob = create_override_obligation(
            source_receipt_id="r_1",
            superseded_receipt_id="r_0",
            created_by_actor="actor",
            due_days=30,
        )
        ob_store.save(ob)

        monkeypatch.setattr(ob_mod, "assay_home", lambda: store_dir)

        ep = open_episode(store=store)
        ep.emit("model_call", {"model": "test", "tokens": 100})
        cp = ep.seal_checkpoint("test debt posture", output_dir=tmp_path / "pack")
        ep.close()

        entries = store.read_trace(store.trace_id)
        posture_entries = [e for e in entries if e.get("type") == POSTURE_RECEIPT_TYPE]

        assert len(posture_entries) >= 1
        pe = posture_entries[-1]
        assert pe["posture"] == "DEBT_OUTSTANDING"
        assert pe["open_count"] == 1
        assert ob.obligation_id in pe["obligation_ids"]

    def test_posture_extractable_from_sealed_pack(self, tmp_path, monkeypatch):
        """Production posture should be extractable from the sealed pack."""
        import json as _json

        import assay.obligation as ob_mod
        from assay.episode import open_episode
        from assay.store import AssayStore

        store_dir = tmp_path / ".assay"
        store_dir.mkdir()
        store = AssayStore(base_dir=store_dir)

        monkeypatch.setattr(ob_mod, "assay_home", lambda: store_dir)

        ep = open_episode(store=store)
        ep.emit("model_call", {"model": "test", "tokens": 100})
        pack_dir = tmp_path / "pack"
        cp = ep.seal_checkpoint("test extraction", output_dir=pack_dir)
        ep.close()

        # Load entries from the pack
        receipt_path = pack_dir / "receipt_pack.jsonl"
        entries = []
        for line in receipt_path.read_text().splitlines():
            if line.strip():
                entries.append(_json.loads(line))

        posture = extract_production_posture(entries)
        assert posture is not None
        assert posture.posture == "CLEAN"


# ---------------------------------------------------------------------------
# Witness gate (promotion gate — secondary policy)
# ---------------------------------------------------------------------------

class TestWitnessPostureGate:
    """Test the governance posture gate on witness submission.

    This is secondary policy: an optional promotion gate at a trust-escalation
    boundary. The primary doctrine (claim eligibility) is tested elsewhere.
    """

    def _build_pack_with_posture(self, tmp_path, posture, monkeypatch):
        """Build a real pack with a specific governance posture embedded."""
        import assay.obligation as ob_mod
        from assay.episode import open_episode
        from assay.store import AssayStore

        store_dir = tmp_path / ".assay"
        store_dir.mkdir(exist_ok=True)
        ob_store = ObligationStore(base_dir=store_dir)
        store = AssayStore(base_dir=store_dir)

        if posture in ("DEBT_OUTSTANDING", "DEBT_OVERDUE"):
            due_days = 30 if posture == "DEBT_OUTSTANDING" else -1
            ob = create_override_obligation(
                source_receipt_id="r_1",
                superseded_receipt_id="r_0",
                created_by_actor="actor",
                due_days=due_days,
            )
            ob_store.save(ob)

        monkeypatch.setattr(ob_mod, "assay_home", lambda: store_dir)

        ep = open_episode(store=store)
        ep.emit("model_call", {"model": "test", "tokens": 100})
        pack_dir = tmp_path / "pack"
        ep.seal_checkpoint("test", output_dir=pack_dir)
        ep.close()
        return pack_dir

    def test_witness_blocked_on_debt_overdue(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from assay.commands import assay_app

        pack_dir = self._build_pack_with_posture(tmp_path, "DEBT_OVERDUE", monkeypatch)
        runner = CliRunner()
        result = runner.invoke(assay_app, ["witness", str(pack_dir), "--json"])

        assert result.exit_code == 1
        import json as _json
        out = _json.loads(result.output)
        assert out["status"] == "blocked"
        assert out["error"] == "governance_posture_gate"
        assert out["production_posture"] == "DEBT_OVERDUE"

    def test_witness_proceeds_with_acknowledge_debt(self, tmp_path, monkeypatch):
        """--acknowledge-debt bypasses the gate."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        pack_dir = self._build_pack_with_posture(tmp_path, "DEBT_OVERDUE", monkeypatch)
        runner = CliRunner()
        # Will fail with exit 2 (TSA network error), NOT exit 1 (posture gate)
        result = runner.invoke(assay_app, [
            "witness", str(pack_dir), "--acknowledge-debt", "--json",
        ])
        assert result.exit_code != 1, f"Should bypass posture gate, got exit {result.exit_code}"

    def test_witness_warns_on_debt_outstanding(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from assay.commands import assay_app

        pack_dir = self._build_pack_with_posture(tmp_path, "DEBT_OUTSTANDING", monkeypatch)
        runner = CliRunner()
        result = runner.invoke(assay_app, ["witness", str(pack_dir)])
        assert result.exit_code != 1, f"DEBT_OUTSTANDING should warn, not block"
        assert "DEBT_OUTSTANDING" in result.output

    def test_witness_clean_posture_no_warning(self, tmp_path, monkeypatch):
        from typer.testing import CliRunner
        from assay.commands import assay_app

        pack_dir = self._build_pack_with_posture(tmp_path, "CLEAN", monkeypatch)
        runner = CliRunner()
        result = runner.invoke(assay_app, ["witness", str(pack_dir)])
        assert result.exit_code != 1
        assert "DEBT" not in result.output
