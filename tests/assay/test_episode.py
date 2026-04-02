"""
Tests for the Episode SDK (Mode 2: Runtime, Mode 3: Settlement).

Tests the episode lifecycle, receipt emission, checkpoint sealing,
and verdict verification — the bridge from CLI-shaped packaging
to organism-shaped runtime evidence.
"""

import json
from pathlib import Path

import pytest

from assay.episode import (
    Checkpoint,
    EpisodeClosedError,
    Verdict,
    open_episode,
    verify_checkpoint,
    verify_pack,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.store import AssayStore


@pytest.fixture
def tmp_store(tmp_path):
    """Create a temporary AssayStore for test isolation."""
    return AssayStore(base_dir=tmp_path / "assay_store")


# ---------------------------------------------------------------------------
# Episode lifecycle
# ---------------------------------------------------------------------------


class TestEpisodeLifecycle:
    """Basic episode open/emit/close."""

    def test_open_episode_creates_trace(self, tmp_store):
        ep = open_episode(store=tmp_store)
        assert ep.episode_id.startswith("ep_")
        assert ep.trace_id.startswith("trace_")
        assert not ep.closed

    def test_open_episode_with_explicit_id(self, tmp_store):
        ep = open_episode(episode_id="ep_custom_001", store=tmp_store)
        assert ep.episode_id == "ep_custom_001"

    def test_open_episode_emits_opened_receipt(self, tmp_store):
        ep = open_episode(
            policy_version="v2.1",
            guardian_profile="strict",
            risk_class="high",
            store=tmp_store,
        )
        entries = tmp_store.read_trace(ep.trace_id)
        assert len(entries) >= 1
        opened = entries[0]
        assert opened["type"] == "episode.opened"
        assert opened["episode_id"] == ep.episode_id
        assert opened["policy_version"] == "v2.1"
        assert opened["guardian_profile"] == "strict"
        assert opened["risk_class"] == "high"

    def test_close_emits_closed_receipt(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.close(status="completed")
        assert ep.closed

        entries = tmp_store.read_trace(ep.trace_id)
        closed = [e for e in entries if e["type"] == "episode.closed"]
        assert len(closed) == 1
        assert closed[0]["status"] == "completed"

    def test_close_is_idempotent(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.close()
        ep.close()  # should not raise or emit duplicate
        entries = tmp_store.read_trace(ep.trace_id)
        closed = [e for e in entries if e["type"] == "episode.closed"]
        assert len(closed) == 1

    def test_close_with_summary(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.close(summary={"actions_taken": 3, "outcome": "success"})
        entries = tmp_store.read_trace(ep.trace_id)
        closed = [e for e in entries if e["type"] == "episode.closed"][0]
        assert closed["summary"]["actions_taken"] == 3

    def test_context_manager_closes_on_exit(self, tmp_store):
        with open_episode(store=tmp_store) as ep:
            ep.emit("step.started", {"step": "test"})
        assert ep.closed
        entries = tmp_store.read_trace(ep.trace_id)
        closed = [e for e in entries if e["type"] == "episode.closed"]
        assert len(closed) == 1
        assert closed[0]["status"] == "completed"

    def test_context_manager_marks_failed_on_exception(self, tmp_store):
        with pytest.raises(ValueError):
            with open_episode(store=tmp_store) as ep:
                ep.emit("step.started", {"step": "test"})
                raise ValueError("boom")
        assert ep.closed
        entries = tmp_store.read_trace(ep.trace_id)
        closed = [e for e in entries if e["type"] == "episode.closed"]
        assert len(closed) == 1
        assert closed[0]["status"] == "failed"


# ---------------------------------------------------------------------------
# Receipt emission
# ---------------------------------------------------------------------------


class TestReceiptEmission:
    """Emit receipts and verify trace contents."""

    def test_emit_returns_receipt_id(self, tmp_store):
        ep = open_episode(store=tmp_store)
        rid = ep.emit("model.invoked", {"model": "gpt-4"})
        assert rid.startswith("r_")

    def test_emit_writes_to_trace(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4", "tokens": 800})
        entries = tmp_store.read_trace(ep.trace_id)
        model_calls = [e for e in entries if e["type"] == "model.invoked"]
        assert len(model_calls) == 1
        assert model_calls[0]["model"] == "gpt-4"
        assert model_calls[0]["episode_id"] == ep.episode_id

    def test_emit_causal_linking(self, tmp_store):
        ep = open_episode(store=tmp_store)
        r1 = ep.emit("model.invoked", {"model": "gpt-4"})
        r2 = ep.emit("guardian.approved", {"action": "send"}, parent_receipt_id=r1)
        entries = tmp_store.read_trace(ep.trace_id)
        guardian = [e for e in entries if e["type"] == "guardian.approved"][0]
        assert guardian["parent_receipt_id"] == r1

    def test_emit_increments_receipt_count(self, tmp_store):
        ep = open_episode(store=tmp_store)
        assert ep.receipt_count == 1  # episode.opened
        ep.emit("step.started")
        assert ep.receipt_count == 2
        ep.emit("step.completed")
        assert ep.receipt_count == 3

    def test_emit_after_close_raises(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.close()
        with pytest.raises(EpisodeClosedError):
            ep.emit("step.started")

    def test_emit_without_data(self, tmp_store):
        ep = open_episode(store=tmp_store)
        rid = ep.emit("step.started")
        assert rid.startswith("r_")
        entries = tmp_store.read_trace(ep.trace_id)
        step = [e for e in entries if e["type"] == "step.started"]
        assert len(step) == 1

    def test_all_receipts_have_episode_id(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        ep.emit("tool.invoked", {"tool": "search"})
        ep.emit("guardian.approved")
        ep.close()
        entries = tmp_store.read_trace(ep.trace_id)
        for entry in entries:
            assert entry.get("episode_id") == ep.episode_id

    def test_all_receipts_have_schema_version(self, tmp_store):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked")
        ep.close()
        entries = tmp_store.read_trace(ep.trace_id)
        for entry in entries:
            assert entry.get("schema_version") == "3.0"

    def test_data_cannot_overwrite_structural_fields(self, tmp_store):
        """User data must not clobber receipt_id, type, episode_id, etc."""
        ep = open_episode(store=tmp_store)
        rid = ep.emit(
            "model.invoked",
            {
                "receipt_id": "SHOULD_BE_IGNORED",
                "type": "SHOULD_BE_IGNORED",
                "episode_id": "SHOULD_BE_IGNORED",
                "schema_version": "SHOULD_BE_IGNORED",
                "model": "gpt-4",
            },
        )
        entries = tmp_store.read_trace(ep.trace_id)
        model_call = [e for e in entries if e.get("model") == "gpt-4"][0]
        assert model_call["receipt_id"] == rid
        assert model_call["receipt_id"] != "SHOULD_BE_IGNORED"
        assert model_call["type"] == "model.invoked"
        assert model_call["episode_id"] == ep.episode_id
        assert model_call["schema_version"] == "3.0"


# ---------------------------------------------------------------------------
# Checkpoint sealing
# ---------------------------------------------------------------------------


class TestCheckpointSealing:
    """Seal checkpoints into proof packs."""

    def test_seal_creates_pack_directory(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        cp = ep.seal_checkpoint(
            reason="test_seal",
            output_dir=tmp_path / "test_pack",
        )
        assert isinstance(cp, Checkpoint)
        assert cp.pack_dir.exists()
        assert cp.reason == "test_seal"
        assert cp.episode_id == ep.episode_id
        assert cp.receipt_count >= 2  # opened + model.invoked + checkpoint.sealed

    def test_seal_produces_5_file_kernel(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        cp = ep.seal_checkpoint(output_dir=tmp_path / "test_pack")
        expected_files = {
            "receipt_pack.jsonl",
            "pack_manifest.json",
            "pack_signature.sig",
            "verify_report.json",
            "verify_transcript.md",
        }
        actual_files = {f.name for f in cp.pack_dir.iterdir() if f.is_file()}
        assert expected_files.issubset(actual_files)

    def test_seal_emits_checkpoint_receipt(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("step.started")
        ep.seal_checkpoint(
            reason="before_action",
            output_dir=tmp_path / "test_pack",
        )
        entries = tmp_store.read_trace(ep.trace_id)
        sealed = [e for e in entries if e["type"] == "checkpoint.sealed"]
        assert len(sealed) == 1
        assert sealed[0]["reason"] == "before_action"
        assert sealed[0]["checkpoint_number"] == 1

    def test_multiple_checkpoints(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("step.started", {"phase": "plan"})
        cp1 = ep.seal_checkpoint(
            reason="after_plan",
            output_dir=tmp_path / "pack_1",
        )
        ep.emit("step.started", {"phase": "execute"})
        cp2 = ep.seal_checkpoint(
            reason="after_execute",
            output_dir=tmp_path / "pack_2",
        )
        assert cp1.pack_dir != cp2.pack_dir
        assert cp1.pack_dir.exists()
        assert cp2.pack_dir.exists()
        # Second pack should have more receipts
        assert cp2.receipt_count > cp1.receipt_count

    def test_seal_after_close_raises(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.close()
        with pytest.raises(EpisodeClosedError):
            ep.seal_checkpoint(output_dir=tmp_path / "test_pack")

    def test_checkpoint_receipts_in_pack(self, tmp_store, tmp_path):
        """All emitted receipts appear in the sealed pack."""
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        ep.emit("guardian.approved", {"action": "send"})
        cp = ep.seal_checkpoint(output_dir=tmp_path / "test_pack")

        pack_receipts = []
        for line in (cp.pack_dir / "receipt_pack.jsonl").read_text().splitlines():
            if line.strip():
                pack_receipts.append(json.loads(line))

        types = {r["type"] for r in pack_receipts}
        assert "episode.opened" in types
        assert "model.invoked" in types
        assert "guardian.approved" in types
        assert "checkpoint.sealed" in types


# ---------------------------------------------------------------------------
# Verification / Settlement
# ---------------------------------------------------------------------------


class TestVerification:
    """Verify checkpoints and produce verdicts."""

    def _build_external_pack_with_unknown_type(
        self, tmp_path: Path, monkeypatch
    ) -> Path:
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        ks.generate_key("episode-test-signer")
        entries = [
            {
                "receipt_id": "r_episode_001",
                "type": "model_call",
                "timestamp": "2026-04-02T00:00:00+00:00",
                "schema_version": "3.0",
                "seq": 0,
            },
            {
                "receipt_id": "r_episode_002",
                "type": "experimental_verdict",
                "timestamp": "2026-04-02T00:00:01+00:00",
                "schema_version": "3.0",
                "seq": 1,
            },
        ]
        with monkeypatch.context() as context:
            context.setattr(
                "assay.proof_pack._assert_allowed_receipt_types", lambda entries: None
            )
            pack = ProofPack(
                run_id="episode-foreign-pack",
                entries=entries,
                signer_id="episode-test-signer",
            )
            return pack.build(tmp_path / "foreign_pack", keystore=ks)

    def test_verify_checkpoint_pass(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        cp = ep.seal_checkpoint(output_dir=tmp_path / "test_pack")
        verdict = verify_checkpoint(cp)
        assert isinstance(verdict, Verdict)
        assert verdict.ok is True
        assert verdict.integrity_pass is True
        assert verdict.honest_fail is False

    def test_verify_pack_directly(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        cp = ep.seal_checkpoint(output_dir=tmp_path / "test_pack")
        verdict = verify_pack(cp.pack_dir)
        assert verdict.ok is True

    def test_verify_detects_tamper(self, tmp_store, tmp_path):
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        cp = ep.seal_checkpoint(output_dir=tmp_path / "test_pack")

        # Tamper: modify receipt_pack.jsonl
        receipt_file = cp.pack_dir / "receipt_pack.jsonl"
        original = receipt_file.read_text()
        receipt_file.write_text(original.replace("gpt-4", "gpt-3.5-turbo"))

        verdict = verify_pack(cp.pack_dir)
        assert verdict.integrity_pass is False
        assert verdict.ok is False

    def test_verify_rejects_unknown_non_proof_pack_receipt_type(
        self, tmp_path, monkeypatch
    ):
        pack_dir = self._build_external_pack_with_unknown_type(tmp_path, monkeypatch)

        verdict = verify_pack(pack_dir)

        assert verdict.integrity_pass is False
        assert verdict.ok is False
        assert any("experimental_verdict" in error for error in verdict.errors)

    def test_verify_missing_pack_dir(self, tmp_path):
        fake_cp = Checkpoint(
            pack_dir=tmp_path / "nonexistent",
            episode_id="ep_fake",
            reason="test",
            receipt_count=0,
            sealed_at="2026-01-01T00:00:00Z",
        )
        verdict = verify_checkpoint(fake_cp)
        assert verdict.ok is False
        assert verdict.integrity_pass is False

    def test_honest_fail_property(self):
        v = Verdict(ok=False, integrity_pass=True, claims_pass=False)
        assert v.honest_fail is True

    def test_not_honest_fail_when_tampered(self):
        v = Verdict(ok=False, integrity_pass=False, claims_pass=False)
        assert v.honest_fail is False

    def test_verdict_with_claim_failure(self, tmp_store, tmp_path):
        from assay.claim_verifier import ClaimSpec

        claims = [
            ClaimSpec(
                claim_id="require_guardian",
                description="Guardian verdict must be present",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="critical",
            ),
        ]
        ep = open_episode(store=tmp_store)
        ep.emit("model.invoked", {"model": "gpt-4"})
        # No guardian receipt emitted
        cp = ep.seal_checkpoint(output_dir=tmp_path / "test_pack")
        verdict = verify_checkpoint(cp, claims=claims)
        assert verdict.integrity_pass is True
        assert verdict.claims_pass is False
        assert verdict.ok is False
        assert verdict.honest_fail is True


# ---------------------------------------------------------------------------
# End-to-end: the settlement pattern
# ---------------------------------------------------------------------------


class TestSettlementPattern:
    """The full episode -> checkpoint -> verify -> settle loop."""

    def test_full_settlement_loop(self, tmp_store, tmp_path):
        """Demonstrates the intended Mode 2 + Mode 3 usage."""
        # Open episode
        with open_episode(
            policy_version="v2.1",
            guardian_profile="standard",
            store=tmp_store,
        ) as ep:
            # Emit runtime receipts
            r1 = ep.emit("model.invoked", {"model": "gpt-4", "tokens": 800})
            r2 = ep.emit("tool.invoked", {"tool": "email_draft"}, parent_receipt_id=r1)
            r3 = ep.emit(
                "guardian.approved",
                {
                    "action": "send_email",
                    "policy": "outbound_comms",
                },
                parent_receipt_id=r2,
            )

            # Seal before consequence
            cp = ep.seal_checkpoint(
                reason="before_send_email",
                output_dir=tmp_path / "settlement_pack",
            )

            # Verify
            verdict = verify_checkpoint(cp)

            # Settlement decision
            if verdict.ok:
                ep.emit("action.settled", {"action": "send_email"})
                action_taken = True
            elif verdict.honest_fail:
                ep.emit("action.denied", {"reason": "honest_fail"})
                action_taken = False
            else:
                ep.emit("action.denied", {"reason": "tampered"})
                action_taken = False

        # Assertions
        assert verdict.ok is True
        assert action_taken is True
        assert ep.closed

        # Verify the full narrative in the trace
        entries = tmp_store.read_trace(ep.trace_id)
        types = [e["type"] for e in entries]
        assert types[0] == "episode.opened"
        assert "model.invoked" in types
        assert "tool.invoked" in types
        assert "guardian.approved" in types
        assert "checkpoint.sealed" in types
        assert "action.settled" in types
        assert types[-1] == "episode.closed"

    def test_settlement_blocks_on_missing_guardian(self, tmp_store, tmp_path):
        """Claims can enforce that guardian approval is present."""
        from assay.claim_verifier import ClaimSpec

        claims = [
            ClaimSpec(
                claim_id="guardian_present",
                description="Guardian must approve before action",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]

        with open_episode(store=tmp_store, claims=claims) as ep:
            ep.emit("model.invoked", {"model": "gpt-4"})
            # Deliberately skip guardian receipt
            cp = ep.seal_checkpoint(
                reason="before_action",
                output_dir=tmp_path / "pack",
            )
            verdict = verify_checkpoint(cp, claims=claims)

        assert verdict.ok is False
        assert verdict.honest_fail is True  # authentic evidence of a real gap


# ---------------------------------------------------------------------------
# Import surface
# ---------------------------------------------------------------------------


class TestImportSurface:
    """Verify the public API is importable from assay root."""

    def test_import_from_assay(self):
        import assay

        assert hasattr(assay, "open_episode")
        assert hasattr(assay, "verify_checkpoint")
        assert hasattr(assay, "verify_pack")
        assert hasattr(assay, "Episode")
        assert hasattr(assay, "Checkpoint")
        assert hasattr(assay, "Verdict")
        assert hasattr(assay, "EpisodeClosedError")

    def test_open_episode_callable(self):
        import assay

        assert callable(assay.open_episode)

    def test_verify_checkpoint_callable(self):
        import assay

        assert callable(assay.verify_checkpoint)
