"""Tests for the constitutional Episode contract."""
from __future__ import annotations

from pathlib import Path

import pytest

from assay.episode import (
    MEMORY_GRAPH,
    Episode,
    EpisodePersistenceError,
    EpisodeState,
    Obligation,
    Receipt,
    SettlementOutcome,
    emit_proof_pack,
    emit_receipt,
    open_episode,
    persist_episode,
    settle_episode,
)
from assay.store import AssayStore


@pytest.fixture
def tmp_store(tmp_path: Path) -> AssayStore:
    return AssayStore(base_dir=tmp_path / "assay_store")


def _episode_with_model_obligation(tmp_store: AssayStore) -> Episode:
    return open_episode(
        store=tmp_store,
        obligation_context={"purpose": "review"},
        required_obligations=[
            Obligation(
                obligation_id="must_emit_model",
                description="The episode must record a model call.",
                expected_receipt_types=("model.invoked",),
            )
        ],
    )


def test_open_episode_initializes_constitutional_state(tmp_store: AssayStore) -> None:
    episode = _episode_with_model_obligation(tmp_store)

    assert episode.state == EpisodeState.OPEN
    assert episode.required_obligations[0].obligation_id == "must_emit_model"
    assert episode.receipt_count == 1
    assert episode.receipts[0].receipt_type == "episode.opened"
    assert episode.receipts[0].seq == 0
    assert episode.receipt_index[episode.receipts[0].receipt_id] == episode.receipts[0]
    assert episode.receipts_by_type["episode.opened"] == [episode.receipts[0].receipt_id]
    assert episode.receipts[0].payload["obligation_context"]["purpose"] == "review"


def test_package_root_exports_constitutional_contract() -> None:
    import assay

    assert assay.EpisodeState.OPEN.value == "open"
    assert callable(assay.persist_episode)
    assert callable(assay.settle_episode)
    assert callable(assay.emit_proof_pack)


def test_honest_failure_when_required_receipt_is_missing(tmp_store: AssayStore) -> None:
    episode = _episode_with_model_obligation(tmp_store)

    episode.start_execution()
    receipt = emit_receipt(episode, "tool.invoked", {"tool": "search"})
    assert isinstance(receipt, Receipt)
    episode.mark_execution_complete()

    settlement = settle_episode(episode)

    assert settlement.outcome == SettlementOutcome.HONEST_FAIL
    assert settlement.missing_obligations == ("must_emit_model",)
    assert episode.state == EpisodeState.SETTLED
    assert episode.decision_id == settlement.decision_id


def test_settlement_passes_when_required_receipt_is_present(tmp_store: AssayStore) -> None:
    episode = _episode_with_model_obligation(tmp_store)

    episode.start_execution()
    emit_receipt(episode, "model.invoked", {"model": "gpt-4"})
    episode.mark_execution_complete()

    settlement = settle_episode(episode)

    assert settlement.outcome == SettlementOutcome.PASS
    assert settlement.missing_obligations == ()
    assert episode.state == EpisodeState.SETTLED


def test_tampered_trace_settles_as_tampered(tmp_store: AssayStore) -> None:
    episode = _episode_with_model_obligation(tmp_store)

    episode.start_execution()
    emit_receipt(episode, "model.invoked", {"model": "gpt-4"})
    episode.mark_execution_complete()

    trace_file = tmp_store.trace_file
    assert trace_file is not None
    trace_text = trace_file.read_text(encoding="utf-8")
    trace_file.write_text(trace_text.replace("gpt-4", "gpt-3.5-turbo"), encoding="utf-8")

    settlement = settle_episode(episode)

    assert settlement.outcome == SettlementOutcome.TAMPERED
    assert settlement.missing_obligations == ()
    assert episode.state == EpisodeState.SETTLED


def test_proof_pack_emission_and_persistence_gate(tmp_store: AssayStore, tmp_path: Path) -> None:
    episode = _episode_with_model_obligation(tmp_store)

    episode.start_execution()
    emit_receipt(episode, "model.invoked", {"model": "gpt-4"})
    episode.mark_execution_complete()
    settle_episode(episode)

    with pytest.raises(EpisodePersistenceError):
        persist_episode(episode)

    pack_dir = tmp_path / "proof_pack_episode"
    artifact = emit_proof_pack(episode, pack_dir)
    assert artifact.pack_dir == pack_dir
    assert artifact.proof_pack_hash == episode.proof_pack_hash
    assert (pack_dir / "pack_manifest.json").exists()

    memory_record = persist_episode(episode)
    assert episode.state == EpisodeState.PERSISTED
    assert episode.persisted is True
    assert memory_record.episode_id == episode.episode_id
    assert memory_record.snapshot_hash == episode.proof_pack_hash
    assert MEMORY_GRAPH[episode.episode_id] == memory_record
    assert memory_record.snapshot["settlement"]["outcome"] == SettlementOutcome.PASS.value
