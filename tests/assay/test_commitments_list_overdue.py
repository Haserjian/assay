"""Tests for ``assay commitments list`` and ``assay commitments overdue``.

These commands round out the operator surface for the commitment
wedge. They share a single-pass corpus scan (``summarize_all_commitments``)
and differ only in how they filter/render the same summaries.

Scope discipline:
    - Read-only. No writes, no receipt emissions, no ``.store_seq``
      mutation.
    - Same data source as ``explain`` and the detector
      (``_iter_all_receipts``) — no parallel rule.
    - Top-level CLI integration tests go through ``assay_app``, not
      the sub-app in isolation (same regression canary as PR #83).
    - Tests assert structured JSON fields, not fragile prose.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.commitment_closure_detector import detect_open_overdue_commitments
from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
)
from assay.commitment_summary import (
    CommitmentSummary,
    SummariesResult,
    summarize_all_commitments,
)
from assay.store import AssayStore


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path):
    return AssayStore(base_dir=tmp_path / "store")


def _write_registered(store, commitment_id, *, actor_id="alice", due_at=None,
                      text=None, commitment_type="delivery"):
    data = {
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": commitment_id,
        "episode_id": "ep_test",
        "actor_id": actor_id,
        "text": text or f"Commitment {commitment_id}.",
        "commitment_type": commitment_type,
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T10:00:00.000Z",
    }
    if due_at is not None:
        data["due_at"] = due_at
    store.append_dict(data)


def _write_result(store, result_id, *, references=None):
    store.append_dict({
        "type": RESULT_OBSERVATION_RECEIPT_TYPE,
        "result_id": result_id,
        "episode_id": "ep_test",
        "text": f"Observed {result_id}.",
        "evidence_uri": "file:///tmp/evidence.log",
        "policy_hash": "sha256:" + "c" * 64,
        "references": references or [],
        "timestamp": "2026-04-20T11:00:00.000Z",
    })


def _write_kept(store, commitment_id, result_id):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": f"ful_{commitment_id}",
        "episode_id": "ep_test",
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T12:00:00.000Z",
    })


# ---------------------------------------------------------------------------
# 1. summarize_all_commitments core behavior
# ---------------------------------------------------------------------------


class TestSummarize:
    """The shared bulk-scan helper."""

    def test_empty_store(self, tmp_store):
        result = summarize_all_commitments(tmp_store)
        assert isinstance(result, SummariesResult)
        assert result.commitments == []
        assert result.integrity_error is None

    def test_single_open_not_overdue(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_future",
                          due_at="2099-01-01T00:00:00Z")
        result = summarize_all_commitments(tmp_store)
        assert len(result.commitments) == 1
        s = result.commitments[0]
        assert s.commitment_id == "cmt_future"
        assert s.state == "OPEN"
        assert s.is_overdue is False
        assert s.closing_terminal_seq is None

    def test_single_open_overdue(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_late",
                          due_at="2020-01-01T00:00:00Z")
        result = summarize_all_commitments(tmp_store)
        assert len(result.commitments) == 1
        s = result.commitments[0]
        assert s.state == "OPEN"
        assert s.is_overdue is True

    def test_single_closed(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_done",
                          due_at="2020-01-01T00:00:00Z")
        _write_result(tmp_store, "res_1",
                      references=[{"kind": "commitment", "id": "cmt_done"}])
        _write_kept(tmp_store, "cmt_done", "res_1")
        result = summarize_all_commitments(tmp_store)
        assert len(result.commitments) == 1
        s = result.commitments[0]
        assert s.state == "CLOSED"
        # is_overdue is False for closed commitments regardless of due_at.
        assert s.is_overdue is False
        assert s.closing_terminal_seq is not None
        assert s.closing_terminal_type == FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE

    def test_perpetual_open_never_overdue(self, tmp_store):
        """A commitment with no due_at is perpetual, never overdue."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_perpetual", due_at=None)
        result = summarize_all_commitments(tmp_store)
        assert len(result.commitments) == 1
        assert result.commitments[0].state == "OPEN"
        assert result.commitments[0].is_overdue is False

    def test_mixed_view(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_open_future",
                          due_at="2099-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_open_overdue",
                          due_at="2020-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_closed",
                          due_at="2020-06-01T00:00:00Z")
        _write_result(tmp_store, "res_closed",
                      references=[{"kind": "commitment", "id": "cmt_closed"}])
        _write_kept(tmp_store, "cmt_closed", "res_closed")

        result = summarize_all_commitments(tmp_store)
        by_id = {s.commitment_id: s for s in result.commitments}
        assert by_id["cmt_open_future"].state == "OPEN"
        assert by_id["cmt_open_future"].is_overdue is False
        assert by_id["cmt_open_overdue"].state == "OPEN"
        assert by_id["cmt_open_overdue"].is_overdue is True
        assert by_id["cmt_closed"].state == "CLOSED"
        assert by_id["cmt_closed"].is_overdue is False

    def test_order_is_by_registered_seq(self, tmp_store):
        """Summaries are returned in registration (causal) order."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_first")
        _write_registered(tmp_store, "cmt_second")
        _write_registered(tmp_store, "cmt_third")
        result = summarize_all_commitments(tmp_store)
        ids = [s.commitment_id for s in result.commitments]
        assert ids == ["cmt_first", "cmt_second", "cmt_third"]
        seqs = [s.registered_seq for s in result.commitments]
        assert seqs == sorted(seqs)


# ---------------------------------------------------------------------------
# 2. Invariant: detector and summarizer agree on overdue set
# ---------------------------------------------------------------------------


class TestDetectorSummarizerAgreement:
    """``detect_open_overdue_commitments`` and ``summarize_all_commitments``
    must produce the same overdue set. Both use the same ``_iter_all_receipts``
    and the same anchored-terminal rule; divergence would indicate a fork
    in closure semantics between the two readers.
    """

    def test_overdue_set_matches_detector(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_a", due_at="2020-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_b", due_at="2020-02-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_c", due_at="2099-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_d", due_at="2020-03-01T00:00:00Z")
        _write_result(tmp_store, "res_d",
                      references=[{"kind": "commitment", "id": "cmt_d"}])
        _write_kept(tmp_store, "cmt_d", "res_d")

        detector = detect_open_overdue_commitments(tmp_store)
        summaries = summarize_all_commitments(tmp_store)

        det_ids = {c.commitment_id for c in detector.open_commitments}
        sum_overdue_ids = {s.commitment_id for s in summaries.commitments if s.is_overdue}
        assert det_ids == sum_overdue_ids


# ---------------------------------------------------------------------------
# 3. Read-only invariant
# ---------------------------------------------------------------------------


class TestSummarizeIsReadOnly:
    def test_summarize_does_not_mutate_store(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_ro", due_at="2020-01-01T00:00:00Z")
        seq_before = (tmp_store.base_dir / ".store_seq").read_text()

        summarize_all_commitments(tmp_store)
        summarize_all_commitments(tmp_store)  # call twice; still no writes

        seq_after = (tmp_store.base_dir / ".store_seq").read_text()
        assert seq_before == seq_after


# ---------------------------------------------------------------------------
# 4. INVALID_STORE behavior
# ---------------------------------------------------------------------------


class TestSummarizeInvalidStore:
    def test_malformed_json_line(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_x", due_at="2099-01-01T00:00:00Z")
        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        with open(trace_files[-1], "a") as f:
            f.write("{not valid json\n")

        result = summarize_all_commitments(tmp_store)
        assert result.commitments == []
        assert result.integrity_error is not None


# ---------------------------------------------------------------------------
# 5. Sub-app CLI smoke (bypasses assay_app; keep for fast iteration)
# ---------------------------------------------------------------------------


class TestSubAppCLI:
    def test_list_empty_plain(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commitment_explain import commitments_app

        runner = CliRunner()
        result = runner.invoke(
            commitments_app, ["list", "--base-dir", str(tmp_path / "s")]
        )
        assert result.exit_code == 0, result.output
        assert "No commitments" in result.output

    def test_list_json_structure(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commitment_explain import commitments_app

        base = tmp_path / "s"
        store = AssayStore(base_dir=base)
        store.start_trace()
        _write_registered(store, "cmt_one", due_at="2020-01-01T00:00:00Z")

        runner = CliRunner()
        result = runner.invoke(
            commitments_app,
            ["list", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert "commitments" in parsed
        assert len(parsed["commitments"]) == 1
        assert parsed["commitments"][0]["commitment_id"] == "cmt_one"
        assert parsed["commitments"][0]["state"] == "OPEN"
        assert parsed["commitments"][0]["is_overdue"] is True

    def test_overdue_filters_out_non_overdue(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commitment_explain import commitments_app

        base = tmp_path / "s"
        store = AssayStore(base_dir=base)
        store.start_trace()
        _write_registered(store, "cmt_future", due_at="2099-01-01T00:00:00Z")
        _write_registered(store, "cmt_past", due_at="2020-01-01T00:00:00Z")

        runner = CliRunner()
        result = runner.invoke(
            commitments_app,
            ["overdue", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        ids = [c["commitment_id"] for c in parsed["commitments"]]
        assert ids == ["cmt_past"]

    def test_overdue_excludes_closed(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commitment_explain import commitments_app

        base = tmp_path / "s"
        store = AssayStore(base_dir=base)
        store.start_trace()
        _write_registered(store, "cmt_done", due_at="2020-01-01T00:00:00Z")
        _write_result(store, "res_1",
                      references=[{"kind": "commitment", "id": "cmt_done"}])
        _write_kept(store, "cmt_done", "res_1")

        runner = CliRunner()
        result = runner.invoke(
            commitments_app,
            ["overdue", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["commitments"] == []


# ---------------------------------------------------------------------------
# 6. Top-level assay_app integration (regression canary)
# ---------------------------------------------------------------------------


class TestAssayAppIntegration:
    """Invoke the real top-level ``assay_app`` — the surface users hit
    via ``python -m assay.cli``. Sub-app tests alone miss dispatch-layer
    regressions (this is the same class of bug PR #83 fixed when the
    commitment sub-app was accidentally mounted at ``explain``).
    """

    def test_commitments_list_reachable_from_top_level(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commands import assay_app

        base = tmp_path / "topcli"
        store = AssayStore(base_dir=base)
        store.start_trace()
        _write_registered(store, "cmt_top", due_at="2099-01-01T00:00:00Z")

        runner = CliRunner()
        result = runner.invoke(
            assay_app,
            ["commitments", "list", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert len(parsed["commitments"]) == 1
        assert parsed["commitments"][0]["commitment_id"] == "cmt_top"

    def test_commitments_overdue_reachable_from_top_level(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commands import assay_app

        base = tmp_path / "topcli_overdue"
        store = AssayStore(base_dir=base)
        store.start_trace()
        _write_registered(store, "cmt_late", due_at="2020-01-01T00:00:00Z")

        runner = CliRunner()
        result = runner.invoke(
            assay_app,
            ["commitments", "overdue", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        ids = [c["commitment_id"] for c in parsed["commitments"]]
        assert ids == ["cmt_late"]

    def test_commitments_help_lists_all_three_subcommands(self):
        """`assay commitments --help` must surface list, overdue, explain."""
        from typer.testing import CliRunner
        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(assay_app, ["commitments", "--help"])
        assert result.exit_code == 0, result.output
        assert "list" in result.output
        assert "overdue" in result.output
        assert "explain" in result.output

    def test_assay_explain_still_goes_to_pack_explainer(self):
        """Regression canary: adding new commitments subcommands must not
        affect the top-level ``assay explain <pack_dir>`` dispatch.
        """
        from typer.testing import CliRunner
        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(
            assay_app, ["explain", "/nonexistent/proof/pack", "--json"]
        )
        output = (result.output or "") + (result.stderr or "")
        assert "No such command" not in output, output
        assert "Missing command" not in output, output
        assert "Got unexpected extra argument" not in output, output


# ---------------------------------------------------------------------------
# 7. CLI exits nonzero on corrupt store
# ---------------------------------------------------------------------------


class TestCliInvalidStoreExit:
    def _populate_then_corrupt(self, base: Path):
        store = AssayStore(base_dir=base)
        store.start_trace()
        _write_registered(store, "cmt_corrupt", due_at="2099-01-01T00:00:00Z")
        trace_files = sorted(store.base_dir.rglob("trace_*.jsonl"))
        with open(trace_files[-1], "a") as f:
            f.write("{not valid json\n")

    def test_list_exits_nonzero_on_corrupt_store(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commitment_explain import commitments_app

        base = tmp_path / "corrupt"
        self._populate_then_corrupt(base)
        runner = CliRunner()
        result = runner.invoke(
            commitments_app, ["list", "--base-dir", str(base)]
        )
        assert result.exit_code == 1, result.output
        assert "INVALID_STORE" in result.output

    def test_overdue_exits_nonzero_on_corrupt_store(self, tmp_path):
        from typer.testing import CliRunner
        from assay.commitment_explain import commitments_app

        base = tmp_path / "corrupt_o"
        self._populate_then_corrupt(base)
        runner = CliRunner()
        result = runner.invoke(
            commitments_app, ["overdue", "--base-dir", str(base)]
        )
        assert result.exit_code == 1, result.output
        assert "INVALID_STORE" in result.output
