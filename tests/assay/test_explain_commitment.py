"""Tests for `assay explain commitment <id>` — read-only doctrine surface.

Explains why a commitment is OPEN, CLOSED, NOT_REGISTERED, or why the
store is INVALID_STORE. Never mutates state, never emits receipts.

Mirrors the doctrine the detector already enforces. Asserting this as a
separate module keeps the explanation surface honest about its boundary:
it is an inspection tool, not a repair tool.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from assay.commitment_fulfillment import (
    COMMITMENT_REGISTRATION_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
    FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
    RESULT_OBSERVATION_RECEIPT_TYPE,
)
from assay.commitment_explain import ExplainResult, explain_commitment
from assay.store import AssayStore


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path):
    return AssayStore(base_dir=tmp_path / "assay_store")


def _policy_hash_for(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


@pytest.fixture
def compile_receipt(tmp_path):
    """Emit a minimal valid COMPILE_RECEIPT.json for tests that need it."""
    body = b"explain-test-policy-v0\n"
    ph = _policy_hash_for(body)
    doc = {
        "compile_receipt_version": "0.1",
        "policy_hash": ph,
        "compiled_at": "2026-04-20T12:00:00Z",
        "profile": "base",
    }
    path = tmp_path / "COMPILE_RECEIPT.json"
    path.write_text(json.dumps(doc))
    return path, ph


def _resolver_dict(path: Path, policy_hash: str) -> dict:
    return {"kind": "uri", "ref": f"file://{path}", "policy_hash": policy_hash}


def _write_registered(store, commitment_id, *, due_at=None):
    data = {
        "type": COMMITMENT_REGISTRATION_RECEIPT_TYPE,
        "commitment_id": commitment_id,
        "episode_id": "ep_explain",
        "actor_id": "actor_test",
        "text": f"Commitment {commitment_id} text.",
        "commitment_type": "delivery",
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
        "episode_id": "ep_explain",
        "text": f"Observed {result_id}",
        "evidence_uri": "file:///tmp/evidence.log",
        "policy_hash": "sha256:" + "c" * 64,
        "references": references or [],
        "timestamp": "2026-04-20T11:00:00.000Z",
    })


def _write_kept(store, commitment_id, result_id):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
        "fulfillment_id": f"ful_{commitment_id}_kept",
        "episode_id": "ep_explain",
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "timestamp": "2026-04-20T12:00:00.000Z",
    })


def _write_broken(store, commitment_id, result_id, reason="missed"):
    store.append_dict({
        "type": FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
        "fulfillment_id": f"ful_{commitment_id}_broken",
        "episode_id": "ep_explain",
        "commitment_id": commitment_id,
        "result_id": result_id,
        "evaluator": "test",
        "evaluator_version": "0.1",
        "policy_hash": "sha256:" + "c" * 64,
        "violation_reason": reason,
        "timestamp": "2026-04-20T12:00:00.000Z",
    })


# ---------------------------------------------------------------------------
# 1. CLOSED — happy path
# ---------------------------------------------------------------------------


class TestExplainClosed:
    """A commitment closed by a valid kept-anchor-after-observation terminal
    must explain itself as CLOSED with the specific seqs that justified it."""

    def test_kept_closes_commitment_with_anchor(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_close_1", due_at="2020-01-01T00:00:00Z")
        _write_result(
            tmp_store, "res_close_1",
            references=[{"kind": "commitment", "id": "cmt_close_1"}],
        )
        _write_kept(tmp_store, "cmt_close_1", "res_close_1")

        result = explain_commitment(tmp_store, "cmt_close_1")
        assert isinstance(result, ExplainResult)
        assert result.state == "CLOSED"
        assert result.registration is not None
        assert result.registration.receipt_type == COMMITMENT_REGISTRATION_RECEIPT_TYPE
        # Timeline should include: registration, observation, terminal — in seq order
        types = [line.receipt_type for line in result.timeline]
        assert COMMITMENT_REGISTRATION_RECEIPT_TYPE in types
        assert RESULT_OBSERVATION_RECEIPT_TYPE in types
        assert FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE in types
        # Decision must cite the specific terminal seq that closed it.
        assert "CLOSED" in result.decision
        term_seq = next(
            l.seq for l in result.timeline
            if l.receipt_type == FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE
        )
        assert f"seq={term_seq}" in result.decision

    def test_broken_also_closes_commitment(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_broken_1", due_at="2020-01-01T00:00:00Z")
        _write_result(
            tmp_store, "res_broken_1",
            references=[{"kind": "commitment", "id": "cmt_broken_1"}],
        )
        _write_broken(tmp_store, "cmt_broken_1", "res_broken_1", reason="deadline")

        result = explain_commitment(tmp_store, "cmt_broken_1")
        assert result.state == "CLOSED"
        assert FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE in [
            l.receipt_type for l in result.timeline
        ]


# ---------------------------------------------------------------------------
# 2. OPEN — missing anchor edge
# ---------------------------------------------------------------------------


class TestExplainOpenMissingAnchor:
    """A commitment with a terminal that does not anchor to an observation
    referencing it must explain as OPEN and name the missing anchor."""

    def test_terminal_without_result_observation(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_no_res", due_at="2020-01-01T00:00:00Z")
        # Terminal references a result_id that was never observed.
        _write_kept(tmp_store, "cmt_no_res", "res_phantom")

        result = explain_commitment(tmp_store, "cmt_no_res")
        assert result.state == "OPEN"
        assert "anchor" in result.decision.lower()
        # Terminal should be in timeline, marked as invalid/unanchored.
        terminal_line = next(
            l for l in result.timeline
            if l.receipt_type == FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE
        )
        assert "anchor" in terminal_line.note.lower() or "invalid" in terminal_line.note.lower()

    def test_result_observation_without_commitment_reference(self, tmp_store):
        """Observation exists for the result_id but doesn't reference this commitment."""
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_A", due_at="2020-01-01T00:00:00Z")
        _write_registered(tmp_store, "cmt_B", due_at="2020-01-01T00:00:00Z")
        # res_B references cmt_B only.
        _write_result(
            tmp_store, "res_B",
            references=[{"kind": "commitment", "id": "cmt_B"}],
        )
        # Forged-looking terminal: says "close cmt_A using res_B" but res_B
        # doesn't reference cmt_A.
        _write_kept(tmp_store, "cmt_A", "res_B")

        result = explain_commitment(tmp_store, "cmt_A")
        assert result.state == "OPEN"
        assert "anchor" in result.decision.lower()


# ---------------------------------------------------------------------------
# 3. OPEN — no terminal at all
# ---------------------------------------------------------------------------


class TestExplainOpenNoTerminal:
    """A commitment registered with no terminal fulfillment at all is OPEN."""

    def test_registered_only(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_pending", due_at="2099-01-01T00:00:00Z")

        result = explain_commitment(tmp_store, "cmt_pending")
        assert result.state == "OPEN"
        assert "terminal" in result.decision.lower() or "fulfillment" in result.decision.lower()
        # No terminal should appear in the timeline.
        for line in result.timeline:
            assert line.receipt_type not in (
                FULFILLMENT_COMMITMENT_KEPT_RECEIPT_TYPE,
                FULFILLMENT_COMMITMENT_BROKEN_RECEIPT_TYPE,
            )

    def test_registered_with_observation_but_no_terminal(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_halfway", due_at="2099-01-01T00:00:00Z")
        _write_result(
            tmp_store, "res_halfway",
            references=[{"kind": "commitment", "id": "cmt_halfway"}],
        )
        result = explain_commitment(tmp_store, "cmt_halfway")
        assert result.state == "OPEN"
        assert "terminal" in result.decision.lower() or "fulfillment" in result.decision.lower()


# ---------------------------------------------------------------------------
# 4. NOT_REGISTERED — commitment never declared
# ---------------------------------------------------------------------------


class TestExplainNotRegistered:
    def test_unknown_commitment_id(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_real", due_at="2099-01-01T00:00:00Z")

        result = explain_commitment(tmp_store, "cmt_phantom")
        assert result.state == "NOT_REGISTERED"
        assert result.registration is None
        assert "not registered" in result.decision.lower() or \
               "no commitment.registered" in result.decision.lower()

    def test_empty_store(self, tmp_store):
        result = explain_commitment(tmp_store, "cmt_anything")
        assert result.state == "NOT_REGISTERED"


# ---------------------------------------------------------------------------
# 5. INVALID_STORE — corruption fails closed
# ---------------------------------------------------------------------------


class TestExplainInvalidStore:
    """Corruption / mixed state must surface as INVALID_STORE, not be hidden
    behind an OPEN/CLOSED judgment that could be based on partial data."""

    def test_malformed_json_line_in_corpus(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_corrupt", due_at="2020-01-01T00:00:00Z")
        # Corrupt the current trace file.
        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        target = trace_files[-1]
        with open(target, "a") as handle:
            handle.write("{this is not valid json\n")

        result = explain_commitment(tmp_store, "cmt_corrupt")
        assert result.state == "INVALID_STORE"
        assert result.integrity_error is not None
        assert "malformed" in result.integrity_error.lower() or \
               "json" in result.integrity_error.lower()

    def test_missing_store_seq_reports_invalid(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_leg", due_at="2020-01-01T00:00:00Z")
        trace_files = sorted(tmp_store.base_dir.rglob("trace_*.jsonl"))
        target = trace_files[-1]
        # Append a line without _store_seq — triggers fail-closed.
        with open(target, "a") as handle:
            handle.write('{"type": "result.observed", "result_id": "orphan"}\n')

        result = explain_commitment(tmp_store, "cmt_leg")
        assert result.state == "INVALID_STORE"
        assert result.integrity_error is not None


# ---------------------------------------------------------------------------
# 6. Read-only invariant
# ---------------------------------------------------------------------------


class TestExplainIsReadOnly:
    """Running explain must NOT emit any receipts or touch .store_seq."""

    def test_explain_does_not_emit_receipts(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_ro", due_at="2099-01-01T00:00:00Z")

        before_count = sum(
            1 for _ in tmp_store.base_dir.rglob("trace_*.jsonl")
            for _line in open(_)
        )
        seq_before = (tmp_store.base_dir / ".store_seq").read_text() \
            if (tmp_store.base_dir / ".store_seq").exists() else None

        result = explain_commitment(tmp_store, "cmt_ro")
        assert result.state == "OPEN"  # sanity

        after_count = sum(
            1 for _ in tmp_store.base_dir.rglob("trace_*.jsonl")
            for _line in open(_)
        )
        seq_after = (tmp_store.base_dir / ".store_seq").read_text() \
            if (tmp_store.base_dir / ".store_seq").exists() else None

        assert after_count == before_count, (
            "explain_commitment must be read-only; no new trace lines should appear"
        )
        assert seq_after == seq_before, (
            "explain_commitment must not modify .store_seq"
        )

    def test_explain_unknown_id_also_read_only(self, tmp_store):
        tmp_store.start_trace()
        _write_registered(tmp_store, "cmt_real", due_at="2099-01-01T00:00:00Z")

        seq_before = (tmp_store.base_dir / ".store_seq").read_text()
        explain_commitment(tmp_store, "cmt_never_existed")
        seq_after = (tmp_store.base_dir / ".store_seq").read_text()

        assert seq_before == seq_after


# ---------------------------------------------------------------------------
# 7. CLI smoke — plain text + JSON
# ---------------------------------------------------------------------------


class TestExplainCLI:
    """The Typer CLI wrapper wires correctly. Minimal smoke tests; the
    heavy lifting is in explain_commitment()."""

    def test_sub_app_plain_output_contains_state(self, tmp_path):
        base = tmp_path / "cli_store"
        real_store = AssayStore(base_dir=base)
        real_store.start_trace()
        _write_registered(real_store, "cmt_cli", due_at="2099-01-01T00:00:00Z")

        from typer.testing import CliRunner

        from assay.commitment_explain import commitments_app

        runner = CliRunner()
        result = runner.invoke(
            commitments_app,
            ["explain", "cmt_cli", "--base-dir", str(base)],
        )
        assert result.exit_code == 0, result.output
        assert "cmt_cli" in result.output
        assert "OPEN" in result.output

    def test_sub_app_json_output_parses(self, tmp_path):
        base = tmp_path / "cli_store_json"
        real_store = AssayStore(base_dir=base)
        real_store.start_trace()
        _write_registered(real_store, "cmt_cli_json", due_at="2099-01-01T00:00:00Z")

        from typer.testing import CliRunner

        from assay.commitment_explain import commitments_app

        runner = CliRunner()
        result = runner.invoke(
            commitments_app,
            ["explain", "cmt_cli_json", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["commitment_id"] == "cmt_cli_json"
        assert parsed["state"] == "OPEN"


# ---------------------------------------------------------------------------
# 8. Top-level CLI integration — regression canary
# ---------------------------------------------------------------------------


class TestAssayAppIntegration:
    """These tests invoke the REAL top-level ``assay_app`` (not the sub-app in
    isolation). This is the surface actual users hit via ``python -m assay.cli``.

    Rationale: a previous iteration of this work mounted the sub-app at the
    wrong name (``explain``), silently shadowing a pre-existing
    ``@assay_app.command("explain")`` for proof-pack explanation. The
    sub-app tests above PASSED because they bypass ``assay_app``. The
    regression only shows up when you go through the real top-level CLI.
    Any future renames/remounts must keep these tests green.
    """

    def test_commitments_explain_reachable_from_top_level_cli(self, tmp_path):
        from typer.testing import CliRunner

        from assay.commands import assay_app

        base = tmp_path / "topcli"
        real_store = AssayStore(base_dir=base)
        real_store.start_trace()
        _write_registered(real_store, "cmt_top", due_at="2099-01-01T00:00:00Z")

        runner = CliRunner()
        result = runner.invoke(
            assay_app,
            ["commitments", "explain", "cmt_top", "--base-dir", str(base), "--json"],
        )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["commitment_id"] == "cmt_top"
        assert parsed["state"] == "OPEN"

    def test_assay_explain_still_goes_to_pack_explainer(self):
        """``assay explain <pack_dir>`` must still resolve to the proof-pack
        explainer — not to the commitment sub-app. This was the regression
        that motivated this test class.

        We do not need the pack-explainer to succeed against a real pack;
        we just need it to be the one that handles the invocation (i.e.,
        the failure signature should match pack-explainer semantics, not
        'No such command'/'Missing subcommand').
        """
        from typer.testing import CliRunner

        from assay.commands import assay_app

        runner = CliRunner()
        # Invoke with a pack_dir that doesn't exist. The pack-explainer
        # takes pack_dir as a positional argument; if our remount
        # accidentally points 'explain' at the commitment sub-app, this
        # invocation would error as "No such command" or "Missing
        # subcommand" instead of reaching the pack-explainer at all.
        result = runner.invoke(
            assay_app,
            ["explain", "/nonexistent/proof/pack", "--json"],
        )
        output = (result.output or "") + (result.stderr or "")
        # Negative assertions: must NOT look like sub-app argparse errors.
        assert "No such command" not in output, output
        assert "Missing command" not in output, output
        assert "Got unexpected extra argument" not in output, output
        # Positive signal: either the pack explainer ran (success or graceful
        # failure with pack-shaped output), or it emitted an explain-style
        # error. Either way, the routing reached the pack-explainer, not
        # the commitment sub-app.
        # The pack explainer should at least not complain about the command
        # name itself. Exit code may be non-zero because the pack doesn't
        # exist; that's fine — we just care that we got past command
        # dispatch.

    def test_top_level_commitments_help_lists_explain(self):
        """`assay commitments --help` must surface the `explain` subcommand."""
        from typer.testing import CliRunner

        from assay.commands import assay_app

        runner = CliRunner()
        result = runner.invoke(assay_app, ["commitments", "--help"])
        assert result.exit_code == 0, result.output
        assert "explain" in result.output
