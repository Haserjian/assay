"""Tests for assay incident timeline and causal analysis."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.incident import (
    CausalChain,
    DivergencePoint,
    IncidentTimeline,
    TimelineEvent,
    build_causal_chains,
    build_comparative_timeline,
    build_timeline,
    render_causal_md,
    render_causal_text,
    render_timeline_md,
    render_timeline_text,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)


def _ts(offset_minutes: int = 0) -> str:
    return (_T0 + timedelta(minutes=offset_minutes)).isoformat()


def _make_receipt(**overrides) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": _ts(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


def _model_call(model_id="gpt-4", in_t=100, out_t=50, latency=200.0,
                error=None, offset=0, **kw) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "model_id": model_id,
        "input_tokens": in_t,
        "output_tokens": out_t,
        "latency_ms": latency,
    }
    if error:
        base["error"] = error
    base.update(kw)
    return base


def _guardian(action="send_email", verdict="allow", reason="", offset=0, **kw) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "guardian_verdict",
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "action": action,
        "verdict": verdict,
        "reason": reason,
    }
    base.update(kw)
    return base


def _mcp_call(tool_name="read_file", outcome="forwarded", policy_verdict="allow",
              policy_reason="", duration=50.0, offset=0, **kw) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "mcp_tool_call",
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "tool_name": tool_name,
        "outcome": outcome,
        "policy_verdict": policy_verdict,
        "policy_reason": policy_reason,
        "duration_ms": duration,
    }
    base.update(kw)
    return base


def _build_pack_with_receipts(tmp_path: Path, receipts: List[Dict[str, Any]],
                               pack_name: str = "pack",
                               signer_id: str = "test-signer") -> Path:
    """Build a signed proof pack with given receipts."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key(signer_id)
    pack = ProofPack(
        run_id="incident-test-run",
        entries=receipts,
        signer_id=signer_id,
        mode="shadow",
    )
    return pack.build(tmp_path / pack_name, keystore=ks)


# Pack A: clean baseline (3 model_calls + 1 guardian allow)
def _pack_a_receipts() -> List[Dict[str, Any]]:
    return [
        _model_call(model_id="gpt-4", offset=0),
        _model_call(model_id="gpt-4", offset=1),
        _guardian(action="send_email", verdict="allow", offset=2),
        _model_call(model_id="gpt-4", offset=3),
    ]


# Pack B: incident (3 model_calls + 1 guardian deny + 1 error)
def _pack_b_receipts() -> List[Dict[str, Any]]:
    return [
        _model_call(model_id="gpt-4", offset=0),
        _model_call(model_id="gpt-4", offset=1, error="rate_limit_exceeded"),
        _guardian(action="delete_records", verdict="deny", reason="PII access not allowed", offset=2),
        _model_call(model_id="gpt-3.5-turbo", offset=3),
        _model_call(model_id="gpt-3.5-turbo", offset=4),
    ]


# Pack C: MCP calls (2 model_calls + 2 mcp_tool_calls, 1 denied)
def _pack_c_receipts() -> List[Dict[str, Any]]:
    return [
        _model_call(model_id="gpt-4", offset=0),
        _mcp_call(tool_name="read_file", outcome="forwarded", offset=1),
        _mcp_call(tool_name="exec_command", outcome="denied",
                  policy_verdict="deny", policy_reason="exec not allowed", offset=2),
        _model_call(model_id="gpt-4", offset=3),
    ]


# Pack D: parent chain (3 levels deep)
def _pack_d_receipts() -> List[Dict[str, Any]]:
    r1 = _model_call(model_id="gpt-4", offset=0, receipt_id="root_001")
    r2 = _model_call(model_id="gpt-4", offset=1, receipt_id="mid_002",
                     parent_receipt_id="root_001")
    r3 = _model_call(model_id="gpt-4", offset=2, receipt_id="fail_003",
                     parent_receipt_id="mid_002", error="context_length_exceeded")
    return [r1, r2, r3]


# ---------------------------------------------------------------------------
# Module tests: event classification
# ---------------------------------------------------------------------------

class TestEventClassification:
    def test_model_call_normal(self):
        r = _model_call(model_id="gpt-4", in_t=100, out_t=50, latency=200.0)
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.event_type == "model_call"
        assert event.severity == "normal"
        assert "gpt-4" in event.summary
        assert "100+50" in event.summary

    def test_model_call_error(self):
        r = _model_call(model_id="gpt-4", error="timeout")
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.severity == "critical"
        assert "FAILED" in event.summary
        assert "timeout" in event.summary

    def test_guardian_allow(self):
        r = _guardian(action="send_email", verdict="allow")
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.event_type == "guardian_verdict"
        assert event.severity == "normal"
        assert "ALLOW" in event.summary

    def test_guardian_deny(self):
        r = _guardian(action="delete_records", verdict="deny", reason="PII")
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.severity == "critical"
        assert "DENY" in event.summary
        assert "PII" in event.summary

    def test_mcp_forwarded(self):
        r = _mcp_call(tool_name="read_file", outcome="forwarded", duration=50.0)
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.event_type == "mcp_tool_call"
        assert event.severity == "normal"
        assert "read_file" in event.summary

    def test_mcp_denied(self):
        r = _mcp_call(tool_name="exec_command", outcome="denied",
                      policy_verdict="deny", policy_reason="not allowed")
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.severity == "critical"
        assert "DENIED" in event.summary
        assert "exec_command" in event.summary

    def test_unknown_type(self):
        r = {"receipt_id": "r_x", "type": "custom_event", "timestamp": _ts()}
        from assay.incident import _classify_receipt
        event = _classify_receipt(r)
        assert event.event_type == "custom_event"
        assert event.severity == "normal"


# ---------------------------------------------------------------------------
# Module tests: timeline building
# ---------------------------------------------------------------------------

class TestBuildTimeline:
    def test_basic_timeline(self, tmp_path):
        receipts = _pack_a_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        assert timeline.n_events == 4
        assert timeline.integrity_status == "PASSED"
        # Events sorted by timestamp
        for i in range(1, len(timeline.events)):
            assert timeline.events[i].timestamp >= timeline.events[i - 1].timestamp

    def test_empty_pack(self, tmp_path):
        pack_dir = _build_pack_with_receipts(tmp_path, [])
        timeline = build_timeline(pack_dir)
        assert timeline.n_events == 0
        assert timeline.events == []

    def test_incident_pack_has_critical_events(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        critical = [e for e in timeline.events if e.severity == "critical"]
        assert len(critical) == 2  # 1 error + 1 deny

    def test_mcp_pack_events(self, tmp_path):
        receipts = _pack_c_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        mcp_events = [e for e in timeline.events if e.event_type == "mcp_tool_call"]
        assert len(mcp_events) == 2

    def test_time_start_end(self, tmp_path):
        receipts = _pack_a_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        assert timeline.time_start != ""
        assert timeline.time_end != ""
        assert timeline.time_start <= timeline.time_end


# ---------------------------------------------------------------------------
# Module tests: causal chains
# ---------------------------------------------------------------------------

class TestCausalChains:
    def test_causal_chain_from_guardian_deny(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        deny_chains = [c for c in timeline.causal_chains
                       if "Guardian" in c.failure_description]
        assert len(deny_chains) >= 1
        assert "Guardian blocked" in deny_chains[0].root_cause

    def test_causal_chain_from_error(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        error_chains = [c for c in timeline.causal_chains
                        if "FAILED" in c.failure_description]
        assert len(error_chains) >= 1
        assert "Model call failed" in error_chains[0].root_cause

    def test_causal_chain_with_parent_chain(self, tmp_path):
        receipts = _pack_d_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        assert len(timeline.causal_chains) == 1
        chain = timeline.causal_chains[0]
        # Chain should have 3 events (root -> mid -> failure)
        assert len(chain.chain) == 3
        # First event in chain should be the root
        assert chain.chain[0].receipt_id == "root_001"

    def test_causal_chain_no_failures(self, tmp_path):
        receipts = _pack_a_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        assert timeline.causal_chains == []


# ---------------------------------------------------------------------------
# Module tests: comparative timeline / divergence
# ---------------------------------------------------------------------------

class TestComparativeTimeline:
    def test_divergence_new_model(self, tmp_path):
        pack_a = _build_pack_with_receipts(
            tmp_path, _pack_a_receipts(), pack_name="baseline"
        )
        pack_b = _build_pack_with_receipts(
            tmp_path, _pack_b_receipts(), pack_name="current"
        )
        timeline = build_comparative_timeline(pack_b, pack_a)
        assert timeline.divergence is not None
        # Pack B introduces gpt-3.5-turbo which wasn't in pack A
        assert "gpt-3.5-turbo" in timeline.divergence.description or "critical" in timeline.divergence.description.lower()

    def test_no_divergence_identical(self, tmp_path):
        receipts = _pack_a_receipts()
        pack_a = _build_pack_with_receipts(
            tmp_path, receipts, pack_name="baseline"
        )
        pack_a2 = _build_pack_with_receipts(
            tmp_path, _pack_a_receipts(), pack_name="current"
        )
        timeline = build_comparative_timeline(pack_a2, pack_a)
        # Same models, no critical events in either -> no divergence
        assert timeline.divergence is None


# ---------------------------------------------------------------------------
# Module tests: summary
# ---------------------------------------------------------------------------

class TestSummary:
    def test_clean_pack_summary(self, tmp_path):
        receipts = _pack_a_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        # Pack A has no claims, so summary mentions "no claims" not "no issues"
        low = timeline.summary.lower()
        assert "no claims" in low or "no issues" in low or "passed" in low

    def test_incident_pack_summary(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        # Summary should mention events or critical
        assert "event" in timeline.summary.lower() or "critical" in timeline.summary.lower() or "failed" in timeline.summary.lower()


# ---------------------------------------------------------------------------
# Module tests: serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_timeline_to_dict_json_serializable(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        d = timeline.to_dict()
        # Must be JSON-serializable
        s = json.dumps(d)
        assert isinstance(json.loads(s), dict)
        assert d["n_events"] == timeline.n_events

    def test_event_to_dict(self):
        event = TimelineEvent(
            timestamp=_ts(),
            receipt_id="r_test",
            event_type="model_call",
            summary="test event",
            severity="normal",
        )
        d = event.to_dict()
        assert d["receipt_id"] == "r_test"
        assert d["event_type"] == "model_call"


# ---------------------------------------------------------------------------
# Module tests: renderers
# ---------------------------------------------------------------------------

class TestRenderers:
    def test_render_text_contains_events(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        text = render_timeline_text(timeline)
        assert "INCIDENT TIMELINE" in text
        assert "CHRONOLOGY" in text
        assert "gpt-4" in text

    def test_render_md_has_table(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        md = render_timeline_md(timeline)
        assert "| Time |" in md
        assert "## Chronology" in md

    def test_render_causal_text_no_failures(self):
        text = render_causal_text([])
        assert "No failures" in text

    def test_render_causal_text_with_chains(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        text = render_causal_text(timeline.causal_chains)
        assert "CAUSAL ANALYSIS" in text
        assert "root cause" in text.lower() or "failure" in text.lower()

    def test_render_causal_md(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        timeline = build_timeline(pack_dir)
        md = render_causal_md(timeline.causal_chains)
        assert "## Causal Analysis" in md


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLITimeline:
    def test_basic_timeline(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["incident", "timeline", str(pack_dir)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert "INCIDENT TIMELINE" in result.output

    def test_with_baseline(self, tmp_path):
        pack_a = _build_pack_with_receipts(tmp_path, _pack_a_receipts(), pack_name="baseline")
        pack_b = _build_pack_with_receipts(tmp_path, _pack_b_receipts(), pack_name="current")
        result = runner.invoke(assay_app, [
            "incident", "timeline", str(pack_b),
            "--against", str(pack_a),
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

    def test_json_output(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["incident", "timeline", str(pack_dir), "--json"])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)
        assert data["command"] == "incident timeline"
        assert "events" in data
        assert "causal_chains" in data

    def test_md_output(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "incident", "timeline", str(pack_dir), "--format", "md",
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert "## Chronology" in result.output

    def test_bad_input_not_directory(self, tmp_path):
        result = runner.invoke(assay_app, [
            "incident", "timeline", str(tmp_path / "nonexistent"),
        ])
        assert result.exit_code == 3

    def test_no_manifest(self, tmp_path):
        (tmp_path / "empty_pack").mkdir()
        result = runner.invoke(assay_app, [
            "incident", "timeline", str(tmp_path / "empty_pack"),
        ])
        assert result.exit_code == 3

    def test_json_all_receipt_types(self, tmp_path):
        receipts = (
            [_model_call(offset=0)]
            + [_guardian(offset=1)]
            + [_mcp_call(offset=2)]
        )
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["incident", "timeline", str(pack_dir), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        types = {e["event_type"] for e in data["events"]}
        assert "model_call" in types
        assert "guardian_verdict" in types
        assert "mcp_tool_call" in types


class TestCLIExplainCausal:
    def test_explain_causal_flag(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["explain", str(pack_dir), "--causal"])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert "CAUSAL ANALYSIS" in result.output

    def test_explain_causal_no_failures(self, tmp_path):
        receipts = _pack_a_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["explain", str(pack_dir), "--causal"])
        assert result.exit_code == 0
        assert "No failures" in result.output

    def test_explain_causal_json(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["explain", str(pack_dir), "--causal", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "causal_chains" in data
        assert len(data["causal_chains"]) >= 1

    def test_explain_causal_md(self, tmp_path):
        receipts = _pack_b_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "explain", str(pack_dir), "--causal", "--format", "md",
        ])
        assert result.exit_code == 0
        assert "Causal Analysis" in result.output

    def test_explain_backward_compat(self, tmp_path):
        """explain without --causal works as before."""
        receipts = _pack_a_receipts()
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, ["explain", str(pack_dir)])
        assert result.exit_code == 0
        # Should NOT contain causal output when flag is not set
        assert "CAUSAL ANALYSIS" not in result.output
