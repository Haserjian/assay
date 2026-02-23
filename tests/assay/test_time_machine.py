"""Tests for assay time_machine (Policy Time Machine)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.time_machine import PolicyImpact, render_impact_md, render_impact_text, replay_policy

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)


def _ts(offset_minutes: int = 0) -> str:
    return (_T0 + timedelta(minutes=offset_minutes)).isoformat()


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


def _model_call(model_id="gpt-4", in_t=100, out_t=50, offset=0, **kw) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "model_id": model_id,
        "input_tokens": in_t,
        "output_tokens": out_t,
        "latency_ms": 200.0,
    }
    base.update(kw)
    return base


def _build_pack(tmp_path: Path, receipts: List[Dict[str, Any]],
                pack_name: str = "pack") -> Path:
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("tm-signer")
    pack = ProofPack(
        run_id="tm-test-run",
        entries=receipts,
        signer_id="tm-signer",
        mode="shadow",
    )
    return pack.build(tmp_path / pack_name, keystore=ks)


def _write_policy(tmp_path: Path, policy_dict: Dict[str, Any],
                  name: str = "candidate.yaml") -> Path:
    """Write a YAML policy file."""
    import yaml
    p = tmp_path / name
    p.write_text(yaml.dump(policy_dict), encoding="utf-8")
    return p


# Standard receipts: 5 tool calls (3 allowed, 2 different tools)
def _standard_receipts() -> List[Dict[str, Any]]:
    return [
        _mcp_call(tool_name="read_file", outcome="forwarded", offset=0),
        _model_call(offset=1),
        _mcp_call(tool_name="write_file", outcome="forwarded", offset=2),
        _mcp_call(tool_name="exec_command", outcome="forwarded", offset=3),
        _model_call(offset=4),
        _mcp_call(tool_name="read_file", outcome="forwarded", offset=5),
        _mcp_call(tool_name="list_dir", outcome="forwarded", offset=6),
    ]


# Receipts with some already denied
def _mixed_receipts() -> List[Dict[str, Any]]:
    return [
        _mcp_call(tool_name="read_file", outcome="forwarded", offset=0),
        _mcp_call(tool_name="exec_command", outcome="denied",
                  policy_verdict="deny", policy_reason="blocked", offset=1),
        _model_call(offset=2),
        _mcp_call(tool_name="write_file", outcome="forwarded", offset=3),
    ]


# ---------------------------------------------------------------------------
# Module tests
# ---------------------------------------------------------------------------

class TestReplayAllAllowed:
    def test_permissive_policy_no_denials(self, tmp_path):
        """Candidate policy allows everything -> 0 newly denied."""
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "mode": "audit",
            "tools": {"default": "allow"},
        })
        impact = replay_policy(pack_dir, policy_path)
        assert impact.would_deny == 0
        assert impact.newly_denied == []
        assert impact.total_tool_calls == 5

    def test_model_calls_counted(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        impact = replay_policy(pack_dir, policy_path)
        assert impact.total_model_calls == 2


class TestReplaySomeDenied:
    def test_deny_list_blocks_tools(self, tmp_path):
        """Deny list blocks 2 of 5 tools -> 2 newly denied."""
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {
                "default": "allow",
                "deny": ["exec_command", "write_file"],
            },
        })
        impact = replay_policy(pack_dir, policy_path)
        assert impact.would_deny == 2
        assert len(impact.newly_denied) == 2
        denied_tools = {nd["tool_name"] for nd in impact.newly_denied}
        assert "exec_command" in denied_tools
        assert "write_file" in denied_tools

    def test_default_deny_blocks_unlisted(self, tmp_path):
        """Default deny with allow list -> blocks unlisted tools."""
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {
                "default": "deny",
                "allow": ["read_file"],
            },
        })
        impact = replay_policy(pack_dir, policy_path)
        # read_file appears twice, all others denied
        assert impact.would_deny == 3  # write_file, exec_command, list_dir


class TestReplayRelaxedPolicy:
    def test_relaxed_policy_newly_allowed(self, tmp_path):
        """More permissive policy -> previously denied calls now allowed."""
        receipts = _mixed_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        impact = replay_policy(pack_dir, policy_path)
        assert len(impact.newly_allowed) == 1
        assert impact.newly_allowed[0]["tool_name"] == "exec_command"


class TestReplayNoMCPReceipts:
    def test_model_only_pack(self, tmp_path):
        """Pack with only model_calls -> 0 tool calls replayed."""
        receipts = [_model_call(offset=i) for i in range(3)]
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "deny"},
        })
        impact = replay_policy(pack_dir, policy_path)
        assert impact.total_tool_calls == 0
        assert impact.would_deny == 0
        assert impact.total_model_calls == 3


class TestReplaySummary:
    def test_summary_mentions_denials(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = replay_policy(pack_dir, policy_path)
        assert "NEWLY DENIED" in impact.summary

    def test_summary_no_change(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        impact = replay_policy(pack_dir, policy_path)
        assert "No change" in impact.summary


class TestReplaySerialization:
    def test_to_dict_json_serializable(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = replay_policy(pack_dir, policy_path)
        d = impact.to_dict()
        s = json.dumps(d)
        assert isinstance(json.loads(s), dict)
        assert d["total_tool_calls"] == 5


class TestReplayErrors:
    def test_invalid_policy(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: valid: yaml: [", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid candidate policy"):
            replay_policy(pack_dir, bad)

    def test_invalid_pack(self, tmp_path):
        policy_path = _write_policy(tmp_path, {"version": "1"})
        with pytest.raises(FileNotFoundError):
            replay_policy(tmp_path / "nonexistent", policy_path)

    def test_pack_no_manifest(self, tmp_path):
        (tmp_path / "empty_pack").mkdir()
        policy_path = _write_policy(tmp_path, {"version": "1"})
        with pytest.raises(FileNotFoundError):
            replay_policy(tmp_path / "empty_pack", policy_path)


# ---------------------------------------------------------------------------
# Renderer tests
# ---------------------------------------------------------------------------

class TestRenderers:
    def test_render_text(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = replay_policy(pack_dir, policy_path)
        text = render_impact_text(impact)
        assert "POLICY REPLAY" in text
        assert "NEWLY DENIED" in text

    def test_render_md(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = replay_policy(pack_dir, policy_path)
        md = render_impact_md(impact)
        assert "# Policy Replay" in md
        assert "## Newly Denied" in md


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLIReplay:
    def test_basic_replay(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        result = runner.invoke(assay_app, [
            "incident", "replay", str(pack_dir),
            "-p", str(policy_path),
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert "POLICY REPLAY" in result.output

    def test_json_output(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        policy_path = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        result = runner.invoke(assay_app, [
            "incident", "replay", str(pack_dir),
            "-p", str(policy_path),
            "--json",
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)
        assert data["command"] == "incident replay"
        assert "total_tool_calls" in data

    def test_bad_policy(self, tmp_path):
        receipts = _standard_receipts()
        pack_dir = _build_pack(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "incident", "replay", str(pack_dir),
            "-p", str(tmp_path / "nonexistent.yaml"),
        ])
        assert result.exit_code == 3
