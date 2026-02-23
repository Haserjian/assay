"""Tests for assay policy_guard (Policy Merge Guard)."""
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
from assay.policy_guard import (
    AggregateImpact,
    aggregate_policy_impact,
    evaluate_thresholds,
    render_impact_md,
    render_impact_text,
)
from assay.proof_pack import ProofPack

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)


def _ts(offset_minutes: int = 0) -> str:
    return (_T0 + timedelta(minutes=offset_minutes)).isoformat()


def _mcp_call(tool_name="read_file", outcome="forwarded", policy_verdict="allow",
              policy_reason="", offset=0, **kw) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "mcp_tool_call",
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "tool_name": tool_name,
        "outcome": outcome,
        "policy_verdict": policy_verdict,
        "policy_reason": policy_reason,
        "duration_ms": 50.0,
    }
    base.update(kw)
    return base


def _model_call(model_id="gpt-4", offset=0, **kw) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "model_id": model_id,
        "input_tokens": 100,
        "output_tokens": 50,
        "latency_ms": 200.0,
    }
    base.update(kw)
    return base


def _build_pack(tmp_path: Path, receipts: List[Dict[str, Any]],
                pack_name: str = "pack") -> Path:
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("pg-signer")
    pack = ProofPack(
        run_id="pg-test-run",
        entries=receipts,
        signer_id="pg-signer",
        mode="shadow",
    )
    return pack.build(tmp_path / pack_name, keystore=ks)


def _write_policy(tmp_path: Path, policy_dict: Dict[str, Any],
                  name: str = "candidate.yaml") -> Path:
    import yaml
    p = tmp_path / name
    p.write_text(yaml.dump(policy_dict), encoding="utf-8")
    return p


def _setup_multi_pack(tmp_path: Path) -> Path:
    """Create a packs directory with 3 pack subdirectories."""
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()

    # Pack 1: 3 tool calls (read_file, write_file, exec_command)
    r1 = [
        _mcp_call(tool_name="read_file", offset=0),
        _mcp_call(tool_name="write_file", offset=1),
        _mcp_call(tool_name="exec_command", offset=2),
        _model_call(offset=3),
    ]
    _build_pack(tmp_path, r1, pack_name="packs/pack_a")

    # Pack 2: 2 tool calls (read_file, list_dir)
    r2 = [
        _mcp_call(tool_name="read_file", offset=0),
        _mcp_call(tool_name="list_dir", offset=1),
        _model_call(offset=2),
    ]
    _build_pack(tmp_path, r2, pack_name="packs/pack_b")

    # Pack 3: 2 tool calls (exec_command, write_file) + 1 denied
    r3 = [
        _mcp_call(tool_name="exec_command", offset=0),
        _mcp_call(tool_name="write_file", offset=1, outcome="denied",
                  policy_verdict="deny", policy_reason="blocked"),
        _model_call(offset=2),
    ]
    _build_pack(tmp_path, r3, pack_name="packs/pack_c")

    return packs_dir


# ---------------------------------------------------------------------------
# Aggregation tests
# ---------------------------------------------------------------------------

class TestAggregateSinglePack:
    def test_single_pack_all_allowed(self, tmp_path):
        receipts = [
            _mcp_call(tool_name="read_file", offset=0),
            _mcp_call(tool_name="write_file", offset=1),
            _model_call(offset=2),
        ]
        pack_dir = _build_pack(tmp_path, receipts)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        # Put pack in a packs dir
        packs_dir = tmp_path / "single_packs"
        packs_dir.mkdir()
        pack_dir.rename(packs_dir / "pack_a")

        impact = aggregate_policy_impact(packs_dir, policy)
        assert impact.packs_examined == 1
        assert impact.mcp_calls_examined == 2
        assert impact.model_calls_examined == 1
        assert impact.newly_denied_count == 0
        assert impact.risk_delta == 0.0


class TestAggregateMultiPack:
    def test_multi_pack_deny_some(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        assert impact.packs_examined == 3
        assert impact.mcp_calls_examined == 7  # 3 + 2 + 2
        assert impact.newly_denied_count == 2  # exec_command in pack_a + pack_c
        assert impact.risk_delta > 0

    def test_multi_pack_all_allowed(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        assert impact.newly_denied_count == 0
        assert impact.risk_delta == 0.0


class TestAggregateEmptyPacks:
    def test_no_packs(self, tmp_path):
        packs_dir = tmp_path / "empty_packs"
        packs_dir.mkdir()
        policy = _write_policy(tmp_path, {"version": "1"})
        impact = aggregate_policy_impact(packs_dir, policy)
        assert impact.packs_examined == 0
        assert impact.mcp_calls_examined == 0
        assert impact.risk_delta == 0.0

    def test_no_mcp_receipts(self, tmp_path):
        receipts = [_model_call(offset=0), _model_call(offset=1)]
        pack_dir = _build_pack(tmp_path, receipts)
        packs_dir = tmp_path / "model_only_packs"
        packs_dir.mkdir()
        pack_dir.rename(packs_dir / "pack_a")

        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "deny"},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        assert impact.mcp_calls_examined == 0
        assert impact.model_calls_examined == 2
        assert impact.risk_delta == 0.0


class TestAggregateRelaxed:
    def test_newly_allowed(self, tmp_path):
        """Pack with denied calls + permissive candidate -> newly allowed."""
        receipts = [
            _mcp_call(tool_name="exec_command", outcome="denied",
                      policy_verdict="deny", offset=0),
            _mcp_call(tool_name="read_file", offset=1),
        ]
        pack_dir = _build_pack(tmp_path, receipts)
        packs_dir = tmp_path / "relaxed_packs"
        packs_dir.mkdir()
        pack_dir.rename(packs_dir / "pack_a")

        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        assert impact.newly_allowed_count == 1


# ---------------------------------------------------------------------------
# Threshold tests
# ---------------------------------------------------------------------------

class TestThresholds:
    def _make_impact(self, denied=0, risk=0.0) -> AggregateImpact:
        return AggregateImpact(
            policy_old_hash=None,
            policy_new_hash="sha256:abc",
            policy_old_path=None,
            policy_new_path="candidate.yaml",
            packs_examined=1,
            mcp_calls_examined=100,
            model_calls_examined=50,
            newly_denied_count=denied,
            newly_allowed_count=0,
            risk_delta=risk,
        )

    def test_pass_no_thresholds(self):
        impact = self._make_impact(denied=10, risk=0.1)
        verdict, reason = evaluate_thresholds(impact)
        assert verdict == "pass"

    def test_pass_under_thresholds(self):
        impact = self._make_impact(denied=2, risk=0.02)
        verdict, _ = evaluate_thresholds(impact, fail_if_newly_denied=5, fail_if_risk_delta=0.1)
        assert verdict == "pass"

    def test_fail_denied_threshold(self):
        impact = self._make_impact(denied=5, risk=0.05)
        verdict, reason = evaluate_thresholds(impact, fail_if_newly_denied=3)
        assert verdict == "fail"
        assert "newly_denied_count" in reason
        assert "5" in reason

    def test_fail_risk_delta_threshold(self):
        impact = self._make_impact(denied=10, risk=0.15)
        verdict, reason = evaluate_thresholds(impact, fail_if_risk_delta=0.1)
        assert verdict == "fail"
        assert "risk_delta" in reason

    def test_denied_threshold_exact_boundary(self):
        """Exactly at threshold should pass (> not >=)."""
        impact = self._make_impact(denied=3)
        verdict, _ = evaluate_thresholds(impact, fail_if_newly_denied=3)
        assert verdict == "pass"

    def test_denied_threshold_zero(self):
        """fail_if_newly_denied=0 means any denial fails."""
        impact = self._make_impact(denied=1)
        verdict, _ = evaluate_thresholds(impact, fail_if_newly_denied=0)
        assert verdict == "fail"


# ---------------------------------------------------------------------------
# Severity + top tools tests
# ---------------------------------------------------------------------------

class TestSeverityBreakdown:
    def test_severity_counts(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command", "write_file"]},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        assert "deny_list" in impact.severity_breakdown
        assert impact.severity_breakdown["deny_list"] >= 3  # exec+write across packs

    def test_top_changed_tools_sorted(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command", "write_file"]},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        if len(impact.top_changed_tools) >= 2:
            # Should be sorted by newly_denied descending
            assert impact.top_changed_tools[0]["newly_denied"] >= impact.top_changed_tools[1]["newly_denied"]


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_to_dict_json_serializable(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        d = impact.to_dict()
        s = json.dumps(d)
        parsed = json.loads(s)
        assert parsed["packs_examined"] == 3


# ---------------------------------------------------------------------------
# Renderer tests
# ---------------------------------------------------------------------------

class TestRenderers:
    def test_render_text(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        text = render_impact_text(impact, verdict="fail", verdict_reason="too many denials")
        assert "POLICY IMPACT ANALYSIS" in text
        assert "CI VERDICT: FAIL" in text

    def test_render_md(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        impact = aggregate_policy_impact(packs_dir, policy)
        md = render_impact_md(impact, verdict="pass")
        assert "# Policy Impact Analysis" in md
        assert "PASS" in md


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI:
    def test_basic_impact(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(policy),
            "--packs", str(packs_dir),
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert "POLICY IMPACT" in result.output

    def test_json_output(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(policy),
            "--packs", str(packs_dir),
            "--json",
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)
        assert data["command"] == "policy impact"
        assert data["ci_verdict"] == "pass"
        assert "packs_examined" in data

    def test_md_output(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(policy),
            "--packs", str(packs_dir),
            "--format", "md",
        ])
        assert result.exit_code == 0
        assert "# Policy Impact" in result.output

    def test_threshold_fail_exit_1(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow", "deny": ["exec_command"]},
        })
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(policy),
            "--packs", str(packs_dir),
            "--fail-if-newly-denied", "0",
        ])
        assert result.exit_code == 1

    def test_threshold_pass_exit_0(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        policy = _write_policy(tmp_path, {
            "version": "1",
            "tools": {"default": "allow"},
        })
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(policy),
            "--packs", str(packs_dir),
            "--fail-if-newly-denied", "0",
        ])
        assert result.exit_code == 0

    def test_bad_policy_exit_3(self, tmp_path):
        packs_dir = _setup_multi_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(tmp_path / "nonexistent.yaml"),
            "--packs", str(packs_dir),
        ])
        assert result.exit_code == 3

    def test_bad_packs_exit_3(self, tmp_path):
        policy = _write_policy(tmp_path, {"version": "1"})
        result = runner.invoke(assay_app, [
            "policy", "impact",
            "--policy-new", str(policy),
            "--packs", str(tmp_path / "nonexistent"),
        ])
        assert result.exit_code == 3
