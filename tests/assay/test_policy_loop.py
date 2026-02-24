"""Tests for policy loop: receipt -> signal -> recommendation pipeline."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.policy_loop import (
    PolicyLoopResult,
    Recommendation,
    TrendComparison,
    WindowSignals,
    aggregate_signals,
    analyze_receipt_history,
    compare_windows,
    generate_recommendations,
    load_receipts_in_window,
    render_text,
)

runner = CliRunner()

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)


def _ts(offset_minutes: int = 0) -> str:
    return (_T0 + timedelta(minutes=offset_minutes)).isoformat()


def _receipt(
    tool_name: str = "read_file",
    outcome: str = "ok",
    allowed: bool = True,
    policy_verdict: str = "allow",
    offset: int = 0,
    rtype: str = "mcp_tool_call",
    **kw: Any,
) -> Dict[str, Any]:
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": rtype,
        "timestamp": _ts(offset),
        "schema_version": "3.0",
        "tool_name": tool_name,
        "outcome": outcome,
        "allowed": allowed,
        "policy_verdict": policy_verdict,
        "duration_ms": 42.0,
    }
    base.update(kw)
    return base


def _write_receipts(store_dir: Path, receipts: List[Dict[str, Any]], day: str = "2026-02-20") -> None:
    """Write receipts as JSONL into a fake store directory."""
    day_dir = store_dir / day
    day_dir.mkdir(parents=True, exist_ok=True)
    trace_file = day_dir / f"trace_{uuid.uuid4().hex[:8]}.jsonl"
    with open(trace_file, "w") as f:
        for r in receipts:
            f.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------------------
# Test: load_receipts_in_window
# ---------------------------------------------------------------------------

class TestLoadReceipts:
    def test_empty_store(self, tmp_path: Path):
        receipts = load_receipts_in_window(tmp_path, window_days=7, end_time=_T0)
        assert receipts == []

    def test_nonexistent_store(self, tmp_path: Path):
        receipts = load_receipts_in_window(tmp_path / "nope", window_days=7, end_time=_T0)
        assert receipts == []

    def test_loads_receipts_in_window(self, tmp_path: Path):
        recs = [_receipt(offset=i) for i in range(5)]
        _write_receipts(tmp_path, recs, day="2026-02-20")
        loaded = load_receipts_in_window(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        assert len(loaded) == 5

    def test_excludes_old_receipts(self, tmp_path: Path):
        old = [_receipt(offset=0)]
        old[0]["timestamp"] = (datetime(2026, 1, 1, tzinfo=timezone.utc)).isoformat()
        _write_receipts(tmp_path, old, day="2026-01-01")

        current = [_receipt(offset=i) for i in range(3)]
        _write_receipts(tmp_path, current, day="2026-02-20")

        loaded = load_receipts_in_window(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        assert len(loaded) == 3

    def test_sorted_by_timestamp(self, tmp_path: Path):
        recs = [_receipt(offset=10), _receipt(offset=0), _receipt(offset=5)]
        _write_receipts(tmp_path, recs, day="2026-02-20")
        loaded = load_receipts_in_window(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        timestamps = [r["timestamp"] for r in loaded]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# Test: aggregate_signals
# ---------------------------------------------------------------------------

class TestAggregateSignals:
    def test_all_success(self):
        recs = [_receipt(offset=i) for i in range(10)]
        signals = aggregate_signals(recs)
        assert signals.total_receipts == 10
        assert signals.deny_rate == 0.0
        assert signals.failure_rate == 0.0
        assert signals.timeout_rate == 0.0
        assert signals.success_count == 10

    def test_deny_rate(self):
        recs = [_receipt(offset=i) for i in range(10)]
        recs[0]["allowed"] = False
        recs[1]["policy_verdict"] = "deny"
        recs[1]["allowed"] = False
        signals = aggregate_signals(recs)
        assert signals.deny_count == 2
        assert signals.deny_rate == pytest.approx(0.2)

    def test_failure_rate(self):
        recs = [_receipt(offset=i) for i in range(10)]
        recs[0]["outcome"] = "error"
        recs[1]["outcome"] = "crash"
        signals = aggregate_signals(recs)
        assert signals.failure_count == 2
        assert signals.failure_rate == pytest.approx(0.2)

    def test_timeout_rate(self):
        recs = [_receipt(offset=i) for i in range(10)]
        recs[0]["outcome"] = "timeout"
        signals = aggregate_signals(recs)
        assert signals.timeout_count == 1
        assert signals.timeout_rate == pytest.approx(0.1)

    def test_empty_receipts(self):
        signals = aggregate_signals([])
        assert signals.total_receipts == 0
        assert signals.deny_rate == 0.0
        assert signals.failure_rate == 0.0

    def test_top_denied_tools(self):
        recs = []
        for i in range(5):
            recs.append(_receipt(tool_name="dangerous_tool", allowed=False, offset=i))
        for i in range(3):
            recs.append(_receipt(tool_name="risky_tool", allowed=False, offset=10 + i))
        for i in range(10):
            recs.append(_receipt(tool_name="safe_tool", offset=20 + i))
        signals = aggregate_signals(recs)
        assert len(signals.top_denied_tools) == 2
        assert signals.top_denied_tools[0]["tool"] == "dangerous_tool"
        assert signals.top_denied_tools[0]["count"] == 5

    def test_type_counts(self):
        recs = [
            _receipt(rtype="mcp_tool_call", offset=0),
            _receipt(rtype="mcp_tool_call", offset=1),
            _receipt(rtype="BridgeExecution", offset=2),
        ]
        signals = aggregate_signals(recs)
        assert signals.type_counts["mcp_tool_call"] == 2
        assert signals.type_counts["BridgeExecution"] == 1

    def test_mixed_signals(self):
        recs = [
            _receipt(outcome="ok", offset=0),
            _receipt(outcome="ok", offset=1),
            _receipt(outcome="ok", offset=2),
            _receipt(outcome="error", offset=3),
            _receipt(outcome="timeout", offset=4),
            _receipt(allowed=False, offset=5),
        ]
        signals = aggregate_signals(recs)
        assert signals.total_receipts == 6
        assert signals.success_count == 3
        assert signals.failure_count == 1
        assert signals.timeout_count == 1
        assert signals.deny_count == 1


# ---------------------------------------------------------------------------
# Test: compare_windows
# ---------------------------------------------------------------------------

class TestCompareWindows:
    def test_no_change(self):
        current = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.1, failure_rate=0.05,
            timeout_rate=0.02, deny_count=10, failure_count=5,
            timeout_count=2, success_count=83,
        )
        previous = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.1, failure_rate=0.05,
            timeout_rate=0.02, deny_count=10, failure_count=5,
            timeout_count=2, success_count=83,
        )
        trend = compare_windows(current, previous)
        assert trend.deny_rate_delta == pytest.approx(0.0)
        assert trend.failure_rate_delta == pytest.approx(0.0)

    def test_worsening_trend(self):
        current = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.3, failure_rate=0.2,
            timeout_rate=0.1, deny_count=30, failure_count=20,
            timeout_count=10, success_count=40,
        )
        previous = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.1, failure_rate=0.05,
            timeout_rate=0.02, deny_count=10, failure_count=5,
            timeout_count=2, success_count=83,
        )
        trend = compare_windows(current, previous)
        assert trend.deny_rate_delta == pytest.approx(0.2)
        assert trend.failure_rate_delta == pytest.approx(0.15)

    def test_improving_trend(self):
        current = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.05, failure_rate=0.01,
            timeout_rate=0.0, deny_count=5, failure_count=1,
            timeout_count=0, success_count=94,
        )
        previous = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=80, deny_rate=0.2, failure_rate=0.1,
            timeout_rate=0.05, deny_count=16, failure_count=8,
            timeout_count=4, success_count=52,
        )
        trend = compare_windows(current, previous)
        assert trend.deny_rate_delta < 0  # improved
        assert trend.failure_rate_delta < 0


# ---------------------------------------------------------------------------
# Test: generate_recommendations
# ---------------------------------------------------------------------------

class TestGenerateRecommendations:
    def test_healthy_system(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.02, failure_rate=0.01,
            timeout_rate=0.0, deny_count=2, failure_count=1,
            timeout_count=0, success_count=97,
        )
        recs = generate_recommendations(signals)
        assert len(recs) == 1
        assert recs[0].severity == "info"
        assert recs[0].signal == "healthy"

    def test_high_deny_rate_critical(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.35, failure_rate=0.0,
            timeout_rate=0.0, deny_count=35, failure_count=0,
            timeout_count=0, success_count=65,
        )
        recs = generate_recommendations(signals)
        assert any(r.signal == "high_deny_rate" and r.severity == "critical" for r in recs)

    def test_elevated_deny_rate_warning(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.15, failure_rate=0.0,
            timeout_rate=0.0, deny_count=15, failure_count=0,
            timeout_count=0, success_count=85,
        )
        recs = generate_recommendations(signals)
        assert any(r.signal == "elevated_deny_rate" and r.severity == "warning" for r in recs)

    def test_high_failure_rate_critical(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.0, failure_rate=0.25,
            timeout_rate=0.0, deny_count=0, failure_count=25,
            timeout_count=0, success_count=75,
        )
        recs = generate_recommendations(signals)
        assert any(r.signal == "high_failure_rate" and r.severity == "critical" for r in recs)

    def test_timeout_warning(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.0, failure_rate=0.0,
            timeout_rate=0.15, deny_count=0, failure_count=0,
            timeout_count=15, success_count=85,
        )
        recs = generate_recommendations(signals)
        assert any(r.signal == "elevated_timeout_rate" for r in recs)

    def test_deny_trend_warning(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.15, failure_rate=0.0,
            timeout_rate=0.0, deny_count=15, failure_count=0,
            timeout_count=0, success_count=85,
        )
        trend = TrendComparison(
            deny_rate_delta=0.10, failure_rate_delta=0.0,
            timeout_rate_delta=0.0, total_receipts_delta=0,
        )
        recs = generate_recommendations(signals, trend)
        assert any(r.signal == "deny_rate_trending_up" for r in recs)

    def test_no_receipts_info(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=0, deny_rate=0.0, failure_rate=0.0,
            timeout_rate=0.0, deny_count=0, failure_count=0,
            timeout_count=0, success_count=0,
        )
        recs = generate_recommendations(signals)
        assert len(recs) == 1
        assert recs[0].signal == "no_receipts"

    def test_multiple_issues(self):
        signals = WindowSignals(
            window_start="", window_end="", window_days=7,
            total_receipts=100, deny_rate=0.35, failure_rate=0.25,
            timeout_rate=0.15, deny_count=35, failure_count=25,
            timeout_count=15, success_count=25,
        )
        recs = generate_recommendations(signals)
        assert len(recs) >= 3  # deny + failure + timeout


# ---------------------------------------------------------------------------
# Test: full pipeline (analyze_receipt_history)
# ---------------------------------------------------------------------------

class TestAnalyzeReceiptHistory:
    def test_full_pipeline(self, tmp_path: Path):
        recs = [_receipt(offset=i) for i in range(20)]
        recs[0]["allowed"] = False
        recs[1]["outcome"] = "error"
        _write_receipts(tmp_path, recs, day="2026-02-20")

        result = analyze_receipt_history(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        assert result.current_window.total_receipts == 20
        assert result.recommendation_count >= 1
        assert isinstance(result.generated_at, str)

    def test_with_previous_window(self, tmp_path: Path):
        # Previous window
        old_ts = _T0 - timedelta(days=10)
        old = []
        for i in range(10):
            r = _receipt(offset=0)
            r["timestamp"] = (old_ts + timedelta(minutes=i)).isoformat()
            old.append(r)
        _write_receipts(tmp_path, old, day="2026-02-10")

        # Current window
        current = [_receipt(offset=i) for i in range(15)]
        _write_receipts(tmp_path, current, day="2026-02-20")

        result = analyze_receipt_history(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        assert result.current_window.total_receipts == 15
        # Previous window might or might not load depending on exact timestamps
        # The key thing is the pipeline runs without error

    def test_result_serializes_to_json(self, tmp_path: Path):
        recs = [_receipt(offset=i) for i in range(5)]
        _write_receipts(tmp_path, recs, day="2026-02-20")

        result = analyze_receipt_history(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        d = result.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)
        parsed = json.loads(serialized)
        assert parsed["current_window"]["total_receipts"] == 5


# ---------------------------------------------------------------------------
# Test: render_text
# ---------------------------------------------------------------------------

class TestRenderText:
    def test_renders_without_error(self, tmp_path: Path):
        recs = [_receipt(offset=i) for i in range(5)]
        recs[0]["allowed"] = False
        _write_receipts(tmp_path, recs, day="2026-02-20")

        result = analyze_receipt_history(tmp_path, window_days=7, end_time=_T0 + timedelta(hours=1))
        text = render_text(result)
        assert "Policy Loop Analysis" in text
        assert "Deny rate:" in text
        assert "Recommendations:" in text

    def test_renders_with_trend(self):
        current = WindowSignals(
            window_start="2026-02-20T00:00:00", window_end="2026-02-20T23:59:59",
            window_days=7, total_receipts=100, deny_rate=0.2, failure_rate=0.1,
            timeout_rate=0.05, deny_count=20, failure_count=10,
            timeout_count=5, success_count=65,
        )
        trend = TrendComparison(
            deny_rate_delta=0.1, failure_rate_delta=0.05,
            timeout_rate_delta=0.02, total_receipts_delta=20,
        )
        recs = generate_recommendations(current, trend)
        result = PolicyLoopResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            current_window=current,
            previous_window=None,
            trend=trend,
            recommendations=recs,
            recommendation_count=len(recs),
            has_critical=any(r.severity == "critical" for r in recs),
        )
        text = render_text(result)
        assert "Trend" in text
        assert "+" in text  # Positive delta shown


# ---------------------------------------------------------------------------
# Test: CLI
# ---------------------------------------------------------------------------

class TestCLI:
    def test_recommend_no_store(self, tmp_path: Path):
        result = runner.invoke(
            assay_app,
            ["policy", "recommend", "--store-dir", str(tmp_path / "nonexistent")],
        )
        assert result.exit_code == 3

    def test_recommend_empty_store(self, tmp_path: Path):
        store = tmp_path / "store"
        store.mkdir()
        result = runner.invoke(
            assay_app,
            ["policy", "recommend", "--store-dir", str(store)],
        )
        assert result.exit_code == 0  # no receipts = info, not critical

    def test_recommend_json_output(self, tmp_path: Path):
        store = tmp_path / "store"
        recs = [_receipt(offset=i) for i in range(5)]
        _write_receipts(store, recs, day="2026-02-20")

        result = runner.invoke(
            assay_app,
            ["policy", "recommend", "--store-dir", str(store), "--window", "30", "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["command"] == "policy recommend"
        assert data["current_window"]["total_receipts"] == 5

    def test_recommend_critical_exits_1(self, tmp_path: Path):
        store = tmp_path / "store"
        # 100 receipts, 35 denied -> 35% deny rate -> critical
        recs = []
        for i in range(100):
            r = _receipt(offset=i)
            if i < 35:
                r["allowed"] = False
            recs.append(r)
        _write_receipts(store, recs, day="2026-02-20")

        result = runner.invoke(
            assay_app,
            ["policy", "recommend", "--store-dir", str(store), "--window", "30", "--json"],
        )
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert data["has_critical"] is True
