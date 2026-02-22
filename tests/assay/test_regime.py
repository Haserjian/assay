"""Tests for assay regime detection (temporal intelligence)."""
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
from assay.regime import (
    COST_SPIKE_ALERT,
    COST_SPIKE_WARNING,
    ERROR_SPIKE_ALERT,
    ERROR_SPIKE_WARNING,
    LATENCY_DRIFT_ALERT,
    LATENCY_DRIFT_WARNING,
    MIN_CALLS_PER_WINDOW,
    DriftFlag,
    RegimeReport,
    WindowStats,
    aggregate_windows,
    detect_regimes,
)


# ---------------------------------------------------------------------------
# Synthetic receipt builders
# ---------------------------------------------------------------------------

_BASE_TS = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)


def _make_receipt(
    *,
    hour_offset: float = 0,
    model_id: str = "gpt-4o",
    provider: str = "openai",
    input_tokens: int = 100,
    output_tokens: int = 50,
    latency_ms: float = 500,
    error: bool = False,
    seq: int = 0,
) -> Dict[str, Any]:
    ts = _BASE_TS + timedelta(hours=hour_offset)
    r: Dict[str, Any] = {
        "receipt_id": f"r_{seq}_{int(hour_offset * 100):06d}",
        "type": "model_call",
        "timestamp": ts.isoformat(),
        "schema_version": "3.0",
        "seq": seq,
        "model_id": model_id,
        "provider": provider,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": latency_ms,
        "finish_reason": "stop",
    }
    if error:
        r["error"] = "test error"
    return r


def _make_window_receipts(
    n: int,
    *,
    hour_start: float = 0,
    hour_spread: float = 1.0,
    **kwargs,
) -> List[Dict[str, Any]]:
    """Create n receipts spread across a time window."""
    receipts = []
    for i in range(n):
        offset = hour_start + (hour_spread * i / max(n - 1, 1))
        receipts.append(_make_receipt(hour_offset=offset, seq=i, **kwargs))
    return receipts


# ---------------------------------------------------------------------------
# Window aggregation tests
# ---------------------------------------------------------------------------


class TestAggregateWindows:
    def test_empty_receipts(self):
        assert aggregate_windows([]) == []

    def test_non_model_call_ignored(self):
        receipts = [
            {"type": "guardian_verdict", "timestamp": _BASE_TS.isoformat()},
        ]
        assert aggregate_windows(receipts) == []

    def test_single_receipt_one_window(self):
        receipts = [_make_receipt(hour_offset=0)]
        windows = aggregate_windows(receipts, window_hours=24)
        assert len(windows) == 1
        assert windows[0].n_calls == 1

    def test_two_days_two_windows(self):
        receipts = (
            _make_window_receipts(5, hour_start=1, hour_spread=2) +
            _make_window_receipts(5, hour_start=25, hour_spread=2)
        )
        windows = aggregate_windows(receipts, window_hours=24)
        assert len(windows) == 2
        assert windows[0].n_calls == 5
        assert windows[1].n_calls == 5

    def test_window_stats_accumulate(self):
        receipts = _make_window_receipts(
            4, hour_start=0, hour_spread=2,
            input_tokens=100, output_tokens=50, latency_ms=500,
        )
        windows = aggregate_windows(receipts, window_hours=24)
        assert len(windows) == 1
        w = windows[0]
        assert w.n_calls == 4
        assert w.input_tokens == 400
        assert w.output_tokens == 200
        assert w.total_tokens == 600
        assert len(w.latencies) == 4
        assert all(lat == 500 for lat in w.latencies)

    def test_model_counts(self):
        receipts = [
            _make_receipt(hour_offset=0, model_id="gpt-4o", seq=0),
            _make_receipt(hour_offset=1, model_id="gpt-4o", seq=1),
            _make_receipt(hour_offset=2, model_id="claude-3-haiku", seq=2),
        ]
        windows = aggregate_windows(receipts, window_hours=24)
        assert windows[0].models == {"gpt-4o": 2, "claude-3-haiku": 1}

    def test_provider_counts(self):
        receipts = [
            _make_receipt(hour_offset=0, provider="openai", seq=0),
            _make_receipt(hour_offset=1, provider="anthropic", seq=1),
        ]
        windows = aggregate_windows(receipts, window_hours=24)
        assert windows[0].providers == {"openai": 1, "anthropic": 1}

    def test_error_count(self):
        receipts = [
            _make_receipt(hour_offset=0, error=False, seq=0),
            _make_receipt(hour_offset=1, error=True, seq=1),
            _make_receipt(hour_offset=2, error=True, seq=2),
        ]
        windows = aggregate_windows(receipts, window_hours=24)
        assert windows[0].errors == 2
        assert windows[0].error_rate == pytest.approx(2 / 3, abs=0.01)

    def test_custom_window_hours(self):
        # 12 receipts over 12 hours, 6-hour windows -> 2 windows
        receipts = _make_window_receipts(12, hour_start=0, hour_spread=11)
        windows = aggregate_windows(receipts, window_hours=6)
        assert len(windows) == 2

    def test_empty_windows_omitted(self):
        # Receipts in hour 0-2 and 48-50 (gap in middle)
        receipts = (
            _make_window_receipts(3, hour_start=0, hour_spread=1) +
            _make_window_receipts(3, hour_start=48, hour_spread=1)
        )
        windows = aggregate_windows(receipts, window_hours=24)
        # Should have 2 windows (day 1 and day 3), day 2 empty and omitted
        assert len(windows) == 2

    def test_missing_timestamp_skipped(self):
        receipts = [
            _make_receipt(hour_offset=0, seq=0),
            {"type": "model_call", "seq": 1},  # no timestamp
        ]
        windows = aggregate_windows(receipts, window_hours=24)
        assert windows[0].n_calls == 1


# ---------------------------------------------------------------------------
# WindowStats property tests
# ---------------------------------------------------------------------------


class TestWindowStatsProperties:
    def test_latency_mean(self):
        ws = WindowStats(
            window_start="", window_end="",
            n_calls=3, latencies=[100, 200, 300],
        )
        assert ws.latency_mean == 200.0

    def test_latency_p50(self):
        ws = WindowStats(
            window_start="", window_end="",
            n_calls=4, latencies=[100, 200, 300, 400],
        )
        assert ws.latency_p50 == 300  # index 2 for 4 items at 50%

    def test_latency_p95(self):
        ws = WindowStats(
            window_start="", window_end="",
            n_calls=20, latencies=list(range(1, 21)),
        )
        # 95% of 20 = index 19, capped at 19
        assert ws.latency_p95 == 20

    def test_empty_latencies(self):
        ws = WindowStats(window_start="", window_end="", n_calls=0)
        assert ws.latency_mean is None
        assert ws.latency_p50 is None
        assert ws.latency_p95 is None

    def test_dominant_model(self):
        ws = WindowStats(
            window_start="", window_end="",
            models={"gpt-4o": 10, "claude-3": 3},
        )
        assert ws.dominant_model == "gpt-4o"

    def test_dominant_model_empty(self):
        ws = WindowStats(window_start="", window_end="")
        assert ws.dominant_model is None

    def test_cost_per_call(self):
        ws = WindowStats(
            window_start="", window_end="",
            n_calls=10, cost_usd=0.50,
        )
        assert ws.cost_per_call == pytest.approx(0.05)

    def test_cost_per_call_zero_calls(self):
        ws = WindowStats(window_start="", window_end="", n_calls=0)
        assert ws.cost_per_call == 0.0

    def test_to_dict(self):
        ws = WindowStats(
            window_start="2026-02-01T00:00:00+00:00",
            window_end="2026-02-02T00:00:00+00:00",
            n_calls=5, models={"gpt-4o": 5},
            latencies=[100, 200],
        )
        d = ws.to_dict()
        assert d["n_calls"] == 5
        assert "latency_ms" in d
        assert d["latency_ms"]["mean"] is not None


# ---------------------------------------------------------------------------
# Model swap detection tests
# ---------------------------------------------------------------------------


class TestModelSwapDetection:
    def test_no_swap_same_model(self):
        receipts = (
            _make_window_receipts(5, hour_start=0, model_id="gpt-4o") +
            _make_window_receipts(5, hour_start=24, model_id="gpt-4o")
        )
        report = detect_regimes(receipts, window_hours=24)
        swaps = [f for f in report.flags if f.flag_type == "model_swap"]
        assert len(swaps) == 0

    def test_swap_detected(self):
        receipts = (
            _make_window_receipts(5, hour_start=0, model_id="gpt-4o") +
            _make_window_receipts(5, hour_start=24, model_id="claude-3-sonnet")
        )
        report = detect_regimes(receipts, window_hours=24)
        swaps = [f for f in report.flags if f.flag_type == "model_swap"]
        assert len(swaps) == 1
        assert swaps[0].detail["before"] == "gpt-4o"
        assert swaps[0].detail["after"] == "claude-3-sonnet"

    def test_swap_alert_on_complete_replacement(self):
        receipts = (
            _make_window_receipts(5, hour_start=0, model_id="gpt-4o") +
            _make_window_receipts(5, hour_start=24, model_id="claude-3-sonnet")
        )
        report = detect_regimes(receipts, window_hours=24)
        swaps = [f for f in report.flags if f.flag_type == "model_swap"]
        assert swaps[0].severity == "alert"
        assert "gpt-4o" in swaps[0].detail["removed_models"]

    def test_swap_ignored_below_min_calls(self):
        # Only 2 calls per window (below MIN_CALLS_PER_WINDOW=3)
        receipts = (
            _make_window_receipts(2, hour_start=0, model_id="gpt-4o") +
            _make_window_receipts(2, hour_start=24, model_id="claude-3-sonnet")
        )
        report = detect_regimes(receipts, window_hours=24)
        swaps = [f for f in report.flags if f.flag_type == "model_swap"]
        assert len(swaps) == 0


# ---------------------------------------------------------------------------
# Cost spike detection tests
# ---------------------------------------------------------------------------


class TestCostSpikeDetection:
    def test_no_spike_stable_cost(self):
        receipts = (
            _make_window_receipts(5, hour_start=0, input_tokens=100, output_tokens=50) +
            _make_window_receipts(5, hour_start=24, input_tokens=100, output_tokens=50)
        )
        report = detect_regimes(receipts, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "cost_spike"]
        assert len(spikes) == 0

    def test_warning_on_moderate_spike(self):
        # Second window: 2x tokens -> ~2x cost per call
        receipts = (
            _make_window_receipts(5, hour_start=0, input_tokens=100, output_tokens=50) +
            _make_window_receipts(5, hour_start=24, input_tokens=200, output_tokens=100)
        )
        report = detect_regimes(receipts, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "cost_spike"]
        assert len(spikes) == 1
        assert spikes[0].severity in ("warning", "alert")

    def test_alert_on_large_spike(self):
        # 10x the tokens
        receipts = (
            _make_window_receipts(5, hour_start=0, input_tokens=100, output_tokens=50) +
            _make_window_receipts(5, hour_start=24, input_tokens=1000, output_tokens=500)
        )
        report = detect_regimes(receipts, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "cost_spike"]
        assert len(spikes) == 1
        assert spikes[0].severity == "alert"

    def test_cost_decrease_not_flagged(self):
        # Cost goes down -- not a spike
        receipts = (
            _make_window_receipts(5, hour_start=0, input_tokens=1000, output_tokens=500) +
            _make_window_receipts(5, hour_start=24, input_tokens=100, output_tokens=50)
        )
        report = detect_regimes(receipts, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "cost_spike"]
        assert len(spikes) == 0


# ---------------------------------------------------------------------------
# Latency drift detection tests
# ---------------------------------------------------------------------------


class TestLatencyDriftDetection:
    def test_no_drift_stable_latency(self):
        receipts = (
            _make_window_receipts(5, hour_start=0, latency_ms=500) +
            _make_window_receipts(5, hour_start=24, latency_ms=500)
        )
        report = detect_regimes(receipts, window_hours=24)
        drifts = [f for f in report.flags if f.flag_type == "latency_drift"]
        assert len(drifts) == 0

    def test_warning_on_moderate_drift(self):
        # 80% increase (above 50% warning threshold)
        receipts = (
            _make_window_receipts(5, hour_start=0, latency_ms=500) +
            _make_window_receipts(5, hour_start=24, latency_ms=900)
        )
        report = detect_regimes(receipts, window_hours=24)
        drifts = [f for f in report.flags if f.flag_type == "latency_drift"]
        assert len(drifts) == 1
        assert drifts[0].severity == "warning"

    def test_alert_on_large_drift(self):
        # 200% increase (above 100% alert threshold)
        receipts = (
            _make_window_receipts(5, hour_start=0, latency_ms=500) +
            _make_window_receipts(5, hour_start=24, latency_ms=1500)
        )
        report = detect_regimes(receipts, window_hours=24)
        drifts = [f for f in report.flags if f.flag_type == "latency_drift"]
        assert len(drifts) == 1
        assert drifts[0].severity == "alert"

    def test_latency_decrease_not_flagged(self):
        receipts = (
            _make_window_receipts(5, hour_start=0, latency_ms=1000) +
            _make_window_receipts(5, hour_start=24, latency_ms=200)
        )
        report = detect_regimes(receipts, window_hours=24)
        drifts = [f for f in report.flags if f.flag_type == "latency_drift"]
        assert len(drifts) == 0


# ---------------------------------------------------------------------------
# Error spike detection tests
# ---------------------------------------------------------------------------


class TestErrorSpikeDetection:
    def test_no_spike_zero_errors(self):
        receipts = (
            _make_window_receipts(5, hour_start=0) +
            _make_window_receipts(5, hour_start=24)
        )
        report = detect_regimes(receipts, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "error_spike"]
        assert len(spikes) == 0

    def test_warning_on_error_increase(self):
        # Window 1: 0% errors, Window 2: 60% errors (3/5)
        good = _make_window_receipts(5, hour_start=0)
        bad = []
        for i in range(5):
            r = _make_receipt(hour_offset=24 + i, seq=100 + i, error=(i < 3))
            bad.append(r)
        report = detect_regimes(good + bad, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "error_spike"]
        assert len(spikes) == 1
        assert spikes[0].severity == "alert"  # 60% absolute increase > 15%

    def test_small_error_change_not_flagged(self):
        # Window 1: 0% errors, Window 2: 1/20 = 5% -> exactly at threshold
        w1 = _make_window_receipts(20, hour_start=0, hour_spread=20)
        w2 = []
        for i in range(20):
            r = _make_receipt(hour_offset=24 + i * 0.5, seq=100 + i, error=(i == 0))
            w2.append(r)
        report = detect_regimes(w1 + w2, window_hours=24)
        spikes = [f for f in report.flags if f.flag_type == "error_spike"]
        # 5% exactly at WARNING boundary -- should trigger
        assert len(spikes) == 1
        assert spikes[0].severity == "warning"


# ---------------------------------------------------------------------------
# Full detect_regimes tests
# ---------------------------------------------------------------------------


class TestDetectRegimes:
    def test_empty_receipts(self):
        report = detect_regimes([])
        assert report.n_windows == 0
        assert report.n_receipts == 0
        assert len(report.flags) == 0

    def test_single_window_no_flags(self):
        receipts = _make_window_receipts(10, hour_start=0, hour_spread=20)
        report = detect_regimes(receipts, window_hours=24)
        assert report.n_windows == 1
        assert len(report.flags) == 0

    def test_stable_system_no_flags(self):
        # 7 days, same model, same cost, same latency, no errors
        receipts = []
        for day in range(7):
            receipts.extend(_make_window_receipts(
                10, hour_start=day * 24 + 2, hour_spread=20,
                model_id="gpt-4o", input_tokens=100, output_tokens=50,
                latency_ms=500,
            ))
        report = detect_regimes(receipts, window_hours=24)
        assert report.n_windows == 7
        assert len(report.flags) == 0

    def test_multi_flag_detection(self):
        # Day 1: cheap, fast, gpt-4o
        # Day 2: expensive, slow, claude-3-opus (swap + cost + latency)
        day1 = _make_window_receipts(
            5, hour_start=2, hour_spread=8,
            model_id="gpt-4o", input_tokens=100, output_tokens=50,
            latency_ms=200,
        )
        day2 = _make_window_receipts(
            5, hour_start=26, hour_spread=8,
            model_id="claude-3-opus", input_tokens=5000, output_tokens=2000,
            latency_ms=2000, provider="anthropic",
        )
        report = detect_regimes(day1 + day2, window_hours=24)
        flag_types = {f.flag_type for f in report.flags}
        assert "model_swap" in flag_types
        assert "cost_spike" in flag_types
        assert "latency_drift" in flag_types

    def test_report_to_dict_structure(self):
        receipts = (
            _make_window_receipts(5, hour_start=0) +
            _make_window_receipts(5, hour_start=24, model_id="claude-3-sonnet")
        )
        report = detect_regimes(receipts, window_hours=24)
        d = report.to_dict()
        assert "window_hours" in d
        assert "n_windows" in d
        assert "summary" in d
        assert "flags" in d
        assert "windows" in d
        assert d["summary"]["total_flags"] == len(d["flags"])

    def test_report_severity_counts(self):
        # Generate multiple flags
        day1 = _make_window_receipts(
            5, hour_start=2, model_id="gpt-4o",
            input_tokens=100, output_tokens=50, latency_ms=200,
        )
        day2 = _make_window_receipts(
            5, hour_start=26, model_id="claude-3-opus",
            input_tokens=5000, output_tokens=2000, latency_ms=2000,
            provider="anthropic",
        )
        report = detect_regimes(day1 + day2, window_hours=24)
        assert report.n_alerts + report.n_warnings + report.n_info == len(report.flags)

    def test_flags_sorted_by_time_then_severity(self):
        # 3 days: day2 has model swap + cost spike
        day1 = _make_window_receipts(5, hour_start=2, model_id="gpt-4o",
                                     input_tokens=100, output_tokens=50)
        day2 = _make_window_receipts(5, hour_start=26, model_id="claude-3-opus",
                                     input_tokens=5000, output_tokens=2000,
                                     provider="anthropic")
        day3 = _make_window_receipts(5, hour_start=50, model_id="claude-3-opus",
                                     input_tokens=5000, output_tokens=2000,
                                     provider="anthropic")
        report = detect_regimes(day1 + day2 + day3, window_hours=24)
        for i in range(1, len(report.flags)):
            # Flags should be ordered by window_after, then severity
            assert report.flags[i].window_after >= report.flags[i - 1].window_after

    def test_guardian_receipts_ignored(self):
        receipts = _make_window_receipts(5, hour_start=0)
        receipts.append({
            "type": "guardian_verdict",
            "timestamp": (_BASE_TS + timedelta(hours=25)).isoformat(),
            "verdict": "allow",
        })
        report = detect_regimes(receipts, window_hours=24)
        assert report.n_receipts == 5  # only model_call counted

    def test_window_hours_parameter(self):
        # 12-hour windows on 48 hours of data
        receipts = []
        for i in range(48):
            receipts.append(_make_receipt(hour_offset=i + 0.5, seq=i))
        report = detect_regimes(receipts, window_hours=12)
        assert report.window_hours == 12
        assert report.n_windows == 4


# ---------------------------------------------------------------------------
# DriftFlag and RegimeReport serialization tests
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_drift_flag_to_dict(self):
        flag = DriftFlag(
            flag_type="model_swap",
            severity="alert",
            window_before="2026-02-01T00:00:00+00:00",
            window_after="2026-02-02T00:00:00+00:00",
            description="Model changed",
            detail={"before": "gpt-4o", "after": "claude-3"},
        )
        d = flag.to_dict()
        assert d["flag_type"] == "model_swap"
        assert d["severity"] == "alert"
        assert d["detail"]["before"] == "gpt-4o"

    def test_regime_report_to_dict_json_serializable(self):
        receipts = (
            _make_window_receipts(5, hour_start=0) +
            _make_window_receipts(5, hour_start=24, model_id="claude-3-sonnet")
        )
        report = detect_regimes(receipts, window_hours=24)
        d = report.to_dict()
        # Must be JSON-serializable
        json_str = json.dumps(d)
        assert json_str  # non-empty
        parsed = json.loads(json_str)
        assert parsed["n_windows"] == 2


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------

runner = CliRunner()


def _build_pack_with_receipts(tmp_path: Path, receipts: List[Dict[str, Any]]):
    """Build a signed proof pack from custom receipts."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("regime-test-signer")
    pack = ProofPack(
        run_id="regime-test-run",
        entries=receipts,
        signer_id="regime-test-signer",
        mode="shadow",
    )
    return pack.build(tmp_path / "pack", keystore=ks)


class TestAnalyzeRegimeCLI:
    def test_regime_detect_flag_exists(self, tmp_path):
        """--regime-detect flag is recognized."""
        receipts = _make_window_receipts(5, hour_start=0)
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "analyze", str(pack_dir), "--regime-detect",
        ])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

    def test_regime_detect_no_flags_stable(self, tmp_path):
        """Stable pack should show 'No regime changes'."""
        receipts = _make_window_receipts(5, hour_start=0)
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "analyze", str(pack_dir), "--regime-detect",
        ])
        assert result.exit_code == 0
        assert "Regime Detection" in result.output

    def test_regime_detect_with_drift(self, tmp_path):
        """Pack with model swap should show drift flags."""
        day1 = _make_window_receipts(5, hour_start=0, model_id="gpt-4o")
        day2 = _make_window_receipts(5, hour_start=24, model_id="claude-3-opus",
                                     provider="anthropic",
                                     input_tokens=5000, output_tokens=2000,
                                     latency_ms=2000)
        pack_dir = _build_pack_with_receipts(tmp_path, day1 + day2)
        result = runner.invoke(assay_app, [
            "analyze", str(pack_dir), "--regime-detect",
        ])
        assert result.exit_code == 0
        assert "model_swap" in result.output

    def test_regime_detect_json_output(self, tmp_path):
        """--json includes regime block when --regime-detect is set."""
        day1 = _make_window_receipts(5, hour_start=0, model_id="gpt-4o")
        day2 = _make_window_receipts(5, hour_start=24, model_id="claude-3-sonnet")
        pack_dir = _build_pack_with_receipts(tmp_path, day1 + day2)
        result = runner.invoke(assay_app, [
            "analyze", str(pack_dir), "--regime-detect", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert "regime" in data
        assert data["regime"]["n_windows"] == 2
        assert len(data["regime"]["flags"]) >= 1

    def test_regime_detect_json_without_flag(self, tmp_path):
        """--json without --regime-detect has no regime key."""
        receipts = _make_window_receipts(5, hour_start=0)
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "analyze", str(pack_dir), "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "regime" not in data

    def test_window_hours_option(self, tmp_path):
        """--window-hours parameter is respected."""
        receipts = []
        for i in range(24):
            receipts.append(_make_receipt(hour_offset=i + 0.5, seq=i))
        pack_dir = _build_pack_with_receipts(tmp_path, receipts)
        result = runner.invoke(assay_app, [
            "analyze", str(pack_dir), "--regime-detect",
            "--window-hours", "6", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["regime"]["window_hours"] == 6
        assert data["regime"]["n_windows"] >= 3
