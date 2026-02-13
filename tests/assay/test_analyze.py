"""Tests for receipt analytics (assay analyze)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from assay.analyze import (
    AnalysisResult,
    _lookup_pricing,
    _DEFAULT_PRICING,
    analyze_receipts,
    estimate_cost,
    load_pack_receipts,
    load_history_receipts,
)
from assay import commands as assay_commands


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_receipt(
    model_id: str = "gpt-4o",
    provider: str = "openai",
    input_tokens: int = 1000,
    output_tokens: int = 500,
    latency_ms: int = 800,
    finish_reason: str = "stop",
    error: bool = False,
    timestamp: str = "2026-02-10T12:00:00Z",
    callsite_id: str | None = None,
    callsite_file: str = "",
    callsite_line: str = "",
) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "receipt_id": "r_test",
        "type": "model_call",
        "schema_version": "3.0",
        "model_id": model_id,
        "provider": provider,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": latency_ms,
        "finish_reason": finish_reason,
        "timestamp": timestamp,
    }
    if error:
        r["error"] = "test error"
    if callsite_id:
        r["callsite_id"] = callsite_id
        r["callsite_file"] = callsite_file
        r["callsite_line"] = callsite_line
    return r


def _make_non_model_receipt() -> Dict[str, Any]:
    return {
        "receipt_id": "r_guard",
        "type": "guardian_verdict",
        "schema_version": "3.0",
        "verdict": "allow",
        "action": "generate_summary",
    }


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

class TestPricing:
    def test_exact_match(self) -> None:
        prices = _lookup_pricing("gpt-4o")
        assert prices["input"] == 2.50
        assert prices["output"] == 10.0

    def test_prefix_match(self) -> None:
        prices = _lookup_pricing("gpt-4o-2024-08-06")
        assert prices["input"] == 2.50

    def test_unknown_model_gets_default(self) -> None:
        prices = _lookup_pricing("totally-unknown-model")
        assert prices == _DEFAULT_PRICING

    def test_estimate_cost_gpt4(self) -> None:
        cost = estimate_cost("gpt-4", 1_000_000, 1_000_000)
        assert cost == pytest.approx(90.0)  # 30 + 60

    def test_estimate_cost_zero_tokens(self) -> None:
        cost = estimate_cost("gpt-4o", 0, 0)
        assert cost == 0.0

    def test_anthropic_pricing(self) -> None:
        prices = _lookup_pricing("claude-3-5-sonnet-20241022")
        assert prices["input"] == 3.0
        assert prices["output"] == 15.0


# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------

class TestAnalysisResult:
    def test_error_rate_zero_calls(self) -> None:
        r = AnalysisResult()
        assert r.error_rate == 0.0

    def test_error_rate_with_calls(self) -> None:
        r = AnalysisResult(model_calls=10, errors=2)
        assert r.error_rate == pytest.approx(0.2)

    def test_latency_properties_empty(self) -> None:
        r = AnalysisResult()
        assert r.latency_p50 is None
        assert r.latency_p95 is None
        assert r.latency_p99 is None
        assert r.latency_mean is None
        assert r.latency_max is None

    def test_latency_properties(self) -> None:
        r = AnalysisResult(latencies=[100, 200, 300, 400, 500])
        assert r.latency_p50 == 300
        assert r.latency_max == 500
        assert r.latency_mean == 300.0

    def test_to_dict_basic(self) -> None:
        r = AnalysisResult(
            total_receipts=3,
            model_calls=2,
            input_tokens=1000,
            output_tokens=500,
            total_tokens=1500,
            cost_usd=0.05,
            source_type="pack",
            source_path="/tmp/test",
        )
        d = r.to_dict()
        assert d["model_calls"] == 2
        assert d["tokens"]["total"] == 1500
        assert d["source"]["type"] == "pack"
        assert "latency_ms" not in d  # no latencies

    def test_to_dict_with_latency(self) -> None:
        r = AnalysisResult(latencies=[100, 200])
        d = r.to_dict()
        assert "latency_ms" in d
        assert d["latency_ms"]["max"] == 200

    def test_to_dict_with_callsite(self) -> None:
        r = AnalysisResult(by_callsite={"cs_1": {"file": "app.py", "line": "10", "calls": 1}})
        d = r.to_dict()
        assert "by_callsite" in d


# ---------------------------------------------------------------------------
# analyze_receipts
# ---------------------------------------------------------------------------

class TestAnalyzeReceipts:
    def test_empty_list(self) -> None:
        result = analyze_receipts([])
        assert result.total_receipts == 0
        assert result.model_calls == 0
        assert result.cost_usd == 0.0

    def test_non_model_receipts_ignored(self) -> None:
        result = analyze_receipts([_make_non_model_receipt()])
        assert result.total_receipts == 1
        assert result.model_calls == 0

    def test_single_receipt(self) -> None:
        r = _make_receipt(input_tokens=1000, output_tokens=500)
        result = analyze_receipts([r])
        assert result.model_calls == 1
        assert result.input_tokens == 1000
        assert result.output_tokens == 500
        assert result.total_tokens == 1500
        assert result.cost_usd > 0
        assert result.errors == 0
        assert result.finish_reasons == {"stop": 1}

    def test_multiple_models(self) -> None:
        receipts = [
            _make_receipt(model_id="gpt-4o", provider="openai"),
            _make_receipt(model_id="claude-sonnet-4", provider="anthropic"),
        ]
        result = analyze_receipts(receipts)
        assert result.model_calls == 2
        assert "gpt-4o" in result.by_model
        assert "claude-sonnet-4" in result.by_model
        assert "openai" in result.by_provider
        assert "anthropic" in result.by_provider

    def test_error_counting(self) -> None:
        receipts = [
            _make_receipt(error=False),
            _make_receipt(error=True),
            _make_receipt(error=True),
        ]
        result = analyze_receipts(receipts)
        assert result.errors == 2
        assert result.error_rate == pytest.approx(2 / 3)

    def test_latency_aggregation(self) -> None:
        receipts = [
            _make_receipt(latency_ms=100),
            _make_receipt(latency_ms=200),
            _make_receipt(latency_ms=300),
        ]
        result = analyze_receipts(receipts)
        assert len(result.latencies) == 3
        assert result.latency_p50 == 200

    def test_timestamp_ordering(self) -> None:
        receipts = [
            _make_receipt(timestamp="2026-02-10T12:05:00Z"),
            _make_receipt(timestamp="2026-02-10T12:00:00Z"),
            _make_receipt(timestamp="2026-02-10T12:10:00Z"),
        ]
        result = analyze_receipts(receipts)
        assert result.time_start == "2026-02-10T12:00:00Z"
        assert result.time_end == "2026-02-10T12:10:00Z"

    def test_callsite_breakdown(self) -> None:
        receipts = [
            _make_receipt(callsite_id="cs_1", callsite_file="app.py", callsite_line="10"),
            _make_receipt(callsite_id="cs_1", callsite_file="app.py", callsite_line="10"),
            _make_receipt(callsite_id="cs_2", callsite_file="lib.py", callsite_line="42"),
        ]
        result = analyze_receipts(receipts)
        assert len(result.by_callsite) == 2
        assert result.by_callsite["cs_1"]["calls"] == 2
        assert result.by_callsite["cs_2"]["calls"] == 1

    def test_mixed_receipt_types(self) -> None:
        receipts = [
            _make_receipt(),
            _make_non_model_receipt(),
            _make_receipt(),
            _make_non_model_receipt(),
        ]
        result = analyze_receipts(receipts)
        assert result.total_receipts == 4
        assert result.model_calls == 2

    def test_null_token_counts_treated_as_zero(self) -> None:
        r = _make_receipt()
        r["input_tokens"] = None
        r["output_tokens"] = None
        r["total_tokens"] = None
        result = analyze_receipts([r])
        assert result.input_tokens == 0
        assert result.output_tokens == 0
        assert result.total_tokens == 0

    def test_cost_rounding(self) -> None:
        result = analyze_receipts([_make_receipt()])
        assert isinstance(result.cost_usd, float)
        # Cost should be rounded to 6 decimal places
        cost_str = f"{result.cost_usd:.6f}"
        assert float(cost_str) == result.cost_usd

    def test_by_model_cost_rounded(self) -> None:
        result = analyze_receipts([_make_receipt()])
        for bucket in result.by_model.values():
            cost_str = f"{bucket['cost_usd']:.4f}"
            assert float(cost_str) == bucket["cost_usd"]


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

class TestLoadPackReceipts:
    def test_load_from_pack(self, tmp_path: Path) -> None:
        receipts = [_make_receipt(), _make_receipt(model_id="gpt-4")]
        pack_dir = tmp_path / "pack"
        pack_dir.mkdir()
        lines = [json.dumps(r) for r in receipts]
        (pack_dir / "receipt_pack.jsonl").write_text("\n".join(lines) + "\n")

        loaded = load_pack_receipts(pack_dir)
        assert len(loaded) == 2
        assert loaded[0]["model_id"] == "gpt-4o"
        assert loaded[1]["model_id"] == "gpt-4"

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_pack_receipts(tmp_path / "nonexistent")

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        pack_dir = tmp_path / "pack"
        pack_dir.mkdir()
        content = json.dumps(_make_receipt()) + "\n\n\n" + json.dumps(_make_receipt()) + "\n"
        (pack_dir / "receipt_pack.jsonl").write_text(content)

        loaded = load_pack_receipts(pack_dir)
        assert len(loaded) == 2


class TestLoadHistoryReceipts:
    def test_empty_store(self, tmp_path: Path) -> None:
        receipts, count = load_history_receipts(store_dir=tmp_path / "nope")
        assert receipts == []
        assert count == 0

    def test_loads_traces(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        date_dir = tmp_path / today
        date_dir.mkdir(parents=True)
        trace_file = date_dir / "trace_001.jsonl"
        trace_file.write_text(json.dumps(_make_receipt()) + "\n")

        receipts, count = load_history_receipts(store_dir=tmp_path, since_days=7)
        assert len(receipts) == 1
        assert count == 1

    def test_old_traces_filtered(self, tmp_path: Path) -> None:
        old_dir = tmp_path / "2020-01-01"
        old_dir.mkdir(parents=True)
        (old_dir / "trace_001.jsonl").write_text(json.dumps(_make_receipt()) + "\n")

        receipts, count = load_history_receipts(store_dir=tmp_path, since_days=7)
        assert len(receipts) == 0
        assert count == 0

    def test_bad_json_skipped(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        date_dir = tmp_path / today
        date_dir.mkdir(parents=True)
        trace_file = date_dir / "trace_001.jsonl"
        trace_file.write_text(json.dumps(_make_receipt()) + "\n{bad json}\n")

        receipts, count = load_history_receipts(store_dir=tmp_path, since_days=7)
        assert len(receipts) == 1
        assert count == 1


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestAnalyzeCLI:
    def test_no_args_exits_3(self) -> None:
        runner = CliRunner()
        result = runner.invoke(assay_commands.assay_app, ["analyze"])
        assert result.exit_code == 3

    def test_both_pack_and_history_exits_3(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("pack").mkdir()
            result = runner.invoke(assay_commands.assay_app, ["analyze", "pack", "--history"])
            assert result.exit_code == 3

    def test_nonexistent_pack_exits_3(self) -> None:
        runner = CliRunner()
        result = runner.invoke(assay_commands.assay_app, ["analyze", "/nonexistent/pack"])
        assert result.exit_code == 3

    def test_pack_missing_receipts_exits_3(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("empty_pack").mkdir()
            result = runner.invoke(assay_commands.assay_app, ["analyze", "empty_pack"])
            assert result.exit_code == 3

    def test_analyze_pack_json(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            pack = Path("test_pack")
            pack.mkdir()
            receipts = [
                _make_receipt(model_id="gpt-4o", input_tokens=1000, output_tokens=500),
                _make_receipt(model_id="gpt-4", input_tokens=2000, output_tokens=1000),
            ]
            (pack / "receipt_pack.jsonl").write_text(
                "\n".join(json.dumps(r) for r in receipts) + "\n"
            )

            result = runner.invoke(assay_commands.assay_app, ["analyze", "test_pack", "--json"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["command"] == "analyze"
            assert data["model_calls"] == 2
            assert data["tokens"]["input"] == 3000
            assert data["tokens"]["output"] == 1500
            assert "gpt-4o" in data["by_model"]
            assert "gpt-4" in data["by_model"]

    def test_analyze_pack_json_sets_verified_from_manifest(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            pack = Path("test_pack")
            pack.mkdir()
            (pack / "receipt_pack.jsonl").write_text(json.dumps(_make_receipt()) + "\n")
            (pack / "pack_manifest.json").write_text(
                json.dumps({"attestation": {"receipt_integrity": "PASS"}})
            )

            result = runner.invoke(assay_commands.assay_app, ["analyze", "test_pack", "--json"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["source"]["verified"] is True

    def test_analyze_pack_table(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            pack = Path("test_pack")
            pack.mkdir()
            receipts = [_make_receipt()]
            (pack / "receipt_pack.jsonl").write_text(json.dumps(receipts[0]) + "\n")

            result = runner.invoke(assay_commands.assay_app, ["analyze", "test_pack"])
            assert result.exit_code == 0, result.output
            assert "Model calls" in result.output
            assert "gpt-4o" in result.output

    def test_analyze_empty_pack_no_model_calls(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            pack = Path("test_pack")
            pack.mkdir()
            receipts = [_make_non_model_receipt()]
            (pack / "receipt_pack.jsonl").write_text(json.dumps(receipts[0]) + "\n")

            result = runner.invoke(assay_commands.assay_app, ["analyze", "test_pack"])
            assert result.exit_code == 0
            assert "No model_call receipts" in result.output

    def test_analyze_history_empty(self) -> None:
        runner = CliRunner()
        result = runner.invoke(assay_commands.assay_app, ["analyze", "--history"])
        # Should succeed but show "no receipts" or similar
        assert result.exit_code == 0

    def test_analyze_history_json_includes_window_days(self) -> None:
        runner = CliRunner()
        result = runner.invoke(assay_commands.assay_app, ["analyze", "--history", "--since", "30", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["source"]["window_days"] == 30
