"""Tests for assay diff (proof pack comparison)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from assay.diff import (
    ClaimDelta,
    DiffResult,
    GateEvaluation,
    GateResult,
    ModelDelta,
    PackInfo,
    _load_pack_info,
    _pct_change,
    diff_packs,
    evaluate_gates,
)
from assay import commands as assay_commands


# ---------------------------------------------------------------------------
# Helpers
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
    return r


def _write_pack(
    pack_dir: Path,
    receipts: list,
    claim_results: dict | None = None,
    claim_set_hash: str = "abc123",
    signer_id: str = "test-signer",
    signer_fp: str = "fp_aaa",
    verifier_version: str = "1.3.3",
    integrity: str = "PASS",
    claim_check: str = "PASS",
) -> Path:
    """Write a minimal pack structure for testing."""
    pack_dir.mkdir(parents=True, exist_ok=True)

    # receipt_pack.jsonl
    lines = [json.dumps(r) for r in receipts]
    (pack_dir / "receipt_pack.jsonl").write_text("\n".join(lines) + "\n")

    # pack_manifest.json
    manifest = {
        "pack_id": f"pack_{pack_dir.name}",
        "claim_set_hash": claim_set_hash,
        "signer_id": signer_id,
        "signer_pubkey_sha256": signer_fp,
        "attestation": {
            "pack_id": f"pack_{pack_dir.name}",
            "receipt_integrity": integrity,
            "claim_check": claim_check,
            "verifier_version": verifier_version,
            "n_receipts": len(receipts),
            "timestamp_start": "2026-02-10T12:00:00Z",
            "timestamp_end": "2026-02-10T12:05:00Z",
        },
    }
    (pack_dir / "pack_manifest.json").write_text(json.dumps(manifest, indent=2))

    # verify_report.json (with claim results)
    report: Dict[str, Any] = {"status": "ok"}
    if claim_results is not None:
        report["claim_verification"] = {
            "passed": all(claim_results.values()),
            "results": [
                {"claim_id": cid, "passed": passed, "expected": "", "actual": "", "severity": "critical"}
                for cid, passed in claim_results.items()
            ],
        }
    (pack_dir / "verify_report.json").write_text(json.dumps(report, indent=2))

    return pack_dir


# ---------------------------------------------------------------------------
# ClaimDelta
# ---------------------------------------------------------------------------

class TestClaimDelta:
    def test_unchanged(self) -> None:
        cd = ClaimDelta(claim_id="c1", a_passed=True, b_passed=True)
        assert cd.status == "unchanged"
        assert not cd.regressed

    def test_regressed(self) -> None:
        cd = ClaimDelta(claim_id="c1", a_passed=True, b_passed=False, regressed=True)
        assert cd.status == "regressed"

    def test_improved(self) -> None:
        cd = ClaimDelta(claim_id="c1", a_passed=False, b_passed=True)
        assert cd.status == "improved"

    def test_new(self) -> None:
        cd = ClaimDelta(claim_id="c1", a_passed=None, b_passed=True)
        assert cd.status == "new"

    def test_removed(self) -> None:
        cd = ClaimDelta(claim_id="c1", a_passed=True, b_passed=None)
        assert cd.status == "removed"


# ---------------------------------------------------------------------------
# ModelDelta
# ---------------------------------------------------------------------------

class TestModelDelta:
    def test_added(self) -> None:
        md = ModelDelta(model_id="gpt-4o", a_calls=0, b_calls=5)
        assert md.status == "added"
        assert md.calls_delta == 5

    def test_removed(self) -> None:
        md = ModelDelta(model_id="gpt-4o", a_calls=5, b_calls=0)
        assert md.status == "removed"
        assert md.calls_delta == -5

    def test_changed(self) -> None:
        md = ModelDelta(model_id="gpt-4o", a_calls=5, b_calls=8, a_cost=0.10, b_cost=0.15)
        assert md.status == "changed"
        assert md.cost_delta == pytest.approx(0.05)


# ---------------------------------------------------------------------------
# _load_pack_info
# ---------------------------------------------------------------------------

class TestLoadPackInfo:
    def test_loads_manifest(self, tmp_path: Path) -> None:
        pack = _write_pack(
            tmp_path / "pack",
            receipts=[_make_receipt()],
            claim_results={"receipt_completeness": True},
            signer_id="my-signer",
        )
        info = _load_pack_info(pack)
        assert info.pack_id == "pack_pack"
        assert info.integrity == "PASS"
        assert info.signer_id == "my-signer"
        assert info.claim_results == {"receipt_completeness": True}

    def test_missing_manifest(self, tmp_path: Path) -> None:
        pack = tmp_path / "empty"
        pack.mkdir()
        info = _load_pack_info(pack)
        assert info.pack_id == ""
        assert info.claim_results == {}

    def test_missing_verify_report(self, tmp_path: Path) -> None:
        pack = tmp_path / "pack"
        pack.mkdir()
        (pack / "pack_manifest.json").write_text(json.dumps({
            "attestation": {"receipt_integrity": "PASS", "claim_check": "N/A"},
        }))
        info = _load_pack_info(pack)
        assert info.integrity == "PASS"
        assert info.claim_results == {}


# ---------------------------------------------------------------------------
# diff_packs
# ---------------------------------------------------------------------------

class TestDiffPacks:
    def test_identical_packs(self, tmp_path: Path) -> None:
        receipts = [_make_receipt()]
        claims = {"receipt_completeness": True}
        pack_a = _write_pack(tmp_path / "a", receipts, claims)
        pack_b = _write_pack(tmp_path / "b", receipts, claims)

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.both_valid
        assert not result.has_regression
        assert result.exit_code == 0
        assert result.same_claim_set
        assert len(result.claim_deltas) == 1
        assert result.claim_deltas[0].status == "unchanged"

    def test_claim_regression(self, tmp_path: Path) -> None:
        receipts = [_make_receipt()]
        pack_a = _write_pack(tmp_path / "a", receipts, {"rc": True})
        pack_b = _write_pack(tmp_path / "b", receipts, {"rc": False}, claim_check="FAIL")

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.has_regression
        assert result.exit_code == 1
        assert any(cd.regressed for cd in result.claim_deltas)

    def test_claim_improvement(self, tmp_path: Path) -> None:
        receipts = [_make_receipt()]
        pack_a = _write_pack(tmp_path / "a", receipts, {"rc": False}, claim_check="FAIL")
        pack_b = _write_pack(tmp_path / "b", receipts, {"rc": True})

        result = diff_packs(pack_a, pack_b, verify=False)
        assert not result.has_regression
        assert result.exit_code == 0
        assert any(cd.status == "improved" for cd in result.claim_deltas)

    def test_new_claim_in_b(self, tmp_path: Path) -> None:
        receipts = [_make_receipt()]
        pack_a = _write_pack(tmp_path / "a", receipts, {"rc": True})
        pack_b = _write_pack(tmp_path / "b", receipts, {"rc": True, "coverage": True},
                             claim_set_hash="different")

        result = diff_packs(pack_a, pack_b, verify=False)
        assert not result.same_claim_set
        assert any(cd.status == "new" for cd in result.claim_deltas)

    def test_model_churn(self, tmp_path: Path) -> None:
        pack_a = _write_pack(tmp_path / "a", [
            _make_receipt(model_id="gpt-4"),
            _make_receipt(model_id="gpt-4"),
        ])
        pack_b = _write_pack(tmp_path / "b", [
            _make_receipt(model_id="gpt-4"),
            _make_receipt(model_id="claude-sonnet-4"),
        ])

        result = diff_packs(pack_a, pack_b, verify=False)
        model_ids = {md.model_id for md in result.model_deltas}
        assert "gpt-4" in model_ids
        assert "claude-sonnet-4" in model_ids

        gpt4 = next(md for md in result.model_deltas if md.model_id == "gpt-4")
        assert gpt4.a_calls == 2
        assert gpt4.b_calls == 1
        assert gpt4.status == "changed"

        claude = next(md for md in result.model_deltas if md.model_id == "claude-sonnet-4")
        assert claude.status == "added"

    def test_cost_delta(self, tmp_path: Path) -> None:
        pack_a = _write_pack(tmp_path / "a", [
            _make_receipt(input_tokens=1000, output_tokens=500),
        ])
        pack_b = _write_pack(tmp_path / "b", [
            _make_receipt(input_tokens=2000, output_tokens=1000),
        ])

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.a_analysis is not None
        assert result.b_analysis is not None
        assert result.b_analysis.cost_usd > result.a_analysis.cost_usd

    def test_signer_change_detected(self, tmp_path: Path) -> None:
        pack_a = _write_pack(tmp_path / "a", [_make_receipt()], signer_fp="fp_aaa")
        pack_b = _write_pack(tmp_path / "b", [_make_receipt()], signer_fp="fp_bbb")

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.signer_changed

    def test_version_change_detected(self, tmp_path: Path) -> None:
        pack_a = _write_pack(tmp_path / "a", [_make_receipt()], verifier_version="1.3.2")
        pack_b = _write_pack(tmp_path / "b", [_make_receipt()], verifier_version="1.3.3")

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.version_changed

    def test_to_dict_roundtrip(self, tmp_path: Path) -> None:
        pack_a = _write_pack(tmp_path / "a", [_make_receipt()], {"rc": True})
        pack_b = _write_pack(tmp_path / "b", [_make_receipt()], {"rc": True})

        result = diff_packs(pack_a, pack_b, verify=False)
        d = result.to_dict()
        assert d["has_regression"] is False
        assert d["preflight"]["both_valid"] is True
        assert len(d["claims"]) == 1
        assert "summary" in d

    def test_error_delta(self, tmp_path: Path) -> None:
        pack_a = _write_pack(tmp_path / "a", [_make_receipt(error=False)])
        pack_b = _write_pack(tmp_path / "b", [_make_receipt(error=True)])

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.a_analysis.errors == 0
        assert result.b_analysis.errors == 1

    def test_missing_receipt_file(self, tmp_path: Path) -> None:
        pack_a = tmp_path / "a"
        pack_a.mkdir()
        (pack_a / "pack_manifest.json").write_text("{}")
        pack_b = tmp_path / "b"
        pack_b.mkdir()
        (pack_b / "pack_manifest.json").write_text("{}")

        result = diff_packs(pack_a, pack_b, verify=False)
        assert result.a_analysis is None
        assert result.b_analysis is None


# ---------------------------------------------------------------------------
# DiffResult.exit_code
# ---------------------------------------------------------------------------

class TestExitCode:
    def test_clean(self) -> None:
        r = DiffResult(pack_a=PackInfo(path="a"), pack_b=PackInfo(path="b"),
                       both_valid=True, has_regression=False)
        assert r.exit_code == 0

    def test_regression(self) -> None:
        r = DiffResult(pack_a=PackInfo(path="a"), pack_b=PackInfo(path="b"),
                       both_valid=True, has_regression=True)
        assert r.exit_code == 1

    def test_integrity_fail(self) -> None:
        r = DiffResult(pack_a=PackInfo(path="a"), pack_b=PackInfo(path="b"),
                       both_valid=False)
        assert r.exit_code == 2


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestDiffCLI:
    def test_nonexistent_pack_a(self) -> None:
        runner = CliRunner()
        result = runner.invoke(assay_commands.assay_app, ["diff", "/nonexistent", "/also-nope"])
        assert result.exit_code == 3

    def test_nonexistent_pack_b(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("a").mkdir()
            result = runner.invoke(assay_commands.assay_app, ["diff", "a", "/nonexistent"])
            assert result.exit_code == 3

    def test_diff_json_output(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt(input_tokens=2000)], {"rc": True})

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["command"] == "diff"
            assert data["has_regression"] is False
            assert "summary" in data

    def test_diff_regression_json(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": False}, claim_check="FAIL")

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json"])
            assert result.exit_code == 1
            data = json.loads(result.output)
            assert data["has_regression"] is True

    def test_diff_table_output(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify"])
            assert result.exit_code == 0, result.output
            assert "No regression" in result.output

    def test_diff_regression_table_output(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": False}, claim_check="FAIL")

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify"])
            assert result.exit_code == 1
            assert "REGRESSION" in result.output


# ---------------------------------------------------------------------------
# _pct_change
# ---------------------------------------------------------------------------

class TestPctChange:
    def test_normal(self) -> None:
        assert _pct_change(100, 120) == pytest.approx(20.0)

    def test_decrease(self) -> None:
        assert _pct_change(100, 80) == pytest.approx(-20.0)

    def test_zero_baseline_positive(self) -> None:
        assert _pct_change(0, 10) == float("inf")

    def test_zero_baseline_zero(self) -> None:
        assert _pct_change(0, 0) == 0.0

    def test_no_change(self) -> None:
        assert _pct_change(50, 50) == 0.0


# ---------------------------------------------------------------------------
# GateResult / GateEvaluation
# ---------------------------------------------------------------------------

class TestGateResult:
    def test_defaults(self) -> None:
        g = GateResult(name="cost_pct", threshold=20.0)
        assert g.passed is True
        assert g.skipped is False

    def test_to_dict(self) -> None:
        ge = GateEvaluation(results=[
            GateResult(name="cost_pct", threshold=20.0, actual=15.0, passed=True, unit="pct"),
        ])
        d = ge.to_dict()
        assert d["all_passed"] is True
        assert len(d["results"]) == 1

    def test_all_passed_skips_skipped(self) -> None:
        ge = GateEvaluation(results=[
            GateResult(name="cost_pct", threshold=20.0, passed=True, skipped=True),
            GateResult(name="errors", threshold=0.0, actual=0.0, passed=True, unit="count"),
        ])
        assert ge.all_passed is True

    def test_any_failed(self) -> None:
        ge = GateEvaluation(results=[
            GateResult(name="cost_pct", threshold=20.0, actual=30.0, passed=False, unit="pct"),
        ])
        assert ge.any_failed is True


# ---------------------------------------------------------------------------
# evaluate_gates
# ---------------------------------------------------------------------------

class TestEvaluateGates:
    def _make_diff_result_with_analysis(self, tmp_path: Path,
                                         a_receipts=None, b_receipts=None) -> "DiffResult":
        """Build a DiffResult with analysis populated."""
        if a_receipts is None:
            a_receipts = [_make_receipt(input_tokens=1000, output_tokens=500, latency_ms=800)]
        if b_receipts is None:
            b_receipts = [_make_receipt(input_tokens=1000, output_tokens=500, latency_ms=800)]
        pack_a = _write_pack(tmp_path / "a", a_receipts)
        pack_b = _write_pack(tmp_path / "b", b_receipts)
        return diff_packs(pack_a, pack_b, verify=False)

    def test_no_gates_empty(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(tmp_path)
        ge = evaluate_gates(result)
        assert ge.results == []
        assert ge.all_passed is True

    def test_cost_gate_pass(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(tmp_path)
        ge = evaluate_gates(result, cost_pct=50.0)
        assert len(ge.results) == 1
        assert ge.results[0].passed is True

    def test_cost_gate_fail(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(input_tokens=100, output_tokens=50)],
            b_receipts=[_make_receipt(input_tokens=1000, output_tokens=500)],
        )
        ge = evaluate_gates(result, cost_pct=10.0)
        assert ge.results[0].passed is False
        assert ge.any_failed is True

    def test_cost_gate_zero_baseline(self, tmp_path: Path) -> None:
        """A=0 cost, B>0 cost -> infinite increase -> fail finite threshold."""
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(input_tokens=0, output_tokens=0)],
            b_receipts=[_make_receipt(input_tokens=1000, output_tokens=500)],
        )
        ge = evaluate_gates(result, cost_pct=50.0)
        assert ge.results[0].passed is False

    def test_p95_gate_pass(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(latency_ms=100)],
            b_receipts=[_make_receipt(latency_ms=110)],
        )
        ge = evaluate_gates(result, p95_pct=20.0)
        assert ge.results[0].passed is True

    def test_p95_gate_fail(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(latency_ms=100)],
            b_receipts=[_make_receipt(latency_ms=200)],
        )
        ge = evaluate_gates(result, p95_pct=20.0)
        assert ge.results[0].passed is False

    def test_errors_gate_pass(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(
            tmp_path,
            b_receipts=[_make_receipt(error=False)],
        )
        ge = evaluate_gates(result, errors=0)
        assert ge.results[0].passed is True

    def test_errors_gate_fail(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(
            tmp_path,
            b_receipts=[_make_receipt(error=True)],
        )
        ge = evaluate_gates(result, errors=0)
        assert ge.results[0].passed is False

    def test_multiple_gates(self, tmp_path: Path) -> None:
        result = self._make_diff_result_with_analysis(tmp_path)
        ge = evaluate_gates(result, cost_pct=50.0, p95_pct=50.0, errors=5)
        assert len(ge.results) == 3
        assert ge.all_passed is True

    def test_gate_skipped_no_analysis(self) -> None:
        """Gates skip gracefully when analysis is unavailable."""
        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
        )
        ge = evaluate_gates(result, cost_pct=20.0, p95_pct=20.0, errors=0)
        assert len(ge.results) == 3
        assert all(g.skipped for g in ge.results)
        assert ge.all_passed is True

    def test_cost_gate_inf_threshold_passes_infinite_increase(self, tmp_path: Path) -> None:
        """--gate-cost-pct inf should pass even when increase is infinite."""
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(input_tokens=0, output_tokens=0)],
            b_receipts=[_make_receipt(input_tokens=1000, output_tokens=500)],
        )
        ge = evaluate_gates(result, cost_pct=float("inf"))
        assert ge.results[0].passed is True

    def test_p95_gate_inf_threshold_passes_infinite_increase(self, tmp_path: Path) -> None:
        """--gate-p95-pct inf should pass even when increase is infinite."""
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(latency_ms=0)],
            b_receipts=[_make_receipt(latency_ms=500)],
        )
        ge = evaluate_gates(result, p95_pct=float("inf"))
        assert ge.results[0].passed is True

    def test_gate_to_dict_json_safe(self, tmp_path: Path) -> None:
        """to_dict must not emit inf/nan -- must be valid JSON."""
        result = self._make_diff_result_with_analysis(
            tmp_path,
            a_receipts=[_make_receipt(input_tokens=0, output_tokens=0)],
            b_receipts=[_make_receipt(input_tokens=1000, output_tokens=500)],
        )
        ge = evaluate_gates(result, cost_pct=float("inf"))
        d = ge.to_dict()
        # threshold=inf should serialize as None
        assert d["results"][0]["threshold"] is None
        # Roundtrip through json.dumps must not raise
        json.dumps(d)

    # -- strict mode --

    def test_strict_skipped_gate_fails(self) -> None:
        """In strict mode, missing data causes gate failure."""
        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
        )
        ge = evaluate_gates(result, cost_pct=20.0, errors=0, strict=True)
        assert all(g.skipped for g in ge.results)
        assert all(not g.passed for g in ge.results)
        assert ge.any_failed is True

    def test_non_strict_skipped_gate_passes(self) -> None:
        """Default (non-strict): missing data = skip = pass."""
        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
        )
        ge = evaluate_gates(result, cost_pct=20.0, errors=0, strict=False)
        assert all(g.skipped for g in ge.results)
        assert all(g.passed for g in ge.results)
        assert ge.all_passed is True


# ---------------------------------------------------------------------------
# CLI gate integration
# ---------------------------------------------------------------------------

class TestDiffGateCLI:
    def test_gate_pass_json(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json",
                                    "--gate-cost-pct", "50"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert "gates" in data
            assert data["gates"]["all_passed"] is True

    def test_gate_fail_exit_code(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt(input_tokens=100, output_tokens=50)])
            _write_pack(Path("b"), [_make_receipt(input_tokens=1000, output_tokens=500)])

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json",
                                    "--gate-cost-pct", "10"])
            assert result.exit_code == 1
            data = json.loads(result.output)
            assert data["gates"]["all_passed"] is False

    def test_gate_table_output(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify",
                                    "--gate-cost-pct", "50"])
            assert result.exit_code == 0, result.output
            assert "Gates" in result.output
            assert "PASS" in result.output

    def test_gate_fail_table_output(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt(input_tokens=100, output_tokens=50)])
            _write_pack(Path("b"), [_make_receipt(input_tokens=1000, output_tokens=500)])

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify",
                                    "--gate-cost-pct", "10"])
            assert result.exit_code == 1
            assert "THRESHOLD EXCEEDED" in result.output

    def test_integrity_failure_overrides_gate(self) -> None:
        """Integrity failure (exit 2) must take precedence over gate fail (exit 1)."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Pack A: valid manifest. Pack B: empty manifest (will fail integrity).
            _write_pack(Path("a"), [_make_receipt()])
            Path("b").mkdir()
            (Path("b") / "pack_manifest.json").write_text("{}")
            (Path("b") / "receipt_pack.jsonl").write_text("")

            # Verify=True (default) will fail integrity before gates matter.
            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--gate-errors", "0"])
            assert result.exit_code == 2

    def test_gate_strict_cli_missing_data_fails(self) -> None:
        """--gate-strict makes missing analysis data fail the gate."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Packs with no receipt file at all -> no analysis data
            for name in ("a", "b"):
                Path(name).mkdir()
                (Path(name) / "pack_manifest.json").write_text("{}")

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json",
                                    "--gate-errors", "0", "--gate-strict"])
            assert result.exit_code == 1
            data = json.loads(result.output)
            assert data["gates"]["all_passed"] is False
            assert data["gates_failed"] is True

    def test_json_separate_booleans(self) -> None:
        """JSON output includes integrity_failed, claims_regressed, gates_failed."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json",
                                    "--gate-cost-pct", "50"])
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["integrity_failed"] is False
            assert data["claims_regressed"] is False
            assert data["gates_failed"] is False
            assert data["has_regression"] is False

    def test_json_separate_booleans_regression(self) -> None:
        """claims_regressed is True but gates_failed is False when only claims regress."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": False}, claim_check="FAIL")

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify", "--json",
                                    "--gate-cost-pct", "50"])
            assert result.exit_code == 1
            data = json.loads(result.output)
            assert data["claims_regressed"] is True
            assert data["gates_failed"] is False
            assert data["has_regression"] is True

    def test_gate_summary_line_in_table(self) -> None:
        """Table output includes a summary line with pass/fail/skip counts."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify",
                                    "--gate-cost-pct", "50", "--gate-errors", "5"])
            assert result.exit_code == 0, result.output
            assert "2 passed" in result.output
            assert "0 failed" in result.output
            assert "0 skipped" in result.output

    def test_gate_strict_table_shows_strict_label(self) -> None:
        """Strict mode shows 'missing data (strict mode)' instead of 'skipped'."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            for name in ("a", "b"):
                Path(name).mkdir()
                (Path(name) / "pack_manifest.json").write_text("{}")

            result = runner.invoke(assay_commands.assay_app,
                                   ["diff", "a", "b", "--no-verify",
                                    "--gate-errors", "0", "--gate-strict"])
            assert result.exit_code == 1
            assert "strict mode" in result.output
