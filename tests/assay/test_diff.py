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
    ModelDelta,
    PackInfo,
    _load_pack_info,
    diff_packs,
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
