"""Tests for posture-aware CI gate (assay gate check --posture-pack)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.gate import DISPOSITION_RANK, evaluate_posture_gate
from assay.proof_posture import (
    PackPostureResult,
    ProofPosture,
    build_proof_posture,
    compute_disposition,
    posture_from_pack,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Unit tests: evaluate_posture_gate
# ---------------------------------------------------------------------------


class TestEvaluatePostureGate:
    def test_verified_passes_any_minimum(self) -> None:
        for min_d in DISPOSITION_RANK:
            report = evaluate_posture_gate(disposition="verified", min_disposition=min_d)
            assert report["posture_result"] == "PASS", f"verified should pass min={min_d}"

    def test_blocked_fails_all_except_blocked(self) -> None:
        report = evaluate_posture_gate(disposition="blocked", min_disposition="blocked")
        assert report["posture_result"] == "PASS"
        for min_d in ("incomplete", "supported_but_capped", "verified"):
            report = evaluate_posture_gate(disposition="blocked", min_disposition=min_d)
            assert report["posture_result"] == "FAIL", f"blocked should fail min={min_d}"

    def test_incomplete_passes_incomplete(self) -> None:
        report = evaluate_posture_gate(disposition="incomplete", min_disposition="incomplete")
        assert report["posture_result"] == "PASS"

    def test_incomplete_fails_verified(self) -> None:
        report = evaluate_posture_gate(disposition="incomplete", min_disposition="verified")
        assert report["posture_result"] == "FAIL"

    def test_supported_but_capped_passes_supported_but_capped(self) -> None:
        report = evaluate_posture_gate(
            disposition="supported_but_capped",
            min_disposition="supported_but_capped",
        )
        assert report["posture_result"] == "PASS"

    def test_supported_but_capped_fails_verified(self) -> None:
        report = evaluate_posture_gate(
            disposition="supported_but_capped",
            min_disposition="verified",
        )
        assert report["posture_result"] == "FAIL"

    def test_unknown_disposition_fails(self) -> None:
        report = evaluate_posture_gate(disposition="bogus", min_disposition="incomplete")
        assert report["posture_result"] == "FAIL"
        assert "Unknown disposition" in report["reasons"][0]

    def test_unknown_min_disposition_fails(self) -> None:
        report = evaluate_posture_gate(disposition="verified", min_disposition="bogus")
        assert report["posture_result"] == "FAIL"
        assert "Unknown min_disposition" in report["reasons"][0]

    def test_reason_message_includes_both_dispositions(self) -> None:
        report = evaluate_posture_gate(disposition="blocked", min_disposition="verified")
        assert "blocked" in report["reasons"][0]
        assert "verified" in report["reasons"][0]

    def test_json_contract(self) -> None:
        report = evaluate_posture_gate(disposition="verified", min_disposition="verified")
        assert "posture_result" in report
        assert "disposition" in report
        assert "min_disposition" in report
        assert "reasons" in report
        assert "timestamp" in report
        assert isinstance(report["reasons"], list)


# ---------------------------------------------------------------------------
# Unit tests: disposition ranking
# ---------------------------------------------------------------------------


class TestDispositionRanking:
    def test_rank_order(self) -> None:
        assert DISPOSITION_RANK["blocked"] < DISPOSITION_RANK["incomplete"]
        assert DISPOSITION_RANK["incomplete"] < DISPOSITION_RANK["supported_but_capped"]
        assert DISPOSITION_RANK["supported_but_capped"] < DISPOSITION_RANK["verified"]

    def test_compute_disposition_verified(self) -> None:
        assert compute_disposition(n_failed=0, n_capped=0, n_risks_blocking=0, n_debt_severe=0) == "verified"

    def test_compute_disposition_blocked(self) -> None:
        assert compute_disposition(n_failed=0, n_capped=0, n_risks_blocking=1, n_debt_severe=0) == "blocked"

    def test_compute_disposition_incomplete_on_failure(self) -> None:
        assert compute_disposition(n_failed=1, n_capped=0, n_risks_blocking=0, n_debt_severe=0) == "incomplete"

    def test_compute_disposition_incomplete_on_severe_debt(self) -> None:
        assert compute_disposition(n_failed=0, n_capped=0, n_risks_blocking=0, n_debt_severe=1) == "incomplete"

    def test_compute_disposition_capped(self) -> None:
        assert compute_disposition(n_failed=0, n_capped=1, n_risks_blocking=0, n_debt_severe=0) == "supported_but_capped"


# ---------------------------------------------------------------------------
# Unit tests: build_proof_posture
# ---------------------------------------------------------------------------


class TestBuildProofPosture:
    def test_empty_inputs_yields_verified(self) -> None:
        posture = build_proof_posture()
        assert posture.disposition == "verified"

    def test_failed_claims_yield_incomplete(self) -> None:
        posture = build_proof_posture(
            claim_set_result={"n_claims": 2, "n_passed": 1, "n_failed": 1, "n_capped": 0, "results": []},
        )
        assert posture.disposition == "incomplete"

    def test_to_dict_contract(self) -> None:
        posture = build_proof_posture()
        d = posture.to_dict()
        assert "disposition" in d
        assert "claims" in d
        assert "residual_risk" in d
        assert "proof_debt" in d


# ---------------------------------------------------------------------------
# Unit tests: posture_from_pack (shared domain function)
# ---------------------------------------------------------------------------


class TestPostureFromPack:
    def test_empty_pack_yields_verified_with_warnings(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = posture_from_pack(str(pack))
        assert result.posture.disposition == "verified"
        assert result.receipts_loaded == 0
        assert result.claims_loaded == 0
        assert any("receipt_pack.jsonl not found" in w for w in result.warnings)
        assert any("pack_manifest.json not found" in w for w in result.warnings)

    def test_receipts_no_claims(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text(
            json.dumps({"type": "model_call", "ts": "2026-03-21T00:00:00Z"}) + "\n",
            encoding="utf-8",
        )
        result = posture_from_pack(str(pack))
        assert result.posture.disposition == "verified"
        assert result.receipts_loaded == 1
        assert result.claims_loaded == 0

    def test_failed_claim_yields_incomplete(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        (pack / "pack_manifest.json").write_text(json.dumps({
            "claims": [{
                "claim_id": "c1",
                "description": "Must have model_call",
                "check": "receipt_type_present",
                "params": {"receipt_type": "model_call"},
                "severity": "critical",
            }]
        }), encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert result.posture.disposition == "incomplete"
        assert result.posture.n_failed == 1
        assert result.claims_loaded == 1

    def test_to_dict_has_no_nested_posture(self, tmp_path: Path) -> None:
        """Verify output dict is flat — no posture.posture nesting."""
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = posture_from_pack(str(pack))
        d = result.to_dict()
        assert "disposition" in d
        assert "warnings" in d
        assert "pack_dir" in d
        # No nested "posture" key — fields are flattened
        assert "posture" not in d


# ---------------------------------------------------------------------------
# Truthfulness tests: damaged / adversarial evidence
# ---------------------------------------------------------------------------


class TestPostureTruthfulness:
    """Proof posture must be honest under damaged, partial, or adversarial input."""

    def test_malformed_receipt_lines_produce_warning(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text(
            '{"type": "model_call"}\n'
            'NOT_JSON_AT_ALL\n'
            '{"type": "guardian_verdict"}\n'
            '{ALSO_BAD}\n',
            encoding="utf-8",
        )
        result = posture_from_pack(str(pack))
        assert result.receipts_loaded == 2  # only 2 valid lines
        assert any("2 malformed receipt line(s)" in w for w in result.warnings)

    def test_corrupt_manifest_produces_warning(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        (pack / "pack_manifest.json").write_text("NOT_VALID_JSON{{{", encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert result.claims_loaded == 0
        assert any("pack_manifest.json unreadable" in w for w in result.warnings)
        # Disposition is verified (no claims to fail), but warnings are honest
        assert result.posture.disposition == "verified"

    def test_empty_claims_array_yields_verified_with_no_extra_warning(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        (pack / "pack_manifest.json").write_text('{"claims": []}', encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert result.posture.disposition == "verified"
        assert result.claims_loaded == 0
        # No warning about missing manifest — it exists, just has no claims
        assert not any("pack_manifest.json not found" in w for w in result.warnings)

    def test_missing_receipt_pack_warns_but_does_not_crash(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "pack_manifest.json").write_text('{"claims": []}', encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert any("receipt_pack.jsonl not found" in w for w in result.warnings)
        assert result.receipts_loaded == 0

    def test_claim_against_empty_receipts_fails_honestly(self, tmp_path: Path) -> None:
        """A claim that requires evidence should fail when no receipts exist."""
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        (pack / "pack_manifest.json").write_text(json.dumps({
            "claims": [{
                "claim_id": "c1",
                "description": "model_call must be present",
                "check": "receipt_type_present",
                "params": {"receipt_type": "model_call"},
                "severity": "critical",
            }]
        }), encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert result.posture.disposition == "incomplete"
        assert result.posture.n_failed == 1
        assert result.posture.n_passed == 0

    def test_passing_claim_with_evidence_yields_verified(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text(
            json.dumps({"type": "model_call", "ts": "2026-03-21T00:00:00Z"}) + "\n",
            encoding="utf-8",
        )
        (pack / "pack_manifest.json").write_text(json.dumps({
            "claims": [{
                "claim_id": "c1",
                "description": "model_call must be present",
                "check": "receipt_type_present",
                "params": {"receipt_type": "model_call"},
                "severity": "critical",
            }]
        }), encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert result.posture.disposition == "verified"
        assert result.posture.n_passed == 1
        assert result.posture.n_failed == 0

    def test_warnings_surfaced_in_to_dict(self, tmp_path: Path) -> None:
        """Warnings must be visible in serialized output, never swallowed."""
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = posture_from_pack(str(pack))
        d = result.to_dict()
        assert isinstance(d["warnings"], list)
        assert len(d["warnings"]) > 0  # empty pack always has warnings


# ---------------------------------------------------------------------------
# Invariant: damaged inputs can never silently yield "verified"
# ---------------------------------------------------------------------------


class TestPostureInvariants:
    """Organism law: damaged or unreadable posture inputs can never yield
    'verified' without warnings.  If warnings exist, the consumer must be
    able to see them.  If structural damage is severe enough, disposition
    must degrade — it must never silently elevate."""

    def test_corrupt_manifest_never_verified_without_warning(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        (pack / "pack_manifest.json").write_text("{{{CORRUPT", encoding="utf-8")
        result = posture_from_pack(str(pack))
        # May be verified (no claims to fail), but MUST have warnings
        if result.posture.disposition == "verified":
            assert len(result.warnings) > 0, \
                "verified disposition with damaged manifest must carry warnings"

    def test_all_receipts_malformed_never_verified_silently(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("BAD\nALSO_BAD\n", encoding="utf-8")
        (pack / "pack_manifest.json").write_text('{"claims": []}', encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert len(result.warnings) > 0
        assert result.receipts_loaded == 0

    def test_missing_both_files_never_verified_silently(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = posture_from_pack(str(pack))
        assert len(result.warnings) >= 2, \
            "missing both receipt_pack.jsonl and pack_manifest.json must produce at least 2 warnings"

    def test_failed_claim_never_elevated_to_verified(self, tmp_path: Path) -> None:
        """A critical claim failure must never produce 'verified' disposition."""
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        (pack / "pack_manifest.json").write_text(json.dumps({
            "claims": [{
                "claim_id": "c1",
                "description": "Must have model_call",
                "check": "receipt_type_present",
                "params": {"receipt_type": "model_call"},
                "severity": "critical",
            }]
        }), encoding="utf-8")
        result = posture_from_pack(str(pack))
        assert result.posture.disposition != "verified", \
            "failed critical claim must never produce verified disposition"
        assert result.posture.disposition in ("incomplete", "blocked")

    def test_warnings_always_in_serialized_output(self, tmp_path: Path) -> None:
        """No code path may strip warnings from to_dict() output."""
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        (pack / "receipt_pack.jsonl").write_text("BAD_LINE\n", encoding="utf-8")
        result = posture_from_pack(str(pack))
        d = result.to_dict()
        assert "warnings" in d
        assert isinstance(d["warnings"], list)
        assert len(d["warnings"]) > 0


# ---------------------------------------------------------------------------
# CLI tests: assay posture <pack_dir>
# ---------------------------------------------------------------------------


class TestPostureCLI:
    def test_missing_dir_exit_1(self) -> None:
        result = runner.invoke(assay_app, ["posture", "/no/such/dir", "--json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"

    def test_empty_pack_yields_verified(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = runner.invoke(assay_app, ["posture", str(pack), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["disposition"] == "verified"

    def test_warnings_in_json_output(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = runner.invoke(assay_app, ["posture", str(pack), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "warnings" in data
        assert len(data["warnings"]) > 0

    def test_console_output_shows_panel(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = runner.invoke(assay_app, ["posture", str(pack)])
        assert result.exit_code == 0, result.output
        assert "Proof Posture" in result.output

    def test_console_shows_warnings(self, tmp_path: Path) -> None:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        result = runner.invoke(assay_app, ["posture", str(pack)])
        assert result.exit_code == 0, result.output
        assert "warning" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI tests: assay gate check --posture-pack
# ---------------------------------------------------------------------------


class TestGateCheckPosture:
    def _make_pack(self, tmp_path: Path) -> Path:
        pack = tmp_path / "proof_pack"
        pack.mkdir()
        return pack

    def test_posture_pass_json(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "0", "--posture-pack", str(pack), "--json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["result"] == "PASS"
        # New naming: posture_gate and proof_posture are separate keys
        assert "posture_gate" in data
        assert "proof_posture" in data
        assert data["proof_posture"]["disposition"] == "verified"

    def test_no_nested_posture_posture(self, tmp_path: Path, monkeypatch) -> None:
        """Verify the old posture.posture nesting is gone."""
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "0", "--posture-pack", str(pack), "--json"],
        )
        data = json.loads(result.output)
        # posture_gate has gate evaluation, proof_posture has posture data
        assert "posture" not in data.get("posture_gate", {})

    def test_posture_fail_high_disposition(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        manifest = {
            "claims": [{
                "claim_id": "c1",
                "description": "Model call present",
                "check": "receipt_type_present",
                "params": {"receipt_type": "model_call"},
                "severity": "critical",
            }]
        }
        (pack / "pack_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (pack / "receipt_pack.jsonl").write_text("", encoding="utf-8")
        result = runner.invoke(
            assay_app,
            [
                "gate", "check", ".", "--min-score", "0",
                "--posture-pack", str(pack),
                "--min-disposition", "verified",
                "--json",
            ],
        )
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["result"] == "FAIL"
        assert any("disposition" in r.lower() or "posture" in r.lower() for r in data.get("reasons", []))

    def test_posture_missing_pack_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "0", "--posture-pack", "/no/such/pack", "--json"],
        )
        assert result.exit_code == 3

    def test_posture_invalid_min_disposition_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            [
                "gate", "check", ".", "--min-score", "0",
                "--posture-pack", str(pack),
                "--min-disposition", "bogus",
                "--json",
            ],
        )
        assert result.exit_code == 3

    def test_posture_without_min_disposition_defaults_to_incomplete(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "0", "--posture-pack", str(pack), "--json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["posture_gate"]["min_disposition"] == "incomplete"

    def test_score_and_posture_both_evaluated(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            [
                "gate", "check", ".", "--min-score", "100",
                "--posture-pack", str(pack),
                "--json",
            ],
        )
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["result"] == "FAIL"
        assert any("below minimum" in r for r in data.get("reasons", []))
        assert data["posture_gate"]["posture_result"] == "PASS"

    def test_posture_warnings_in_gate_output(self, tmp_path: Path, monkeypatch) -> None:
        """Gate output includes posture warnings so nothing is silently swallowed."""
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        pack = self._make_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "0", "--posture-pack", str(pack), "--json"],
        )
        data = json.loads(result.output)
        assert "warnings" in data.get("proof_posture", {})
        assert len(data["proof_posture"]["warnings"]) > 0
