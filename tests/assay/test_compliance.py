"""Tests for assay compliance report command and module."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.compliance import (
    ALL_FRAMEWORK_IDS,
    ComplianceReport,
    evaluate_compliance,
    render_compliance_md,
    render_compliance_text,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
        "model_id": "gpt-4",
        "provider": "openai",
        "input_tokens": 100,
        "output_tokens": 50,
        "total_tokens": 150,
        "latency_ms": 800,
    }
    base.update(overrides)
    return base


def _build_pack(tmp_path: Path, signer_id: str = "compliance-test-signer", receipts=None):
    """Build a valid signed proof pack for testing."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key(signer_id)
    if receipts is None:
        receipts = [_make_receipt(seq=i) for i in range(3)]
    pack = ProofPack(
        run_id="compliance-test-run",
        entries=receipts,
        signer_id=signer_id,
        mode="shadow",
    )
    out = pack.build(tmp_path / "pack", keystore=ks)
    return out, ks


def _build_minimal_pack(tmp_path: Path):
    """Build a pack with receipts that lack monitoring fields."""
    receipts = [
        {
            "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": i,
        }
        for i in range(2)
    ]
    return _build_pack(tmp_path, receipts=receipts)


# ---------------------------------------------------------------------------
# Module tests
# ---------------------------------------------------------------------------


class TestEvaluateCompliance:
    def test_eu_ai_act_all_pass(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        assert report.framework == "eu-ai-act"
        assert report.framework_label == "EU AI Act (Articles 12 & 19)"
        required_controls = [c for c in report.controls if c.severity == "required"]
        for c in required_controls:
            assert c.verdict == "PASS", f"{c.control_id} should PASS: {c.evidence}"

    def test_eu_ai_act_retention_unknown(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        retention = [c for c in report.controls if c.control_id == "EU-19.2"]
        assert len(retention) == 1
        assert retention[0].verdict == "UNKNOWN"

    def test_soc2_all_pass(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "soc2")
        assert report.framework == "soc2"
        # SOC2-CC7.2.2 (claims evaluated) may FAIL since test pack has no claims
        # Others should PASS
        non_claims = [c for c in report.controls if c.control_id != "SOC2-CC7.2.2"]
        for c in non_claims:
            assert c.verdict == "PASS", f"{c.control_id}: {c.evidence}"

    def test_iso42001_all_pass(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "iso42001")
        assert report.framework == "iso42001"
        # ISO-DOC.2 (claims evaluated) may FAIL
        non_claims = [c for c in report.controls if c.control_id != "ISO-DOC.2"]
        for c in non_claims:
            assert c.verdict == "PASS", f"{c.control_id}: {c.evidence}"

    def test_nist_all_pass(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "nist-ai-rmf")
        assert report.framework == "nist-ai-rmf"
        # NIST-MANAGE.1 (claims evaluated) may FAIL
        non_claims = [c for c in report.controls if c.control_id != "NIST-MANAGE.1"]
        for c in non_claims:
            assert c.verdict == "PASS", f"{c.control_id}: {c.evidence}"

    def test_missing_monitoring_fields(self, tmp_path):
        pack_dir, _ = _build_minimal_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        monitoring = [c for c in report.controls if c.control_id == "EU-12.4"]
        assert len(monitoring) == 1
        assert monitoring[0].verdict == "FAIL"

    def test_no_claims_evaluated(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "soc2")
        claims_ctrl = [c for c in report.controls if c.control_id == "SOC2-CC7.2.2"]
        assert len(claims_ctrl) == 1
        assert claims_ctrl[0].verdict == "FAIL"
        assert "No governance claims" in claims_ctrl[0].evidence

    def test_framework_not_found(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        with pytest.raises(ValueError, match="Unknown framework"):
            evaluate_compliance(pack_dir, "invalid-framework")

    def test_report_summary_counts(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        s = report.summary
        assert s["total"] == 6
        assert s["passed"] + s["failed"] + s["unknown"] == s["total"]

    def test_report_to_dict(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        d = report.to_dict()
        assert d["framework"] == "eu-ai-act"
        assert "controls" in d
        assert "summary" in d
        assert "compliance_version" in d
        assert "disclaimer" in d


class TestRenderers:
    def test_render_text(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        text = render_compliance_text(report)
        assert "COMPLIANCE REPORT" in text
        assert "EU AI Act" in text
        assert "EU-12.1" in text
        assert "Disclaimer" in text

    def test_render_md(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        report = evaluate_compliance(pack_dir, "eu-ai-act")
        md = render_compliance_md(report)
        assert "# Compliance Report" in md
        assert "| Control |" in md
        assert "`EU-12.1`" in md
        assert "## Citations" in md


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestComplianceCLI:
    def test_cli_default_framework(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["compliance", "report", str(pack_dir)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        assert "EU AI Act" in result.output

    def test_cli_explicit_framework(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "compliance", "report", str(pack_dir), "--framework", "soc2",
        ])
        assert result.exit_code == 0
        assert "SOC 2" in result.output

    def test_cli_all_frameworks(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "compliance", "report", str(pack_dir), "--framework", "all",
        ])
        assert result.exit_code == 0
        assert "EU AI Act" in result.output
        assert "SOC 2" in result.output
        assert "ISO" in result.output
        assert "NIST" in result.output

    def test_cli_json_output(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "compliance", "report", str(pack_dir), "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["command"] == "compliance report"
        assert data["framework"] == "eu-ai-act"
        assert "controls" in data
        assert "summary" in data

    def test_cli_json_all_frameworks(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "compliance", "report", str(pack_dir),
            "--framework", "all", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert "frameworks" in data
        assert len(data["frameworks"]) == 4

    def test_cli_md_format(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "compliance", "report", str(pack_dir), "--format", "md",
        ])
        assert result.exit_code == 0
        assert "# Compliance Report" in result.output
        assert "| Control |" in result.output

    def test_cli_bad_input_not_dir(self, tmp_path):
        result = runner.invoke(assay_app, [
            "compliance", "report", str(tmp_path / "nonexistent"),
        ])
        assert result.exit_code == 3

    def test_cli_bad_input_no_manifest(self, tmp_path):
        (tmp_path / "empty_pack").mkdir()
        result = runner.invoke(assay_app, [
            "compliance", "report", str(tmp_path / "empty_pack"),
        ])
        assert result.exit_code == 3

    def test_cli_unknown_framework(self, tmp_path):
        pack_dir, _ = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "compliance", "report", str(pack_dir),
            "--framework", "hipaa",
        ])
        assert result.exit_code == 3
        assert "Unknown framework" in result.output
