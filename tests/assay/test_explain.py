"""Regression tests for assay explain truthfulness and state reporting."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.claim_verifier import ClaimSpec
from assay.commands import assay_app
from assay.explain import explain_pack
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


def _receipt(receipt_id: str, receipt_type: str = "model_call") -> dict[str, str]:
    return {
        "receipt_id": receipt_id,
        "type": receipt_type,
        "timestamp": "2026-02-10T09:00:00Z",
        "schema_version": "3.0",
    }


def _build_claim_pack(
    tmp_path: Path,
    *,
    receipts: list[dict[str, str]],
    claims: list[ClaimSpec],
    pack_name: str,
) -> Path:
    keystore = AssayKeyStore(keys_dir=tmp_path / "keys")
    keystore.generate_key("test-signer")
    pack = ProofPack(
        run_id=f"{pack_name}-run",
        entries=receipts,
        signer_id="test-signer",
        claims=claims,
        mode="shadow",
    )
    return pack.build(tmp_path / pack_name, keystore=keystore)


def test_explain_reports_credible_pass_and_t0_posture(tmp_path: Path) -> None:
    pack_dir = _build_claim_pack(
        tmp_path,
        receipts=[_receipt("r1")],
        claims=[
            ClaimSpec(
                claim_id="has_model_call",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            )
        ],
        pack_name="credible_pass",
    )

    info = explain_pack(pack_dir)
    assert info["integrity_pass"] is True
    assert info["verification_state"] == "CREDIBLE_PASS"
    assert info["claims_status"] == "PASSED"
    assert info["trust_posture_code"] == "T0_SELF_SIGNED"

    result = runner.invoke(assay_app, ["explain", str(pack_dir)])
    assert result.exit_code == 0
    assert "Credible pass" in result.output
    assert "T0 self-signed" in result.output


def test_explain_reports_honest_fail(tmp_path: Path) -> None:
    pack_dir = _build_claim_pack(
        tmp_path,
        receipts=[_receipt("r1")],
        claims=[
            ClaimSpec(
                claim_id="need_guardian",
                description="guardian receipt required",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
                severity="critical",
            )
        ],
        pack_name="honest_fail",
    )

    result = runner.invoke(assay_app, ["explain", str(pack_dir), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["integrity_pass"] is True
    assert payload["verification_state"] == "HONEST_FAIL"
    assert payload["claims_status"] == "FAILED"


def test_explain_does_not_trust_tampered_verify_report(tmp_path: Path) -> None:
    pack_dir = _build_claim_pack(
        tmp_path,
        receipts=[_receipt("r1")],
        claims=[
            ClaimSpec(
                claim_id="has_model_call",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            )
        ],
        pack_name="tampered_report",
    )

    report_path = pack_dir / "verify_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["claim_verification"]["passed"] = False
    report["claim_verification"]["results"][0]["passed"] = False
    report["claim_verification"]["results"][0]["actual"] = "tampered"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    result = runner.invoke(assay_app, ["explain", str(pack_dir), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["integrity_pass"] is False
    assert payload["verification_state"] == "TAMPERED"
    assert payload["claims_status"] == "UNTRUSTED"
    assert payload["claim_results"] == []

    text_result = runner.invoke(assay_app, ["explain", str(pack_dir)])
    assert text_result.exit_code == 0
    assert "cached claim results are not authoritative" in text_result.output
