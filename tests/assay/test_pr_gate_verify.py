"""Tests for PR Gate packet/report/signature verification."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Sequence

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.pr_gate.packet import build_pr_gate_packet
from assay.pr_gate.policy import compute_policy_sha256, load_policy
from assay.pr_gate.verify import (
    DEFAULT_CERTIFICATE_OIDC_ISSUER,
    DEFAULT_EXPECTED_SIGNER_IDENTITY,
    PRGateVerificationError,
    VERIFY_RESULT,
    verify_pr_gate_packet,
)

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "docs" / "examples" / "pr-gate-v0" / "assay-policy.yml"


def _evidence() -> Dict[str, Any]:
    policy = load_policy(POLICY_PATH)
    return {
        "schema_version": "assay.pr_gate.evidence.v0.1",
        "subject": {
            "repo": "Haserjian/assay",
            "pr_number": 123,
            "base_sha": "base",
            "head_sha": "head",
            "diff_sha256": "sha256:" + "a" * 64,
            "diff_source": "git diff --binary --full-index <base_sha> <head_sha>",
        },
        "capture": {
            "provider": "github_actions",
            "workflow_ref": DEFAULT_EXPECTED_SIGNER_IDENTITY,
            "workflow_sha": "workflow-sha",
            "run_id": "1001",
            "run_attempt": "1",
            "actor": "tim",
            "event_name": "pull_request",
            "github_sha": "merge-sha",
        },
        "changed_files": [
            {
                "path": "auth/session.py",
                "status": "modified",
                "sha256_after": "sha256:" + "b" * 64,
            }
        ],
        "observed_checks": [
            {
                "name": "tests",
                "provider": "github_checks",
                "head_sha": "head",
                "status": "completed",
                "conclusion": "success",
                "observed_at": "2026-05-08T12:00:00Z",
            }
        ],
        "policy": {
            "profile": "coding_pr_v0",
            "policy_sha256": compute_policy_sha256(policy),
        },
    }


def _decision() -> Dict[str, Any]:
    return {
        "overall_decision": "NEEDS_REVIEW",
        "recommended_action": "require_human_approval",
        "reasons": [
            {
                "rule": "risk_path_touched",
                "path": "auth/session.py",
                "matched_pattern": "auth/**",
            }
        ],
        "channels": {
            "integrity": "PASS",
            "claim": "PASS",
            "replay": "NOT_RUN",
            "trust_policy": "NEEDS_REVIEW",
        },
    }


def _build_signed_packet(tmp_path: Path) -> Dict[str, Any]:
    result = build_pr_gate_packet(
        evidence=_evidence(),
        decision=_decision(),
        policy_path=POLICY_PATH,
        out_dir=tmp_path,
    )
    report_path = tmp_path / "signed-report" / "verify_report.json"
    signature_proof = {
        "schema_version": "assay.pr_gate.signature_proof.v0.1",
        "signature_status": "SIGNED",
        "signed_artifact": "verify_report.json",
        "certificate_identity": DEFAULT_EXPECTED_SIGNER_IDENTITY,
        "certificate_oidc_issuer": DEFAULT_CERTIFICATE_OIDC_ISSUER,
        "verify_report_sha256": "sha256:" + hashlib.sha256(
            report_path.read_bytes()
        ).hexdigest(),
    }
    (tmp_path / "signed-report" / "verify_report.sigstore.json").write_text(
        json.dumps(signature_proof, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def _passing_cosign(
    args: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    assert DEFAULT_EXPECTED_SIGNER_IDENTITY.startswith("https://github.com/")
    assert "verify-blob" in args
    assert "--certificate-identity" in args
    assert DEFAULT_EXPECTED_SIGNER_IDENTITY in args
    return subprocess.CompletedProcess(args, 0, "Verified OK", "")


def test_verify_pr_gate_packet_accepts_signed_clean_packet(tmp_path: Path) -> None:
    _build_signed_packet(tmp_path)

    result = verify_pr_gate_packet(
        pack_dir=tmp_path / "proof-pack",
        report_path=tmp_path / "signed-report" / "verify_report.json",
        sigstore_path=tmp_path / "signed-report" / "verify_report.sigstore.json",
        cosign_runner=_passing_cosign,
    )

    assert result["status"] == "ok"
    assert result["result"] == VERIFY_RESULT
    assert result["decision"] == "NEEDS_REVIEW"
    assert result["recommended_action"] == "require_human_approval"
    assert result["channels"]["trust_policy"] == "NEEDS_REVIEW"


def test_verify_pr_gate_packet_rejects_unsigned_placeholder(tmp_path: Path) -> None:
    build_pr_gate_packet(
        evidence=_evidence(),
        decision=_decision(),
        policy_path=POLICY_PATH,
        out_dir=tmp_path,
    )

    with pytest.raises(PRGateVerificationError, match="not signed"):
        verify_pr_gate_packet(
            pack_dir=tmp_path / "proof-pack",
            report_path=tmp_path / "signed-report" / "verify_report.json",
            sigstore_path=tmp_path / "signed-report" / "verify_report.sigstore.json",
            cosign_runner=_passing_cosign,
        )


def test_verify_pr_gate_packet_rejects_report_tamper(tmp_path: Path) -> None:
    _build_signed_packet(tmp_path)
    report_path = tmp_path / "signed-report" / "verify_report.json"
    report = json.loads(report_path.read_text())
    report["recommended_action"] = "proceed"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    with pytest.raises(PRGateVerificationError, match="signature proof"):
        verify_pr_gate_packet(
            pack_dir=tmp_path / "proof-pack",
            report_path=report_path,
            sigstore_path=tmp_path / "signed-report" / "verify_report.sigstore.json",
            cosign_runner=_passing_cosign,
        )


def test_verify_pr_gate_packet_rejects_pack_tamper(tmp_path: Path) -> None:
    _build_signed_packet(tmp_path)
    (tmp_path / "proof-pack" / "changed_files.json").write_text("[]\n")

    with pytest.raises(PRGateVerificationError, match="file hash mismatch"):
        verify_pr_gate_packet(
            pack_dir=tmp_path / "proof-pack",
            report_path=tmp_path / "signed-report" / "verify_report.json",
            sigstore_path=tmp_path / "signed-report" / "verify_report.sigstore.json",
            cosign_runner=_passing_cosign,
        )


def test_verify_pr_gate_packet_rejects_wrong_identity(tmp_path: Path) -> None:
    _build_signed_packet(tmp_path)

    with pytest.raises(PRGateVerificationError, match="expected signer identity"):
        verify_pr_gate_packet(
            pack_dir=tmp_path / "proof-pack",
            report_path=tmp_path / "signed-report" / "verify_report.json",
            sigstore_path=tmp_path / "signed-report" / "verify_report.sigstore.json",
            expected_identity=(
                "https://github.com/Haserjian/assay/.github/workflows/"
                "other.yml@refs/heads/main"
            ),
            cosign_runner=_passing_cosign,
        )


def test_verify_pr_gate_packet_rejects_non_required_signature_policy(
    tmp_path: Path,
) -> None:
    _build_signed_packet(tmp_path)
    report_path = tmp_path / "signed-report" / "verify_report.json"
    report = json.loads(report_path.read_text())
    report["signature_policy"]["required"] = False
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    signature_path = tmp_path / "signed-report" / "verify_report.sigstore.json"
    signature_proof = json.loads(signature_path.read_text())
    signature_proof["verify_report_sha256"] = (
        "sha256:" + hashlib.sha256(report_path.read_bytes()).hexdigest()
    )
    signature_path.write_text(
        json.dumps(signature_proof, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(PRGateVerificationError, match="signature policy"):
        verify_pr_gate_packet(
            pack_dir=tmp_path / "proof-pack",
            report_path=report_path,
            sigstore_path=signature_path,
            cosign_runner=_passing_cosign,
        )


def test_pr_gate_verify_cli_json_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import assay.pr_gate.verify as verify_mod

    _build_signed_packet(tmp_path)
    monkeypatch.setattr(verify_mod, "_run_cosign", _passing_cosign)

    result = runner.invoke(
        assay_app,
        [
            "pr-gate",
            "verify",
            "--pack",
            str(tmp_path / "proof-pack"),
            "--report",
            str(tmp_path / "signed-report" / "verify_report.json"),
            "--sigstore",
            str(tmp_path / "signed-report" / "verify_report.sigstore.json"),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["result"] == VERIFY_RESULT
    assert payload["expected_identity"] == DEFAULT_EXPECTED_SIGNER_IDENTITY
