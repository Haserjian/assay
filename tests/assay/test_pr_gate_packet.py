"""Tests for PR Gate packet/report generation."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.pr_gate.packet import (
    PACK_FILES,
    PacketError,
    build_pr_gate_packet,
)
from assay.pr_gate.policy import compute_policy_sha256, load_policy

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
            "workflow_ref": "Haserjian/assay/.github/workflows/assay.yml@refs/heads/main",
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


def test_build_pr_gate_packet_writes_expected_tree(tmp_path: Path) -> None:
    result = build_pr_gate_packet(
        evidence=_evidence(),
        decision=_decision(),
        policy_path=POLICY_PATH,
        out_dir=tmp_path,
    )

    proof_pack = tmp_path / "proof-pack"
    signed_report = tmp_path / "signed-report"
    for name in (*PACK_FILES, "pack_manifest.json"):
        assert (proof_pack / name).exists(), name
    assert (signed_report / "verify_report.json").exists()
    assert (signed_report / "verify_report.sigstore.json").exists()

    manifest = json.loads((proof_pack / "pack_manifest.json").read_text())
    report = json.loads((signed_report / "verify_report.json").read_text())
    signature_proof = json.loads(
        (signed_report / "verify_report.sigstore.json").read_text()
    )

    assert manifest == result["pack_manifest"]
    assert manifest["schema_version"] == "assay.pr_gate.pack_manifest.v0.1"
    assert manifest["pack_root_sha256"].startswith("sha256:")
    assert manifest["policy"]["profile"] == "coding_pr_v0"
    assert manifest["policy"]["policy_sha256"] == _evidence()["policy"]["policy_sha256"]
    assert manifest["expected_files"] == [*PACK_FILES, "pack_manifest.json"]
    assert {entry["path"] for entry in manifest["files"]} == set(PACK_FILES)
    for entry in manifest["files"]:
        file_bytes = (proof_pack / entry["path"]).read_bytes()
        assert entry["sha256"] == "sha256:" + hashlib.sha256(file_bytes).hexdigest()
    assert report["schema_version"] == "assay.pr_gate.verify_report.v0.1"
    assert report["pack_root_sha256"] == manifest["pack_root_sha256"]
    assert report["pack_manifest_sha256"].startswith("sha256:")
    assert report["policy"] == manifest["policy"]
    assert report["channels"] == _decision()["channels"]
    assert report["overall_decision"] == "NEEDS_REVIEW"
    assert report["recommended_action"] == "require_human_approval"
    assert report["signature_status"] == "NOT_SIGNED"
    assert signature_proof["signature_status"] == "NOT_SIGNED"
    assert signature_proof["verify_report_sha256"].startswith("sha256:")


def test_build_pr_gate_packet_is_deterministic(tmp_path: Path) -> None:
    first = build_pr_gate_packet(
        evidence=_evidence(),
        decision=_decision(),
        policy_path=POLICY_PATH,
        out_dir=tmp_path / "first",
    )
    second = build_pr_gate_packet(
        evidence=_evidence(),
        decision=_decision(),
        policy_path=POLICY_PATH,
        out_dir=tmp_path / "second",
    )

    assert (
        first["pack_manifest"]["pack_root_sha256"]
        == second["pack_manifest"]["pack_root_sha256"]
    )
    assert first["verify_report"]["report_id"] == second["verify_report"]["report_id"]


def test_build_pr_gate_packet_removes_stale_generated_files(tmp_path: Path) -> None:
    stale_pack = tmp_path / "proof-pack" / "stale.json"
    stale_report = tmp_path / "signed-report" / "stale.json"
    stale_pack.parent.mkdir(parents=True)
    stale_report.parent.mkdir(parents=True)
    stale_pack.write_text("stale", encoding="utf-8")
    stale_report.write_text("stale", encoding="utf-8")

    build_pr_gate_packet(
        evidence=_evidence(),
        decision=_decision(),
        policy_path=POLICY_PATH,
        out_dir=tmp_path,
    )

    assert not stale_pack.exists()
    assert not stale_report.exists()


def test_build_pr_gate_packet_rejects_policy_hash_mismatch(tmp_path: Path) -> None:
    evidence = _evidence()
    evidence["policy"]["policy_sha256"] = "sha256:" + "0" * 64

    with pytest.raises(PacketError, match="policy_sha256"):
        build_pr_gate_packet(
            evidence=evidence,
            decision=_decision(),
            policy_path=POLICY_PATH,
            out_dir=tmp_path,
        )


def test_build_pr_gate_packet_rejects_decision_mismatch(tmp_path: Path) -> None:
    decision = _decision()
    decision["overall_decision"] = "PASS"
    decision["recommended_action"] = "proceed"
    decision["reasons"] = []
    decision["channels"]["trust_policy"] = "PASS"

    with pytest.raises(PacketError, match="decision does not match"):
        build_pr_gate_packet(
            evidence=_evidence(),
            decision=decision,
            policy_path=POLICY_PATH,
            out_dir=tmp_path,
        )


def test_pr_gate_pack_cli_writes_artifacts(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.json"
    decision_path = tmp_path / "decision.json"
    out_dir = tmp_path / "artifacts"
    evidence_path.write_text(json.dumps(_evidence()), encoding="utf-8")
    decision_path.write_text(json.dumps(_decision()), encoding="utf-8")

    result = runner.invoke(
        assay_app,
        [
            "pr-gate",
            "pack",
            "--evidence",
            str(evidence_path),
            "--decision",
            str(decision_path),
            "--policy",
            str(POLICY_PATH),
            "--out",
            str(out_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["pack_root_sha256"].startswith("sha256:")
    assert (out_dir / "proof-pack" / "pack_manifest.json").exists()
    assert (out_dir / "signed-report" / "verify_report.json").exists()


def test_pr_gate_pack_cli_bad_input_exits_3(tmp_path: Path) -> None:
    result = runner.invoke(
        assay_app,
        [
            "pr-gate",
            "pack",
            "--evidence",
            str(tmp_path / "missing-evidence.json"),
            "--decision",
            str(tmp_path / "missing-decision.json"),
            "--policy",
            str(POLICY_PATH),
            "--out",
            str(tmp_path / "artifacts"),
        ],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["status"] == "error"
    assert "Evidence file not found" in payload["error"]
