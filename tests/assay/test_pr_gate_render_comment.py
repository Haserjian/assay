"""Tests for PR Gate comment rendering."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.pr_gate.packet import build_pr_gate_packet
from assay.pr_gate.policy import compute_policy_sha256, evaluate_policy, load_policy
from assay.pr_gate.render_comment import (
    CommentRenderError,
    render_pr_gate_comment_files,
)

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "docs" / "examples" / "pr-gate-v0" / "assay-policy.yml"
SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshots"


def _evidence(
    *,
    head_sha: str,
    changed_files: List[Dict[str, Any]],
    conclusion: str,
) -> Dict[str, Any]:
    policy = load_policy(POLICY_PATH)
    return {
        "schema_version": "assay.pr_gate.evidence.v0.1",
        "subject": {
            "repo": "Haserjian/assay",
            "pr_number": 123,
            "base_sha": "base",
            "head_sha": head_sha,
            "diff_sha256": "sha256:" + "a" * 64,
            "diff_source": "git diff --binary --full-index <base_sha> <head_sha>",
        },
        "capture": {
            "provider": "github_actions",
            "workflow_ref": (
                "Haserjian/assay/.github/workflows/"
                "assay-pr-gate.yml@refs/heads/main"
            ),
            "workflow_sha": "workflow-sha",
            "run_id": "1001",
            "run_attempt": "1",
            "actor": "tim",
            "event_name": "pull_request",
            "github_sha": "merge-sha",
        },
        "changed_files": changed_files,
        "observed_checks": [
            {
                "name": "tests",
                "provider": "github_checks",
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "observed_at": "2026-05-08T12:00:00Z",
            }
        ],
        "policy": {
            "profile": "coding_pr_v0",
            "policy_sha256": compute_policy_sha256(policy),
        },
    }


def _render_case(tmp_path: Path, evidence: Dict[str, Any]) -> str:
    decision = evaluate_policy(evidence, load_policy(POLICY_PATH))
    build_pr_gate_packet(
        evidence=evidence,
        decision=decision,
        policy_path=POLICY_PATH,
        out_dir=tmp_path,
    )
    return render_pr_gate_comment_files(
        report_path=tmp_path / "signed-report" / "verify_report.json",
        pack_manifest_path=tmp_path / "proof-pack" / "pack_manifest.json",
    )


def _snapshot(name: str) -> str:
    return (SNAPSHOT_DIR / name).read_text(encoding="utf-8")


def test_render_comment_pass_snapshot(tmp_path: Path) -> None:
    comment = _render_case(
        tmp_path,
        _evidence(
            head_sha="head-pass",
            changed_files=[
                {
                    "path": "README.md",
                    "status": "modified",
                    "sha256_after": "sha256:" + "b" * 64,
                }
            ],
            conclusion="success",
        ),
    )

    assert comment == _snapshot("comment_pass.md")


def test_render_comment_needs_review_snapshot(tmp_path: Path) -> None:
    comment = _render_case(
        tmp_path,
        _evidence(
            head_sha="head-needs-review",
            changed_files=[
                {
                    "path": "auth/session.py",
                    "status": "modified",
                    "sha256_after": "sha256:" + "b" * 64,
                }
            ],
            conclusion="success",
        ),
    )

    assert comment == _snapshot("comment_needs_review.md")


def test_render_comment_block_snapshot(tmp_path: Path) -> None:
    comment = _render_case(
        tmp_path,
        _evidence(
            head_sha="head-block",
            changed_files=[
                {
                    "path": "README.md",
                    "status": "modified",
                    "sha256_after": "sha256:" + "b" * 64,
                }
            ],
            conclusion="failure",
        ),
    )

    assert comment == _snapshot("comment_block.md")


def test_render_comment_missing_required_check_does_not_quote_unrelated_check(
    tmp_path: Path,
) -> None:
    evidence = _evidence(
        head_sha="head-missing-check",
        changed_files=[
            {
                "path": "README.md",
                "status": "modified",
                "sha256_after": "sha256:" + "b" * 64,
            }
        ],
        conclusion="success",
    )
    evidence["observed_checks"] = [
        {
            "name": "Prepare",
            "provider": "github_checks",
            "head_sha": "head-missing-check",
            "status": "completed",
            "conclusion": "success",
            "observed_at": "2026-05-08T12:00:00Z",
        }
    ]

    comment = _render_case(tmp_path, evidence)

    assert 'Claim: NOT_EVALUATED - required check "tests" was not observed' in comment
    assert 'observed check "Prepare"' not in comment


def test_pr_gate_render_comment_cli_writes_comment(tmp_path: Path) -> None:
    _render_case(
        tmp_path,
        _evidence(
            head_sha="head-pass",
            changed_files=[
                {
                    "path": "README.md",
                    "status": "modified",
                    "sha256_after": "sha256:" + "b" * 64,
                }
            ],
            conclusion="success",
        ),
    )
    out_path = tmp_path / "comment.md"

    result = runner.invoke(
        assay_app,
        [
            "pr-gate",
            "render-comment",
            "--report",
            str(tmp_path / "signed-report" / "verify_report.json"),
            "--pack",
            str(tmp_path / "proof-pack" / "pack_manifest.json"),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["bytes"] == len(out_path.read_bytes())
    assert out_path.read_text(encoding="utf-8") == _snapshot("comment_pass.md")


def test_render_comment_rejects_mismatched_report_and_pack(tmp_path: Path) -> None:
    _render_case(
        tmp_path,
        _evidence(
            head_sha="head-pass",
            changed_files=[
                {
                    "path": "README.md",
                    "status": "modified",
                    "sha256_after": "sha256:" + "b" * 64,
                }
            ],
            conclusion="success",
        ),
    )
    report_path = tmp_path / "signed-report" / "verify_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["pack_root_sha256"] = "sha256:" + "c" * 64
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CommentRenderError, match="pack_root_sha256"):
        render_pr_gate_comment_files(
            report_path=report_path,
            pack_manifest_path=tmp_path / "proof-pack" / "pack_manifest.json",
        )


def test_pr_gate_render_comment_cli_bad_input_exits_3(tmp_path: Path) -> None:
    result = runner.invoke(
        assay_app,
        [
            "pr-gate",
            "render-comment",
            "--report",
            str(tmp_path / "missing-report.json"),
            "--pack",
            str(tmp_path / "missing-pack.json"),
            "--out",
            str(tmp_path / "comment.md"),
        ],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["status"] == "error"
    assert "Verification Report not found" in payload["error"]
