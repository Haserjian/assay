"""Tests for evidence readiness scoring (`assay score`)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.score import SCORE_VERSION, compute_evidence_readiness_score, gather_score_facts

runner = CliRunner()


def _facts(
    *,
    sites_total: int = 10,
    instrumented: int = 10,
    uninstrumented: int = 0,
    lock_present: bool = True,
    lock_valid: bool = True,
    lock_stale: bool = False,
    has_assay_ref: bool = True,
    has_run: bool = True,
    has_verify: bool = True,
    has_lock: bool = True,
    repo_receipt_files: int = 2,
    signer_count: int = 1,
) -> Dict[str, Any]:
    return {
        "repo_path": "/tmp/repo",
        "scan": {
            "sites_total": sites_total,
            "instrumented": instrumented,
            "uninstrumented": uninstrumented,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "lockfile": {
            "present": lock_present,
            "valid": lock_valid,
            "stale": lock_stale,
            "issues": [] if lock_valid else ["drift"],
        },
        "ci": {
            "workflow_count": 1 if has_assay_ref else 0,
            "files": [".github/workflows/assay-verify.yml"] if has_assay_ref else [],
            "has_assay_ref": has_assay_ref,
            "has_run": has_run,
            "has_verify": has_verify,
            "has_lock": has_lock,
        },
        "receipts": {
            "proof_pack_receipt_files": repo_receipt_files,
            "mcp_session_files": 0,
            "repo_receipt_files": repo_receipt_files,
        },
        "keys": {
            "signer_count": signer_count,
            "active_signer": "assay-local" if signer_count else None,
        },
    }


class TestComputeEvidenceReadiness:
    def test_score_version_present(self) -> None:
        result = compute_evidence_readiness_score(_facts())
        assert result["score_version"] == SCORE_VERSION

    def test_no_receipts_caps_grade_to_d(self) -> None:
        result = compute_evidence_readiness_score(_facts(repo_receipt_files=0))
        assert result["grade"] in {"D", "F"}
        # Cap should be visible when no receipts.
        assert any(c["id"] == "CAP_NO_RECEIPTS_MAX_D" for c in result["caps_applied"])
        assert result["score"] <= 69.9

    def test_stale_lockfile_gets_partial_credit(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(lock_present=True, lock_valid=False, lock_stale=True)
        )
        lock = result["breakdown"]["lockfile"]
        assert lock["status"] == "partial"
        assert 0 < lock["points"] < lock["weight"]

    def test_ci_without_lock_is_partial_credit(self) -> None:
        result = compute_evidence_readiness_score(_facts(has_lock=False))
        ci = result["breakdown"]["ci_gate"]
        assert ci["status"] == "partial"
        assert 0 < ci["points"] < ci["weight"]

    def test_perfect_facts_reaches_a(self) -> None:
        result = compute_evidence_readiness_score(_facts())
        assert result["grade"] == "A"
        assert result["score"] >= 90

    def test_next_actions_include_patch_when_uninstrumented(self) -> None:
        result = compute_evidence_readiness_score(_facts(instrumented=4, uninstrumented=6))
        assert any("assay patch" in step for step in result["next_actions"])

    def test_next_actions_include_lock_when_missing(self) -> None:
        result = compute_evidence_readiness_score(_facts(lock_present=False, lock_valid=False))
        assert any("assay lock write" in step for step in result["next_actions"])


class TestGatherFacts:
    def test_gather_score_facts_basic_shape(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )
        facts = gather_score_facts(tmp_path)
        assert "scan" in facts
        assert "lockfile" in facts
        assert "ci" in facts
        assert "receipts" in facts
        assert "keys" in facts
        assert facts["scan"]["sites_total"] == 1


class TestScoreCLI:
    def test_score_json_contract(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )

        result = runner.invoke(assay_app, ["score", ".", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["command"] == "score"
        assert data["status"] == "ok"
        assert data["score_version"] == SCORE_VERSION
        assert "score" in data
        assert "grade" in data
        assert "caps_applied" in data
        assert "breakdown" in data
        assert "next_actions" in data

    def test_score_missing_path_exit_3(self) -> None:
        result = runner.invoke(assay_app, ["score", "/definitely/not/a/real/path", "--json"])
        assert result.exit_code == 3, result.output
        data = json.loads(result.output)
        assert data["status"] == "error"

