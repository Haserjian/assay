"""Tests for evidence readiness scoring (`assay score`)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.score import GRADE_TIERS, SCORE_VERSION, compute_evidence_readiness_score, gather_score_facts

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
        assert any("assay lock init" in step for step in result["next_actions"])


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


# ---------------------------------------------------------------------------
# Guidance layer: grade tiers, point estimation, fastest path
# ---------------------------------------------------------------------------


class TestGuidanceLayer:
    def test_grade_description_present(self) -> None:
        result = compute_evidence_readiness_score(_facts())
        assert "grade_description" in result
        assert result["grade_description"] == GRADE_TIERS["A"][1]

    def test_grade_description_for_f(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(
                sites_total=0, instrumented=0, uninstrumented=0,
                lock_present=False, lock_valid=False,
                has_assay_ref=False, has_run=False, has_verify=False, has_lock=False,
                repo_receipt_files=0, signer_count=0,
            )
        )
        assert result["grade"] == "F"
        assert result["grade_description"] == GRADE_TIERS["F"][1]

    def test_next_actions_detail_structure(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(lock_present=False, lock_valid=False)
        )
        detail = result["next_actions_detail"]
        assert isinstance(detail, list)
        assert len(detail) >= 1
        for ad in detail:
            assert "action" in ad
            assert "command" in ad
            assert "component" in ad
            assert "points_est" in ad
            assert isinstance(ad["points_est"], float)

    def test_next_actions_detail_has_lockfile_estimate(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(lock_present=False, lock_valid=False)
        )
        lock_actions = [
            a for a in result["next_actions_detail"] if a["component"] == "lockfile"
        ]
        assert len(lock_actions) == 1
        assert lock_actions[0]["points_est"] == 15.0
        assert "assay lock init" in lock_actions[0]["command"]

    def test_next_actions_backward_compat_strings(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(lock_present=False, lock_valid=False)
        )
        # next_actions is still a list of strings.
        assert isinstance(result["next_actions"], list)
        assert all(isinstance(s, str) for s in result["next_actions"])
        assert any("assay lock init" in s for s in result["next_actions"])

    def test_next_actions_sorted_by_points(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(
                lock_present=False, lock_valid=False,
                repo_receipt_files=0, signer_count=0,
            )
        )
        detail = result["next_actions_detail"]
        points = [a["points_est"] for a in detail]
        assert points == sorted(points, reverse=True)

    def test_fastest_path_present_when_not_a(self) -> None:
        result = compute_evidence_readiness_score(
            _facts(lock_present=False, lock_valid=False)
        )
        assert result["grade"] != "A"
        fp = result["fastest_path"]
        assert fp is not None
        assert "target_grade" in fp
        assert "target_score" in fp
        assert "command" in fp
        assert "points_est" in fp
        assert "projected_score" in fp
        assert fp["projected_score"] == round(result["score"] + fp["points_est"], 1)

    def test_fastest_path_none_when_a(self) -> None:
        result = compute_evidence_readiness_score(_facts())
        assert result["grade"] == "A"
        assert result["fastest_path"] is None

    def test_perfect_score_has_ready_action(self) -> None:
        result = compute_evidence_readiness_score(_facts())
        detail = result["next_actions_detail"]
        assert len(detail) == 1
        assert detail[0]["action"] == "Ready"
        assert detail[0]["points_est"] == 0.0

    def test_json_output_includes_guidance_fields(self, tmp_path: Path, monkeypatch) -> None:
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
        assert "grade_description" in data
        assert "next_actions_detail" in data
        # fastest_path may be None or dict -- just check key exists
        assert "fastest_path" in data

