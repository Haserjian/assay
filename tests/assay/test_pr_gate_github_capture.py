"""Tests for the Assay PR Gate GitHub capture adapter."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.pr_gate.github_capture import (
    CaptureError,
    capture_github_pr,
    resolve_pr_number,
)

runner = CliRunner()

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "docs" / "examples" / "pr-gate-v0" / "assay-policy.yml"


class FakeGitHubClient:
    def __init__(self) -> None:
        self.paths: List[str] = []

    def get_json(
        self, path: str, params: Optional[Mapping[str, Any]] = None
    ) -> Dict[str, Any]:
        self.paths.append(path)
        assert params is None
        if path == "/repos/Haserjian/assay/pulls/123":
            return {
                "number": 123,
                "base": {"sha": "base-sha"},
                "head": {"sha": "head-sha"},
            }
        raise AssertionError(f"unexpected get_json path: {path}")

    def paginate(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        result_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        self.paths.append(path)
        assert params is None
        if path == "/repos/Haserjian/assay/pulls/123/files":
            return [
                {"filename": "src/app.py", "status": "modified"},
                {"filename": "old.py", "status": "removed"},
                {
                    "filename": ".github/workflows/ci.yml",
                    "status": "renamed",
                    "previous_filename": ".github/workflows/old.yml",
                },
            ]
        if path == "/repos/Haserjian/assay/commits/head-sha/check-runs":
            assert result_key == "check_runs"
            return [
                {
                    "name": "tests",
                    "head_sha": "head-sha",
                    "status": "completed",
                    "conclusion": "success",
                    "completed_at": "2026-05-08T12:00:00Z",
                },
                {
                    "name": "lint",
                    "head_sha": "head-sha",
                    "status": "in_progress",
                    "conclusion": None,
                    "updated_at": "2026-05-08T12:01:00Z",
                },
            ]
        raise AssertionError(f"unexpected paginate path: {path}")


class FakeGit:
    def __init__(self) -> None:
        self.calls: List[List[str]] = []

    def __call__(self, args: Sequence[str], cwd: Path) -> bytes:
        call = list(args)
        self.calls.append(call)
        assert cwd == Path("/repo")
        if call == ["diff", "--binary", "--full-index", "base-sha", "head-sha"]:
            return b"diff bytes\n"
        if call == ["show", "head-sha:src/app.py"]:
            return b"print('hi')\n"
        if call == ["show", "head-sha:.github/workflows/ci.yml"]:
            return b"name: ci\n"
        raise AssertionError(f"unexpected git call: {call}")


def test_capture_github_pr_builds_stable_evidence() -> None:
    fake_git = FakeGit()

    evidence = capture_github_pr(
        repo="Haserjian/assay",
        pr_number=123,
        head_sha="head-sha",
        policy_path=POLICY_PATH,
        env={
            "GITHUB_WORKFLOW_REF": "Haserjian/assay/.github/workflows/assay.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "workflow-sha",
            "GITHUB_RUN_ID": "1001",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_ACTOR": "tim",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_SHA": "merge-sha",
        },
        git_cwd=Path("/repo"),
        git_runner=fake_git,
        github_client=FakeGitHubClient(),  # type: ignore[arg-type]
    )

    assert evidence["schema_version"] == "assay.pr_gate.evidence.v0.1"
    assert evidence["subject"] == {
        "repo": "Haserjian/assay",
        "pr_number": 123,
        "base_sha": "base-sha",
        "head_sha": "head-sha",
        "diff_sha256": "sha256:" + hashlib.sha256(b"diff bytes\n").hexdigest(),
        "diff_source": "git diff --binary --full-index <base_sha> <head_sha>",
    }
    assert evidence["capture"]["workflow_sha"] == "workflow-sha"
    assert evidence["capture"]["github_sha"] == "merge-sha"
    assert evidence["changed_files"] == [
        {
            "path": ".github/workflows/ci.yml",
            "previous_path": ".github/workflows/old.yml",
            "sha256_after": "sha256:" + hashlib.sha256(b"name: ci\n").hexdigest(),
            "status": "renamed",
        },
        {"path": "old.py", "sha256_after": None, "status": "deleted"},
        {
            "path": "src/app.py",
            "sha256_after": "sha256:" + hashlib.sha256(b"print('hi')\n").hexdigest(),
            "status": "modified",
        },
    ]
    assert evidence["observed_checks"] == [
        {
            "name": "lint",
            "provider": "github_checks",
            "head_sha": "head-sha",
            "status": "in_progress",
            "conclusion": None,
            "observed_at": "2026-05-08T12:01:00Z",
        },
        {
            "name": "tests",
            "provider": "github_checks",
            "head_sha": "head-sha",
            "status": "completed",
            "conclusion": "success",
            "observed_at": "2026-05-08T12:00:00Z",
        },
    ]
    assert evidence["policy"]["profile"] == "coding_pr_v0"
    assert evidence["policy"]["policy_sha256"].startswith("sha256:")
    assert ["show", "head-sha:old.py"] not in fake_git.calls


def test_capture_rejects_head_sha_mismatch() -> None:
    with pytest.raises(CaptureError, match="does not match"):
        capture_github_pr(
            repo="Haserjian/assay",
            pr_number=123,
            head_sha="merge-sha",
            git_cwd=Path("/repo"),
            git_runner=FakeGit(),
            github_client=FakeGitHubClient(),  # type: ignore[arg-type]
        )


def test_capture_rejects_check_run_for_different_head_sha() -> None:
    class MismatchedCheckClient(FakeGitHubClient):
        def paginate(
            self,
            path: str,
            *,
            params: Optional[Mapping[str, Any]] = None,
            result_key: Optional[str] = None,
        ) -> List[Dict[str, Any]]:
            if path.endswith("/files"):
                return [{"filename": "src/app.py", "status": "modified"}]
            if path.endswith("/check-runs"):
                return [
                    {
                        "name": "tests",
                        "head_sha": "other-sha",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            raise AssertionError(path)

    with pytest.raises(CaptureError, match="not bound to PR head SHA"):
        capture_github_pr(
            repo="Haserjian/assay",
            pr_number=123,
            git_cwd=Path("/repo"),
            git_runner=FakeGit(),
            github_client=MismatchedCheckClient(),  # type: ignore[arg-type]
        )


def test_untrusted_file_path_is_passed_as_git_argument() -> None:
    class WeirdPathClient(FakeGitHubClient):
        def paginate(
            self,
            path: str,
            *,
            params: Optional[Mapping[str, Any]] = None,
            result_key: Optional[str] = None,
        ) -> List[Dict[str, Any]]:
            if path.endswith("/files"):
                return [{"filename": "src/$(touch pwned).py", "status": "modified"}]
            if path.endswith("/check-runs"):
                return []
            raise AssertionError(path)

    calls: List[List[str]] = []

    def fake_git(args: Sequence[str], cwd: Path) -> bytes:
        calls.append(list(args))
        return b"x"

    capture_github_pr(
        repo="Haserjian/assay",
        pr_number=123,
        git_cwd=Path("/repo"),
        git_runner=fake_git,
        github_client=WeirdPathClient(),  # type: ignore[arg-type]
    )

    assert ["show", "head-sha:src/$(touch pwned).py"] in calls


def test_resolve_pr_number_from_event_path(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 456}}))

    assert resolve_pr_number({"GITHUB_EVENT_PATH": str(event_path)}) == 456


def test_capture_cli_writes_evidence(monkeypatch, tmp_path: Path) -> None:
    out_path = tmp_path / "evidence.json"

    def fake_capture_github_pr(**kwargs):
        assert kwargs["repo"] == "Haserjian/assay"
        assert kwargs["pr_number"] == 123
        assert kwargs["head_sha"] == "head-sha"
        kwargs["out_path"].write_text('{"ok": true}\n', encoding="utf-8")
        return {"ok": True}

    import assay.pr_gate.github_capture as github_capture

    monkeypatch.setenv("GITHUB_REPOSITORY", "Haserjian/assay")
    monkeypatch.setenv("PR_NUMBER", "123")
    monkeypatch.setattr(github_capture, "capture_github_pr", fake_capture_github_pr)

    result = runner.invoke(
        assay_app,
        [
            "pr-gate",
            "capture",
            "--head-sha",
            "head-sha",
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(out_path.read_text(encoding="utf-8")) == {"ok": True}
