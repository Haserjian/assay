"""Tests for PR Gate comment upsert behavior."""
from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List
from urllib.error import HTTPError

import pytest

from assay.pr_gate import comment_upsert
from assay.pr_gate.comment_upsert import (
    COMMENT_MARKER,
    CommentUpsertError,
    GitHubIssueCommentClient,
    ensure_comment_marker,
    find_marked_comment,
    upsert_pr_gate_comment,
    upsert_pr_gate_comment_file,
)


class FakeCommentClient:
    def __init__(self, comments: List[Dict[str, Any]]) -> None:
        self.comments = list(comments)
        self.created: List[Dict[str, Any]] = []
        self.updated: List[Dict[str, Any]] = []

    def list_issue_comments(self, *, repo: str, issue_number: int) -> List[Dict[str, Any]]:
        self.repo = repo
        self.issue_number = issue_number
        return list(self.comments)

    def create_issue_comment(
        self, *, repo: str, issue_number: int, body: str
    ) -> Dict[str, Any]:
        comment = {"id": 9001, "body": body}
        self.created.append(
            {"repo": repo, "issue_number": issue_number, "body": body}
        )
        self.comments.append(comment)
        return comment

    def update_issue_comment(
        self, *, repo: str, comment_id: int, body: str
    ) -> Dict[str, Any]:
        self.updated.append({"repo": repo, "comment_id": comment_id, "body": body})
        return {"id": comment_id, "body": body}


def test_ensure_comment_marker_adds_stable_marker() -> None:
    body = ensure_comment_marker("Assay PR Gate: PASS\n")

    assert body.startswith(f"{COMMENT_MARKER}\n")
    assert body.count(COMMENT_MARKER) == 1


def test_ensure_comment_marker_does_not_duplicate_marker() -> None:
    body = ensure_comment_marker(f"{COMMENT_MARKER}\nAssay PR Gate: PASS\n")

    assert body.count(COMMENT_MARKER) == 1


def test_find_marked_comment_returns_existing_pr_gate_comment() -> None:
    marked = {"id": 2, "body": f"{COMMENT_MARKER}\nold"}

    assert find_marked_comment([{"id": 1, "body": "other"}, marked]) == marked


def test_upsert_pr_gate_comment_creates_when_marker_missing() -> None:
    client = FakeCommentClient([{"id": 1, "body": "other"}])

    result = upsert_pr_gate_comment(
        repo="Haserjian/assay",
        pr_number=123,
        body="Assay PR Gate: PASS\n",
        client=client,
    )

    assert result["action"] == "created"
    assert len(client.created) == 1
    assert len(client.updated) == 0
    assert client.created[0]["body"].startswith(f"{COMMENT_MARKER}\n")


def test_upsert_pr_gate_comment_updates_existing_marker_without_duplicate() -> None:
    client = FakeCommentClient(
        [{"id": 44, "body": f"{COMMENT_MARKER}\nAssay PR Gate: OLD\n"}]
    )

    result = upsert_pr_gate_comment(
        repo="Haserjian/assay",
        pr_number=123,
        body="Assay PR Gate: NEEDS_REVIEW\n",
        client=client,
    )

    assert result["action"] == "updated"
    assert result["comment_id"] == 44
    assert len(client.created) == 0
    assert len(client.updated) == 1
    assert client.updated[0]["body"].count(COMMENT_MARKER) == 1
    assert "NEEDS_REVIEW" in client.updated[0]["body"]


def test_upsert_pr_gate_comment_file_reads_body_and_inserts_marker(tmp_path: Path) -> None:
    body_path = tmp_path / "comment.md"
    body_path.write_text("Assay PR Gate: BLOCK\n", encoding="utf-8")
    client = FakeCommentClient([])

    result = upsert_pr_gate_comment_file(
        repo="Haserjian/assay",
        pr_number=123,
        body_path=body_path,
        token="token",
        client=client,
    )

    assert result["action"] == "created"
    assert client.created[0]["body"].startswith(f"{COMMENT_MARKER}\n")


def test_github_client_http_errors_include_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request: Any, timeout: int) -> None:
        raise HTTPError(
            request.full_url,
            403,
            "Forbidden",
            {},
            BytesIO(
                b'{"message":"Resource not accessible by integration",'
                b'"documentation_url":"https://docs.github.com/rest"}'
            ),
        )

    monkeypatch.setattr(comment_upsert, "urlopen", fake_urlopen)
    client = GitHubIssueCommentClient(token="token")

    with pytest.raises(CommentUpsertError) as exc_info:
        client.list_issue_comments(repo="Haserjian/assay", issue_number=134)

    message = str(exc_info.value)
    assert "GET /repos/Haserjian/assay/issues/134/comments" in message
    assert "HTTP 403 Forbidden" in message
    assert "Resource not accessible by integration" in message
