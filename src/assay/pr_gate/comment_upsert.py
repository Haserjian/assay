"""Create or update the Assay PR Gate pull request comment."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from assay.pr_gate.github_capture import DEFAULT_GITHUB_API_URL

COMMENT_MARKER = "<!-- assay-pr-gate:v0 -->"


class CommentUpsertError(ValueError):
    """Raised when the PR Gate comment cannot be published safely."""


class IssueCommentClient(Protocol):
    """Minimal client contract for PR timeline comments."""

    def list_issue_comments(self, *, repo: str, issue_number: int) -> List[Dict[str, Any]]:
        """Return issue comments for a PR/issue timeline."""

    def create_issue_comment(
        self, *, repo: str, issue_number: int, body: str
    ) -> Dict[str, Any]:
        """Create a PR/issue timeline comment."""

    def update_issue_comment(
        self, *, repo: str, comment_id: int, body: str
    ) -> Dict[str, Any]:
        """Update a PR/issue timeline comment."""


class GitHubIssueCommentClient:
    """Small GitHub REST client for PR Gate issue comments."""

    def __init__(
        self,
        *,
        token: str,
        api_url: str = DEFAULT_GITHUB_API_URL,
        timeout_sec: int = 30,
    ) -> None:
        if not token:
            raise CommentUpsertError("GitHub token is required to upsert PR comments")
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout_sec = timeout_sec

    def list_issue_comments(self, *, repo: str, issue_number: int) -> List[Dict[str, Any]]:
        all_items: List[Dict[str, Any]] = []
        page = 1
        while True:
            payload = self._request_json(
                "GET",
                _repo_path(repo, f"issues/{issue_number}/comments"),
                params={"per_page": 100, "page": page},
            )
            if not isinstance(payload, list):
                raise CommentUpsertError("GitHub comments response was not a list")
            items: List[Dict[str, Any]] = []
            for index, item in enumerate(payload):
                if not isinstance(item, dict):
                    raise CommentUpsertError(
                        f"GitHub comments[{index}] response was not an object"
                    )
                items.append(item)
            all_items.extend(items)
            if len(items) < 100:
                return all_items
            page += 1

    def create_issue_comment(
        self, *, repo: str, issue_number: int, body: str
    ) -> Dict[str, Any]:
        payload = self._request_json(
            "POST",
            _repo_path(repo, f"issues/{issue_number}/comments"),
            body={"body": body},
        )
        return _json_object(payload, "create comment response")

    def update_issue_comment(
        self, *, repo: str, comment_id: int, body: str
    ) -> Dict[str, Any]:
        payload = self._request_json(
            "PATCH",
            _repo_path(repo, f"issues/comments/{comment_id}"),
            body={"body": body},
        )
        return _json_object(payload, "update comment response")

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        url = f"{self.api_url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "assay-pr-gate-comment",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_sec) as response:
                raw = response.read().decode("utf-8")
        except HTTPError as exc:
            raise CommentUpsertError(
                f"GitHub comment request failed: HTTP {exc.code} {exc.reason}"
            ) from exc
        except URLError as exc:
            raise CommentUpsertError(
                f"GitHub comment request failed: {exc.reason}"
            ) from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CommentUpsertError("GitHub comment response was malformed JSON") from exc


def upsert_pr_gate_comment(
    *,
    repo: str,
    pr_number: int,
    body: str,
    client: IssueCommentClient,
) -> Dict[str, Any]:
    """Create or update the marked PR Gate PR comment."""
    _validate_repo(repo)
    if pr_number <= 0:
        raise CommentUpsertError("pr_number must be positive")
    marked_body = ensure_comment_marker(body)
    comments = client.list_issue_comments(repo=repo, issue_number=pr_number)
    existing = find_marked_comment(comments)
    if existing is None:
        created = client.create_issue_comment(
            repo=repo,
            issue_number=pr_number,
            body=marked_body,
        )
        return {
            "action": "created",
            "comment_id": created.get("id"),
            "marker": COMMENT_MARKER,
            "bytes": len(marked_body.encode("utf-8")),
        }

    comment_id = _comment_id(existing)
    updated = client.update_issue_comment(
        repo=repo,
        comment_id=comment_id,
        body=marked_body,
    )
    return {
        "action": "updated",
        "comment_id": updated.get("id", comment_id),
        "marker": COMMENT_MARKER,
        "bytes": len(marked_body.encode("utf-8")),
    }


def upsert_pr_gate_comment_file(
    *,
    repo: str,
    pr_number: int,
    body_path: Path,
    token: str,
    api_url: Optional[str] = None,
    client: Optional[IssueCommentClient] = None,
) -> Dict[str, Any]:
    """Load a rendered comment file and upsert it on the PR timeline."""
    if not body_path.exists():
        raise CommentUpsertError(f"comment body file not found: {body_path}")
    if not body_path.is_file():
        raise CommentUpsertError(f"comment body path is not a file: {body_path}")
    body = body_path.read_text(encoding="utf-8")
    actual_client = client or GitHubIssueCommentClient(
        token=token,
        api_url=api_url or DEFAULT_GITHUB_API_URL,
    )
    return upsert_pr_gate_comment(
        repo=repo,
        pr_number=pr_number,
        body=body,
        client=actual_client,
    )


def ensure_comment_marker(body: str) -> str:
    """Return the comment body with a stable PR Gate marker."""
    if COMMENT_MARKER in body:
        return body if body.endswith("\n") else f"{body}\n"
    suffix = body if body.endswith("\n") else f"{body}\n"
    return f"{COMMENT_MARKER}\n{suffix}"


def find_marked_comment(comments: List[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    """Return the first existing PR Gate comment, if present."""
    for comment in comments:
        body = comment.get("body")
        if isinstance(body, str) and COMMENT_MARKER in body:
            return comment
    return None


def _comment_id(comment: Mapping[str, Any]) -> int:
    raw = comment.get("id")
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        raise CommentUpsertError("marked comment has invalid id")
    return raw


def _repo_path(repo: str, suffix: str) -> str:
    owner, name = repo.split("/", 1)
    return f"/repos/{quote(owner)}/{quote(name)}/{suffix.lstrip('/')}"


def _validate_repo(repo: str) -> None:
    if "/" not in repo:
        raise CommentUpsertError("repo must be in owner/name form")
    owner, name = repo.split("/", 1)
    if not owner or not name:
        raise CommentUpsertError("repo must be in owner/name form")


def _json_object(raw: Any, label: str) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise CommentUpsertError(f"{label} was not a JSON object")
    return raw


__all__ = [
    "COMMENT_MARKER",
    "CommentUpsertError",
    "GitHubIssueCommentClient",
    "ensure_comment_marker",
    "find_marked_comment",
    "upsert_pr_gate_comment",
    "upsert_pr_gate_comment_file",
]
