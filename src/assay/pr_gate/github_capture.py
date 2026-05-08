"""GitHub capture adapter for Assay PR Gate v0."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from assay.pr_gate.policy import compute_policy_sha256, load_policy

DEFAULT_GITHUB_API_URL = "https://api.github.com"
SCHEMA_VERSION = "assay.pr_gate.evidence.v0.1"
GitRunner = Callable[[Sequence[str], Path], bytes]


class CaptureError(ValueError):
    """Raised when PR Gate capture cannot produce trustworthy evidence."""


class GitHubClient:
    """Small GitHub REST client for PR Gate capture."""

    def __init__(
        self,
        *,
        api_url: str = DEFAULT_GITHUB_API_URL,
        token: Optional[str] = None,
        timeout_sec: int = 30,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.timeout_sec = timeout_sec

    def get_json(
        self, path: str, params: Optional[Mapping[str, Any]] = None
    ) -> Any:
        url = self._url(path, params)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "assay-pr-gate-capture",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=self.timeout_sec) as response:
                body = response.read().decode("utf-8")
        except HTTPError as exc:
            raise CaptureError(
                f"GitHub API request failed: HTTP {exc.code} {exc.reason} for {path}"
            ) from exc
        except URLError as exc:
            raise CaptureError(f"GitHub API request failed for {path}: {exc.reason}") from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise CaptureError(f"GitHub API returned malformed JSON for {path}") from exc

    def paginate(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        result_key: Optional[str] = None,
    ) -> List[Any]:
        """Return all pages for a GitHub list endpoint."""
        all_items: List[Any] = []
        base_params = dict(params or {})
        per_page = int(base_params.pop("per_page", 100))
        page = 1

        while True:
            page_params = {**base_params, "per_page": per_page, "page": page}
            payload = self.get_json(path, page_params)
            items = payload.get(result_key) if result_key else payload
            if not isinstance(items, list):
                raise CaptureError(f"GitHub API list response was not a list for {path}")
            all_items.extend(items)
            if len(items) < per_page:
                return all_items
            page += 1

    def _url(self, path: str, params: Optional[Mapping[str, Any]]) -> str:
        url = f"{self.api_url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url


def capture_github_pr(
    *,
    repo: str,
    pr_number: int,
    head_sha: Optional[str] = None,
    out_path: Optional[Path] = None,
    policy_path: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    git_cwd: Optional[Path] = None,
    git_runner: Optional[GitRunner] = None,
    github_client: Optional[GitHubClient] = None,
    api_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Capture GitHub PR metadata, checks, and local content hashes."""
    if git_runner is None:
        git_runner = run_git
    env = env or os.environ
    git_cwd = git_cwd or Path.cwd()

    _validate_repo(repo)
    if pr_number <= 0:
        raise CaptureError("--pr must be a positive integer")

    client = github_client or GitHubClient(
        api_url=api_url or env.get("GITHUB_API_URL") or DEFAULT_GITHUB_API_URL,
        token=token or env.get("GITHUB_TOKEN") or env.get("GH_TOKEN"),
    )

    pr_payload = client.get_json(_repo_path(repo, f"pulls/{pr_number}"))
    base_sha = _nested_str(pr_payload, "base", "sha")
    api_head_sha = _nested_str(pr_payload, "head", "sha")
    if not base_sha or not api_head_sha:
        raise CaptureError("Pull request response did not include base.sha and head.sha")
    if head_sha and head_sha != api_head_sha:
        raise CaptureError(
            "--head-sha does not match GitHub pull_request.head.sha; "
            "pass the PR head SHA, not the pull_request merge ref"
        )
    subject_head_sha = api_head_sha

    files_payload = client.paginate(_repo_path(repo, f"pulls/{pr_number}/files"))
    checks_payload = client.paginate(
        _repo_path(repo, f"commits/{subject_head_sha}/check-runs"),
        result_key="check_runs",
    )

    diff_bytes = git_runner(
        ["diff", "--binary", "--full-index", base_sha, subject_head_sha],
        git_cwd,
    )

    evidence: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "subject": {
            "repo": repo,
            "pr_number": pr_number,
            "base_sha": base_sha,
            "head_sha": subject_head_sha,
            "diff_sha256": _sha256_prefixed(diff_bytes),
            "diff_source": "git diff --binary --full-index <base_sha> <head_sha>",
        },
        "capture": _capture_context(env),
        "changed_files": _changed_files(
            files_payload,
            head_sha=subject_head_sha,
            git_cwd=git_cwd,
            git_runner=git_runner,
        ),
        "observed_checks": _observed_checks(checks_payload, subject_head_sha),
    }

    if policy_path is not None:
        policy = load_policy(policy_path)
        evidence["policy"] = {
            "profile": policy["profile"],
            "policy_sha256": compute_policy_sha256(policy),
        }

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return evidence


def run_git(args: Sequence[str], cwd: Path) -> bytes:
    """Run git with argv, never through a shell."""
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CaptureError(f"git {' '.join(args[:2])} failed: {stderr[:400]}")
    return proc.stdout


def resolve_pr_number(env: Optional[Mapping[str, str]] = None) -> Optional[int]:
    """Resolve a pull request number from explicit GitHub Actions context."""
    env = env or os.environ
    direct = env.get("PR_NUMBER")
    if direct:
        return _parse_positive_int(direct)

    event_path = env.get("GITHUB_EVENT_PATH")
    if event_path:
        try:
            event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CaptureError(f"Could not read GITHUB_EVENT_PATH: {exc}") from exc
        if not isinstance(event, Mapping):
            raise CaptureError("GITHUB_EVENT_PATH must contain a JSON object")
        number = None
        pull_request = event.get("pull_request")
        if isinstance(pull_request, Mapping):
            number = pull_request.get("number")
        if number is None:
            number = event.get("number")
        if number is not None:
            return _parse_positive_int(str(number))

    ref_name = env.get("GITHUB_REF_NAME", "")
    match = re.match(r"^(\d+)/(?:merge|head)$", ref_name)
    if match:
        return _parse_positive_int(match.group(1))

    return None


def _repo_path(repo: str, suffix: str) -> str:
    owner, name = repo.split("/", 1)
    return f"/repos/{quote(owner)}/{quote(name)}/{suffix.lstrip('/')}"


def _validate_repo(repo: str) -> None:
    if not isinstance(repo, str) or repo.count("/") != 1:
        raise CaptureError("--repo must be in owner/name form")
    owner, name = repo.split("/", 1)
    if not owner or not name:
        raise CaptureError("--repo must be in owner/name form")


def _nested_str(payload: Mapping[str, Any], first: str, second: str) -> Optional[str]:
    raw = payload.get(first)
    if not isinstance(raw, Mapping):
        return None
    value = raw.get(second)
    return value if isinstance(value, str) and value else None


def _capture_context(env: Mapping[str, str]) -> Dict[str, Optional[str]]:
    return {
        "provider": "github_actions",
        "workflow_ref": env.get("GITHUB_WORKFLOW_REF"),
        "workflow_sha": env.get("GITHUB_WORKFLOW_SHA"),
        "run_id": env.get("GITHUB_RUN_ID"),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
        "actor": env.get("GITHUB_ACTOR"),
        "event_name": env.get("GITHUB_EVENT_NAME"),
        "github_sha": env.get("GITHUB_SHA"),
    }


def _changed_files(
    files_payload: Sequence[Any],
    *,
    head_sha: str,
    git_cwd: Path,
    git_runner: GitRunner,
) -> List[Dict[str, Any]]:
    changed: List[Dict[str, Any]] = []
    for raw in files_payload:
        if not isinstance(raw, Mapping):
            raise CaptureError("Pull request file entry was not an object")
        path = raw.get("filename")
        if not isinstance(path, str) or not path:
            raise CaptureError("Pull request file entry missing filename")
        status = _normalize_file_status(raw.get("status"))
        entry: Dict[str, Any] = {
            "path": path,
            "status": status,
            "sha256_after": None
            if status == "deleted"
            else _file_sha256_after(path, head_sha, git_cwd, git_runner),
        }
        previous_filename = raw.get("previous_filename")
        if isinstance(previous_filename, str) and previous_filename:
            entry["previous_path"] = previous_filename
        changed.append(entry)
    return sorted(changed, key=lambda item: item["path"])


def _normalize_file_status(raw_status: Any) -> str:
    status = str(raw_status or "modified")
    if status == "removed":
        return "deleted"
    return status


def _file_sha256_after(
    path: str,
    head_sha: str,
    git_cwd: Path,
    git_runner: GitRunner,
) -> str:
    return _sha256_prefixed(git_runner(["show", f"{head_sha}:{path}"], git_cwd))


def _observed_checks(checks_payload: Sequence[Any], head_sha: str) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    for raw in checks_payload:
        if not isinstance(raw, Mapping):
            raise CaptureError("Check run entry was not an object")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise CaptureError("Check run entry missing name")
        check_head_sha = raw.get("head_sha")
        if check_head_sha != head_sha:
            raise CaptureError(
                f"Check run {name!r} is not bound to PR head SHA {head_sha}"
            )
        checks.append(
            {
                "name": name,
                "provider": "github_checks",
                "head_sha": check_head_sha,
                "status": raw.get("status"),
                "conclusion": raw.get("conclusion"),
                "observed_at": raw.get("completed_at")
                or raw.get("updated_at")
                or raw.get("started_at"),
            }
        )
    return sorted(
        checks,
        key=lambda item: (
            str(item["name"]),
            str(item["head_sha"]),
            str(item.get("observed_at") or ""),
            str(item.get("conclusion") or ""),
        ),
    )


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise CaptureError(f"Pull request number is not an integer: {raw!r}") from exc
    if value <= 0:
        raise CaptureError("Pull request number must be positive")
    return value


__all__ = [
    "CaptureError",
    "DEFAULT_GITHUB_API_URL",
    "GitHubClient",
    "SCHEMA_VERSION",
    "capture_github_pr",
    "resolve_pr_number",
    "run_git",
]
