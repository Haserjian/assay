"""Diff source readers for Assay Claim Gate."""

from __future__ import annotations

import difflib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from assay.claim_gate.models import DiffCollection, DiffPair, TextSpan

TEXT_EXTENSIONS = {
    ".adoc",
    ".cfg",
    ".csv",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".rst",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


PROBABLE_RENAME_MIN_SIMILARITY = 0.35


class DiffSourceError(ValueError):
    """Raised when Claim Gate cannot read the requested diff."""


@dataclass(frozen=True)
class DiffPathChange:
    """One file-level change between two refs."""

    before_path: Optional[str]
    after_path: Optional[str]


def collect_diff(
    *,
    repo_root: Path,
    base: str,
    head: str,
    paths: Optional[Sequence[str]] = None,
) -> DiffCollection:
    """Collect changed text spans between two Git refs."""
    repo_root = repo_root.resolve()
    changes = (
        [DiffPathChange(before_path=path, after_path=path) for path in paths]
        if paths is not None
        else _pair_probable_renames(
            repo_root,
            base,
            head,
            git_diff_changes(repo_root, base, head),
        )
    )
    pairs: List[DiffPair] = []
    files_scanned = 0
    changed_paths: List[str] = []

    for change in changes:
        report_path = change.after_path or change.before_path
        if report_path is None or not is_text_path(report_path):
            continue
        if change.after_path is None:
            continue
        before = (
            git_show_text(repo_root, base, change.before_path)
            if change.before_path is not None
            else None
        )
        after = git_show_text(repo_root, head, change.after_path)
        if before is None and after is None:
            continue
        before_text = before or ""
        after_text = after or ""
        if before_text == after_text:
            continue
        files_scanned += 1
        changed_paths.append(change.after_path)
        pairs.extend(
            diff_pairs_from_texts(
                report_path,
                before_text,
                after_text,
                before_file_path=change.before_path or report_path,
                after_file_path=change.after_path,
            )
        )

    return DiffCollection(
        base=base,
        head=head,
        changed_paths=sorted(dict.fromkeys(changed_paths)),
        pairs=pairs,
        files_scanned=files_scanned,
    )


def diff_pairs_from_texts(
    file_path: str,
    before_text: str,
    after_text: str,
    *,
    before_file_path: Optional[str] = None,
    after_file_path: Optional[str] = None,
) -> List[DiffPair]:
    """Return before/after changed spans for two text blobs."""
    before_file = before_file_path or file_path
    after_file = after_file_path or file_path
    before_lines = before_text.splitlines()
    after_lines = after_text.splitlines()
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    pairs: List[DiffPair] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        before_span = _span(before_file, before_lines, i1, i2)
        after_span = _span(after_file, after_lines, j1, j2)
        pairs.append(
            DiffPair(file=after_file, before_span=before_span, after_span=after_span)
        )
    return pairs


def git_changed_paths(repo_root: Path, base: str, head: str) -> List[str]:
    """Return changed paths between two refs using git diff --name-status."""
    return sorted(
        dict.fromkeys(
            change.after_path
            for change in git_diff_changes(repo_root, base, head)
            if change.after_path is not None
        )
    )


def git_diff_changes(repo_root: Path, base: str, head: str) -> List[DiffPathChange]:
    """Return file-level changes between two refs using git diff --name-status."""
    output = _run_git(repo_root, ["diff", "-M1%", "--name-status", base, head])
    changes: List[DiffPathChange] = []
    for raw_line in output.splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t")
        status = parts[0]
        if len(parts) < 2:
            raise DiffSourceError(
                f"Unexpected git diff --name-status line: {raw_line!r}"
            )
        if status.startswith("D"):
            changes.append(DiffPathChange(before_path=parts[1], after_path=None))
            continue
        if status.startswith("R") and len(parts) >= 3:
            changes.append(DiffPathChange(before_path=parts[1], after_path=parts[2]))
            continue
        after_path = parts[1]
        before_path = None if status.startswith("A") else after_path
        changes.append(DiffPathChange(before_path=before_path, after_path=after_path))
    return changes


def _pair_probable_renames(
    repo_root: Path,
    base: str,
    head: str,
    changes: List[DiffPathChange],
) -> List[DiffPathChange]:
    deleted = [
        change
        for change in changes
        if change.before_path is not None
        and change.after_path is None
        and is_text_path(change.before_path)
    ]
    added = [
        change
        for change in changes
        if change.before_path is None
        and change.after_path is not None
        and is_text_path(change.after_path)
    ]
    if not deleted or not added:
        return changes

    deleted_text = {
        change.before_path: git_show_text(repo_root, base, change.before_path) or ""
        for change in deleted
        if change.before_path is not None
    }
    added_text = {
        change.after_path: git_show_text(repo_root, head, change.after_path) or ""
        for change in added
        if change.after_path is not None
    }

    candidates = []
    for deleted_change in deleted:
        for added_change in added:
            if deleted_change.before_path is None or added_change.after_path is None:
                continue
            if (
                Path(deleted_change.before_path).suffix.lower()
                != Path(added_change.after_path).suffix.lower()
            ):
                continue
            similarity = difflib.SequenceMatcher(
                a=deleted_text[deleted_change.before_path],
                b=added_text[added_change.after_path],
                autojunk=False,
            ).ratio()
            if similarity >= PROBABLE_RENAME_MIN_SIMILARITY:
                candidates.append((similarity, deleted_change, added_change))

    if not candidates:
        return changes

    matched_deletes = set()
    matched_adds = set()
    paired_targets = {}
    for _, deleted_change, added_change in sorted(
        candidates,
        key=lambda item: (
            -item[0],
            item[1].before_path or "",
            item[2].after_path or "",
        ),
    ):
        delete_path = deleted_change.before_path
        add_path = added_change.after_path
        if delete_path is None or add_path is None:
            continue
        if delete_path in matched_deletes or add_path in matched_adds:
            continue
        matched_deletes.add(delete_path)
        matched_adds.add(add_path)
        paired_targets[delete_path] = DiffPathChange(
            before_path=delete_path,
            after_path=add_path,
        )

    if not paired_targets:
        return changes

    paired: List[DiffPathChange] = []
    consumed_deletes = set()
    consumed_adds = set()
    for change in changes:
        if change.before_path in paired_targets and change.after_path is None:
            pair = paired_targets[change.before_path]
            if pair.before_path not in consumed_deletes:
                paired.append(pair)
                consumed_deletes.add(pair.before_path)
                if pair.after_path is not None:
                    consumed_adds.add(pair.after_path)
            continue
        if change.before_path is None and change.after_path in consumed_adds:
            continue
        paired.append(change)
    return paired


def git_show_text(repo_root: Path, ref: str, file_path: str) -> Optional[str]:
    """Read file text at a Git ref. Missing files return None."""
    proc = subprocess.run(
        ["git", "show", f"{ref}:{file_path}"],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def is_text_path(file_path: str) -> bool:
    """Return whether a path is in Claim Gate's text scan surface."""
    return Path(file_path).suffix.lower() in TEXT_EXTENSIONS


def _span(file_path: str, lines: List[str], start: int, end: int) -> TextSpan:
    if start == end:
        line = start + 1 if lines else 0
        return TextSpan(file=file_path, start_line=line, end_line=line, text="")
    return TextSpan(
        file=file_path,
        start_line=start + 1,
        end_line=end,
        text="\n".join(lines[start:end]),
    )


def _run_git(repo_root: Path, args: Sequence[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        raise DiffSourceError(f"git {' '.join(args)} failed: {stderr[:400]}")
    return proc.stdout
