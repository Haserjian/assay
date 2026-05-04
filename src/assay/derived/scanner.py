"""Deterministic local-file scanner for receipted derived context."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from assay.derived.hashing import sha256_bytes, stable_id
from assay.derived.models import SourceSnapshot


DEFAULT_INCLUDE_SUFFIXES = (".py", ".md", ".txt")
DEFAULT_EXCLUDES = (
    ".git",
    ".assay",
    "__pycache__",
    ".venv",
    ".pytest_cache",
    "dist",
    "build",
)


@dataclass(frozen=True)
class ScannedSnapshot:
    snapshot: SourceSnapshot
    source_type: str
    uri: str
    relative_path: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def source_id_for_uri(uri: str, source_type: str = "local_file") -> str:
    return stable_id("src", {"source_type": source_type, "uri": uri})


def snapshot_id_for_source(source_id: str, content_hash: str) -> str:
    return stable_id("snap", {"source_id": source_id, "content_hash": content_hash})


def should_exclude(path: Path, root: Path, excludes: Sequence[str]) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(part in excludes for part in relative.parts)


def iter_source_files(
    root: Path,
    *,
    include_suffixes: Sequence[str] = DEFAULT_INCLUDE_SUFFIXES,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
) -> Iterable[Path]:
    root = root.resolve()
    suffixes = tuple(include_suffixes)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if should_exclude(path, root, excludes):
            continue
        if path.suffix not in suffixes:
            continue
        yield path


def scan_repository(
    root: Path,
    *,
    include_suffixes: Sequence[str] = DEFAULT_INCLUDE_SUFFIXES,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    observed_at: Optional[str] = None,
) -> List[ScannedSnapshot]:
    root = root.resolve()
    observed = observed_at or _now_iso()
    scanned: List[ScannedSnapshot] = []
    for path in iter_source_files(
        root, include_suffixes=include_suffixes, excludes=excludes
    ):
        relative_path = path.relative_to(root).as_posix()
        content = path.read_bytes()
        try:
            content_text = content.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            continue
        content_hash = sha256_bytes(content)
        uri = f"file://{relative_path}"
        source_id = source_id_for_uri(uri)
        snapshot = SourceSnapshot(
            snapshot_id=snapshot_id_for_source(source_id, content_hash),
            source_id=source_id,
            content_hash=content_hash,
            size_bytes=len(content),
            observed_at=observed,
            metadata={
                "relative_path": relative_path,
                "uri": uri,
                "encoding": encoding,
                "content_text": content_text,
            },
        )
        scanned.append(
            ScannedSnapshot(
                snapshot=snapshot,
                source_type="local_file",
                uri=uri,
                relative_path=relative_path,
            )
        )
    return scanned
