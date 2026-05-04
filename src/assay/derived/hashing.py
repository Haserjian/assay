"""Hashing helpers for receipted derived context.

Human JSON is for reading. JCS bytes are for IDs, hashes, signatures, and
receipts.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from assay._receipts.jcs import canonicalize as jcs_canonicalize


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return jcs_canonicalize(value)


def canonical_hash(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def stable_id(prefix: str, payload: Mapping[str, Any], length: int = 24) -> str:
    digest = canonical_hash(dict(payload)).split(":", 1)[1]
    return f"{prefix}_{digest[:length]}"
