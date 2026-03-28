"""Canonicalization law for content hashing.

Before hashing content for comparison (prompts, rubrics, datasets,
format templates), content must be normalized to prevent false
mismatches from trivial formatting differences.

Canonicalization rules (v0):
  - UTF-8 encoding
  - LF newlines (\\r\\n → \\n, bare \\r → \\n)
  - Trailing newline: exactly one \\n at end
  - Leading/trailing whitespace on each line: PRESERVED
  - Order: PRESERVED
  - Comments: PRESERVED
  - Empty content: normalized to single \\n
"""
from __future__ import annotations

import hashlib


def canonicalize_content(content: str | bytes) -> bytes:
    """Normalize content for deterministic hashing.

    Returns canonical UTF-8 bytes.
    """
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="replace")
    else:
        text = content

    # Normalize newlines: \r\n → \n, bare \r → \n
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Ensure exactly one trailing newline
    text = text.rstrip("\n") + "\n"

    return text.encode("utf-8")


def content_hash(content: str | bytes) -> str:
    """SHA-256 hash of canonicalized content.

    Returns hex digest prefixed with algorithm: "sha256:<hex>".
    """
    canonical = canonicalize_content(content)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"
