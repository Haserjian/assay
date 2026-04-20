"""Policy resolver — turn a PolicyResolver handle into a COMPILE_RECEIPT dict.

This is a reusable primitive, not commitment-specific glue. Any receipt type
that carries a ``policy_hash`` may use it to bind the hash to a concrete
compiled-policy provenance record.

Slice 1 scope:
    - kind="uri": read a ``file://`` URI and parse as JSON; verify the
      returned ``policy_hash`` matches the resolver's declared hash.
    - kind="registry": declared but not implemented. Raises
      ``NotImplementedError`` explicitly — callers must not silently fall
      back to a different kind.

Design:
    - ``PolicyResolver`` is a plain dataclass with ``to_dict()``. Callers
      embed ``to_dict()`` into their receipt payloads alongside the
      ``policy_hash`` field.
    - ``resolve_policy`` never mutates state; it returns the parsed dict.
    - Mismatched hashes or missing files raise ``PolicyResolutionError``.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse


VALID_KINDS = {"uri", "registry"}


class PolicyResolutionError(ValueError):
    """Raised when a PolicyResolver cannot bind to a matching COMPILE_RECEIPT."""


@dataclass
class PolicyResolver:
    """Handle that names *where* a compiled policy lives and *what* it hashes to.

    ``ref`` interpretation depends on ``kind``:
        - ``"uri"``      → a ``file://`` URI to a COMPILE_RECEIPT.json document.
        - ``"registry"`` → a registry identifier (reserved; not implemented
          in Slice 1).

    ``policy_hash`` is the expected hash of the compiled policy. The resolved
    document's ``policy_hash`` field must equal this value, or resolution
    fails.
    """

    kind: str
    ref: str
    policy_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        if self.kind not in VALID_KINDS:
            raise PolicyResolutionError(
                f"Unknown PolicyResolver kind: {self.kind!r}. "
                f"Valid kinds: {sorted(VALID_KINDS)}"
            )


def resolve_policy(resolver: PolicyResolver) -> Dict[str, Any]:
    """Resolve a PolicyResolver to its COMPILE_RECEIPT document.

    Args:
        resolver: The handle naming where the compiled policy lives and
            what hash it must carry.

    Returns:
        The parsed COMPILE_RECEIPT.json as a dict.

    Raises:
        PolicyResolutionError: If the document is missing, malformed, or
            carries a ``policy_hash`` that differs from ``resolver.policy_hash``.
        NotImplementedError: If ``kind="registry"``. Registry-backed
            resolution is reserved for a later slice.
    """
    resolver.validate()

    if resolver.kind == "registry":
        raise NotImplementedError(
            "PolicyResolver kind='registry' is not implemented in Slice 1. "
            "Use kind='uri' with a file:// reference. Do not fall back silently."
        )

    if resolver.kind == "uri":
        return _resolve_uri(resolver)

    raise PolicyResolutionError(f"Unhandled resolver kind: {resolver.kind!r}")


def _resolve_uri(resolver: PolicyResolver) -> Dict[str, Any]:
    parsed = urlparse(resolver.ref)
    if parsed.scheme != "file":
        raise PolicyResolutionError(
            f"Slice 1 supports file:// URIs only (got scheme {parsed.scheme!r}). "
            f"ref={resolver.ref!r}"
        )

    path = Path(parsed.path)
    if not path.exists():
        raise PolicyResolutionError(
            f"COMPILE_RECEIPT not found at {path}. "
            f"ref={resolver.ref!r} policy_hash={resolver.policy_hash!r}"
        )

    try:
        raw = path.read_text()
        document = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyResolutionError(
            f"COMPILE_RECEIPT at {path} is unreadable or malformed: {exc}"
        ) from exc

    if not isinstance(document, dict):
        raise PolicyResolutionError(
            f"COMPILE_RECEIPT at {path} must be a JSON object, got {type(document).__name__}"
        )

    declared_hash = document.get("policy_hash")
    if declared_hash != resolver.policy_hash:
        raise PolicyResolutionError(
            f"COMPILE_RECEIPT policy_hash mismatch at {path}. "
            f"Resolver expected {resolver.policy_hash!r}, "
            f"document declares {declared_hash!r}."
        )

    return document


__all__ = [
    "VALID_KINDS",
    "PolicyResolutionError",
    "PolicyResolver",
    "resolve_policy",
]
