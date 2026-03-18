"""Signer registry: load, validate, and query known signers.

Registry is a YAML file at trust/signers.yaml (repo level, not library code).
Each entry defines a signer with grants and lifecycle state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass
class SignerGrant:
    """A specific permission for a signer."""

    artifact_class: str  # proof_pack, witness_envelope, etc.
    scope: str  # repo name, environment, or "*"
    purpose: str  # ci_attestation, publication, internal_evidence, or "*"


@dataclass
class SignerEntry:
    """A signer in the registry."""

    signer_id: str
    fingerprint: str  # SHA-256 of public key
    lifecycle: str  # active, rotated, revoked
    grants: List[SignerGrant]
    notes: str = ""


class SignerRegistry:
    """Loaded signer registry with query methods."""

    def __init__(self, entries: List[SignerEntry]) -> None:
        self._by_fingerprint: Dict[str, SignerEntry] = {}
        self._by_id: Dict[str, SignerEntry] = {}
        for entry in entries:
            self._by_fingerprint[entry.fingerprint] = entry
            self._by_id[entry.signer_id] = entry

    def lookup(
        self, *, signer_id: Optional[str] = None, fingerprint: Optional[str] = None
    ) -> Optional[SignerEntry]:
        """Find a signer by fingerprint (preferred) or signer_id.

        Wildcard fingerprint ("*") in the registry matches any fingerprint.
        """
        if fingerprint and fingerprint in self._by_fingerprint:
            return self._by_fingerprint[fingerprint]
        # Check for wildcard fingerprint entries
        if fingerprint and "*" in self._by_fingerprint:
            entry = self._by_fingerprint["*"]
            if not signer_id or entry.signer_id == signer_id:
                return entry
        if signer_id and signer_id in self._by_id:
            return self._by_id[signer_id]
        return None

    def __len__(self) -> int:
        return len(self._by_fingerprint)


def _parse_grant(raw: Dict[str, Any]) -> SignerGrant:
    return SignerGrant(
        artifact_class=str(raw.get("artifact_class", "*")),
        scope=str(raw.get("scope", "*")),
        purpose=str(raw.get("purpose", "*")),
    )


def _parse_entry(raw: Dict[str, Any]) -> SignerEntry:
    grants = [_parse_grant(g) for g in raw.get("grants", [])]
    return SignerEntry(
        signer_id=str(raw["signer_id"]),
        fingerprint=str(raw["fingerprint"]),
        lifecycle=str(raw.get("lifecycle", "active")),
        grants=grants,
        notes=str(raw.get("notes", "")),
    )


def load_registry(path: Path) -> SignerRegistry:
    """Load signer registry from a YAML file."""
    if yaml is None:
        raise ImportError("PyYAML is required to load signer registry")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Registry file must be a YAML mapping: {path}")
    signers_raw = data.get("signers", [])
    if not isinstance(signers_raw, list):
        raise ValueError(f"'signers' must be a list in: {path}")
    entries = [_parse_entry(s) for s in signers_raw]
    return SignerRegistry(entries)
