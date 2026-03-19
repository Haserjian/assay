"""Bootstrap helpers for the first real ci-org rollout in CI.

This module does two narrow jobs:
1. import an organization-controlled signer into the local Assay keystore
2. write a temporary trust-policy overlay that grants that signer ci-org authority

The overlay is intentionally ephemeral. It lets CI enforce a concrete `ci_gate`
path before a real org fingerprint is pinned into the repo's committed registry.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey, VerifyKey

from assay.keystore import AssayKeyStore, _validate_signer_id, get_default_keystore

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass(frozen=True)
class CiOrgBootstrapResult:
    signer_id: str
    fingerprint: str
    policy_dir: Path


def _decode_pubkey(pub_b64: str) -> tuple[bytes, str]:
    try:
        pub_bytes = base64.b64decode(pub_b64.strip(), validate=True)
    except Exception as exc:  # pragma: no cover - exercised via caller
        raise ValueError(f"invalid public key base64: {exc}") from exc
    try:
        VerifyKey(pub_bytes)
    except Exception as exc:  # pragma: no cover - exercised via caller
        raise ValueError(f"invalid Ed25519 public key: {exc}") from exc
    return pub_bytes, hashlib.sha256(pub_bytes).hexdigest()


def _decode_private_key(key_b64: str, *, pub_bytes: bytes) -> bytes:
    try:
        key_bytes = base64.b64decode(key_b64.strip(), validate=True)
    except Exception as exc:  # pragma: no cover - exercised via caller
        raise ValueError(f"invalid private key base64: {exc}") from exc
    try:
        signing_key = SigningKey(key_bytes)
    except Exception as exc:  # pragma: no cover - exercised via caller
        raise ValueError(f"invalid Ed25519 private key: {exc}") from exc
    if signing_key.verify_key.encode() != pub_bytes:
        raise ValueError("private key does not match public key")
    return key_bytes


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(data)
    tmp_path.chmod(mode)
    os.replace(str(tmp_path), str(path))


def import_ci_org_signer(
    *,
    signer_id: str,
    pub_b64: str,
    key_b64: str,
    expected_fingerprint: Optional[str] = None,
    keystore: Optional[AssayKeyStore] = None,
) -> str:
    """Import a private ci-org signer into the local keystore and set it active."""
    normalized_signer_id = _validate_signer_id(signer_id)
    ks = keystore or get_default_keystore()

    pub_bytes, fingerprint = _decode_pubkey(pub_b64)
    key_bytes = _decode_private_key(key_b64, pub_bytes=pub_bytes)

    if expected_fingerprint and fingerprint != expected_fingerprint:
        raise ValueError(
            f"fingerprint mismatch for {normalized_signer_id}: "
            f"expected {expected_fingerprint}, got {fingerprint}"
        )

    key_path = ks._key_path(normalized_signer_id)
    pub_path = ks._pub_path(normalized_signer_id)

    if key_path.exists() or pub_path.exists():
        if not ks.has_key(normalized_signer_id):
            raise ValueError(
                f"partial signer state already exists for {normalized_signer_id}; "
                "delete the partial files before bootstrapping"
            )
        existing_fingerprint = ks.signer_fingerprint(normalized_signer_id)
        if existing_fingerprint != fingerprint:
            raise ValueError(
                f"existing signer {normalized_signer_id} has fingerprint "
                f"{existing_fingerprint}, expected {fingerprint}"
            )
    else:
        _atomic_write(key_path, key_bytes, mode=0o600)
        _atomic_write(pub_path, pub_bytes, mode=0o644)

    ks.set_active_signer(normalized_signer_id)
    return fingerprint


def write_ci_org_policy_overlay(
    *,
    policy_dir: Path,
    output_dir: Path,
    signer_id: str,
    fingerprint: str,
    notes: Optional[str] = None,
) -> Path:
    """Copy trust policy files and inject one authorized ci-org signer entry."""
    if yaml is None:
        raise ImportError("PyYAML is required to write ci-org policy overlay")

    signers_path = policy_dir / "signers.yaml"
    acceptance_path = policy_dir / "acceptance.yaml"
    if not signers_path.exists():
        raise FileNotFoundError(f"missing signer registry: {signers_path}")
    if not acceptance_path.exists():
        raise FileNotFoundError(f"missing acceptance matrix: {acceptance_path}")

    if output_dir.exists():
        shutil.rmtree(output_dir)
    shutil.copytree(policy_dir, output_dir)

    data = yaml.safe_load((output_dir / "signers.yaml").read_text(encoding="utf-8"))
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("signers.yaml must contain a YAML mapping")

    signers = data.setdefault("signers", [])
    if not isinstance(signers, list):
        raise ValueError("signers.yaml 'signers' key must be a list")

    entry = {
        "signer_id": _validate_signer_id(signer_id),
        "signer_class": "ci-org",
        "fingerprint": fingerprint,
        "lifecycle": "active",
        "grants": [{"artifact_class": "proof_pack", "purpose": "*"}],
        "notes": notes or "Runtime-injected ci-org signer for CI trust enforcement.",
    }

    filtered = []
    for raw in signers:
        if isinstance(raw, dict):
            if raw.get("signer_id") == entry["signer_id"]:
                continue
            if raw.get("fingerprint") == entry["fingerprint"]:
                continue
        filtered.append(raw)
    filtered.append(entry)
    data["signers"] = filtered

    rendered = yaml.safe_dump(data, sort_keys=False)
    (output_dir / "signers.yaml").write_text(rendered, encoding="utf-8")
    return output_dir


def bootstrap_ci_org_signer(
    *,
    policy_dir: Path,
    output_dir: Path,
    signer_id: str,
    pub_b64: str,
    key_b64: str,
    expected_fingerprint: Optional[str] = None,
    notes: Optional[str] = None,
    keystore: Optional[AssayKeyStore] = None,
) -> CiOrgBootstrapResult:
    """Import the signer and create a temporary trust overlay that authorizes it."""
    fingerprint = import_ci_org_signer(
        signer_id=signer_id,
        pub_b64=pub_b64,
        key_b64=key_b64,
        expected_fingerprint=expected_fingerprint,
        keystore=keystore,
    )
    overlay_dir = write_ci_org_policy_overlay(
        policy_dir=policy_dir,
        output_dir=output_dir,
        signer_id=signer_id,
        fingerprint=fingerprint,
        notes=notes,
    )
    return CiOrgBootstrapResult(
        signer_id=signer_id,
        fingerprint=fingerprint,
        policy_dir=overlay_dir,
    )


def build_ci_smoke_pack(
    *,
    output_dir: Path,
    signer_id: Optional[str] = None,
    keystore: Optional[AssayKeyStore] = None,
) -> Path:
    """Build a minimal proof pack suitable for ci-org trust verification."""
    from datetime import datetime, timezone

    from assay.claim_verifier import ClaimSpec
    from assay.proof_pack import ProofPack

    ks = keystore or get_default_keystore()
    effective_signer = signer_id or ks.get_active_signer()
    if not ks.has_key(effective_signer):
        raise ValueError(
            f"signer {effective_signer!r} is not available in the active keystore"
        )

    timestamp_base = datetime.now(timezone.utc)
    receipts = [
        {
            "receipt_id": "ci_org_model_001",
            "type": "model_call",
            "timestamp": timestamp_base.isoformat(),
            "schema_version": "3.0",
            "seq": 0,
            "model_id": "ci-org-smoke-model",
            "provider": "assay",
            "finish_reason": "stop",
        },
        {
            "receipt_id": "ci_org_guardian_001",
            "type": "guardian_verdict",
            "timestamp": timestamp_base.isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "verdict": "allow",
            "action": "ci_org_smoke",
            "reason": "CI org smoke pack is policy compliant",
        },
    ]
    claims = [
        ClaimSpec(
            claim_id="has_model_calls",
            description="At least one model_call receipt",
            check="receipt_type_present",
            params={"receipt_type": "model_call"},
        ),
        ClaimSpec(
            claim_id="guardian_enforced",
            description="Guardian verdict was issued",
            check="receipt_type_present",
            params={"receipt_type": "guardian_verdict"},
        ),
    ]

    if output_dir.exists():
        shutil.rmtree(output_dir)

    pack = ProofPack(
        run_id="ci-org-smoke",
        entries=receipts,
        signer_id=effective_signer,
        claims=claims,
        mode="enforced",
    )
    return pack.build(output_dir, keystore=ks)


__all__ = [
    "CiOrgBootstrapResult",
    "bootstrap_ci_org_signer",
    "build_ci_smoke_pack",
    "import_ci_org_signer",
    "write_ci_org_policy_overlay",
]
