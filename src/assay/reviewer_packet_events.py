"""Signed reviewer-packet sidecar events: human attestations and challenges."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from assay._receipts.canonicalize import to_jcs_bytes
from assay.keystore import AssayKeyStore, get_default_keystore
from assay.vendorq_models import now_utc_iso, write_json


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign_payload(
    payload: Dict[str, Any],
    *,
    signer_id: str,
    keystore: AssayKeyStore,
) -> Dict[str, Any]:
    signature = keystore.sign_b64(to_jcs_bytes(payload), signer_id)
    return {
        **payload,
        "signature": signature,
    }


def build_human_attestation(
    *,
    question: str,
    assertion: str,
    attester: str,
    signer_id: Optional[str] = None,
    keystore: Optional[AssayKeyStore] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    ks = keystore or get_default_keystore()
    resolved_signer = signer_id or ks.get_active_signer()
    ks.ensure_key(resolved_signer)
    timestamp = created_at or now_utc_iso()
    attestation_id = f"attest_{_sha256_hex(to_jcs_bytes([question, assertion, attester, timestamp]))[:12]}"
    payload = {
        "artifact_type": "human_attestation",
        "schema_version": "1.0",
        "attestation_id": attestation_id,
        "evidence_type": "HUMAN_ATTESTED",
        "question": question,
        "assertion": assertion,
        "attester": attester,
        "created_at": timestamp,
        "signer": {
            "identity": resolved_signer,
            "fingerprint": ks.signer_fingerprint(resolved_signer),
        },
    }
    return _sign_payload(payload, signer_id=resolved_signer, keystore=ks)


def write_human_attestation(
    pack_dir: Path,
    payload: Dict[str, Any],
    *,
    out_path: Optional[Path] = None,
) -> Path:
    destination = out_path or (Path(pack_dir) / "human_attestations" / f"{payload['attestation_id']}.json")
    write_json(destination, payload)
    return destination


def build_reviewer_challenge(
    *,
    packet_dir: Path,
    reason: str,
    claim_ref: Optional[str] = None,
    signer_id: Optional[str] = None,
    keystore: Optional[AssayKeyStore] = None,
    challenged_at: Optional[str] = None,
) -> Dict[str, Any]:
    ks = keystore or get_default_keystore()
    resolved_signer = signer_id or ks.get_active_signer()
    ks.ensure_key(resolved_signer)
    timestamp = challenged_at or now_utc_iso()
    packet_dir = Path(packet_dir)
    settlement_path = packet_dir / "SETTLEMENT.json"
    manifest_path = packet_dir / "PACKET_MANIFEST.json"
    settlement = json.loads(settlement_path.read_text())
    settlement_sha256 = _sha256_hex(settlement_path.read_bytes())
    manifest_sha256 = _sha256_hex(manifest_path.read_bytes())
    challenge_id = f"challenge_{_sha256_hex(to_jcs_bytes([str(packet_dir), reason, claim_ref or '', timestamp]))[:12]}"
    payload = {
        "artifact_type": "reviewer_packet_challenge",
        "schema_version": "1.0",
        "challenge_id": challenge_id,
        "packet_id": str(settlement.get("packet_id") or packet_dir.name),
        "packet_ref": str(packet_dir),
        "reviewer_packet_manifest_sha256": manifest_sha256,
        "reviewer_packet_settlement_sha256": settlement_sha256,
        "claim_ref": claim_ref,
        "reason": reason,
        "challenged_at": timestamp,
        "signer": {
            "identity": resolved_signer,
            "fingerprint": ks.signer_fingerprint(resolved_signer),
        },
    }
    return _sign_payload(payload, signer_id=resolved_signer, keystore=ks)


def write_reviewer_challenge(
    packet_dir: Path,
    payload: Dict[str, Any],
    *,
    out_path: Optional[Path] = None,
) -> Path:
    destination = out_path or (Path(packet_dir) / "challenges" / f"{payload['challenge_id']}.json")
    write_json(destination, payload)
    return destination


__all__ = [
    "build_human_attestation",
    "write_human_attestation",
    "build_reviewer_challenge",
    "write_reviewer_challenge",
]
