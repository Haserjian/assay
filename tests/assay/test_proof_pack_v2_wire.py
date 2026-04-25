"""ReceiptV2 production-caller wire test.

Proves the smallest happy-path integration of ReceiptV2 into the canonical
proof-pack producer (`ProofPack._build_into`):

- ``emit_v2_receipts=True`` writes ``unsigned/receipt_pack_v2.jsonl``
- Each line is a v2 envelope (``signatures[]`` + ``verification_bundle``)
- ``digest_valid`` and per-signature ``cryptographically_valid`` both hold
  via ``verify_v2(envelope, key_resolver=...)``
- The v1 5-file kernel is unaffected — ``verify_proof_pack`` still passes
  (v2 sidecar lives outside ``pack_root_sha256``)
- ``emit_v2_receipts=False`` (default) produces no v2 file
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

import pytest

from assay._receipts import verify_v2
from assay.keystore import DEFAULT_SIGNER_ID, AssayKeyStore
from assay.proof_pack import (
    ProofPack,
    get_unsigned_sidecar_dir,
    verify_proof_pack,
)


@pytest.fixture
def tmp_keys(tmp_path):
    return AssayKeyStore(keys_dir=tmp_path / "keys")


def _make_receipt(seq: int) -> dict:
    return {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
        "seq": seq,
        "task": "loan_application_analysis",
        "model_id": "claude-sonnet-4-20250514",
        "input_tokens": 100 + seq,
        "output_tokens": 50 + seq,
    }


def _make_resolver(
    ks: AssayKeyStore, signer_id: str = DEFAULT_SIGNER_ID
) -> Callable[[str, Optional[str]], Optional[bytes]]:
    """Build a key_resolver that returns the matching pubkey bytes."""
    ks.ensure_key(signer_id)
    pubkey_bytes = ks.get_verify_key(signer_id).encode()  # 32-byte raw

    def resolver(sid, _pubkey_sha256=None):
        return pubkey_bytes if sid == signer_id else None

    return resolver


def test_emit_v2_off_by_default_produces_no_sidecar(tmp_path, tmp_keys):
    entries = [_make_receipt(i) for i in range(2)]
    pack = ProofPack(run_id=f"trace_{uuid.uuid4().hex[:8]}", entries=entries)
    out = pack.build(tmp_path / "pack_default", keystore=tmp_keys)

    sidecar = get_unsigned_sidecar_dir(out) / "receipt_pack_v2.jsonl"
    assert not sidecar.exists(), (
        "v2 sidecar must NOT be produced when emit_v2_receipts=False (default)"
    )


def test_emit_v2_writes_signed_envelopes_and_v1_still_verifies(
    tmp_path, tmp_keys
):
    entries = [_make_receipt(i) for i in range(3)]
    pack = ProofPack(
        run_id=f"trace_{uuid.uuid4().hex[:8]}",
        entries=entries,
        emit_v2_receipts=True,
    )
    out = pack.build(tmp_path / "pack_v2", keystore=tmp_keys)

    sidecar = get_unsigned_sidecar_dir(out) / "receipt_pack_v2.jsonl"
    assert sidecar.exists(), (
        "v2 sidecar must be produced when emit_v2_receipts=True"
    )

    lines = [line for line in sidecar.read_text().splitlines() if line.strip()]
    assert len(lines) == len(entries), (
        f"expected {len(entries)} v2 envelopes, got {len(lines)}"
    )

    resolver = _make_resolver(tmp_keys)

    for line in lines:
        env = json.loads(line)
        assert env.get("signatures"), "v2 envelope missing signatures[]"
        assert env.get("verification_bundle"), (
            "v2 envelope missing verification_bundle"
        )
        # Identity preserved from the source v1 entry
        assert env.get("type") == "model_call"
        assert env.get("receipt_id", "").startswith("r_")

        # End-to-end v2 verification
        result = verify_v2(env, key_resolver=resolver)
        assert result.digest_valid, (
            f"digest_valid=False, status={result.digest_status}"
        )
        assert result.signature_results, "no signature_results returned"
        sig = result.signature_results[0]
        assert sig.cryptographically_valid, (
            f"cryptographic verification failed: {sig.error}"
        )
        assert sig.algorithm_acceptable, (
            f"algorithm not acceptable: {sig.algorithm}"
        )

    # v1 5-file kernel still verifies — sidecar lives outside pack_root_sha256
    manifest = json.loads((out / "pack_manifest.json").read_text())
    v1_result = verify_proof_pack(manifest, out, keystore=tmp_keys)
    assert v1_result.passed, (
        f"v1 verification failed after v2 emission: {v1_result.errors}"
    )
