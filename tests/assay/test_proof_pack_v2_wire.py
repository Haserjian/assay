"""ReceiptV2 production-caller wire test.

Proves the smallest happy-path integration of ReceiptV2 into the canonical
proof-pack producer (`ProofPack._build_into`):

- ``emit_v2_receipts=True`` writes ``_unsigned/receipt_pack_v2.jsonl``
- Each line is a v2 envelope (``signatures[]`` + ``verification_bundle``)
- ``digest_valid`` and per-signature ``cryptographically_valid`` both hold
  via ``verify_v2(envelope, key_resolver=...)``
- The v1 5-file kernel is unaffected — ``verify_proof_pack`` still passes
  (v2 sidecar lives outside ``pack_root_sha256``)
- ``emit_v2_receipts=False`` (default) produces no v2 file

Plus pack-binding guarantees (PR #99):

- Each v2 envelope carries an attested ``pack_binding`` dict with
  ``pack_id``, ``source_index``, ``source_receipt_sha256``,
  ``receipt_pack_sha256``, ``pack_root_sha256``.
- ``source_receipt_sha256`` matches sha256 of the corresponding line in
  ``receipt_pack.jsonl``; ``receipt_pack_sha256`` matches sha256 of the
  whole ``receipt_pack.jsonl`` bytes; ``pack_id`` and ``pack_root_sha256``
  match the v1 manifest. This proves "this v2 line is the v2
  representation of THIS exact v1 line in THIS exact pack."
- Tampering with the source v1 line invalidates the recomputed
  ``source_receipt_sha256`` against the attested binding (verifier
  detects the divergence).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
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


def _v1_lines(pack_dir: Path) -> list[str]:
    """Return non-empty lines of receipt_pack.jsonl (in order)."""
    raw = (pack_dir / "receipt_pack.jsonl").read_text()
    return [ln for ln in raw.splitlines() if ln.strip()]


def _v2_envelopes(pack_dir: Path) -> list[dict]:
    """Return parsed envelopes from _unsigned/receipt_pack_v2.jsonl (in order)."""
    sidecar = get_unsigned_sidecar_dir(pack_dir) / "receipt_pack_v2.jsonl"
    raw = sidecar.read_text()
    return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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

    envelopes = _v2_envelopes(out)
    assert len(envelopes) == len(entries), (
        f"expected {len(entries)} v2 envelopes, got {len(envelopes)}"
    )

    resolver = _make_resolver(tmp_keys)

    for env in envelopes:
        assert env.get("signatures"), "v2 envelope missing signatures[]"
        assert env.get("verification_bundle"), (
            "v2 envelope missing verification_bundle"
        )
        # Identity preserved from the source v1 entry
        assert env.get("type") == "model_call"
        assert env.get("receipt_id", "").startswith("r_")

        # pack_binding present and well-formed
        binding = env.get("pack_binding")
        assert binding, "v2 envelope missing pack_binding"
        for field in (
            "pack_id",
            "source_index",
            "source_receipt_sha256",
            "receipt_pack_sha256",
            "pack_root_sha256",
        ):
            assert field in binding, f"pack_binding missing {field!r}"

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


def test_v2_pack_binding_maps_back_to_v1_lines_by_index_and_sha256(
    tmp_path, tmp_keys
):
    """Each v2 envelope's pack_binding must point exactly back to the v1
    line it represents, and to the v1 pack as a whole."""
    entries = [_make_receipt(i) for i in range(4)]
    pack = ProofPack(
        run_id=f"trace_{uuid.uuid4().hex[:8]}",
        entries=entries,
        emit_v2_receipts=True,
    )
    out = pack.build(tmp_path / "pack_binding", keystore=tmp_keys)

    v1_lines = _v1_lines(out)
    envelopes = _v2_envelopes(out)
    manifest = json.loads((out / "pack_manifest.json").read_text())
    receipt_pack_bytes = (out / "receipt_pack.jsonl").read_bytes()

    expected_pack_id = manifest["pack_id"]
    expected_pack_root = manifest["pack_root_sha256"]
    expected_receipt_pack_sha = _sha256_hex(receipt_pack_bytes)

    assert len(envelopes) == len(v1_lines), (
        "v2 envelope count must equal v1 line count"
    )

    for idx, env in enumerate(envelopes):
        binding = env["pack_binding"]
        assert binding["pack_id"] == expected_pack_id, (
            "pack_binding.pack_id mismatch with v1 manifest"
        )
        assert binding["pack_root_sha256"] == expected_pack_root, (
            "pack_binding.pack_root_sha256 mismatch with v1 manifest"
        )
        assert binding["receipt_pack_sha256"] == expected_receipt_pack_sha, (
            "pack_binding.receipt_pack_sha256 mismatch with v1 receipt_pack.jsonl"
        )
        assert binding["source_index"] == idx, (
            f"pack_binding.source_index expected {idx}, got {binding['source_index']}"
        )
        # The exact v1 line at source_index hashes to source_receipt_sha256
        v1_line_bytes = v1_lines[idx].encode("utf-8")
        assert binding["source_receipt_sha256"] == _sha256_hex(v1_line_bytes), (
            f"pack_binding.source_receipt_sha256 does not match sha256 of "
            f"receipt_pack.jsonl line {idx}"
        )


def test_mutating_pack_binding_source_index_invalidates_v2_signature(
    tmp_path, tmp_keys
):
    """pack_binding is attested. Mutating any binding field after the
    envelope is sealed must break ``verify_v2()`` — the doctrine claim
    that pack_binding is covered by bundle_digest, not just metadata."""
    entries = [_make_receipt(i) for i in range(3)]
    pack = ProofPack(
        run_id=f"trace_{uuid.uuid4().hex[:8]}",
        entries=entries,
        emit_v2_receipts=True,
    )
    out = pack.build(tmp_path / "pack_attest_binding", keystore=tmp_keys)

    envelopes = _v2_envelopes(out)
    target = envelopes[0]
    original_index = target["pack_binding"]["source_index"]

    # Sanity: pre-mutation, verify_v2 is happy.
    resolver = _make_resolver(tmp_keys)
    pre = verify_v2(target, key_resolver=resolver)
    assert pre.digest_valid, (
        f"pre-mutation baseline failed: status={pre.digest_status}"
    )

    # Mutate an attested binding field (lift index 0 -> 99 — out of range).
    target["pack_binding"]["source_index"] = original_index + 99

    # Recomputed digest must not match the stored one.
    post = verify_v2(target, key_resolver=resolver)
    assert not post.digest_valid, (
        "Mutating pack_binding.source_index did NOT invalidate the v2 "
        "envelope. pack_binding is supposed to be attested (covered by "
        "bundle_digest); the recomputed digest must diverge from the stored one."
    )
    assert post.digest_status == "mismatch", (
        f"expected digest_status='mismatch', got {post.digest_status!r}"
    )


def test_cli_proof_pack_threads_emit_v2_receipts_flag_to_builder(
    monkeypatch, tmp_path
):
    """The CLI ``assay proof-pack --emit-v2-receipts`` reaches the producer.

    Spy on ``build_proof_pack`` to confirm the flag threads through end to end
    without exercising the on-disk store (which would mutate ``~/.assay/``).
    """
    from typer.testing import CliRunner

    from assay.commands import assay_app

    captured: dict = {}

    def spy_build_proof_pack(trace_id, **kwargs):
        captured["trace_id"] = trace_id
        captured.update(kwargs)
        out = kwargs.get("output_dir") or (tmp_path / f"proof_pack_{trace_id}")
        out.mkdir(parents=True, exist_ok=True)
        # CLI handler reads pack_manifest.json after build returns.
        (out / "pack_manifest.json").write_text(
            json.dumps(
                {
                    "pack_id": "fake_pack_for_cli_test",
                    "attestation": {
                        "pack_id": "fake_pack_for_cli_test",
                        "n_receipts": 0,
                    },
                }
            )
        )
        return out

    monkeypatch.setattr("assay.proof_pack.build_proof_pack", spy_build_proof_pack)

    runner = CliRunner()
    result = runner.invoke(
        assay_app,
        [
            "proof-pack",
            "fake_trace_for_cli_test",
            "--output",
            str(tmp_path / "out"),
            "--emit-v2-receipts",
        ],
    )

    assert result.exit_code == 0, (
        f"CLI exited non-zero: {result.exit_code}\n"
        f"stdout: {result.stdout}\n"
        f"exception: {result.exception}"
    )
    assert captured.get("emit_v2_receipts") is True, (
        f"CLI did not thread --emit-v2-receipts to build_proof_pack; "
        f"captured kwargs: {captured}"
    )


def test_tampering_v1_source_line_breaks_pack_binding_check(
    tmp_path, tmp_keys
):
    """If a verifier reads the v1 file and sees a different line at
    source_index than what the v2 envelope's binding attested, the
    binding check must fail."""
    entries = [_make_receipt(i) for i in range(3)]
    pack = ProofPack(
        run_id=f"trace_{uuid.uuid4().hex[:8]}",
        entries=entries,
        emit_v2_receipts=True,
    )
    out = pack.build(tmp_path / "pack_tamper", keystore=tmp_keys)

    envelopes = _v2_envelopes(out)
    target_idx = 1
    target_envelope = envelopes[target_idx]
    attested_sha = target_envelope["pack_binding"]["source_receipt_sha256"]

    # Sanity: pre-tamper, the binding holds.
    v1_lines_before = _v1_lines(out)
    pre_tamper_sha = _sha256_hex(v1_lines_before[target_idx].encode("utf-8"))
    assert pre_tamper_sha == attested_sha, (
        "pre-tamper baseline failed: binding was already broken"
    )

    # Tamper: rewrite receipt_pack.jsonl with the target line modified.
    tampered_lines = list(v1_lines_before)
    tampered_obj = json.loads(tampered_lines[target_idx])
    tampered_obj["input_tokens"] = 999_999
    # Re-serialize without canonicalization — adversary need not be polite.
    tampered_lines[target_idx] = json.dumps(tampered_obj, sort_keys=True)
    (out / "receipt_pack.jsonl").write_text(
        "\n".join(tampered_lines) + "\n"
    )

    # Post-tamper, the binding check fails.
    v1_lines_after = _v1_lines(out)
    post_tamper_sha = _sha256_hex(v1_lines_after[target_idx].encode("utf-8"))
    assert post_tamper_sha != attested_sha, (
        "tamper went undetected: post-tamper sha256 still matches the "
        "attested source_receipt_sha256 in the v2 envelope"
    )

    # And the v2 envelope itself is still cryptographically valid (its
    # own signature covers the original binding) — the binding check is
    # the discriminator, not the v2 signature.
    resolver = _make_resolver(tmp_keys)
    result = verify_v2(target_envelope, key_resolver=resolver)
    assert result.digest_valid, (
        "v2 envelope's own digest must remain valid under tamper of the "
        "external v1 file (the envelope was not modified)"
    )
