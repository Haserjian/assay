"""Tamper matrix: mutate each proof-pack file and assert detection.

For every file in the 5-file kernel, we:
  1. Build a valid pack
  2. Corrupt exactly one file (one byte flip, truncation, or deletion)
  3. Assert verify-pack catches it with the expected error code

This is the core security guarantee: any single-byte change in any file
must be detected.
"""
from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay.claim_verifier import ClaimSpec
from assay.integrity import (
    E_MANIFEST_TAMPER,
    E_PACK_OMISSION_DETECTED,
    E_PACK_SIG_INVALID,
    verify_pack_manifest,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


@pytest.fixture
def ks(tmp_path):
    store = AssayKeyStore(keys_dir=tmp_path / "keys")
    store.generate_key("tamper-signer")
    return store


@pytest.fixture
def valid_pack(tmp_path, ks):
    """Build a valid proof pack and return (pack_dir, keystore)."""
    receipts = [_make_receipt(seq=i) for i in range(3)]
    claims = [
        ClaimSpec(
            claim_id="has_model_calls",
            description="At least one model_call",
            check="receipt_type_present",
            params={"receipt_type": "model_call"},
        ),
    ]
    pack = ProofPack(
        run_id="tamper-test",
        entries=receipts,
        signer_id="tamper-signer",
        claims=claims,
        mode="shadow",
    )
    out = pack.build(tmp_path / "pack", keystore=ks)
    return out, ks


def _copy_pack(pack_dir: Path, dest: Path) -> Path:
    """Copy a pack directory to a new location."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(pack_dir, dest)
    return dest


def _flip_byte(path: Path, offset: int = -1):
    """Flip one byte in a file. Default: last byte."""
    data = bytearray(path.read_bytes())
    if not data:
        return
    idx = offset if offset >= 0 else len(data) + offset
    data[idx] = (data[idx] + 1) % 256
    path.write_bytes(bytes(data))


def _verify(pack_dir: Path, ks: AssayKeyStore):
    """Load manifest and run verification, return result."""
    manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
    return verify_pack_manifest(manifest, pack_dir, ks)


# ---------------------------------------------------------------------------
# Hash-covered files: receipt_pack.jsonl, verify_report.json, verify_transcript.md
# ---------------------------------------------------------------------------

HASH_COVERED_FILES = [
    "receipt_pack.jsonl",
    "verify_report.json",
    "verify_transcript.md",
]


class TestHashCoveredFileTampering:
    """Mutating any hash-covered file must produce E_MANIFEST_TAMPER."""

    @pytest.mark.parametrize("filename", HASH_COVERED_FILES)
    def test_one_byte_flip(self, valid_pack, tmp_path, filename):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        _flip_byte(corrupt / filename)
        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors), (
            f"Expected E_MANIFEST_TAMPER for {filename}, got: "
            f"{[e.code for e in result.errors]}"
        )

    @pytest.mark.parametrize("filename", HASH_COVERED_FILES)
    def test_append_content(self, valid_pack, tmp_path, filename):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        path = corrupt / filename
        if filename == "receipt_pack.jsonl":
            # Append a valid JSON line to avoid parse crash
            path.write_bytes(path.read_bytes() + b'{"extra":"tampered"}\n')
        else:
            path.write_bytes(path.read_bytes() + b"X")
        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors)

    @pytest.mark.parametrize("filename", HASH_COVERED_FILES)
    def test_truncate(self, valid_pack, tmp_path, filename):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        path = corrupt / filename
        if filename == "receipt_pack.jsonl":
            # Remove last line (preserves JSON validity)
            lines = path.read_text().strip().split("\n")
            path.write_text("\n".join(lines[:-1]) + "\n")
        else:
            data = path.read_bytes()
            path.write_bytes(data[: len(data) // 2])
        result = _verify(corrupt, ks)
        assert not result.passed
        codes = {e.code for e in result.errors}
        assert E_MANIFEST_TAMPER in codes or E_PACK_SIG_INVALID in codes or E_PACK_OMISSION_DETECTED in codes

    @pytest.mark.parametrize("filename", HASH_COVERED_FILES)
    def test_empty_file(self, valid_pack, tmp_path, filename):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        (corrupt / filename).write_bytes(b"")
        result = _verify(corrupt, ks)
        assert not result.passed


class TestManifestTampering:
    """Mutating pack_manifest.json invalidates the signature."""

    def test_flip_byte_in_manifest(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        manifest_path = corrupt / "pack_manifest.json"
        data = json.loads(manifest_path.read_text())
        # Mutate a field
        data["receipt_count_expected"] = 999
        manifest_path.write_text(json.dumps(data))
        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)

    def test_remove_attestation(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        manifest_path = corrupt / "pack_manifest.json"
        data = json.loads(manifest_path.read_text())
        del data["attestation"]
        manifest_path.write_text(json.dumps(data))
        result = _verify(corrupt, ks)
        assert not result.passed

    def test_swap_file_hash(self, valid_pack, tmp_path):
        """Swapping two file hashes in manifest invalidates signature."""
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        manifest_path = corrupt / "pack_manifest.json"
        data = json.loads(manifest_path.read_text())
        files = data.get("files", [])
        if len(files) >= 2:
            files[0]["sha256"], files[1]["sha256"] = files[1]["sha256"], files[0]["sha256"]
            manifest_path.write_text(json.dumps(data))
            result = _verify(corrupt, ks)
            assert not result.passed


class TestSignatureTampering:
    """Mutating pack_signature.sig must be detected."""

    def test_corrupt_signature(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        sig_path = corrupt / "pack_signature.sig"
        sig_path.write_bytes(b"corrupted-signature-data")
        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)

    def test_zero_byte_signature(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        (corrupt / "pack_signature.sig").write_bytes(b"")
        result = _verify(corrupt, ks)
        assert not result.passed

    def test_flip_one_bit_in_signature(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        sig_path = corrupt / "pack_signature.sig"
        data = bytearray(sig_path.read_bytes())
        if data:
            data[0] = (data[0] + 1) % 256
            sig_path.write_bytes(bytes(data))
        result = _verify(corrupt, ks)
        assert not result.passed


class TestFileDeletion:
    """Deleting any kernel file must be detected."""

    @pytest.mark.parametrize("filename", HASH_COVERED_FILES)
    def test_delete_hash_covered_file(self, valid_pack, tmp_path, filename):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        (corrupt / filename).unlink()
        result = _verify(corrupt, ks)
        assert not result.passed

    def test_delete_signature_file(self, valid_pack, tmp_path):
        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")
        (corrupt / "pack_signature.sig").unlink()
        result = _verify(corrupt, ks)
        assert not result.passed


class TestCrossFileTampering:
    """Coordinated tampering across files must still be detected."""

    def test_replace_receipts_and_rehash_without_resigning(self, valid_pack, tmp_path):
        """Replace receipts, update manifest hashes, but don't re-sign.
        Should fail because the manifest signature is now invalid."""
        import hashlib

        pack_dir, ks = valid_pack
        corrupt = _copy_pack(pack_dir, tmp_path / "corrupt")

        # Write completely new receipt content
        new_receipt = json.dumps({
            "receipt_id": "r_fake_001",
            "type": "model_call",
            "timestamp": "2026-01-01T00:00:00Z",
            "schema_version": "3.0",
        }) + "\n"
        receipt_path = corrupt / "receipt_pack.jsonl"
        receipt_path.write_text(new_receipt)

        # Update the manifest hash for receipt_pack.jsonl
        manifest_path = corrupt / "pack_manifest.json"
        data = json.loads(manifest_path.read_text())
        new_hash = hashlib.sha256(new_receipt.encode()).hexdigest()
        for entry in data.get("files", []):
            if entry["path"] == "receipt_pack.jsonl":
                entry["sha256"] = new_hash
                break
        manifest_path.write_text(json.dumps(data))

        # Signature is still the old one -> must fail
        result = _verify(corrupt, ks)
        assert not result.passed
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)
