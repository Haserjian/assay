"""
Pack conformance tests — golden minimal specimen.

Loads the golden_minimal pack specimen from tests/contracts/vectors/pack/
and verifies it against the real verify_pack_manifest() pipeline.

This is the first full-pipeline conformance artifact.  A second
implementation (e.g., TypeScript browser verifier) must produce the same
verification result for the same pack files.

Specimen inputs are documented in expected_outputs.json alongside the pack.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from assay.integrity import verify_pack_manifest
from assay._receipts.jcs import canonicalize as jcs_canonicalize

VECTORS_DIR = Path(__file__).parent / "vectors" / "pack"
GOLDEN_DIR = VECTORS_DIR / "golden_minimal"
EXPECTED_FILE = VECTORS_DIR / "expected_outputs.json"


@pytest.fixture(scope="module")
def expected():
    return json.loads(EXPECTED_FILE.read_text())


@pytest.fixture(scope="module")
def manifest():
    return json.loads((GOLDEN_DIR / "pack_manifest.json").read_text())


class TestPackConformanceGolden:
    """Full-pipeline verification of the golden_minimal specimen."""

    def test_verify_pack_manifest_passes(self, manifest, expected):
        """The specimen passes verify_pack_manifest() with no errors."""
        result = verify_pack_manifest(manifest, GOLDEN_DIR, keystore=None)
        assert result.passed is True
        assert len(result.errors) == 0

    def test_receipt_count(self, manifest, expected):
        result = verify_pack_manifest(manifest, GOLDEN_DIR, keystore=None)
        assert result.receipt_count == expected["expected_verification"]["receipt_count"]
        assert manifest["receipt_count_expected"] == expected["expected_verification"]["receipt_count"]

    def test_head_hash(self, manifest, expected):
        result = verify_pack_manifest(manifest, GOLDEN_DIR, keystore=None)
        assert result.head_hash == expected["expected_verification"]["head_hash"]

    def test_attestation_sha256(self, manifest, expected):
        """SHA256(JCS(attestation)) matches manifest field."""
        att_bytes = jcs_canonicalize(manifest["attestation"])
        computed = hashlib.sha256(att_bytes).hexdigest()
        assert computed == manifest["attestation_sha256"]
        assert computed == expected["expected_verification"]["attestation_sha256"]

    def test_d12_invariant(self, manifest, expected):
        """pack_root_sha256 == attestation_sha256 (D12 design)."""
        assert manifest["pack_root_sha256"] == manifest["attestation_sha256"]
        assert expected["expected_verification"]["d12_invariant_holds"] is True

    def test_file_hashes(self, manifest, expected):
        """Every file listed in manifest has correct SHA-256."""
        expected_hashes = expected["expected_file_hashes"]
        for f_entry in manifest["files"]:
            fpath = GOLDEN_DIR / f_entry["path"]
            actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
            assert actual == f_entry["sha256"], f"{f_entry['path']} hash mismatch"
            assert actual == expected_hashes[f_entry["path"]]

    def test_file_sizes(self, manifest):
        """File sizes match manifest bytes field."""
        for f_entry in manifest["files"]:
            fpath = GOLDEN_DIR / f_entry["path"]
            assert fpath.stat().st_size == f_entry["bytes"], f"{f_entry['path']} size mismatch"

    def test_all_expected_files_present(self, manifest):
        """All 5 kernel files exist in the specimen directory."""
        for fname in manifest["expected_files"]:
            assert (GOLDEN_DIR / fname).exists(), f"missing: {fname}"

    def test_detached_signature_parity(self, manifest):
        """pack_signature.sig raw bytes == base64.decode(manifest.signature)."""
        sig_bytes = (GOLDEN_DIR / "pack_signature.sig").read_bytes()
        manifest_sig = base64.b64decode(manifest["signature"])
        assert sig_bytes == manifest_sig
        assert len(sig_bytes) == 64  # Ed25519 signature

    def test_ed25519_verification_standalone(self, manifest):
        """Verify signature using only embedded signer_pubkey — no keystore."""
        from nacl.signing import VerifyKey

        pubkey_bytes = base64.b64decode(manifest["signer_pubkey"])
        vk = VerifyKey(pubkey_bytes)

        # Reconstruct unsigned manifest (strip signature + pack_root_sha256)
        unsigned = {k: v for k, v in manifest.items()
                    if k not in ("signature", "pack_root_sha256")}
        canonical_bytes = jcs_canonicalize(unsigned)
        sig_bytes = base64.b64decode(manifest["signature"])

        # This raises if verification fails
        vk.verify(canonical_bytes, sig_bytes)

    def test_signer_pubkey_sha256(self, manifest, expected):
        """signer_pubkey_sha256 == SHA256(base64.decode(signer_pubkey))."""
        pubkey_bytes = base64.b64decode(manifest["signer_pubkey"])
        computed = hashlib.sha256(pubkey_bytes).hexdigest()
        assert computed == manifest["signer_pubkey_sha256"]
        assert computed == expected["expected_manifest_fields"]["signer_pubkey_sha256"]

    def test_pack_id_matches(self, manifest, expected):
        assert manifest["pack_id"] == expected["expected_manifest_fields"]["pack_id"]

    def test_unsigned_manifest_reconstruction(self, manifest):
        """Unsigned manifest excludes exactly {signature, pack_root_sha256}."""
        unsigned = {k: v for k, v in manifest.items()
                    if k not in ("signature", "pack_root_sha256")}
        assert "signature" not in unsigned
        assert "pack_root_sha256" not in unsigned
        # All other keys preserved
        assert unsigned["pack_id"] == manifest["pack_id"]
        assert unsigned["attestation"] == manifest["attestation"]
        assert unsigned["signer_pubkey"] == manifest["signer_pubkey"]

    def test_receipt_pack_jsonl_structure(self, manifest):
        """Each line in receipt_pack.jsonl is valid JSON with required fields."""
        content = (GOLDEN_DIR / "receipt_pack.jsonl").read_text()
        lines = [l for l in content.strip().split("\n") if l.strip()]
        assert len(lines) == manifest["receipt_count_expected"]
        for i, line in enumerate(lines):
            receipt = json.loads(line)
            assert "receipt_id" in receipt, f"line {i}: missing receipt_id"
            assert "type" in receipt, f"line {i}: missing type"
            assert "timestamp" in receipt, f"line {i}: missing timestamp"

    def test_receipt_lines_are_jcs_canonical(self, manifest):
        """Each JSONL line is already JCS-canonical (round-trip stable)."""
        content = (GOLDEN_DIR / "receipt_pack.jsonl").read_text()
        lines = [l for l in content.strip().split("\n") if l.strip()]
        for i, line in enumerate(lines):
            receipt = json.loads(line)
            canonical = jcs_canonicalize(receipt).decode("utf-8")
            assert canonical == line, f"line {i}: not JCS-canonical"
