"""
Phase 0 Gate: 10 mutated receipts must produce 10 deterministic rejections.

Each test creates a specific mutation and asserts the exact error code.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from assay.integrity import (
    E_CANON_MISMATCH,
    E_DUPLICATE_ID,
    E_MANIFEST_TAMPER,
    E_PACK_OMISSION_DETECTED,
    E_PACK_SIG_INVALID,
    E_SCHEMA_UNKNOWN,
    E_TIMESTAMP_INVALID,
    verify_pack_manifest,
    verify_receipt,
    verify_receipt_pack,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack


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
    store.generate_key("mutant-signer")
    return store


# ---------------------------------------------------------------------------
# 10 mutant tests
# ---------------------------------------------------------------------------


class TestMutant:
    """Each test mutates one thing and verifies deterministic rejection."""

    def test_mutant_01_missing_receipt_id(self):
        """Mutant 1: receipt with no receipt_id."""
        r = _make_receipt()
        del r["receipt_id"]
        errors = verify_receipt(r, index=0)
        assert len(errors) >= 1
        assert errors[0].code == E_SCHEMA_UNKNOWN
        assert errors[0].field == "receipt_id"

    def test_mutant_02_missing_type(self):
        """Mutant 2: receipt with no type field."""
        r = _make_receipt()
        del r["type"]
        errors = verify_receipt(r, index=0)
        assert len(errors) >= 1
        assert any(e.code == E_SCHEMA_UNKNOWN and e.field == "type" for e in errors)

    def test_mutant_03_missing_timestamp(self):
        """Mutant 3: receipt with no timestamp."""
        r = _make_receipt()
        del r["timestamp"]
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_SCHEMA_UNKNOWN and e.field == "timestamp" for e in errors)

    def test_mutant_04_invalid_timestamp(self):
        """Mutant 4: timestamp is garbage."""
        r = _make_receipt(timestamp="not-a-date-at-all")
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_TIMESTAMP_INVALID for e in errors)

    def test_mutant_05_nan_in_field(self):
        """Mutant 5: NaN in a numeric field breaks canonicalization."""
        r = _make_receipt(score=float("nan"))
        errors = verify_receipt(r, index=0)
        assert any(e.code == E_CANON_MISMATCH for e in errors)

    def test_mutant_06_duplicate_receipt_id(self):
        """Mutant 6: two receipts with the same receipt_id."""
        r1 = _make_receipt(receipt_id="dup_001")
        r2 = _make_receipt(receipt_id="dup_001")
        result = verify_receipt_pack([r1, r2])
        assert not result.passed
        assert any(e.code == E_DUPLICATE_ID for e in result.errors)

    def test_mutant_07_receipt_count_mismatch(self, tmp_path, ks):
        """Mutant 7: manifest says 5 receipts but file has 3."""
        receipts = [_make_receipt(seq=i) for i in range(5)]
        pack = ProofPack(
            trace_id="mutant_07",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack07", keystore=ks)

        # Remove 2 receipts from file
        rp = out / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        rp.write_text("\n".join(lines[:3]) + "\n")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        codes = {e.code for e in result.errors}
        assert E_PACK_OMISSION_DETECTED in codes or E_MANIFEST_TAMPER in codes

    def test_mutant_08_file_hash_mismatch(self, tmp_path, ks):
        """Mutant 8: file on disk doesn't match hash in manifest."""
        receipts = [_make_receipt(seq=i) for i in range(3)]
        pack = ProofPack(
            trace_id="mutant_08",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack08", keystore=ks)

        # Corrupt verify_transcript.md
        (out / "verify_transcript.md").write_text("corrupted content")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        assert any(e.code == E_MANIFEST_TAMPER for e in result.errors)

    def test_mutant_09_signature_over_wrong_bytes(self, tmp_path, ks):
        """Mutant 9: manifest content changed after signing."""
        receipts = [_make_receipt(seq=i) for i in range(3)]
        pack = ProofPack(
            trace_id="mutant_09",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack09", keystore=ks)

        # Load, tamper, and re-write manifest (keeping old signature)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        manifest["pack_version"] = "9.9.9"  # tamper
        (out / "pack_manifest.json").write_text(json.dumps(manifest, indent=2))

        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        assert any(e.code == E_PACK_SIG_INVALID for e in result.errors)

    def test_mutant_10_attestation_hash_mismatch(self, tmp_path, ks):
        """Mutant 10: attestation_sha256 doesn't match attestation object."""
        receipts = [_make_receipt(seq=i) for i in range(3)]
        pack = ProofPack(
            trace_id="mutant_10",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack10", keystore=ks)

        manifest = json.loads((out / "pack_manifest.json").read_text())
        # Tamper attestation_sha256 (keep attestation object unchanged)
        manifest["attestation_sha256"] = "0" * 64

        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        has_tamper = any(
            e.code == E_MANIFEST_TAMPER and e.field == "attestation_sha256"
            for e in result.errors
        )
        has_sig = any(e.code == E_PACK_SIG_INVALID for e in result.errors)
        assert has_tamper or has_sig


# ---------------------------------------------------------------------------
# Recomputation mutants (receipt integrity cross-check)
# ---------------------------------------------------------------------------


class TestRecomputationMutants:
    """Verifier must recompute receipt integrity, not trust the attestation."""

    def test_mutant_11_attestation_lies_about_integrity(self, tmp_path, ks):
        """Mutant 11: attestation says PASS but receipts are corrupt."""
        receipts = [_make_receipt(seq=i) for i in range(3)]
        pack = ProofPack(
            trace_id="mutant_11",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack11", keystore=ks)

        # Corrupt a receipt in receipt_pack.jsonl (remove receipt_id)
        rp = out / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        corrupted = json.loads(lines[0])
        del corrupted["receipt_id"]
        lines[0] = json.dumps(corrupted)
        rp.write_text("\n".join(lines) + "\n")

        # Manifest still says receipt_integrity=PASS (it was built before corruption)
        manifest = json.loads((out / "pack_manifest.json").read_text())
        assert manifest["attestation"]["receipt_integrity"] == "PASS"

        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        integrity_errors = [e for e in result.errors if e.field == "receipt_integrity"]
        assert len(integrity_errors) >= 1
        assert integrity_errors[0].code == E_MANIFEST_TAMPER

    def test_mutant_12_head_hash_mismatch(self, tmp_path, ks):
        """Mutant 12: attestation head_hash doesn't match recomputed value."""
        receipts = [_make_receipt(seq=i) for i in range(3)]
        pack = ProofPack(
            trace_id="mutant_12",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack12", keystore=ks)

        # Tamper the last receipt in receipt_pack.jsonl (changes head_hash)
        rp = out / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        last = json.loads(lines[-1])
        last["tampered_field"] = "this changes the canonical hash"
        lines[-1] = json.dumps(last)
        rp.write_text("\n".join(lines) + "\n")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        head_errors = [e for e in result.errors if e.field == "head_hash"]
        assert len(head_errors) >= 1
        assert head_errors[0].code == E_MANIFEST_TAMPER


# ---------------------------------------------------------------------------
# Structural invariant: integrity verifier stays small
# ---------------------------------------------------------------------------

class TestVerifierBudget:
    def test_integrity_verifier_under_500_loc(self):
        """P3 constitutional constraint: integrity.py must stay under 500 LOC."""
        import assay.integrity as mod
        from pathlib import Path

        source_path = Path(mod.__file__)
        line_count = len(source_path.read_text().splitlines())
        assert line_count <= 500, (
            f"integrity.py is {line_count} LOC (limit: 500). "
            f"Move non-core helpers out to stay under budget."
        )
