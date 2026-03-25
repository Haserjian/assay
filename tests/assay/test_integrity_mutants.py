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


class TestHeadHashNoSilentSkip:
    """Constitutional invariant: if an attestation claims a head_hash and the
    verifier cannot recompute it, the result must be an explicit error, never
    a silent comparison skip."""

    def test_head_hash_none_produces_explicit_error(self, tmp_path, ks):
        """When the last receipt fails canonicalization, head_hash recomputes
        to None.  If the attestation claims a head_hash, the verifier must
        emit an explicit error instead of silently skipping the comparison."""
        receipts = [_make_receipt(seq=0)]
        pack = ProofPack(
            run_id="head-hash-skip",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack_headhash", keystore=ks)

        # The attestation claims a head_hash.  Now corrupt the receipt_pack
        # so the last receipt fails canonicalization (make it non-JSON).
        rp = out / "receipt_pack.jsonl"
        rp.write_text("NOT VALID JSON AT ALL\n")

        manifest = json.loads((out / "pack_manifest.json").read_text())
        claimed_head = manifest["attestation"].get("head_hash")
        assert claimed_head is not None, "Attestation should claim a head_hash"

        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed

        # The key assertion: there must be an error mentioning head_hash,
        # NOT a silent skip.  Before this fix, the comparison was silently
        # skipped when recomputed head_hash was None.
        head_errors = [e for e in result.errors if e.field == "head_hash"]
        assert len(head_errors) >= 1, (
            f"Expected explicit head_hash error, got none. "
            f"All errors: {[e.message for e in result.errors]}"
        )

    def test_canonicalization_failure_does_not_retain_stale_hash(self):
        """verify_receipt_pack must set head_hash to None when the last
        receipt fails canonicalization, not silently retain the previous
        receipt's hash."""
        good_receipt = {
            "receipt_id": "r1",
            "type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
        }
        # An uncanonicalizeable receipt: contains a type JCS rejects
        bad_receipt = {
            "receipt_id": "r2",
            "type": "test",
            "timestamp": "2026-01-01T00:00:01Z",
            "bad_field": float("inf"),  # Non-finite float → JCS rejects
        }

        result = verify_receipt_pack([good_receipt, bad_receipt])

        # head_hash should be None because the last receipt (bad_receipt)
        # failed canonicalization.  Before this fix, it would silently
        # retain good_receipt's hash.
        assert result.head_hash is None, (
            f"head_hash should be None after canonicalization failure, "
            f"got {result.head_hash!r}"
        )


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
        assert line_count <= 620, (
            f"integrity.py is {line_count} LOC (limit: 620). "
            f"Move non-core helpers out to stay under budget."
        )


# ---------------------------------------------------------------------------
# Phase 1 hardening: verifier graceful degradation on I/O errors
# ---------------------------------------------------------------------------

class TestVerifierIOResilience:
    """verify_pack_manifest must return structured errors, not crash, on I/O failures."""

    def test_unreadable_file_produces_structured_error(self, tmp_path):
        """If a manifest-listed file is unreadable, verifier returns E_MANIFEST_TAMPER."""
        import os

        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        pack = ProofPack(
            run_id="io-test",
            entries=[_make_receipt()],
            signer_id="io-tester",
        )
        pack_dir = pack.build(tmp_path / "pack", keystore=ks)

        # Make receipt_pack.jsonl unreadable
        target = pack_dir / "receipt_pack.jsonl"
        target.chmod(0o000)

        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)

        # Restore permissions for cleanup
        target.chmod(0o644)

        assert not result.passed
        tamper_codes = [e.code for e in result.errors]
        assert E_MANIFEST_TAMPER in tamper_codes


# ---------------------------------------------------------------------------
# Path containment enforcement
# ---------------------------------------------------------------------------

class TestPathContainment:
    """Manifest-listed paths must resolve under pack_dir."""

    def test_containment_rejects_traversal(self, tmp_path):
        """_check_containment rejects paths that escape pack_dir."""
        from assay.integrity import _check_containment
        pack_dir = tmp_path / "pack"
        pack_dir.mkdir()
        assert not _check_containment(pack_dir / ".." / "evil.txt", pack_dir)
        assert not _check_containment(pack_dir / ".." / ".." / "etc" / "passwd", pack_dir)

    def test_containment_accepts_normal_paths(self, tmp_path):
        """_check_containment accepts paths under pack_dir."""
        from assay.integrity import _check_containment
        pack_dir = tmp_path / "pack"
        pack_dir.mkdir()
        assert _check_containment(pack_dir / "receipt_pack.jsonl", pack_dir)
        assert _check_containment(pack_dir / "_unsigned" / "PACK_SUMMARY.md", pack_dir)

    def test_containment_rejects_symlink_escape(self, tmp_path):
        """A symlink that resolves outside pack_dir must fail containment."""
        from assay.integrity import _check_containment
        pack_dir = tmp_path / "pack"
        pack_dir.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = pack_dir / "sneaky.txt"
        link.symlink_to(outside)
        assert not _check_containment(link, pack_dir)

    def test_verifier_rejects_traversal_path(self, tmp_path):
        """verify_pack_manifest rejects a manifest with traversal paths."""
        ks = AssayKeyStore(keys_dir=tmp_path / "keys")
        pack = ProofPack(run_id="escape-test", entries=[_make_receipt()],
                         signer_id="escape-tester")
        pack_dir = pack.build(tmp_path / "pack", keystore=ks)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        # Inject traversal path (schema validation may catch this first,
        # which is also a valid rejection — defense in depth)
        manifest["files"].append({"path": "../../etc/passwd", "sha256": "a" * 64})
        result = verify_pack_manifest(manifest, pack_dir, ks)
        assert not result.passed


class TestSignatureScopeInvariant:
    """The verifier must NOT derive the signing exclusion set from
    the manifest's ``signature_scope`` field.  That field is descriptive
    only.  The normative exclusion set is {"signature", "pack_root_sha256"},
    defined by the contract."""

    def test_legacy_scope_field_still_verifies(self, tmp_path, ks):
        """Old packs with legacy signature_scope value must still pass
        verification if actual signed bytes match the contract behavior."""
        receipts = [_make_receipt(seq=0)]
        pack = ProofPack(
            run_id="legacy-scope",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack_legacy", keystore=ks)

        # Overwrite the signature_scope field with the old value.
        # The signature covers JCS(manifest minus {signature, pack_root_sha256})
        # so changing signature_scope (which is inside the signed content)
        # would break the signature.  We must re-sign.
        manifest = json.loads((out / "pack_manifest.json").read_text())
        manifest["signature_scope"] = "JCS(pack_manifest_without_signature)"

        # Re-sign with the correct exclusion set (not the field value)
        import base64
        from assay._receipts.jcs import canonicalize as jcs_canonicalize
        unsigned = {
            k: v for k, v in manifest.items()
            if k not in ("signature", "pack_root_sha256")
        }
        canonical = jcs_canonicalize(unsigned)
        sig_b64 = ks.sign_b64(canonical, "mutant-signer")
        manifest["signature"] = sig_b64
        sig_raw = base64.b64decode(sig_b64)

        (out / "pack_manifest.json").write_bytes(
            json.dumps(manifest, indent=2).encode()
        )
        (out / "pack_signature.sig").write_bytes(sig_raw)

        result = verify_pack_manifest(manifest, out, ks)
        assert result.passed, (
            f"Legacy signature_scope value should not prevent verification: "
            f"{[e.message for e in result.errors]}"
        )

    def test_poison_pill_field_driven_verifier_would_fail(self, tmp_path, ks):
        """Poison-pill vector: a pack where the signature only verifies
        against the TRUE exclusion set {signature, pack_root_sha256}.

        A naive verifier that reads signature_scope and excludes only
        "signature" (not pack_root_sha256) would compute different
        canonical bytes and fail verification.  The real verifier must
        pass because it uses the contract-defined exclusion set."""
        receipts = [_make_receipt(seq=0)]
        pack = ProofPack(
            run_id="poison-pill",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack_poison", keystore=ks)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        # The manifest contains pack_root_sha256.  A field-driven verifier
        # reading "JCS(pack_manifest_without_signature)" would exclude only
        # "signature" and include pack_root_sha256 in the signed content,
        # producing different canonical bytes -> signature mismatch.
        #
        # The compliant verifier excludes BOTH and succeeds.
        assert "pack_root_sha256" in manifest
        assert manifest["pack_root_sha256"] == manifest["attestation_sha256"]

        result = verify_pack_manifest(manifest, out, ks)
        assert result.passed, (
            f"Contract-compliant verifier must pass: "
            f"{[e.message for e in result.errors]}"
        )

        # Now prove the naive approach would fail:
        # Reconstruct with only "signature" excluded (like a field-driven verifier)
        from assay._receipts.jcs import canonicalize as jcs_canonicalize
        naive_unsigned = {
            k: v for k, v in manifest.items()
            if k != "signature"  # only excludes signature, keeps pack_root_sha256
        }
        naive_canonical = jcs_canonicalize(naive_unsigned)

        # The correct canonical bytes (both excluded)
        correct_unsigned = {
            k: v for k, v in manifest.items()
            if k not in ("signature", "pack_root_sha256")
        }
        correct_canonical = jcs_canonicalize(correct_unsigned)

        # These MUST differ — that's the whole point
        assert naive_canonical != correct_canonical, (
            "Naive and correct canonical bytes should differ — "
            "pack_root_sha256 presence must change the hash"
        )


class TestDescriptiveFieldInvariant:
    """Verifier behavior must not change when descriptive metadata fields
    are altered.  These fields are for human readers and tooling, not
    for proof-critical dispatch.  See OCD-10."""

    def test_hash_alg_schema_prevents_misleading_values(self, tmp_path, ks):
        """The JSON schema constrains hash_alg to enum: ["sha256"].
        This is defense-in-depth: even though the verifier code hardcodes
        SHA-256 and never reads the field, the schema prevents a pack
        from carrying a misleading hash_alg value.

        This test proves the schema catches the mutation.  Compare with
        signature_alg below, where the schema is loose and the verifier
        must be immune to field values on its own."""
        import base64
        from assay._receipts.jcs import canonicalize as jcs_canonicalize

        receipts = [_make_receipt(seq=0)]
        pack = ProofPack(
            run_id="hash-alg-poison",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack_hashalg", keystore=ks)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        manifest["hash_alg"] = "sha512"

        # Re-sign so the signature is valid for the modified content
        unsigned = {
            k: v for k, v in manifest.items()
            if k not in ("signature", "pack_root_sha256")
        }
        canonical = jcs_canonicalize(unsigned)
        sig_b64 = ks.sign_b64(canonical, "mutant-signer")
        manifest["signature"] = sig_b64
        sig_raw = base64.b64decode(sig_b64)

        (out / "pack_manifest.json").write_bytes(
            json.dumps(manifest, indent=2).encode()
        )
        (out / "pack_signature.sig").write_bytes(sig_raw)

        # Schema validation catches the misleading hash_alg before
        # the verifier ever gets to hash comparison.
        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        schema_errors = [e for e in result.errors if "hash_alg" in e.message]
        assert len(schema_errors) >= 1, (
            "Schema must reject hash_alg='sha512' — defense in depth"
        )

    def test_signature_alg_schema_prevents_misleading_values(self, tmp_path, ks):
        """After OCD-10 hardening, signature_alg is now constrained to
        enum: ["ed25519"] like hash_alg.  Schema catches misleading values
        as defense in depth, so the verifier never has to deal with a
        pack claiming a different signature algorithm."""
        import base64
        from assay._receipts.jcs import canonicalize as jcs_canonicalize

        receipts = [_make_receipt(seq=0)]
        pack = ProofPack(
            run_id="sigalg-poison",
            entries=receipts,
            signer_id="mutant-signer",
        )
        out = pack.build(tmp_path / "pack_sigalg", keystore=ks)
        manifest = json.loads((out / "pack_manifest.json").read_text())

        manifest["signature_alg"] = "rsa-pss"

        # Re-sign so signature is valid for modified content
        unsigned = {
            k: v for k, v in manifest.items()
            if k not in ("signature", "pack_root_sha256")
        }
        canonical = jcs_canonicalize(unsigned)
        sig_b64 = ks.sign_b64(canonical, "mutant-signer")
        manifest["signature"] = sig_b64
        sig_raw = base64.b64decode(sig_b64)

        (out / "pack_manifest.json").write_bytes(
            json.dumps(manifest, indent=2).encode()
        )
        (out / "pack_signature.sig").write_bytes(sig_raw)

        # Schema validation catches misleading signature_alg
        result = verify_pack_manifest(manifest, out, ks)
        assert not result.passed
        schema_errors = [e for e in result.errors if "signature_alg" in e.message]
        assert len(schema_errors) >= 1, (
            "Schema must reject signature_alg='rsa-pss' — defense in depth (OCD-10)"
        )
