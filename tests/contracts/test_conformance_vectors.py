"""
Conformance vector tests — first pass.

These tests load machine-readable vector files and verify that the current
Assay implementation matches every expected output exactly.  A second
implementation (e.g., TypeScript browser verifier) must produce the same
outputs for the same inputs.

Vector files live in tests/contracts/vectors/*.json.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay._receipts.merkle import (
    compute_merkle_root,
    generate_inclusion_proof,
    verify_merkle_inclusion,
)
from assay._receipts.canonicalize import prepare_receipt_for_hashing
from assay.integrity import verify_pack_manifest, E_MANIFEST_TAMPER
from assay.keystore import AssayKeyStore

VECTORS_DIR = Path(__file__).resolve().parent / "vectors"


def _load_vectors(filename: str) -> dict:
    path = VECTORS_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# JCS (Layer 1) conformance
# ---------------------------------------------------------------------------

class TestJCSConformance:
    """Every JCS vector must produce exact canonical bytes and exact SHA-256."""

    @pytest.fixture(scope="class")
    def vectors(self):
        return _load_vectors("jcs_vectors.json")["vectors"]

    def test_vector_count(self, vectors):
        """Sanity: we have the expected number of vectors."""
        assert len(vectors) >= 15

    @pytest.mark.parametrize("idx", range(16))
    def test_jcs_golden_vector(self, vectors, idx):
        if idx >= len(vectors):
            pytest.skip("Vector index out of range")
        v = vectors[idx]
        canonical = jcs_canonicalize(v["input"])
        canonical_utf8 = canonical.decode("utf-8")

        assert canonical_utf8 == v["expected_canonical_utf8"], (
            f"[{v['id']}] Canonical mismatch: "
            f"expected {v['expected_canonical_utf8']!r}, got {canonical_utf8!r}"
        )

        sha256 = hashlib.sha256(canonical).hexdigest()
        assert sha256 == v["expected_sha256"], (
            f"[{v['id']}] SHA-256 mismatch: "
            f"expected {v['expected_sha256']}, got {sha256}"
        )

    def test_negative_zero(self, vectors):
        """JCS-G09: language-level -0.0 must canonicalize as 0."""
        v = next(v for v in vectors if v["id"] == "JCS-G09")
        # Construct -0.0 at language level (JSON can't represent it)
        inp = {"a": -0.0}
        canonical = jcs_canonicalize(inp)
        assert canonical.decode("utf-8") == v["expected_canonical_utf8"]


# ---------------------------------------------------------------------------
# Merkle (Layer 1) conformance
# ---------------------------------------------------------------------------

class TestMerkleConformance:
    """Every Merkle vector must produce exact root and valid inclusion proofs."""

    @pytest.fixture(scope="class")
    def data(self):
        return _load_vectors("merkle_vectors.json")

    def test_golden_roots(self, data):
        for v in data["vectors"]:
            root = compute_merkle_root(v["leaves"])
            assert root == v["expected_root"], (
                f"[{v['id']}] Root mismatch: "
                f"expected {v['expected_root']}, got {root}"
            )

    def test_inclusion_proofs(self, data):
        for v in data["vectors"]:
            if "inclusion_proofs" not in v:
                continue
            for proof_spec in v["inclusion_proofs"]:
                leaf = v["leaves"][proof_spec["leaf_index"]]
                valid = verify_merkle_inclusion(
                    leaf,
                    proof_spec["proof"],
                    v["expected_root"],
                    proof_spec["leaf_index"],
                )
                assert valid == proof_spec["expected_valid"], (
                    f"[{v['id']}] Inclusion proof failed for leaf index "
                    f"{proof_spec['leaf_index']}"
                )

    def test_adversarial_wrong_index(self, data):
        """MK-A01: proof for index 0 must fail when verified at index 1."""
        v = next(v for v in data["vectors"] if v["id"] == "MK-G03")
        proof = v["inclusion_proofs"][0]["proof"]
        # Use proof for index 0 but verify at index 1
        leaf_1 = v["leaves"][1]
        valid = verify_merkle_inclusion(leaf_1, proof, v["expected_root"], 1)
        # This should fail (wrong leaf for the proof)
        assert not valid

    def test_adversarial_tampered_proof(self, data):
        """MK-A02: flipping a hex char in proof node must fail."""
        v = next(v for v in data["vectors"] if v["id"] == "MK-G03")
        proof = list(v["inclusion_proofs"][0]["proof"])
        # Flip first hex char
        tampered = ("0" if proof[0][0] != "0" else "1") + proof[0][1:]
        proof[0] = tampered
        valid = verify_merkle_inclusion(
            v["leaves"][0], proof, v["expected_root"], 0,
        )
        assert not valid


# ---------------------------------------------------------------------------
# Receipt Projection (Layer 2) conformance
# ---------------------------------------------------------------------------

class TestReceiptProjectionConformance:
    """Receipt projection must strip exactly the v0 signature fields at root level."""

    @pytest.fixture(scope="class")
    def data(self):
        return _load_vectors("receipt_projection_vectors.json")

    def test_golden_vectors(self, data):
        for v in data["vectors"]:
            prepared = prepare_receipt_for_hashing(v["input"])
            assert prepared == v["expected_prepared"], (
                f"[{v['id']}] Prepared dict mismatch"
            )

            canonical = jcs_canonicalize(prepared)
            assert canonical.decode("utf-8") == v["expected_canonical_utf8"], (
                f"[{v['id']}] Canonical mismatch"
            )

            sha256 = hashlib.sha256(canonical).hexdigest()
            assert sha256 == v["expected_sha256"], (
                f"[{v['id']}] SHA-256 mismatch: "
                f"expected {v['expected_sha256']}, got {sha256}"
            )

    def test_stripping_equivalence(self, data):
        """RC-A01: receipts with same payload but different sig fields → same hash."""
        hashes = {}
        for v in data["vectors"]:
            if v["id"] in ("RC-G01", "RC-G02"):
                hashes[v["id"]] = v["expected_sha256"]
        assert hashes["RC-G01"] == hashes["RC-G02"], (
            "Stripping equivalence failed: RC-G01 and RC-G02 must match"
        )

    def test_nested_signature_preserved(self, data):
        """RC-A02: nested 'signature' field is NOT stripped (root-only)."""
        rc1 = next(v for v in data["vectors"] if v["id"] == "RC-G01")
        rc3 = next(v for v in data["vectors"] if v["id"] == "RC-G03")
        assert rc1["expected_sha256"] != rc3["expected_sha256"], (
            "RC-G01 and RC-G03 should differ — nested signature is payload"
        )

    def test_exclusion_set_matches_doc(self, data):
        """The vector file's exclusion set must match the code's _SIGNATURE_FIELD_SETS."""
        from assay._receipts.canonicalize import _SIGNATURE_FIELD_SETS
        doc_set = set(data["exclusion_set"])
        code_set = _SIGNATURE_FIELD_SETS["v0"]
        assert doc_set == code_set, (
            f"Exclusion set drift: doc={sorted(doc_set)}, code={sorted(code_set)}"
        )


# ---------------------------------------------------------------------------
# Adversarial pack specimen: tampered receipt content
# ---------------------------------------------------------------------------

class TestAdversarialTamperedReceipt:
    """PK-A01-class vector: single-byte tamper in receipt_pack.jsonl.

    Preregistration:
    - Mutation: receipt_pack.jsonl line 1, 'conformance-r001' → 'xonformance-r001'
      (byte 62: 0x63 → 0x78)
    - File size: unchanged (387 bytes)
    - Expected failure step: step_1_file_hash_verification
    - Expected error: E_MANIFEST_TAMPER on field receipt_pack.jsonl
    - Occurs before: Ed25519 signature verification
    - Verifier continuation: implementation-dependent (Python does not short-circuit)
    """

    SPECIMEN_DIR = VECTORS_DIR / "pack" / "tampered_receipt_content"
    SPEC_PATH = VECTORS_DIR / "pack" / "tampered_receipt_content_spec.json"

    @pytest.fixture(scope="class")
    def spec(self):
        return json.loads(self.SPEC_PATH.read_text())

    @pytest.fixture(scope="class")
    def result(self, tmp_path_factory):
        """Run verify_pack_manifest once for the class."""
        manifest = json.loads(
            (self.SPECIMEN_DIR / "pack_manifest.json").read_text()
        )
        tmp = tmp_path_factory.mktemp("ks")
        ks = AssayKeyStore(keys_dir=tmp)
        return verify_pack_manifest(manifest, self.SPECIMEN_DIR, ks)

    def test_verification_fails(self, result):
        """Tampered pack must fail verification."""
        assert not result.passed

    def test_primary_error_is_manifest_tamper(self, result):
        """Primary error must be E_MANIFEST_TAMPER on receipt_pack.jsonl."""
        tamper_errors = [
            e for e in result.errors
            if e.code == E_MANIFEST_TAMPER and e.field == "receipt_pack.jsonl"
        ]
        assert len(tamper_errors) >= 1, (
            f"Expected E_MANIFEST_TAMPER on receipt_pack.jsonl, got: "
            f"{[(e.code, e.field) for e in result.errors]}"
        )

    def test_error_mentions_hash_mismatch(self, result):
        """Error message must mention hash mismatch."""
        tamper_errors = [
            e for e in result.errors
            if e.code == E_MANIFEST_TAMPER and e.field == "receipt_pack.jsonl"
        ]
        assert any("Hash mismatch" in e.message for e in tamper_errors)

    def test_file_size_unchanged(self, spec):
        """Tamper must not change file size (spec requirement)."""
        assert not spec["preregistration"]["file_size_changed"]
        original_size = (VECTORS_DIR / "pack" / "golden_minimal" / "receipt_pack.jsonl").stat().st_size
        tampered_size = (self.SPECIMEN_DIR / "receipt_pack.jsonl").stat().st_size
        assert original_size == tampered_size

    def test_tampered_hash_differs_from_golden(self, spec):
        """Tampered file SHA-256 must differ from golden specimen."""
        assert (
            spec["preregistration"]["tampered_file_sha256"]
            != spec["preregistration"]["original_file_sha256"]
        )


# ---------------------------------------------------------------------------
# Adversarial specimen suite: one-fault-per-pack
# ---------------------------------------------------------------------------

class _AdversarialSpecimenBase:
    """Base for one-fault adversarial specimens. Subclasses set SPECIMEN_NAME,
    EXPECTED_CODE, and optionally EXPECTED_FIELD."""

    SPECIMEN_NAME: str
    EXPECTED_CODE: str
    EXPECTED_FIELD: str | None = None

    @pytest.fixture(scope="class")
    def result(self, tmp_path_factory):
        pack_dir = VECTORS_DIR / "pack" / self.SPECIMEN_NAME
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        tmp = tmp_path_factory.mktemp("ks")
        ks = AssayKeyStore(keys_dir=tmp)
        return verify_pack_manifest(manifest, pack_dir, ks)

    @pytest.fixture(scope="class")
    def spec(self):
        spec_path = VECTORS_DIR / "pack" / f"{self.SPECIMEN_NAME}_spec.json"
        return json.loads(spec_path.read_text())

    def test_verification_fails(self, result):
        assert not result.passed

    def test_expected_error_code_present(self, result):
        matching = [e for e in result.errors if e.code == self.EXPECTED_CODE]
        assert len(matching) >= 1, (
            f"Expected {self.EXPECTED_CODE}, got: "
            f"{[(e.code, e.field) for e in result.errors]}"
        )

    def test_expected_field_if_specified(self, result):
        if self.EXPECTED_FIELD is None:
            pytest.skip("No specific field assertion for this specimen")
        matching = [
            e for e in result.errors
            if e.code == self.EXPECTED_CODE and e.field and self.EXPECTED_FIELD in e.field
        ]
        assert len(matching) >= 1, (
            f"Expected {self.EXPECTED_CODE} on field containing '{self.EXPECTED_FIELD}', "
            f"got: {[(e.code, e.field) for e in result.errors]}"
        )


class TestTamperedSignature(_AdversarialSpecimenBase):
    """Detached signature replaced with invalid bytes."""
    SPECIMEN_NAME = "tampered_signature"
    EXPECTED_CODE = "E_PACK_SIG_INVALID"
    EXPECTED_FIELD = "pack_signature.sig"


class TestMissingKernelFile(_AdversarialSpecimenBase):
    """verify_report.json deleted from pack."""
    SPECIMEN_NAME = "missing_kernel_file"
    EXPECTED_CODE = "E_MANIFEST_TAMPER"
    EXPECTED_FIELD = "verify_report.json"


class TestD12InvariantBreak(_AdversarialSpecimenBase):
    """pack_root_sha256 differs from attestation_sha256."""
    SPECIMEN_NAME = "d12_invariant_break"
    EXPECTED_CODE = "E_MANIFEST_TAMPER"
    EXPECTED_FIELD = "pack_root_sha256"


class TestPathTraversal(_AdversarialSpecimenBase):
    """Manifest files array includes path traversal entry."""
    SPECIMEN_NAME = "path_traversal"
    EXPECTED_CODE = "E_PATH_ESCAPE"
    EXPECTED_FIELD = None  # field value varies by implementation


class TestDuplicateReceiptId(_AdversarialSpecimenBase):
    """Two receipts with same receipt_id. Root cause is E_DUPLICATE_ID
    at receipt level; pack verifier surfaces as receipt_integrity mismatch."""
    SPECIMEN_NAME = "duplicate_receipt_id"
    EXPECTED_CODE = "E_MANIFEST_TAMPER"
    EXPECTED_FIELD = "receipt_integrity"


# ---------------------------------------------------------------------------
# Shared fixture-driven conformance (same JSON as TS verifier)
# ---------------------------------------------------------------------------

class TestSharedConformanceFixtures:
    """Load conformance expectations from the shared spec file
    (conformance-fixtures.json) and verify Python agrees.

    This is the same fixture file consumed by the TypeScript verifier.
    Both implementations must agree on pass/fail for every specimen."""

    FIXTURES_PATH = VECTORS_DIR / "pack" / "conformance-fixtures.json"

    @pytest.fixture(scope="class")
    def fixtures(self):
        return json.loads(self.FIXTURES_PATH.read_text())["fixtures"]

    @pytest.fixture(scope="class")
    def ks(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("shared-ks")
        return AssayKeyStore(keys_dir=tmp)

    def test_fixture_count(self, fixtures):
        """Sanity: shared fixtures file has at least one specimen."""
        assert len(fixtures) >= 1

    def test_all_shared_fixtures(self, fixtures, ks):
        """Each shared fixture must match Python's verification outcome.

        Fully data-driven: fixture count is derived from the spec file,
        not hardcoded. Adding a specimen to conformance-fixtures.json
        automatically tests it here."""
        for f in fixtures:
            pack_dir = VECTORS_DIR / "pack" / f["name"]
            manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
            result = verify_pack_manifest(manifest, pack_dir, ks)

            assert result.passed == f["expectPassed"], (
                f"[{f['name']}] expected passed={f['expectPassed']}, "
                f"got {result.passed}. Errors: {[(e.code, e.field) for e in result.errors]}"
            )

            # Check expected error code(s)
            expect_codes = f.get("expectCodesAnyOf") or ([f["expectCode"]] if f.get("expectCode") else [])
            if expect_codes:
                matching = [e for e in result.errors if e.code in expect_codes]
                assert len(matching) >= 1, (
                    f"[{f['name']}] expected one of {expect_codes}, "
                    f"got: {[(e.code, e.field) for e in result.errors]}"
                )
