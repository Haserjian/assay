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
