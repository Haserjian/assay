"""Attestation semantics specimen tests.

These tests validate that the semantic specimen packs produce the
expected claim evaluation outcomes. They exercise the Python claim
verifier against the attestation-semantics-fixtures.json spec.

This is NOT yet cross-implementation conformance — only Python
evaluates claims today. These specimens document and test what
attestation semantic fields mean.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.integrity import verify_pack_manifest
from assay.keystore import AssayKeyStore

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "contracts" / "vectors"
SEMANTIC_DIR = VECTORS_DIR / "semantic"


@pytest.fixture(scope="module")
def fixtures():
    path = SEMANTIC_DIR / "attestation-semantics-fixtures.json"
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def ks(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sem-ks")
    return AssayKeyStore(keys_dir=tmp)


class TestClaimPass:
    """Specimen: claim_pass — all claims satisfied."""

    def test_mechanical_integrity(self, ks):
        """Pack must pass mechanical verification first."""
        pack_dir = SEMANTIC_DIR / "claim_pass"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)
        assert result.passed, f"Mechanical verification failed: {[e.code for e in result.errors]}"

    def test_claim_check_pass(self, fixtures):
        """Attestation claim_check must be PASS."""
        pack_dir = SEMANTIC_DIR / "claim_pass"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_check"] == "PASS"

    def test_claim_count(self, fixtures):
        """verify_report should show 2 claims, 2 passed."""
        pack_dir = SEMANTIC_DIR / "claim_pass"
        report = json.loads((pack_dir / "verify_report.json").read_text())
        cv = report.get("claim_verification", {})
        assert cv.get("n_claims") == 2
        assert cv.get("n_passed") == 2
        assert cv.get("n_failed") == 0

    def test_claim_set_id_matches_spec(self, fixtures):
        """claim_set_id should match the fixture spec."""
        pack_dir = SEMANTIC_DIR / "claim_pass"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_set_id"] == fixtures["claim_set"]["claim_set_id"]


class TestClaimInsufficient:
    """Specimen: claim_insufficient — one claim fails due to missing evidence."""

    def test_mechanical_integrity(self, ks):
        """Pack must still pass mechanical verification."""
        pack_dir = SEMANTIC_DIR / "claim_insufficient"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)
        assert result.passed, f"Mechanical verification failed: {[e.code for e in result.errors]}"

    def test_claim_check_fail(self, fixtures):
        """Attestation claim_check must be FAIL."""
        pack_dir = SEMANTIC_DIR / "claim_insufficient"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_check"] == "FAIL"

    def test_one_claim_failed(self, fixtures):
        """verify_report should show 1 passed, 1 failed."""
        pack_dir = SEMANTIC_DIR / "claim_insufficient"
        report = json.loads((pack_dir / "verify_report.json").read_text())
        cv = report.get("claim_verification", {})
        assert cv.get("n_claims") == 2
        assert cv.get("n_passed") == 1
        assert cv.get("n_failed") == 1

    def test_guardian_claim_is_the_failure(self, fixtures):
        """The guardian_checked claim should be the one that failed."""
        pack_dir = SEMANTIC_DIR / "claim_insufficient"
        report = json.loads((pack_dir / "verify_report.json").read_text())
        cv = report.get("claim_verification", {})
        failed = [r for r in cv.get("results", []) if not r["passed"]]
        assert len(failed) == 1
        assert failed[0]["claim_id"] == "guardian_checked"

    def test_different_discrepancy_fingerprint(self, fixtures):
        """PASS and FAIL specimens must have different discrepancy fingerprints."""
        pass_manifest = json.loads((SEMANTIC_DIR / "claim_pass" / "pack_manifest.json").read_text())
        fail_manifest = json.loads((SEMANTIC_DIR / "claim_insufficient" / "pack_manifest.json").read_text())
        fp_pass = pass_manifest["attestation"].get("discrepancy_fingerprint")
        fp_fail = fail_manifest["attestation"].get("discrepancy_fingerprint")
        assert fp_pass != fp_fail, "PASS and FAIL should have different discrepancy fingerprints"


class TestMechanicalSemanticIndependence:
    """The semantic layer is independent of the mechanical layer.
    A pack can be mechanically valid but semantically insufficient."""

    def test_insufficient_is_mechanically_valid(self, ks):
        """claim_insufficient should pass mechanical verification."""
        pack_dir = SEMANTIC_DIR / "claim_insufficient"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)
        assert result.passed, "Mechanically valid pack with semantic FAIL"

    def test_insufficient_is_semantically_fail(self):
        """claim_insufficient should fail semantic evaluation."""
        pack_dir = SEMANTIC_DIR / "claim_insufficient"
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert manifest["attestation"]["claim_check"] == "FAIL"
