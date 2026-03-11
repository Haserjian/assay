"""Tests for ADC v0.1 emitter."""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay._receipts.canonicalize import to_jcs_bytes
from assay.adc_emitter import (
    _derive_claim_results,
    _derive_overall_result,
    build_adc,
)
from assay.claim_verifier import ClaimResult, ClaimSetResult
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack, get_decision_credential_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(str(tmp_path / "keys"))
    ks.generate_key("test-signer")
    return ks


def _make_sign_fn(ks: AssayKeyStore, signer_id: str = "test-signer"):
    return lambda data: ks.sign_b64(data, signer_id)


def _make_receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


def _minimal_adc_kwargs(ks: AssayKeyStore) -> dict:
    """Minimal valid kwargs for build_adc()."""
    vk = ks.get_verify_key("test-signer")
    pubkey_bytes = vk.encode()
    return dict(
        issuer_id="test-signer",
        signer_pubkey=base64.b64encode(pubkey_bytes).decode("ascii"),
        signer_pubkey_sha256=_sha256_hex(pubkey_bytes),
        claim_namespace="assay:test:v0.1",
        claim_ids=["pack_integrity"],
        evidence_manifest_sha256="a" * 64,
        evidence_pack_id="pack_test_001",
        evidence_n_receipts=3,
        integrity_passed=True,
        issued_at="2026-03-09T12:00:00Z",
        evaluated_at="2026-03-09T12:00:00Z",
        sign_fn=_make_sign_fn(ks),
    )


# ---------------------------------------------------------------------------
# _derive_overall_result
# ---------------------------------------------------------------------------

class TestDeriveOverallResult:

    def test_tampered_when_integrity_fails(self):
        assert _derive_overall_result(False, None) == "TAMPERED"

    def test_pass_when_no_claims(self):
        assert _derive_overall_result(True, None) == "PASS"

    def test_pass_when_all_claims_pass(self):
        cr = ClaimSetResult(passed=True, n_claims=2, n_passed=2, n_failed=0)
        assert _derive_overall_result(True, cr) == "PASS"

    def test_honest_fail_when_claims_fail(self):
        cr = ClaimSetResult(passed=False, n_claims=2, n_passed=1, n_failed=1)
        assert _derive_overall_result(True, cr) == "HONEST_FAIL"

    def test_tampered_overrides_claims(self):
        cr = ClaimSetResult(passed=True, n_claims=1, n_passed=1, n_failed=0)
        assert _derive_overall_result(False, cr) == "TAMPERED"


# ---------------------------------------------------------------------------
# _derive_claim_results
# ---------------------------------------------------------------------------

class TestDeriveClaimResults:

    def test_none_when_no_claims(self):
        assert _derive_claim_results(None) is None

    def test_maps_pass_and_fail(self):
        csr = ClaimSetResult(
            passed=False,
            results=[
                ClaimResult(claim_id="c1", passed=True, expected="x", actual="x", severity="critical"),
                ClaimResult(claim_id="c2", passed=False, expected="y", actual="z", severity="warning"),
            ],
            n_claims=2,
            n_passed=1,
            n_failed=1,
        )
        out = _derive_claim_results(csr)
        assert len(out) == 2
        assert out[0] == {"claim_id": "c1", "result": "PASS"}
        assert out[1] == {"claim_id": "c2", "result": "FAIL", "severity": "warning"}

    def test_unknown_severity_defaults_to_error(self):
        csr = ClaimSetResult(
            passed=False,
            results=[
                ClaimResult(claim_id="c1", passed=False, expected="a", actual="b", severity="bogus"),
            ],
            n_claims=1,
            n_passed=0,
            n_failed=1,
        )
        out = _derive_claim_results(csr)
        assert out[0]["severity"] == "error"


# ---------------------------------------------------------------------------
# build_adc
# ---------------------------------------------------------------------------

class TestBuildAdc:

    def test_required_fields_present(self, tmp_path):
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))

        required = [
            "credential_id", "credential_version", "credential_type",
            "issued_at", "issuer_id", "signer_pubkey", "signer_pubkey_sha256",
            "claim_namespace", "claim_ids", "evidence_manifest_sha256",
            "evidence_pack_id", "integrity_result", "overall_result",
            "evaluated_at", "signature", "signature_scope", "canon_version",
        ]
        for field in required:
            assert field in adc, f"Missing required field: {field}"

    def test_const_fields(self, tmp_path):
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))
        assert adc["credential_version"] == "0.1.0"
        assert adc["credential_type"] == "ai_decision_credential"
        assert adc["signature_scope"] == "jcs_rfc8785_without_signature"
        assert adc["canon_version"] == "jcs-rfc8785"

    def test_credential_id_is_content_addressable(self, tmp_path):
        """credential_id can be recomputed from the credential body."""
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))

        # Reconstruct: remove signature and credential_id, hash body
        body = {k: v for k, v in adc.items() if k not in ("signature", "credential_id")}
        expected_id = _sha256_hex(to_jcs_bytes(body))
        assert adc["credential_id"] == expected_id

    def test_signature_verifies(self, tmp_path):
        """Signature is valid Ed25519 over JCS(credential minus signature)."""
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))

        # Verify: remove signature, JCS-canonicalize, verify
        without_sig = {k: v for k, v in adc.items() if k != "signature"}
        canonical = to_jcs_bytes(without_sig)

        vk = ks.get_verify_key("test-signer")
        sig_bytes = base64.b64decode(adc["signature"])
        vk.verify(canonical, sig_bytes)  # raises if invalid

    def test_pass_result(self, tmp_path):
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))
        assert adc["integrity_result"] == "PASS"
        assert adc["overall_result"] == "PASS"

    def test_tampered_result(self, tmp_path):
        ks = _make_keystore(tmp_path)
        kwargs = _minimal_adc_kwargs(ks)
        kwargs["integrity_passed"] = False
        adc = build_adc(**kwargs)
        assert adc["integrity_result"] == "FAIL"
        assert adc["overall_result"] == "TAMPERED"

    def test_honest_fail_with_claims(self, tmp_path):
        ks = _make_keystore(tmp_path)
        kwargs = _minimal_adc_kwargs(ks)
        kwargs["claim_result"] = ClaimSetResult(
            passed=False,
            results=[
                ClaimResult(claim_id="c1", passed=False, expected="x", actual="y", severity="critical"),
            ],
            n_claims=1, n_passed=0, n_failed=1,
        )
        kwargs["claim_ids"] = ["c1"]
        adc = build_adc(**kwargs)
        assert adc["overall_result"] == "HONEST_FAIL"
        assert len(adc["claim_results"]) == 1
        assert adc["claim_results"][0]["result"] == "FAIL"

    def test_optional_fields(self, tmp_path):
        ks = _make_keystore(tmp_path)
        kwargs = _minimal_adc_kwargs(ks)
        kwargs.update(
            claim_summary="Test summary",
            evidence_head_hash="b" * 64,
            policy_id="test-policy",
            policy_hash="c" * 64,
            governance_framework="nist_ai_rmf_1.0",
            evidence_observed_at="2026-03-09T11:00:00Z",
            valid_until="2026-06-09T12:00:00Z",
            challenge_window_seconds=604800,
            supersedes="d" * 64,
        )
        adc = build_adc(**kwargs)
        assert adc["claim_summary"] == "Test summary"
        assert adc["evidence_head_hash"] == "b" * 64
        assert adc["policy_id"] == "test-policy"
        assert adc["governance_framework"] == "nist_ai_rmf_1.0"
        assert adc["valid_until"] == "2026-06-09T12:00:00Z"
        assert adc["challenge_window_seconds"] == 604800
        assert adc["supersedes"] == "d" * 64

    def test_nullable_fields_default_to_none(self, tmp_path):
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))
        assert adc["valid_until"] is None
        assert adc["challenge_window_seconds"] is None
        assert adc["challenge_endpoint"] is None
        assert adc["supersedes"] is None
        assert adc["superseded_by"] is None
        assert adc["ledger_entry_hash"] is None
        assert adc["transparency_log_id"] is None

    def test_witness_defaults_unwitnessed(self, tmp_path):
        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))
        assert adc["witness_status"] == "unwitnessed"

    def test_deterministic_same_input_same_id(self, tmp_path):
        """Same inputs produce same credential_id (content-addressable)."""
        ks = _make_keystore(tmp_path)
        kwargs = _minimal_adc_kwargs(ks)
        adc1 = build_adc(**kwargs)
        adc2 = build_adc(**kwargs)
        assert adc1["credential_id"] == adc2["credential_id"]
        # Signatures may differ (Ed25519 is deterministic for same key, so
        # they should actually be equal too with the same keystore)
        assert adc1["signature"] == adc2["signature"]

    def test_schema_validation(self, tmp_path):
        """Emitted ADC validates against the JSON Schema."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        ks = _make_keystore(tmp_path)
        adc = build_adc(**_minimal_adc_kwargs(ks))

        schema_path = Path(__file__).resolve().parent.parent.parent / "src" / "assay" / "schemas" / "adc_v0.1.schema.json"
        if not schema_path.exists():
            pytest.skip(f"Schema not found at {schema_path}")
        schema = json.loads(schema_path.read_text())
        jsonschema.validate(adc, schema)


# ---------------------------------------------------------------------------
# ProofPack integration
# ---------------------------------------------------------------------------

class TestProofPackIntegration:

    def test_emit_adc_false_by_default(self, tmp_path):
        """Default build does not emit decision_credential.json."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-001",
            entries=[_make_receipt()],
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)
        assert not get_decision_credential_path(out, legacy_fallback=False).exists()
        assert not (out / "decision_credential.json").exists()

    def test_emit_adc_true_writes_file(self, tmp_path):
        """emit_adc=True produces decision_credential.json."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-002",
            entries=[_make_receipt()],
            emit_adc=True,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)
        cred_path = get_decision_credential_path(out, legacy_fallback=False)
        assert cred_path.exists()
        assert cred_path.parent.name == "_unsigned"

        adc = json.loads(cred_path.read_text())
        assert adc["credential_type"] == "ai_decision_credential"
        assert adc["evidence_pack_id"].startswith("pack_")
        assert adc["integrity_result"] == "PASS"
        assert adc["overall_result"] == "PASS"

    def test_emit_adc_with_deterministic_ts(self, tmp_path):
        """Deterministic timestamp flows through to ADC."""
        ks = _make_keystore(tmp_path)
        ts = "2026-03-09T12:00:00Z"
        pack = ProofPack(
            run_id="run-003",
            entries=[_make_receipt(timestamp=ts)],
            emit_adc=True,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks, deterministic_ts=ts)
        adc = json.loads(get_decision_credential_path(out, legacy_fallback=False).read_text())
        assert adc["issued_at"] == ts
        assert adc["evaluated_at"] == ts

    def test_emit_adc_default_namespace(self, tmp_path):
        """Default claim_namespace derived from suite_id."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-004",
            entries=[_make_receipt()],
            emit_adc=True,
            suite_id="vendorq_v1",
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)
        adc = json.loads(get_decision_credential_path(out, legacy_fallback=False).read_text())
        assert adc["claim_namespace"] == "assay:vendorq_v1"

    def test_emit_adc_manual_namespace_fallback(self, tmp_path):
        """suite_id='manual' produces generic namespace."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-005",
            entries=[_make_receipt()],
            emit_adc=True,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)
        adc = json.loads(get_decision_credential_path(out, legacy_fallback=False).read_text())
        assert adc["claim_namespace"] == "assay:pack:v0.1"

    def test_emit_adc_explicit_namespace(self, tmp_path):
        """Explicit claim_namespace overrides derivation."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-006",
            entries=[_make_receipt()],
            emit_adc=True,
            claim_namespace="org:fintech:loan:v1",
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)
        adc = json.loads(get_decision_credential_path(out, legacy_fallback=False).read_text())
        assert adc["claim_namespace"] == "org:fintech:loan:v1"

    def test_emit_adc_signature_verifies(self, tmp_path):
        """ADC signature from pack build is verifiable."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-007",
            entries=[_make_receipt()],
            emit_adc=True,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)
        adc = json.loads(get_decision_credential_path(out, legacy_fallback=False).read_text())

        without_sig = {k: v for k, v in adc.items() if k != "signature"}
        canonical = to_jcs_bytes(without_sig)
        vk = ks.get_verify_key("test-signer")
        sig_bytes = base64.b64decode(adc["signature"])
        vk.verify(canonical, sig_bytes)

    def test_emit_adc_evidence_binding(self, tmp_path):
        """ADC evidence_manifest_sha256 matches pack_root_sha256."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-008",
            entries=[_make_receipt()],
            emit_adc=True,
            signer_id="test-signer",
        )
        out = pack.build(tmp_path / "pack", keystore=ks)

        manifest = json.loads((out / "pack_manifest.json").read_text())
        adc = json.loads(get_decision_credential_path(out, legacy_fallback=False).read_text())
        assert adc["evidence_manifest_sha256"] == manifest["pack_root_sha256"]
