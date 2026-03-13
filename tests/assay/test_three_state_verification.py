"""Tests for three-state verification: PASS / HONEST_FAIL / TAMPERED / INSUFFICIENT_EVIDENCE.

Also covers:
- failure_mechanism classification on VerifyError
- witness_sufficiency scoring on WitnessVerifyResult
- verdict field in JSON output
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.failure_mechanisms import (
    ERROR_TO_MECHANISM,
    FM_POLICY_CONFLICT,
    FM_SCHEMA_MISMATCH,
    FM_STALE_EVIDENCE,
    FM_TAMPER_DETECTED,
    FM_WITNESS_GAP,
    mechanism_for_code,
)
from assay.integrity import (
    E_CANON_MISMATCH,
    E_CI_BINDING_MISMATCH,
    E_MANIFEST_TAMPER,
    E_PACK_SIG_INVALID,
    E_PACK_STALE,
    E_POLICY_MISSING,
    E_SCHEMA_UNKNOWN,
    E_SIG_MISSING,
    E_TIMESTAMP_INVALID,
    VerifyError,
    VerifyResult,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.verification_status import (
    VERDICT_COLORS,
    VERDICT_LABELS,
    classify_verdict,
)
from assay.witness import WitnessVerifyResult

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
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


def _build_pack(tmp_path, receipts=None, signer_id="test-signer"):
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key(signer_id)
    if receipts is None:
        receipts = [_make_receipt(seq=i) for i in range(3)]
    pack = ProofPack(
        run_id="three-state-test",
        entries=receipts,
        signer_id=signer_id,
        claims=[],
        mode="shadow",
    )
    out = pack.build(tmp_path / "pack", keystore=ks)
    return out, ks


# ---------------------------------------------------------------------------
# VerifyError failure_mechanism
# ---------------------------------------------------------------------------

class TestFailureMechanism:

    def test_tamper_errors_classified(self):
        err = VerifyError(code=E_MANIFEST_TAMPER, message="test")
        assert err.failure_mechanism == FM_TAMPER_DETECTED

    def test_stale_errors_classified(self):
        err = VerifyError(code=E_PACK_STALE, message="test")
        assert err.failure_mechanism == FM_STALE_EVIDENCE

    def test_timestamp_invalid_is_stale(self):
        err = VerifyError(code=E_TIMESTAMP_INVALID, message="test")
        assert err.failure_mechanism == FM_STALE_EVIDENCE

    def test_schema_errors_classified(self):
        err = VerifyError(code=E_SCHEMA_UNKNOWN, message="test")
        assert err.failure_mechanism == FM_SCHEMA_MISMATCH

    def test_canon_mismatch_is_schema(self):
        err = VerifyError(code=E_CANON_MISMATCH, message="test")
        assert err.failure_mechanism == FM_SCHEMA_MISMATCH

    def test_sig_missing_is_witness_gap(self):
        err = VerifyError(code=E_SIG_MISSING, message="test")
        assert err.failure_mechanism == FM_WITNESS_GAP

    def test_policy_missing_is_policy_conflict(self):
        err = VerifyError(code=E_POLICY_MISSING, message="test")
        assert err.failure_mechanism == FM_POLICY_CONFLICT

    def test_ci_binding_mismatch_is_policy_conflict(self):
        err = VerifyError(code=E_CI_BINDING_MISMATCH, message="test")
        assert err.failure_mechanism == FM_POLICY_CONFLICT

    def test_pack_sig_invalid_is_tamper(self):
        err = VerifyError(code=E_PACK_SIG_INVALID, message="test")
        assert err.failure_mechanism == FM_TAMPER_DETECTED

    def test_unknown_code_gets_none(self):
        err = VerifyError(code="E_CUSTOM_UNKNOWN", message="test")
        assert err.failure_mechanism is None

    def test_explicit_mechanism_overrides_default(self):
        err = VerifyError(code=E_MANIFEST_TAMPER, message="test",
                          failure_mechanism="custom_override")
        assert err.failure_mechanism == "custom_override"

    def test_to_dict_includes_mechanism(self):
        err = VerifyError(code=E_MANIFEST_TAMPER, message="test")
        d = err.to_dict()
        assert d["failure_mechanism"] == FM_TAMPER_DETECTED

    def test_to_dict_omits_none_mechanism(self):
        err = VerifyError(code="E_CUSTOM", message="test")
        d = err.to_dict()
        assert "failure_mechanism" not in d

    def test_all_known_codes_have_mechanism(self):
        """Every E_ constant in integrity.py should map to a mechanism."""
        from assay import integrity
        e_codes = [v for k, v in vars(integrity).items()
                   if k.startswith("E_") and isinstance(v, str)]
        for code in e_codes:
            assert mechanism_for_code(code) is not None, (
                f"Error code {code} has no mechanism mapping"
            )


# ---------------------------------------------------------------------------
# VerifyResult.failure_mechanisms
# ---------------------------------------------------------------------------

class TestFailureMechanismsSummary:

    def test_empty_errors_returns_empty_dict(self):
        r = VerifyResult(passed=True, errors=[])
        assert r.failure_mechanisms == {}

    def test_groups_by_mechanism(self):
        errors = [
            VerifyError(code=E_MANIFEST_TAMPER, message="a"),
            VerifyError(code=E_PACK_SIG_INVALID, message="b"),
            VerifyError(code=E_PACK_STALE, message="c"),
        ]
        r = VerifyResult(passed=False, errors=errors)
        fm = r.failure_mechanisms
        assert fm[FM_TAMPER_DETECTED] == 2
        assert fm[FM_STALE_EVIDENCE] == 1

    def test_to_dict_includes_mechanisms_when_present(self):
        errors = [VerifyError(code=E_MANIFEST_TAMPER, message="a")]
        r = VerifyResult(passed=False, errors=errors)
        d = r.to_dict()
        assert "failure_mechanisms" in d
        assert d["failure_mechanisms"][FM_TAMPER_DETECTED] == 1

    def test_to_dict_omits_mechanisms_when_no_errors(self):
        r = VerifyResult(passed=True, errors=[])
        d = r.to_dict()
        assert "failure_mechanisms" not in d


# ---------------------------------------------------------------------------
# classify_verdict — three-state + INSUFFICIENT_EVIDENCE
# ---------------------------------------------------------------------------

class TestClassifyVerdict:

    def test_tampered_when_integrity_fails(self):
        assert classify_verdict(
            integrity_passed=False, claim_check="N/A"
        ) == "TAMPERED"

    def test_tampered_trumps_witness(self):
        assert classify_verdict(
            integrity_passed=False, claim_check="PASS",
            witness_sufficient=False,
        ) == "TAMPERED"

    def test_pass_when_all_good(self):
        assert classify_verdict(
            integrity_passed=True, claim_check="PASS"
        ) == "PASS"

    def test_pass_when_no_claims(self):
        assert classify_verdict(
            integrity_passed=True, claim_check="N/A"
        ) == "PASS"

    def test_pass_with_witness_ok(self):
        assert classify_verdict(
            integrity_passed=True, claim_check="PASS",
            witness_sufficient=True,
        ) == "PASS"

    def test_honest_fail_when_claims_fail(self):
        assert classify_verdict(
            integrity_passed=True, claim_check="FAIL"
        ) == "HONEST_FAIL"

    def test_insufficient_evidence_when_witness_insufficient(self):
        assert classify_verdict(
            integrity_passed=True, claim_check="N/A",
            witness_sufficient=False,
        ) == "INSUFFICIENT_EVIDENCE"

    def test_insufficient_evidence_trumps_honest_fail(self):
        """If witness is insufficient, we can't even trust the claim check."""
        assert classify_verdict(
            integrity_passed=True, claim_check="FAIL",
            witness_sufficient=False,
        ) == "INSUFFICIENT_EVIDENCE"

    def test_witness_none_means_not_evaluated(self):
        """Default: witness not evaluated -> no INSUFFICIENT_EVIDENCE."""
        assert classify_verdict(
            integrity_passed=True, claim_check="N/A",
            witness_sufficient=None,
        ) == "PASS"

    def test_all_verdicts_have_labels(self):
        for v in ["PASS", "HONEST_FAIL", "TAMPERED", "INSUFFICIENT_EVIDENCE"]:
            assert v in VERDICT_LABELS
            assert v in VERDICT_COLORS


# ---------------------------------------------------------------------------
# WitnessVerifyResult.sufficiency
# ---------------------------------------------------------------------------

class TestWitnessSufficiency:

    def test_passed_witness_has_full_sufficiency(self):
        r = WitnessVerifyResult(passed=True, sufficiency=1.0)
        assert r.sufficiency == 1.0

    def test_failed_witness_has_partial_sufficiency(self):
        r = WitnessVerifyResult(passed=False, errors=["test"], sufficiency=0.75)
        assert r.sufficiency == 0.75

    def test_default_sufficiency_is_zero(self):
        r = WitnessVerifyResult(passed=False, errors=["test"])
        assert r.sufficiency == 0.0


# ---------------------------------------------------------------------------
# CLI JSON output: verdict field
# ---------------------------------------------------------------------------

class TestVerifyPackJsonVerdict:

    def test_json_includes_verdict_pass(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["verdict"] == "PASS"

    def test_json_includes_verdict_tampered(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        # Tamper with receipt_pack.jsonl
        rp = pack_dir / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        obj = json.loads(lines[0])
        obj["receipt_id"] = "r_tampered"
        lines[0] = json.dumps(obj)
        rp.write_text("\n".join(lines) + "\n")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
        ])
        data = json.loads(result.output)
        assert data["verdict"] == "TAMPERED"

    def test_json_includes_failure_mechanisms(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        # Tamper
        rp = pack_dir / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        obj = json.loads(lines[0])
        obj["receipt_id"] = "r_tampered"
        lines[0] = json.dumps(obj)
        rp.write_text("\n".join(lines) + "\n")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
        ])
        data = json.loads(result.output)
        assert "failure_mechanisms" in data
        assert FM_TAMPER_DETECTED in data["failure_mechanisms"]

    def test_json_no_failure_mechanisms_on_pass(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
        ])
        data = json.loads(result.output)
        assert "failure_mechanisms" not in data

    def test_exit_codes_unchanged(self, tmp_path):
        """Verify that adding verdict field doesn't change exit code contract."""
        pack_dir, ks = _build_pack(tmp_path)

        # PASS -> exit 0
        r = runner.invoke(assay_app, ["verify-pack", str(pack_dir), "--json"])
        assert r.exit_code == 0

        # TAMPERED -> exit 2
        rp = pack_dir / "receipt_pack.jsonl"
        lines = rp.read_text().strip().split("\n")
        obj = json.loads(lines[0])
        obj["receipt_id"] = "r_tampered"
        lines[0] = json.dumps(obj)
        rp.write_text("\n".join(lines) + "\n")
        r = runner.invoke(assay_app, ["verify-pack", str(pack_dir), "--json"])
        assert r.exit_code == 2


# ---------------------------------------------------------------------------
# Failure mechanism mapping completeness
# ---------------------------------------------------------------------------

class TestMechanismMappingCompleteness:

    def test_five_mechanism_families(self):
        families = set(ERROR_TO_MECHANISM.values())
        assert families == {
            FM_STALE_EVIDENCE, FM_SCHEMA_MISMATCH, FM_WITNESS_GAP,
            FM_TAMPER_DETECTED, FM_POLICY_CONFLICT,
        }

    def test_every_mechanism_maps_to_valid_family(self):
        valid = {FM_STALE_EVIDENCE, FM_SCHEMA_MISMATCH, FM_WITNESS_GAP,
                 FM_TAMPER_DETECTED, FM_POLICY_CONFLICT}
        for code, mech in ERROR_TO_MECHANISM.items():
            assert mech in valid, f"{code} maps to unknown mechanism {mech}"
