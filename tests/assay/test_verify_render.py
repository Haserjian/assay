"""Tests for verification status, HTML report, and SVG badge rendering."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from assay.claim_verifier import ClaimSpec
from assay.integrity import VerifyResult, VerifyError, verify_pack_manifest
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.verification_status import (
    VERDICT_COLORS,
    VERDICT_LABELS,
    classify_verdict,
)
from assay.verify_render import render_verification_badge, render_verification_html


# ---------------------------------------------------------------------------
# classify_verdict
# ---------------------------------------------------------------------------


class TestClassifyVerdict:
    def test_pass_when_integrity_and_claims_pass(self):
        assert classify_verdict(integrity_passed=True, claim_check="PASS") == "PASS"

    def test_pass_when_no_claims(self):
        assert classify_verdict(integrity_passed=True, claim_check="N/A") == "PASS"

    def test_honest_fail_when_claims_fail(self):
        assert classify_verdict(integrity_passed=True, claim_check="FAIL") == "HONEST_FAIL"

    def test_tampered_overrides_claim_pass(self):
        assert classify_verdict(integrity_passed=False, claim_check="PASS") == "TAMPERED"

    def test_tampered_overrides_claim_fail(self):
        assert classify_verdict(integrity_passed=False, claim_check="FAIL") == "TAMPERED"

    def test_tampered_overrides_no_claims(self):
        assert classify_verdict(integrity_passed=False, claim_check="N/A") == "TAMPERED"

    def test_all_verdicts_have_labels(self):
        for v in ("PASS", "HONEST_FAIL", "TAMPERED"):
            assert v in VERDICT_LABELS
            assert v in VERDICT_COLORS


# ---------------------------------------------------------------------------
# render_verification_html
# ---------------------------------------------------------------------------

_HTML_DEFAULTS = dict(
    verdict="PASS",
    pack_id="pack_001",
    run_id="run_001",
    pack_dir="/tmp/pack",
    integrity_passed=True,
    claim_check="PASS",
    receipt_count=3,
    signer_id="test-signer",
    errors=[],
    warnings=[],
    head_hash="abcd1234" * 8,
    generated_at="2026-03-08T12:00:00Z",
    version="1.16.0",
)


class TestRenderHtml:
    def test_pass_html_contains_key_fields(self):
        html = render_verification_html(**_HTML_DEFAULTS)
        assert "PASS" in html
        assert "pack_001" in html
        assert "run_001" in html
        assert "test-signer" in html
        assert "assay verify-pack" in html
        assert "1.16.0" in html
        assert "Pack verified" in html

    def test_pass_html_is_valid_document(self):
        html = render_verification_html(**_HTML_DEFAULTS)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_tampered_html_includes_errors(self):
        html = render_verification_html(
            **{
                **_HTML_DEFAULTS,
                "verdict": "TAMPERED",
                "integrity_passed": False,
                "errors": [{"code": "E_MANIFEST_TAMPER", "message": "hash mismatch"}],
            }
        )
        assert "TAMPERED" in html
        assert "Pack integrity compromised" in html
        assert "E_MANIFEST_TAMPER" in html
        assert "hash mismatch" in html
        assert "Failure Details" in html

    def test_honest_fail_html_shows_correct_label(self):
        html = render_verification_html(
            **{**_HTML_DEFAULTS, "verdict": "HONEST_FAIL", "claim_check": "FAIL"}
        )
        assert "HONEST_FAIL" in html
        assert "Pack verified, claims failed" in html

    def test_html_escapes_special_chars(self):
        html = render_verification_html(
            **{**_HTML_DEFAULTS, "pack_id": "<script>alert(1)</script>"}
        )
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_includes_receipt_count(self):
        html = render_verification_html(**_HTML_DEFAULTS)
        assert "3" in html

    def test_html_includes_head_hash_truncated(self):
        html = render_verification_html(**_HTML_DEFAULTS)
        assert "abcd1234abcd1234..." in html

    def test_html_includes_reproduce_command(self):
        html = render_verification_html(**_HTML_DEFAULTS)
        assert "assay verify-pack /tmp/pack" in html


# ---------------------------------------------------------------------------
# render_verification_badge
# ---------------------------------------------------------------------------


class TestRenderBadge:
    def test_pass_badge(self):
        svg = render_verification_badge("PASS")
        assert "<svg" in svg
        assert "PASS" in svg
        assert "assay" in svg
        assert VERDICT_COLORS["PASS"] in svg

    def test_honest_fail_badge(self):
        svg = render_verification_badge("HONEST_FAIL")
        assert "HONEST_FAIL" in svg
        assert VERDICT_COLORS["HONEST_FAIL"] in svg

    def test_tampered_badge(self):
        svg = render_verification_badge("TAMPERED")
        assert "TAMPERED" in svg
        assert VERDICT_COLORS["TAMPERED"] in svg

    def test_badge_has_no_external_references(self):
        svg = render_verification_badge("PASS")
        # xmlns is required for SVG; check no other http references
        lines = [l for l in svg.splitlines() if "xmlns" not in l]
        for line in lines:
            assert "http" not in line
        assert "href" not in svg

    def test_badge_is_deterministic(self):
        a = render_verification_badge("PASS")
        b = render_verification_badge("PASS")
        assert a == b


# ---------------------------------------------------------------------------
# Integration: verify-pack → classify → render
# ---------------------------------------------------------------------------

_TS = "2026-03-08T12:00:00Z"


def _make_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(tmp_path / "keys")
    ks.generate_key("test-signer")
    return ks


def _make_receipt(receipt_id: str, receipt_type: str = "model_call") -> Dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "type": receipt_type,
        "timestamp": _TS,
        "schema_version": "3.0",
        "provider": "openai",
        "model_id": "gpt-4o",
    }


class TestIntegration:
    def test_pass_pack_produces_pass_html_and_badge(self, tmp_path):
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-int",
            entries=[_make_receipt("r1")],
            signer_id="test-signer",
            mode="shadow",
        )
        pack_dir = pack.build(tmp_path / "pack", keystore=ks)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)
        att = manifest["attestation"]

        verdict = classify_verdict(
            integrity_passed=result.passed,
            claim_check=att.get("claim_check", "N/A"),
        )
        assert verdict == "PASS"

        html = render_verification_html(
            verdict=verdict,
            pack_id=att["pack_id"],
            run_id=att["run_id"],
            pack_dir=str(pack_dir),
            integrity_passed=result.passed,
            claim_check=att.get("claim_check", "N/A"),
            receipt_count=result.receipt_count,
            signer_id=att.get("signer_id", "unknown"),
            errors=[e.to_dict() for e in result.errors],
            warnings=result.warnings,
            head_hash=result.head_hash,
        )
        assert "PASS" in html
        assert att["pack_id"] in html

        svg = render_verification_badge(verdict)
        assert "PASS" in svg

    def test_tampered_pack_produces_tampered_html(self, tmp_path):
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-int",
            entries=[_make_receipt("r1")],
            signer_id="test-signer",
            mode="shadow",
        )
        pack_dir = pack.build(tmp_path / "pack", keystore=ks)

        # Tamper
        receipt_file = pack_dir / "receipt_pack.jsonl"
        data = bytearray(receipt_file.read_bytes())
        data[10] = (data[10] + 1) % 256
        receipt_file.write_bytes(bytes(data))

        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)
        att = manifest["attestation"]

        verdict = classify_verdict(
            integrity_passed=result.passed,
            claim_check=att.get("claim_check", "N/A"),
        )
        assert verdict == "TAMPERED"

        html = render_verification_html(
            verdict=verdict,
            pack_id=att["pack_id"],
            run_id=att["run_id"],
            pack_dir=str(pack_dir),
            integrity_passed=result.passed,
            claim_check=att.get("claim_check", "N/A"),
            receipt_count=result.receipt_count,
            signer_id=att.get("signer_id", "unknown"),
            errors=[e.to_dict() for e in result.errors],
            warnings=result.warnings,
            head_hash=result.head_hash,
        )
        assert "TAMPERED" in html
        assert "Failure Details" in html

    def test_honest_fail_pack_produces_honest_fail(self, tmp_path):
        ks = _make_keystore(tmp_path)
        claims = [
            ClaimSpec(
                claim_id="needs_tool",
                description="tool_call receipt exists",
                check="receipt_type_present",
                params={"receipt_type": "tool_call"},
            )
        ]
        pack = ProofPack(
            run_id="run-hf",
            entries=[_make_receipt("r1", "model_call")],
            signer_id="test-signer",
            claims=claims,
            mode="shadow",
        )
        pack_dir = pack.build(tmp_path / "pack", keystore=ks)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)
        att = manifest["attestation"]

        verdict = classify_verdict(
            integrity_passed=result.passed,
            claim_check=att.get("claim_check", "N/A"),
        )
        assert verdict == "HONEST_FAIL"

        svg = render_verification_badge(verdict)
        assert "HONEST_FAIL" in svg

    def test_artifact_generation_does_not_change_exit_semantics(self, tmp_path):
        """Badge/HTML generation must not alter the verification result."""
        ks = _make_keystore(tmp_path)
        pack = ProofPack(
            run_id="run-exit",
            entries=[_make_receipt("r1")],
            signer_id="test-signer",
            mode="shadow",
        )
        pack_dir = pack.build(tmp_path / "pack", keystore=ks)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        result = verify_pack_manifest(manifest, pack_dir, ks)

        # Rendering should not modify result
        verdict = classify_verdict(
            integrity_passed=result.passed,
            claim_check=manifest["attestation"].get("claim_check", "N/A"),
        )
        _html = render_verification_html(
            verdict=verdict,
            pack_id="x",
            run_id="x",
            pack_dir="x",
            integrity_passed=result.passed,
            claim_check="PASS",
            receipt_count=1,
            signer_id="x",
            errors=[],
            warnings=[],
        )
        _svg = render_verification_badge(verdict)

        # Result unchanged
        assert result.passed is True
        assert result.errors == []
