"""Tests for passport X-Ray diagnostic."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.keystore import AssayKeyStore
from assay.xray import XRayResult, xray_passport


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    import assay.store as store_mod

    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


@pytest.fixture
def keystore(assay_home_tmp: Path) -> AssayKeyStore:
    ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
    ks.generate_key("assay-local")
    return ks


def _make_passport(**overrides) -> dict:
    base = {
        "passport_version": "0.1",
        "issued_at": "2026-03-14T00:00:00+00:00",
        "valid_until": "2036-04-13T00:00:00+00:00",
        "status": {"state": "FRESH", "reason": "ok"},
        "reliance": {"class": "R2", "label": "Signed, partial"},
        "trust_posture": {
            "freshness": "current",
            "signature": "signed",
            "coverage": "4 of 5",
            "evidence_mix": "3 machine / 1 human",
            "challenges": "none",
            "scope_class": "partial",
        },
        "subject": {
            "name": "TestApp",
            "system_id": "test.v1",
            "owner": "Test Inc.",
        },
        "scope": {
            "in_scope": ["Feature A", "Feature B"],
            "not_covered": ["Feature C"],
            "not_observed": [],
            "not_concluded": [],
        },
        "claims": [
            {
                "claim_id": "C-001",
                "topic": "Integrity",
                "claim_type": "integrity",
                "assertion": "Test claim",
                "result": "pass",
                "evidence_type": "machine_verified",
                "proof_tier": "core",
            },
            {
                "claim_id": "C-002",
                "topic": "Coverage",
                "claim_type": "coverage",
                "assertion": "Test coverage",
                "result": "partial",
                "evidence_type": "machine_verified",
                "proof_tier": "core",
            },
        ],
        "evidence_summary": {
            "total_claims": 2,
            "machine_verified": 2,
            "human_attested": 0,
        },
        "coverage": {
            "identified_total": 5,
            "covered_total": 4,
            "coverage_pct": 80,
            "call_sites": [
                {"call_site_id": "s1", "status": "covered"},
                {"call_site_id": "s2", "status": "covered"},
                {"call_site_id": "s3", "status": "covered"},
                {"call_site_id": "s4", "status": "covered"},
                {"call_site_id": "s5", "status": "missing"},
            ],
        },
        "verification": {"how_to_verify": "test"},
        "challenge": {"how_to_challenge": "test"},
    }
    base.update(overrides)
    return base


def _write_passport(tmp_path: Path, passport: dict, name: str = "passport.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")
    return path


class TestXRayGrading:
    def test_unsigned_gets_grade_c(self, tmp_path: Path) -> None:
        """Unsigned passport with claims → grade C."""
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)
        result = xray_passport(path)
        assert result.overall_grade == "C"
        assert any("Sign" in m for m in result.missing_for_next_grade)

    def test_signed_partial_gets_grade_b(self, tmp_path: Path, keystore: AssayKeyStore) -> None:
        """Signed passport with partial claims → grade B."""
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)

        from assay.passport_sign import sign_passport
        sign_passport(path, keystore=keystore)

        result = xray_passport(path, keystore=keystore, verify=True)
        assert result.overall_grade == "B"

    def test_signed_all_pass_full_coverage_gets_grade_a(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """Signed, all pass, full coverage → grade A."""
        passport = _make_passport()
        # All claims pass
        for c in passport["claims"]:
            c["result"] = "pass"
        # Full coverage
        passport["coverage"]["covered_total"] = 5
        passport["coverage"]["coverage_pct"] = 100
        for site in passport["coverage"]["call_sites"]:
            site["status"] = "covered"
        path = _write_passport(tmp_path, passport)

        from assay.passport_sign import sign_passport
        sign_passport(path, keystore=keystore)

        result = xray_passport(path, keystore=keystore, verify=True)
        assert result.overall_grade == "A"
        assert result.missing_for_next_grade == []

    def test_no_claims_gets_grade_d(self, tmp_path: Path) -> None:
        """No claims, no coverage → grade D."""
        passport = _make_passport(claims=[], coverage={}, evidence_summary={})
        path = _write_passport(tmp_path, passport)
        result = xray_passport(path)
        assert result.overall_grade == "D"

    def test_revoked_gets_grade_f(self, tmp_path: Path) -> None:
        """Revoked passport → grade F."""
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)
        # Create revocation receipt
        rev = {"type": "revocation", "reason": "test", "timestamp": "2026-03-14T00:00:00+00:00"}
        (tmp_path / "revocation_20260314T000000.json").write_text(
            json.dumps(rev), encoding="utf-8"
        )
        result = xray_passport(path)
        assert result.overall_grade == "F"

    def test_tampered_gets_grade_f(self, tmp_path: Path, keystore: AssayKeyStore) -> None:
        """Tampered signature → grade F."""
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)

        from assay.passport_sign import sign_passport
        sign_passport(path, keystore=keystore)

        # Tamper
        data = json.loads(path.read_text(encoding="utf-8"))
        data["subject"]["name"] = "Tampered"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        result = xray_passport(path, keystore=keystore, verify=True)
        assert result.overall_grade == "F"


class TestXRayFindings:
    def test_findings_include_all_categories(self, tmp_path: Path) -> None:
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)
        result = xray_passport(path)
        categories = {f.category for f in result.findings}
        assert "signature" in categories
        assert "freshness" in categories
        assert "coverage" in categories
        assert "claims" in categories
        assert "evidence" in categories
        assert "scope" in categories

    def test_stale_finding(self, tmp_path: Path) -> None:
        passport = _make_passport(valid_until="2025-01-01T00:00:00+00:00")
        path = _write_passport(tmp_path, passport)
        result = xray_passport(path)
        freshness_findings = [f for f in result.findings if f.category == "freshness"]
        assert any(f.severity == "fail" for f in freshness_findings)

    def test_missing_file(self, tmp_path: Path) -> None:
        result = xray_passport(tmp_path / "nonexistent.json")
        assert result.overall_grade == "F"
        assert len(result.findings) > 0

    def test_malformed_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        result = xray_passport(path)
        assert result.overall_grade == "F"


class TestXRayResult:
    def test_to_dict(self, tmp_path: Path) -> None:
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)
        result = xray_passport(path)
        d = result.to_dict()
        assert "overall_grade" in d
        assert "findings" in d
        assert "finding_counts" in d

    def test_exit_code_a_is_0(self) -> None:
        r = XRayResult(passport_path="test", overall_grade="A")
        assert r.exit_code == 0

    def test_exit_code_b_is_0(self) -> None:
        r = XRayResult(passport_path="test", overall_grade="B")
        assert r.exit_code == 0

    def test_exit_code_c_is_1(self) -> None:
        r = XRayResult(passport_path="test", overall_grade="C")
        assert r.exit_code == 1

    def test_exit_code_f_is_2(self) -> None:
        r = XRayResult(passport_path="test", overall_grade="F")
        assert r.exit_code == 2


class TestXRayReport:
    def test_html_report(self, tmp_path: Path) -> None:
        passport = _make_passport()
        path = _write_passport(tmp_path, passport)
        result = xray_passport(path)

        from assay.reporting.xray_report import render_xray_html
        html_text = render_xray_html(result)
        assert "<!DOCTYPE html>" in html_text
        assert "X-Ray" in html_text
        assert result.overall_grade in html_text
