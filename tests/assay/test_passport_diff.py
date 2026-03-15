"""Tests for passport diff engine."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.passport_diff import (
    CoverageDelta,
    PassportClaimDelta,
    PassportDiffResult,
    diff_passports,
)


def _make_passport(**overrides) -> dict:
    base = {
        "passport_version": "0.1",
        "passport_id": "sha256:" + "a" * 64,
        "issued_at": "2026-03-14T00:00:00+00:00",
        "valid_until": "2026-04-13T00:00:00+00:00",
        "status": {"state": "FRESH", "reason": "ok"},
        "reliance": {"class": "R2", "label": "Signed, partial"},
        "subject": {"name": "TestApp", "system_id": "test.v1", "owner": "Test Inc."},
        "scope": {
            "in_scope": ["Feature A", "Feature B"],
            "not_covered": ["Feature C"],
            "not_observed": [],
            "not_concluded": [],
        },
        "claims": [
            {"claim_id": "C-001", "result": "pass", "assertion": "test1"},
            {"claim_id": "C-002", "result": "partial", "assertion": "test2"},
        ],
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
        "relationships": {"supersedes": None, "superseded_by": None},
    }
    base.update(overrides)
    return base


def _write(tmp_path: Path, passport: dict, name: str) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")
    return path


class TestDiffPassports:
    def test_identical_passports_exit_0(self, tmp_path: Path) -> None:
        p = _make_passport()
        a = _write(tmp_path, p, "a.json")
        b = _write(tmp_path, p, "b.json")
        result = diff_passports(a, b)
        assert result.exit_code == 0
        assert not result.has_regression

    def test_claim_regression_exit_1(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["claims"][0]["result"] = "fail"  # C-001: pass → fail
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.exit_code == 1
        assert result.has_regression
        regressed = [d for d in result.claim_deltas if d.status == "regressed"]
        assert len(regressed) == 1
        assert regressed[0].claim_id == "C-001"

    def test_claim_improvement(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["claims"][1]["result"] = "pass"  # C-002: partial → pass
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.exit_code == 0
        improved = [d for d in result.claim_deltas if d.status == "improved"]
        assert len(improved) == 1

    def test_new_claim_detected(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["claims"].append({"claim_id": "C-003", "result": "pass", "assertion": "new"})
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        new_claims = [d for d in result.claim_deltas if d.status == "new"]
        assert len(new_claims) == 1
        assert new_claims[0].claim_id == "C-003"

    def test_removed_claim_is_regression(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["claims"] = [pb["claims"][0]]  # remove C-002
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.has_regression
        removed = [d for d in result.claim_deltas if d.status == "removed"]
        assert len(removed) == 1

    def test_coverage_improvement(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["coverage"]["covered_total"] = 5
        pb["coverage"]["coverage_pct"] = 100
        for site in pb["coverage"]["call_sites"]:
            site["status"] = "covered"
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.coverage_delta is not None
        assert result.coverage_delta.status == "improved"
        assert result.exit_code == 0

    def test_coverage_regression(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["coverage"]["covered_total"] = 2
        pb["coverage"]["coverage_pct"] = 40
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.has_regression
        assert result.coverage_delta.status == "regressed"

    def test_reliance_upgrade(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["reliance"]["class"] = "R3"
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.reliance_changed
        assert result.exit_code == 0  # upgrade is not regression

    def test_reliance_downgrade_is_regression(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["reliance"]["class"] = "R0"
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.has_regression

    def test_supersession_chain(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pa["passport_id"] = "sha256:oldid"
        pb = _make_passport()
        pb["passport_id"] = "sha256:newid"
        pb["relationships"]["supersedes"] = "sha256:oldid"
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert result.is_supersession

    def test_scope_changes_detected(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["scope"]["in_scope"].append("Feature D")
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)
        assert "in_scope" in result.scope_changes
        assert "Feature D" in result.scope_changes["in_scope"]["added"]

    def test_bad_file_returns_integrity_error(self, tmp_path: Path) -> None:
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text("not json", encoding="utf-8")
        b.write_text("{}", encoding="utf-8")
        result = diff_passports(a, b)
        assert result.exit_code == 2
        assert result.integrity_error is not None

    def test_missing_file_returns_integrity_error(self, tmp_path: Path) -> None:
        result = diff_passports(
            tmp_path / "nonexistent_a.json",
            tmp_path / "nonexistent_b.json",
        )
        assert result.exit_code == 2


class TestDiffResultDataclass:
    def test_to_dict(self) -> None:
        result = PassportDiffResult(
            passport_a_id="sha256:a",
            passport_b_id="sha256:b",
            has_regression=False,
        )
        d = result.to_dict()
        assert d["passport_a_id"] == "sha256:a"
        assert d["exit_code"] == 0

    def test_claim_delta_to_dict(self) -> None:
        delta = PassportClaimDelta(
            claim_id="C-001",
            a_result="pass",
            b_result="fail",
            status="regressed",
        )
        d = delta.to_dict()
        assert d["status"] == "regressed"

    def test_coverage_delta_to_dict(self) -> None:
        delta = CoverageDelta(
            a_covered=3, a_total=5,
            b_covered=5, b_total=5,
            status="improved",
        )
        d = delta.to_dict()
        assert d["a_pct"] == 60
        assert d["b_pct"] == 100


class TestDiffReport:
    def test_html_report_renders(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["claims"][1]["result"] = "pass"
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)

        from assay.reporting.passport_diff_report import render_passport_diff_html
        html_text = render_passport_diff_html(result)
        assert "<!DOCTYPE html>" in html_text
        assert "Trust Diff" in html_text

    def test_regression_report(self, tmp_path: Path) -> None:
        pa = _make_passport()
        pb = _make_passport()
        pb["claims"][0]["result"] = "fail"
        a = _write(tmp_path, pa, "a.json")
        b = _write(tmp_path, pb, "b.json")
        result = diff_passports(a, b)

        from assay.reporting.passport_diff_report import render_passport_diff_html
        html_text = render_passport_diff_html(result)
        assert "Regression" in html_text
