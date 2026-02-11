"""Tests for the Completeness Contract: coverage.py + check integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.coverage import (
    CoverageContract,
    ContractSite,
    compute_callsite_id,
    verify_coverage,
)
from assay.scanner import CallSite, Confidence, ScanResult


# ---------------------------------------------------------------------------
# compute_callsite_id
# ---------------------------------------------------------------------------

class TestCallsiteId:
    def test_deterministic(self):
        id1 = compute_callsite_id("src/app.py", 42)
        id2 = compute_callsite_id("src/app.py", 42)
        assert id1 == id2

    def test_length_is_12(self):
        cid = compute_callsite_id("src/app.py", 42)
        assert len(cid) == 12

    def test_hex_chars_only(self):
        cid = compute_callsite_id("src/app.py", 42)
        assert all(c in "0123456789abcdef" for c in cid)

    def test_different_line_different_id(self):
        id1 = compute_callsite_id("src/app.py", 42)
        id2 = compute_callsite_id("src/app.py", 43)
        assert id1 != id2

    def test_different_file_different_id(self):
        id1 = compute_callsite_id("src/app.py", 42)
        id2 = compute_callsite_id("src/other.py", 42)
        assert id1 != id2


# ---------------------------------------------------------------------------
# CoverageContract.from_scan_result
# ---------------------------------------------------------------------------

def _make_scan_result(*findings):
    return ScanResult(findings=list(findings))


def _site(path, line, call, confidence, instrumented=False):
    return CallSite(
        path=path, line=line, call=call,
        confidence=confidence, instrumented=instrumented,
    )


class TestCoverageContractFromScan:
    def test_excludes_low_by_default(self):
        result = _make_scan_result(
            _site("a.py", 1, "client.create()", Confidence.HIGH),
            _site("b.py", 2, "llm_call()", Confidence.LOW),
        )
        contract = CoverageContract.from_scan_result(result)
        assert len(contract.call_sites) == 1
        assert contract.call_sites[0].path == "a.py"

    def test_includes_low_with_flag(self):
        result = _make_scan_result(
            _site("a.py", 1, "client.create()", Confidence.HIGH),
            _site("b.py", 2, "llm_call()", Confidence.LOW),
        )
        contract = CoverageContract.from_scan_result(result, include_low=True)
        assert len(contract.call_sites) == 2

    def test_includes_medium(self):
        result = _make_scan_result(
            _site("a.py", 1, ".invoke()", Confidence.MEDIUM),
        )
        contract = CoverageContract.from_scan_result(result)
        assert len(contract.call_sites) == 1
        assert contract.call_sites[0].confidence == "medium"

    def test_callsite_ids_match_compute(self):
        result = _make_scan_result(
            _site("src/app.py", 42, "client.create()", Confidence.HIGH),
        )
        contract = CoverageContract.from_scan_result(result)
        expected_id = compute_callsite_id("src/app.py", 42)
        assert contract.call_sites[0].callsite_id == expected_id

    def test_empty_scan_result(self):
        result = _make_scan_result()
        contract = CoverageContract.from_scan_result(result)
        assert len(contract.call_sites) == 0


# ---------------------------------------------------------------------------
# CoverageContract hash + serialization
# ---------------------------------------------------------------------------

class TestCoverageContractHash:
    def test_hash_is_deterministic(self):
        result = _make_scan_result(
            _site("a.py", 1, "create()", Confidence.HIGH),
            _site("b.py", 2, "create()", Confidence.HIGH),
        )
        c1 = CoverageContract.from_scan_result(result)
        c2 = CoverageContract.from_scan_result(result)
        assert c1.contract_hash == c2.contract_hash

    def test_different_sites_different_hash(self):
        r1 = _make_scan_result(_site("a.py", 1, "create()", Confidence.HIGH))
        r2 = _make_scan_result(_site("b.py", 1, "create()", Confidence.HIGH))
        c1 = CoverageContract.from_scan_result(r1)
        c2 = CoverageContract.from_scan_result(r2)
        assert c1.contract_hash != c2.contract_hash

    def test_summary_counts(self):
        result = _make_scan_result(
            _site("a.py", 1, "create()", Confidence.HIGH),
            _site("b.py", 2, ".invoke()", Confidence.MEDIUM),
            _site("c.py", 3, ".invoke()", Confidence.MEDIUM),
        )
        contract = CoverageContract.from_scan_result(result)
        s = contract.summary
        assert s["total_sites"] == 3
        assert s["high"] == 1
        assert s["medium"] == 2


class TestCoverageContractRoundTrip:
    def test_write_load_roundtrip(self, tmp_path):
        result = _make_scan_result(
            _site("src/app.py", 10, "client.create()", Confidence.HIGH),
            _site("src/worker.py", 20, ".invoke()", Confidence.MEDIUM),
        )
        original = CoverageContract.from_scan_result(result, project_root="/tmp/test")
        path = tmp_path / "contract.json"
        original.write(path)

        loaded = CoverageContract.load(path)
        assert len(loaded.call_sites) == 2
        assert loaded.contract_hash == original.contract_hash
        assert loaded.project_root == "/tmp/test"

    def test_load_detects_tamper(self, tmp_path):
        result = _make_scan_result(
            _site("a.py", 1, "create()", Confidence.HIGH),
        )
        contract = CoverageContract.from_scan_result(result)
        path = tmp_path / "contract.json"
        contract.write(path)

        # Tamper: change a callsite_id
        data = json.loads(path.read_text())
        data["call_sites"][0]["callsite_id"] = "tampered12ab"
        path.write_text(json.dumps(data))

        with pytest.raises(ValueError, match="tampered"):
            CoverageContract.load(path)

    def test_to_dict_has_required_fields(self):
        contract = CoverageContract(call_sites=[], generated_at="2026-01-01T00:00:00")
        d = contract.to_dict()
        assert d["contract_version"] == "1.0"
        assert d["generated_by"] == "assay-scan"
        assert "contract_hash" in d
        assert "summary" in d
        assert "call_sites" in d


# ---------------------------------------------------------------------------
# verify_coverage
# ---------------------------------------------------------------------------

class TestVerifyCoverage:
    def _contract(self, *ids):
        """Helper: contract with given callsite_ids."""
        sites = [
            ContractSite(
                callsite_id=cid, path=f"{cid}.py", line=1,
                call="create()", confidence="high", instrumented=False,
            )
            for cid in ids
        ]
        return CoverageContract(call_sites=sites)

    def _receipts(self, *ids):
        """Helper: receipts with given callsite_ids."""
        return [
            {"receipt_id": f"r_{cid}", "type": "model_call", "callsite_id": cid}
            for cid in ids
        ]

    def test_full_coverage(self):
        contract = self._contract("aaa", "bbb", "ccc")
        receipts = self._receipts("aaa", "bbb", "ccc")
        result = verify_coverage(contract, receipts)
        assert result["coverage_pct"] == 1.0
        assert result["covered_count"] == 3
        assert result["total_count"] == 3
        assert result["uncovered_ids"] == []

    def test_partial_coverage(self):
        contract = self._contract("aaa", "bbb", "ccc")
        receipts = self._receipts("aaa")
        result = verify_coverage(contract, receipts)
        assert abs(result["coverage_pct"] - 1 / 3) < 0.01
        assert result["covered_count"] == 1
        assert sorted(result["uncovered_ids"]) == ["bbb", "ccc"]

    def test_zero_coverage(self):
        contract = self._contract("aaa", "bbb")
        receipts = self._receipts("xxx")  # no match
        result = verify_coverage(contract, receipts)
        assert result["coverage_pct"] == 0.0
        assert result["covered_count"] == 0

    def test_empty_contract_is_vacuous_pass(self):
        contract = self._contract()  # no sites
        receipts = self._receipts("aaa")
        result = verify_coverage(contract, receipts)
        assert result["coverage_pct"] == 1.0
        assert result["total_count"] == 0

    def test_extra_ids_tracked(self):
        contract = self._contract("aaa")
        receipts = self._receipts("aaa", "xxx", "yyy")
        result = verify_coverage(contract, receipts)
        assert result["coverage_pct"] == 1.0
        assert sorted(result["extra_ids"]) == ["xxx", "yyy"]

    def test_receipts_without_callsite_id_ignored(self):
        contract = self._contract("aaa")
        receipts = [
            {"receipt_id": "r1", "type": "model_call"},  # no callsite_id
            {"receipt_id": "r2", "type": "model_call", "callsite_id": "aaa"},
        ]
        result = verify_coverage(contract, receipts)
        assert result["coverage_pct"] == 1.0
        assert result["covered_count"] == 1


# ---------------------------------------------------------------------------
# check_coverage_contract (claim system integration)
# ---------------------------------------------------------------------------

class TestCheckCoverageContract:
    @pytest.fixture
    def contract_file(self, tmp_path):
        """Write a contract with 2 sites and return the path."""
        result = _make_scan_result(
            _site("a.py", 10, "create()", Confidence.HIGH),
            _site("b.py", 20, "create()", Confidence.HIGH),
        )
        contract = CoverageContract.from_scan_result(result)
        path = tmp_path / "assay.coverage.json"
        contract.write(path)
        return path, contract

    def test_passes_at_threshold(self, contract_file):
        from assay.claim_verifier import CHECKS
        path, contract = contract_file
        id_a = compute_callsite_id("a.py", 10)
        id_b = compute_callsite_id("b.py", 20)
        receipts = [
            {"receipt_id": "r1", "type": "model_call", "callsite_id": id_a},
            {"receipt_id": "r2", "type": "model_call", "callsite_id": id_b},
        ]
        result = CHECKS["coverage_contract"](
            receipts, claim_id="test", contract_path=str(path), min_coverage=1.0,
        )
        assert result.passed

    def test_fails_below_threshold(self, contract_file):
        from assay.claim_verifier import CHECKS
        path, contract = contract_file
        id_a = compute_callsite_id("a.py", 10)
        receipts = [
            {"receipt_id": "r1", "type": "model_call", "callsite_id": id_a},
        ]
        result = CHECKS["coverage_contract"](
            receipts, claim_id="test", contract_path=str(path), min_coverage=0.8,
        )
        assert not result.passed
        assert "50%" in result.actual

    def test_missing_contract_file_fails(self):
        from assay.claim_verifier import CHECKS
        result = CHECKS["coverage_contract"](
            [], claim_id="test", contract_path="/nonexistent/contract.json",
        )
        assert not result.passed

    def test_corrupt_contract_file_fails(self, tmp_path):
        from assay.claim_verifier import CHECKS
        path = tmp_path / "bad.json"
        path.write_text("not json")
        result = CHECKS["coverage_contract"](
            [], claim_id="test", contract_path=str(path),
        )
        assert not result.passed
