"""Tests for diff --against-previous and --why."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from typer.testing import CliRunner

from assay.diff import (
    ClaimDelta,
    DiffResult,
    PackInfo,
    WhyExplanation,
    _trace_chain,
    explain_why,
    find_previous_pack,
)
from assay import commands as assay_commands


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_receipt(
    receipt_id: str = "r_test",
    rtype: str = "model_call",
    model_id: str = "gpt-4o",
    parent_receipt_id: Optional[str] = None,
    schema_version: str = "3.0",
    **extra: Any,
) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "receipt_id": receipt_id,
        "type": rtype,
        "schema_version": schema_version,
        "model_id": model_id,
        "provider": "openai",
        "input_tokens": 1000,
        "output_tokens": 500,
        "total_tokens": 1500,
        "latency_ms": 800,
        "finish_reason": "stop",
        "timestamp": "2026-02-10T12:00:00Z",
    }
    if parent_receipt_id is not None:
        r["parent_receipt_id"] = parent_receipt_id
    r.update(extra)
    return r


def _write_pack(
    pack_dir: Path,
    receipts: list,
    claim_results: Optional[Dict[str, bool]] = None,
    claim_details: Optional[List[Dict[str, Any]]] = None,
    claim_set_hash: str = "abc123",
) -> Path:
    """Write a minimal pack structure for testing."""
    pack_dir.mkdir(parents=True, exist_ok=True)

    # receipt_pack.jsonl
    lines = [json.dumps(r) for r in receipts]
    (pack_dir / "receipt_pack.jsonl").write_text("\n".join(lines) + "\n")

    # pack_manifest.json
    manifest = {
        "pack_id": f"pack_{pack_dir.name}",
        "claim_set_hash": claim_set_hash,
        "signer_id": "test-signer",
        "signer_pubkey_sha256": "fp_aaa",
        "attestation": {
            "pack_id": f"pack_{pack_dir.name}",
            "receipt_integrity": "PASS",
            "claim_check": "PASS" if not claim_results or all(claim_results.values()) else "FAIL",
            "verifier_version": "1.4.2",
            "n_receipts": len(receipts),
            "timestamp_start": "2026-02-10T12:00:00Z",
            "timestamp_end": "2026-02-10T12:05:00Z",
        },
    }
    (pack_dir / "pack_manifest.json").write_text(json.dumps(manifest, indent=2))

    # verify_report.json
    report: Dict[str, Any] = {"status": "ok"}
    if claim_details is not None:
        report["claim_verification"] = {
            "passed": all(cd.get("passed", True) for cd in claim_details),
            "results": claim_details,
        }
    elif claim_results is not None:
        report["claim_verification"] = {
            "passed": all(claim_results.values()),
            "results": [
                {"claim_id": cid, "passed": passed, "expected": "", "actual": "", "severity": "critical"}
                for cid, passed in claim_results.items()
            ],
        }
    (pack_dir / "verify_report.json").write_text(json.dumps(report, indent=2))

    return pack_dir


# ---------------------------------------------------------------------------
# find_previous_pack
# ---------------------------------------------------------------------------

class TestFindPreviousPack:
    def test_finds_previous(self, tmp_path: Path) -> None:
        """Returns the chronologically previous pack."""
        pack_old = _write_pack(tmp_path / "proof_pack_old", [_make_receipt()])
        time.sleep(0.05)  # ensure distinct mtime
        pack_new = _write_pack(tmp_path / "proof_pack_new", [_make_receipt()])

        result = find_previous_pack(pack_new)
        assert result is not None
        assert result.resolve() == pack_old.resolve()

    def test_no_previous_for_oldest(self, tmp_path: Path) -> None:
        """Oldest pack has no previous."""
        pack_old = _write_pack(tmp_path / "proof_pack_old", [_make_receipt()])
        time.sleep(0.05)
        _write_pack(tmp_path / "proof_pack_new", [_make_receipt()])

        result = find_previous_pack(pack_old)
        assert result is None

    def test_single_pack_returns_none(self, tmp_path: Path) -> None:
        """Only one pack -> no previous."""
        pack = _write_pack(tmp_path / "proof_pack_only", [_make_receipt()])
        assert find_previous_pack(pack) is None

    def test_ignores_dirs_without_manifest(self, tmp_path: Path) -> None:
        """Directories without pack_manifest.json are skipped."""
        (tmp_path / "proof_pack_orphan").mkdir()  # No manifest
        pack_real = _write_pack(tmp_path / "proof_pack_real", [_make_receipt()])
        assert find_previous_pack(pack_real) is None

    def test_ignores_non_proof_pack_dirs(self, tmp_path: Path) -> None:
        """Only considers proof_pack_* directories."""
        other = tmp_path / "some_other_dir"
        other.mkdir()
        (other / "pack_manifest.json").write_text("{}")

        pack = _write_pack(tmp_path / "proof_pack_one", [_make_receipt()])
        assert find_previous_pack(pack) is None

    def test_three_packs_finds_immediate_predecessor(self, tmp_path: Path) -> None:
        """With 3 packs, finds the one right before current."""
        _write_pack(tmp_path / "proof_pack_1", [_make_receipt()])
        time.sleep(0.05)
        pack_mid = _write_pack(tmp_path / "proof_pack_2", [_make_receipt()])
        time.sleep(0.05)
        pack_new = _write_pack(tmp_path / "proof_pack_3", [_make_receipt()])

        result = find_previous_pack(pack_new)
        assert result is not None
        assert result.resolve() == pack_mid.resolve()


# ---------------------------------------------------------------------------
# _trace_chain
# ---------------------------------------------------------------------------

class TestTraceChain:
    def test_single_receipt_no_parent(self) -> None:
        """Receipt without parent_receipt_id returns chain of 1."""
        index = {"r1": {"receipt_id": "r1", "type": "model_call"}}
        chain = _trace_chain("r1", index)
        assert len(chain) == 1
        assert chain[0]["receipt_id"] == "r1"

    def test_two_receipt_chain(self) -> None:
        """Two receipts linked by parent_receipt_id."""
        index = {
            "r1": {"receipt_id": "r1", "type": "model_call"},
            "r2": {"receipt_id": "r2", "type": "guardian_verdict", "parent_receipt_id": "r1"},
        }
        chain = _trace_chain("r2", index)
        assert len(chain) == 2
        assert chain[0]["receipt_id"] == "r2"
        assert chain[1]["receipt_id"] == "r1"

    def test_three_deep_chain(self) -> None:
        """Three-level causal chain."""
        index = {
            "r1": {"receipt_id": "r1", "type": "model_call"},
            "r2": {"receipt_id": "r2", "type": "guardian_verdict", "parent_receipt_id": "r1"},
            "r3": {"receipt_id": "r3", "type": "escalation", "parent_receipt_id": "r2"},
        }
        chain = _trace_chain("r3", index)
        assert len(chain) == 3
        assert [r["receipt_id"] for r in chain] == ["r3", "r2", "r1"]

    def test_missing_parent_stops(self) -> None:
        """Chain stops when parent not in index."""
        index = {
            "r2": {"receipt_id": "r2", "type": "test", "parent_receipt_id": "r_missing"},
        }
        chain = _trace_chain("r2", index)
        assert len(chain) == 1

    def test_cycle_detection(self) -> None:
        """Cycle in parent chain doesn't infinite loop."""
        index = {
            "r1": {"receipt_id": "r1", "type": "a", "parent_receipt_id": "r2"},
            "r2": {"receipt_id": "r2", "type": "b", "parent_receipt_id": "r1"},
        }
        chain = _trace_chain("r1", index)
        assert len(chain) == 2  # r1 -> r2, then stops (r1 already seen)

    def test_unknown_start(self) -> None:
        """Starting from unknown receipt returns empty chain."""
        chain = _trace_chain("r_unknown", {})
        assert chain == []


# ---------------------------------------------------------------------------
# explain_why
# ---------------------------------------------------------------------------

class TestExplainWhy:
    def test_no_regression_returns_empty(self, tmp_path: Path) -> None:
        """No regressed claims -> empty list."""
        pack_b = _write_pack(tmp_path / "proof_pack_b", [_make_receipt()])
        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
            claim_deltas=[
                ClaimDelta(claim_id="c1", a_passed=True, b_passed=True),
            ],
        )
        assert explain_why(result, pack_b) == []

    def test_regression_with_evidence(self, tmp_path: Path) -> None:
        """Regressed claim returns explanation with evidence IDs."""
        receipts = [
            _make_receipt(receipt_id="r1", schema_version="3.0"),
            _make_receipt(receipt_id="r2", schema_version="2.0"),  # the mismatch
        ]
        pack_b = _write_pack(
            tmp_path / "proof_pack_b",
            receipts,
            claim_details=[{
                "claim_id": "schema_version_consistent",
                "passed": False,
                "expected": "all 'model_call' receipts: schema_version='3.0'",
                "actual": "1 mismatches out of 2",
                "severity": "warning",
                "evidence_receipt_ids": ["r2"],
            }],
        )

        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
            claim_deltas=[
                ClaimDelta(claim_id="schema_version_consistent", a_passed=True, b_passed=False, regressed=True),
            ],
        )

        explanations = explain_why(result, pack_b)
        assert len(explanations) == 1
        w = explanations[0]
        assert w.claim_id == "schema_version_consistent"
        assert w.evidence_receipt_ids == ["r2"]
        assert "1 mismatches" in w.actual

    def test_regression_with_causal_chain(self, tmp_path: Path) -> None:
        """Evidence receipt with parent_receipt_id produces causal chain."""
        receipts = [
            _make_receipt(receipt_id="r1"),
            _make_receipt(receipt_id="r2", rtype="guardian_verdict",
                          parent_receipt_id="r1", schema_version="2.0"),
        ]
        pack_b = _write_pack(
            tmp_path / "proof_pack_b",
            receipts,
            claim_details=[{
                "claim_id": "schema_version_consistent",
                "passed": False,
                "expected": "schema_version='3.0'",
                "actual": "1 mismatch",
                "severity": "warning",
                "evidence_receipt_ids": ["r2"],
            }],
        )

        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
            claim_deltas=[
                ClaimDelta(claim_id="schema_version_consistent", a_passed=True, b_passed=False, regressed=True),
            ],
        )

        explanations = explain_why(result, pack_b)
        assert len(explanations) == 1
        w = explanations[0]
        assert len(w.causal_chains) == 1
        chain = w.causal_chains[0]
        assert chain[0]["receipt_id"] == "r2"
        assert chain[1]["receipt_id"] == "r1"

    def test_to_dict(self, tmp_path: Path) -> None:
        """WhyExplanation serializes to dict correctly."""
        w = WhyExplanation(
            claim_id="c1",
            expected="all pass",
            actual="1 fail",
            evidence_receipt_ids=["r1"],
            causal_chains=[[
                {"receipt_id": "r1", "type": "model_call", "parent_receipt_id": None},
            ]],
        )
        d = w.to_dict()
        assert d["claim_id"] == "c1"
        assert d["evidence_receipt_ids"] == ["r1"]
        assert len(d["causal_chains"]) == 1

    def test_no_verify_report(self, tmp_path: Path) -> None:
        """Missing verify_report.json still returns explanations (empty detail)."""
        pack_b = tmp_path / "proof_pack_b"
        pack_b.mkdir()
        (pack_b / "pack_manifest.json").write_text("{}")
        (pack_b / "receipt_pack.jsonl").write_text("")

        result = DiffResult(
            pack_a=PackInfo(path="a"),
            pack_b=PackInfo(path="b"),
            claim_deltas=[
                ClaimDelta(claim_id="c1", a_passed=True, b_passed=False, regressed=True),
            ],
        )

        explanations = explain_why(result, pack_b)
        assert len(explanations) == 1
        assert explanations[0].expected == ""
        assert explanations[0].evidence_receipt_ids == []


# ---------------------------------------------------------------------------
# CLI integration: --against-previous
# ---------------------------------------------------------------------------

class TestAgainstPreviousCLI:
    def test_against_previous_basic(self, tmp_path: Path) -> None:
        """--against-previous auto-discovers baseline and runs diff."""
        r = _make_receipt(receipt_id="r1")
        _write_pack(tmp_path / "proof_pack_old", [r])
        time.sleep(0.05)
        _write_pack(tmp_path / "proof_pack_new", [r])

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_new"), "--against-previous", "--no-verify", "--json"],
        )
        data = json.loads(result.output)
        assert data["command"] == "diff"

    def test_against_previous_no_baseline(self, tmp_path: Path) -> None:
        """Error when no previous pack exists."""
        _write_pack(tmp_path / "proof_pack_only", [_make_receipt()])

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_only"), "--against-previous"],
        )
        assert result.exit_code == 3
        assert "No baseline found" in result.output

    def test_against_previous_with_two_args_errors(self, tmp_path: Path) -> None:
        """Error when --against-previous used with two pack args."""
        _write_pack(tmp_path / "proof_pack_a", [_make_receipt()])
        _write_pack(tmp_path / "proof_pack_b", [_make_receipt()])

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_a"), str(tmp_path / "proof_pack_b"), "--against-previous"],
        )
        assert result.exit_code == 3
        assert "one pack argument" in result.output

    def test_no_args_no_flag_errors(self, tmp_path: Path) -> None:
        """Single pack arg without --against-previous errors."""
        _write_pack(tmp_path / "proof_pack_one", [_make_receipt()])

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_one")],
        )
        assert result.exit_code == 3
        assert "Two pack arguments required" in result.output


# ---------------------------------------------------------------------------
# CLI integration: --why
# ---------------------------------------------------------------------------

class TestWhyCLI:
    def test_why_json_output(self, tmp_path: Path) -> None:
        """--why adds 'why' key to JSON output on regression."""
        r1 = _make_receipt(receipt_id="r1", schema_version="3.0")
        r2 = _make_receipt(receipt_id="r2", schema_version="2.0")

        _write_pack(
            tmp_path / "proof_pack_a", [r1],
            claim_results={"schema_version_consistent": True},
        )
        _write_pack(
            tmp_path / "proof_pack_b", [r1, r2],
            claim_details=[{
                "claim_id": "schema_version_consistent",
                "passed": False,
                "expected": "schema_version='3.0'",
                "actual": "1 mismatch",
                "severity": "warning",
                "evidence_receipt_ids": ["r2"],
            }],
        )

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_a"), str(tmp_path / "proof_pack_b"),
             "--why", "--no-verify", "--json"],
        )
        data = json.loads(result.output)
        assert "why" in data
        assert len(data["why"]) == 1
        assert data["why"][0]["claim_id"] == "schema_version_consistent"

    def test_why_no_regression_no_output(self, tmp_path: Path) -> None:
        """--why with no regression doesn't add 'why' to output."""
        r = _make_receipt(receipt_id="r1")
        _write_pack(tmp_path / "proof_pack_a", [r], claim_results={"c1": True})
        _write_pack(tmp_path / "proof_pack_b", [r], claim_results={"c1": True})

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_a"), str(tmp_path / "proof_pack_b"),
             "--why", "--no-verify", "--json"],
        )
        data = json.loads(result.output)
        assert "why" not in data

    def test_why_with_against_previous(self, tmp_path: Path) -> None:
        """--why + --against-previous work together."""
        r1 = _make_receipt(receipt_id="r1")
        _write_pack(
            tmp_path / "proof_pack_old", [r1],
            claim_results={"c1": True},
        )
        time.sleep(0.05)
        _write_pack(
            tmp_path / "proof_pack_new", [r1],
            claim_details=[{
                "claim_id": "c1",
                "passed": False,
                "expected": "pass",
                "actual": "fail",
                "severity": "critical",
                "evidence_receipt_ids": ["r1"],
            }],
            claim_results={"c1": False},
        )

        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            ["diff", str(tmp_path / "proof_pack_new"),
             "--against-previous", "--why", "--no-verify", "--json"],
        )
        data = json.loads(result.output)
        assert data["command"] == "diff"
        assert "why" in data
