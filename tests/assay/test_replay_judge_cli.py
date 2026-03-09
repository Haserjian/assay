"""Tests for replay-judge CLI command and verdict boundary invariants."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from assay._receipts.canonicalize import to_jcs_bytes
from assay.claim_verifier import ClaimSpec
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.replay_judge import (
    ReplayJudgeResult,
    write_replay_judgment,
)


_TS = "2026-03-09T12:00:00Z"


def _make_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(tmp_path / "keys")
    ks.generate_key("test-signer")
    return ks


def _make_receipt(
    *,
    receipt_id: str,
    receipt_type: str = "model_call",
    timestamp: str = _TS,
) -> Dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "type": receipt_type,
        "timestamp": timestamp,
        "schema_version": "3.0",
        "provider": "openai",
        "model_id": "gpt-4o",
    }


def _build_pack(
    tmp_path: Path,
    ks: AssayKeyStore,
    *,
    output_name: str,
    run_id: str = "run-001",
    pack_id: str = "pack_001",
    entries: Optional[List[Dict[str, Any]]] = None,
    claims: Optional[List[ClaimSpec]] = None,
    policy_hash: Optional[str] = None,
    emit_adc: bool = True,
    claim_namespace: str = "assay:replay:v0.1",
) -> Path:
    pack = ProofPack(
        run_id=run_id,
        entries=entries or [_make_receipt(receipt_id=f"{output_name}-r1")],
        claims=claims,
        emit_adc=emit_adc,
        signer_id="test-signer",
        suite_id="replay_suite_v1",
        claim_set_id="replay_claims_v1",
        policy_hash=policy_hash or ("a" * 64),
        claim_namespace=claim_namespace,
    )
    return pack.build(
        tmp_path / output_name,
        keystore=ks,
        pack_id=pack_id,
        deterministic_ts=_TS,
    )


def _identical_packs(tmp_path, ks):
    """Build two identical packs with shared receipts."""
    entries = [_make_receipt(receipt_id="shared-r1")]
    expected = _build_pack(
        tmp_path, ks,
        output_name="expected",
        run_id="run-same",
        pack_id="pack_same",
        entries=entries,
    )
    observed = _build_pack(
        tmp_path, ks,
        output_name="observed",
        run_id="run-same",
        pack_id="pack_same",
        entries=entries,
    )
    return expected, observed


# ---------------------------------------------------------------------------
# write_replay_judgment (path-based writer)
# ---------------------------------------------------------------------------

class TestWriteReplayJudgment:

    def test_writes_both_files(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)
        out = tmp_path / "output"

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=out,
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.judgment_path.exists()
        assert result.trace_path.exists()
        assert result.judgment_path.name == "replay_judgment.json"
        assert result.trace_path.name == "replay_explanation_trace.json"

    def test_reproducible_exit_code_0(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "reproducible"
        assert result.exit_code == 0

    def test_drifted_exit_code_1(self, tmp_path):
        ks = _make_keystore(tmp_path)
        claims = [
            ClaimSpec(
                claim_id="model_call_present",
                description="model_call receipts exist",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            )
        ]
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            run_id="run-orig",
            pack_id="pack_orig",
            claims=claims,
            entries=[_make_receipt(receipt_id="orig-r1", receipt_type="model_call")],
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            run_id="run-replay",
            pack_id="pack_replay",
            claims=claims,
            entries=[_make_receipt(receipt_id="replay-r1", receipt_type="tool_call")],
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "drifted"
        assert result.exit_code == 1

    def test_unverifiable_exit_code_2(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            entries=[_make_receipt(receipt_id="e-r1")],
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            entries=[_make_receipt(receipt_id="o-r1")],
            emit_adc=False,
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "unverifiable"
        assert result.exit_code == 2

    def test_overwrite_false_raises_on_existing(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)
        out = tmp_path / "output"

        write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=out,
            keystore=ks,
            signer_id="test-signer",
        )

        with pytest.raises(FileExistsError):
            write_replay_judgment(
                expected_pack_dir=expected,
                observed_pack_dir=observed,
                out_dir=out,
                keystore=ks,
                signer_id="test-signer",
                overwrite=False,
            )

    def test_overwrite_true_succeeds(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)
        out = tmp_path / "output"

        write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=out,
            keystore=ks,
            signer_id="test-signer",
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=out,
            keystore=ks,
            signer_id="test-signer",
            overwrite=True,
        )
        assert result.verdict == "reproducible"

    def test_pretty_indents_json(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
            pretty=True,
        )

        raw = result.judgment_path.read_text()
        assert "\n  " in raw  # indented

    def test_compact_without_pretty(self, tmp_path):
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
            pretty=False,
        )

        raw = result.judgment_path.read_text()
        # Compact JSON is a single line
        assert raw.count("\n") <= 1


# ---------------------------------------------------------------------------
# Verdict boundary invariants
# ---------------------------------------------------------------------------

class TestVerdictBoundaryInvariants:
    """Freeze the verdict classification contract.

    These tests exist to prevent accidental reclassification of verdicts.
    If any of these fail after a code change, the change has altered the
    constitutional boundary between reproducible/drifted/unverifiable.
    """

    def test_evidence_binding_failure_is_unverifiable_never_drifted(self, tmp_path):
        """Evidence binding mismatch must map to unverifiable, not drifted."""
        ks = _make_keystore(tmp_path)
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            policy_hash="a" * 64,
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            policy_hash="b" * 64,
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "unverifiable"
        assert result.verdict != "drifted"

    def test_missing_adc_is_unverifiable_never_drifted(self, tmp_path):
        """Missing ADC must map to unverifiable, not drifted."""
        ks = _make_keystore(tmp_path)
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            emit_adc=False,
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "unverifiable"

    def test_claim_result_mismatch_is_drifted(self, tmp_path):
        """Semantic result disagreement maps to drifted, not unverifiable."""
        ks = _make_keystore(tmp_path)
        claims = [
            ClaimSpec(
                claim_id="has_model_call",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            )
        ]
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            run_id="run-a",
            pack_id="pack_a",
            claims=claims,
            entries=[_make_receipt(receipt_id="a-r1", receipt_type="model_call")],
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            run_id="run-b",
            pack_id="pack_b",
            claims=claims,
            entries=[_make_receipt(receipt_id="b-r1", receipt_type="tool_call")],
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "drifted"

    def test_identical_semantic_outcomes_is_reproducible(self, tmp_path):
        """Same policy, same claims, same results = reproducible."""
        ks = _make_keystore(tmp_path)
        entries = [_make_receipt(receipt_id="shared-r1")]
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            run_id="run-same",
            pack_id="pack_same",
            entries=entries,
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            run_id="run-same",
            pack_id="pack_same",
            entries=entries,
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "reproducible"

    def test_deterministic_ids_across_repeated_runs(self, tmp_path):
        """Same inputs produce same judgment_id."""
        ks = _make_keystore(tmp_path)
        entries = [_make_receipt(receipt_id="shared-r1")]
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            run_id="run-same",
            pack_id="pack_same",
            entries=entries,
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            run_id="run-same",
            pack_id="pack_same",
            entries=entries,
        )

        r1 = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "out1",
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )
        r2 = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "out2",
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert r1.judgment_id == r2.judgment_id

    def test_explanation_trace_excludes_evidence_blobs(self, tmp_path):
        """Explanation trace must not contain raw receipt data."""
        ks = _make_keystore(tmp_path)
        expected, observed = _identical_packs(tmp_path, ks)

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
            pretty=True,
        )

        trace = json.loads(result.trace_path.read_text())
        trace_str = json.dumps(trace)
        assert "receipt_pack" not in trace_str
        assert "receipt_id" not in trace_str
        assert "model_call" not in trace_str

    def test_claim_binding_mismatch_is_unverifiable(self, tmp_path):
        """Different claim namespaces produce unverifiable, not drifted."""
        ks = _make_keystore(tmp_path)
        expected = _build_pack(
            tmp_path, ks,
            output_name="expected",
            claim_namespace="assay:ns_a:v1",
        )
        observed = _build_pack(
            tmp_path, ks,
            output_name="observed",
            claim_namespace="assay:ns_b:v1",
        )

        result = write_replay_judgment(
            expected_pack_dir=expected,
            observed_pack_dir=observed,
            out_dir=tmp_path / "output",
            keystore=ks,
            signer_id="test-signer",
        )

        assert result.verdict == "unverifiable"
