"""Tests for replay judge v0.1."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.canonicalize import to_jcs_bytes
from assay.claim_verifier import ClaimSpec
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.replay_judge import (
    build_explanation_trace,
    judge_replay,
    validate_explanation_trace,
    validate_replay_judgment,
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
    schema_version: str = "3.0",
) -> Dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "type": receipt_type,
        "timestamp": timestamp,
        "schema_version": schema_version,
        "provider": "openai",
        "model_id": "gpt-4o",
    }


def _build_pack(
    tmp_path: Path,
    ks: AssayKeyStore,
    *,
    output_name: str,
    run_id: str,
    pack_id: str,
    entries: Optional[List[Dict[str, Any]]] = None,
    claims: Optional[List[ClaimSpec]] = None,
    policy_hash: Optional[str] = None,
    emit_adc: bool = True,
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
        claim_namespace="assay:replay:v0.1",
    )
    return pack.build(
        tmp_path / output_name,
        keystore=ks,
        pack_id=pack_id,
        deterministic_ts=_TS,
    )


class TestReplayJudge:
    def test_reproducible_for_matching_adc_and_pack(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        entries = [_make_receipt(receipt_id="shared-r1")]
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-same",
            pack_id="pack_same",
            entries=entries,
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-same",
            pack_id="pack_same",
            entries=entries,
        )

        judgment, trace = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert judgment["verdict"] == "reproducible"
        assert judgment["comparison"]["logical_equivalent"] is True
        assert judgment["comparison"]["byte_equivalent"] is True
        assert judgment["divergence_reasons"] == []
        assert trace["verdict"] == "reproducible"

    def test_drifted_when_claim_results_change(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        claims = [
            ClaimSpec(
                claim_id="model_call_present",
                description="At least one model_call receipt exists",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            )
        ]
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-orig",
            pack_id="pack_orig",
            claims=claims,
            entries=[_make_receipt(receipt_id="orig-r1", receipt_type="model_call")],
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-replay",
            pack_id="pack_replay",
            claims=claims,
            entries=[_make_receipt(receipt_id="replay-r1", receipt_type="tool_call")],
        )

        judgment, trace = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert judgment["verdict"] == "drifted"
        assert "overall_result_mismatch" in judgment["divergence_reasons"]
        assert "claim_results_mismatch" in judgment["divergence_reasons"]
        assert trace["drivers"]["divergence_fields"] == ["claim_results", "overall_result"] or trace["drivers"]["divergence_fields"] == ["overall_result", "claim_results"]

    def test_unverifiable_when_replay_adc_missing(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-orig",
            pack_id="pack_orig",
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-replay",
            pack_id="pack_replay",
            emit_adc=False,
        )

        judgment, trace = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert judgment["verdict"] == "unverifiable"
        assert "missing_decision_credential" in judgment["divergence_reasons"]
        assert trace["verdict"] == "unverifiable"

    def test_unverifiable_when_policy_hash_mismatches(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-orig",
            pack_id="pack_orig",
            policy_hash="a" * 64,
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-replay",
            pack_id="pack_replay",
            policy_hash="b" * 64,
        )

        judgment, _ = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert judgment["verdict"] == "unverifiable"
        assert "policy_mismatch" in judgment["divergence_reasons"]

    def test_judgment_signature_verifies(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-same",
            pack_id="pack_same",
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-same",
            pack_id="pack_same",
        )

        judgment, _ = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        canonical = to_jcs_bytes({k: v for k, v in judgment.items() if k != "signature"})
        signature = base64.b64decode(judgment["signature"])
        ks.get_verify_key("test-signer").verify(canonical, signature)

    def test_schema_validation_passes_for_judgment_and_trace(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-same",
            pack_id="pack_same",
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-same",
            pack_id="pack_same",
        )

        judgment, trace = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert validate_replay_judgment(judgment) == []
        assert validate_explanation_trace(trace) == []

    def test_explanation_trace_is_projection_not_reasoning_dump(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-same",
            pack_id="pack_same",
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-same",
            pack_id="pack_same",
        )

        judgment, _ = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )
        trace = build_explanation_trace(judgment)

        assert "signature" not in trace
        assert "reasoning" not in trace
        assert trace["drivers"]["claim_ids"] == ["pack_integrity"]
        assert trace["summary"]

    def test_end_to_end_bridge_binds_to_pack_roots(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-same",
            pack_id="pack_same",
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-same",
            pack_id="pack_same",
        )
        original_manifest = json.loads((original / "pack_manifest.json").read_text(encoding="utf-8"))
        replay_manifest = json.loads((replay / "pack_manifest.json").read_text(encoding="utf-8"))

        judgment, trace = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert judgment["original"]["pack_root_sha256"] == original_manifest["pack_root_sha256"]
        assert judgment["replay"]["pack_root_sha256"] == replay_manifest["pack_root_sha256"]
        assert trace["drivers"]["pack_roots"]["original"] == original_manifest["pack_root_sha256"]
        assert trace["drivers"]["pack_roots"]["replay"] == replay_manifest["pack_root_sha256"]

    def test_deterministic_judgment_id_for_same_inputs(self, tmp_path: Path) -> None:
        ks = _make_keystore(tmp_path)
        original = _build_pack(
            tmp_path,
            ks,
            output_name="original",
            run_id="run-same",
            pack_id="pack_same",
        )
        replay = _build_pack(
            tmp_path,
            ks,
            output_name="replay",
            run_id="run-same",
            pack_id="pack_same",
        )

        judgment_a, trace_a = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )
        judgment_b, trace_b = judge_replay(
            original,
            replay,
            keystore=ks,
            signer_id="test-signer",
            issued_at=_TS,
        )

        assert judgment_a["judgment_id"] == judgment_b["judgment_id"]
        assert judgment_a["signature"] == judgment_b["signature"]
        assert trace_a == trace_b