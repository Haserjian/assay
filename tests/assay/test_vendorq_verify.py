from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.vendorq_compile import compile_answers_payload
from assay.vendorq_index import build_evidence_index
from assay.vendorq_lock import write_vendorq_lock
from assay.vendorq_verify import verify_answers_payload

runner = CliRunner()


def _build_pack(tmp_path: Path, ts: str | None = None) -> Path:
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("vendorq-verify")
    receipts = [
        {
            "receipt_id": "r1",
            "type": "model_call",
            "timestamp": ts or datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "model_id": "gpt-4",
            "provider": "openai",
            "input_tokens": 7,
            "output_tokens": 3,
            "total_tokens": 10,
        }
    ]
    pack = ProofPack(run_id="vendorq-verify-run", entries=receipts, signer_id="vendorq-verify")
    return pack.build(tmp_path / "pack", keystore=ks)


def _base_answers_and_index(tmp_path: Path):
    pack_dir = _build_pack(tmp_path)
    idx = build_evidence_index([pack_dir])
    questions = {
        "schema_version": "vendorq.question.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "test",
        "questions": [{"question_id": "Q1", "question_text": "Provide process evidence.", "type_hint": "free_text", "required_format": "text"}],
        "questions_hash": "2" * 64,
    }
    answers = compile_answers_payload(questions, idx, "conservative")
    return pack_dir, idx, answers


def _first_code(report: dict) -> str:
    assert report["errors"], report
    return report["errors"][0]["code"]


def test_vendorq_verify_cli_pass(tmp_path: Path) -> None:
    pack_dir, idx, answers = _base_answers_and_index(tmp_path)

    a_path = tmp_path / "answers.json"
    a_path.write_text(json.dumps(answers))

    lock_path = tmp_path / "vendorq.lock"
    write_vendorq_lock(answers, idx, lock_path)

    r = runner.invoke(
        assay_app,
        [
            "vendorq", "verify",
            "--answers", str(a_path),
            "--pack", str(pack_dir),
            "--lock", str(lock_path),
            "--strict",
            "--json",
        ],
    )
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["status"] == "ok"


def test_vendorq_verify_cli_missing_pack_exit_3(tmp_path: Path) -> None:
    _pack_dir, _idx, answers = _base_answers_and_index(tmp_path)
    a_path = tmp_path / "answers.json"
    a_path.write_text(json.dumps(answers))

    r = runner.invoke(
        assay_app,
        ["vendorq", "verify", "--answers", str(a_path), "--pack", str(tmp_path / "missing"), "--json"],
    )
    assert r.exit_code == 3


def test_vq001_missing_citation(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad["answers"][0]["status"] = "ANSWERED"
    bad["answers"][0]["evidence_refs"] = []
    bad["answers"][0]["missing_evidence_requests"] = []
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert "VQ001_MISSING_CITATION" in {e["code"] for e in report["errors"]}


def test_vq002_bad_evidence_ref(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad["answers"][0]["evidence_refs"][0]["pack_id"] = "missing-pack"
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert "VQ002_EVIDENCE_REF_NOT_FOUND" in {e["code"] for e in report["errors"]}


def test_vq003_pack_hash_mismatch(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    lock_path = tmp_path / "vendorq.lock"
    lock_payload = write_vendorq_lock(answers, idx, lock_path)
    lock_payload["pack_digests"][0]["digest"] = "0" * 64
    report = verify_answers_payload(answers, idx, policy_name="conservative", strict=True, lock_payload=lock_payload)
    assert "VQ003_PACK_HASH_MISMATCH" in {e["code"] for e in report["errors"]}


def test_vq004_metric_without_numeric_source(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad_ans = bad["answers"][0]
    bad_ans["claim_type"] = "METRIC"
    bad_ans["status"] = "ANSWERED"
    bad_ans["evidence_refs"][0]["field_path"] = "type"
    bad_ans["evidence_refs"][0]["target"]["pointer"] = "type"
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert "VQ004_NUMERIC_CLAIM_NO_NUMERIC_SOURCE" in {e["code"] for e in report["errors"]}


def test_vq005_prohibited_commitment(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad_ans = bad["answers"][0]
    bad_ans["claim_type"] = "COMMITMENT"
    bad_ans["details"] = "We guarantee this will always be true."
    report = verify_answers_payload(bad, idx, policy_name="balanced", strict=True)
    assert "VQ005_PROHIBITED_COMMITMENT" in {e["code"] for e in report["errors"]}


def test_vq006_stale_evidence_strict(tmp_path: Path) -> None:
    old_ts = "2020-01-01T00:00:00+00:00"
    pack_dir = _build_pack(tmp_path, ts=old_ts)
    idx = build_evidence_index([pack_dir])
    questions = {
        "schema_version": "vendorq.question.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "test",
        "questions": [{"question_id": "Q1", "question_text": "Describe your process.", "type_hint": "free_text", "required_format": "text"}],
        "questions_hash": "3" * 64,
    }
    answers = compile_answers_payload(questions, idx, "conservative")
    # Force timestamp stale in ref to make check explicit
    answers["answers"][0]["evidence_refs"][0]["evidence_timestamp"] = old_ts
    report = verify_answers_payload(answers, idx, policy_name="conservative", strict=True)
    assert "VQ006_STALE_EVIDENCE" in {e["code"] for e in report["errors"]}


def test_vq007_schema_invalid(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    del bad["answers"][0]["evidence_refs"]
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert _first_code(report) == "VQ007_SCHEMA_INVALID"


def test_vq008_answer_status_invalid(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad["answers"][0]["status"] = "ANSWERED"
    bad["answers"][0]["missing_evidence_requests"] = ["still missing"]
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert "VQ008_ANSWER_STATUS_INVALID_FOR_CONTENT" in {e["code"] for e in report["errors"]}


def test_vq009_yes_without_support(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad["answers"][0]["status"] = "ANSWERED"
    bad["answers"][0]["answer_bool"] = True
    bad["answers"][0]["claim_type"] = "TECH_CONTROL"
    bad["answers"][0]["evidence_refs"][0]["field_path"] = "type"
    bad["answers"][0]["evidence_refs"][0]["target"]["pointer"] = "type"
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert "VQ009_YES_WITHOUT_SUPPORT" in {e["code"] for e in report["errors"]}


def test_vq010_claim_type_policy_violation(tmp_path: Path) -> None:
    _pack_dir, idx, answers = _base_answers_and_index(tmp_path)
    bad = copy.deepcopy(answers)
    bad["answers"][0]["claim_type"] = "COMMITMENT"
    report = verify_answers_payload(bad, idx, policy_name="conservative", strict=True)
    assert "VQ010_CLAIM_TYPE_POLICY_VIOLATION" in {e["code"] for e in report["errors"]}
