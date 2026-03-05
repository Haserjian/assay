from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.vendorq_compile import compile_answers_payload
from assay.vendorq_index import build_evidence_index
from assay.vendorq_models import VendorQInputError, stable_answers_hash

runner = CliRunner()


def _build_pack(tmp_path: Path) -> Path:
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("vendorq-test")
    receipts = [
        {
            "receipt_id": "r1",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "model_id": "gpt-4",
            "provider": "openai",
            "input_tokens": 10,
            "output_tokens": 10,
            "total_tokens": 20,
        }
    ]
    pack = ProofPack(run_id="vendorq-run", entries=receipts, signer_id="vendorq-test")
    return pack.build(tmp_path / "pack", keystore=ks)


def _questions_payload() -> dict:
    return {
        "schema_version": "vendorq.question.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "test",
        "questions": [
            {
                "question_id": "Q1",
                "question_text": "How many model calls were observed?",
                "type_hint": "numeric",
                "required_format": "number",
            }
        ],
        "questions_hash": "0" * 64,
    }


def test_vendorq_compile_cli(tmp_path: Path) -> None:
    pack_dir = _build_pack(tmp_path)
    q = _questions_payload()
    q["questions_hash"] = stable_answers_hash([
        {
            "question_id": "Q1",
            "answer_id": "Q1",
            "status": "OUT_OF_SCOPE",
            "answer_mode": "EVIDENCE_ONLY",
            "claim_type": "PROCESS",
            "answer_bool": None,
            "answer_value": None,
            "details": "How many model calls were observed?",
            "confidence": 0.0,
            "evidence_refs": [],
            "review_required": False,
            "review_reason": "",
            "review_owner_hint": "NONE",
            "risk_flags": ["NONE"],
            "missing_evidence_requests": [],
        }
    ])
    q_path = tmp_path / "questions.json"
    q_path.write_text(json.dumps(q))

    out = tmp_path / "answers.json"
    r = runner.invoke(
        assay_app,
        ["vendorq", "compile", "--questions", str(q_path), "--pack", str(pack_dir), "--policy", "conservative", "--out", str(out), "--json"],
    )
    assert r.exit_code == 0, r.output
    payload = json.loads(out.read_text())
    assert payload["schema_version"] == "vendorq.answer.v1"
    assert len(payload["answers"]) == 1


def test_vendorq_compile_deterministic_answer_hash(tmp_path: Path) -> None:
    pack_dir = _build_pack(tmp_path)
    idx = build_evidence_index([pack_dir])
    q = _questions_payload()
    a1 = compile_answers_payload(q, idx, "conservative")
    a2 = compile_answers_payload(q, idx, "conservative")
    assert stable_answers_hash(a1["answers"]) == stable_answers_hash(a2["answers"])


def test_vendorq_compile_invalid_provider_spec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack_dir = _build_pack(tmp_path)
    idx = build_evidence_index([pack_dir])
    q = _questions_payload()
    monkeypatch.setenv("ASSAY_VENDORQ_PROVIDER", "bad-spec-without-colon")
    with pytest.raises(VendorQInputError):
        compile_answers_payload(q, idx, "conservative")
