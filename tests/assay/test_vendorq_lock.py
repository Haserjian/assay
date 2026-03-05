from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.vendorq_compile import compile_answers_payload
from assay.vendorq_index import build_evidence_index

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
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
        }
    ]
    pack = ProofPack(run_id="vendorq-lock-run", entries=receipts, signer_id="vendorq-test")
    return pack.build(tmp_path / "pack", keystore=ks)


def test_vendorq_lock_write_cli(tmp_path: Path) -> None:
    pack_dir = _build_pack(tmp_path)
    idx = build_evidence_index([pack_dir])
    questions = {
        "schema_version": "vendorq.question.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "test",
        "questions": [{"question_id": "Q1", "question_text": "How many model calls?", "type_hint": "numeric", "required_format": "number"}],
        "questions_hash": "1" * 64,
    }
    answers = compile_answers_payload(questions, idx, "conservative")
    answers_path = tmp_path / "answers.json"
    answers_path.write_text(json.dumps(answers))

    lock_path = tmp_path / "vendorq.lock"
    r = runner.invoke(
        assay_app,
        ["vendorq", "lock", "write", "--answers", str(answers_path), "--pack", str(pack_dir), "--out", str(lock_path), "--json"],
    )
    assert r.exit_code == 0, r.output
    lock_payload = json.loads(lock_path.read_text())
    assert lock_payload["lock_version"] == "1.0"
    assert len(lock_payload["pack_digests"]) == 1
