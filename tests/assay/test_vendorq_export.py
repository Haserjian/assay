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
from assay.vendorq_verify import verify_answers_payload

runner = CliRunner()


def _build_pack(tmp_path: Path) -> Path:
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("vendorq-export")
    receipts = [
        {
            "receipt_id": "r1",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 1,
            "model_id": "gpt-4",
            "provider": "openai",
            "input_tokens": 3,
            "output_tokens": 2,
            "total_tokens": 5,
        }
    ]
    pack = ProofPack(run_id="vendorq-export-run", entries=receipts, signer_id="vendorq-export")
    return pack.build(tmp_path / "pack", keystore=ks)


def test_vendorq_export_markdown_contains_navigation_chain(tmp_path: Path) -> None:
    pack_dir = _build_pack(tmp_path)
    idx = build_evidence_index([pack_dir])
    questions = {
        "schema_version": "vendorq.question.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "test",
        "questions": [{"question_id": "Q1", "question_text": "Describe your process", "type_hint": "free_text", "required_format": "text"}],
        "questions_hash": "4" * 64,
    }
    answers = compile_answers_payload(questions, idx, "conservative")
    report = verify_answers_payload(answers, idx, policy_name="conservative", strict=False)

    a_path = tmp_path / "answers.json"
    r_path = tmp_path / "verify.json"
    out = tmp_path / "packet.md"
    a_path.write_text(json.dumps(answers))
    r_path.write_text(json.dumps(report))

    res = runner.invoke(
        assay_app,
        [
            "vendorq", "export",
            "--answers", str(a_path),
            "--verify-report", str(r_path),
            "--format", "md",
            "--out", str(out),
            "--json",
        ],
    )
    assert res.exit_code == 0, res.output
    text = out.read_text()
    assert "Evidence Navigation Chain" in text
    assert "assay verify-pack" in text
    assert "Verification scope" in text
