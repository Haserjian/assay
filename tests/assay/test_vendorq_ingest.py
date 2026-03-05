from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app

runner = CliRunner()


def test_vendorq_ingest_csv(tmp_path: Path) -> None:
    csv_path = tmp_path / "q.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["question_id", "question_text", "type_hint", "required_format"])
        w.writeheader()
        w.writerow({"question_id": "Q1", "question_text": "Do you log model calls?", "type_hint": "yes_no", "required_format": "yes_no"})
        w.writerow({"question_id": "Q2", "question_text": "How many incidents in 12 months?", "type_hint": "numeric", "required_format": "number"})

    out = tmp_path / "questions.json"
    r = runner.invoke(assay_app, ["vendorq", "ingest", "--in", str(csv_path), "--out", str(out), "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["question_count"] == 2
    payload = json.loads(out.read_text())
    assert payload["schema_version"] == "vendorq.question.v1"
    assert payload["source"] == csv_path.name


def test_vendorq_ingest_markdown(tmp_path: Path) -> None:
    md = tmp_path / "q.md"
    md.write_text("""
# Vendor Questionnaire
- Do you use CI checks for AI changes?
- Provide incident response process.
""".strip() + "\n")

    out = tmp_path / "questions.json"
    r = runner.invoke(assay_app, ["vendorq", "ingest", "--in", str(md), "--out", str(out), "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["question_count"] == 2


def test_vendorq_ingest_missing_file_exit_3(tmp_path: Path) -> None:
    out = tmp_path / "questions.json"
    r = runner.invoke(assay_app, ["vendorq", "ingest", "--in", str(tmp_path / "missing.csv"), "--out", str(out), "--json"])
    assert r.exit_code == 3, r.output
    data = json.loads(r.output)
    assert data["status"] == "error"


def test_vendorq_ingest_source_label(tmp_path: Path) -> None:
    csv_path = tmp_path / "q.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["question_id", "question_text", "type_hint", "required_format"])
        w.writeheader()
        w.writerow({"question_id": "Q1", "question_text": "Do you log model calls?", "type_hint": "yes_no", "required_format": "yes_no"})

    out = tmp_path / "questions.json"
    r = runner.invoke(
        assay_app,
        ["vendorq", "ingest", "--in", str(csv_path), "--source-label", "customer_q1_2026", "--out", str(out), "--json"],
    )
    assert r.exit_code == 0, r.output
    payload = json.loads(out.read_text())
    assert payload["source"] == "customer_q1_2026"
