"""Tests for evidence gate (assay gate check/save-baseline)."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.gate import (
    DEFAULT_BASELINE_PATH,
    evaluate_gate,
    load_score_baseline,
    save_score_baseline,
)

runner = CliRunner()


def _score(score: float = 75.0, grade: str = "C") -> dict:
    """Minimal score dict for testing."""
    return {
        "score_version": "1.0.0",
        "score": score,
        "grade": grade,
        "raw_score": score,
        "raw_grade": grade,
        "caps_applied": [],
        "breakdown": {},
        "next_actions": [],
    }


# ---------------------------------------------------------------------------
# Unit tests: evaluate_gate
# ---------------------------------------------------------------------------


class TestEvaluateGate:
    def test_pass_above_threshold(self) -> None:
        report = evaluate_gate(current_score=_score(80), min_score=60)
        assert report["result"] == "PASS"
        assert report["current_score"] == 80
        assert report["reasons"] == []

    def test_fail_below_threshold(self) -> None:
        report = evaluate_gate(current_score=_score(45), min_score=60)
        assert report["result"] == "FAIL"
        assert len(report["reasons"]) == 1
        assert "below minimum" in report["reasons"][0]

    def test_fail_on_regression(self) -> None:
        report = evaluate_gate(
            current_score=_score(70),
            fail_on_regression=True,
            baseline_score=80.0,
        )
        assert report["result"] == "FAIL"
        assert report["regression_detected"] is True
        assert "regressed" in report["reasons"][0]

    def test_pass_no_regression(self) -> None:
        report = evaluate_gate(
            current_score=_score(85),
            fail_on_regression=True,
            baseline_score=80.0,
        )
        assert report["result"] == "PASS"
        assert report["regression_detected"] is False

    def test_regression_disabled(self) -> None:
        report = evaluate_gate(
            current_score=_score(70),
            fail_on_regression=False,
            baseline_score=80.0,
        )
        assert report["result"] == "PASS"

    def test_no_baseline_no_regression(self) -> None:
        report = evaluate_gate(
            current_score=_score(70),
            fail_on_regression=True,
            baseline_score=None,
        )
        assert report["result"] == "PASS"
        assert report["regression_detected"] is False

    def test_both_threshold_and_regression_fail(self) -> None:
        report = evaluate_gate(
            current_score=_score(50),
            min_score=60,
            fail_on_regression=True,
            baseline_score=70,
        )
        assert report["result"] == "FAIL"
        assert len(report["reasons"]) == 2

    def test_score_exactly_at_threshold_passes(self) -> None:
        report = evaluate_gate(current_score=_score(60), min_score=60)
        assert report["result"] == "PASS"
        assert report["reasons"] == []

    def test_score_equal_to_baseline_passes(self) -> None:
        report = evaluate_gate(
            current_score=_score(80),
            fail_on_regression=True,
            baseline_score=80.0,
        )
        assert report["result"] == "PASS"
        assert report["regression_detected"] is False

    def test_json_contract(self) -> None:
        report = evaluate_gate(current_score=_score(80), min_score=60)
        assert report["command"] == "assay gate"
        assert "timestamp" in report
        assert isinstance(report["reasons"], list)
        assert isinstance(report["regression_detected"], bool)


# ---------------------------------------------------------------------------
# Unit tests: baseline persistence
# ---------------------------------------------------------------------------


class TestBaselinePersistence:
    def test_save_and_load(self, tmp_path: Path) -> None:
        bf = tmp_path / "baseline.json"
        save_score_baseline(_score(82.5, "B"), bf)
        loaded = load_score_baseline(bf)
        assert loaded == 82.5

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        assert load_score_baseline(tmp_path / "nope.json") is None

    def test_load_corrupt_returns_none(self, tmp_path: Path) -> None:
        bf = tmp_path / "bad.json"
        bf.write_text("not json", encoding="utf-8")
        assert load_score_baseline(bf) is None

    def test_load_no_score_key_returns_none(self, tmp_path: Path) -> None:
        bf = tmp_path / "empty.json"
        bf.write_text('{"grade": "A"}', encoding="utf-8")
        assert load_score_baseline(bf) is None

    def test_load_out_of_range_score_returns_none(self, tmp_path: Path) -> None:
        bf = tmp_path / "bad-range.json"
        bf.write_text('{"score": 123.4}', encoding="utf-8")
        assert load_score_baseline(bf) is None

    def test_load_non_finite_score_returns_none(self, tmp_path: Path) -> None:
        bf = tmp_path / "bad-nan.json"
        bf.write_text('{"score": "nan"}', encoding="utf-8")
        assert load_score_baseline(bf) is None

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        bf = tmp_path / "deep" / "nested" / "baseline.json"
        save_score_baseline(_score(90), bf)
        assert bf.exists()
        assert load_score_baseline(bf) == 90.0


# ---------------------------------------------------------------------------
# CLI tests: assay gate check
# ---------------------------------------------------------------------------


class TestGateCheckCLI:
    def test_pass_json(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text(
            "import openai\nclient = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )
        result = runner.invoke(assay_app, ["gate", "check", ".", "--min-score", "0", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["command"] == "assay gate"
        assert data["result"] == "PASS"
        assert "current_score" in data
        assert "current_grade" in data

    def test_fail_high_threshold_json(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(assay_app, ["gate", "check", ".", "--min-score", "100", "--json"])
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["result"] == "FAIL"
        assert data["status"] == "blocked"

    def test_missing_dir_exit_3(self) -> None:
        result = runner.invoke(assay_app, ["gate", "check", "/no/such/path", "--json"])
        assert result.exit_code == 3

    def test_invalid_min_score_high_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["gate", "check", ".", "--min-score", "101", "--json"])
        assert result.exit_code == 3, result.output
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "between 0 and 100" in data["error"]

    def test_invalid_min_score_non_finite_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(assay_app, ["gate", "check", ".", "--min-score", "nan", "--json"])
        assert result.exit_code == 3, result.output
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "between 0 and 100" in data["error"]

    def test_regression_with_baseline_file(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        # Save a high baseline
        bf = tmp_path / ".assay" / "score-baseline.json"
        save_score_baseline(_score(99.0, "A"), bf)
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--fail-on-regression", "--baseline", str(bf), "--json"],
        )
        assert result.exit_code == 1, result.output
        data = json.loads(result.output)
        assert data["regression_detected"] is True

    def test_regression_no_baseline_passes(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--fail-on-regression", "--json"],
        )
        # No baseline file exists, so regression check is skipped -> PASS (on regression dimension)
        data = json.loads(result.output)
        assert data["regression_detected"] is False

    def test_regression_invalid_default_baseline_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        bad = tmp_path / ".assay" / "score-baseline.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text('{"score": 500}', encoding="utf-8")
        result = runner.invoke(assay_app, ["gate", "check", ".", "--fail-on-regression", "--json"])
        assert result.exit_code == 3, result.output
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "Invalid baseline score" in data["error"]

    def test_save_report_json_pass(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        out = tmp_path / ".assay" / "gate-report.json"
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "0", "--save-report", str(out), "--json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["report_file"] == str(out)
        assert out.exists()
        written = json.loads(out.read_text(encoding="utf-8"))
        assert written["result"] == "PASS"
        assert written["status"] == "ok"
        assert written["report_file"] == str(out)

    def test_save_report_non_json_fail(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        out = tmp_path / ".assay" / "gate-report-fail.json"
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--min-score", "100", "--save-report", str(out)],
        )
        assert result.exit_code == 1, result.output
        assert out.exists()
        written = json.loads(out.read_text(encoding="utf-8"))
        assert written["result"] == "FAIL"
        assert written["status"] == "blocked"
        assert written["report_file"] == str(out)

    def test_save_report_write_failure_exit_3(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(
            assay_app,
            ["gate", "check", ".", "--save-report", "/dev/null/impossible.json", "--json"],
        )
        assert result.exit_code == 3, result.output
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "Cannot write report" in data["error"]


# ---------------------------------------------------------------------------
# CLI tests: assay gate save-baseline
# ---------------------------------------------------------------------------


class TestGateSaveBaselineCLI:
    def test_save_baseline_creates_file(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(assay_app, ["gate", "save-baseline", ".", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert "score" in data
        bf = tmp_path / DEFAULT_BASELINE_PATH
        assert bf.exists()

    def test_save_baseline_custom_output(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        custom = tmp_path / "my-baseline.json"
        result = runner.invoke(assay_app, ["gate", "save-baseline", ".", "-o", str(custom), "--json"])
        assert result.exit_code == 0
        assert custom.exists()
        loaded = load_score_baseline(custom)
        assert loaded is not None

    def test_save_baseline_write_failure(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        Path("app.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(
            assay_app,
            ["gate", "save-baseline", ".", "-o", "/dev/null/impossible.json", "--json"],
        )
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "Cannot write baseline" in data["error"]
