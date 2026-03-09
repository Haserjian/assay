"""Tests for assay diff proof report generation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from assay.diff import ClaimDelta, DiffResult, ModelDelta, PackInfo, diff_packs
from assay.reporting.diff_report import (
    compute_bullets,
    compute_explanation,
    compute_verdict,
    generate_diff_json,
    generate_diff_report,
    render_html,
)
from assay import commands as assay_commands


# ---------------------------------------------------------------------------
# Helpers (mirror of test_diff.py helpers)
# ---------------------------------------------------------------------------

def _make_receipt(
    model_id: str = "gpt-4o",
    provider: str = "openai",
    input_tokens: int = 1000,
    output_tokens: int = 500,
    latency_ms: int = 800,
    finish_reason: str = "stop",
    error: bool = False,
    timestamp: str = "2026-02-10T12:00:00Z",
) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "receipt_id": "r_test",
        "type": "model_call",
        "schema_version": "3.0",
        "model_id": model_id,
        "provider": provider,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "latency_ms": latency_ms,
        "finish_reason": finish_reason,
        "timestamp": timestamp,
    }
    if error:
        r["error"] = "test error"
    return r


def _write_pack(
    pack_dir: Path,
    receipts: list,
    claim_results: dict | None = None,
    claim_set_hash: str = "abc123",
    signer_id: str = "test-signer",
    signer_fp: str = "fp_aaa",
    verifier_version: str = "1.3.3",
    integrity: str = "PASS",
    claim_check: str = "PASS",
) -> Path:
    """Write a minimal pack structure for testing."""
    pack_dir.mkdir(parents=True, exist_ok=True)

    lines = [json.dumps(r) for r in receipts]
    (pack_dir / "receipt_pack.jsonl").write_text("\n".join(lines) + "\n")

    manifest = {
        "pack_id": f"pack_{pack_dir.name}",
        "claim_set_hash": claim_set_hash,
        "signer_id": signer_id,
        "signer_pubkey_sha256": signer_fp,
        "attestation": {
            "pack_id": f"pack_{pack_dir.name}",
            "receipt_integrity": integrity,
            "claim_check": claim_check,
            "verifier_version": verifier_version,
            "n_receipts": len(receipts),
            "timestamp_start": "2026-02-10T12:00:00Z",
            "timestamp_end": "2026-02-10T12:05:00Z",
        },
    }
    (pack_dir / "pack_manifest.json").write_text(json.dumps(manifest, indent=2))

    report: Dict[str, Any] = {"status": "ok"}
    if claim_results is not None:
        report["claim_verification"] = {
            "passed": all(claim_results.values()),
            "results": [
                {"claim_id": cid, "passed": passed, "expected": "", "actual": "", "severity": "critical"}
                for cid, passed in claim_results.items()
            ],
        }
    (pack_dir / "verify_report.json").write_text(json.dumps(report, indent=2))

    return pack_dir


def _make_comparable_result(
    *,
    has_regression: bool = False,
    claim_statuses: list[tuple[str, bool | None, bool | None]] | None = None,
    signer_changed: bool = False,
    version_changed: bool = False,
) -> DiffResult:
    """Build a DiffResult with both_valid=True for testing."""
    a = PackInfo(
        path="/tmp/pack_a",
        pack_id="pack_a",
        integrity="PASS",
        claim_check="PASS",
        signer_id="signer-1",
        signer_fingerprint="fp_aaa",
        verifier_version="1.0.0",
        n_receipts=5,
    )
    b = PackInfo(
        path="/tmp/pack_b",
        pack_id="pack_b",
        integrity="PASS",
        claim_check="PASS",
        signer_id="signer-1",
        signer_fingerprint="fp_aaa",
        verifier_version="1.0.0",
        n_receipts=5,
    )
    result = DiffResult(pack_a=a, pack_b=b, both_valid=True)
    result.signer_changed = signer_changed
    result.version_changed = version_changed
    result.has_regression = has_regression

    if claim_statuses:
        for cid, a_passed, b_passed in claim_statuses:
            regressed = a_passed is True and b_passed is False
            result.claim_deltas.append(
                ClaimDelta(claim_id=cid, a_passed=a_passed, b_passed=b_passed, regressed=regressed)
            )

    return result


def _make_unverifiable_result() -> DiffResult:
    """Build a DiffResult with both_valid=False for testing."""
    a = PackInfo(path="/tmp/pack_a", pack_id="pack_a", integrity="FAIL")
    b = PackInfo(path="/tmp/pack_b", pack_id="pack_b", integrity="PASS")
    result = DiffResult(pack_a=a, pack_b=b, both_valid=False)
    result.integrity_errors = ["Pack A: receipt hash mismatch"]
    return result


# ---------------------------------------------------------------------------
# compute_verdict
# ---------------------------------------------------------------------------

class TestComputeVerdict:
    def test_unverifiable_when_not_both_valid(self) -> None:
        result = _make_unverifiable_result()
        trust, outcome = compute_verdict(result)
        assert trust == "Unverifiable"
        assert outcome is None

    def test_comparable_reproduced_when_no_changes(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True), ("sc", True, True)],
        )
        trust, outcome = compute_verdict(result)
        assert trust == "Comparable"
        assert outcome == "Reproduced"

    def test_comparable_drifted_when_claims_changed(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False), ("sc", True, True)],
            has_regression=True,
        )
        trust, outcome = compute_verdict(result)
        assert trust == "Comparable"
        assert outcome == "Drifted"

    def test_comparable_drifted_when_signer_changed(self) -> None:
        result = _make_comparable_result(signer_changed=True)
        trust, outcome = compute_verdict(result)
        assert trust == "Comparable"
        assert outcome == "Drifted"

    def test_comparable_drifted_when_version_changed(self) -> None:
        result = _make_comparable_result(version_changed=True)
        trust, outcome = compute_verdict(result)
        assert trust == "Comparable"
        assert outcome == "Drifted"

    def test_no_regressed_as_top_level_verdict(self) -> None:
        """Top-level outcome must never be 'Regressed' (v1 constraint)."""
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False)],
            has_regression=True,
        )
        _, outcome = compute_verdict(result)
        assert outcome != "Regressed"
        assert outcome == "Drifted"


# ---------------------------------------------------------------------------
# compute_explanation
# ---------------------------------------------------------------------------

class TestComputeExplanation:
    def test_unverifiable_explanation(self) -> None:
        result = _make_unverifiable_result()
        trust, outcome = compute_verdict(result)
        exp = compute_explanation(result, trust, outcome)
        assert "cannot be trusted" in exp.lower() or "integrity" in exp.lower()

    def test_reproduced_explanation_mentions_comparable(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True)],
        )
        trust, outcome = compute_verdict(result)
        exp = compute_explanation(result, trust, outcome)
        assert "comparable" in exp.lower()
        assert "unchanged" in exp.lower()

    def test_drifted_explanation_mentions_changed(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False), ("sc", True, True), ("tc", True, True)],
            has_regression=True,
        )
        trust, outcome = compute_verdict(result)
        exp = compute_explanation(result, trust, outcome)
        assert "1 of 3" in exp or "changed" in exp.lower()


# ---------------------------------------------------------------------------
# compute_bullets
# ---------------------------------------------------------------------------

class TestComputeBullets:
    def test_unverifiable_bullets_start_with_integrity_reason(self) -> None:
        result = _make_unverifiable_result()
        trust, outcome = compute_verdict(result)
        bullets = compute_bullets(result, trust, outcome)
        assert len(bullets) >= 1
        assert "integrity" in bullets[0].lower() or "valid" in bullets[0].lower()

    def test_comparable_reproduced_bullets_have_three(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True), ("sc", True, True)],
        )
        trust, outcome = compute_verdict(result)
        bullets = compute_bullets(result, trust, outcome)
        assert 1 <= len(bullets) <= 3

    def test_comparable_first_bullet_is_trust_reason(self) -> None:
        result = _make_comparable_result()
        trust, outcome = compute_verdict(result)
        bullets = compute_bullets(result, trust, outcome)
        assert "valid" in bullets[0].lower() or "comparable" in bullets[0].lower()

    def test_claim_change_in_second_bullet(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False), ("sc", True, True)],
            has_regression=True,
        )
        trust, outcome = compute_verdict(result)
        bullets = compute_bullets(result, trust, outcome)
        assert len(bullets) >= 2
        assert "1 of 2" in bullets[1] or "changed" in bullets[1].lower()


# ---------------------------------------------------------------------------
# render_html
# ---------------------------------------------------------------------------

class TestRenderHtml:
    def test_reproduced_html_has_comparable_and_reproduced(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True)],
        )
        html = render_html(result)
        assert "Comparable" in html
        assert "Reproduced" in html
        assert "Unverifiable" not in html

    def test_drifted_html_has_comparable_and_drifted(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False)],
            has_regression=True,
        )
        html = render_html(result)
        assert "Comparable" in html
        assert "Drifted" in html

    def test_unverifiable_html_has_unverifiable_no_outcome(self) -> None:
        result = _make_unverifiable_result()
        html = render_html(result)
        assert "Unverifiable" in html
        assert "Reproduced" not in html
        assert "Drifted" not in html

    def test_html_is_self_contained_no_external_resources(self) -> None:
        result = _make_comparable_result()
        html = render_html(result)
        # No CDN or external URLs
        assert "https://cdn" not in html
        assert "http://cdn" not in html
        assert 'src="http' not in html
        assert 'href="http' not in html

    def test_html_has_proof_footer_with_pack_paths(self) -> None:
        result = _make_comparable_result()
        html = render_html(result)
        assert "Proof Footer" in html
        assert "/tmp/pack_a" in html
        assert "/tmp/pack_b" in html
        assert "assay verify-pack" in html

    def test_html_has_claims_table(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True), ("sc", True, False)],
            has_regression=True,
        )
        html = render_html(result)
        assert "Claims" in html
        assert "rc" in html
        assert "sc" in html

    def test_html_always_shows_proof_roots_in_footer(self) -> None:
        """Proof roots must always be shown regardless of verdict."""
        result = _make_unverifiable_result()
        html = render_html(result)
        assert "Proof Footer" in html
        assert "manifest sha256" in html.lower() or "sha256" in html

    def test_html_claim_regressed_row_highlighted(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False)],
            has_regression=True,
        )
        html = render_html(result)
        assert "regressed" in html

    def test_html_new_claim_shown(self) -> None:
        result = _make_comparable_result(
            claim_statuses=[("new_claim", None, True)],
        )
        html = render_html(result)
        assert "new_claim" in html
        assert "★" in html or "new" in html

    def test_html_title_is_proof_report(self) -> None:
        result = _make_comparable_result()
        html = render_html(result)
        assert "Assay Diff Proof Report" in html


# ---------------------------------------------------------------------------
# generate_diff_report
# ---------------------------------------------------------------------------

class TestGenerateDiffReport:
    def test_writes_html_file(self, tmp_path: Path) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True)],
        )
        out = tmp_path / "report.html"
        returned = generate_diff_report(result, out)
        assert returned == out
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "Assay Diff Proof Report" in content

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        result = _make_comparable_result()
        out = tmp_path / "subdir" / "deep" / "report.html"
        generate_diff_report(result, out)
        assert out.exists()

    def test_reproduced_case(self, tmp_path: Path) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True), ("sc", True, True)],
        )
        out = tmp_path / "report.html"
        generate_diff_report(result, out)
        html = out.read_text(encoding="utf-8")
        assert "Reproduced" in html
        assert "Comparable" in html

    def test_drifted_case(self, tmp_path: Path) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False)],
            has_regression=True,
        )
        out = tmp_path / "report.html"
        generate_diff_report(result, out)
        html = out.read_text(encoding="utf-8")
        assert "Drifted" in html

    def test_unverifiable_case(self, tmp_path: Path) -> None:
        result = _make_unverifiable_result()
        out = tmp_path / "report.html"
        generate_diff_report(result, out)
        html = out.read_text(encoding="utf-8")
        assert "Unverifiable" in html
        assert "Reproduced" not in html
        assert "Drifted" not in html


# ---------------------------------------------------------------------------
# generate_diff_json
# ---------------------------------------------------------------------------

class TestGenerateDiffJson:
    def test_writes_json_with_verdict(self, tmp_path: Path) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True)],
        )
        out = tmp_path / "diff_result.json"
        returned = generate_diff_json(result, out)
        assert returned == out
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert "verdict" in payload
        assert payload["verdict"]["trust"] == "Comparable"
        assert payload["verdict"]["outcome"] == "Reproduced"

    def test_json_structure_matches_to_dict_plus_verdict(self, tmp_path: Path) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True)],
        )
        out = tmp_path / "diff_result.json"
        generate_diff_json(result, out)
        payload = json.loads(out.read_text(encoding="utf-8"))

        # Core DiffResult fields are present
        assert "pack_a" in payload
        assert "pack_b" in payload
        assert "preflight" in payload
        assert "claims" in payload
        # Verdict fields added on top
        assert "verdict" in payload
        assert "trust" in payload["verdict"]
        assert "outcome" in payload["verdict"]
        assert "explanation" in payload["verdict"]
        assert "bullets" in payload["verdict"]

    def test_unverifiable_json_has_no_outcome(self, tmp_path: Path) -> None:
        result = _make_unverifiable_result()
        out = tmp_path / "diff_result.json"
        generate_diff_json(result, out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["verdict"]["trust"] == "Unverifiable"
        assert payload["verdict"]["outcome"] is None

    def test_drifted_json(self, tmp_path: Path) -> None:
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False)],
            has_regression=True,
        )
        out = tmp_path / "diff_result.json"
        generate_diff_json(result, out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["verdict"]["trust"] == "Comparable"
        assert payload["verdict"]["outcome"] == "Drifted"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestDiffReportCLI:
    def test_report_flag_writes_html(self, tmp_path: Path) -> None:
        """--report -o path writes HTML proof report."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify", "--report", "-o", "out.html"],
            )
            assert result.exit_code == 0, result.output
            assert Path("out.html").exists()
            content = Path("out.html").read_text(encoding="utf-8")
            assert "Assay Diff Proof Report" in content
            assert "Comparable" in content

    def test_report_flag_writes_json_alongside(self, tmp_path: Path) -> None:
        """--report also writes diff_result.json."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify", "--report", "-o", "out.html"],
            )
            assert result.exit_code == 0, result.output
            assert Path("diff_result.json").exists()
            payload = json.loads(Path("diff_result.json").read_text(encoding="utf-8"))
            assert "verdict" in payload

    def test_auto_naming_when_output_not_specified(self) -> None:
        """--report without -o uses assay_diff_report.html."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify", "--report"],
            )
            assert result.exit_code == 0, result.output
            assert Path("assay_diff_report.html").exists()
            assert Path("diff_result.json").exists()

    def test_no_report_flag_no_html_written(self) -> None:
        """Without --report, no HTML file is written (existing behavior unchanged)."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify"],
            )
            assert result.exit_code == 0, result.output
            assert not Path("assay_diff_report.html").exists()
            assert not Path("diff_result.json").exists()

    def test_report_with_regression_exit_code_1(self) -> None:
        """--report with regression still exits with code 1."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": False}, claim_check="FAIL")

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify", "--report", "-o", "out.html"],
            )
            assert result.exit_code == 1
            assert Path("out.html").exists()
            content = Path("out.html").read_text(encoding="utf-8")
            assert "Drifted" in content

    def test_report_json_stdout_includes_report_path(self) -> None:
        """--json --report includes report_path in JSON stdout."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify", "--json", "--report", "-o", "out.html"],
            )
            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert "report_path" in data
            assert "json_path" in data
            assert Path("out.html").exists()

    def test_existing_terminal_diff_unchanged_without_report(self) -> None:
        """Without --report, terminal diff output is unchanged (shows assay diff header)."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            _write_pack(Path("a"), [_make_receipt()], {"rc": True})
            _write_pack(Path("b"), [_make_receipt()], {"rc": True})

            result = runner.invoke(
                assay_commands.assay_app,
                ["diff", "a", "b", "--no-verify"],
            )
            assert result.exit_code == 0, result.output
            assert "assay diff" in result.output.lower() or "Pack A" in result.output or "Pack B" in result.output


# ---------------------------------------------------------------------------
# Test invariants
# ---------------------------------------------------------------------------

class TestReportInvariants:
    def test_integrity_failure_always_unverifiable(self, tmp_path: Path) -> None:
        """Structural trust failure → always Unverifiable, never shows outcome."""
        result = _make_unverifiable_result()
        out = tmp_path / "report.html"
        generate_diff_report(result, out)
        html = out.read_text(encoding="utf-8")
        assert "Unverifiable" in html
        assert "Reproduced" not in html
        assert "Drifted" not in html

    def test_proof_roots_always_in_footer(self, tmp_path: Path) -> None:
        """Proof roots shown in footer regardless of verdict."""
        for result in [_make_comparable_result(), _make_unverifiable_result()]:
            out = tmp_path / f"report_{result.pack_a.integrity}.html"
            generate_diff_report(result, out)
            html = out.read_text(encoding="utf-8")
            assert "Proof Footer" in html

    def test_html_no_external_dependencies(self, tmp_path: Path) -> None:
        """HTML is fully self-contained — no external fetches."""
        result = _make_comparable_result()
        out = tmp_path / "report.html"
        generate_diff_report(result, out)
        html = out.read_text(encoding="utf-8")
        for bad_pattern in ["cdn.jsdelivr", "unpkg.com", "googleapis.com", "bootstrap.css"]:
            assert bad_pattern not in html

    def test_json_verdict_semantics_match_html_verdict(self, tmp_path: Path) -> None:
        """JSON verdict fields must be consistent with HTML report."""
        result = _make_comparable_result(
            claim_statuses=[("rc", True, False)],
            has_regression=True,
        )
        html_out = tmp_path / "report.html"
        json_out = tmp_path / "diff_result.json"
        generate_diff_report(result, html_out)
        generate_diff_json(result, json_out)

        html = html_out.read_text(encoding="utf-8")
        payload = json.loads(json_out.read_text(encoding="utf-8"))

        # Both should agree on trust/outcome
        assert payload["verdict"]["trust"] == "Comparable"
        assert payload["verdict"]["outcome"] == "Drifted"
        assert "Comparable" in html
        assert "Drifted" in html

    def test_reproduced_comparable_no_material_delta(self, tmp_path: Path) -> None:
        """Comparable + no meaningful delta → Reproduced."""
        result = _make_comparable_result(
            claim_statuses=[("rc", True, True), ("sc", True, True)],
        )
        out = tmp_path / "diff_result.json"
        generate_diff_json(result, out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["verdict"]["trust"] == "Comparable"
        assert payload["verdict"]["outcome"] == "Reproduced"
