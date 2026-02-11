"""Tests for the evidence gap HTML report."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from assay import commands as assay_commands
from assay.reporting.evidence_gap import (
    EvidenceGapReport,
    ReportFinding,
    ReportMeta,
    ReportSummary,
    _detect_provider,
    _is_test_path,
    build_report,
    render_html,
    write_report,
)
from assay.scanner import CallSite, Confidence, ScanResult


def _make_scan_dict(*call_sites):
    """Build a ScanResult.to_dict() from CallSite tuples."""
    findings = []
    for path, line, call, conf, instrumented, fix in call_sites:
        findings.append(CallSite(path, line, call, conf, instrumented, fix))
    return ScanResult(findings=findings).to_dict()


class TestBuildReport:
    def test_basic_report_fields(self, tmp_path):
        scan = _make_scan_dict(
            ("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
        )
        report = build_report(scan, tmp_path)
        assert report.meta.assay_version
        assert report.meta.generated_at
        assert report.meta.repo_root == str(tmp_path.resolve())
        assert report.summary.sites_total == 1
        assert report.summary.uninstrumented == 1
        assert len(report.findings) == 1

    def test_coverage_math_high_medium_only(self, tmp_path):
        """Coverage = instrumented / (HIGH + MEDIUM total) * 100. LOW excluded."""
        scan = _make_scan_dict(
            ("a.py", 1, "client.chat.completions.create", Confidence.HIGH, True, None),
            ("b.py", 2, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
            ("c.py", 3, "chain.invoke()", Confidence.MEDIUM, False, "patch langchain"),
            ("d.py", 4, "llm_call()", Confidence.LOW, False, "emit_receipt"),
        )
        report = build_report(scan, tmp_path)
        # HIGH+MEDIUM total = 3, instrumented among them = 1
        assert report.summary.coverage_pct == round(1 / 3 * 100, 1)

    def test_low_excluded_from_denominator(self, tmp_path):
        """Only LOW findings -> coverage should be 0% (no HIGH/MEDIUM)."""
        scan = _make_scan_dict(
            ("a.py", 1, "llm_call()", Confidence.LOW, False, "emit_receipt"),
            ("b.py", 2, "chat_func()", Confidence.LOW, False, "emit_receipt"),
        )
        report = build_report(scan, tmp_path)
        # No HIGH/MEDIUM, so coverage should be 0.0
        # (findings exist but none are HIGH/MEDIUM)
        assert report.summary.coverage_pct == 0.0

    def test_all_instrumented_is_100(self, tmp_path):
        scan = _make_scan_dict(
            ("a.py", 1, "client.chat.completions.create", Confidence.HIGH, True, None),
            ("b.py", 2, "messages.create", Confidence.HIGH, True, None),
        )
        report = build_report(scan, tmp_path)
        assert report.summary.coverage_pct == 100.0

    def test_no_findings_is_100(self, tmp_path):
        scan = ScanResult(findings=[]).to_dict()
        report = build_report(scan, tmp_path)
        assert report.summary.coverage_pct == 100.0
        assert report.summary.sites_total == 0

    def test_provider_computed_in_build(self, tmp_path):
        """Provider should be set as a real field during build_report."""
        scan = _make_scan_dict(
            ("a.py", 1, "client.chat.completions.create", Confidence.HIGH, False, "patch"),
            ("b.py", 2, "anthropic_client.messages.create", Confidence.HIGH, False, "patch"),
            ("c.py", 3, "agent.invoke()", Confidence.MEDIUM, False, "emit"),
            ("d.py", 4, "litellm.completion()", Confidence.MEDIUM, False, "emit"),
        )
        report = build_report(scan, tmp_path)
        assert report.findings[0].provider == "openai"
        assert report.findings[1].provider == "anthropic"
        assert report.findings[2].provider == "langchain"
        assert report.findings[3].provider == "litellm"

    def test_is_test_detected(self, tmp_path):
        """Files in test directories should be flagged."""
        scan = _make_scan_dict(
            ("src/app.py", 1, "client.chat.completions.create", Confidence.HIGH, False, "patch"),
            ("tests/test_app.py", 2, "client.chat.completions.create", Confidence.HIGH, False, "patch"),
        )
        report = build_report(scan, tmp_path)
        assert report.findings[0].is_test is False
        assert report.findings[1].is_test is True
        assert report.summary.prod_total == 1
        assert report.summary.test_total == 1

    def test_prod_test_split_in_summary(self, tmp_path):
        scan = _make_scan_dict(
            ("src/a.py", 1, "client.chat.completions.create", Confidence.HIGH, False, "p"),
            ("src/b.py", 2, "client.chat.completions.create", Confidence.HIGH, True, None),
            ("tests/t.py", 3, "client.chat.completions.create", Confidence.HIGH, False, "p"),
            ("tests/t2.py", 4, "client.chat.completions.create", Confidence.HIGH, False, "p"),
        )
        report = build_report(scan, tmp_path)
        assert report.summary.prod_total == 2
        assert report.summary.prod_uninstrumented == 1
        assert report.summary.test_total == 2
        assert report.summary.test_uninstrumented == 2


class TestRenderHTML:
    def _render_with_findings(self, tmp_path, *call_sites):
        scan = _make_scan_dict(*call_sites)
        report = build_report(scan, tmp_path)
        return render_html(report)

    def test_generates_valid_html(self, tmp_path):
        html = self._render_with_findings(
            tmp_path,
            ("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
        )
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        assert "Evidence Gap Report" in html

    def test_self_contained_no_external_resources(self, tmp_path):
        """Report must not link to external CSS/JS/fonts."""
        html = self._render_with_findings(
            tmp_path,
            ("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
        )
        # No external links
        assert 'href="http' not in html
        assert 'src="http' not in html
        assert "<link " not in html

    def test_contains_embedded_json(self, tmp_path):
        html = self._render_with_findings(
            tmp_path,
            ("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
        )
        assert 'id="report-data"' in html
        assert '"sites_total"' in html

    def test_no_innerhtml_in_js(self, tmp_path):
        """Security: dynamic content must use textContent, not innerHTML."""
        html = self._render_with_findings(
            tmp_path,
            ("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
        )
        # Extract JS section and check no innerHTML assignment (comments OK)
        js_section = html.split("<script>")[-1].split("</script>")[0]
        # Remove comment lines before checking
        js_lines = [line for line in js_section.split("\n")
                     if line.strip() and not line.strip().startswith("//")]
        js_code = "\n".join(js_lines)
        assert ".innerHTML" not in js_code

    def test_empty_scan_renders_without_crash(self, tmp_path):
        scan = ScanResult(findings=[]).to_dict()
        report = build_report(scan, tmp_path)
        html = render_html(report)
        assert "<!DOCTYPE html>" in html
        assert "No LLM call sites detected" in html

    def test_special_chars_in_path_safe(self, tmp_path):
        """File paths with special characters shouldn't break the report."""
        html = self._render_with_findings(
            tmp_path,
            ('src/<script>alert("xss")</script>.py', 1, "client.chat.completions.create", Confidence.HIGH, False, "patch"),
        )
        # The path should be in the embedded JSON (escaped), not raw in HTML
        assert "<!DOCTYPE html>" in html
        # JSON-escaped version should be present
        assert "<script>alert" not in html.split('id="report-data"')[0]

    def test_embedded_json_escapes_script_termination(self):
        """Embedded JSON must escape '</' to avoid closing <script> early."""
        report = EvidenceGapReport(
            meta=ReportMeta(
                assay_version="1.2.2",
                generated_at="2026-02-10T00:00:00+00:00",
                repo_name="demo",
                repo_root="/tmp/demo",
            ),
            summary=ReportSummary(
                sites_total=1,
                instrumented=0,
                uninstrumented=1,
                high=1,
                medium=0,
                low=0,
                coverage_pct=0.0,
            ),
            findings=[
                ReportFinding(
                    path="src/</script>.py",
                    line=1,
                    call="client.chat.completions.create",
                    confidence="high",
                    instrumented=False,
                    provider="openai",
                    fix="from assay.integrations.openai import patch; patch()",
                )
            ],
        )
        html = render_html(report)
        assert "src/</script>.py" not in html
        assert "src/<\\/script>.py" in html


class TestWriteReport:
    def test_writes_html_file(self, tmp_path):
        scan = _make_scan_dict(
            ("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
        )
        report = build_report(scan, tmp_path)
        html = render_html(report)
        out = tmp_path / "report.html"
        write_report(html, out)
        assert out.exists()
        content = out.read_text()
        assert "Evidence Gap Report" in content

    def test_creates_parent_dirs(self, tmp_path):
        scan = ScanResult(findings=[]).to_dict()
        report = build_report(scan, tmp_path)
        html = render_html(report)
        out = tmp_path / "sub" / "dir" / "report.html"
        write_report(html, out)
        assert out.exists()


class TestDetectProvider:
    def test_openai(self):
        assert _detect_provider("client.chat.completions.create") == "openai"
        assert _detect_provider("ChatOpenAI") == "openai"

    def test_anthropic(self):
        assert _detect_provider("anthropic_client.messages.create") == "anthropic"
        assert _detect_provider("ChatAnthropic") == "anthropic"

    def test_langchain(self):
        assert _detect_provider("chain.invoke()") == "langchain"
        assert _detect_provider("agent.invoke") == "langchain"
        assert _detect_provider("agent.ainvoke") == "langchain"
        assert _detect_provider("model.invoke") == "langchain"
        assert _detect_provider("retriever.invoke") == "langchain"
        assert _detect_provider("llm.predict(x)") == "langchain"

    def test_litellm(self):
        assert _detect_provider("litellm.completion()") == "litellm"

    def test_other(self):
        assert _detect_provider("custom_llm()") == "other"
        assert _detect_provider("my_func") == "other"


class TestIsTestPath:
    def test_test_dirs(self):
        assert _is_test_path("tests/test_app.py") is True
        assert _is_test_path("test/test_app.py") is True
        assert _is_test_path("libs/core/tests/unit_tests/test_runnable.py") is True

    def test_prod_paths(self):
        assert _is_test_path("src/app.py") is False
        assert _is_test_path("libs/core/langchain_core/runnables/base.py") is False

    def test_test_file_in_prod_dir(self):
        assert _is_test_path("src/test_utils/helper.py") is True


class TestToDict:
    def test_roundtrip_json(self, tmp_path):
        """Report dict should be JSON-serializable and stable."""
        scan = _make_scan_dict(
            ("a.py", 1, "client.chat.completions.create", Confidence.HIGH, False, "patch openai"),
            ("b.py", 2, "messages.create", Confidence.MEDIUM, True, None),
        )
        report = build_report(scan, tmp_path)
        d = report.to_dict()
        # Should be JSON-serializable
        serialized = json.dumps(d, sort_keys=True)
        parsed = json.loads(serialized)
        assert parsed["summary"]["sites_total"] == 2
        assert len(parsed["findings"]) == 2
        # Fields present
        assert "coverage_pct" in parsed["summary"]
        assert "assay_version" in parsed["meta"]
        # New fields present
        assert "provider" in parsed["findings"][0]
        assert "is_test" in parsed["findings"][0]
        assert "prod_total" in parsed["summary"]
        assert "test_total" in parsed["summary"]


class TestScanCLIReport:
    def test_report_does_not_pollute_json_output(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "client.chat.completions.create(model='gpt-4', messages=[])\n",
            encoding="utf-8",
        )
        report_path = tmp_path / "report.html"
        runner = CliRunner()
        result = runner.invoke(
            assay_commands.assay_app,
            [
                "scan",
                str(tmp_path),
                "--json",
                "--report",
                "--report-path",
                str(report_path),
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["tool"] == "assay-scan"
        assert report_path.exists()
        assert report_path.with_suffix(".json").exists()
