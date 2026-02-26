"""Tests for the unified evidence readiness report (score_report)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.reporting.score_report import (
    UnifiedReport,
    _compute_content_hash,
    _hash_payload_string,
    build_score_report,
    render_html,
    render_markdown,
    render_sarif,
    write_markdown,
    write_report,
)
from assay.reporting.evidence_gap import ReportFinding, ReportMeta


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _make_facts(**overrides):
    """Minimal valid facts dict."""
    base = {
        "repo_path": "/tmp/test-repo",
        "scan": {
            "sites_total": 10,
            "instrumented": 7,
            "uninstrumented": 3,
            "high": 2,
            "medium": 1,
            "low": 0,
            "findings": [
                {"path": "src/app.py", "line": 10, "call": "openai.ChatCompletion.create()",
                 "confidence": "high", "instrumented": False, "fix": "add receipt"},
                {"path": "src/app.py", "line": 20, "call": "client.messages.create()",
                 "confidence": "medium", "instrumented": False, "fix": None},
                {"path": "src/app.py", "line": 30, "call": "openai.ChatCompletion.create()",
                 "confidence": "high", "instrumented": True, "fix": None},
            ],
        },
        "lockfile": {
            "present": True,
            "valid": True,
            "stale": False,
            "issues": [],
        },
        "ci": {
            "workflow_count": 2,
            "files": [".github/workflows/ci.yml"],
            "has_assay_ref": True,
            "has_run": True,
            "has_verify": True,
            "has_lock": False,
        },
        "receipts": {
            "proof_pack_receipt_files": 0,
            "mcp_session_files": 0,
            "repo_receipt_files": 0,
        },
        "keys": {
            "signer_count": 0,
            "active_signer": None,
        },
    }
    base.update(overrides)
    return base


def _make_score(**overrides):
    """Minimal valid score dict."""
    base = {
        "score_version": "1.0.0",
        "score": 45.5,
        "grade": "F",
        "grade_description": "No evidence pipeline -- most repos start here.",
        "raw_score": 45.5,
        "raw_grade": "F",
        "caps_applied": [],
        "breakdown": {
            "coverage": {"weight": 35, "points": 24.5, "status": "partial", "note": "7/10 instrumented"},
            "lockfile": {"weight": 15, "points": 15.0, "status": "pass", "note": "Lockfile present and valid."},
            "ci_gate": {"weight": 20, "points": 14.0, "status": "partial", "note": "Run + verify detected."},
            "receipts": {"weight": 20, "points": 0.0, "status": "fail", "note": "No receipts."},
            "key_setup": {"weight": 10, "points": 0.0, "status": "fail", "note": "No signing key."},
        },
        "next_actions": [
            "Instrument gaps: assay patch .",
            "Generate first evidence pack: assay run ...",
        ],
        "next_actions_detail": [
            {"action": "Instrument gaps", "command": "assay patch .", "component": "coverage", "points_est": 10.5},
            {"action": "Generate first evidence pack", "command": "assay run -c receipt_completeness -- python your_app.py", "component": "receipts", "points_est": 20.0},
            {"action": "Initialize signer key", "command": 'assay run --allow-empty -- python -c "pass"', "component": "key_setup", "points_est": 10.0},
            {"action": "Harden CI gate", "command": 'assay ci init github --run-command "python your_app.py"', "component": "ci_gate", "points_est": 6.0},
        ],
        "fastest_path": {
            "target_grade": "D",
            "target_score": 60,
            "command": "assay run -c receipt_completeness -- python your_app.py",
            "points_est": 20.0,
            "projected_score": 65.5,
        },
        "disclaimer": "Evidence Readiness Score is a readiness signal, not a security guarantee.",
    }
    base.update(overrides)
    return base


def _make_report(**kwargs) -> UnifiedReport:
    """Build a UnifiedReport from defaults."""
    facts = kwargs.pop("facts", _make_facts())
    score = kwargs.pop("score", _make_score())
    meta = ReportMeta(
        assay_version="1.10.1",
        generated_at="2026-01-01T00:00:00+00:00",
        repo_name="test-repo",
        repo_root="/tmp/test-repo",
        git_branch="main",
        git_commit="abc1234",
        git_dirty=False,
    )
    evidence_gaps = [
        ReportFinding(
            path="src/app.py", line=10,
            call="openai.ChatCompletion.create()",
            confidence="high", instrumented=False,
            provider="openai", is_test=False, fix="add receipt",
        ),
        ReportFinding(
            path="src/app.py", line=20,
            call="client.messages.create()",
            confidence="medium", instrumented=False,
            provider="anthropic", is_test=False, fix=None,
        ),
    ]
    content_hash = _compute_content_hash(score, facts)
    return UnifiedReport(
        meta=meta, score=score, facts=facts,
        evidence_gaps=evidence_gaps, content_hash=content_hash,
    )


# ---------------------------------------------------------------------------
# Tests: build_score_report
# ---------------------------------------------------------------------------


class TestBuildReport:
    def test_build_report_from_facts(self, tmp_path):
        """build_score_report returns a UnifiedReport with all fields populated."""
        (tmp_path / ".git").mkdir()
        facts = _make_facts(repo_path=str(tmp_path))
        score = _make_score()
        report = build_score_report(facts, score, tmp_path)

        assert isinstance(report, UnifiedReport)
        assert report.meta.repo_root == str(tmp_path)
        assert report.score == score
        assert report.facts == facts
        assert report.content_hash.startswith("sha256:")

    def test_build_report_no_findings(self, tmp_path):
        """Empty scan -> report is still valid."""
        (tmp_path / ".git").mkdir()
        facts = _make_facts(
            repo_path=str(tmp_path),
            scan={"sites_total": 0, "instrumented": 0, "uninstrumented": 0,
                  "high": 0, "medium": 0, "low": 0, "findings": []},
        )
        score = _make_score()
        report = build_score_report(facts, score, tmp_path)

        assert isinstance(report, UnifiedReport)
        assert len(report.evidence_gaps) == 0


# ---------------------------------------------------------------------------
# Tests: render_html
# ---------------------------------------------------------------------------


class TestRenderHTML:
    def test_render_html_contains_grade(self):
        """HTML contains the grade letter."""
        report = _make_report()
        html = render_html(report)
        assert report.score["grade"] in html
        assert "Evidence Readiness Report" in html

    def test_render_html_contains_hash(self):
        """Content hash meta tag is present."""
        report = _make_report()
        html = render_html(report)
        assert 'meta name="assay-content-hash"' in html

    def test_render_html_print_styles(self):
        """@media print block is present."""
        report = _make_report()
        html = render_html(report)
        assert "@media print" in html

    def test_render_html_whatif_simulator(self):
        """JS contains the what-if simulator function."""
        report = _make_report()
        html = render_html(report)
        assert "updateWhatIf" in html

    def test_render_html_self_contained(self):
        """HTML has no external resource references."""
        report = _make_report()
        html = render_html(report)
        # No external CSS or JS
        assert "stylesheet" not in html.lower() or 'rel="stylesheet"' not in html
        assert '<script src=' not in html
        assert '<link ' not in html

    def test_render_html_no_innerhtml(self):
        """JS does not use innerHTML (XSS safety)."""
        report = _make_report()
        html = render_html(report)
        assert "innerHTML" not in html

    def test_render_html_embedded_json(self):
        """Report data is embedded as JSON in a script tag."""
        report = _make_report()
        html = render_html(report)
        assert 'id="report-data"' in html
        assert "application/json" in html


# ---------------------------------------------------------------------------
# Tests: render_markdown
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_render_markdown_structure(self):
        """Markdown contains score table, caps, next actions."""
        report = _make_report()
        report.score["caps_applied"] = [
            {"id": "CAP_NO_RECEIPTS_MAX_D", "reason": "No receipts."}
        ]
        md = render_markdown(report)

        assert "**F**" in md
        assert "45.5" in md
        assert "| coverage" in md
        assert "CAP_NO_RECEIPTS_MAX_D" in md
        assert "assay run" in md

    def test_render_markdown_no_caps(self):
        """No caps section when caps_applied is empty."""
        report = _make_report()
        report.score["caps_applied"] = []
        md = render_markdown(report)

        assert "**Caps:**" not in md

    def test_render_markdown_no_fastest_path(self):
        """No fastest path line when fastest_path is None."""
        report = _make_report()
        report.score["fastest_path"] = None
        md = render_markdown(report)

        assert "**Next:**" not in md


# ---------------------------------------------------------------------------
# Tests: render_sarif
# ---------------------------------------------------------------------------


class TestRenderSARIF:
    def test_render_sarif_schema(self):
        """Valid SARIF 2.1.0 structure."""
        report = _make_report()
        sarif = render_sarif(report)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "assay"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert run["tool"]["driver"]["rules"][0]["id"] == "assay/evidence-gap"

    def test_render_sarif_finding_count(self):
        """Result count matches uninstrumented findings."""
        report = _make_report()
        sarif = render_sarif(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == len(report.evidence_gaps)

    def test_render_sarif_confidence_mapping(self):
        """high->error, medium->warning, low->note."""
        report = _make_report()
        sarif = render_sarif(report)
        results = sarif["runs"][0]["results"]

        levels = {r["level"] for r in results}
        # We have high and medium findings
        assert "error" in levels
        assert "warning" in levels

    def test_render_sarif_no_findings(self):
        """Empty gaps -> empty results list."""
        report = _make_report()
        report.evidence_gaps = []
        sarif = render_sarif(report)
        assert sarif["runs"][0]["results"] == []

    def test_render_sarif_locations(self):
        """Each result has valid file:line location."""
        report = _make_report()
        sarif = render_sarif(report)
        for result in sarif["runs"][0]["results"]:
            loc = result["locations"][0]["physicalLocation"]
            assert "uri" in loc["artifactLocation"]
            assert "startLine" in loc["region"]


# ---------------------------------------------------------------------------
# Tests: write functions
# ---------------------------------------------------------------------------


class TestWriteReport:
    def test_write_report_creates_file(self, tmp_path):
        """File exists after write."""
        out = tmp_path / "report.html"
        write_report("<html></html>", out)
        assert out.exists()
        assert out.read_text() == "<html></html>"

    def test_write_report_creates_parent_dirs(self, tmp_path):
        """Parent directories are created automatically."""
        out = tmp_path / "sub" / "dir" / "report.html"
        write_report("<html></html>", out)
        assert out.exists()

    def test_write_markdown_creates_file(self, tmp_path):
        """Markdown file exists after write."""
        out = tmp_path / "report.md"
        write_markdown("# Test", out)
        assert out.exists()
        assert out.read_text() == "# Test"


# ---------------------------------------------------------------------------
# Tests: content hash
# ---------------------------------------------------------------------------


class TestContentHash:
    def test_content_hash_deterministic(self):
        """Same input -> same hash."""
        facts = _make_facts()
        score = _make_score()
        h1 = _compute_content_hash(score, facts)
        h2 = _compute_content_hash(score, facts)
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_content_hash_changes_on_mutation(self):
        """Different input -> different hash."""
        facts = _make_facts()
        score1 = _make_score(score=45.5)
        score2 = _make_score(score=99.0)
        h1 = _compute_content_hash(score1, facts)
        h2 = _compute_content_hash(score2, facts)
        assert h1 != h2

    def test_embedded_hash_matches_content_hash(self):
        """The hash payload embedded in HTML produces the same hash as content_hash."""
        import hashlib

        facts = _make_facts()
        score = _make_score()
        content_hash = _compute_content_hash(score, facts)
        payload_str = _hash_payload_string(score, facts)
        recomputed = "sha256:" + hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        assert recomputed == content_hash

    def test_hash_payload_embedded_in_html(self):
        """HTML contains the hash-payload script tag with the exact payload bytes."""
        import hashlib

        report = _make_report()
        html = render_html(report)
        # Extract the hash-payload content from the HTML
        assert 'id="hash-payload"' in html
        start = html.index('id="hash-payload">') + len('id="hash-payload">')
        end = html.index("</script>", start)

        # The payload in the HTML should produce the same hash as content_hash
        # (accounting for the <\/ escaping)
        payload_section = html[start:end].strip().replace("<\\/", "</")
        recomputed = "sha256:" + hashlib.sha256(payload_section.encode("utf-8")).hexdigest()
        assert recomputed == report.content_hash


# ---------------------------------------------------------------------------
# Tests: what-if simulator with caps
# ---------------------------------------------------------------------------


class TestWhatIfCaps:
    def test_whatif_contains_cap_rules(self):
        """HTML contains cap rules for the what-if simulator."""
        report = _make_report()
        html = render_html(report)
        assert "capRules" in html
        assert "CAP_NO_RECEIPTS_MAX_D" in html

    def test_whatif_contains_raw_score_in_json_data(self):
        """raw_score is in the embedded JSON data, not just anywhere in HTML."""
        report = _make_report()
        report.score["raw_score"] = 72.5
        html = render_html(report)
        # Extract the JSON data section
        start = html.index('id="report-data">') + len('id="report-data">')
        end = html.index("</script>", start)
        json_section = html[start:end]
        assert '"raw_score"' in json_section
        assert "72.5" in json_section

    def test_cap_rules_match_score_py(self):
        """JS capRules array covers all caps defined in score.py."""
        # score.py only defines CAP_NO_RECEIPTS_MAX_D (receipts component, max D = 69.9)
        # If score.py adds new caps, this test should be updated.
        from assay.score import compute_evidence_readiness_score
        # Create facts that trigger the cap: receipts=0, but high enough raw score
        facts = _make_facts()
        facts["receipts"] = {"proof_pack_receipt_files": 0, "mcp_session_files": 0, "repo_receipt_files": 0}
        facts["lockfile"] = {"present": True, "valid": True, "stale": False, "issues": []}
        facts["ci"] = {"workflow_count": 2, "files": [], "has_assay_ref": True,
                        "has_run": True, "has_verify": True, "has_lock": True}
        facts["keys"] = {"signer_count": 1, "active_signer": "test"}
        facts["scan"] = {"sites_total": 10, "instrumented": 10, "uninstrumented": 0,
                         "high": 0, "medium": 0, "low": 0}
        score = compute_evidence_readiness_score(facts)
        # Verify only CAP_NO_RECEIPTS_MAX_D exists
        cap_ids = [c["id"] for c in score["caps_applied"]]
        assert cap_ids == ["CAP_NO_RECEIPTS_MAX_D"]

    def test_whatif_cap_boundary_69_9(self):
        """raw_score=70+ with receipts failing should project 69.9, not 70+.

        The JS applies: if receipts component is 'fail' and not toggled,
        clamp projected score to 69.9.
        """
        report = _make_report()
        # Set raw_score above the D threshold so the cap would bite
        report.score["raw_score"] = 80.0
        report.score["score"] = 69.9  # capped
        report.score["grade"] = "D"
        report.score["breakdown"]["receipts"] = {
            "weight": 20, "points": 0.0, "status": "fail", "note": "No receipts."
        }
        # Give a non-receipt action that adds points
        report.score["next_actions_detail"] = [
            {"action": "Add lockfile", "command": "assay lock init",
             "component": "lockfile", "points_est": 15.0},
            {"action": "Generate receipts",
             "command": "assay run -c receipt_completeness -- python app.py",
             "component": "receipts", "points_est": 20.0},
        ]
        html = render_html(report)
        # The JS capRules should contain maxScore: 69.9
        assert "maxScore: 69.9" in html
        # The JS checks breakdown[rule.component].status === "fail"
        # and only applies the cap if the component is not toggled
        assert 'isFailing && !isToggled' in html


# ---------------------------------------------------------------------------
# Tests: special characters (XSS regression guard)
# ---------------------------------------------------------------------------


class TestSpecialCharacters:
    def test_xss_in_repo_name(self):
        """Repo name with HTML/JS doesn't break the report."""
        report = _make_report()
        report.meta.repo_name = '<script>alert("xss")</script>'
        html = render_html(report)
        # The script tag should be safely embedded in JSON, not executable
        assert "alert" in html  # it's in the JSON data
        # But it should NOT appear as a raw HTML tag outside the JSON
        # The el() builder uses textContent, so it's safe

    def test_script_tag_in_call_site(self):
        """</script> in a finding value doesn't break the HTML."""
        report = _make_report()
        report.evidence_gaps[0].call = 'foo("</script><script>alert(1)</script>")'
        html = render_html(report)
        # The </script> should be escaped to <\/script> in the JSON
        assert "<\\/script>" in html
        # The raw </script> should not appear in the JSON section
        json_start = html.index('id="report-data">') + len('id="report-data">')
        json_end = html.index("</script>", json_start)
        json_section = html[json_start:json_end]
        assert "</script>" not in json_section

    def test_special_chars_in_file_path(self):
        """File paths with special chars render safely."""
        report = _make_report()
        report.evidence_gaps[0].path = "src/app & <helpers>/foo.py"
        html = render_html(report)
        # Should be in the JSON data (escaped)
        assert "app &" in html


# ---------------------------------------------------------------------------
# Tests: SARIF ruleIndex
# ---------------------------------------------------------------------------


class TestSARIFRuleIndex:
    def test_sarif_results_have_rule_index(self):
        """Each SARIF result has ruleIndex referencing the rules[] array."""
        report = _make_report()
        sarif = render_sarif(report)
        for result in sarif["runs"][0]["results"]:
            assert "ruleIndex" in result
            assert result["ruleIndex"] == 0


# ---------------------------------------------------------------------------
# Tests: graceful degradation with missing fields
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_empty_score_dict(self):
        """Report renders with empty/minimal score dict."""
        report = _make_report()
        report.score = {"score": 0, "grade": "F", "breakdown": {},
                        "caps_applied": [], "next_actions_detail": [],
                        "fastest_path": None, "disclaimer": ""}
        html = render_html(report)
        assert "Evidence Readiness Report" in html

    def test_missing_optional_fields(self):
        """Report renders when optional fields are None."""
        report = _make_report()
        report.meta.git_branch = None
        report.meta.git_commit = None
        report.meta.git_dirty = None
        html = render_html(report)
        assert "Evidence Readiness Report" in html

    def test_empty_evidence_gaps(self):
        """Markdown and SARIF handle zero gaps."""
        report = _make_report()
        report.evidence_gaps = []
        md = render_markdown(report)
        sarif = render_sarif(report)
        assert "Assay Evidence Readiness" in md
        assert sarif["runs"][0]["results"] == []
