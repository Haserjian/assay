"""Tests for assay patch -- auto-insert SDK integration patches."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.patcher import (
    PatchPlan,
    _check_already_patched,
    _find_insertion_point,
    apply_patch,
    generate_diff,
    plan_patch,
)
from assay.scanner import CallSite, Confidence, ScanResult


# ---------------------------------------------------------------------------
# _find_insertion_point
# ---------------------------------------------------------------------------

class TestFindInsertionPoint:
    def test_empty_file(self):
        assert _find_insertion_point([]) == 0

    def test_simple_imports(self):
        lines = ["import os", "import sys", "", "x = 1"]
        assert _find_insertion_point(lines) == 0

    def test_shebang(self):
        lines = ["#!/usr/bin/env python", "import os"]
        assert _find_insertion_point(lines) == 1

    def test_shebang_with_blank(self):
        lines = ["#!/usr/bin/env python", "", "import os"]
        assert _find_insertion_point(lines) == 2

    def test_module_docstring_single_line(self):
        lines = ['"""Module docstring."""', "import os"]
        assert _find_insertion_point(lines) == 1

    def test_module_docstring_multi_line(self):
        lines = ['"""', "Module docstring.", '"""', "import os"]
        assert _find_insertion_point(lines) == 3

    def test_module_docstring_single_quotes(self):
        lines = ["'''Module.'''", "import os"]
        assert _find_insertion_point(lines) == 1

    def test_shebang_docstring_future(self):
        lines = [
            "#!/usr/bin/env python",
            '"""Docstring."""',
            "",
            "from __future__ import annotations",
            "",
            "import os",
        ]
        assert _find_insertion_point(lines) == 5

    def test_future_imports_only(self):
        lines = [
            "from __future__ import annotations",
            "from __future__ import division",
            "",
            "import os",
        ]
        assert _find_insertion_point(lines) == 3

    def test_blank_lines_only(self):
        lines = ["", "", ""]
        assert _find_insertion_point(lines) == 3


# ---------------------------------------------------------------------------
# _check_already_patched
# ---------------------------------------------------------------------------

class TestCheckAlreadyPatched:
    def test_no_patches(self):
        lines = ["import os", "import openai"]
        assert _check_already_patched(lines) == set()

    def test_openai_patched(self):
        lines = ["from assay.integrations.openai import patch; patch()"]
        assert _check_already_patched(lines) == {"openai"}

    def test_anthropic_patched(self):
        lines = ["from assay.integrations.anthropic import patch; patch()"]
        assert _check_already_patched(lines) == {"anthropic"}

    def test_both_patched(self):
        lines = [
            "from assay.integrations.openai import patch as patch_openai; patch_openai()",
            "from assay.integrations.anthropic import patch as patch_anthropic; patch_anthropic()",
        ]
        assert _check_already_patched(lines) == {"openai", "anthropic"}

    def test_aliased_import(self):
        lines = ["from assay.integrations.openai import patch as p; p()"]
        assert _check_already_patched(lines) == {"openai"}


# ---------------------------------------------------------------------------
# plan_patch
# ---------------------------------------------------------------------------

def _make_scan_result(findings):
    return ScanResult(findings=findings)


def _openai_finding(path="app.py", line=5):
    return CallSite(
        path=path, line=line,
        call="client.chat.completions.create",
        confidence=Confidence.HIGH,
        instrumented=False,
        framework="openai",
    )


def _anthropic_finding(path="app.py", line=10):
    return CallSite(
        path=path, line=line,
        call="client.messages.create",
        confidence=Confidence.HIGH,
        instrumented=False,
        framework="anthropic",
    )


def _langchain_finding(path="chain.py", line=3):
    return CallSite(
        path=path, line=line,
        call="chain.invoke",
        confidence=Confidence.MEDIUM,
        instrumented=False,
        framework="langchain",
    )


class TestPlanPatch:
    def test_single_openai(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
        scan = _make_scan_result([_openai_finding()])
        plan = plan_patch(scan, tmp_path)
        assert plan.has_work
        assert plan.entrypoint == "app.py"
        assert len(plan.lines_to_insert) == 1
        assert "openai" in plan.lines_to_insert[0]
        assert "patch()" in plan.lines_to_insert[0]

    def test_single_anthropic(self, tmp_path):
        (tmp_path / "app.py").write_text("import anthropic\n")
        scan = _make_scan_result([_anthropic_finding()])
        plan = plan_patch(scan, tmp_path)
        assert plan.has_work
        assert "anthropic" in plan.lines_to_insert[0]

    def test_multi_framework_uses_aliases(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nimport anthropic\n")
        scan = _make_scan_result([_openai_finding(), _anthropic_finding()])
        plan = plan_patch(scan, tmp_path)
        assert len(plan.lines_to_insert) == 2
        joined = "\n".join(plan.lines_to_insert)
        assert "patch_openai" in joined
        assert "patch_anthropic" in joined

    def test_already_patched_skips(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "from assay.integrations.openai import patch; patch()\nimport openai\n"
        )
        scan = _make_scan_result([_openai_finding()])
        plan = plan_patch(scan, tmp_path)
        assert not plan.has_work
        assert plan.already_patched == ["openai"]

    def test_partially_patched(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "from assay.integrations.openai import patch; patch()\nimport openai\nimport anthropic\n"
        )
        scan = _make_scan_result([_openai_finding(), _anthropic_finding()])
        plan = plan_patch(scan, tmp_path)
        assert plan.has_work
        assert len(plan.lines_to_insert) == 1
        assert "anthropic" in plan.lines_to_insert[0]
        assert "openai" in plan.already_patched

    def test_langchain_only_no_patch(self, tmp_path):
        (tmp_path / "chain.py").write_text("from langchain.llms import ChatOpenAI\n")
        scan = _make_scan_result([_langchain_finding()])
        plan = plan_patch(scan, tmp_path)
        assert not plan.has_work
        assert plan.langchain_note is not None
        assert "callback" in plan.langchain_note.lower()

    def test_langchain_mixed_patches_sdk_only(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        scan = _make_scan_result([_openai_finding(), _langchain_finding("app.py", 20)])
        plan = plan_patch(scan, tmp_path)
        assert plan.has_work
        assert len(plan.lines_to_insert) == 1
        assert "openai" in plan.lines_to_insert[0]
        assert plan.langchain_note is not None

    def test_instrumented_framework_not_patched(self, tmp_path):
        """P2 regression: don't patch frameworks that are already instrumented elsewhere."""
        (tmp_path / "chain.py").write_text("from langchain.llms import ChatOpenAI\n")
        instrumented_openai = CallSite(
            path="chain.py", line=5,
            call="client.chat.completions.create",
            confidence=Confidence.HIGH,
            instrumented=True,  # already instrumented
            framework="openai",
        )
        scan = _make_scan_result([instrumented_openai, _langchain_finding()])
        plan = plan_patch(scan, tmp_path)
        # OpenAI is instrumented, LangChain can't be auto-patched -> no work
        assert not plan.has_work
        assert plan.langchain_note is not None

    def test_no_findings(self, tmp_path):
        scan = _make_scan_result([])
        plan = plan_patch(scan, tmp_path)
        assert not plan.has_work

    def test_explicit_entrypoint(self, tmp_path):
        (tmp_path / "main.py").write_text("import openai\n")
        (tmp_path / "app.py").write_text("import openai\n")
        scan = _make_scan_result([
            _openai_finding("app.py", 5),
            _openai_finding("app.py", 10),
            _openai_finding("main.py", 3),
        ])
        # Without explicit entrypoint, picks app.py (more findings)
        plan = plan_patch(scan, tmp_path)
        assert plan.entrypoint == "app.py"

        # With explicit entrypoint
        plan2 = plan_patch(scan, tmp_path, entrypoint="main.py")
        assert plan2.entrypoint == "main.py"

    def test_entrypoint_not_found_raises(self, tmp_path):
        scan = _make_scan_result([_openai_finding()])
        with pytest.raises(FileNotFoundError):
            plan_patch(scan, tmp_path, entrypoint="nonexistent.py")

    def test_insertion_after_docstring(self, tmp_path):
        (tmp_path / "app.py").write_text('"""My app."""\n\nimport openai\n')
        scan = _make_scan_result([_openai_finding()])
        plan = plan_patch(scan, tmp_path)
        assert plan.insertion_line == 2  # after docstring + blank line


# ---------------------------------------------------------------------------
# generate_diff / apply_patch
# ---------------------------------------------------------------------------

class TestGenerateDiff:
    def test_produces_unified_diff(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
        scan = _make_scan_result([_openai_finding()])
        plan = plan_patch(scan, tmp_path)
        diff = generate_diff(plan, tmp_path)
        assert "--- a/app.py" in diff
        assert "+++ b/app.py" in diff
        assert "+from assay.integrations.openai import patch; patch()" in diff

    def test_no_work_returns_empty(self, tmp_path):
        plan = PatchPlan(
            entrypoint="app.py", frameworks=[], lines_to_insert=[],
            insertion_line=0,
        )
        assert generate_diff(plan, tmp_path) == ""


class TestApplyPatch:
    def test_inserts_patch_line(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
        scan = _make_scan_result([_openai_finding()])
        plan = plan_patch(scan, tmp_path)
        diff = apply_patch(plan, tmp_path)

        content = (tmp_path / "app.py").read_text()
        assert content.startswith("from assay.integrations.openai import patch; patch()\n")
        assert "import openai" in content
        assert "--- a/app.py" in diff

    def test_idempotent(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        scan = _make_scan_result([_openai_finding()])

        plan1 = plan_patch(scan, tmp_path)
        apply_patch(plan1, tmp_path)
        after_first = (tmp_path / "app.py").read_text()

        plan2 = plan_patch(scan, tmp_path)
        assert not plan2.has_work
        after_second = (tmp_path / "app.py").read_text()
        assert after_first == after_second

    def test_multi_framework_insertion(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nimport anthropic\n")
        scan = _make_scan_result([_openai_finding(), _anthropic_finding()])
        plan = plan_patch(scan, tmp_path)
        apply_patch(plan, tmp_path)

        content = (tmp_path / "app.py").read_text()
        lines = content.splitlines()
        # Both patch lines inserted before original imports (alphabetical order)
        joined = "\n".join(lines[:2])
        assert "patch_openai" in joined
        assert "patch_anthropic" in joined
        assert lines[2] == "import openai"

    def test_preserves_shebang_and_docstring(self, tmp_path):
        original = '#!/usr/bin/env python\n"""My app."""\n\nimport openai\n'
        (tmp_path / "app.py").write_text(original)
        scan = _make_scan_result([_openai_finding()])
        plan = plan_patch(scan, tmp_path)
        apply_patch(plan, tmp_path)

        lines = (tmp_path / "app.py").read_text().splitlines()
        assert lines[0] == "#!/usr/bin/env python"
        assert lines[1] == '"""My app."""'
        assert lines[2] == ""
        assert "from assay.integrations.openai import patch" in lines[3]
        assert lines[4] == "import openai"

    def test_no_work_no_write(self, tmp_path):
        plan = PatchPlan(
            entrypoint="app.py", frameworks=[], lines_to_insert=[],
            insertion_line=0,
        )
        result = apply_patch(plan, tmp_path)
        assert result == ""


# ---------------------------------------------------------------------------
# patch command JSON mode regression tests
# ---------------------------------------------------------------------------

class TestPatchCommandJSON:
    def test_json_dry_run_exits_0_and_does_not_write(self, tmp_path):
        app_file = tmp_path / "app.py"
        original = (
            "import openai\n"
            "client = openai.OpenAI()\n"
            "resp = client.chat.completions.create(model='gpt-4', messages=[])\n"
        )
        app_file.write_text(original)

        runner = CliRunner()
        result = runner.invoke(assay_app, ["patch", str(tmp_path), "--json", "--dry-run"])
        assert result.exit_code == 0, result.output

        payload = json.loads(result.output)
        assert payload["command"] == "patch"
        assert payload["status"] == "dry_run"
        assert "+from assay.integrations.openai import patch; patch()" in payload["diff"]

        # Dry run must not mutate the file.
        assert app_file.read_text() == original

    def test_json_apply_exits_0_and_writes_file(self, tmp_path):
        app_file = tmp_path / "app.py"
        app_file.write_text(
            "import openai\n"
            "client = openai.OpenAI()\n"
            "resp = client.chat.completions.create(model='gpt-4', messages=[])\n"
        )

        runner = CliRunner()
        result = runner.invoke(assay_app, ["patch", str(tmp_path), "--json", "--yes"])
        assert result.exit_code == 0, result.output

        payload = json.loads(result.output)
        assert payload["command"] == "patch"
        assert payload["status"] == "applied"

        # Apply mode must mutate the file.
        content = app_file.read_text()
        assert content.startswith("from assay.integrations.openai import patch; patch()\n")
