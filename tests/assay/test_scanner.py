"""Tests for assay.scanner -- AST-based LLM call site detection."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from assay.scanner import (
    CallSite,
    Confidence,
    ScanResult,
    _LLMCallVisitor,
    _suggest_fix,
    scan_directory,
    scan_file,
)


# ---------------------------------------------------------------------------
# Fixtures: temp Python files with known patterns
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, name: str, code: str) -> Path:
    """Write a Python file under tmp_path and return its path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(code))
    return p


# ---------------------------------------------------------------------------
# High-confidence detection
# ---------------------------------------------------------------------------

class TestHighConfidence:
    def test_openai_chat_completions(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.HIGH
        assert "chat.completions.create" in sites[0].call
        assert sites[0].instrumented is False
        assert sites[0].fix is not None

    def test_openai_completions_create(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            client = get_client()
            resp = client.completions.create(model="gpt-3.5-turbo")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.HIGH

    def test_anthropic_messages_create(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import anthropic
            client = anthropic.Anthropic()
            msg = client.messages.create(model="claude-3", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.HIGH
        assert "messages.create" in sites[0].call

    def test_azure_chat_completions(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            resp = azure_client.chat_completions.create(model="gpt-4")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.HIGH

    def test_multiple_calls_same_file(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import openai
            c = openai.OpenAI()
            r1 = c.chat.completions.create(model="gpt-4", messages=[])
            r2 = c.chat.completions.create(model="gpt-3.5-turbo", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 2
        assert all(s.confidence == Confidence.HIGH for s in sites)


# ---------------------------------------------------------------------------
# Medium-confidence detection
# ---------------------------------------------------------------------------

class TestMediumConfidence:
    def test_langchain_invoke(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from langchain_core.runnables import RunnableSequence
            chain = build_chain()
            result = chain.invoke({"input": "hello"})
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM

    def test_langchain_ainvoke(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from langchain_core.runnables import RunnableSequence
            result = await chain.ainvoke({"input": "hello"})
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM

    def test_invoke_without_framework_import_is_dropped(self, tmp_path):
        """invoke() without framework imports is silently dropped (not a false positive)."""
        f = _write(tmp_path, "app.py", """\
            result = something.invoke({"key": "val"})
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 0

    def test_langchain_chatopenai(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(model="gpt-4")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM

    def test_langchain_chatanthropic(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            llm = ChatAnthropic(model="claude-3")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM

    def test_litellm_completion(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import litellm
            resp = litellm.completion(model="gpt-4", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM

    def test_litellm_acompletion(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import litellm
            resp = await litellm.acompletion(model="gpt-4", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM

    def test_llm_predict(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from langchain.llms import OpenAI
            result = llm.predict("What is 2+2?")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Low-confidence detection (heuristic names)
# ---------------------------------------------------------------------------

class TestLowConfidence:
    @pytest.mark.parametrize("func_name", [
        "llm_call", "call_llm", "query_model", "call_model",
        "generate_response", "chat_completion", "model_inference",
        "run_model", "ask_llm", "prompt_model",
    ])
    def test_heuristic_names(self, tmp_path, func_name):
        f = _write(tmp_path, "app.py", f"""\
            result = {func_name}("hello")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.LOW

    def test_heuristic_as_method(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            result = self.call_llm("hello")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.LOW


# ---------------------------------------------------------------------------
# No false positives
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_stdlib_calls(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import os
            import json
            data = json.loads("{}")
            path = os.path.join("a", "b")
            print("hello")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 0

    def test_regular_create_method(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            db.users.create(name="Alice")
            session.query.create(params={})
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 0

    def test_regular_invoke_on_non_chain(self, tmp_path):
        """invoke() without framework imports is correctly dropped."""
        f = _write(tmp_path, "app.py", """\
            result = something.invoke({"key": "val"})
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 0

    def test_empty_file(self, tmp_path):
        f = _write(tmp_path, "empty.py", "")
        sites, _ = scan_file(f)
        assert len(sites) == 0

    def test_syntax_error_file(self, tmp_path):
        f = _write(tmp_path, "bad.py", "def foo(:\n  pass")
        sites, has_instr = scan_file(f)
        assert len(sites) == 0
        assert has_instr is False

    def test_non_python_ignored(self, tmp_path):
        """scan_directory only processes .py files."""
        (tmp_path / "data.json").write_text('{"completions.create": true}')
        (tmp_path / "readme.md").write_text("# chat.completions.create")
        result = scan_directory(tmp_path)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Instrumentation evidence detection
# ---------------------------------------------------------------------------

class TestInstrumentationEvidence:
    def test_emit_receipt_import(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from assay import emit_receipt
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
            emit_receipt("model_call", {"model": "gpt-4"})
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].instrumented is True
        assert sites[0].fix is None
        assert has_instr is True

    def test_openai_patch_import(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from assay.integrations.openai import patch
            patch()
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].instrumented is True
        assert has_instr is True

    def test_anthropic_patch_import(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from assay.integrations.anthropic import patch
            patch()
            import anthropic
            msg = anthropic.Anthropic().messages.create(model="claude-3", messages=[])
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].instrumented is True

    def test_langchain_patch_import(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            from langchain_core.runnables import RunnableSequence
            from assay.integrations.langchain import patch
            patch()
            chain = build_chain()
            result = chain.invoke({"input": "hi"})
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].instrumented is True

    def test_assay_emit_call(self, tmp_path):
        """_assay_emit is also evidence (used in internal integrations)."""
        f = _write(tmp_path, "app.py", """\
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
            _assay_emit("model_call", {"model": "gpt-4"})
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].instrumented is True

    def test_no_instrumentation(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
        """)
        sites, has_instr = scan_file(f)
        assert len(sites) == 1
        assert sites[0].instrumented is False
        assert has_instr is False
        assert sites[0].fix is not None


# ---------------------------------------------------------------------------
# Fix suggestions
# ---------------------------------------------------------------------------

class TestFixSuggestions:
    def test_openai_fix(self):
        fix = _suggest_fix("client.chat.completions.create")
        assert "assay.integrations.openai" in fix

    def test_anthropic_fix(self):
        fix = _suggest_fix("client.messages.create")
        assert "assay.integrations.anthropic" in fix

    def test_langchain_fix(self):
        fix = _suggest_fix("ChatOpenAI")
        assert "AssayCallbackHandler" in fix

    def test_generic_fix(self):
        fix = _suggest_fix("call_llm")
        assert "emit_receipt" in fix


# ---------------------------------------------------------------------------
# ScanResult model
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_empty_result(self):
        r = ScanResult()
        assert r.summary["sites_total"] == 0
        assert r.status == "pass"
        assert r.next_command is None

    def test_status_fail_on_high(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False),
        ])
        assert r.status == "fail"

    def test_status_warn_on_medium(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "chain.invoke", Confidence.MEDIUM, False),
        ])
        assert r.status == "warn"

    def test_status_warn_on_low(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "call_llm", Confidence.LOW, False),
        ])
        assert r.status == "warn"

    def test_status_pass_when_all_instrumented(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, True),
            CallSite("f.py", 5, "chain.invoke", Confidence.MEDIUM, True),
        ])
        assert r.status == "pass"

    def test_summary_counts(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False),
            CallSite("f.py", 2, "chain.invoke", Confidence.MEDIUM, False),
            CallSite("f.py", 3, "call_llm", Confidence.LOW, False),
            CallSite("g.py", 1, "client.chat.completions.create", Confidence.HIGH, True),
        ])
        s = r.summary
        assert s["sites_total"] == 4
        assert s["instrumented"] == 1
        assert s["uninstrumented"] == 3
        assert s["high"] == 1
        assert s["medium"] == 1
        assert s["low"] == 1

    def test_next_command_openai(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False),
        ])
        assert "openai" in r.next_command

    def test_next_command_anthropic(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.messages.create", Confidence.HIGH, False),
        ])
        assert "anthropic" in r.next_command

    def test_next_command_multi_framework_prefers_patch_command(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False, framework="openai"),
            CallSite("f.py", 2, "client.messages.create", Confidence.HIGH, False, framework="anthropic"),
        ])
        assert "assay patch ." in r.next_command

    def test_next_steps_all_instrumented_skip_patch_guidance(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, True, framework="openai"),
            CallSite("g.py", 2, "client.messages.create", Confidence.HIGH, True, framework="anthropic"),
        ])
        steps = r.next_steps
        assert len(steps) == 3
        # Should guide into run/verify/lock/ci, not re-patching.
        assert steps[0]["commands"] == ["assay run -c receipt_completeness -- python your_app.py"]
        assert "assay patch" not in " ".join(cmd for step in steps for cmd in step["commands"])
        assert "assay ci init github" in " ".join(cmd for step in steps for cmd in step["commands"])

    def test_next_command_all_instrumented_mentions_ci(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, True, framework="openai"),
        ])
        assert r.next_command is not None
        assert "assay ci init github" in r.next_command

    def test_to_dict_schema(self):
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False, fix="do this"),
        ])
        d = r.to_dict()
        assert d["tool"] == "assay-scan"
        assert d["status"] == "fail"
        assert isinstance(d["summary"], dict)
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 1
        assert d["findings"][0]["confidence"] == "high"
        assert d["findings"][0]["fix"] == "do this"
        assert d["next_command"] is not None
        assert isinstance(d["next_steps"], list)


# ---------------------------------------------------------------------------
# CallSite model
# ---------------------------------------------------------------------------

class TestCallSite:
    def test_to_dict_with_fix(self):
        cs = CallSite("app.py", 10, "client.chat.completions.create", Confidence.HIGH, False, fix="patch it")
        d = cs.to_dict()
        assert d == {
            "path": "app.py",
            "line": 10,
            "call": "client.chat.completions.create",
            "confidence": "high",
            "instrumented": False,
            "fix": "patch it",
        }

    def test_to_dict_without_fix(self):
        cs = CallSite("app.py", 10, "client.chat.completions.create", Confidence.HIGH, True)
        d = cs.to_dict()
        assert "fix" not in d


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------

class TestDirectoryScanning:
    def test_scan_finds_files_recursively(self, tmp_path):
        sub = tmp_path / "pkg"
        sub.mkdir()
        _write(tmp_path, "top.py", """\
            import openai
            openai.OpenAI().chat.completions.create(model="gpt-4", messages=[])
        """)
        _write(sub, "inner.py", """\
            import anthropic
            anthropic.Anthropic().messages.create(model="claude-3", messages=[])
        """)
        result = scan_directory(tmp_path)
        assert len(result.findings) == 2
        paths = {f.path for f in result.findings}
        assert "top.py" in paths
        inner_path = str(Path("pkg") / "inner.py")
        assert inner_path in paths

    def test_scan_excludes_venv(self, tmp_path):
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        _write(venv_dir, "openai_internal.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        _write(tmp_path, "app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].path == "app.py"

    def test_scan_excludes_pycache(self, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        _write(cache_dir, "cached.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path)
        assert len(result.findings) == 0

    def test_scan_excludes_proof_pack_and_challenge_pack(self, tmp_path):
        """Scanner skips assay-generated proof_pack_* and challenge_pack dirs."""
        pack_dir = tmp_path / "proof_pack_20260209T013526_8abbd030"
        pack_dir.mkdir()
        _write(pack_dir, "stray.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        challenge_dir = tmp_path / "challenge_pack"
        challenge_dir.mkdir()
        _write(challenge_dir, "stray2.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        _write(tmp_path, "app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].path == "app.py"

    def test_include_filter(self, tmp_path):
        _write(tmp_path, "app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        _write(tmp_path, "test_app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path, include=["app.py"])
        assert len(result.findings) == 1
        assert result.findings[0].path == "app.py"

    def test_exclude_filter(self, tmp_path):
        _write(tmp_path, "app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        _write(tmp_path, "test_app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path, exclude=["test_*"])
        assert len(result.findings) == 1
        assert result.findings[0].path == "app.py"

    def test_findings_sorted_by_path_and_line(self, tmp_path):
        _write(tmp_path, "b.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        _write(tmp_path, "a.py", """\
            client.messages.create(model="claude-3", messages=[])
        """)
        result = scan_directory(tmp_path)
        assert result.findings[0].path == "a.py"
        assert result.findings[1].path == "b.py"

    def test_empty_directory(self, tmp_path):
        result = scan_directory(tmp_path)
        assert len(result.findings) == 0
        assert result.status == "pass"

    def test_relative_paths_in_output(self, tmp_path):
        _write(tmp_path, "app.py", """\
            client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path)
        # Paths should be relative, not absolute
        assert not result.findings[0].path.startswith("/")


# ---------------------------------------------------------------------------
# Mixed confidence in one file
# ---------------------------------------------------------------------------

class TestMixedConfidence:
    def test_high_and_medium_same_file(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import openai
            from langchain_core.runnables import RunnableSequence
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
            chain = build_chain()
            result = chain.invoke({"input": "hello"})
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 2
        confidences = {s.confidence for s in sites}
        assert Confidence.HIGH in confidences
        assert Confidence.MEDIUM in confidences

    def test_all_three_levels(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import openai
            from langchain_core.runnables import RunnableSequence
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
            result = chain.invoke({"input": "hello"})
            result2 = call_llm("hi")
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 3
        confidences = {s.confidence for s in sites}
        assert confidences == {Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW}


# ---------------------------------------------------------------------------
# JSON output contract (schema snapshot)
# ---------------------------------------------------------------------------

class TestJSONContract:
    def test_json_schema_shape(self):
        """The JSON output must always have these top-level keys."""
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False, fix="do this"),
        ])
        d = r.to_dict()
        assert set(d.keys()) == {"tool", "status", "summary", "findings", "next_command", "next_steps"}
        assert set(d["summary"].keys()) == {
            "sites_total", "instrumented", "uninstrumented", "high", "medium", "low",
        }
        finding = d["findings"][0]
        assert set(finding.keys()) == {"path", "line", "call", "confidence", "instrumented", "fix"}

    def test_json_round_trips(self):
        """to_dict output must be JSON-serializable."""
        r = ScanResult(findings=[
            CallSite("f.py", 1, "client.chat.completions.create", Confidence.HIGH, False, fix="x"),
            CallSite("g.py", 5, "chain.invoke", Confidence.MEDIUM, True),
        ])
        raw = json.dumps(r.to_dict())
        parsed = json.loads(raw)
        assert parsed["tool"] == "assay-scan"
        assert len(parsed["findings"]) == 2

    def test_instrumented_finding_has_no_fix(self):
        """Instrumented findings must not have a fix key."""
        cs = CallSite("f.py", 1, "x", Confidence.HIGH, True)
        d = cs.to_dict()
        assert "fix" not in d


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestGoldenFixture:
    """Golden output test: prevents accidental schema/field drift in scanner output."""

    def test_golden_openai_uninstrumented(self, tmp_path):
        """Canonical OpenAI finding must always produce this exact shape."""
        f = _write(tmp_path, "app.py", """\
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path)
        d = result.to_dict()

        # Top-level keys (schema contract)
        assert set(d.keys()) == {"tool", "status", "summary", "findings", "next_command", "next_steps"}
        assert d["tool"] == "assay-scan"
        assert d["status"] == "fail"

        # Summary keys (schema contract)
        assert set(d["summary"].keys()) == {
            "sites_total", "instrumented", "uninstrumented", "high", "medium", "low",
        }
        assert d["summary"]["sites_total"] == 1
        assert d["summary"]["uninstrumented"] == 1
        assert d["summary"]["high"] == 1

        # Finding keys (schema contract)
        f0 = d["findings"][0]
        assert set(f0.keys()) == {"path", "line", "call", "confidence", "instrumented", "fix", "framework"}
        assert f0["path"] == "app.py"
        assert f0["confidence"] == "high"
        assert f0["instrumented"] is False
        assert "openai" in f0["fix"]
        assert f0["call"] == "client.chat.completions.create"
        assert f0["framework"] == "openai"

        # next_command present for openai findings
        assert d["next_command"] is not None
        assert "openai" in d["next_command"]

    def test_golden_instrumented(self, tmp_path):
        """Instrumented finding must not have fix key."""
        f = _write(tmp_path, "app.py", """\
            from assay.integrations.openai import patch
            patch()
            import openai
            client = openai.OpenAI()
            resp = client.chat.completions.create(model="gpt-4", messages=[])
        """)
        result = scan_directory(tmp_path)
        d = result.to_dict()
        assert d["status"] == "pass"
        assert d["summary"]["instrumented"] == 1
        assert d["summary"]["uninstrumented"] == 0
        f0 = d["findings"][0]
        assert f0["instrumented"] is True
        assert "fix" not in f0

    def test_golden_empty_project(self, tmp_path):
        """Empty project must produce clean pass with no findings."""
        (tmp_path / "empty.py").write_text("x = 1\n")
        result = scan_directory(tmp_path)
        d = result.to_dict()
        assert d["status"] == "pass"
        assert d["findings"] == []
        assert d["summary"]["sites_total"] == 0
        assert d["next_command"] is None


class TestEdgeCases:
    def test_async_openai_call(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            import openai
            client = openai.AsyncOpenAI()
            resp = await client.chat.completions.create(model="gpt-4", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.HIGH

    def test_nested_attribute_access(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            resp = self.client.chat.completions.create(model="gpt-4", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].confidence == Confidence.HIGH

    def test_multiline_call(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            resp = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "user", "content": "hi"}
                ],
            )
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1

    def test_binary_file_skipped(self, tmp_path):
        """Binary files that happen to end with .py should not crash."""
        f = tmp_path / "binary.py"
        f.write_bytes(b"\x00\x01\x02\xff\xfe")
        sites, _ = scan_file(f)
        assert len(sites) == 0

    def test_line_numbers_are_correct(self, tmp_path):
        f = _write(tmp_path, "app.py", """\
            # line 1
            # line 2
            import openai
            client = openai.OpenAI()
            # line 5
            resp = client.chat.completions.create(model="gpt-4", messages=[])
        """)
        sites, _ = scan_file(f)
        assert len(sites) == 1
        assert sites[0].line == 6
