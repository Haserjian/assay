"""Tests for assay.bridge — the hard shim for untrusted tool orchestrators."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from assay.bridge import (
    BridgeConfig,
    InvokeResult,
    ReceiptBridge,
    ToolPolicy,
    _host_is_private,
    _preview,
    _sha256_text,
)


# ---------------------------------------------------------------------------
# ToolPolicy tests
# ---------------------------------------------------------------------------

class TestToolPolicy:
    def setup_method(self):
        self.policy = ToolPolicy()

    def test_safe_tool_allowed(self):
        v = self.policy.check("web_search", {"query": "hello"})
        assert v.allowed is True

    def test_dangerous_tool_denied(self):
        v = self.policy.check("shell_exec", {"cmd": "rm -rf /"})
        assert v.allowed is False
        assert "disabled" in v.reason

    def test_unknown_tool_denied(self):
        v = self.policy.check("mystery_tool", {})
        assert v.allowed is False
        assert "default deny" in v.reason.lower()

    def test_web_fetch_allowed_public_url(self):
        v = self.policy.check("web_fetch", {"url": "https://docs.python.org/3/"})
        assert v.allowed is True

    def test_web_fetch_denied_localhost(self):
        v = self.policy.check("web_fetch", {"url": "http://127.0.0.1:8080/admin"})
        assert v.allowed is False
        assert "POLICY_URL_002" == v.policy_ref

    def test_web_fetch_denied_metadata_endpoint(self):
        v = self.policy.check("web_fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert v.allowed is False

    def test_web_fetch_denied_private_10(self):
        v = self.policy.check("web_fetch", {"url": "http://10.0.0.1/internal"})
        assert v.allowed is False

    def test_web_fetch_denied_private_172(self):
        v = self.policy.check("web_fetch", {"url": "http://172.16.0.1/secret"})
        assert v.allowed is False

    def test_web_fetch_denied_private_192(self):
        v = self.policy.check("web_fetch", {"url": "http://192.168.1.1/router"})
        assert v.allowed is False

    def test_web_fetch_denied_non_http_scheme(self):
        v = self.policy.check("web_fetch", {"url": "file:///etc/passwd"})
        assert v.allowed is False
        assert "POLICY_URL_001" == v.policy_ref

    def test_web_fetch_denied_ftp_scheme(self):
        v = self.policy.check("web_fetch", {"url": "ftp://evil.com/payload"})
        assert v.allowed is False

    def test_web_fetch_denied_empty_url(self):
        v = self.policy.check("web_fetch", {"url": ""})
        assert v.allowed is False

    def test_web_fetch_denied_no_url_key(self):
        v = self.policy.check("web_fetch", {})
        assert v.allowed is False

    def test_policy_hash_stable(self):
        h1 = self.policy.policy_hash()
        h2 = self.policy.policy_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_custom_safe_tools(self):
        p = ToolPolicy(safe_tools=frozenset({"my_tool"}))
        assert p.check("my_tool", {}).allowed is True
        assert p.check("web_search", {}).allowed is False  # no longer safe


class TestHostIsPrivate:
    def test_localhost_v4(self):
        assert _host_is_private("127.0.0.1") is True

    def test_localhost_v6(self):
        assert _host_is_private("::1") is True

    def test_public_ip(self):
        assert _host_is_private("8.8.8.8") is False

    def test_link_local(self):
        assert _host_is_private("169.254.169.254") is True

    def test_unresolvable_fails_closed(self):
        assert _host_is_private("this-host-does-not-exist-xyz123.invalid") is True


# ---------------------------------------------------------------------------
# Mock invoker for testing ReceiptBridge without real subprocess
# ---------------------------------------------------------------------------

class MockInvoker:
    """Configurable mock that records calls."""

    def __init__(
        self,
        exit_code: int = 0,
        stdout: str = "mock output",
        stderr: str = "",
        duration_ms: float = 42.0,
        timed_out: bool = False,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.timed_out = timed_out
        self.calls: list[tuple[str, Dict[str, Any]]] = []

    def invoke(self, tool_name: str, arguments: Dict[str, Any]) -> InvokeResult:
        self.calls.append((tool_name, arguments))
        return InvokeResult(
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            duration_ms=self.duration_ms,
            timed_out=self.timed_out,
        )


# ---------------------------------------------------------------------------
# ReceiptBridge tests
# ---------------------------------------------------------------------------

class TestReceiptBridge:
    def _make_bridge(self, tmp_path: Path, **invoker_kwargs) -> tuple[ReceiptBridge, MockInvoker]:
        cfg = BridgeConfig(artifacts_dir=tmp_path / "artifacts", cwd=str(tmp_path))
        invoker = MockInvoker(**invoker_kwargs)
        bridge = ReceiptBridge(cfg=cfg, invoker=invoker, agent_id="test-agent")
        return bridge, invoker

    def test_allowed_tool_produces_execution_receipt(self, tmp_path):
        bridge, invoker = self._make_bridge(tmp_path)
        receipt = bridge.run_tool("s1", "web_search", {"query": "test"})

        assert receipt["receipt_type"] == "BridgeExecution"
        assert receipt["allowed"] is True
        assert receipt["outcome"] == "ok"
        assert receipt["exit_code"] == 0
        assert receipt["tool_name"] == "web_search"
        assert receipt["agent_id"] == "test-agent"
        assert receipt["session_id"] == "s1"
        assert "stdout_sha256" in receipt
        assert "stderr_sha256" in receipt
        assert "stdout_preview" in receipt
        assert "policy_hash" in receipt
        assert len(receipt["receipt_id"]) > 0

    def test_denied_tool_produces_denial_receipt(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path)
        receipt = bridge.run_tool("s1", "shell_exec", {"cmd": "rm -rf /"})

        assert receipt["receipt_type"] == "BridgeDenial"
        assert receipt["allowed"] is False
        assert "denial_reason" in receipt
        assert receipt["tool_name"] == "shell_exec"
        assert "arguments_sha256" in receipt

    def test_denied_tool_never_invokes(self, tmp_path):
        bridge, invoker = self._make_bridge(tmp_path)
        bridge.run_tool("s1", "file_delete", {"path": "/important"})
        assert len(invoker.calls) == 0

    def test_ssrf_denied_web_fetch(self, tmp_path):
        bridge, invoker = self._make_bridge(tmp_path)
        receipt = bridge.run_tool("s1", "web_fetch", {"url": "http://127.0.0.1:9200/_cat/indices"})

        assert receipt["allowed"] is False
        assert receipt["receipt_type"] == "BridgeDenial"
        assert len(invoker.calls) == 0

    def test_timeout_produces_receipt(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path, timed_out=True, exit_code=None, stderr="[bridge] TIMEOUT")
        receipt = bridge.run_tool("s1", "web_search", {"query": "slow"})

        assert receipt["receipt_type"] == "BridgeExecution"
        assert receipt["outcome"] == "timeout"
        assert receipt["exit_code"] is None

    def test_error_exit_produces_error_outcome(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path, exit_code=1, stderr="error: bad input")
        receipt = bridge.run_tool("s1", "web_search", {"query": "bad"})

        assert receipt["outcome"] == "error"
        assert receipt["exit_code"] == 1

    def test_artifacts_written_to_disk(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path)
        bridge.run_tool("s1", "web_search", {"query": "hello"})

        current = tmp_path / "artifacts" / "current"
        history = tmp_path / "artifacts" / "history"
        assert current.exists()
        assert history.exists()

        current_files = list(current.glob("*.json"))
        assert len(current_files) == 1
        assert "execution_web_search_latest.json" == current_files[0].name

        history_files = list(history.glob("*.json"))
        assert len(history_files) == 1

        # Verify JSON is valid
        data = json.loads(current_files[0].read_text())
        assert data["receipt_type"] == "BridgeExecution"

    def test_denial_artifacts_written(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path)
        bridge.run_tool("s1", "shell_exec", {"cmd": "bad"})

        current_files = list((tmp_path / "artifacts" / "current").glob("*.json"))
        assert any("denial_shell_exec" in f.name for f in current_files)

    def test_full_payload_written_when_enabled(self, tmp_path):
        cfg = BridgeConfig(
            artifacts_dir=tmp_path / "artifacts",
            cwd=str(tmp_path),
            write_full_payload=True,
        )
        invoker = MockInvoker(stdout="big output here")
        bridge = ReceiptBridge(cfg=cfg, invoker=invoker, agent_id="test")
        receipt = bridge.run_tool("s1", "web_search", {"query": "x"})

        assert "stdout_artifact_path" in receipt
        payload_path = Path(receipt["stdout_artifact_path"])
        assert payload_path.exists()
        assert payload_path.read_text().strip() == "big output here"

    def test_payload_not_written_by_default(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path)
        receipt = bridge.run_tool("s1", "web_search", {"query": "x"})

        assert "stdout_artifact_path" not in receipt

    def test_stdout_hash_deterministic(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path, stdout="deterministic")
        r1 = bridge.run_tool("s1", "web_search", {"query": "a"})
        r2 = bridge.run_tool("s2", "web_search", {"query": "b"})
        assert r1["stdout_sha256"] == r2["stdout_sha256"]

    def test_arguments_not_in_receipt_plaintext(self, tmp_path):
        """Arguments should be hashed, not stored in plaintext."""
        bridge, _ = self._make_bridge(tmp_path)
        receipt = bridge.run_tool("s1", "web_search", {"query": "secret_password_123"})

        receipt_json = json.dumps(receipt)
        assert "secret_password_123" not in receipt_json
        assert "arguments_sha256" in receipt

    def test_multiple_runs_create_history(self, tmp_path):
        bridge, _ = self._make_bridge(tmp_path)
        bridge.run_tool("s1", "web_search", {"query": "first"})
        bridge.run_tool("s2", "web_search", {"query": "second"})

        history_files = list((tmp_path / "artifacts" / "history").glob("*.json"))
        assert len(history_files) == 2

        # Current should have only latest
        current_files = list((tmp_path / "artifacts" / "current").glob("*.json"))
        assert len(current_files) == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_sha256_text_stable(self):
        assert _sha256_text("hello") == _sha256_text("hello")
        assert _sha256_text("hello") != _sha256_text("world")

    def test_preview_short_unchanged(self):
        assert _preview("short", 1000) == "short"

    def test_preview_long_truncated(self):
        long = "x" * 10000
        p = _preview(long, 100)
        assert len(p.encode("utf-8")) < 200
        assert "PREVIEW_TRUNCATED" in p

    def test_preview_unicode_safe(self):
        # Multi-byte chars shouldn't break at byte boundary
        text = "\U0001f600" * 100  # emoji
        p = _preview(text, 50)
        assert "PREVIEW_TRUNCATED" in p


# ---------------------------------------------------------------------------
# InvokeResult
# ---------------------------------------------------------------------------

class TestInvokeResult:
    def test_frozen(self):
        r = InvokeResult(exit_code=0, stdout="ok", stderr="", duration_ms=10.0)
        with pytest.raises(AttributeError):
            r.exit_code = 1  # type: ignore[misc]

    def test_timeout_result(self):
        r = InvokeResult(exit_code=None, stdout="", stderr="[bridge] TIMEOUT",
                         duration_ms=90000.0, timed_out=True)
        assert r.timed_out is True
        assert r.exit_code is None


# ---------------------------------------------------------------------------
# BridgeConfig
# ---------------------------------------------------------------------------

class TestBridgeConfig:
    def test_defaults(self):
        cfg = BridgeConfig()
        assert cfg.timeout_s == 90
        assert cfg.tz == "UTC"
        assert cfg.locale == "C"
        assert cfg.pythonhashseed == "0"
        assert cfg.max_preview_bytes == 16_000

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("OPENCLAW_BIN", "/usr/local/bin/my-openclaw")
        cfg = BridgeConfig()
        assert cfg.openclaw_bin == "/usr/local/bin/my-openclaw"

    def test_frozen(self):
        cfg = BridgeConfig()
        with pytest.raises(AttributeError):
            cfg.timeout_s = 999  # type: ignore[misc]
