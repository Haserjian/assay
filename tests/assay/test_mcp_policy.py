"""Tests for assay MCP Guard Profile: policy loader, evaluator, and budget tracker."""
from __future__ import annotations

from pathlib import Path

import pytest

from assay.mcp_policy import (
    MCPPolicy,
    PolicyDecision,
    PolicyEvaluator,
    PolicyLoadError,
    ToolConstraint,
    ToolPolicy,
    _matches_any,
    compute_policy_hash,
    load_policy,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_policy(tmp_path: Path, content: str, name: str = "policy.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


MINIMAL_POLICY = """\
version: "1"
server_id: test-server
mode: audit
"""

ENFORCE_POLICY = """\
version: "1"
server_id: test-server
mode: enforce
store_args: false
store_results: false

tools:
  default: allow
  deny:
    - "delete_*"
    - "drop_*"
    - "send_email"
  allow:
    - "read_*"
    - "search"

  constraints:
    web_fetch:
      max_calls: 3
    execute_query:
      max_calls: 10
      deny_patterns:
        - "DROP TABLE"
        - "DELETE FROM"

budget:
  max_tool_calls: 20
"""

DEFAULT_DENY_POLICY = """\
version: "1"
server_id: strict-server
mode: enforce

tools:
  default: deny
  allow:
    - "read_file"
    - "search"
    - "list_*"
"""


# ---------------------------------------------------------------------------
# Loader tests
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    def test_load_minimal(self, tmp_path):
        path = _write_policy(tmp_path, MINIMAL_POLICY)
        policy = load_policy(path)
        assert policy.version == "1"
        assert policy.server_id == "test-server"
        assert policy.mode == "audit"
        assert policy.tools.default == "allow"
        assert policy.source_hash.startswith("sha256:")

    def test_load_enforce(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        assert policy.mode == "enforce"
        assert "delete_*" in policy.tools.deny
        assert "read_*" in policy.tools.allow
        assert policy.tools.constraints["web_fetch"].max_calls == 3
        assert policy.budget.max_tool_calls == 20

    def test_load_default_deny(self, tmp_path):
        path = _write_policy(tmp_path, DEFAULT_DENY_POLICY)
        policy = load_policy(path)
        assert policy.tools.default == "deny"
        assert "read_file" in policy.tools.allow

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(PolicyLoadError, match="not found"):
            load_policy(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        path = _write_policy(tmp_path, "{{not: valid: yaml: [}")
        with pytest.raises(PolicyLoadError, match="parse"):
            load_policy(path)

    def test_non_mapping_raises(self, tmp_path):
        path = _write_policy(tmp_path, "- just\n- a\n- list\n")
        with pytest.raises(PolicyLoadError, match="mapping"):
            load_policy(path)

    def test_invalid_mode_raises(self, tmp_path):
        path = _write_policy(tmp_path, "mode: turbo\n")
        with pytest.raises(PolicyLoadError, match="Invalid mode"):
            load_policy(path)

    def test_invalid_default_raises(self, tmp_path):
        path = _write_policy(tmp_path, "tools:\n  default: maybe\n")
        with pytest.raises(PolicyLoadError, match="Invalid tools.default"):
            load_policy(path)

    def test_v0_backward_compat(self, tmp_path):
        """Policy without mode field defaults to audit."""
        path = _write_policy(tmp_path, "server_id: old-server\n")
        policy = load_policy(path)
        assert policy.mode == "audit"

    def test_policy_hash_deterministic(self, tmp_path):
        path = _write_policy(tmp_path, MINIMAL_POLICY)
        h1 = compute_policy_hash(path)
        h2 = compute_policy_hash(path)
        assert h1 == h2
        assert h1.startswith("sha256:")


# ---------------------------------------------------------------------------
# Glob matching tests
# ---------------------------------------------------------------------------


class TestGlobMatching:
    def test_exact_match(self):
        assert _matches_any("send_email", ["send_email"]) == "send_email"

    def test_wildcard_match(self):
        assert _matches_any("delete_user", ["delete_*"]) == "delete_*"

    def test_no_match(self):
        assert _matches_any("read_file", ["delete_*", "drop_*"]) is None

    def test_first_match_returned(self):
        assert _matches_any("delete_all", ["del*", "delete_*"]) == "del*"


# ---------------------------------------------------------------------------
# Evaluator tests
# ---------------------------------------------------------------------------


class TestEvaluator:
    def test_deny_list_blocks(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("delete_user")
        assert d.verdict == "deny"
        assert d.reason == "deny_list"
        assert "delete_*" in d.detail

    def test_allow_list_passes(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("read_file")
        assert d.verdict == "allow"

    def test_default_allow_unlisted_tool(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("custom_tool")
        assert d.verdict == "allow"

    def test_default_deny_blocks_unlisted(self, tmp_path):
        path = _write_policy(tmp_path, DEFAULT_DENY_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("custom_tool")
        assert d.verdict == "deny"
        assert d.reason == "not_in_allow"

    def test_default_deny_allows_listed(self, tmp_path):
        path = _write_policy(tmp_path, DEFAULT_DENY_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("read_file")
        assert d.verdict == "allow"

    def test_default_deny_allows_glob(self, tmp_path):
        path = _write_policy(tmp_path, DEFAULT_DENY_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("list_users")
        assert d.verdict == "allow"

    def test_deny_beats_allow(self, tmp_path):
        """Tool matching both deny and allow should be denied (deny checked first)."""
        content = """\
tools:
  default: allow
  deny:
    - "read_secret"
  allow:
    - "read_*"
"""
        path = _write_policy(tmp_path, content)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("read_secret")
        assert d.verdict == "deny"

    def test_per_tool_max_calls(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        for _ in range(3):
            d = ev.evaluate("web_fetch")
            assert d.verdict == "allow"
        d = ev.evaluate("web_fetch")
        assert d.verdict == "deny"
        assert d.reason == "tool_budget_exceeded"

    def test_deny_patterns_on_args(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("execute_query", {"sql": "DROP TABLE users"})
        assert d.verdict == "deny"
        assert d.reason == "argument_denied"

    def test_deny_patterns_no_match(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("execute_query", {"sql": "SELECT * FROM users"})
        assert d.verdict == "allow"

    def test_session_budget_exceeded(self, tmp_path):
        content = """\
tools:
  default: allow
budget:
  max_tool_calls: 3
"""
        path = _write_policy(tmp_path, content)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        for _ in range(3):
            d = ev.evaluate("any_tool")
            assert d.verdict == "allow"
        d = ev.evaluate("any_tool")
        assert d.verdict == "deny"
        assert d.reason == "session_budget_exceeded"

    def test_empty_policy_allows_all(self, tmp_path):
        path = _write_policy(tmp_path, "server_id: open\n")
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        d = ev.evaluate("anything")
        assert d.verdict == "allow"

    def test_call_counts_only_increment_on_allow(self, tmp_path):
        path = _write_policy(tmp_path, ENFORCE_POLICY)
        policy = load_policy(path)
        ev = PolicyEvaluator(policy)
        ev.evaluate("delete_user")  # denied
        ev.evaluate("delete_db")    # denied
        assert ev.total_calls == 0
        ev.evaluate("read_file")    # allowed
        assert ev.total_calls == 1
