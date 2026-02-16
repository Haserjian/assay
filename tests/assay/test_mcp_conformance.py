"""MCP Gateway Conformance Tests for Assay MCP Proxy v0.

Maps all 9 MUSTs from MCP_MINIMUM_PROFILE.md (assay-protocol) to test
functions against assay's mcp_proxy.py.

## Conformance Matrix

| MUST | Requirement                          | Proxy v0 Status | Coverage |
|------|--------------------------------------|-----------------|----------|
| 1    | Tool Inventory + Trust Classification | NOT_APPLICABLE  | SKIP     |
| 2    | AuthN on Every Request               | NOT_APPLICABLE  | SKIP     |
| 3    | Identity-Bound Tool Discovery        | NOT_APPLICABLE  | SKIP     |
| 4    | Runtime AuthZ per Invocation         | NOT_APPLICABLE  | SKIP     |
| 5    | Credential Boundary                  | NOT_APPLICABLE  | SKIP     |
| 6    | OAuth Proxy Safety                   | NOT_APPLICABLE  | SKIP     |
| 7    | Preflight Validation                 | NOT_APPLICABLE  | SKIP     |
| 8    | Execution Sandbox                    | NOT_APPLICABLE  | SKIP     |
| 9    | Audit Receipts + Incident Mode       | PARTIAL         | TESTED   |

MUSTs 1-8 are gateway-tier enforcement. The v0 MCP proxy is an audit-only
proxy that observes and receipts tool calls without enforcement. These
MUSTs are tested by assay-protocol's reference gateway conformance suite
(run via CI multi-checkout in mcp-conformance.yml).

MUST 9 (Audit Receipts) is partially implemented: receipts are emitted for
every tools/call, but the receipt schema is a superset/subset of the
protocol's required schema, and incident mode is not yet implemented.

Reference: https://github.com/Haserjian/assay-protocol/blob/main/MCP_MINIMUM_PROFILE.md
"""
from __future__ import annotations

import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

from assay.mcp_proxy import MCPProxy, _jcs_sha256, _now_iso


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proxy(**kwargs) -> MCPProxy:
    """Create a proxy instance for testing."""
    defaults = {"server_id": "conformance-test", "auto_pack": False}
    defaults.update(kwargs)
    return MCPProxy(**defaults)


def _simulate_tool_call(proxy: MCPProxy, req_id: int = 1,
                        tool_name: str = "test_tool",
                        arguments: dict | None = None,
                        error: bool = False) -> dict:
    """Simulate a tool call round-trip and return the receipt."""
    proxy._on_tool_call_request({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
    })
    if error:
        response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32000, "message": "Tool failed"},
        }
    else:
        response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": f"result for {tool_name}"}]},
        }
    with patch.object(proxy, "_emit_to_store"):
        proxy._on_tool_call_response(req_id, response)
    return proxy.receipts[-1]


# ---------------------------------------------------------------------------
# MUSTs 1-8: Gateway-tier enforcement (not applicable to audit proxy)
# ---------------------------------------------------------------------------


class TestMCPConformanceMatrix:
    """Placeholder tests for MUSTs 1-8.

    These are NOT expected to pass against the v0 audit proxy. They exist to:
    1. Make the conformance gap visible in pytest output
    2. Serve as a roadmap for future gateway capabilities
    3. Link each MUST to its spec reference

    The reference MCPGateway implementation passes all of these via
    assay-protocol's test_conformance.py (run in CI multi-checkout).
    """

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 1 (Tool Inventory + Trust "
        "Classification). Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 1"
    ))
    def test_must_1_tool_inventory(self):
        """MUST 1: Maintain tool inventory with trust classification."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 2 (AuthN). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 2"
    ))
    def test_must_2_authn(self):
        """MUST 2: AuthN on every gateway request."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 3 (Identity-Bound Discovery). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 3"
    ))
    def test_must_3_identity_discovery(self):
        """MUST 3: tools/list filtered by principal permissions."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 4 (Runtime AuthZ). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 4"
    ))
    def test_must_4_runtime_authz(self):
        """MUST 4: Runtime AuthZ on each tools/call invocation."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 5 (Credential Boundary). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 5"
    ))
    def test_must_5_credential_boundary(self):
        """MUST 5: No token passthrough to upstream servers."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 6 (OAuth Proxy Safety). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 6"
    ))
    def test_must_6_oauth_proxy(self):
        """MUST 6: Confused deputy protections for OAuth proxying."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 7 (Preflight Validation). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 7"
    ))
    def test_must_7_preflight_validation(self):
        """MUST 7: Schema validation, size limits, path restrictions."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement MUST 8 (Execution Sandbox). "
        "Gateway-tier enforcement. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 8"
    ))
    def test_must_8_execution_sandbox(self):
        """MUST 8: Filesystem + network isolation for untrusted tools."""


# ---------------------------------------------------------------------------
# MUST 9: Audit Receipts
# ---------------------------------------------------------------------------


class TestMust9AuditReceipts:
    """MUST 9 (partial): Audit receipts for every tools/call.

    The protocol requires receipts with specific fields (see Receipt Schema
    in MCP_MINIMUM_PROFILE.md). The v0 proxy emits receipts with its own
    schema (MCPToolCallReceipt v3.0) which overlaps but does not fully match.

    Tests verify what the proxy DOES provide. The schema coverage test at
    the bottom documents the gap.
    """

    def test_rcpt_every_tool_call_emits_receipt(self):
        """Every tools/call request-response pair emits exactly one receipt."""
        proxy = _make_proxy()
        for i in range(1, 4):
            _simulate_tool_call(proxy, req_id=i, tool_name=f"tool_{i}")
        assert len(proxy.receipts) == 3

    def test_rcpt_has_required_id_fields(self):
        """Receipt has receipt_id and timestamp."""
        proxy = _make_proxy()
        r = _simulate_tool_call(proxy)
        assert r["receipt_id"] is not None
        assert r["receipt_id"].startswith("mtc_")
        assert r["timestamp"] is not None
        assert r["timestamp"].endswith("Z")
        assert "T" in r["timestamp"]

    def test_rcpt_has_trace_id(self):
        """Receipt includes trace_id for distributed trace correlation."""
        proxy = _make_proxy()
        r = _simulate_tool_call(proxy)
        assert "trace_id" in r, "trace_id missing from receipt"
        assert r["trace_id"] is not None
        assert r["trace_id"] == proxy.trace_id

    def test_rcpt_has_mcp_context(self):
        """Receipt includes MCP context: server_id and tool_name."""
        proxy = _make_proxy(server_id="my-server")
        r = _simulate_tool_call(proxy, tool_name="web_search")
        assert r["server_id"] == "my-server"
        assert r["tool_name"] == "web_search"
        assert r["server_transport"] == "stdio"

    def test_rcpt_has_args_hash(self):
        """Receipt includes arguments_hash (privacy-by-default)."""
        proxy = _make_proxy()
        args = {"query": "sensitive data", "limit": 10}
        r = _simulate_tool_call(proxy, arguments=args)
        assert r["arguments_hash"] is not None
        assert r["arguments_hash"].startswith("sha256:")
        # By default, cleartext is NOT stored
        assert r["arguments_content"] is None
        # Hash is deterministic
        assert r["arguments_hash"] == _jcs_sha256(args)

    def test_rcpt_has_outcome(self):
        """Receipt includes outcome status."""
        proxy = _make_proxy()
        r = _simulate_tool_call(proxy)
        assert r["outcome"] == "forwarded"
        assert r["result_is_error"] is False

    def test_rcpt_has_duration(self):
        """Receipt includes duration_ms measurement."""
        proxy = _make_proxy()
        r = _simulate_tool_call(proxy)
        assert "duration_ms" in r
        assert isinstance(r["duration_ms"], (int, float))
        assert r["duration_ms"] >= 0

    def test_rcpt_error_response_also_receipted(self):
        """Error responses (JSON-RPC error or MCP isError) emit receipts."""
        proxy = _make_proxy()
        r = _simulate_tool_call(proxy, error=True)
        assert r["outcome"] == "error"
        assert r["result_is_error"] is True
        assert r["result_hash"] is not None

    def test_rcpt_schema_field_coverage(self):
        """Document which protocol-required fields are present/absent.

        This test does NOT fail on absent fields -- it documents the gap.
        Missing fields emit warnings visible in pytest -v output.
        """
        proxy = _make_proxy()
        r = _simulate_tool_call(proxy, tool_name="coverage_test",
                                arguments={"input": "data"})

        # Protocol-required fields -> proxy field mapping
        # See MCP_MINIMUM_PROFILE.md Receipt Schema (Minimum Fields)
        field_map = {
            # (protocol_field, proxy_field, required_in_v0)
            ("ts", "timestamp", True),
            ("receipt_id", "receipt_id", True),
            ("trace_id", "trace_id", True),
            ("principal.sub", None, False),
            ("principal.actor_type", None, False),
            ("principal.client_id", None, False),
            ("principal.org_id", None, False),
            ("mcp.method", None, False),
            ("mcp.server_id", "server_id", True),
            ("mcp.tool_name", "tool_name", True),
            ("mcp.trust_level", None, False),
            ("request.args_hash", "arguments_hash", True),
            ("request.size_bytes_in", None, False),
            ("decision.result", "policy_verdict", True),
            ("decision.policy_id", "policy_ref", True),
            ("decision.reason_codes", None, False),
            ("token_handling.mode", None, False),
            ("token_handling.audience", None, False),
            ("token_handling.passthrough_detected", None, False),
            ("sandbox.fs_policy", None, False),
            ("sandbox.net_policy", None, False),
            ("approval.required", None, False),
            ("approval.approved_by", None, False),
            ("approval.step_up", None, False),
            ("outcome.status", "outcome", True),
            ("outcome.size_bytes_out", None, False),
        }

        present = 0
        absent = 0
        for proto_field, proxy_field, required_v0 in field_map:
            if proxy_field and proxy_field in r:
                present += 1
            else:
                absent += 1
                if not required_v0:
                    warnings.warn(
                        f"Protocol field '{proto_field}' not mapped in v0 proxy "
                        f"(gateway-tier or future)",
                        stacklevel=1,
                    )

        # At minimum, the v0 proxy should have these core fields
        assert present >= 9, (
            f"Expected at least 9 mapped fields, got {present}. "
            f"Present: {present}, Absent: {absent}"
        )
        # Document the coverage ratio
        total = present + absent
        coverage_pct = round(100 * present / total, 1)
        warnings.warn(
            f"Protocol receipt field coverage: {present}/{total} "
            f"({coverage_pct}%). "
            f"Absent fields are gateway-tier (MUSTs 1-8) or future scope.",
            stacklevel=1,
        )


# ---------------------------------------------------------------------------
# MUST 9: Incident Mode (not yet implemented)
# ---------------------------------------------------------------------------


class TestMust9IncidentMode:
    """MUST 9 (incident mode): Not implemented in v0 audit proxy."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement incident mode "
        "(kill switch, key revocation, egress block, quarantine). "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 9, Incident Mode section"
    ))
    def test_incident_kill_switch(self):
        """Kill switch denies high-risk tools when incident mode active."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement incident mode. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 9"
    ))
    def test_incident_key_revocation(self):
        """Key/token revocation on incident activation."""

    @pytest.mark.skip(reason=(
        "v0: audit proxy does not implement incident mode. "
        "Ref: MCP_MINIMUM_PROFILE.md MUST 9"
    ))
    def test_incident_receipts_flag(self):
        """Receipts include incident_mode flag when active."""


# ---------------------------------------------------------------------------
# Skip matrix enforcement
# ---------------------------------------------------------------------------


class TestSkipMatrixEnforcement:
    """Assert that the skip matrix YAML matches actual skips.

    Guardrail: adding a new skip without updating mcp_skip_matrix.yaml
    will fail this test. Removing a skip (implementing a MUST) without
    updating the YAML will also fail.
    """

    def _load_skip_matrix(self) -> dict:
        import yaml
        matrix_path = Path(__file__).parent / "mcp_skip_matrix.yaml"
        with open(matrix_path) as f:
            return yaml.safe_load(f)

    def _collect_skipped_tests(self) -> list[str]:
        """Collect all skipped test names from this module's conformance classes."""
        import inspect
        skipped = []
        # Classes that contain skipped tests
        conformance_classes = [TestMCPConformanceMatrix, TestMust9IncidentMode]
        for cls in conformance_classes:
            for name, method in inspect.getmembers(cls, predicate=inspect.isfunction):
                if not name.startswith("test_"):
                    continue
                markers = getattr(method, "pytestmark", [])
                for marker in markers:
                    if marker.name == "skip":
                        skipped.append(f"{cls.__name__}::{name}")
        return sorted(skipped)

    def test_skip_count_matches_matrix(self):
        """Number of skipped tests matches expected_skip_count in YAML."""
        matrix = self._load_skip_matrix()
        actual_skipped = self._collect_skipped_tests()
        expected_count = matrix["expected_skip_count"]
        assert len(actual_skipped) == expected_count, (
            f"Skip count mismatch: {len(actual_skipped)} actual vs "
            f"{expected_count} expected in mcp_skip_matrix.yaml. "
            f"Actual skips: {actual_skipped}"
        )

    def test_every_skip_in_matrix(self):
        """Every skipped test has an entry in the YAML matrix."""
        matrix = self._load_skip_matrix()
        matrix_tests = {s["test"] for s in matrix["skips"]}
        actual_skipped = set(self._collect_skipped_tests())

        missing_from_matrix = actual_skipped - matrix_tests
        assert not missing_from_matrix, (
            f"Skipped tests not in mcp_skip_matrix.yaml: {missing_from_matrix}. "
            f"Add entries with must_id + unblock_condition."
        )

    def test_no_stale_matrix_entries(self):
        """Every matrix entry corresponds to an actual skipped test."""
        matrix = self._load_skip_matrix()
        matrix_tests = {s["test"] for s in matrix["skips"]}
        actual_skipped = set(self._collect_skipped_tests())

        stale_entries = matrix_tests - actual_skipped
        assert not stale_entries, (
            f"Stale entries in mcp_skip_matrix.yaml (test no longer skipped): "
            f"{stale_entries}. Remove entries for implemented MUSTs."
        )


# ---------------------------------------------------------------------------
# Conformance report generator (machine-readable artifact)
# ---------------------------------------------------------------------------


def generate_conformance_report(results: dict | None = None) -> dict:
    """Generate a machine-readable conformance report.

    Called from conftest.py pytest_sessionfinish hook or standalone.
    Returns a dict suitable for JSON serialization.
    """
    import datetime

    proxy = _make_proxy()
    receipt = _simulate_tool_call(proxy, tool_name="conformance_probe")

    # Protocol field coverage
    protocol_fields = [
        "ts", "receipt_id", "trace_id",
        "principal.sub", "principal.actor_type", "principal.client_id", "principal.org_id",
        "mcp.method", "mcp.server_id", "mcp.tool_name", "mcp.trust_level",
        "request.args_hash", "request.size_bytes_in",
        "decision.result", "decision.policy_id", "decision.reason_codes",
        "token_handling.mode", "token_handling.audience", "token_handling.passthrough_detected",
        "sandbox.fs_policy", "sandbox.net_policy",
        "approval.required", "approval.approved_by", "approval.step_up",
        "outcome.status", "outcome.size_bytes_out",
    ]
    field_map = {
        "ts": "timestamp", "receipt_id": "receipt_id", "trace_id": "trace_id",
        "mcp.server_id": "server_id", "mcp.tool_name": "tool_name",
        "request.args_hash": "arguments_hash",
        "decision.result": "policy_verdict", "decision.policy_id": "policy_ref",
        "outcome.status": "outcome",
    }
    fields_present = []
    fields_absent = []
    for pf in protocol_fields:
        proxy_field = field_map.get(pf)
        if proxy_field and proxy_field in receipt:
            fields_present.append(pf)
        else:
            fields_absent.append(pf)

    must_status = {}
    for i in range(1, 10):
        if i <= 8:
            must_status[f"MUST_{i}"] = "NOT_APPLICABLE"
        else:
            must_status[f"MUST_{i}"] = "PARTIAL"

    report = {
        "report_version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tier": "proxy",
        "proxy_version": receipt.get("proxy_version", "unknown"),
        "schema_version": receipt.get("schema_version", "unknown"),
        "must_status": must_status,
        "receipt_field_coverage": {
            "total": len(protocol_fields),
            "present": len(fields_present),
            "absent": len(fields_absent),
            "coverage_pct": round(100 * len(fields_present) / len(protocol_fields), 1),
            "fields_present": fields_present,
            "fields_absent": fields_absent,
        },
        "skip_count": 11,
        "pass_count": results.get("passed", 0) if results else 0,
        "fail_count": results.get("failed", 0) if results else 0,
    }
    return report
