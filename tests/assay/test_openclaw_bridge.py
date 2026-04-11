"""
Tests for OpenClaw bridge and WebToolReceipt.
"""
import pytest
import tempfile
from pathlib import Path


class TestWebToolReceipt:
    """Tests for WebToolReceipt types."""

    def test_create_web_search_receipt(self):
        """Can create a web search receipt."""
        from assay._receipts.domains.web_tool import create_web_search_receipt

        receipt = create_web_search_receipt(
            query="python asyncio tutorial",
            agent_id="agent:researcher",
            provider="brave",
            result_items=5,
        )

        assert receipt.tool == "web_search"
        assert receipt.query == "python asyncio tutorial"
        assert receipt.provider == "brave"
        assert receipt.result_items == 5
        assert receipt.allowed is True
        assert receipt.receipt_id.startswith("wtr_")

    def test_create_web_fetch_receipt(self):
        """Can create a web fetch receipt."""
        from assay._receipts.domains.web_tool import create_web_fetch_receipt

        receipt = create_web_fetch_receipt(
            url="https://docs.python.org/3/library/asyncio.html",
            agent_id="agent:researcher",
            result_size_chars=15000,
            latency_ms=450,
        )

        assert receipt.tool == "web_fetch"
        assert receipt.url == "https://docs.python.org/3/library/asyncio.html"
        assert receipt.target_domain == "docs.python.org"
        assert receipt.result_size_chars == 15000
        assert receipt.latency_ms == 450

    def test_create_browser_receipt_allowed(self):
        """Can create an allowed browser receipt."""
        from assay._receipts.domains.web_tool import create_browser_receipt

        receipt = create_browser_receipt(
            url="https://github.com/anthropics/claude-code",
            agent_id="agent:researcher",
            domain_allowlist_match=True,
            policy_rule="*.github.com",
        )

        assert receipt.tool == "browser"
        assert receipt.allowed is True
        assert receipt.domain_allowlist_match is True
        assert receipt.policy_rule == "*.github.com"

    def test_create_browser_receipt_blocked(self):
        """Browser receipt is blocked when domain not in allowlist."""
        from assay._receipts.domains.web_tool import create_browser_receipt

        receipt = create_browser_receipt(
            url="https://evil.com/malware",
            agent_id="agent:researcher",
            domain_allowlist_match=False,
        )

        assert receipt.tool == "browser"
        assert receipt.allowed is False
        assert receipt.domain_allowlist_match is False
        assert receipt.policy_rule == "domain_not_in_allowlist"

    def test_web_search_requires_query(self):
        """web_search tool requires query field."""
        from assay._receipts.domains.web_tool import WebToolReceipt

        with pytest.raises(ValueError, match="web_search requires query"):
            WebToolReceipt(
                receipt_id="wtr_test",
                tool="web_search",
                target_domain="search",
                agent_id="agent:test",
                outcome="success",
                allowed=True,
                # Missing query!
            )

    def test_web_fetch_requires_url(self):
        """web_fetch tool requires url field."""
        from assay._receipts.domains.web_tool import WebToolReceipt

        with pytest.raises(ValueError, match="web_fetch requires url"):
            WebToolReceipt(
                receipt_id="wtr_test",
                tool="web_fetch",
                target_domain="example.com",
                agent_id="agent:test",
                outcome="success",
                allowed=True,
                # Missing url!
            )

    def test_content_hash_computed(self):
        """Content hash is computed from response bytes."""
        from assay._receipts.domains.web_tool import create_web_fetch_receipt, compute_content_hash

        content = b"Hello, world!"
        expected_hash = compute_content_hash(content)

        receipt = create_web_fetch_receipt(
            url="https://example.com/",
            agent_id="agent:test",
            content=content,
        )

        assert receipt.content_hash == expected_hash
        assert receipt.content_hash.startswith("sha256:")
        assert receipt.result_size_chars == 13

    def test_redirect_chain_tracking(self):
        """Redirect chain is tracked and cross-domain detected."""
        from assay._receipts.domains.web_tool import create_web_fetch_receipt

        # Same-domain redirect
        receipt1 = create_web_fetch_receipt(
            url="https://docs.python.org/3/",
            agent_id="agent:test",
            redirect_chain=["https://docs.python.org/", "https://docs.python.org/3/"],
        )
        assert receipt1.redirect_chain == ["https://docs.python.org/", "https://docs.python.org/3/"]
        assert receipt1.crossed_domain_boundary is False

        # Cross-domain redirect
        receipt2 = create_web_fetch_receipt(
            url="https://evil.com/stolen",
            agent_id="agent:test",
            redirect_chain=["https://safe.com/link", "https://evil.com/stolen"],
        )
        assert receipt2.crossed_domain_boundary is True

    def test_sensitive_action_requires_approval(self):
        """Sensitive actions must have explicit approval status."""
        from assay._receipts.domains.web_tool import WebToolReceipt

        with pytest.raises(ValueError, match="approval status not set"):
            WebToolReceipt(
                receipt_id="wtr_test",
                tool="browser",
                url="https://bank.com/login",
                target_domain="bank.com",
                agent_id="agent:test",
                outcome="success",
                allowed=True,
                sensitive_action_attempted=True,
                sensitive_action_type="credential_entry",
                # Missing sensitive_action_approved!
            )

    def test_unapproved_sensitive_action_cannot_succeed(self):
        """Unapproved sensitive actions cannot have success outcome."""
        from assay._receipts.domains.web_tool import WebToolReceipt

        with pytest.raises(ValueError, match="Unapproved sensitive actions must be blocked"):
            WebToolReceipt(
                receipt_id="wtr_test",
                tool="browser",
                url="https://bank.com/login",
                target_domain="bank.com",
                agent_id="agent:test",
                outcome="success",  # Can't be success if not approved
                allowed=True,
                sensitive_action_attempted=True,
                sensitive_action_type="credential_entry",
                sensitive_action_approved=False,
            )

    def test_approved_sensitive_action_can_succeed(self):
        """Approved sensitive actions can succeed."""
        from assay._receipts.domains.web_tool import WebToolReceipt

        receipt = WebToolReceipt(
            receipt_id="wtr_test",
            tool="browser",
            url="https://mybank.com/login",
            target_domain="mybank.com",
            agent_id="agent:test",
            outcome="success",
            allowed=True,
            sensitive_action_attempted=True,
            sensitive_action_type="credential_entry",
            sensitive_action_approved=True,  # Explicitly approved
        )

        assert receipt.sensitive_action_approved is True


class TestOpenClawBridgeSensitiveActions:
    """Tests for sensitive action enforcement in the OpenClaw bridge."""

    def test_sensitive_action_requires_explicit_approval(self):
        """Bridge rejects sensitive actions without approval status."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(
            allowlist=["example.com"],
            agent_id="agent:test",
        )

        with pytest.raises(ValueError, match="explicit approval"):
            bridge.record_browser(
                url="https://example.com/login",
                sensitive_action_attempted=True,
                sensitive_action_type="credential_entry",
            )

    def test_sensitive_action_unapproved_is_blocked(self):
        """Unapproved sensitive actions are forced to blocked outcome."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(
            allowlist=["example.com"],
            agent_id="agent:test",
        )

        receipt = bridge.record_browser(
            url="https://example.com/login",
            sensitive_action_attempted=True,
            sensitive_action_type="credential_entry",
            sensitive_action_approved=False,
        )

        assert receipt.outcome == "blocked"
        assert receipt.allowed is False
        assert receipt.sensitive_action_approved is False

    def test_sensitive_action_approved_can_succeed(self):
        """Approved sensitive actions can succeed if allowlist matches."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(
            allowlist=["example.com"],
            agent_id="agent:test",
        )

        receipt = bridge.record_browser(
            url="https://example.com/login",
            sensitive_action_attempted=True,
            sensitive_action_type="credential_entry",
            sensitive_action_approved=True,
        )

        assert receipt.outcome == "success"
        assert receipt.allowed is True
        assert receipt.sensitive_action_approved is True
        assert receipt.outcome == "success"


class TestOpenClawBridge:
    """Tests for OpenClawBridge integration."""

    def test_check_browser_access_allowed(self):
        """Browser access allowed when domain matches allowlist."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(
            agent_id="agent:researcher",
            allowlist=["*.github.com", "*.python.org"],
        )

        verdict = bridge.check_browser_access("https://github.com/anthropics/claude-code")

        assert verdict.allowed is True
        assert verdict.domain == "github.com"
        assert verdict.matched_pattern == "*.github.com"

    def test_check_browser_access_denied(self):
        """Browser access denied when domain not in allowlist."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(
            agent_id="agent:researcher",
            allowlist=["*.github.com"],
        )

        verdict = bridge.check_browser_access("https://evil.com/malware")

        assert verdict.allowed is False
        assert verdict.domain == "evil.com"
        assert verdict.matched_pattern is None
        assert "not in allowlist" in verdict.reason

    def test_record_operations(self):
        """Bridge records operations and returns receipts."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(
            agent_id="agent:researcher",
            allowlist=["*.github.com"],
        )

        # Record various operations
        bridge.record_web_search("python tutorial", result_items=10)
        bridge.record_web_fetch("https://docs.python.org/3/", result_size=5000)
        bridge.record_browser("https://github.com/test")  # Allowed
        bridge.record_browser("https://blocked.com/page")  # Blocked

        receipts = bridge.get_receipts()

        assert len(receipts) == 4
        assert receipts[0].tool == "web_search"
        assert receipts[1].tool == "web_fetch"
        assert receipts[2].tool == "browser"
        assert receipts[2].allowed is True
        assert receipts[3].tool == "browser"
        assert receipts[3].allowed is False
        assert receipts[3].outcome == "blocked"

    def test_to_trace_entries(self):
        """Can convert receipts to trace-compatible dicts."""
        from assay.openclaw_bridge import OpenClawBridge

        bridge = OpenClawBridge(agent_id="agent:test")
        bridge.record_web_search("test query")

        entries = bridge.to_trace_entries()

        assert len(entries) == 1
        assert entries[0]["tool"] == "web_search"
        assert entries[0]["query"] == "test query"
        assert "receipt_id" in entries[0]


class TestParseOpenClawSessionLog:
    """Tests for session log parsing."""

    def test_parse_session_log(self):
        """Can parse OpenClaw session log into receipts."""
        from assay.openclaw_bridge import parse_openclaw_session_log

        # Create a mock session log
        log_content = """
{"tool": "web_search", "query": "python async", "results": [{"title": "a"}, {"title": "b"}]}
{"tool": "web_fetch", "url": "https://docs.python.org/", "content_length": 5000}
{"tool": "browser", "url": "https://github.com/test"}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(log_content)
            log_path = Path(f.name)

        try:
            receipts = parse_openclaw_session_log(
                log_path=log_path,
                agent_id="agent:test",
                allowlist=["*.github.com"],
            )

            assert len(receipts) == 3
            assert receipts[0].tool == "web_search"
            assert receipts[0].result_items == 2
            assert receipts[1].tool == "web_fetch"
            assert receipts[1].result_size_chars == 5000
            assert receipts[2].tool == "browser"
            assert receipts[2].allowed is True  # github.com in allowlist

        finally:
            log_path.unlink()
