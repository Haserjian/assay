"""
OpenClaw Bridge: Integration between OpenClaw gateway and Assay receipts.

Provides:
- Session log parsing → WebToolReceipts
- Domain allowlist policy enforcement
- Trace-compatible audit trail

Usage:
    from assay.openclaw_bridge import OpenClawBridge

    bridge = OpenClawBridge(
        allowlist=["*.github.com", "*.nytimes.com"],
        agent_id="agent:researcher",
    )

    # Check if browser access is allowed
    verdict = bridge.check_browser_access("https://github.com/anthropics/claude-code")

    # Create receipt for a web operation
    receipt = bridge.record_web_fetch(
        url="https://docs.python.org/3/",
        result_size=15000,
        latency_ms=450,
    )
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from assay._receipts.domains.web_tool import (
    WebToolReceipt,
    create_web_search_receipt,
    create_web_fetch_receipt,
    create_browser_receipt,
)


@dataclass
class BrowserVerdict:
    """Result of browser access policy check."""
    allowed: bool
    domain: str
    matched_pattern: Optional[str] = None
    reason: str = ""


@dataclass
class OpenClawBridge:
    """
    Bridge between OpenClaw gateway operations and CCIO receipt system.

    Enforces domain allowlist policy for browser tool and emits
    WebToolReceipts for all operations.
    """

    agent_id: str
    allowlist: List[str] = field(default_factory=list)
    provider: str = "openclaw"
    session_id: Optional[str] = None

    # Internal state
    _receipts: List[WebToolReceipt] = field(default_factory=list, repr=False)

    def check_browser_access(self, url: str) -> BrowserVerdict:
        """
        Check if browser access to URL is allowed by domain allowlist.

        Returns a BrowserVerdict with allow/deny decision and reasoning.

        Allowlist patterns:
        - "*.github.com" matches github.com AND www.github.com AND api.github.com
        - "github.com" matches only github.com exactly
        - "docs.*.org" matches docs.python.org, docs.rust.org, etc.
        """
        parsed = urlparse(url)
        domain = parsed.netloc

        if not domain:
            return BrowserVerdict(
                allowed=False,
                domain="unknown",
                reason="Could not parse domain from URL",
            )

        # Check against allowlist patterns
        for pattern in self.allowlist:
            # Handle "*.domain.com" to also match "domain.com" (not just subdomains)
            if pattern.startswith("*."):
                base_domain = pattern[2:]  # Remove "*."
                # Match exact base domain OR any subdomain
                if domain == base_domain or fnmatch.fnmatch(domain, pattern):
                    return BrowserVerdict(
                        allowed=True,
                        domain=domain,
                        matched_pattern=pattern,
                        reason=f"Domain matches allowlist pattern: {pattern}",
                    )
            elif fnmatch.fnmatch(domain, pattern):
                return BrowserVerdict(
                    allowed=True,
                    domain=domain,
                    matched_pattern=pattern,
                    reason=f"Domain matches allowlist pattern: {pattern}",
                )

        return BrowserVerdict(
            allowed=False,
            domain=domain,
            reason=f"Domain '{domain}' not in allowlist",
        )

    def record_web_search(
        self,
        query: str,
        result_items: Optional[int] = None,
        latency_ms: Optional[int] = None,
        outcome: str = "success",
    ) -> WebToolReceipt:
        """Record a web_search operation and return receipt."""
        receipt = create_web_search_receipt(
            query=query,
            agent_id=self.agent_id,
            provider=self.provider,
            outcome=outcome,
            result_items=result_items,
            latency_ms=latency_ms,
            session_id=self.session_id,
        )
        self._receipts.append(receipt)
        return receipt

    def record_web_fetch(
        self,
        url: str,
        result_size: Optional[int] = None,
        latency_ms: Optional[int] = None,
        outcome: str = "success",
        cached: bool = False,
    ) -> WebToolReceipt:
        """Record a web_fetch operation and return receipt."""
        receipt = create_web_fetch_receipt(
            url=url,
            agent_id=self.agent_id,
            provider=self.provider,
            outcome=outcome,
            result_size_chars=result_size,
            latency_ms=latency_ms,
            cached=cached,
            session_id=self.session_id,
        )
        self._receipts.append(receipt)
        return receipt

    def record_browser(
        self,
        url: str,
        result_size: Optional[int] = None,
        latency_ms: Optional[int] = None,
        outcome: Optional[str] = None,
        sensitive_action_attempted: bool = False,
        sensitive_action_type: Optional[Literal["credential_entry", "form_submit", "file_upload", "payment"]] = None,
        sensitive_action_approved: Optional[bool] = None,
    ) -> WebToolReceipt:
        """
        Record a browser operation with automatic policy check.

        If domain not in allowlist, outcome is set to 'blocked'.
        """
        verdict = self.check_browser_access(url)

        if sensitive_action_type and not sensitive_action_attempted:
            sensitive_action_attempted = True

        if outcome is None:
            outcome = "success" if verdict.allowed else "blocked"

        if sensitive_action_attempted:
            if sensitive_action_approved is None:
                raise ValueError(
                    "Sensitive action attempted requires explicit approval status."
                )
            if not sensitive_action_approved:
                outcome = "blocked"

        receipt = create_browser_receipt(
            url=url,
            agent_id=self.agent_id,
            domain_allowlist_match=verdict.allowed,
            outcome=outcome,
            policy_rule=verdict.matched_pattern or "domain_not_in_allowlist",
            result_size_chars=result_size if verdict.allowed else None,
            latency_ms=latency_ms if verdict.allowed else None,
            session_id=self.session_id,
            outcome_details=verdict.reason,
            sensitive_action_attempted=sensitive_action_attempted,
            sensitive_action_type=sensitive_action_type,
            sensitive_action_approved=sensitive_action_approved,
        )
        self._receipts.append(receipt)
        return receipt

    def get_receipts(self) -> List[WebToolReceipt]:
        """Get all recorded receipts."""
        return list(self._receipts)

    def clear_receipts(self) -> None:
        """Clear recorded receipts."""
        self._receipts.clear()

    def to_trace_entries(self) -> List[Dict[str, Any]]:
        """Convert receipts to trace-compatible dict entries."""
        return [r.model_dump(mode="json", exclude_none=True) for r in self._receipts]


def parse_openclaw_session_log(
    log_path: Path,
    agent_id: str,
    allowlist: Optional[List[str]] = None,
) -> List[WebToolReceipt]:
    """
    Parse an OpenClaw session log and emit WebToolReceipts.

    Expected log format (JSONL):
        {"tool": "web_search", "query": "...", "results": [...], "timestamp": "..."}
        {"tool": "web_fetch", "url": "...", "content_length": 1234, "timestamp": "..."}

    Returns list of WebToolReceipts for each operation found.
    """
    bridge = OpenClawBridge(
        agent_id=agent_id,
        allowlist=allowlist or [],
    )

    receipts = []

    with open(log_path) as f:
        for line in f:
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            tool = entry.get("tool")

            if tool == "web_search":
                receipt = bridge.record_web_search(
                    query=entry.get("query", ""),
                    result_items=len(entry.get("results", [])),
                )
                receipts.append(receipt)

            elif tool == "web_fetch":
                receipt = bridge.record_web_fetch(
                    url=entry.get("url", ""),
                    result_size=entry.get("content_length"),
                    cached=entry.get("cached", False),
                )
                receipts.append(receipt)

            elif tool == "browser":
                receipt = bridge.record_browser(
                    url=entry.get("url", ""),
                    result_size=entry.get("content_length"),
                    sensitive_action_attempted=entry.get("sensitive_action_attempted", False),
                    sensitive_action_type=entry.get("sensitive_action_type"),
                    sensitive_action_approved=entry.get("sensitive_action_approved"),
                )
                receipts.append(receipt)

    return receipts


__all__ = [
    "OpenClawBridge",
    "BrowserVerdict",
    "parse_openclaw_session_log",
]
