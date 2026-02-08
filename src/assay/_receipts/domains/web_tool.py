"""
WebToolReceipt: Receipt for web tool operations (search, fetch, browser).

Tracks OpenClaw and similar gateway web operations with:
- Tool type and parameters
- Domain/URL accessed
- Result metadata (size, success)
- Allow/deny verdict with policy reference

This provides audit trail integration between OpenClaw gateway
and the CCIO receipt system.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from assay._receipts.compat.pyd import Field, model_validator
from assay._receipts.base import BaseReceipt, Domain


class WebToolReceipt(BaseReceipt):
    """
    Receipt documenting a web tool operation.

    Every web_search, web_fetch, or browser action emits this receipt,
    creating an audit trail of external data access.
    """

    receipt_type: str = Field(default="WebToolReceipt")
    domain: str = Field(default=Domain.GOVERNANCE.value)

    # Tool identification
    tool: Literal["web_search", "web_fetch", "browser"] = Field(
        ...,
        description="Which web tool was used",
    )
    provider: Optional[str] = Field(
        default=None,
        description="Provider name (e.g., 'brave', 'openclaw', 'playwright')",
    )

    # Request details
    query: Optional[str] = Field(
        default=None,
        description="Search query (for web_search)",
    )
    url: Optional[str] = Field(
        default=None,
        description="URL accessed (for web_fetch/browser)",
    )
    target_domain: str = Field(
        ...,
        description="Domain being accessed (extracted from URL or search)",
    )

    # Agent context
    agent_id: str = Field(
        ...,
        description="Agent that initiated the request",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="OpenClaw session ID if available",
    )

    # Result metadata
    result_size_chars: Optional[int] = Field(
        default=None,
        ge=0,
        description="Size of returned content in characters",
    )
    result_items: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of items returned (for search results)",
    )
    cached: bool = Field(
        default=False,
        description="Whether result came from cache",
    )

    # Content verification (enables "Truth = Replay")
    content_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of response body (proves what was seen)",
    )
    content_type: Optional[str] = Field(
        default=None,
        description="MIME type of response (e.g., 'text/html', 'application/json')",
    )

    # Redirect chain (critical for security audit)
    redirect_chain: Optional[List[str]] = Field(
        default=None,
        description="URLs in redirect chain, if any (original → ... → final)",
    )
    crossed_domain_boundary: bool = Field(
        default=False,
        description="True if redirect crossed to a different domain",
    )

    # Outcome
    outcome: Literal["success", "failure", "blocked", "redirect_blocked"] = Field(
        ...,
        description="Result of the operation",
    )
    outcome_details: Optional[str] = Field(
        default=None,
        description="Additional details (error message, redirect URL, etc.)",
    )

    # Policy enforcement
    allowed: bool = Field(
        ...,
        description="Whether the operation was allowed by policy",
    )
    policy_rule: Optional[str] = Field(
        default=None,
        description="Policy rule that allowed/denied this operation",
    )
    domain_allowlist_match: Optional[bool] = Field(
        default=None,
        description="Whether domain matched allowlist (for browser tool)",
    )

    # Sensitive action tracking (code-enforced, not just prompt-enforced)
    sensitive_action_attempted: bool = Field(
        default=False,
        description="True if agent attempted credential entry, form submission, etc.",
    )
    sensitive_action_type: Optional[Literal["credential_entry", "form_submit", "file_upload", "payment"]] = Field(
        default=None,
        description="Type of sensitive action if attempted",
    )
    sensitive_action_approved: Optional[bool] = Field(
        default=None,
        description="Whether sensitive action was pre-approved by human",
    )

    # Timing
    latency_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="Request latency in milliseconds",
    )

    @model_validator(mode="after")
    def _validate_tool_fields(self) -> "WebToolReceipt":
        """Validate tool-specific required fields."""
        if self.tool == "web_search" and not self.query:
            raise ValueError("web_search requires query field")
        if self.tool in ("web_fetch", "browser") and not self.url:
            raise ValueError(f"{self.tool} requires url field")

        # Sensitive actions require explicit approval - code-enforced, not prompt-enforced
        if self.sensitive_action_attempted:
            if self.sensitive_action_approved is None:
                raise ValueError(
                    "Sensitive action attempted but approval status not set. "
                    "Must explicitly approve or deny sensitive actions."
                )
            if not self.sensitive_action_approved and self.outcome == "success":
                raise ValueError(
                    "Cannot mark outcome as 'success' when sensitive action was not approved. "
                    "Unapproved sensitive actions must be blocked."
                )

        return self


def compute_content_hash(content: bytes) -> str:
    """Compute SHA-256 hash of content for receipt verification."""
    import hashlib
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def create_web_search_receipt(
    query: str,
    agent_id: str,
    target_domain: str = "search",
    provider: str = "brave",
    outcome: str = "success",
    result_items: Optional[int] = None,
    **kwargs,
) -> WebToolReceipt:
    """Factory for web_search receipts."""
    import uuid
    return WebToolReceipt(
        receipt_id=f"wtr_{uuid.uuid4().hex[:16]}",
        tool="web_search",
        provider=provider,
        query=query,
        target_domain=target_domain,
        agent_id=agent_id,
        outcome=outcome,
        allowed=outcome != "blocked",
        result_items=result_items,
        **kwargs,
    )


def create_web_fetch_receipt(
    url: str,
    agent_id: str,
    outcome: str = "success",
    result_size_chars: Optional[int] = None,
    content: Optional[bytes] = None,
    redirect_chain: Optional[List[str]] = None,
    **kwargs,
) -> WebToolReceipt:
    """Factory for web_fetch receipts.

    Args:
        url: The URL that was fetched
        agent_id: Agent that made the request
        outcome: Result of the operation
        result_size_chars: Size of response content
        content: Raw response bytes (used to compute content_hash)
        redirect_chain: List of URLs if redirects occurred
        **kwargs: Additional receipt fields
    """
    import uuid
    from urllib.parse import urlparse

    parsed = urlparse(url)
    target_domain = parsed.netloc or "unknown"

    # Compute content hash if content provided
    content_hash = None
    if content is not None:
        content_hash = compute_content_hash(content)
        if result_size_chars is None:
            result_size_chars = len(content)

    # Check if redirect crossed domain boundary
    crossed_domain = False
    if redirect_chain and len(redirect_chain) > 1:
        domains = [urlparse(u).netloc for u in redirect_chain]
        crossed_domain = len(set(domains)) > 1

    return WebToolReceipt(
        receipt_id=f"wtr_{uuid.uuid4().hex[:16]}",
        tool="web_fetch",
        url=url,
        target_domain=target_domain,
        agent_id=agent_id,
        outcome=outcome,
        allowed=outcome not in ("blocked", "redirect_blocked"),
        result_size_chars=result_size_chars,
        content_hash=content_hash,
        redirect_chain=redirect_chain,
        crossed_domain_boundary=crossed_domain,
        **kwargs,
    )


def create_browser_receipt(
    url: str,
    agent_id: str,
    domain_allowlist_match: bool,
    outcome: str = "success",
    policy_rule: Optional[str] = None,
    **kwargs,
) -> WebToolReceipt:
    """Factory for browser tool receipts."""
    import uuid
    from urllib.parse import urlparse

    parsed = urlparse(url)
    target_domain = parsed.netloc or "unknown"

    # Browser tool is only allowed if domain matches allowlist
    allowed = domain_allowlist_match and outcome != "blocked"

    return WebToolReceipt(
        receipt_id=f"wtr_{uuid.uuid4().hex[:16]}",
        tool="browser",
        url=url,
        target_domain=target_domain,
        agent_id=agent_id,
        outcome=outcome,
        allowed=allowed,
        domain_allowlist_match=domain_allowlist_match,
        policy_rule=policy_rule or ("domain_allowlist" if allowed else "domain_not_in_allowlist"),
        **kwargs,
    )


__all__ = [
    "WebToolReceipt",
    "create_web_search_receipt",
    "create_web_fetch_receipt",
    "create_browser_receipt",
    "compute_content_hash",
]
