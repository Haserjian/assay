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
    create_browser_receipt,
    create_web_fetch_receipt,
    create_web_search_receipt,
)


@dataclass
class BrowserVerdict:
    """Result of browser access policy check."""

    allowed: bool
    domain: str
    matched_pattern: Optional[str] = None
    reason: str = ""


@dataclass(frozen=True)
class SessionLogSkippedEntry:
    """One session-log row that was ignored during import."""

    line_number: int
    reason: Literal["invalid_json", "unsupported_tool", "invalid_entry"]
    message: str
    tool: Optional[str] = None
    raw_preview: Optional[str] = None


@dataclass(frozen=True)
class SessionLogImportedEntry:
    """One supported session-log row imported into an Assay receipt."""

    line_number: int
    tool: str
    receipt: WebToolReceipt


@dataclass(frozen=True)
class SessionLogImportReport:
    """Structured import result for an OpenClaw exported session log."""

    imported_entries: List[SessionLogImportedEntry]
    skipped_entries: List[SessionLogSkippedEntry]
    total_lines: int
    blank_lines: int

    @property
    def receipts(self) -> List[WebToolReceipt]:
        return [entry.receipt for entry in self.imported_entries]

    @property
    def imported_count(self) -> int:
        return len(self.imported_entries)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped_entries)

    @property
    def completeness(self) -> Literal["clean", "partial"]:
        return "clean" if not self.skipped_entries else "partial"


@dataclass
class OpenClawBridge:
    """
    Bridge between OpenClaw gateway operations and Assay receipt system.

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
        sensitive_action_type: Optional[
            Literal["credential_entry", "form_submit", "file_upload", "payment"]
        ] = None,
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
    return import_openclaw_session_log(
        log_path=log_path,
        agent_id=agent_id,
        allowlist=allowlist,
    ).receipts


def import_openclaw_session_log(
    log_path: Path,
    agent_id: str,
    allowlist: Optional[List[str]] = None,
) -> SessionLogImportReport:
    """Parse a session log and surface imported vs skipped rows explicitly."""

    bridge = OpenClawBridge(
        agent_id=agent_id,
        allowlist=allowlist or [],
    )

    imported_entries: List[SessionLogImportedEntry] = []
    skipped_entries: List[SessionLogSkippedEntry] = []
    total_lines = 0
    blank_lines = 0

    with open(log_path, encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            total_lines += 1
            line = raw_line.strip()
            if not line:
                blank_lines += 1
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                skipped_entries.append(
                    SessionLogSkippedEntry(
                        line_number=line_number,
                        reason="invalid_json",
                        message=str(exc),
                        raw_preview=_preview_line(raw_line),
                    )
                )
                continue

            tool = entry.get("tool")
            try:
                if tool == "web_search":
                    receipt = bridge.record_web_search(
                        query=entry.get("query", ""),
                        result_items=len(entry.get("results", [])),
                    )
                elif tool == "web_fetch":
                    receipt = bridge.record_web_fetch(
                        url=entry.get("url", ""),
                        result_size=entry.get("content_length"),
                        cached=entry.get("cached", False),
                    )
                elif tool == "browser":
                    receipt = bridge.record_browser(
                        url=entry.get("url", ""),
                        result_size=entry.get("content_length"),
                        sensitive_action_attempted=entry.get(
                            "sensitive_action_attempted", False
                        ),
                        sensitive_action_type=entry.get("sensitive_action_type"),
                        sensitive_action_approved=entry.get(
                            "sensitive_action_approved"
                        ),
                    )
                else:
                    skipped_entries.append(
                        SessionLogSkippedEntry(
                            line_number=line_number,
                            reason="unsupported_tool",
                            tool=str(tool) if tool is not None else None,
                            message="Unsupported or missing tool field",
                            raw_preview=_preview_line(raw_line),
                        )
                    )
                    continue
            except (TypeError, ValueError) as exc:
                skipped_entries.append(
                    SessionLogSkippedEntry(
                        line_number=line_number,
                        reason="invalid_entry",
                        tool=str(tool) if tool is not None else None,
                        message=str(exc),
                        raw_preview=_preview_line(raw_line),
                    )
                )
                continue

            imported_entries.append(
                SessionLogImportedEntry(
                    line_number=line_number,
                    tool=str(tool),
                    receipt=receipt,
                )
            )

    return SessionLogImportReport(
        imported_entries=imported_entries,
        skipped_entries=skipped_entries,
        total_lines=total_lines,
        blank_lines=blank_lines,
    )


def _preview_line(raw_line: str, max_chars: int = 160) -> str:
    """Compact raw session-log content for skipped-entry diagnostics."""

    preview = raw_line.strip().replace("\n", "\\n")
    if len(preview) <= max_chars:
        return preview
    return preview[:max_chars] + "...[truncated]"


__all__ = [
    "OpenClawBridge",
    "SessionLogImportedEntry",
    "BrowserVerdict",
    "SessionLogImportReport",
    "SessionLogSkippedEntry",
    "import_openclaw_session_log",
    "parse_openclaw_session_log",
]
