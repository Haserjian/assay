"""Agent incident timeline and causal analysis.

Builds a chronological timeline from a proof pack, classifies events
by severity, identifies divergence points against a baseline, and
constructs backward causal chains from failures to root causes.

Usage:
    from assay.incident import build_timeline, build_comparative_timeline
    timeline = build_timeline(Path("./proof_pack_abc123"))
    timeline = build_comparative_timeline(current, baseline)
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    """One event in the incident chronology."""

    timestamp: str
    receipt_id: str
    event_type: str        # "model_call", "guardian_verdict", "mcp_tool_call"
    summary: str           # Human-readable one-liner
    severity: str          # "normal", "warning", "critical"
    detail: Dict[str, Any] = field(default_factory=dict)
    parent_receipt_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DivergencePoint:
    """First point where the current pack diverges from baseline."""

    receipt_id: str
    timestamp: str
    description: str       # What changed
    baseline_state: str    # What baseline had at this point
    current_state: str     # What current has

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CausalChain:
    """Backward chain from a failure to its likely root cause."""

    failure_receipt_id: str
    failure_description: str
    chain: List[TimelineEvent]  # ordered root -> failure
    root_cause: str             # Human-readable root cause hypothesis

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure_receipt_id": self.failure_receipt_id,
            "failure_description": self.failure_description,
            "chain": [e.to_dict() for e in self.chain],
            "root_cause": self.root_cause,
        }


@dataclass
class IncidentTimeline:
    """Full incident timeline for a pack."""

    pack_id: str
    n_events: int
    time_start: str
    time_end: str
    events: List[TimelineEvent]
    divergence: Optional[DivergencePoint]  # None if no baseline
    causal_chains: List[CausalChain]       # Empty if no failures
    integrity_status: str
    claim_status: str
    summary: str           # 2-3 sentence executive summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "n_events": self.n_events,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "events": [e.to_dict() for e in self.events],
            "divergence": self.divergence.to_dict() if self.divergence else None,
            "causal_chains": [c.to_dict() for c in self.causal_chains],
            "integrity_status": self.integrity_status,
            "claim_status": self.claim_status,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Receipt classification
# ---------------------------------------------------------------------------

def _classify_receipt(receipt: Dict[str, Any]) -> TimelineEvent:
    """Classify a single receipt into a TimelineEvent."""
    rtype = receipt.get("type", "unknown")
    rid = receipt.get("receipt_id", "unknown")
    ts = receipt.get("timestamp", "")
    parent = receipt.get("parent_receipt_id")

    if rtype == "model_call":
        model_id = receipt.get("model_id") or receipt.get("model") or "unknown"
        in_t = receipt.get("input_tokens", 0) or 0
        out_t = receipt.get("output_tokens", 0) or 0
        latency = receipt.get("latency_ms")
        error = receipt.get("error")

        if error:
            return TimelineEvent(
                timestamp=ts,
                receipt_id=rid,
                event_type="model_call",
                summary=f"Model call FAILED: {model_id} -- {error}",
                severity="critical",
                detail={"model_id": model_id, "error": error},
                parent_receipt_id=parent,
            )

        latency_str = f", {latency:.0f}ms" if latency is not None else ""
        return TimelineEvent(
            timestamp=ts,
            receipt_id=rid,
            event_type="model_call",
            summary=f"Model call: {model_id} ({in_t}+{out_t} tokens{latency_str})",
            severity="normal",
            detail={
                "model_id": model_id,
                "input_tokens": in_t,
                "output_tokens": out_t,
                "latency_ms": latency,
            },
            parent_receipt_id=parent,
        )

    if rtype == "guardian_verdict":
        action = receipt.get("action", "unknown")
        verdict = receipt.get("verdict", "unknown")
        reason = receipt.get("reason", "")

        if verdict in ("deny", "denied", "block", "blocked"):
            return TimelineEvent(
                timestamp=ts,
                receipt_id=rid,
                event_type="guardian_verdict",
                summary=f"Guardian: DENY {action} -- {reason}",
                severity="critical",
                detail={"action": action, "verdict": verdict, "reason": reason},
                parent_receipt_id=parent,
            )

        return TimelineEvent(
            timestamp=ts,
            receipt_id=rid,
            event_type="guardian_verdict",
            summary=f"Guardian: ALLOW {action}",
            severity="normal",
            detail={"action": action, "verdict": verdict},
            parent_receipt_id=parent,
        )

    if rtype == "mcp_tool_call":
        tool_name = receipt.get("tool_name", "unknown")
        duration = receipt.get("duration_ms")
        policy_verdict = receipt.get("policy_verdict", "")
        policy_reason = receipt.get("policy_reason", "")
        outcome = receipt.get("outcome", "")

        if policy_verdict == "deny" or outcome == "denied":
            return TimelineEvent(
                timestamp=ts,
                receipt_id=rid,
                event_type="mcp_tool_call",
                summary=f"MCP DENIED: {tool_name} -- policy: {policy_reason}",
                severity="critical",
                detail={
                    "tool_name": tool_name,
                    "policy_verdict": policy_verdict,
                    "policy_reason": policy_reason,
                    "outcome": outcome,
                },
                parent_receipt_id=parent,
            )

        dur_str = f" ({duration:.0f}ms)" if duration is not None else ""
        return TimelineEvent(
            timestamp=ts,
            receipt_id=rid,
            event_type="mcp_tool_call",
            summary=f"MCP tool call: {tool_name}{dur_str}",
            severity="normal",
            detail={
                "tool_name": tool_name,
                "duration_ms": duration,
                "policy_verdict": policy_verdict,
                "outcome": outcome or "forwarded",
            },
            parent_receipt_id=parent,
        )

    # Fallback for unknown receipt types
    return TimelineEvent(
        timestamp=ts,
        receipt_id=rid,
        event_type=rtype,
        summary=f"{rtype}: {rid[:12]}",
        severity="normal",
        detail={"raw_type": rtype},
        parent_receipt_id=parent,
    )


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO 8601 timestamp, tolerant of Z suffix."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Causal chain construction
# ---------------------------------------------------------------------------

def build_causal_chains(
    receipts: List[Dict[str, Any]],
    pack_info: Dict[str, Any],
) -> List[CausalChain]:
    """Build backward causal chains from failures.

    For each critical event (deny, error, claim failure):
    1. Walk parent_receipt_id chains backward via trace_chain()
    2. Identify the root receipt that initiated the chain
    3. Generate a root cause hypothesis
    """
    from assay.diff import trace_chain

    # Index receipts by ID
    receipt_index = {
        r["receipt_id"]: r for r in receipts if r.get("receipt_id")
    }

    # Classify all receipts to find critical events
    events = [_classify_receipt(r) for r in receipts]
    critical = [e for e in events if e.severity == "critical"]

    if not critical:
        return []

    chains: List[CausalChain] = []
    for event in critical:
        raw_chain = trace_chain(event.receipt_id, receipt_index)

        # Convert raw chain to TimelineEvents (root -> failure order)
        chain_events = [_classify_receipt(r) for r in reversed(raw_chain)]

        root_cause = _infer_root_cause(event, raw_chain)

        chains.append(CausalChain(
            failure_receipt_id=event.receipt_id,
            failure_description=event.summary,
            chain=chain_events,
            root_cause=root_cause,
        ))

    return chains


def _infer_root_cause(
    failure: TimelineEvent,
    raw_chain: List[Dict[str, Any]],
) -> str:
    """Infer a human-readable root cause hypothesis."""
    if failure.event_type == "guardian_verdict":
        reason = failure.detail.get("reason", "")
        action = failure.detail.get("action", "")
        return f"Guardian blocked action '{action}': {reason}" if reason else f"Guardian blocked action '{action}'"

    if failure.event_type == "mcp_tool_call":
        tool = failure.detail.get("tool_name", "unknown")
        reason = failure.detail.get("policy_reason", "")
        return f"MCP policy denied tool call '{tool}': {reason}" if reason else f"MCP policy denied tool call '{tool}'"

    if failure.event_type == "model_call":
        error = failure.detail.get("error", "unknown error")
        model = failure.detail.get("model_id", "unknown")
        return f"Model call failed ({model}): {error}"

    return f"Unknown failure: {failure.summary}"


# ---------------------------------------------------------------------------
# Timeline builders
# ---------------------------------------------------------------------------

def _load_receipts_from_pack(pack_dir: Path) -> List[Dict[str, Any]]:
    """Load receipts from a proof pack directory."""
    from assay.analyze import load_pack_receipts
    return load_pack_receipts(pack_dir)


def _load_pack_info(pack_dir: Path) -> Dict[str, Any]:
    """Load pack metadata via explain_pack."""
    from assay.explain import explain_pack
    return explain_pack(pack_dir)


def build_timeline(pack_dir: Path) -> IncidentTimeline:
    """Build a chronological timeline from a single pack.

    1. Load receipts and pack info
    2. Sort by timestamp
    3. Classify each receipt into a TimelineEvent
    4. Identify critical events
    5. Build causal chains for failures
    6. Generate executive summary
    """
    pack_dir = Path(pack_dir)
    receipts = _load_receipts_from_pack(pack_dir)
    pack_info = _load_pack_info(pack_dir)

    # Classify and sort by timestamp
    events = [_classify_receipt(r) for r in receipts]
    events.sort(key=lambda e: e.timestamp or "")

    # Build causal chains from critical events
    causal_chains = build_causal_chains(receipts, pack_info)

    # Timestamps
    timestamps = [e.timestamp for e in events if e.timestamp]
    time_start = min(timestamps) if timestamps else ""
    time_end = max(timestamps) if timestamps else ""

    # Executive summary
    n_critical = sum(1 for e in events if e.severity == "critical")
    summary = _build_summary(
        events, causal_chains,
        pack_info.get("integrity_status", "UNKNOWN"),
        pack_info.get("claims_status", "UNKNOWN"),
    )

    return IncidentTimeline(
        pack_id=pack_info.get("pack_id", "unknown"),
        n_events=len(events),
        time_start=time_start,
        time_end=time_end,
        events=events,
        divergence=None,
        causal_chains=causal_chains,
        integrity_status=pack_info.get("integrity_status", "UNKNOWN"),
        claim_status=pack_info.get("claims_status", "UNKNOWN"),
        summary=summary,
    )


def build_comparative_timeline(
    pack_dir: Path,
    baseline_dir: Path,
) -> IncidentTimeline:
    """Build timeline with divergence detection against a baseline.

    1. Build timelines for both packs
    2. Find first divergence point (model swap, new denial, claim flip)
    3. Annotate divergence on the current pack's timeline
    """
    current = build_timeline(pack_dir)
    baseline = build_timeline(baseline_dir)

    divergence = _find_divergence(baseline, current)
    current.divergence = divergence

    # Update summary to mention divergence
    if divergence:
        current.summary += f" First divergence: {divergence.description}"

    return current


def _find_divergence(
    baseline: IncidentTimeline,
    current: IncidentTimeline,
) -> Optional[DivergencePoint]:
    """Find the first point where current diverges from baseline."""
    # Strategy 1: Different dominant models
    baseline_models = set()
    current_models = set()
    for e in baseline.events:
        if e.event_type == "model_call":
            m = e.detail.get("model_id")
            if m:
                baseline_models.add(m)
    for e in current.events:
        if e.event_type == "model_call":
            m = e.detail.get("model_id")
            if m:
                current_models.add(m)

    new_models = current_models - baseline_models
    if new_models:
        # Find first event with a new model
        for e in current.events:
            if e.event_type == "model_call" and e.detail.get("model_id") in new_models:
                return DivergencePoint(
                    receipt_id=e.receipt_id,
                    timestamp=e.timestamp,
                    description=f"New model introduced: {e.detail['model_id']}",
                    baseline_state=f"Models: {', '.join(sorted(baseline_models))}",
                    current_state=f"Models: {', '.join(sorted(current_models))}",
                )

    # Strategy 2: New denials in current that weren't in baseline
    baseline_denials = {e.receipt_id for e in baseline.events if e.severity == "critical"}
    for e in current.events:
        if e.severity == "critical":
            return DivergencePoint(
                receipt_id=e.receipt_id,
                timestamp=e.timestamp,
                description=f"Critical event: {e.summary}",
                baseline_state=f"{len(baseline_denials)} critical events",
                current_state=f"New critical event at {e.timestamp}",
            )

    # Strategy 3: Claim status difference
    if baseline.claim_status != current.claim_status:
        first_event = current.events[0] if current.events else None
        return DivergencePoint(
            receipt_id=first_event.receipt_id if first_event else "unknown",
            timestamp=first_event.timestamp if first_event else "",
            description=f"Claim status changed: {baseline.claim_status} -> {current.claim_status}",
            baseline_state=f"Claims: {baseline.claim_status}",
            current_state=f"Claims: {current.claim_status}",
        )

    return None


def _build_summary(
    events: List[TimelineEvent],
    causal_chains: List[CausalChain],
    integrity_status: str,
    claim_status: str,
) -> str:
    """Generate a 2-3 sentence executive summary."""
    n_events = len(events)
    n_critical = sum(1 for e in events if e.severity == "critical")
    n_chains = len(causal_chains)

    parts: List[str] = []

    # Event count
    types = set(e.event_type for e in events)
    type_str = ", ".join(sorted(types))
    parts.append(f"{n_events} events recorded ({type_str}).")

    # Status
    if integrity_status == "PASSED" and claim_status == "PASSED":
        parts.append("Integrity and claims both passed -- no issues detected.")
    elif integrity_status == "FAILED":
        parts.append("INTEGRITY FAILED: evidence may have been tampered with.")
    elif claim_status == "FAILED":
        parts.append(f"Claims FAILED with {n_critical} critical events and {n_chains} causal chains identified.")
    elif claim_status == "NONE":
        parts.append("No claims were declared.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_timeline_text(timeline: IncidentTimeline) -> str:
    """Console output: chronological events with severity markers."""
    lines: List[str] = []

    lines.append(f"INCIDENT TIMELINE: {timeline.pack_id}")
    lines.append(f"  Events: {timeline.n_events}  |  "
                 f"Integrity: {timeline.integrity_status}  |  "
                 f"Claims: {timeline.claim_status}")
    lines.append(f"  Window: {timeline.time_start} to {timeline.time_end}")
    lines.append("")

    # Summary
    lines.append("SUMMARY")
    lines.append(f"  {timeline.summary}")
    lines.append("")

    # Divergence
    if timeline.divergence:
        lines.append("FIRST DIVERGENCE")
        d = timeline.divergence
        lines.append(f"  {d.description}")
        lines.append(f"  Baseline: {d.baseline_state}")
        lines.append(f"  Current:  {d.current_state}")
        lines.append(f"  Receipt:  {d.receipt_id}")
        lines.append("")

    # Events
    lines.append("CHRONOLOGY")
    severity_markers = {"normal": "  ", "warning": "! ", "critical": "* "}
    for e in timeline.events:
        marker = severity_markers.get(e.severity, "  ")
        ts_short = e.timestamp[:19] if len(e.timestamp) >= 19 else e.timestamp
        lines.append(f"  {marker}{ts_short}  {e.summary}")
    lines.append("")

    # Causal chains
    if timeline.causal_chains:
        lines.append("LIKELY ROOT CAUSES")
        for i, chain in enumerate(timeline.causal_chains, 1):
            lines.append(f"  Chain {i}: {chain.root_cause}")
            lines.append(f"    Failure: {chain.failure_description}")
            if len(chain.chain) > 1:
                lines.append(f"    Trace ({len(chain.chain)} events):")
                for ce in chain.chain:
                    lines.append(f"      -> {ce.summary}")
            lines.append("")

    return "\n".join(lines)


def render_timeline_md(timeline: IncidentTimeline) -> str:
    """Markdown output suitable for incident reports / PR comments."""
    lines: List[str] = []

    lines.append(f"# Incident Timeline: `{timeline.pack_id}`")
    lines.append("")
    lines.append(f"**Events:** {timeline.n_events} | "
                 f"**Integrity:** {timeline.integrity_status} | "
                 f"**Claims:** {timeline.claim_status}")
    lines.append(f"**Window:** {timeline.time_start} to {timeline.time_end}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(timeline.summary)
    lines.append("")

    # Divergence
    if timeline.divergence:
        d = timeline.divergence
        lines.append("## First Divergence")
        lines.append("")
        lines.append(f"**{d.description}**")
        lines.append("")
        lines.append(f"| | State |")
        lines.append(f"|---|---|")
        lines.append(f"| Baseline | {d.baseline_state} |")
        lines.append(f"| Current | {d.current_state} |")
        lines.append(f"| Receipt | `{d.receipt_id}` |")
        lines.append("")

    # Events table
    lines.append("## Chronology")
    lines.append("")
    lines.append("| Time | Severity | Event |")
    lines.append("|------|----------|-------|")
    for e in timeline.events:
        ts_short = e.timestamp[:19] if len(e.timestamp) >= 19 else e.timestamp
        sev = f"**{e.severity.upper()}**" if e.severity != "normal" else e.severity
        lines.append(f"| {ts_short} | {sev} | {e.summary} |")
    lines.append("")

    # Causal chains
    if timeline.causal_chains:
        lines.append("## Likely Root Causes")
        lines.append("")
        for i, chain in enumerate(timeline.causal_chains, 1):
            lines.append(f"### Chain {i}: {chain.root_cause}")
            lines.append("")
            lines.append(f"**Failure:** {chain.failure_description}")
            lines.append("")
            if len(chain.chain) > 1:
                lines.append("**Trace:**")
                lines.append("")
                for ce in chain.chain:
                    sev_tag = f" [{ce.severity.upper()}]" if ce.severity != "normal" else ""
                    lines.append(f"1. {ce.summary}{sev_tag}")
                lines.append("")

    return "\n".join(lines)


def render_causal_text(chains: List[CausalChain]) -> str:
    """Console output for explain --causal: backward chains."""
    if not chains:
        return "CAUSAL ANALYSIS\n  No failures detected -- no causal chains to trace.\n"

    lines: List[str] = []
    lines.append("CAUSAL ANALYSIS")
    lines.append(f"  {len(chains)} failure(s) traced to root cause")
    lines.append("")

    for i, chain in enumerate(chains, 1):
        lines.append(f"  [{i}] {chain.root_cause}")
        lines.append(f"      Failure: {chain.failure_description}")
        if len(chain.chain) > 1:
            lines.append(f"      Chain ({len(chain.chain)} events):")
            for ce in chain.chain:
                lines.append(f"        -> {ce.summary}")
        lines.append("")

    return "\n".join(lines)


def render_causal_md(chains: List[CausalChain]) -> str:
    """Markdown output for causal analysis."""
    if not chains:
        return "## Causal Analysis\n\nNo failures detected -- no causal chains to trace.\n"

    lines: List[str] = []
    lines.append("## Causal Analysis")
    lines.append("")
    lines.append(f"{len(chains)} failure(s) traced to root cause")
    lines.append("")

    for i, chain in enumerate(chains, 1):
        lines.append(f"### [{i}] {chain.root_cause}")
        lines.append("")
        lines.append(f"**Failure:** {chain.failure_description}")
        lines.append("")
        if len(chain.chain) > 1:
            for ce in chain.chain:
                sev_tag = f" [{ce.severity.upper()}]" if ce.severity != "normal" else ""
                lines.append(f"1. {ce.summary}{sev_tag}")
            lines.append("")

    return "\n".join(lines)
