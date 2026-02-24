"""Receipt -> Policy Loop: aggregate signals from receipt history, generate recommendations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class WindowSignals:
    """Aggregated signals from a receipt window."""
    window_start: str
    window_end: str
    window_days: int
    total_receipts: int

    # Rates (0.0 - 1.0)
    deny_rate: float
    failure_rate: float
    timeout_rate: float

    # Counts
    deny_count: int
    failure_count: int
    timeout_count: int
    success_count: int

    # Top offenders
    top_denied_tools: List[Dict[str, Any]] = field(default_factory=list)
    top_failing_tools: List[Dict[str, Any]] = field(default_factory=list)

    # Breakdown by type
    type_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrendComparison:
    """Comparison between current and previous window."""
    deny_rate_delta: float  # positive = getting worse
    failure_rate_delta: float
    timeout_rate_delta: float
    total_receipts_delta: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Recommendation:
    """A deterministic policy recommendation."""
    severity: str  # "critical", "warning", "info"
    signal: str  # Machine-readable signal name
    message: str  # Human-readable description
    metric_name: str
    metric_value: float
    threshold: float
    suggested_action: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyLoopResult:
    """Complete result of a policy loop analysis."""
    generated_at: str
    current_window: WindowSignals
    previous_window: Optional[WindowSignals]
    trend: Optional[TrendComparison]
    recommendations: List[Recommendation]
    recommendation_count: int
    has_critical: bool

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "generated_at": self.generated_at,
            "current_window": self.current_window.to_dict(),
            "previous_window": self.previous_window.to_dict() if self.previous_window else None,
            "trend": self.trend.to_dict() if self.trend else None,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "recommendation_count": self.recommendation_count,
            "has_critical": self.has_critical,
        }
        return d


# ---------------------------------------------------------------------------
# Receipt loading
# ---------------------------------------------------------------------------

def load_receipts_in_window(
    store_dir: Path,
    window_days: int = 7,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Load all receipts from JSONL trace files within a time window.

    Args:
        store_dir: Path to assay store (e.g. ~/.assay/)
        window_days: Number of days to look back
        end_time: End of window (default: now)

    Returns:
        List of receipt dicts, sorted by timestamp.
    """
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=window_days)

    receipts: List[Dict[str, Any]] = []

    if not store_dir.exists():
        return receipts

    for day_dir in sorted(store_dir.iterdir()):
        if not day_dir.is_dir():
            continue
        # Quick date filter on directory name
        try:
            dir_date = datetime.strptime(day_dir.name, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        # Skip directories outside window (with 1-day buffer for timezone edge cases)
        if dir_date.date() < (start_time - timedelta(days=1)).date():
            continue
        if dir_date.date() > end_time.date():
            continue

        for trace_file in sorted(day_dir.glob("trace_*.jsonl")):
            try:
                with open(trace_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            receipt = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        # Filter by timestamp
                        ts_str = receipt.get("timestamp") or receipt.get("_stored_at")
                        if not ts_str:
                            continue
                        try:
                            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        except (ValueError, AttributeError):
                            continue
                        if start_time <= ts <= end_time:
                            receipts.append(receipt)
            except (OSError, IOError):
                continue

    receipts.sort(key=lambda r: r.get("timestamp", r.get("_stored_at", "")))
    return receipts


# ---------------------------------------------------------------------------
# Signal aggregation
# ---------------------------------------------------------------------------

def aggregate_signals(
    receipts: List[Dict[str, Any]],
    window_days: int = 7,
    window_label: Optional[str] = None,
) -> WindowSignals:
    """Compute aggregate signals from a list of receipts.

    Classifies receipts by outcome:
    - denied: allowed=False or policy_verdict="deny"
    - failed: outcome not in ("ok", "forwarded", "success") and not denied
    - timeout: outcome="timeout"
    - success: everything else
    """
    total = len(receipts)

    deny_count = 0
    failure_count = 0
    timeout_count = 0
    success_count = 0

    tool_denials: Dict[str, int] = {}
    tool_failures: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}

    for r in receipts:
        rtype = r.get("type", "unknown")
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

        tool = r.get("tool_name", "unknown")
        outcome = r.get("outcome", "unknown")
        allowed = r.get("allowed", True)
        verdict = r.get("policy_verdict", "")

        if not allowed or verdict == "deny":
            deny_count += 1
            tool_denials[tool] = tool_denials.get(tool, 0) + 1
        elif outcome == "timeout":
            timeout_count += 1
            tool_failures[tool] = tool_failures.get(tool, 0) + 1
        elif outcome not in ("ok", "forwarded", "success", ""):
            failure_count += 1
            tool_failures[tool] = tool_failures.get(tool, 0) + 1
        else:
            success_count += 1

    # Build top-N lists
    top_denied = sorted(
        [{"tool": t, "count": c} for t, c in tool_denials.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    top_failing = sorted(
        [{"tool": t, "count": c} for t, c in tool_failures.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]

    # Timestamps
    timestamps = [r.get("timestamp", r.get("_stored_at", "")) for r in receipts]
    timestamps = [t for t in timestamps if t]
    window_start = min(timestamps) if timestamps else ""
    window_end = max(timestamps) if timestamps else ""

    return WindowSignals(
        window_start=window_start,
        window_end=window_end,
        window_days=window_days,
        total_receipts=total,
        deny_rate=deny_count / total if total > 0 else 0.0,
        failure_rate=failure_count / total if total > 0 else 0.0,
        timeout_rate=timeout_count / total if total > 0 else 0.0,
        deny_count=deny_count,
        failure_count=failure_count,
        timeout_count=timeout_count,
        success_count=success_count,
        top_denied_tools=top_denied,
        top_failing_tools=top_failing,
        type_counts=type_counts,
    )


# ---------------------------------------------------------------------------
# Trend comparison
# ---------------------------------------------------------------------------

def compare_windows(
    current: WindowSignals,
    previous: WindowSignals,
) -> TrendComparison:
    """Compare two windows to detect trends."""
    return TrendComparison(
        deny_rate_delta=current.deny_rate - previous.deny_rate,
        failure_rate_delta=current.failure_rate - previous.failure_rate,
        timeout_rate_delta=current.timeout_rate - previous.timeout_rate,
        total_receipts_delta=current.total_receipts - previous.total_receipts,
    )


# ---------------------------------------------------------------------------
# Recommendation engine (deterministic rules)
# ---------------------------------------------------------------------------

# Thresholds (configurable later, hardcoded for v1)
_DENY_RATE_CRITICAL = 0.30
_DENY_RATE_WARNING = 0.10
_FAILURE_RATE_CRITICAL = 0.20
_FAILURE_RATE_WARNING = 0.05
_TIMEOUT_RATE_WARNING = 0.10
_DENY_TREND_WARNING = 0.05  # 5% increase triggers warning
_TOOL_FAILURE_RATE_WARNING = 0.50  # Tool with >50% failure rate


def generate_recommendations(
    current: WindowSignals,
    trend: Optional[TrendComparison] = None,
) -> List[Recommendation]:
    """Generate deterministic policy recommendations from signals.

    Rules are threshold-based with no LLM dependency.
    """
    recs: List[Recommendation] = []

    if current.total_receipts == 0:
        recs.append(Recommendation(
            severity="info",
            signal="no_receipts",
            message="No receipts found in window. Nothing to analyze.",
            metric_name="total_receipts",
            metric_value=0,
            threshold=0,
            suggested_action="Run instrumented workloads to generate receipts.",
        ))
        return recs

    # Deny rate
    if current.deny_rate >= _DENY_RATE_CRITICAL:
        recs.append(Recommendation(
            severity="critical",
            signal="high_deny_rate",
            message=f"{current.deny_rate:.0%} of calls denied ({current.deny_count}/{current.total_receipts}). Policy may be too strict.",
            metric_name="deny_rate",
            metric_value=current.deny_rate,
            threshold=_DENY_RATE_CRITICAL,
            suggested_action="Review policy deny rules. Run: assay policy impact --policy-new <candidate>",
        ))
    elif current.deny_rate >= _DENY_RATE_WARNING:
        recs.append(Recommendation(
            severity="warning",
            signal="elevated_deny_rate",
            message=f"{current.deny_rate:.0%} of calls denied ({current.deny_count}/{current.total_receipts}).",
            metric_name="deny_rate",
            metric_value=current.deny_rate,
            threshold=_DENY_RATE_WARNING,
            suggested_action="Monitor deny patterns. Check top denied tools below.",
        ))

    # Failure rate
    if current.failure_rate >= _FAILURE_RATE_CRITICAL:
        recs.append(Recommendation(
            severity="critical",
            signal="high_failure_rate",
            message=f"{current.failure_rate:.0%} of calls failing ({current.failure_count}/{current.total_receipts}).",
            metric_name="failure_rate",
            metric_value=current.failure_rate,
            threshold=_FAILURE_RATE_CRITICAL,
            suggested_action="Investigate error patterns in failing tools. Check tool availability and configuration.",
        ))
    elif current.failure_rate >= _FAILURE_RATE_WARNING:
        recs.append(Recommendation(
            severity="warning",
            signal="elevated_failure_rate",
            message=f"{current.failure_rate:.0%} of calls failing ({current.failure_count}/{current.total_receipts}).",
            metric_name="failure_rate",
            metric_value=current.failure_rate,
            threshold=_FAILURE_RATE_WARNING,
            suggested_action="Review failing tools and error patterns.",
        ))

    # Timeout rate
    if current.timeout_rate >= _TIMEOUT_RATE_WARNING:
        recs.append(Recommendation(
            severity="warning",
            signal="elevated_timeout_rate",
            message=f"{current.timeout_rate:.0%} of calls timing out ({current.timeout_count}/{current.total_receipts}).",
            metric_name="timeout_rate",
            metric_value=current.timeout_rate,
            threshold=_TIMEOUT_RATE_WARNING,
            suggested_action="Consider increasing timeouts or investigating slow tools.",
        ))

    # Trend: deny rate increasing
    if trend and trend.deny_rate_delta >= _DENY_TREND_WARNING:
        recs.append(Recommendation(
            severity="warning",
            signal="deny_rate_trending_up",
            message=f"Deny rate increased by {trend.deny_rate_delta:+.0%} vs previous window.",
            metric_name="deny_rate_delta",
            metric_value=trend.deny_rate_delta,
            threshold=_DENY_TREND_WARNING,
            suggested_action="Policy may be tightening. Compare recent policy changes with: assay policy impact",
        ))

    # Trend: failure rate increasing
    if trend and trend.failure_rate_delta >= _FAILURE_RATE_WARNING:
        recs.append(Recommendation(
            severity="warning",
            signal="failure_rate_trending_up",
            message=f"Failure rate increased by {trend.failure_rate_delta:+.0%} vs previous window.",
            metric_name="failure_rate_delta",
            metric_value=trend.failure_rate_delta,
            threshold=_FAILURE_RATE_WARNING,
            suggested_action="New failure mode detected. Investigate recently changed tools or configurations.",
        ))

    # No recommendations = healthy
    if not recs:
        recs.append(Recommendation(
            severity="info",
            signal="healthy",
            message=f"All signals within normal range ({current.total_receipts} receipts analyzed).",
            metric_name="total_receipts",
            metric_value=float(current.total_receipts),
            threshold=0,
            suggested_action="No action needed.",
        ))

    return recs


# ---------------------------------------------------------------------------
# Full analysis pipeline
# ---------------------------------------------------------------------------

def analyze_receipt_history(
    store_dir: Path,
    window_days: int = 7,
    end_time: Optional[datetime] = None,
) -> PolicyLoopResult:
    """Run the full receipt -> recommendation pipeline.

    1. Load receipts for current window
    2. Load receipts for previous window (same duration, immediately prior)
    3. Aggregate signals for both
    4. Compare trends
    5. Generate recommendations
    """
    if end_time is None:
        end_time = datetime.now(timezone.utc)

    # Current window
    current_receipts = load_receipts_in_window(store_dir, window_days, end_time)
    current_signals = aggregate_signals(current_receipts, window_days)

    # Previous window (same duration, immediately prior)
    prev_end = end_time - timedelta(days=window_days)
    prev_receipts = load_receipts_in_window(store_dir, window_days, prev_end)

    previous_signals = None
    trend = None
    if prev_receipts:
        previous_signals = aggregate_signals(prev_receipts, window_days)
        trend = compare_windows(current_signals, previous_signals)

    # Generate recommendations
    recommendations = generate_recommendations(current_signals, trend)

    return PolicyLoopResult(
        generated_at=datetime.now(timezone.utc).isoformat(),
        current_window=current_signals,
        previous_window=previous_signals,
        trend=trend,
        recommendations=recommendations,
        recommendation_count=len(recommendations),
        has_critical=any(r.severity == "critical" for r in recommendations),
    )


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def render_text(result: PolicyLoopResult) -> str:
    """Render analysis result as plain text."""
    lines = []
    cw = result.current_window

    lines.append("Policy Loop Analysis")
    lines.append("=" * 40)
    lines.append(f"Window: {cw.window_days}d ({cw.window_start[:10] if cw.window_start else '?'} to {cw.window_end[:10] if cw.window_end else '?'})")
    lines.append(f"Receipts: {cw.total_receipts}")
    lines.append("")

    lines.append("Signals:")
    lines.append(f"  Deny rate:    {cw.deny_rate:6.1%}  ({cw.deny_count}/{cw.total_receipts})")
    lines.append(f"  Failure rate: {cw.failure_rate:6.1%}  ({cw.failure_count}/{cw.total_receipts})")
    lines.append(f"  Timeout rate: {cw.timeout_rate:6.1%}  ({cw.timeout_count}/{cw.total_receipts})")
    lines.append(f"  Success rate: {1 - cw.deny_rate - cw.failure_rate - cw.timeout_rate:6.1%}")

    if result.trend:
        t = result.trend
        lines.append("")
        lines.append("Trend (vs previous window):")
        lines.append(f"  Deny rate:    {t.deny_rate_delta:+.1%}")
        lines.append(f"  Failure rate: {t.failure_rate_delta:+.1%}")
        lines.append(f"  Volume:       {t.total_receipts_delta:+d} receipts")

    if cw.top_denied_tools:
        lines.append("")
        lines.append("Top denied tools:")
        for t in cw.top_denied_tools[:3]:
            lines.append(f"  {t['tool']:30s}  {t['count']} denials")

    if cw.top_failing_tools:
        lines.append("")
        lines.append("Top failing tools:")
        for t in cw.top_failing_tools[:3]:
            lines.append(f"  {t['tool']:30s}  {t['count']} failures")

    lines.append("")
    lines.append("Recommendations:")
    for r in result.recommendations:
        icon = {"critical": "!!", "warning": "!", "info": "-"}[r.severity]
        lines.append(f"  [{icon}] {r.message}")
        lines.append(f"      Action: {r.suggested_action}")

    return "\n".join(lines)
