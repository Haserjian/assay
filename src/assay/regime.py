"""Temporal regime detection for Assay receipt streams.

Aggregates receipts into time windows and detects regime changes:
model swaps, cost spikes, latency drift, and error rate shifts.

A "regime" is a period where system behavior is statistically stable.
A "drift flag" signals a transition between regimes.

Usage:
    from assay.regime import detect_regimes
    flags = detect_regimes(receipts, window_hours=24)
"""
from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WindowStats:
    """Aggregated statistics for one time window."""

    window_start: str
    window_end: str
    n_calls: int = 0
    models: Dict[str, int] = field(default_factory=dict)
    providers: Dict[str, int] = field(default_factory=dict)
    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latencies: List[float] = field(default_factory=list)
    errors: int = 0

    @property
    def latency_mean(self) -> Optional[float]:
        return statistics.mean(self.latencies) if self.latencies else None

    @property
    def latency_p50(self) -> Optional[float]:
        if not self.latencies:
            return None
        s = sorted(self.latencies)
        idx = min(int(len(s) * 0.5), len(s) - 1)
        return s[idx]

    @property
    def latency_p95(self) -> Optional[float]:
        if not self.latencies:
            return None
        s = sorted(self.latencies)
        idx = min(int(len(s) * 0.95), len(s) - 1)
        return s[idx]

    @property
    def error_rate(self) -> float:
        return self.errors / self.n_calls if self.n_calls else 0.0

    @property
    def cost_per_call(self) -> float:
        return self.cost_usd / self.n_calls if self.n_calls else 0.0

    @property
    def dominant_model(self) -> Optional[str]:
        if not self.models:
            return None
        return max(self.models, key=self.models.get)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "n_calls": self.n_calls,
            "models": self.models,
            "providers": self.providers,
            "tokens": {
                "input": self.input_tokens,
                "output": self.output_tokens,
                "total": self.total_tokens,
            },
            "cost_usd": round(self.cost_usd, 4),
            "errors": self.errors,
            "error_rate": round(self.error_rate, 4),
        }
        if self.latencies:
            d["latency_ms"] = {
                "mean": round(self.latency_mean, 1) if self.latency_mean else None,
                "p50": round(self.latency_p50, 1) if self.latency_p50 else None,
                "p95": round(self.latency_p95, 1) if self.latency_p95 else None,
            }
        return d


@dataclass
class DriftFlag:
    """A detected regime change between two adjacent windows."""

    flag_type: str        # "model_swap", "cost_spike", "latency_drift", "error_spike"
    severity: str         # "info", "warning", "alert"
    window_before: str    # ISO timestamp of the preceding window start
    window_after: str     # ISO timestamp of the changed window start
    description: str      # Human-readable description
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RegimeReport:
    """Full regime detection report."""

    window_hours: int
    n_windows: int
    n_receipts: int
    flags: List[DriftFlag]
    windows: List[WindowStats]

    @property
    def n_alerts(self) -> int:
        return sum(1 for f in self.flags if f.severity == "alert")

    @property
    def n_warnings(self) -> int:
        return sum(1 for f in self.flags if f.severity == "warning")

    @property
    def n_info(self) -> int:
        return sum(1 for f in self.flags if f.severity == "info")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_hours": self.window_hours,
            "n_windows": self.n_windows,
            "n_receipts": self.n_receipts,
            "summary": {
                "total_flags": len(self.flags),
                "alerts": self.n_alerts,
                "warnings": self.n_warnings,
                "info": self.n_info,
            },
            "flags": [f.to_dict() for f in self.flags],
            "windows": [w.to_dict() for w in self.windows],
        }


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Cost spike: relative change threshold
COST_SPIKE_WARNING = 0.50   # 50% increase
COST_SPIKE_ALERT = 1.00     # 100% increase (doubled)

# Latency drift: relative change in p50 latency
LATENCY_DRIFT_WARNING = 0.50   # 50% increase
LATENCY_DRIFT_ALERT = 1.00     # 100% increase

# Error rate: absolute change thresholds
ERROR_SPIKE_WARNING = 0.05     # 5% absolute increase
ERROR_SPIKE_ALERT = 0.15       # 15% absolute increase

# Minimum calls per window to consider for drift analysis
MIN_CALLS_PER_WINDOW = 3


# ---------------------------------------------------------------------------
# Time window aggregation
# ---------------------------------------------------------------------------

def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp, tolerant of common variants."""
    if not ts:
        return None
    try:
        # Handle 'Z' suffix
        ts_clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_clean)
    except (ValueError, TypeError):
        return None


def aggregate_windows(
    receipts: List[Dict[str, Any]],
    window_hours: int = 24,
) -> List[WindowStats]:
    """Aggregate receipts into fixed-duration time windows.

    Only model_call receipts contribute to windowed statistics.
    Windows with zero calls are omitted.
    """
    from assay.analyze import estimate_cost

    # Filter and parse timestamps
    timed: List[Tuple[datetime, Dict[str, Any]]] = []
    for r in receipts:
        if r.get("type") != "model_call":
            continue
        ts = _parse_timestamp(r.get("timestamp", ""))
        if ts is not None:
            timed.append((ts, r))

    if not timed:
        return []

    timed.sort(key=lambda x: x[0])
    earliest = timed[0][0]
    latest = timed[-1][0]

    # Build window boundaries
    delta = timedelta(hours=window_hours)
    windows: List[WindowStats] = []
    win_start = earliest.replace(minute=0, second=0, microsecond=0)

    while win_start <= latest:
        win_end = win_start + delta
        ws = WindowStats(
            window_start=win_start.isoformat(),
            window_end=win_end.isoformat(),
        )
        windows.append(ws)
        win_start = win_end

    # Assign receipts to windows
    for ts, r in timed:
        # Find the right window
        for ws in windows:
            ws_start = datetime.fromisoformat(ws.window_start)
            ws_end = datetime.fromisoformat(ws.window_end)
            if ws_start <= ts < ws_end:
                model_id = r.get("model_id") or r.get("model") or "unknown"
                provider = r.get("provider", "unknown")
                in_t = r.get("input_tokens", 0) or 0
                out_t = r.get("output_tokens", 0) or 0
                tot_t = r.get("total_tokens") or (in_t + out_t)

                ws.n_calls += 1
                ws.models[model_id] = ws.models.get(model_id, 0) + 1
                ws.providers[provider] = ws.providers.get(provider, 0) + 1
                ws.input_tokens += in_t
                ws.output_tokens += out_t
                ws.total_tokens += tot_t
                ws.cost_usd += estimate_cost(model_id, in_t, out_t)
                if r.get("latency_ms") is not None:
                    ws.latencies.append(float(r["latency_ms"]))
                if r.get("error"):
                    ws.errors += 1
                break

    # Drop empty windows
    return [w for w in windows if w.n_calls > 0]


# ---------------------------------------------------------------------------
# Regime detectors
# ---------------------------------------------------------------------------

def _detect_model_swaps(windows: List[WindowStats]) -> List[DriftFlag]:
    """Detect when the dominant model changes between windows."""
    flags: List[DriftFlag] = []
    for i in range(1, len(windows)):
        prev = windows[i - 1]
        curr = windows[i]
        if prev.n_calls < MIN_CALLS_PER_WINDOW or curr.n_calls < MIN_CALLS_PER_WINDOW:
            continue

        prev_dom = prev.dominant_model
        curr_dom = curr.dominant_model
        if prev_dom and curr_dom and prev_dom != curr_dom:
            # Check if this is a major swap (dominant model completely changed)
            # vs minor (new model appeared alongside existing)
            prev_set = set(prev.models.keys())
            curr_set = set(curr.models.keys())
            new_models = curr_set - prev_set
            removed_models = prev_set - curr_set

            severity = "warning"
            if removed_models and new_models:
                severity = "alert"  # Complete replacement

            flags.append(DriftFlag(
                flag_type="model_swap",
                severity=severity,
                window_before=prev.window_start,
                window_after=curr.window_start,
                description=f"Dominant model changed: {prev_dom} -> {curr_dom}",
                detail={
                    "before": prev_dom,
                    "after": curr_dom,
                    "new_models": sorted(new_models),
                    "removed_models": sorted(removed_models),
                },
            ))

    return flags


def _detect_cost_spikes(windows: List[WindowStats]) -> List[DriftFlag]:
    """Detect significant cost-per-call increases between windows."""
    flags: List[DriftFlag] = []
    for i in range(1, len(windows)):
        prev = windows[i - 1]
        curr = windows[i]
        if prev.n_calls < MIN_CALLS_PER_WINDOW or curr.n_calls < MIN_CALLS_PER_WINDOW:
            continue

        prev_cpc = prev.cost_per_call
        curr_cpc = curr.cost_per_call
        if prev_cpc <= 0:
            continue

        change = (curr_cpc - prev_cpc) / prev_cpc
        if change >= COST_SPIKE_ALERT:
            severity = "alert"
        elif change >= COST_SPIKE_WARNING:
            severity = "warning"
        else:
            continue

        flags.append(DriftFlag(
            flag_type="cost_spike",
            severity=severity,
            window_before=prev.window_start,
            window_after=curr.window_start,
            description=f"Cost per call increased {change:.0%}: ${prev_cpc:.4f} -> ${curr_cpc:.4f}",
            detail={
                "before_cost_per_call": round(prev_cpc, 6),
                "after_cost_per_call": round(curr_cpc, 6),
                "change_pct": round(change * 100, 1),
            },
        ))

    return flags


def _detect_latency_drift(windows: List[WindowStats]) -> List[DriftFlag]:
    """Detect significant latency p50 increases between windows."""
    flags: List[DriftFlag] = []
    for i in range(1, len(windows)):
        prev = windows[i - 1]
        curr = windows[i]
        if prev.n_calls < MIN_CALLS_PER_WINDOW or curr.n_calls < MIN_CALLS_PER_WINDOW:
            continue

        prev_p50 = prev.latency_p50
        curr_p50 = curr.latency_p50
        if prev_p50 is None or curr_p50 is None or prev_p50 <= 0:
            continue

        change = (curr_p50 - prev_p50) / prev_p50
        if change >= LATENCY_DRIFT_ALERT:
            severity = "alert"
        elif change >= LATENCY_DRIFT_WARNING:
            severity = "warning"
        else:
            continue

        flags.append(DriftFlag(
            flag_type="latency_drift",
            severity=severity,
            window_before=prev.window_start,
            window_after=curr.window_start,
            description=f"Latency p50 increased {change:.0%}: {prev_p50:.0f}ms -> {curr_p50:.0f}ms",
            detail={
                "before_p50_ms": round(prev_p50, 1),
                "after_p50_ms": round(curr_p50, 1),
                "change_pct": round(change * 100, 1),
            },
        ))

    return flags


def _detect_error_spikes(windows: List[WindowStats]) -> List[DriftFlag]:
    """Detect significant error rate increases between windows."""
    flags: List[DriftFlag] = []
    for i in range(1, len(windows)):
        prev = windows[i - 1]
        curr = windows[i]
        if prev.n_calls < MIN_CALLS_PER_WINDOW or curr.n_calls < MIN_CALLS_PER_WINDOW:
            continue

        prev_rate = prev.error_rate
        curr_rate = curr.error_rate
        change = curr_rate - prev_rate

        if change >= ERROR_SPIKE_ALERT:
            severity = "alert"
        elif change >= ERROR_SPIKE_WARNING:
            severity = "warning"
        else:
            continue

        flags.append(DriftFlag(
            flag_type="error_spike",
            severity=severity,
            window_before=prev.window_start,
            window_after=curr.window_start,
            description=f"Error rate increased: {prev_rate:.1%} -> {curr_rate:.1%} (+{change:.1%})",
            detail={
                "before_error_rate": round(prev_rate, 4),
                "after_error_rate": round(curr_rate, 4),
                "change_abs": round(change, 4),
            },
        ))

    return flags


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def detect_regimes(
    receipts: List[Dict[str, Any]],
    window_hours: int = 24,
) -> RegimeReport:
    """Detect regime changes in a receipt stream.

    Aggregates receipts into time windows, then compares adjacent windows
    for model swaps, cost spikes, latency drift, and error rate shifts.

    Args:
        receipts: List of receipt dicts (all types; only model_call used).
        window_hours: Duration of each aggregation window in hours.

    Returns:
        RegimeReport with drift flags and per-window statistics.
    """
    windows = aggregate_windows(receipts, window_hours=window_hours)

    flags: List[DriftFlag] = []
    flags.extend(_detect_model_swaps(windows))
    flags.extend(_detect_cost_spikes(windows))
    flags.extend(_detect_latency_drift(windows))
    flags.extend(_detect_error_spikes(windows))

    # Sort by window_after timestamp, then severity (alert > warning > info)
    severity_order = {"alert": 0, "warning": 1, "info": 2}
    flags.sort(key=lambda f: (f.window_after, severity_order.get(f.severity, 3)))

    return RegimeReport(
        window_hours=window_hours,
        n_windows=len(windows),
        n_receipts=sum(w.n_calls for w in windows),
        flags=flags,
        windows=windows,
    )


__all__ = [
    "WindowStats",
    "DriftFlag",
    "RegimeReport",
    "aggregate_windows",
    "detect_regimes",
    "COST_SPIKE_WARNING",
    "COST_SPIKE_ALERT",
    "LATENCY_DRIFT_WARNING",
    "LATENCY_DRIFT_ALERT",
    "ERROR_SPIKE_WARNING",
    "ERROR_SPIKE_ALERT",
    "MIN_CALLS_PER_WINDOW",
]
