"""Receipt analytics for Assay proof packs and traces.

Reads model_call receipts and computes cost, latency, error, and
distribution breakdowns. Pricing estimates are approximate.
"""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Approximate pricing (USD per 1M tokens)
# ---------------------------------------------------------------------------

_PRICING: Dict[str, Dict[str, float]] = {
    # OpenAI
    "gpt-4o": {"input": 2.50, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.0, "output": 30.0},
    "gpt-4": {"input": 30.0, "output": 60.0},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "o1": {"input": 15.0, "output": 60.0},
    "o1-mini": {"input": 3.0, "output": 12.0},
    # Anthropic
    "claude-opus-4": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4": {"input": 3.0, "output": 15.0},
    "claude-3-opus": {"input": 15.0, "output": 75.0},
    "claude-3-sonnet": {"input": 3.0, "output": 15.0},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3-5-sonnet": {"input": 3.0, "output": 15.0},
    "claude-3-5-haiku": {"input": 0.80, "output": 4.0},
}

_DEFAULT_PRICING = {"input": 10.0, "output": 30.0}


def _lookup_pricing(model_id: str) -> Dict[str, float]:
    """Look up pricing by exact match, then prefix match."""
    if model_id in _PRICING:
        return _PRICING[model_id]
    for prefix, prices in _PRICING.items():
        if model_id.startswith(prefix):
            return prices
    return _DEFAULT_PRICING


def estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost in USD."""
    prices = _lookup_pricing(model_id)
    return (input_tokens / 1_000_000) * prices["input"] + \
           (output_tokens / 1_000_000) * prices["output"]


# ---------------------------------------------------------------------------
# Analysis result
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """Structured result of receipt analysis."""

    # Summary
    total_receipts: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    time_start: Optional[str] = None
    time_end: Optional[str] = None

    # Latency
    latencies: List[int] = field(default_factory=list)

    # Errors
    errors: int = 0

    # Finish reasons
    finish_reasons: Dict[str, int] = field(default_factory=dict)

    # Breakdowns
    by_model: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_provider: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_callsite: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Source metadata
    source_type: str = ""  # "pack" or "history"
    source_path: str = ""
    trace_count: int = 0
    verified: bool = False
    history_days: Optional[int] = None

    @property
    def error_rate(self) -> float:
        return self.errors / self.model_calls if self.model_calls else 0.0

    @property
    def latency_p50(self) -> Optional[int]:
        return self._percentile(0.50)

    @property
    def latency_p95(self) -> Optional[int]:
        return self._percentile(0.95)

    @property
    def latency_p99(self) -> Optional[int]:
        return self._percentile(0.99)

    @property
    def latency_mean(self) -> Optional[float]:
        return round(statistics.mean(self.latencies), 1) if self.latencies else None

    @property
    def latency_max(self) -> Optional[int]:
        return max(self.latencies) if self.latencies else None

    def _percentile(self, pct: float) -> Optional[int]:
        if not self.latencies:
            return None
        s = sorted(self.latencies)
        idx = min(int(len(s) * pct), len(s) - 1)
        return s[idx]

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "total_receipts": self.total_receipts,
            "model_calls": self.model_calls,
            "tokens": {
                "input": self.input_tokens,
                "output": self.output_tokens,
                "total": self.total_tokens,
            },
            "estimated_cost_usd": round(self.cost_usd, 4),
            "time_span": {
                "start": self.time_start,
                "end": self.time_end,
            },
            "errors": {
                "count": self.errors,
                "rate": round(self.error_rate, 4),
            },
            "finish_reasons": self.finish_reasons,
            "by_model": self.by_model,
            "by_provider": self.by_provider,
            "source": {
                "type": self.source_type,
                "path": self.source_path,
                "trace_count": self.trace_count,
                "verified": self.verified,
                "window_days": self.history_days,
            },
        }
        if self.latencies:
            d["latency_ms"] = {
                "p50": self.latency_p50,
                "p95": self.latency_p95,
                "p99": self.latency_p99,
                "mean": self.latency_mean,
                "max": self.latency_max,
            }
        if self.by_callsite:
            d["by_callsite"] = self.by_callsite
        return d


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def analyze_receipts(receipts: List[Dict[str, Any]]) -> AnalysisResult:
    """Analyze a list of receipt dicts and produce an AnalysisResult."""
    result = AnalysisResult(total_receipts=len(receipts))
    timestamps: List[str] = []

    for r in receipts:
        if r.get("type") != "model_call":
            continue

        result.model_calls += 1
        model_id = r.get("model_id", "unknown")
        provider = r.get("provider", "unknown")
        in_t = r.get("input_tokens", 0) or 0
        out_t = r.get("output_tokens", 0) or 0
        tot_t = r.get("total_tokens") or (in_t + out_t)
        cost = estimate_cost(model_id, in_t, out_t)

        result.input_tokens += in_t
        result.output_tokens += out_t
        result.total_tokens += tot_t
        result.cost_usd += cost

        latency = r.get("latency_ms")
        if latency is not None:
            result.latencies.append(int(latency))

        if r.get("error"):
            result.errors += 1

        fr = r.get("finish_reason") or "unknown"
        result.finish_reasons[fr] = result.finish_reasons.get(fr, 0) + 1

        ts = r.get("timestamp")
        if ts:
            timestamps.append(ts)

        # -- by model --
        if model_id not in result.by_model:
            result.by_model[model_id] = _new_bucket()
        _accum(result.by_model[model_id], in_t, out_t, tot_t, cost, r.get("error"))

        # -- by provider --
        if provider not in result.by_provider:
            result.by_provider[provider] = _new_bucket()
        _accum(result.by_provider[provider], in_t, out_t, tot_t, cost, r.get("error"))

        # -- by callsite --
        cs_id = r.get("callsite_id")
        if cs_id:
            if cs_id not in result.by_callsite:
                result.by_callsite[cs_id] = {
                    "file": r.get("callsite_file", ""),
                    "line": r.get("callsite_line", ""),
                    **_new_bucket(),
                }
            _accum(result.by_callsite[cs_id], in_t, out_t, tot_t, cost, r.get("error"))

    if timestamps:
        timestamps.sort()
        result.time_start = timestamps[0]
        result.time_end = timestamps[-1]

    # Round costs
    result.cost_usd = round(result.cost_usd, 6)
    for bucket in list(result.by_model.values()) + list(result.by_provider.values()) + list(result.by_callsite.values()):
        bucket["cost_usd"] = round(bucket["cost_usd"], 4)

    return result


def _new_bucket() -> Dict[str, Any]:
    return {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0, "errors": 0}


def _accum(bucket: Dict[str, Any], in_t: int, out_t: int, tot_t: int, cost: float, error: Any) -> None:
    bucket["calls"] += 1
    bucket["input_tokens"] += in_t
    bucket["output_tokens"] += out_t
    bucket["total_tokens"] += tot_t
    bucket["cost_usd"] += cost
    if error:
        bucket["errors"] += 1


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_pack_receipts(pack_dir: Path) -> List[Dict[str, Any]]:
    """Load receipts from a proof pack directory."""
    receipt_file = pack_dir / "receipt_pack.jsonl"
    if not receipt_file.exists():
        raise FileNotFoundError(f"No receipt_pack.jsonl in {pack_dir}")
    receipts = []
    for line in receipt_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            receipts.append(json.loads(line))
    return receipts


def load_history_receipts(
    store_dir: Optional[Path] = None,
    since_days: int = 7,
) -> Tuple[List[Dict[str, Any]], int]:
    """Load receipts from local trace history.

    Returns (receipts, trace_count).
    """
    if store_dir is None:
        from assay.store import assay_home
        store_dir = assay_home()
    if not store_dir.exists():
        return [], 0

    cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%d")
    receipts: List[Dict[str, Any]] = []
    trace_count = 0

    for date_dir in sorted(store_dir.iterdir()):
        if not date_dir.is_dir() or date_dir.name.startswith("."):
            continue
        if date_dir.name < cutoff:
            continue
        for trace_file in sorted(date_dir.glob("trace_*.jsonl")):
            trace_count += 1
            for line in trace_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        receipts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    return receipts, trace_count
