"""Policy Merge Guard: aggregate policy impact analysis with CI gating.

Replays multiple historical packs against a candidate policy, computes
aggregate impact (newly denied / allowed / risk delta), evaluates CI
thresholds, and optionally emits a signed PolicyImpactReceipt.

Usage:
    from assay.policy_guard import aggregate_policy_impact, evaluate_thresholds
    impact = aggregate_policy_impact(packs_dir, policy_new)
    verdict, reason = evaluate_thresholds(impact, fail_if_newly_denied=0)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AggregateImpact:
    """Aggregated impact across multiple packs."""

    policy_old_hash: Optional[str]
    policy_new_hash: str
    policy_old_path: Optional[str]
    policy_new_path: str
    packs_examined: int
    mcp_calls_examined: int
    model_calls_examined: int
    newly_denied_count: int
    newly_allowed_count: int
    risk_delta: float
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    top_changed_tools: List[Dict[str, Any]] = field(default_factory=list)
    per_pack_summaries: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Aggregation engine
# ---------------------------------------------------------------------------

def _discover_packs(packs_dir: Path) -> List[Path]:
    """Find all pack directories under packs_dir."""
    packs: List[Path] = []
    if not packs_dir.is_dir():
        return packs

    # Direct pack (packs_dir itself has manifest)
    if (packs_dir / "pack_manifest.json").exists():
        return [packs_dir]

    # Subdirectories with manifests
    for child in sorted(packs_dir.iterdir()):
        if child.is_dir() and (child / "pack_manifest.json").exists():
            packs.append(child)

    return packs


def aggregate_policy_impact(
    packs_dir: Path,
    policy_new: Path,
    policy_old: Optional[Path] = None,
) -> AggregateImpact:
    """Replay all packs in a directory against a candidate policy.

    Args:
        packs_dir: Directory containing one or more pack subdirectories.
        policy_new: Path to candidate policy YAML.
        policy_old: Optional path to current/baseline policy YAML.

    Returns:
        AggregateImpact with summed counts and per-pack details.

    Raises:
        FileNotFoundError: If packs_dir doesn't exist.
        ValueError: If policy_new is invalid.
    """
    from assay.mcp_policy import PolicyLoadError, compute_policy_hash, load_policy
    from assay.time_machine import replay_policy

    packs_dir = Path(packs_dir)
    policy_new = Path(policy_new)

    if not packs_dir.exists():
        raise FileNotFoundError(f"Packs directory not found: {packs_dir}")

    # Validate candidate policy
    try:
        _ = load_policy(policy_new)
    except PolicyLoadError as e:
        raise ValueError(f"Invalid candidate policy: {e}") from e

    new_hash = compute_policy_hash(policy_new)
    old_hash = None
    if policy_old:
        policy_old = Path(policy_old)
        try:
            old_hash = compute_policy_hash(policy_old)
        except Exception:
            pass

    # Discover packs
    pack_dirs = _discover_packs(packs_dir)

    # Replay each pack
    total_mcp = 0
    total_model = 0
    total_denied = 0
    total_allowed = 0
    severity: Dict[str, int] = {}
    tool_impact: Dict[str, Dict[str, Any]] = {}  # tool_name -> {denied, reasons}
    per_pack: List[Dict[str, Any]] = []

    for pd in pack_dirs:
        try:
            impact = replay_policy(pd, policy_new, current_policy=policy_old)
        except (FileNotFoundError, ValueError):
            continue

        total_mcp += impact.total_tool_calls
        total_model += impact.total_model_calls
        total_denied += impact.would_deny
        total_allowed += len(impact.newly_allowed)

        # Accumulate severity breakdown
        for nd in impact.newly_denied:
            reason = nd.get("candidate_reason", "unknown")
            severity[reason] = severity.get(reason, 0) + 1

            tool_name = nd.get("tool_name", "unknown")
            if tool_name not in tool_impact:
                tool_impact[tool_name] = {"tool_name": tool_name, "newly_denied": 0, "reason": reason}
            tool_impact[tool_name]["newly_denied"] += 1

        per_pack.append({
            "pack_id": impact.pack_id,
            "tool_calls": impact.total_tool_calls,
            "model_calls": impact.total_model_calls,
            "newly_denied": impact.would_deny,
            "newly_allowed": len(impact.newly_allowed),
        })

    # Top changed tools (sorted by impact, cap at 10)
    top_tools = sorted(tool_impact.values(), key=lambda x: x["newly_denied"], reverse=True)[:10]

    # Risk delta
    risk_delta = total_denied / total_mcp if total_mcp > 0 else 0.0

    return AggregateImpact(
        policy_old_hash=old_hash,
        policy_new_hash=new_hash,
        policy_old_path=str(policy_old) if policy_old else None,
        policy_new_path=str(policy_new),
        packs_examined=len(pack_dirs),
        mcp_calls_examined=total_mcp,
        model_calls_examined=total_model,
        newly_denied_count=total_denied,
        newly_allowed_count=total_allowed,
        risk_delta=round(risk_delta, 6),
        severity_breakdown=severity,
        top_changed_tools=top_tools,
        per_pack_summaries=per_pack,
    )


# ---------------------------------------------------------------------------
# Threshold evaluation
# ---------------------------------------------------------------------------

def evaluate_thresholds(
    impact: AggregateImpact,
    fail_if_newly_denied: Optional[int] = None,
    fail_if_risk_delta: Optional[float] = None,
) -> Tuple[str, str]:
    """Evaluate CI thresholds against aggregate impact.

    Returns:
        (verdict, reason) where verdict is "pass" or "fail".
    """
    if fail_if_newly_denied is not None:
        if impact.newly_denied_count > fail_if_newly_denied:
            return (
                "fail",
                f"newly_denied_count ({impact.newly_denied_count}) "
                f"exceeds threshold ({fail_if_newly_denied})",
            )

    if fail_if_risk_delta is not None:
        if impact.risk_delta > fail_if_risk_delta:
            return (
                "fail",
                f"risk_delta ({impact.risk_delta:.4f}) "
                f"exceeds threshold ({fail_if_risk_delta})",
            )

    return ("pass", "all thresholds passed")


# ---------------------------------------------------------------------------
# Receipt emission
# ---------------------------------------------------------------------------

def emit_policy_impact_receipt(
    impact: AggregateImpact,
    verdict: str,
    verdict_reason: str,
    thresholds: Dict[str, Any],
) -> Dict[str, Any]:
    """Emit a PolicyImpactReceipt to the current trace.

    Returns the full receipt dict.
    """
    from assay.store import emit_receipt

    data = {
        "policy_old_hash": impact.policy_old_hash,
        "policy_new_hash": impact.policy_new_hash,
        "policy_old_path": impact.policy_old_path,
        "policy_new_path": impact.policy_new_path,
        "packs_examined": impact.packs_examined,
        "mcp_calls_examined": impact.mcp_calls_examined,
        "model_calls_examined": impact.model_calls_examined,
        "newly_denied_count": impact.newly_denied_count,
        "newly_allowed_count": impact.newly_allowed_count,
        "risk_delta": impact.risk_delta,
        "severity_breakdown": impact.severity_breakdown,
        "top_changed_tools": impact.top_changed_tools,
        "thresholds": thresholds,
        "ci_verdict": verdict,
        "ci_verdict_reason": verdict_reason,
    }

    return emit_receipt("policy_impact", data)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_impact_text(
    impact: AggregateImpact,
    verdict: str = "pass",
    verdict_reason: str = "",
) -> str:
    """Console output for aggregate policy impact."""
    lines: List[str] = []

    lines.append("POLICY IMPACT ANALYSIS")
    lines.append(f"  Candidate: {impact.policy_new_path}")
    if impact.policy_old_path:
        lines.append(f"  Baseline:  {impact.policy_old_path}")
    lines.append(f"  Packs examined: {impact.packs_examined}")
    lines.append(f"  MCP calls replayed: {impact.mcp_calls_examined}")
    lines.append(f"  Model calls in packs: {impact.model_calls_examined}")
    lines.append("")

    lines.append("IMPACT")
    lines.append(f"  Newly denied:  {impact.newly_denied_count}")
    lines.append(f"  Newly allowed: {impact.newly_allowed_count}")
    lines.append(f"  Risk delta:    {impact.risk_delta:.4f} ({impact.risk_delta:.1%} of tool calls)")
    lines.append("")

    if impact.severity_breakdown:
        lines.append("SEVERITY BREAKDOWN")
        for reason, count in sorted(impact.severity_breakdown.items()):
            lines.append(f"  {reason}: {count}")
        lines.append("")

    if impact.top_changed_tools:
        lines.append("TOP AFFECTED TOOLS")
        for t in impact.top_changed_tools:
            lines.append(f"  {t['tool_name']}: {t['newly_denied']} denied ({t['reason']})")
        lines.append("")

    verd_upper = verdict.upper()
    lines.append(f"CI VERDICT: {verd_upper}")
    if verdict_reason:
        lines.append(f"  {verdict_reason}")
    lines.append("")

    return "\n".join(lines)


def render_impact_md(
    impact: AggregateImpact,
    verdict: str = "pass",
    verdict_reason: str = "",
) -> str:
    """Markdown output for aggregate policy impact."""
    lines: List[str] = []

    lines.append("# Policy Impact Analysis")
    lines.append("")
    lines.append(f"**Candidate:** `{impact.policy_new_path}`")
    if impact.policy_old_path:
        lines.append(f"**Baseline:** `{impact.policy_old_path}`")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Packs examined | {impact.packs_examined} |")
    lines.append(f"| MCP calls replayed | {impact.mcp_calls_examined} |")
    lines.append(f"| Newly denied | {impact.newly_denied_count} |")
    lines.append(f"| Newly allowed | {impact.newly_allowed_count} |")
    lines.append(f"| Risk delta | {impact.risk_delta:.4f} ({impact.risk_delta:.1%}) |")
    lines.append("")

    if impact.top_changed_tools:
        lines.append("## Top Affected Tools")
        lines.append("")
        lines.append("| Tool | Newly Denied | Reason |")
        lines.append("|------|-------------|--------|")
        for t in impact.top_changed_tools:
            lines.append(f"| `{t['tool_name']}` | {t['newly_denied']} | {t['reason']} |")
        lines.append("")

    verd_upper = verdict.upper()
    lines.append(f"## CI Verdict: **{verd_upper}**")
    lines.append("")
    if verdict_reason:
        lines.append(verdict_reason)
        lines.append("")

    return "\n".join(lines)
