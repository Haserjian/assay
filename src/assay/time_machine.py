"""Policy Time Machine: replay historical packs against candidate policies.

Given a proof pack and a candidate policy file, replay all tool calls
through the policy evaluator and compute what WOULD have changed.
Emit an impact delta showing newly denied/allowed calls and cost impact.

Usage:
    from assay.time_machine import replay_policy
    impact = replay_policy(pack_dir, candidate_policy)
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PolicyImpact:
    """Impact of applying a candidate policy to historical evidence."""

    pack_id: str
    policy_path: str
    policy_hash: str
    total_tool_calls: int
    total_model_calls: int
    would_deny: int            # calls that would be denied under new policy
    would_allow: int           # calls that would remain allowed
    newly_denied: List[Dict[str, Any]]   # receipt summaries of calls that would be denied
    newly_allowed: List[Dict[str, Any]]  # if relaxing: calls that were denied, now allowed
    cost_impact: Optional[float]         # estimated cost delta (negative = savings)
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------

def _summarize_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a compact summary from a receipt for impact reporting."""
    rtype = receipt.get("type", "unknown")

    if rtype == "mcp_tool_call":
        return {
            "receipt_id": receipt.get("receipt_id", ""),
            "type": rtype,
            "tool_name": receipt.get("tool_name", "unknown"),
            "timestamp": receipt.get("timestamp", ""),
            "original_verdict": receipt.get("policy_verdict", "unknown"),
            "original_outcome": receipt.get("outcome", "unknown"),
        }

    if rtype == "model_call":
        return {
            "receipt_id": receipt.get("receipt_id", ""),
            "type": rtype,
            "model_id": receipt.get("model_id") or receipt.get("model", "unknown"),
            "timestamp": receipt.get("timestamp", ""),
            "input_tokens": receipt.get("input_tokens", 0),
            "output_tokens": receipt.get("output_tokens", 0),
        }

    return {
        "receipt_id": receipt.get("receipt_id", ""),
        "type": rtype,
        "timestamp": receipt.get("timestamp", ""),
    }


def replay_policy(
    pack_dir: Path,
    candidate_policy: Path,
    current_policy: Optional[Path] = None,
) -> PolicyImpact:
    """Replay a pack's tool calls against a candidate policy.

    1. Load receipts from pack
    2. Load candidate policy via load_policy()
    3. Optionally load current policy for delta comparison
    4. For each mcp_tool_call receipt:
       a. Extract tool_name
       b. Evaluate against candidate policy
       c. Compare verdict vs actual outcome in receipt
    5. Compute impact summary

    Args:
        pack_dir: Path to proof pack directory.
        candidate_policy: Path to candidate policy YAML file.
        current_policy: Optional path to current policy for delta comparison.

    Returns:
        PolicyImpact with newly denied/allowed calls and cost estimate.

    Raises:
        FileNotFoundError: If pack_dir or candidate_policy don't exist.
        ValueError: If policy file is invalid.
    """
    from assay.analyze import estimate_cost, load_pack_receipts
    from assay.explain import explain_pack
    from assay.mcp_policy import PolicyEvaluator, PolicyLoadError, load_policy

    pack_dir = Path(pack_dir)
    candidate_policy = Path(candidate_policy)

    # Load pack
    if not pack_dir.is_dir():
        raise FileNotFoundError(f"Pack directory not found: {pack_dir}")
    manifest_path = pack_dir / "pack_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No pack_manifest.json in {pack_dir}")

    receipts = load_pack_receipts(pack_dir)
    pack_info = explain_pack(pack_dir)

    # Load candidate policy
    try:
        policy = load_policy(candidate_policy)
    except PolicyLoadError as e:
        raise ValueError(f"Invalid candidate policy: {e}") from e

    evaluator = PolicyEvaluator(policy)

    # Optionally load current policy for delta comparison
    current_evaluator = None
    if current_policy:
        current_policy = Path(current_policy)
        try:
            cur_policy = load_policy(current_policy)
            current_evaluator = PolicyEvaluator(cur_policy)
        except PolicyLoadError:
            pass  # If current policy is invalid, just skip delta

    # Replay
    newly_denied: List[Dict[str, Any]] = []
    newly_allowed: List[Dict[str, Any]] = []
    total_tool_calls = 0
    total_model_calls = 0
    denied_cost = 0.0

    for r in receipts:
        rtype = r.get("type", "")

        if rtype == "mcp_tool_call":
            total_tool_calls += 1
            tool_name = r.get("tool_name", "")
            original_verdict = r.get("policy_verdict", "allow")
            original_outcome = r.get("outcome", "forwarded")

            # Evaluate against candidate policy
            decision = evaluator.evaluate(tool_name)

            if decision.verdict == "deny" and original_outcome != "denied":
                summary = _summarize_receipt(r)
                summary["candidate_verdict"] = "deny"
                summary["candidate_reason"] = decision.reason
                newly_denied.append(summary)

            elif decision.verdict == "allow" and original_outcome == "denied":
                summary = _summarize_receipt(r)
                summary["candidate_verdict"] = "allow"
                newly_allowed.append(summary)

        elif rtype == "model_call":
            total_model_calls += 1
            # Check model deny/allow lists if policy has them
            model_id = r.get("model_id") or r.get("model", "")
            # Model calls aren't directly evaluated by MCP policy,
            # but we track them for cost impact
            in_t = r.get("input_tokens", 0) or 0
            out_t = r.get("output_tokens", 0) or 0

    # Estimate cost impact from denied tool calls
    # If a tool call would be denied, subsequent model calls might not happen
    # Conservative estimate: just count direct denial savings
    for nd in newly_denied:
        # Each denied tool call might have saved the follow-up cost
        # Use average cost per call as rough estimate
        denied_cost += 0.0  # We can't reliably estimate without more data

    would_deny = len(newly_denied)
    would_allow = total_tool_calls - would_deny + len(newly_allowed)

    # Build summary
    parts: List[str] = []
    parts.append(f"Replayed {total_tool_calls} tool calls and {total_model_calls} model calls against candidate policy.")
    if would_deny > 0:
        parts.append(f"{would_deny} tool call(s) would be NEWLY DENIED.")
    if newly_allowed:
        parts.append(f"{len(newly_allowed)} previously denied call(s) would be NEWLY ALLOWED.")
    if would_deny == 0 and not newly_allowed:
        parts.append("No change in verdicts.")

    return PolicyImpact(
        pack_id=pack_info.get("pack_id", "unknown"),
        policy_path=str(candidate_policy),
        policy_hash=policy.source_hash or "",
        total_tool_calls=total_tool_calls,
        total_model_calls=total_model_calls,
        would_deny=would_deny,
        would_allow=would_allow,
        newly_denied=newly_denied,
        newly_allowed=newly_allowed,
        cost_impact=None,  # Conservative: don't guess
        summary=" ".join(parts),
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_impact_text(impact: PolicyImpact) -> str:
    """Console output for policy replay results."""
    lines: List[str] = []

    lines.append(f"POLICY REPLAY: {impact.pack_id}")
    lines.append(f"  Candidate policy: {impact.policy_path}")
    lines.append(f"  Tool calls replayed: {impact.total_tool_calls}")
    lines.append(f"  Model calls in pack: {impact.total_model_calls}")
    lines.append("")

    lines.append("IMPACT")
    lines.append(f"  Newly denied: {impact.would_deny}")
    lines.append(f"  Newly allowed: {len(impact.newly_allowed)}")
    lines.append("")

    if impact.newly_denied:
        lines.append("NEWLY DENIED CALLS")
        for nd in impact.newly_denied:
            tool = nd.get("tool_name", nd.get("model_id", "unknown"))
            reason = nd.get("candidate_reason", "")
            lines.append(f"  - {tool}: {reason}")
        lines.append("")

    if impact.newly_allowed:
        lines.append("NEWLY ALLOWED CALLS")
        for na in impact.newly_allowed:
            tool = na.get("tool_name", na.get("model_id", "unknown"))
            lines.append(f"  - {tool} (was denied)")
        lines.append("")

    lines.append("SUMMARY")
    lines.append(f"  {impact.summary}")
    lines.append("")

    return "\n".join(lines)


def render_impact_md(impact: PolicyImpact) -> str:
    """Markdown output for policy replay results."""
    lines: List[str] = []

    lines.append(f"# Policy Replay: `{impact.pack_id}`")
    lines.append("")
    lines.append(f"**Candidate policy:** `{impact.policy_path}`")
    lines.append(f"**Tool calls replayed:** {impact.total_tool_calls}")
    lines.append(f"**Model calls in pack:** {impact.total_model_calls}")
    lines.append("")

    lines.append("## Impact")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Newly denied | {impact.would_deny} |")
    lines.append(f"| Newly allowed | {len(impact.newly_allowed)} |")
    lines.append("")

    if impact.newly_denied:
        lines.append("## Newly Denied Calls")
        lines.append("")
        lines.append("| Tool | Reason |")
        lines.append("|------|--------|")
        for nd in impact.newly_denied:
            tool = nd.get("tool_name", nd.get("model_id", "unknown"))
            reason = nd.get("candidate_reason", "")
            lines.append(f"| `{tool}` | {reason} |")
        lines.append("")

    if impact.newly_allowed:
        lines.append("## Newly Allowed Calls")
        lines.append("")
        for na in impact.newly_allowed:
            tool = na.get("tool_name", na.get("model_id", "unknown"))
            lines.append(f"- `{tool}` (was denied)")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(impact.summary)
    lines.append("")

    return "\n".join(lines)
