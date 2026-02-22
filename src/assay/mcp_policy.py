"""
MCP Guard Profile: policy loader, evaluator, and budget tracker.

Loads an assay.mcp-policy.yaml (v1 schema) and evaluates tool calls
against allow/deny lists, per-tool constraints, and session budgets.

Policy modes:
  - audit:   v0 behavior. Receipts record would-be verdicts but tools are
             never blocked. Default for backward compatibility.
  - enforce: denied tool calls are blocked before reaching the server.
             The proxy returns a JSON-RPC error and emits a denied receipt.

Missing policy file at startup with --policy flag: fail-closed (exit 1).
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ToolConstraint:
    """Per-tool limits and argument filters."""
    max_calls: Optional[int] = None
    deny_patterns: List[str] = field(default_factory=list)


@dataclass
class ToolPolicy:
    """Allow/deny rules for tools."""
    default: str = "allow"  # "allow" or "deny"
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    constraints: Dict[str, ToolConstraint] = field(default_factory=dict)


@dataclass
class BudgetPolicy:
    """Session-wide limits."""
    max_tool_calls: Optional[int] = None
    max_wall_time_sec: Optional[int] = None


@dataclass
class MCPPolicy:
    """Parsed MCP policy file."""
    version: str = "1"
    server_id: str = ""
    mode: str = "audit"  # "audit" or "enforce"
    store_args: bool = False
    store_results: bool = False
    auto_pack: bool = True
    audit_dir: str = ".assay/mcp"
    tools: ToolPolicy = field(default_factory=ToolPolicy)
    budget: BudgetPolicy = field(default_factory=BudgetPolicy)
    source_path: Optional[str] = None
    source_hash: Optional[str] = None


# ---------------------------------------------------------------------------
# Policy decision
# ---------------------------------------------------------------------------


@dataclass
class PolicyDecision:
    """Result of evaluating a tool call against a policy."""
    verdict: str  # "allow", "deny", "no_policy"
    reason: Optional[str] = None  # "deny_list", "not_in_allow", "budget_exceeded", etc.
    detail: Optional[str] = None  # human-readable detail


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded or parsed."""


def _compute_file_hash(path: Path) -> str:
    """SHA-256 of file contents."""
    data = path.read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_tool_constraint(raw: Dict[str, Any]) -> ToolConstraint:
    return ToolConstraint(
        max_calls=raw.get("max_calls"),
        deny_patterns=raw.get("deny_patterns") or [],
    )


def _parse_tool_policy(raw: Dict[str, Any]) -> ToolPolicy:
    constraints_raw = raw.get("constraints") or {}
    constraints = {
        name: _parse_tool_constraint(spec)
        for name, spec in constraints_raw.items()
        if isinstance(spec, dict)
    }
    return ToolPolicy(
        default=str(raw.get("default", "allow")),
        allow=raw.get("allow") or [],
        deny=raw.get("deny") or [],
        constraints=constraints,
    )


def _parse_budget(raw: Dict[str, Any]) -> BudgetPolicy:
    return BudgetPolicy(
        max_tool_calls=raw.get("max_tool_calls"),
        max_wall_time_sec=raw.get("max_wall_time_sec"),
    )


def load_policy(path: Path) -> MCPPolicy:
    """Load and validate an MCP policy file.

    Raises PolicyLoadError on any problem (missing, invalid YAML, bad schema).
    """
    try:
        import yaml
    except ImportError:
        raise PolicyLoadError(
            "PyYAML is required for MCP policy files: pip install pyyaml"
        )

    if not path.exists():
        raise PolicyLoadError(f"Policy file not found: {path}")
    if not path.is_file():
        raise PolicyLoadError(f"Policy path is not a file: {path}")

    try:
        text = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(text)
    except Exception as exc:
        raise PolicyLoadError(f"Failed to parse policy file: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyLoadError(
            f"Policy file must be a YAML mapping, got {type(raw).__name__}"
        )

    # Parse mode
    mode = str(raw.get("mode", "audit"))
    if mode not in ("audit", "enforce"):
        raise PolicyLoadError(
            f"Invalid mode '{mode}': must be 'audit' or 'enforce'"
        )

    # Parse tools section
    tools_raw = raw.get("tools")
    tools = _parse_tool_policy(tools_raw) if isinstance(tools_raw, dict) else ToolPolicy()

    if tools.default not in ("allow", "deny"):
        raise PolicyLoadError(
            f"Invalid tools.default '{tools.default}': must be 'allow' or 'deny'"
        )

    # Parse budget section
    budget_raw = raw.get("budget")
    budget = _parse_budget(budget_raw) if isinstance(budget_raw, dict) else BudgetPolicy()

    source_hash = _compute_file_hash(path)

    return MCPPolicy(
        version=str(raw.get("version", "1")),
        server_id=str(raw.get("server_id", "")),
        mode=mode,
        store_args=bool(raw.get("store_args", False)),
        store_results=bool(raw.get("store_results", False)),
        auto_pack=bool(raw.get("auto_pack", True)),
        audit_dir=str(raw.get("audit_dir", ".assay/mcp")),
        tools=tools,
        budget=budget,
        source_path=str(path),
        source_hash=source_hash,
    )


def compute_policy_hash(path: Path) -> str:
    """Compute deterministic hash of a policy file for receipt embedding."""
    return _compute_file_hash(path)


# ---------------------------------------------------------------------------
# Glob matching
# ---------------------------------------------------------------------------


def _matches_any(tool_name: str, patterns: List[str]) -> Optional[str]:
    """Return the first pattern that matches tool_name, or None.

    Supports fnmatch-style globs: * matches any characters within a name.
    """
    for pattern in patterns:
        if fnmatch.fnmatch(tool_name, pattern):
            return pattern
    return None


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class PolicyEvaluator:
    """Stateful evaluator that tracks per-tool call counts and session budget."""

    def __init__(self, policy: MCPPolicy) -> None:
        self.policy = policy
        self._tool_call_counts: Dict[str, int] = {}
        self._total_calls: int = 0

    @property
    def total_calls(self) -> int:
        return self._total_calls

    def evaluate(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """Evaluate a tool call against the policy.

        Returns a PolicyDecision with verdict and reason.
        Call counts are updated on ALLOW verdicts.
        """
        tools = self.policy.tools

        # 1. Check deny list (checked first, deny wins)
        matched = _matches_any(tool_name, tools.deny)
        if matched is not None:
            return PolicyDecision(
                verdict="deny",
                reason="deny_list",
                detail=f"tool '{tool_name}' matched deny pattern '{matched}'",
            )

        # 2. Check allow list / default
        if tools.default == "deny":
            matched = _matches_any(tool_name, tools.allow)
            if matched is None:
                return PolicyDecision(
                    verdict="deny",
                    reason="not_in_allow",
                    detail=f"tool '{tool_name}' not in allow list (default: deny)",
                )

        # 3. Per-tool constraints
        constraint = tools.constraints.get(tool_name)
        if constraint is not None:
            # max_calls
            if constraint.max_calls is not None:
                count = self._tool_call_counts.get(tool_name, 0)
                if count >= constraint.max_calls:
                    return PolicyDecision(
                        verdict="deny",
                        reason="tool_budget_exceeded",
                        detail=f"tool '{tool_name}' reached max_calls={constraint.max_calls}",
                    )

            # deny_patterns on arguments
            if constraint.deny_patterns and arguments:
                args_str = str(arguments)
                for pattern in constraint.deny_patterns:
                    if re.search(pattern, args_str, re.IGNORECASE):
                        return PolicyDecision(
                            verdict="deny",
                            reason="argument_denied",
                            detail=f"tool '{tool_name}' arguments matched deny pattern '{pattern}'",
                        )

        # 4. Session budget
        budget = self.policy.budget
        if budget.max_tool_calls is not None:
            if self._total_calls >= budget.max_tool_calls:
                return PolicyDecision(
                    verdict="deny",
                    reason="session_budget_exceeded",
                    detail=f"session reached max_tool_calls={budget.max_tool_calls}",
                )

        # 5. ALLOW -- update counters
        self._tool_call_counts[tool_name] = self._tool_call_counts.get(tool_name, 0) + 1
        self._total_calls += 1

        return PolicyDecision(verdict="allow")
