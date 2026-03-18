"""Acceptance matrix: load and evaluate target-specific acceptance rules.

The matrix maps (artifact_class, verification_level, authorization_status)
to a decision (accept/warn/reject) for each policy target.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


VALID_DECISIONS = frozenset({"accept", "warn", "reject"})
VALID_TARGETS = frozenset({"local_verify", "ci_gate", "publication"})


class AcceptanceRule:
    """A single acceptance rule."""

    def __init__(
        self,
        artifact_class: str,
        verification_level: str,
        authorization_status: str,
        target: str,
        decision: str,
        reason: str = "",
    ) -> None:
        self.artifact_class = artifact_class
        self.verification_level = verification_level
        self.authorization_status = authorization_status
        self.target = target
        self.decision = decision
        self.reason = reason


class AcceptanceMatrix:
    """Loaded acceptance policy with query methods."""

    def __init__(self, rules: List[AcceptanceRule]) -> None:
        self._rules = rules

    def evaluate(
        self,
        *,
        artifact_class: str,
        verification_level: str,
        authorization_status: str,
        target: str,
    ) -> tuple[str, str, List[str]]:
        """Evaluate acceptance for a specific target.

        Returns (decision, rationale, reason_codes).
        """
        reason_codes: List[str] = []

        for rule in self._rules:
            if (
                (rule.artifact_class == artifact_class or rule.artifact_class == "*")
                and (rule.verification_level == verification_level or rule.verification_level == "*")
                and (rule.authorization_status == authorization_status or rule.authorization_status == "*")
                and (rule.target == target or rule.target == "*")
            ):
                if rule.decision == "warn":
                    reason_codes.append(rule.reason or "POLICY_DEVIATION")
                return rule.decision, rule.reason, reason_codes

        # Default: conservative reject for unknown combinations
        return "reject", "no matching acceptance rule", ["NO_MATCHING_RULE"]

    def __len__(self) -> int:
        return len(self._rules)


def _parse_rule(raw: Dict[str, Any]) -> AcceptanceRule:
    decision = str(raw.get("decision", "reject"))
    if decision not in VALID_DECISIONS:
        raise ValueError(f"Invalid decision: {decision}")
    return AcceptanceRule(
        artifact_class=str(raw.get("artifact_class", "*")),
        verification_level=str(raw.get("verification_level", "*")),
        authorization_status=str(raw.get("authorization_status", "*")),
        target=str(raw.get("target", "*")),
        decision=decision,
        reason=str(raw.get("reason", "")),
    )


def load_acceptance(path: Path) -> AcceptanceMatrix:
    """Load acceptance matrix from a YAML file."""
    if yaml is None:
        raise ImportError("PyYAML is required to load acceptance matrix")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Acceptance file must be a YAML mapping: {path}")
    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        raise ValueError(f"'rules' must be a list in: {path}")
    rules = [_parse_rule(r) for r in rules_raw]
    return AcceptanceMatrix(rules)
