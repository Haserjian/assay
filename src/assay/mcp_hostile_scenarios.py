"""Shared vocabulary for MCP hostile scenario tests.

Each hostile scenario produces a two-axis verdict:

  EnforcementVerdict — what the enforcement layer did
    CAUGHT           — blocked before reaching the server
    ALLOWED_BY_POLICY — explicitly permitted by a configured policy rule
    GAP              — no current control prevents this; documented absence

  EvidenceVerdict — what the audit trail can claim
    ATTRIBUTABLE     — full provenance available (tool name, arguments hash,
                       invocation ID); any observer can reconstruct the chain
    PARTIAL          — some provenance exists but the causal chain is incomplete
    NONE             — no audit trail; the action is forensically invisible

These are separate axes. A call can be:
  GAP + ATTRIBUTABLE: allowed (no defense) but traceable
  CAUGHT + ATTRIBUTABLE: denied and receipt records why
  GAP + NONE: the worst case; no defense and no trail

Both verdicts are required to fully characterize a hostile scenario.
Neither alone is sufficient.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class EnforcementVerdict(str, Enum):
    CAUGHT = "caught"
    ALLOWED_BY_POLICY = "allowed_by_policy"
    GAP = "gap"


class EvidenceVerdict(str, Enum):
    ATTRIBUTABLE = "attributable"
    PARTIAL = "partial"
    NONE = "none"


# ---------------------------------------------------------------------------
# Typed case schema
# ---------------------------------------------------------------------------

@dataclass
class HostileScenarioCase:
    """One case from docs/hostile_scenarios/manifest.yaml, parsed and typed."""
    id: str
    name: str
    linked_test: str            # name of the test class that covers this case
    boundary_under_test: str    # one-sentence constitutional claim
    can_claim: List[str]        # what can be asserted after this scenario runs
    cannot_claim: List[str]     # what must not be asserted (overclaim guard)
    evidence_verdict: str       # EvidenceVerdict value (upper-case from YAML)

    # Enforcement: either a single verdict or split by policy presence
    enforcement_verdict: Optional[str] = None
    enforcement_verdict_with_policy: Optional[str] = None
    enforcement_verdict_without_policy: Optional[str] = None

    # Optional fields
    attacker_goal: str = ""
    attack_vector: str = ""
    enforcement_note: str = ""
    evidence_note: str = ""
    policy_dependency: str = ""
    known_gap_tracker: str = ""
    target_version: str = ""


class ManifestLoadError(ValueError):
    """Raised when the manifest cannot be parsed or is missing required fields."""


def load_hostile_scenario_manifest(path: Path) -> List[HostileScenarioCase]:
    """Parse docs/hostile_scenarios/manifest.yaml into typed HostileScenarioCase objects.

    Raises ManifestLoadError for missing required fields or bad YAML.
    """
    try:
        import yaml
    except ImportError:
        raise ManifestLoadError("PyYAML required: pip install pyyaml")

    if not path.exists():
        raise ManifestLoadError(f"Manifest not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ManifestLoadError(f"Failed to parse manifest: {exc}") from exc

    if not isinstance(raw, dict) or "cases" not in raw:
        raise ManifestLoadError("Manifest must be a YAML mapping with a 'cases' list")

    cases = []
    for entry in raw["cases"]:
        missing = [f for f in ("id", "name", "linked_test", "boundary_under_test",
                               "can_claim", "cannot_claim", "evidence_verdict")
                   if not entry.get(f)]
        if missing:
            raise ManifestLoadError(
                f"Case {entry.get('id', '?')} missing required fields: {missing}"
            )
        cases.append(HostileScenarioCase(
            id=entry["id"],
            name=entry["name"],
            linked_test=entry["linked_test"],
            boundary_under_test=str(entry["boundary_under_test"]).strip(),
            can_claim=list(entry["can_claim"]),
            cannot_claim=list(entry["cannot_claim"]),
            evidence_verdict=str(entry["evidence_verdict"]).upper(),
            enforcement_verdict=str(entry["enforcement_verdict"]).upper()
                if "enforcement_verdict" in entry else None,
            enforcement_verdict_with_policy=str(entry["enforcement_verdict_with_policy"]).upper()
                if "enforcement_verdict_with_policy" in entry else None,
            enforcement_verdict_without_policy=str(entry["enforcement_verdict_without_policy"]).upper()
                if "enforcement_verdict_without_policy" in entry else None,
            attacker_goal=str(entry.get("attacker_goal", "")).strip(),
            attack_vector=str(entry.get("attack_vector", "")).strip(),
            enforcement_note=str(entry.get("enforcement_note", "")).strip(),
            evidence_note=str(entry.get("evidence_note", "")).strip(),
            policy_dependency=str(entry.get("policy_dependency", "")).strip(),
            known_gap_tracker=str(entry.get("known_gap_tracker", "")).strip(),
            target_version=str(entry.get("target_version", "")).strip(),
        ))
    return cases
