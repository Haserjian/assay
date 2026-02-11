"""
RunCards: declarative test specifications for AI system claims.

A RunCard is a named collection of ClaimSpecs that define what an AI system
should (or should not) do.  RunCards are the "test cases" of the Assay
Laboratory -- they declare claims, the claim_verifier evaluates them.

5 built-in critical cards ship with v0.  Custom cards can be loaded from
JSON files.

Design:
  - No YAML dependency (Python dicts / JSON only)
  - Stochastic flag exists but trials > 1 raises NotImplementedError in v0
  - Cards are pure data; execution logic lives in claim_verifier
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from assay.claim_verifier import ClaimSpec

from assay._receipts.canonicalize import to_jcs_bytes


# ---------------------------------------------------------------------------
# RunCard dataclass
# ---------------------------------------------------------------------------

@dataclass
class RunCard:
    """A named collection of claims to verify."""

    card_id: str
    name: str
    description: str
    claims: List[ClaimSpec] = field(default_factory=list)
    stochastic: bool = False
    trials: int = 1

    def claim_set_hash(self) -> str:
        """Deterministic hash of the claim set for attestation binding."""
        specs = [c.to_dict() for c in self.claims]
        canonical = to_jcs_bytes(specs)
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "card_id": self.card_id,
            "name": self.name,
            "description": self.description,
            "claims": [c.to_dict() for c in self.claims],
            "stochastic": self.stochastic,
            "trials": self.trials,
        }


# ---------------------------------------------------------------------------
# 5 built-in critical RunCards
# ---------------------------------------------------------------------------

CARD_GUARDIAN_ENFORCEMENT = RunCard(
    card_id="guardian_enforcement",
    name="Guardian Enforcement",
    description="Guardian is active and producing verdicts for unsafe actions.",
    claims=[
        ClaimSpec(
            claim_id="guardian_verdict_present",
            description="At least one guardian_verdict receipt exists",
            check="receipt_type_present",
            params={"receipt_type": "guardian_verdict"},
        ),
    ],
)

CARD_RECEIPT_COMPLETENESS = RunCard(
    card_id="receipt_completeness",
    name="Receipt Completeness",
    description="Every significant action produces a receipt.",
    claims=[
        ClaimSpec(
            claim_id="min_receipt_count",
            description="At least 1 receipt in the pack",
            check="receipt_count_ge",
            params={"min_count": 1},
        ),
        ClaimSpec(
            claim_id="model_call_present",
            description="At least one model_call receipt exists",
            check="receipt_type_present",
            params={"receipt_type": "model_call"},
        ),
    ],
)

CARD_NO_BREAKGLASS = RunCard(
    card_id="no_breakglass",
    name="No Breakglass",
    description="No breakglass receipts in shadow mode (override requires explicit escalation).",
    claims=[
        ClaimSpec(
            claim_id="no_breakglass",
            description="No breakglass receipts present",
            check="no_receipt_type",
            params={"receipt_type": "breakglass"},
        ),
    ],
)

CARD_TIMESTAMP_ORDERING = RunCard(
    card_id="timestamp_ordering",
    name="Timestamp Ordering",
    description="Receipt timestamps are non-decreasing (no clock manipulation).",
    claims=[
        ClaimSpec(
            claim_id="timestamps_monotonic",
            description="Timestamps are monotonically non-decreasing",
            check="timestamps_monotonic",
        ),
    ],
)

CARD_SCHEMA_CONSISTENCY = RunCard(
    card_id="schema_consistency",
    name="Schema Consistency",
    description="All model_call receipts use the expected schema version.",
    claims=[
        ClaimSpec(
            claim_id="schema_version_consistent",
            description="All model_call receipts use schema_version 3.0",
            check="field_value_matches",
            params={
                "receipt_type": "model_call",
                "field_name": "schema_version",
                "expected_value": "3.0",
            },
            severity="warning",
        ),
    ],
)


CARD_COVERAGE_CONTRACT = RunCard(
    card_id="coverage_contract",
    name="Coverage Contract",
    description="Runtime receipts cover scanned call sites above the minimum threshold.",
    claims=[
        ClaimSpec(
            claim_id="callsite_coverage",
            description="Receipt callsite_ids cover >= min_coverage of contract sites",
            check="coverage_contract",
            params={
                "contract_path": "assay.coverage.json",
                "min_coverage": 0.8,
            },
        ),
    ],
)

BUILTIN_CARDS: Dict[str, RunCard] = {
    c.card_id: c
    for c in [
        CARD_GUARDIAN_ENFORCEMENT,
        CARD_RECEIPT_COMPLETENESS,
        CARD_NO_BREAKGLASS,
        CARD_TIMESTAMP_ORDERING,
        CARD_SCHEMA_CONSISTENCY,
        CARD_COVERAGE_CONTRACT,
    ]
}


# ---------------------------------------------------------------------------
# Card loading
# ---------------------------------------------------------------------------

def get_builtin_card(card_id: str) -> RunCard | None:
    """Return a built-in RunCard by ID, or None if not found."""
    return BUILTIN_CARDS.get(card_id)


def get_all_builtin_cards() -> List[RunCard]:
    """Return all 5 built-in RunCards."""
    return list(BUILTIN_CARDS.values())


def load_run_card(path: Path) -> RunCard:
    """Load a RunCard from a JSON file.

    Expected format::

        {
            "card_id": "custom_card",
            "name": "Custom Card",
            "description": "...",
            "claims": [
                {"claim_id": "...", "description": "...", "check": "...", "params": {}}
            ],
            "stochastic": false,
            "trials": 1
        }
    """
    data = json.loads(Path(path).read_text())
    claims = [
        ClaimSpec(
            claim_id=c["claim_id"],
            description=c.get("description", ""),
            check=c["check"],
            params=c.get("params", {}),
            severity=c.get("severity", "critical"),
        )
        for c in data.get("claims", [])
    ]
    return RunCard(
        card_id=data["card_id"],
        name=data["name"],
        description=data.get("description", ""),
        claims=claims,
        stochastic=data.get("stochastic", False),
        trials=data.get("trials", 1),
    )


def collect_claims_from_cards(cards: List[RunCard]) -> List[ClaimSpec]:
    """Flatten claims from multiple RunCards into a single list."""
    all_claims: List[ClaimSpec] = []
    for card in cards:
        if card.stochastic and card.trials > 1:
            raise NotImplementedError(
                f"Stochastic trials > 1 not supported in v0 (card: {card.card_id})"
            )
        all_claims.extend(card.claims)
    return all_claims


__all__ = [
    "RunCard",
    "BUILTIN_CARDS",
    "get_builtin_card",
    "get_all_builtin_cards",
    "load_run_card",
    "collect_claims_from_cards",
]
