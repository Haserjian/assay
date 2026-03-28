"""Comparability contract: defines what must match for comparison to be valid.

Contracts are published artifacts. They attach to papers, model cards,
benchmark submissions, dashboards. They are not hidden config.

Contracts are versioned. Changing a contract is a constitutional amendment,
not an edit.

Contracts declare what they do NOT govern. Honest scope prevents false authority.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.comparability.match_rules import available_rules
from assay.comparability.types import (
    FieldRequirement,
    ParityFieldGroup,
    Severity,
)


# ---------------------------------------------------------------------------
# Parity field definition
# ---------------------------------------------------------------------------

@dataclass
class ParityField:
    """A single field that must match for comparison to be valid."""
    field: str
    match_rule: str
    severity: Severity
    group: ParityFieldGroup
    rationale: str
    requirement: FieldRequirement = FieldRequirement.REQUIRED
    rule_params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "field": self.field,
            "match_rule": self.match_rule,
            "severity": self.severity.value,
            "group": self.group.value,
            "rationale": self.rationale,
            "requirement": self.requirement.value,
        }
        if self.rule_params:
            d["rule_params"] = self.rule_params
        return d


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

@dataclass
class ComparabilityContract:
    """Defines what must be true for two evidence bundles to be compared."""

    # Identity
    contract_id: str = ""
    name: str = ""
    version: str = "0.1.0"
    domain: str = ""
    author: str = ""
    created_at: str = ""

    # Scope
    description: str = ""
    metric_family: str = ""

    # Parity fields
    parity_fields: List[ParityField] = field(default_factory=list)

    # Outcome definitions
    outcomes: Dict[str, str] = field(default_factory=dict)

    # Honest scope boundary
    out_of_scope: List[str] = field(default_factory=list)

    def required_field_names(self) -> List[str]:
        """Field names that must be present for contract evaluation."""
        return [
            pf.field for pf in self.parity_fields
            if pf.requirement == FieldRequirement.REQUIRED
        ]

    def fields_by_group(self) -> Dict[ParityFieldGroup, List[ParityField]]:
        """Parity fields grouped by category."""
        groups: Dict[ParityFieldGroup, List[ParityField]] = {}
        for pf in self.parity_fields:
            groups.setdefault(pf.group, []).append(pf)
        return groups

    def instrument_identity_fields(self) -> List[ParityField]:
        """Fields that define the measurement instrument."""
        return [
            pf for pf in self.parity_fields
            if pf.group == ParityFieldGroup.INSTRUMENT_IDENTITY
        ]

    def content_hash(self) -> str:
        """Deterministic fingerprint of the contract's parity fields.

        Covers field names, rules, severities, and groups — the parts
        that affect verdict computation. Metadata (author, created_at)
        is excluded so cosmetic edits don't change the hash.
        """
        import hashlib
        parts = []
        for pf in self.parity_fields:
            parts.append(f"{pf.field}:{pf.match_rule}:{pf.severity.value}:{pf.group.value}:{pf.requirement.value}")
        material = "|".join(sorted(parts))
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "comparability_contract": {
                "version": self.version,
                "id": self.contract_id,
                "name": self.name,
                "domain": self.domain,
                "author": self.author,
                "created_at": self.created_at,
                "scope": {
                    "description": self.description,
                    "metric_family": self.metric_family,
                },
                "parity_fields": [pf.to_dict() for pf in self.parity_fields],
                "outcomes": self.outcomes,
                "out_of_scope": self.out_of_scope,
            }
        }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class ContractValidationError(Exception):
    """Raised when a contract fails validation."""


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError:
        raise ContractValidationError(
            f"Invalid severity: {value!r}. "
            f"Must be one of: {[s.value for s in Severity]}"
        )


def _parse_group(value: str) -> ParityFieldGroup:
    try:
        return ParityFieldGroup(value.lower())
    except ValueError:
        raise ContractValidationError(
            f"Invalid parity field group: {value!r}. "
            f"Must be one of: {[g.value for g in ParityFieldGroup]}"
        )


def _parse_requirement(value: str) -> FieldRequirement:
    try:
        return FieldRequirement(value.upper())
    except ValueError:
        raise ContractValidationError(
            f"Invalid requirement: {value!r}. "
            f"Must be one of: {[r.value for r in FieldRequirement]}"
        )


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load YAML file. Falls back to JSON if PyYAML not available."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            return yaml.safe_load(text)
        except ImportError:
            raise ContractValidationError(
                "PyYAML is required to load YAML contracts. "
                "Install with: pip install pyyaml"
            )
    return json.loads(text)


def load_contract(path: str | Path) -> ComparabilityContract:
    """Load and validate a comparability contract from YAML or JSON.

    Raises ContractValidationError if the contract is malformed.
    """
    path = Path(path)
    if not path.exists():
        raise ContractValidationError(f"Contract file not found: {path}")

    data = _load_yaml(path)

    # Guard empty/null/non-mapping documents
    if data is None:
        raise ContractValidationError(
            f"Contract file is empty or contains only null: {path}"
        )
    if not isinstance(data, dict):
        raise ContractValidationError(
            f"Contract root must be a mapping/object, got {type(data).__name__}: {path}"
        )

    # Accept both wrapped and unwrapped format
    if "comparability_contract" in data:
        data = data["comparability_contract"]
        if not isinstance(data, dict):
            raise ContractValidationError(
                f"'comparability_contract' value must be a mapping, "
                f"got {type(data).__name__}: {path}"
            )

    # Validate required top-level fields
    for required in ("name", "parity_fields"):
        if required not in data:
            raise ContractValidationError(
                f"Contract missing required field: {required!r}"
            )

    # Parse parity fields
    parity_fields: List[ParityField] = []
    known_rules = set(available_rules())
    seen_fields: set[str] = set()

    for i, pf_data in enumerate(data["parity_fields"]):
        if not isinstance(pf_data, dict):
            raise ContractValidationError(
                f"parity_fields[{i}] must be a mapping, got {type(pf_data).__name__}"
            )

        field_name = pf_data.get("field")
        if not field_name:
            raise ContractValidationError(
                f"parity_fields[{i}] missing 'field' name"
            )

        # Reject duplicate field declarations
        if field_name in seen_fields:
            raise ContractValidationError(
                f"parity_fields[{i}]: duplicate field {field_name!r}. "
                f"Each field must appear exactly once in a contract."
            )
        seen_fields.add(field_name)

        rule = pf_data.get("match_rule", "exact")
        if rule not in known_rules:
            raise ContractValidationError(
                f"parity_fields[{i}] ({field_name}): unknown match_rule {rule!r}. "
                f"Available: {sorted(known_rules)}"
            )

        parity_fields.append(ParityField(
            field=field_name,
            match_rule=rule,
            severity=_parse_severity(pf_data.get("severity", "INVALIDATING")),
            group=_parse_group(pf_data.get("group", "instrument_identity")),
            rationale=pf_data.get("rationale", ""),
            requirement=_parse_requirement(pf_data.get("requirement", "REQUIRED")),
            rule_params=pf_data.get("rule_params", {}),
        ))

    # Build contract
    scope = data.get("scope", {})
    if isinstance(scope, str):
        scope = {"description": scope}

    contract = ComparabilityContract(
        contract_id=data.get("id", ""),
        name=data["name"],
        version=data.get("version", "0.1.0"),
        domain=data.get("domain", ""),
        author=data.get("author", ""),
        created_at=data.get("created_at", ""),
        description=scope.get("description", ""),
        metric_family=scope.get("metric_family", ""),
        parity_fields=parity_fields,
        outcomes=data.get("outcomes", {}),
        out_of_scope=data.get("out_of_scope", []),
    )

    return contract
