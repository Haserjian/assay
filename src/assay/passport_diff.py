"""Diff two Assay passports.

Compares claims, coverage, reliance class, scope, and lifecycle state
between two passports. Passport A is baseline, Passport B is current.

Exit codes:
  0  No regression
  1  Regression detected (claims regressed, coverage dropped, reliance downgraded)
  2  Integrity failure (signature invalid or passport tampered)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class PassportClaimDelta:
    """Change in a single claim between two passports."""

    claim_id: str
    a_result: Optional[str] = None  # pass | fail | partial | present | None (absent)
    b_result: Optional[str] = None
    status: str = "unchanged"  # new | removed | improved | regressed | unchanged

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "a_result": self.a_result,
            "b_result": self.b_result,
            "status": self.status,
        }


@dataclass
class CoverageDelta:
    """Change in coverage between two passports."""

    a_covered: int = 0
    a_total: int = 0
    b_covered: int = 0
    b_total: int = 0
    added_sites: List[str] = field(default_factory=list)
    removed_sites: List[str] = field(default_factory=list)
    status: str = "unchanged"  # improved | regressed | unchanged

    def to_dict(self) -> Dict[str, Any]:
        return {
            "a_covered": self.a_covered,
            "a_total": self.a_total,
            "b_covered": self.b_covered,
            "b_total": self.b_total,
            "a_pct": round(self.a_covered / self.a_total * 100) if self.a_total else 0,
            "b_pct": round(self.b_covered / self.b_total * 100) if self.b_total else 0,
            "added_sites": self.added_sites,
            "removed_sites": self.removed_sites,
            "status": self.status,
        }


@dataclass
class PassportDiffResult:
    """Full diff between two passports."""

    passport_a_id: str = ""
    passport_b_id: str = ""

    # State changes
    state_a: str = ""
    state_b: str = ""
    state_changed: bool = False

    # Reliance
    reliance_a: str = ""
    reliance_b: str = ""
    reliance_changed: bool = False

    # Claims
    claim_deltas: List[PassportClaimDelta] = field(default_factory=list)

    # Coverage
    coverage_delta: Optional[CoverageDelta] = None

    # Scope
    scope_changes: Dict[str, Any] = field(default_factory=dict)

    # Verdict
    has_regression: bool = False
    is_supersession: bool = False
    integrity_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passport_a_id": self.passport_a_id,
            "passport_b_id": self.passport_b_id,
            "state_a": self.state_a,
            "state_b": self.state_b,
            "state_changed": self.state_changed,
            "reliance_a": self.reliance_a,
            "reliance_b": self.reliance_b,
            "reliance_changed": self.reliance_changed,
            "claim_deltas": [d.to_dict() for d in self.claim_deltas],
            "coverage_delta": self.coverage_delta.to_dict() if self.coverage_delta else None,
            "scope_changes": self.scope_changes,
            "has_regression": self.has_regression,
            "is_supersession": self.is_supersession,
            "integrity_error": self.integrity_error,
            "exit_code": self.exit_code,
        }

    @property
    def exit_code(self) -> int:
        """0=no regression, 1=regression, 2=integrity failure."""
        if self.integrity_error:
            return 2
        if self.has_regression:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Claim result ordering (for regression detection)
# ---------------------------------------------------------------------------

_RESULT_ORDER = {"pass": 3, "present": 2, "partial": 1, "fail": 0}


def _result_rank(result: Optional[str]) -> int:
    if result is None:
        return -1
    return _RESULT_ORDER.get(result, 0)


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------

def _diff_claims(
    claims_a: List[Dict[str, Any]],
    claims_b: List[Dict[str, Any]],
) -> tuple[List[PassportClaimDelta], bool]:
    """Compare claims between two passports. Returns (deltas, has_regression)."""
    a_map = {c["claim_id"]: c.get("result") for c in claims_a if "claim_id" in c}
    b_map = {c["claim_id"]: c.get("result") for c in claims_b if "claim_id" in c}

    all_ids = sorted(set(a_map.keys()) | set(b_map.keys()))
    deltas: List[PassportClaimDelta] = []
    has_regression = False

    for cid in all_ids:
        a_result = a_map.get(cid)
        b_result = b_map.get(cid)

        if a_result is None:
            status = "new"
        elif b_result is None:
            status = "removed"
            has_regression = True  # removing a claim is a regression
        elif _result_rank(b_result) < _result_rank(a_result):
            status = "regressed"
            has_regression = True
        elif _result_rank(b_result) > _result_rank(a_result):
            status = "improved"
        else:
            status = "unchanged"

        deltas.append(PassportClaimDelta(
            claim_id=cid,
            a_result=a_result,
            b_result=b_result,
            status=status,
        ))

    return deltas, has_regression


def _diff_coverage(
    cov_a: Dict[str, Any],
    cov_b: Dict[str, Any],
) -> CoverageDelta:
    """Compare coverage between two passports."""
    a_covered = cov_a.get("covered_total", 0)
    a_total = cov_a.get("identified_total", 0)
    b_covered = cov_b.get("covered_total", 0)
    b_total = cov_b.get("identified_total", 0)

    # Find added/removed call sites
    a_sites = {s.get("call_site_id", "") for s in cov_a.get("call_sites", [])}
    b_sites = {s.get("call_site_id", "") for s in cov_b.get("call_sites", [])}
    added = sorted(b_sites - a_sites)
    removed = sorted(a_sites - b_sites)

    a_pct = (a_covered / a_total * 100) if a_total else 0
    b_pct = (b_covered / b_total * 100) if b_total else 0

    if b_pct > a_pct:
        status = "improved"
    elif b_pct < a_pct:
        status = "regressed"
    else:
        status = "unchanged"

    return CoverageDelta(
        a_covered=a_covered,
        a_total=a_total,
        b_covered=b_covered,
        b_total=b_total,
        added_sites=added,
        removed_sites=removed,
        status=status,
    )


def _diff_scope(
    scope_a: Dict[str, Any],
    scope_b: Dict[str, Any],
) -> Dict[str, Any]:
    """Compare scope declarations."""
    changes: Dict[str, Any] = {}
    for key in ("in_scope", "not_covered", "not_observed", "not_concluded"):
        a_items = set(scope_a.get(key, []))
        b_items = set(scope_b.get(key, []))
        added = sorted(b_items - a_items)
        removed = sorted(a_items - b_items)
        if added or removed:
            changes[key] = {"added": added, "removed": removed}
    return changes


# ---------------------------------------------------------------------------
# Reliance class ordering
# ---------------------------------------------------------------------------

_RELIANCE_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def diff_passports(
    a: Path,
    b: Path,
    *,
    verify: bool = False,
    keystore: Optional[Any] = None,
) -> PassportDiffResult:
    """Diff two passports.

    Args:
        a: Path to baseline passport JSON.
        b: Path to current passport JSON.
        verify: If True, verify signatures before diffing.
        keystore: Optional keystore for verification.

    Returns:
        PassportDiffResult with claim deltas, coverage delta, and verdict.
    """
    result = PassportDiffResult()

    # Load passports
    try:
        passport_a = json.loads(Path(a).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.integrity_error = f"Cannot read passport A: {exc}"
        return result

    try:
        passport_b = json.loads(Path(b).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.integrity_error = f"Cannot read passport B: {exc}"
        return result

    # Optional signature verification
    if verify:
        from assay.passport_sign import verify_passport_signature
        vr_a = verify_passport_signature(Path(a), keystore=keystore)
        vr_b = verify_passport_signature(Path(b), keystore=keystore)
        if not vr_a.get("signature_valid", False) and passport_a.get("signature"):
            result.integrity_error = f"Passport A signature invalid: {vr_a.get('error', '')}"
            return result
        if not vr_b.get("signature_valid", False) and passport_b.get("signature"):
            result.integrity_error = f"Passport B signature invalid: {vr_b.get('error', '')}"
            return result

    # IDs
    result.passport_a_id = passport_a.get("passport_id", "")
    result.passport_b_id = passport_b.get("passport_id", "")

    # State
    result.state_a = passport_a.get("status", {}).get("state", "")
    result.state_b = passport_b.get("status", {}).get("state", "")
    result.state_changed = result.state_a != result.state_b

    # Reliance
    result.reliance_a = passport_a.get("reliance", {}).get("class", "")
    result.reliance_b = passport_b.get("reliance", {}).get("class", "")
    result.reliance_changed = result.reliance_a != result.reliance_b

    # Claims
    claims_a = passport_a.get("claims", [])
    claims_b = passport_b.get("claims", [])
    claim_deltas, claims_regressed = _diff_claims(claims_a, claims_b)
    result.claim_deltas = claim_deltas

    # Coverage
    cov_a = passport_a.get("coverage", {})
    cov_b = passport_b.get("coverage", {})
    if cov_a or cov_b:
        result.coverage_delta = _diff_coverage(cov_a, cov_b)

    # Scope
    scope_a = passport_a.get("scope", {})
    scope_b = passport_b.get("scope", {})
    result.scope_changes = _diff_scope(scope_a, scope_b)

    # Supersession detection
    rel_b = passport_b.get("relationships", {})
    if rel_b.get("supersedes") == result.passport_a_id:
        result.is_supersession = True

    # Regression detection
    reliance_regressed = (
        _RELIANCE_ORDER.get(result.reliance_b, 0)
        < _RELIANCE_ORDER.get(result.reliance_a, 0)
    )
    coverage_regressed = (
        result.coverage_delta is not None
        and result.coverage_delta.status == "regressed"
    )
    result.has_regression = claims_regressed or reliance_regressed or coverage_regressed

    return result
