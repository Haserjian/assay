"""
Semantic Claim Verifier for Assay Proof Packs.

Separated from core_integrity_verifier by design:
  - Integrity verifier: "was the evidence tampered with?" (structural)
  - Claim verifier: "does the evidence prove what you claim?" (semantic)

A claim is an assertion about AI system behavior.  A claim set is a
collection of claims that should all hold.  The verifier evaluates each
claim against a receipt pack and produces a ClaimSetResult with a
deterministic discrepancy_fingerprint.

Built-in check functions cover common patterns.  Custom checks can be
registered via CHECKS dict.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from assay._receipts.canonicalize import to_jcs_bytes

ALLOWED_SEVERITIES = {"critical", "warning"}

FALSIFIER_STATUSES = {
    "not_required",       # warning-severity claim or falsifiers not enforced
    "absent",             # critical claim with no falsifier named
    "named",              # falsifier described but not yet executed
    "executed_passed",    # falsifier was run and claim survived disproof
    "executed_failed",    # falsifier was run and claim was disproved
}

# Tier cap decision table.
# Maps (severity, falsifier_status) -> (cap_applies, cap_reason).
# This table is the single source of truth for tier cap semantics.
TIER_CAP_TABLE = {
    # Warning claims: never capped regardless of falsifier state
    ("warning", "not_required"):    (False, None),
    ("warning", "absent"):          (False, None),
    ("warning", "named"):           (False, None),
    ("warning", "executed_passed"): (False, None),
    ("warning", "executed_failed"): (False, None),
    # Critical claims: cap depends on falsifier posture
    ("critical", "not_required"):    (False, None),  # enforcement not active
    ("critical", "absent"):          (True,  "capped: no named falsifier"),
    ("critical", "named"):           (True,  "capped: falsifier named but not executed"),
    ("critical", "executed_passed"): (False, None),   # full proof eligible
    ("critical", "executed_failed"): (True,  "capped: falsifier execution disproved claim"),
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FalsifierSpec:
    """Cheapest test that would disprove a claim.

    A falsifier answers: "what would most cheaply prove this claim wrong?"
    Claims without a named falsifier cannot exceed a capped proof tier.
    """

    description: str
    test_command: Optional[str] = None
    evaluation_surface: str = ""
    executed: Optional[bool] = None   # None=not run, True=passed, False=disproved

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"description": self.description}
        if self.test_command:
            d["test_command"] = self.test_command
        if self.evaluation_surface:
            d["evaluation_surface"] = self.evaluation_surface
        if self.executed is not None:
            d["executed"] = self.executed
        return d


@dataclass
class ClaimSpec:
    """A single claim to verify against receipts."""

    claim_id: str
    description: str
    check: str  # name of a function in CHECKS
    params: Dict[str, Any] = field(default_factory=dict)
    severity: str = "critical"  # "critical" | "warning"
    falsifier: Optional[FalsifierSpec] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "claim_id": self.claim_id,
            "description": self.description,
            "check": self.check,
            "params": self.params,
            "severity": self.severity,
        }
        if self.falsifier is not None:
            d["falsifier"] = self.falsifier.to_dict()
        return d


@dataclass
class ClaimResult:
    """Result of verifying a single claim."""

    claim_id: str
    passed: bool
    expected: str
    actual: str
    severity: str = "critical"
    evidence_receipt_ids: List[str] = field(default_factory=list)
    falsifier_status: str = "not_required"
    tier_cap: Optional[str] = None  # None = uncapped; string = cap reason

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "claim_id": self.claim_id,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "severity": self.severity,
            "evidence_receipt_ids": self.evidence_receipt_ids,
            "falsifier_status": self.falsifier_status,
        }
        if self.tier_cap is not None:
            d["tier_cap"] = self.tier_cap
        return d


@dataclass
class ClaimSetResult:
    """Aggregate result of verifying all claims in a set."""

    passed: bool  # all critical claims pass
    results: List[ClaimResult] = field(default_factory=list)
    discrepancy_fingerprint: str = ""
    n_claims: int = 0
    n_passed: int = 0
    n_failed: int = 0
    n_capped: int = 0
    falsifier_summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "passed": self.passed,
            "n_claims": self.n_claims,
            "n_passed": self.n_passed,
            "n_failed": self.n_failed,
            "discrepancy_fingerprint": self.discrepancy_fingerprint,
            "results": [r.to_dict() for r in self.results],
        }
        if self.n_capped > 0:
            d["n_capped"] = self.n_capped
            d["falsifier_summary"] = self.falsifier_summary
        return d


# ---------------------------------------------------------------------------
# Built-in check functions
#
# Each takes (receipts, **params) and returns a ClaimResult.
# The claim_id is injected by verify_claims.
# ---------------------------------------------------------------------------

def check_receipt_type_present(
    receipts: List[Dict[str, Any]], *, claim_id: str, receipt_type: str, **_: Any
) -> ClaimResult:
    """At least one receipt of the given type exists."""
    matching = [r for r in receipts if r.get("type") == receipt_type]
    return ClaimResult(
        claim_id=claim_id,
        passed=len(matching) > 0,
        expected=f"at least 1 receipt of type '{receipt_type}'",
        actual=f"found {len(matching)}",
        evidence_receipt_ids=[r.get("receipt_id", "") for r in matching[:5]],
    )


def check_no_receipt_type(
    receipts: List[Dict[str, Any]], *, claim_id: str, receipt_type: str, **_: Any
) -> ClaimResult:
    """No receipts of the given type exist."""
    matching = [r for r in receipts if r.get("type") == receipt_type]
    return ClaimResult(
        claim_id=claim_id,
        passed=len(matching) == 0,
        expected=f"0 receipts of type '{receipt_type}'",
        actual=f"found {len(matching)}",
        evidence_receipt_ids=[r.get("receipt_id", "") for r in matching[:5]],
    )


def check_receipt_count_ge(
    receipts: List[Dict[str, Any]], *, claim_id: str, min_count: int, **_: Any
) -> ClaimResult:
    """Receipt count is at least min_count."""
    return ClaimResult(
        claim_id=claim_id,
        passed=len(receipts) >= min_count,
        expected=f">= {min_count} receipts",
        actual=f"{len(receipts)} receipts",
    )


def check_timestamps_monotonic(
    receipts: List[Dict[str, Any]], *, claim_id: str, **_: Any
) -> ClaimResult:
    """Timestamps are non-decreasing across the receipt sequence."""
    timestamps: List[str] = []
    for r in receipts:
        ts = r.get("timestamp")
        if ts:
            timestamps.append(str(ts))

    monotonic = all(
        timestamps[i] <= timestamps[i + 1]
        for i in range(len(timestamps) - 1)
    )

    violating: List[str] = []
    if not monotonic:
        for i in range(len(timestamps) - 1):
            if timestamps[i] > timestamps[i + 1]:
                rid = receipts[i + 1].get("receipt_id", f"index_{i+1}")
                violating.append(rid)

    return ClaimResult(
        claim_id=claim_id,
        passed=monotonic,
        expected="timestamps non-decreasing",
        actual="monotonic" if monotonic else f"{len(violating)} violations",
        evidence_receipt_ids=violating[:5],
    )


def check_field_value_matches(
    receipts: List[Dict[str, Any]],
    *,
    claim_id: str,
    receipt_type: str,
    field_name: str,
    expected_value: Any,
    **_: Any,
) -> ClaimResult:
    """All receipts of given type have field == expected_value."""
    matching = [r for r in receipts if r.get("type") == receipt_type]
    if not matching:
        return ClaimResult(
            claim_id=claim_id,
            passed=False,
            expected=f"receipts of type '{receipt_type}' with {field_name}={expected_value!r}",
            actual="no receipts of that type found",
        )

    mismatches = [
        r for r in matching
        if r.get(field_name) != expected_value
    ]
    return ClaimResult(
        claim_id=claim_id,
        passed=len(mismatches) == 0,
        expected=f"all '{receipt_type}' receipts: {field_name}={expected_value!r}",
        actual=f"{len(mismatches)} mismatches out of {len(matching)}",
        evidence_receipt_ids=[r.get("receipt_id", "") for r in mismatches[:5]],
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

CheckFn = Callable[..., ClaimResult]

def check_coverage_contract(
    receipts: List[Dict[str, Any]],
    *,
    claim_id: str,
    contract_path: str = "assay.coverage.json",
    min_coverage: float = 0.8,
    **_: Any,
) -> ClaimResult:
    """Verify that receipts cover at least min_coverage of the call sites
    declared in the coverage contract.
    """
    import json as _json
    from pathlib import Path

    try:
        from assay.coverage import CoverageContract, verify_coverage
        contract = CoverageContract.load(Path(contract_path))
    except FileNotFoundError:
        return ClaimResult(
            claim_id=claim_id,
            passed=False,
            expected=f"valid coverage contract at {contract_path}",
            actual=f"file not found: {contract_path}",
        )
    except (_json.JSONDecodeError, ValueError, KeyError) as e:
        return ClaimResult(
            claim_id=claim_id,
            passed=False,
            expected=f"valid coverage contract at {contract_path}",
            actual=f"error: {e}",
        )

    result = verify_coverage(contract, receipts)
    pct = result["coverage_pct"]

    return ClaimResult(
        claim_id=claim_id,
        passed=pct >= min_coverage,
        expected=f">= {min_coverage:.0%} call site coverage",
        actual=f"{pct:.0%} ({result['covered_count']}/{result['total_count']})",
        evidence_receipt_ids=result["covered_ids"][:5],
    )


CHECKS: Dict[str, CheckFn] = {
    "receipt_type_present": check_receipt_type_present,
    "no_receipt_type": check_no_receipt_type,
    "receipt_count_ge": check_receipt_count_ge,
    "timestamps_monotonic": check_timestamps_monotonic,
    "field_value_matches": check_field_value_matches,
    "coverage_contract": check_coverage_contract,
}


# ---------------------------------------------------------------------------
# Core verifier
# ---------------------------------------------------------------------------

def _compute_discrepancy_fingerprint(
    results: List[ClaimResult],
    *,
    policy_hash: str = "",
    suite_hash: str = "",
) -> str:
    """Deterministic fingerprint of claim outcomes via JCS canonical hash.

    Fingerprint v1: includes policy_hash and suite_hash so identical claim
    results under different policies produce different fingerprints.
    """
    # Sort by claim_id for determinism, include only outcome-relevant fields
    canonical_obj = {
        "policy_hash": policy_hash,
        "suite_hash": suite_hash,
        "results": sorted(
            [
                {
                    "claim_id": r.claim_id,
                    "passed": r.passed,
                    "expected": r.expected,
                    "actual": r.actual,
                    "severity": r.severity,
                }
                for r in results
            ],
            key=lambda x: x["claim_id"],
        ),
    }
    canonical_bytes = to_jcs_bytes(canonical_obj)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_claims(
    receipts: List[Dict[str, Any]],
    claims: List[ClaimSpec],
    *,
    policy_hash: str = "",
    suite_hash: str = "",
    require_falsifiers: bool = False,
) -> ClaimSetResult:
    """Evaluate all claims against a receipt pack.

    Returns ClaimSetResult with deterministic discrepancy_fingerprint.
    Critical claims determine the overall pass/fail; warnings are recorded
    but don't fail the set.

    When require_falsifiers is True, critical claims without a named
    falsifier are tier-capped (they still pass/fail normally, but carry
    a cap annotation indicating the claim cannot reach strong proof status).
    """
    results: List[ClaimResult] = []

    for claim in claims:
        severity = str(claim.severity).lower()
        if severity not in ALLOWED_SEVERITIES:
            # Fail closed on unknown severities; never silently downgrade claim impact.
            results.append(ClaimResult(
                claim_id=claim.claim_id,
                passed=False,
                expected="severity in {'critical','warning'}",
                actual=f"invalid severity '{claim.severity}'",
                severity="critical",
            ))
            continue

        check_fn = CHECKS.get(claim.check)
        if check_fn is None:
            # Unknown check function -> automatic fail
            results.append(ClaimResult(
                claim_id=claim.claim_id,
                passed=False,
                expected=f"check function '{claim.check}' exists",
                actual="unknown check function",
                severity=severity,
            ))
            continue

        result = check_fn(receipts, claim_id=claim.claim_id, **claim.params)
        result.severity = severity

        # Falsifier assessment: tier-aware enforcement via TIER_CAP_TABLE.
        # Warning-severity claims: falsifier not required.
        # Critical claims: cap depends on falsifier posture.
        if severity == "critical" and require_falsifiers:
            if claim.falsifier is None:
                fs = "absent"
            elif claim.falsifier.executed is True:
                fs = "executed_passed"
            elif claim.falsifier.executed is False:
                fs = "executed_failed"
            else:
                fs = "named"
            result.falsifier_status = fs
            cap_applies, cap_reason = TIER_CAP_TABLE.get(
                (severity, fs), (False, None)
            )
            if cap_applies:
                result.tier_cap = cap_reason
        elif severity == "critical" and claim.falsifier is not None:
            # Falsifiers not enforced, but one is present -- record it
            if claim.falsifier.executed is True:
                result.falsifier_status = "executed_passed"
            elif claim.falsifier.executed is False:
                result.falsifier_status = "executed_failed"
            else:
                result.falsifier_status = "named"
        else:
            result.falsifier_status = "not_required"

        results.append(result)

    n_passed = sum(1 for r in results if r.passed)
    n_failed = sum(1 for r in results if not r.passed)
    n_capped = sum(1 for r in results if r.tier_cap is not None)

    # Falsifier summary: count by status
    falsifier_counts: Dict[str, int] = {}
    for r in results:
        falsifier_counts[r.falsifier_status] = falsifier_counts.get(r.falsifier_status, 0) + 1

    # Overall pass: all critical claims pass (warnings don't count).
    # Tier caps do NOT cause failure -- they are informational constraints
    # on how strongly the claim can be relied upon.
    critical_failures = [
        r for r in results
        if not r.passed and r.severity == "critical"
    ]
    overall_passed = len(critical_failures) == 0

    fingerprint = _compute_discrepancy_fingerprint(
        results, policy_hash=policy_hash, suite_hash=suite_hash,
    )

    return ClaimSetResult(
        passed=overall_passed,
        results=results,
        discrepancy_fingerprint=fingerprint,
        n_claims=len(results),
        n_passed=n_passed,
        n_failed=n_failed,
        n_capped=n_capped,
        falsifier_summary=falsifier_counts,
    )


__all__ = [
    "FalsifierSpec",
    "ClaimSpec",
    "ClaimResult",
    "ClaimSetResult",
    "verify_claims",
    "CHECKS",
    "ALLOWED_SEVERITIES",
    "FALSIFIER_STATUSES",
    "TIER_CAP_TABLE",
    "check_receipt_type_present",
    "check_no_receipt_type",
    "check_receipt_count_ge",
    "check_timestamps_monotonic",
    "check_field_value_matches",
]
