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
from typing import Any, Callable, Dict, List

from assay._receipts.canonicalize import to_jcs_bytes

ALLOWED_SEVERITIES = {"critical", "warning"}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ClaimSpec:
    """A single claim to verify against receipts."""

    claim_id: str
    description: str
    check: str  # name of a function in CHECKS
    params: Dict[str, Any] = field(default_factory=dict)
    severity: str = "critical"  # "critical" | "warning"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "description": self.description,
            "check": self.check,
            "params": self.params,
            "severity": self.severity,
        }


@dataclass
class ClaimResult:
    """Result of verifying a single claim."""

    claim_id: str
    passed: bool
    expected: str
    actual: str
    severity: str = "critical"
    evidence_receipt_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "severity": self.severity,
            "evidence_receipt_ids": self.evidence_receipt_ids,
        }


@dataclass
class ClaimSetResult:
    """Aggregate result of verifying all claims in a set."""

    passed: bool  # all critical claims pass
    results: List[ClaimResult] = field(default_factory=list)
    discrepancy_fingerprint: str = ""
    n_claims: int = 0
    n_passed: int = 0
    n_failed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "n_claims": self.n_claims,
            "n_passed": self.n_passed,
            "n_failed": self.n_failed,
            "discrepancy_fingerprint": self.discrepancy_fingerprint,
            "results": [r.to_dict() for r in self.results],
        }


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
) -> ClaimSetResult:
    """Evaluate all claims against a receipt pack.

    Returns ClaimSetResult with deterministic discrepancy_fingerprint.
    Critical claims determine the overall pass/fail; warnings are recorded
    but don't fail the set.
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
        results.append(result)

    n_passed = sum(1 for r in results if r.passed)
    n_failed = sum(1 for r in results if not r.passed)

    # Overall pass: all critical claims pass (warnings don't count)
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
    )


__all__ = [
    "ClaimSpec",
    "ClaimResult",
    "ClaimSetResult",
    "verify_claims",
    "CHECKS",
    "check_receipt_type_present",
    "check_no_receipt_type",
    "check_receipt_count_ge",
    "check_timestamps_monotonic",
    "check_field_value_matches",
]
