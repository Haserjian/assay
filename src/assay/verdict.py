"""Verdict computation for Assay Passports.

Separates object validity from reliance verdict. Computes a deterministic
reliance verdict from six orthogonal dimensions plus a policy mode.

See docs/specs/LIFECYCLE_RECEIPT_SPEC_V0_1.md Section B for the full spec.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

FreshnessStatus = Literal["fresh", "stale"]
GovernanceStatus = Literal["none", "challenged", "superseded", "revoked"]
EventIntegrity = Literal["all_valid", "some_invalid", "no_events"]
RelianceVerdict = Literal["PASS", "WARN", "FAIL"]
PolicyMode = Literal["permissive", "buyer-safe", "strict"]


@dataclass
class VerificationDimensions:
    """Six orthogonal verification facts."""

    signature_valid: Optional[bool]  # True/False/None (unsigned)
    schema_valid: bool
    content_hash_valid: Optional[bool]  # True/False/None (no passport_id)
    freshness_status: FreshnessStatus
    governance_status: GovernanceStatus
    event_integrity: EventIntegrity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_valid": self.signature_valid,
            "schema_valid": self.schema_valid,
            "content_hash_valid": self.content_hash_valid,
            "freshness_status": self.freshness_status,
            "governance_status": self.governance_status,
            "event_integrity": self.event_integrity,
        }


@dataclass
class VerdictResult:
    """Reliance verdict with supporting dimensions."""

    verdict: RelianceVerdict
    policy_mode: PolicyMode
    dimensions: VerificationDimensions
    reason: str
    governance_events: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reliance_verdict": self.verdict,
            "policy_mode": self.policy_mode,
            "dimensions": self.dimensions.to_dict(),
            "reason": self.reason,
            "governance_event_count": len(self.governance_events),
        }

    @property
    def exit_code(self) -> int:
        """0=PASS, 1=WARN, 2=FAIL."""
        if self.verdict == "PASS":
            return 0
        if self.verdict == "WARN":
            return 1
        return 2


# ---------------------------------------------------------------------------
# Verdict computation
# ---------------------------------------------------------------------------

def compute_verdict(
    dimensions: VerificationDimensions,
    *,
    policy_mode: PolicyMode = "permissive",
    governance_events: Optional[List[Dict[str, Any]]] = None,
) -> VerdictResult:
    """Compute reliance verdict from dimensions and policy mode.

    Deterministic mapping — first matching rule wins.
    See spec Section B.5 for the full matrix.
    """
    d = dimensions
    events = governance_events or []

    # Row 1: signature invalid → FAIL everywhere
    if d.signature_valid is False:
        return VerdictResult(
            verdict="FAIL",
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport signature is invalid",
            governance_events=events,
        )

    # Row 2: schema invalid → FAIL everywhere
    if not d.schema_valid:
        return VerdictResult(
            verdict="FAIL",
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport schema validation failed",
            governance_events=events,
        )

    # Row 3: content hash invalid → FAIL everywhere
    if d.content_hash_valid is False:
        return VerdictResult(
            verdict="FAIL",
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport content-addressed ID mismatch (possible tampering)",
            governance_events=events,
        )

    # Row 4: revoked → FAIL everywhere
    if d.governance_status == "revoked":
        return VerdictResult(
            verdict="FAIL",
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport has been revoked",
            governance_events=events,
        )

    # Row 5: event integrity issues
    if d.event_integrity == "some_invalid":
        verdict: RelianceVerdict = "FAIL" if policy_mode == "strict" else "WARN"
        return VerdictResult(
            verdict=verdict,
            policy_mode=policy_mode,
            dimensions=d,
            reason="Some lifecycle receipts failed integrity verification",
            governance_events=events,
        )

    # Row 6: superseded
    if d.governance_status == "superseded":
        verdict = "FAIL" if policy_mode == "strict" else "WARN"
        return VerdictResult(
            verdict=verdict,
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport has been superseded by a newer version",
            governance_events=events,
        )

    # Row 7: challenged
    if d.governance_status == "challenged":
        if policy_mode == "permissive":
            verdict = "WARN"
        else:
            verdict = "FAIL"
        return VerdictResult(
            verdict=verdict,
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport is under active challenge",
            governance_events=events,
        )

    # Row 8: stale
    if d.freshness_status == "stale":
        verdict = "WARN" if policy_mode == "permissive" else "FAIL"
        return VerdictResult(
            verdict=verdict,
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport has expired (valid_until passed)",
            governance_events=events,
        )

    # Row 9: unsigned
    if d.signature_valid is None:
        verdict = "FAIL" if policy_mode == "strict" else "WARN"
        return VerdictResult(
            verdict=verdict,
            policy_mode=policy_mode,
            dimensions=d,
            reason="Passport is unsigned",
            governance_events=events,
        )

    # Row 10: all clean → PASS
    return VerdictResult(
        verdict="PASS",
        policy_mode=policy_mode,
        dimensions=d,
        reason="Passport is valid, fresh, and unchallenged",
        governance_events=events,
    )


# ---------------------------------------------------------------------------
# Dimension extraction helpers
# ---------------------------------------------------------------------------

def extract_dimensions(
    passport: Dict[str, Any],
    *,
    signature_result: Optional[Dict[str, Any]] = None,
    governance_status: GovernanceStatus = "none",
    event_integrity: EventIntegrity = "no_events",
    now: Optional[Any] = None,
) -> VerificationDimensions:
    """Extract verification dimensions from a passport and verification results.

    Args:
        passport: Parsed passport dict.
        signature_result: Result from verify_passport_signature().
        governance_status: Computed governance status.
        event_integrity: Computed event integrity.
        now: Override current time.
    """
    from datetime import datetime, timezone as tz

    # Signature
    if signature_result:
        sig_valid = signature_result.get("signature_valid")
        id_valid = signature_result.get("id_valid")
    elif passport.get("signature"):
        sig_valid = None  # present but not verified
        id_valid = None
    else:
        sig_valid = None  # unsigned
        id_valid = None

    # Schema (basic check: required fields present)
    schema_valid = all(
        passport.get(f) is not None
        for f in ("passport_version", "issued_at", "valid_until", "subject", "claims")
    )

    # Freshness
    now_dt = now or datetime.now(tz.utc)
    valid_until = passport.get("valid_until", "")
    try:
        expiry = datetime.fromisoformat(valid_until)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=tz.utc)
        freshness: FreshnessStatus = "stale" if now_dt > expiry else "fresh"
    except (ValueError, TypeError):
        freshness = "fresh"  # no valid_until = assume fresh

    return VerificationDimensions(
        signature_valid=sig_valid,
        schema_valid=schema_valid,
        content_hash_valid=id_valid,
        freshness_status=freshness,
        governance_status=governance_status,
        event_integrity=event_integrity,
    )
