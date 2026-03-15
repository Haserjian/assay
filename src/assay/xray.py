"""X-Ray diagnostic for Assay passports.

Structural analyzer + grading. Examines a passport for signature status,
freshness, coverage completeness, reliance class, claims quality, evidence
strength, and scope clarity. Produces a grade (A-F) and actionable findings.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.passport_lifecycle import PassportState, compute_passport_state


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class XRayFinding:
    """Single diagnostic finding from passport analysis."""

    category: str      # signature | freshness | coverage | reliance | claims | evidence | scope
    severity: str      # pass | warn | fail | info
    title: str
    detail: str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class XRayResult:
    """Complete X-Ray diagnostic result."""

    passport_path: str
    findings: List[XRayFinding] = field(default_factory=list)
    overall_grade: str = "F"  # A | B | C | D | F
    state: Optional[PassportState] = None
    missing_for_next_grade: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passport_path": self.passport_path,
            "overall_grade": self.overall_grade,
            "state": self.state.to_dict() if self.state else None,
            "findings": [f.to_dict() for f in self.findings],
            "finding_counts": {
                "pass": sum(1 for f in self.findings if f.severity == "pass"),
                "warn": sum(1 for f in self.findings if f.severity == "warn"),
                "fail": sum(1 for f in self.findings if f.severity == "fail"),
                "info": sum(1 for f in self.findings if f.severity == "info"),
            },
            "missing_for_next_grade": self.missing_for_next_grade,
        }

    @property
    def exit_code(self) -> int:
        """0=A/B, 1=C/D, 2=F."""
        if self.overall_grade in ("A", "B"):
            return 0
        if self.overall_grade == "F":
            return 2
        return 1


# ---------------------------------------------------------------------------
# Diagnostic checks
# ---------------------------------------------------------------------------

def _check_signature(
    passport: Dict[str, Any],
    verification_result: Optional[Dict[str, Any]],
) -> List[XRayFinding]:
    """Check signature status."""
    findings: List[XRayFinding] = []
    sig = passport.get("signature")

    if not sig or not isinstance(sig, dict):
        findings.append(XRayFinding(
            category="signature",
            severity="fail",
            title="Passport is unsigned",
            detail="No Ed25519 signature block present.",
            remediation="Run: assay passport sign <passport.json>",
        ))
        return findings

    if verification_result:
        if verification_result.get("signature_valid"):
            findings.append(XRayFinding(
                category="signature",
                severity="pass",
                title="Signature valid",
                detail=f"Ed25519 signature verified with key {sig.get('key_id', 'unknown')}.",
            ))
        else:
            findings.append(XRayFinding(
                category="signature",
                severity="fail",
                title="Signature invalid",
                detail=verification_result.get("error", "Signature verification failed."),
                remediation="Re-sign with the correct key: assay passport sign <passport.json>",
            ))

        if verification_result.get("id_valid"):
            findings.append(XRayFinding(
                category="signature",
                severity="pass",
                title="Content-addressed ID valid",
                detail="passport_id matches SHA-256 of passport body.",
            ))
        else:
            findings.append(XRayFinding(
                category="signature",
                severity="fail",
                title="Content-addressed ID mismatch",
                detail="passport_id does not match SHA-256(JCS(body)). Passport may be tampered.",
                remediation="Re-sign to recompute passport_id: assay passport sign <passport.json>",
            ))
    else:
        findings.append(XRayFinding(
            category="signature",
            severity="info",
            title="Signature present but not verified",
            detail=f"Signed by {sig.get('key_id', 'unknown')} at {sig.get('signed_at', 'unknown')}. "
                   "Pass --verify or provide keystore to check.",
        ))

    return findings


def _check_freshness(passport: Dict[str, Any], state: PassportState) -> List[XRayFinding]:
    """Check freshness and lifecycle state."""
    findings: List[XRayFinding] = []

    if state.state == "FRESH":
        findings.append(XRayFinding(
            category="freshness",
            severity="pass",
            title="Passport is fresh",
            detail=f"Valid until {passport.get('valid_until', 'unknown')}.",
        ))
    elif state.state == "STALE":
        findings.append(XRayFinding(
            category="freshness",
            severity="fail",
            title="Passport is stale",
            detail=f"Expired: valid_until = {passport.get('valid_until', 'unknown')}.",
            remediation="Mint and sign a new passport with current evidence.",
        ))
    elif state.state == "CHALLENGED":
        findings.append(XRayFinding(
            category="freshness",
            severity="warn",
            title="Passport is challenged",
            detail=state.reason,
            remediation="Address challenges and supersede with a new passport.",
        ))
    elif state.state == "SUPERSEDED":
        findings.append(XRayFinding(
            category="freshness",
            severity="warn",
            title="Passport is superseded",
            detail=f"Superseded by: {state.superseded_by or 'unknown'}.",
        ))
    elif state.state == "REVOKED":
        findings.append(XRayFinding(
            category="freshness",
            severity="fail",
            title="Passport is revoked",
            detail=state.reason,
        ))

    return findings


def _check_coverage(passport: Dict[str, Any]) -> List[XRayFinding]:
    """Check coverage completeness."""
    findings: List[XRayFinding] = []
    coverage = passport.get("coverage", {})

    if not coverage:
        findings.append(XRayFinding(
            category="coverage",
            severity="warn",
            title="No coverage section",
            detail="Passport does not declare coverage information.",
            remediation="Add a coverage section with call site instrumentation details.",
        ))
        return findings

    total = coverage.get("identified_total", 0)
    covered = coverage.get("covered_total", 0)
    pct = coverage.get("coverage_pct", 0)

    if total == 0:
        findings.append(XRayFinding(
            category="coverage",
            severity="warn",
            title="No call sites declared",
            detail="Coverage section exists but identifies zero call sites.",
            remediation="Declare call sites in the coverage section.",
        ))
    elif covered == total:
        findings.append(XRayFinding(
            category="coverage",
            severity="pass",
            title="Full coverage",
            detail=f"All {total} identified call sites are covered ({pct}%).",
        ))
    else:
        missing = total - covered
        sev = "warn" if pct >= 50 else "fail"
        findings.append(XRayFinding(
            category="coverage",
            severity=sev,
            title=f"Partial coverage: {covered}/{total} ({pct}%)",
            detail=f"{missing} call site(s) not instrumented.",
            remediation="Instrument missing call sites and re-mint passport.",
        ))

    return findings


def _check_claims(passport: Dict[str, Any]) -> List[XRayFinding]:
    """Check claims quality."""
    findings: List[XRayFinding] = []
    claims = passport.get("claims", [])

    if not claims:
        findings.append(XRayFinding(
            category="claims",
            severity="warn",
            title="No claims",
            detail="Passport contains no claims.",
            remediation="Mint from a proof pack to auto-extract claims.",
        ))
        return findings

    passed = sum(1 for c in claims if c.get("result") == "pass")
    failed = sum(1 for c in claims if c.get("result") == "fail")
    partial = sum(1 for c in claims if c.get("result") == "partial")

    if failed > 0:
        findings.append(XRayFinding(
            category="claims",
            severity="fail",
            title=f"{failed} claim(s) failed",
            detail=", ".join(
                c.get("claim_id", "?") for c in claims if c.get("result") == "fail"
            ),
            remediation="Fix underlying issues and re-verify.",
        ))
    if partial > 0:
        findings.append(XRayFinding(
            category="claims",
            severity="warn",
            title=f"{partial} claim(s) partial",
            detail=", ".join(
                c.get("claim_id", "?") for c in claims if c.get("result") == "partial"
            ),
            remediation="Improve evidence to achieve full pass.",
        ))
    if passed == len(claims):
        findings.append(XRayFinding(
            category="claims",
            severity="pass",
            title=f"All {passed} claims pass",
            detail="Every claim in the passport has result=pass.",
        ))
    elif passed > 0 and failed == 0:
        findings.append(XRayFinding(
            category="claims",
            severity="info",
            title=f"{passed}/{len(claims)} claims pass",
            detail=f"{partial} partial, {len(claims) - passed - partial} other.",
        ))

    return findings


def _check_evidence(passport: Dict[str, Any]) -> List[XRayFinding]:
    """Check evidence strength."""
    findings: List[XRayFinding] = []
    summary = passport.get("evidence_summary", {})

    if not summary:
        findings.append(XRayFinding(
            category="evidence",
            severity="warn",
            title="No evidence summary",
            detail="Passport lacks an evidence_summary section.",
            remediation="Mint from a proof pack to auto-populate evidence summary.",
        ))
        return findings

    machine = summary.get("machine_verified", 0)
    human = summary.get("human_attested", 0)
    total = summary.get("total_claims", 0)

    if total > 0 and machine > 0:
        findings.append(XRayFinding(
            category="evidence",
            severity="pass",
            title=f"Evidence mix: {machine} machine, {human} human",
            detail=f"{machine}/{total} claims have machine-verified evidence.",
        ))
    elif total > 0:
        findings.append(XRayFinding(
            category="evidence",
            severity="warn",
            title="No machine-verified evidence",
            detail="All claims rely on human attestation only.",
            remediation="Add machine-verifiable evidence (integrity checks, hash chains).",
        ))

    return findings


def _check_scope(passport: Dict[str, Any]) -> List[XRayFinding]:
    """Check scope clarity."""
    findings: List[XRayFinding] = []
    scope = passport.get("scope", {})

    if not scope:
        findings.append(XRayFinding(
            category="scope",
            severity="warn",
            title="No scope section",
            detail="Passport does not declare scope boundaries.",
            remediation="Add in_scope, not_covered, not_observed, and not_concluded lists.",
        ))
        return findings

    in_scope = scope.get("in_scope", [])
    not_covered = scope.get("not_covered", [])

    if not in_scope:
        findings.append(XRayFinding(
            category="scope",
            severity="warn",
            title="Empty in_scope",
            detail="No items declared in scope.",
            remediation="List what the passport covers.",
        ))
    else:
        findings.append(XRayFinding(
            category="scope",
            severity="pass",
            title=f"{len(in_scope)} items in scope",
            detail=", ".join(in_scope[:3]) + ("..." if len(in_scope) > 3 else ""),
        ))

    if not_covered:
        findings.append(XRayFinding(
            category="scope",
            severity="info",
            title=f"{len(not_covered)} items not covered",
            detail="Explicitly declared exclusions (good transparency).",
        ))

    return findings


# ---------------------------------------------------------------------------
# Grade computation
# ---------------------------------------------------------------------------

def _compute_grade(
    passport: Dict[str, Any],
    findings: List[XRayFinding],
    state: PassportState,
    verification_result: Optional[Dict[str, Any]],
) -> tuple[str, List[str]]:
    """Compute overall grade and what's missing for next grade.

    A = R3+ (signed, full coverage, all claims pass, fresh)
    B = R2 (signed, partial coverage or partial claims, fresh)
    C = R1 (unsigned or minimal coverage)
    D = R0 (no evidence or stale)
    F = integrity failure or revoked
    """
    missing: List[str] = []
    fail_count = sum(1 for f in findings if f.severity == "fail")

    # F: integrity failure, revoked, or tampered
    if state.state == "REVOKED":
        return "F", ["Passport is revoked — cannot improve grade"]

    if verification_result:
        if not verification_result.get("signature_valid", True):
            return "F", ["Fix signature to improve from F"]
        if not verification_result.get("id_valid", True):
            return "F", ["Fix passport_id integrity to improve from F"]

    # Check key properties
    has_signature = bool(passport.get("signature"))
    claims = passport.get("claims", [])
    all_claims_pass = all(c.get("result") == "pass" for c in claims) if claims else False
    coverage = passport.get("coverage", {})
    full_coverage = (
        coverage.get("covered_total", 0) == coverage.get("identified_total", 0)
        and coverage.get("identified_total", 0) > 0
    )
    is_fresh = state.state == "FRESH"

    # A: signed + full coverage + all claims pass + fresh
    if has_signature and full_coverage and all_claims_pass and is_fresh and claims:
        return "A", []

    # B: signed + fresh + (partial coverage or partial claims)
    if has_signature and is_fresh and claims:
        if not full_coverage:
            missing.append("Achieve full call-site coverage")
        if not all_claims_pass:
            missing.append("Fix all failing/partial claims")
        return "B", missing

    # C: has some evidence but unsigned or stale
    if claims or coverage:
        if not has_signature:
            missing.append("Sign the passport")
        if not is_fresh:
            missing.append("Ensure passport is fresh (not expired/challenged)")
        if not claims:
            missing.append("Add claims from a proof pack")
        return "C", missing

    # D: minimal or no evidence
    if not has_signature:
        missing.append("Sign the passport")
    if not claims:
        missing.append("Mint from a proof pack to extract claims")
    if not coverage:
        missing.append("Add coverage information")
    return "D", missing


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def xray_passport(
    passport_path: Path,
    *,
    keystore: Optional[Any] = None,
    verify: bool = False,
    passport_dir: Optional[Path] = None,
    now: Optional[Any] = None,
) -> XRayResult:
    """Run X-Ray diagnostic on a passport.

    Args:
        passport_path: Path to the passport JSON file.
        keystore: Optional keystore for signature verification.
        verify: If True, verify the signature (requires keystore or default).
        passport_dir: Directory for receipt file lookup. Defaults to
            passport_path's parent directory.
        now: Override current time (for testing).

    Returns:
        XRayResult with grade, findings, and improvement guidance.
    """
    passport_path = Path(passport_path)
    if not passport_path.exists():
        result = XRayResult(passport_path=str(passport_path))
        result.findings.append(XRayFinding(
            category="signature",
            severity="fail",
            title="Passport file not found",
            detail=f"File does not exist: {passport_path}",
        ))
        result.overall_grade = "F"
        return result

    try:
        passport = json.loads(passport_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result = XRayResult(passport_path=str(passport_path))
        result.findings.append(XRayFinding(
            category="signature",
            severity="fail",
            title="Malformed JSON",
            detail=str(exc),
        ))
        result.overall_grade = "F"
        return result

    # Compute lifecycle state
    pdir = passport_dir or passport_path.parent
    state = compute_passport_state(passport, passport_dir=pdir, now=now)

    # Optionally verify signature
    verification_result: Optional[Dict[str, Any]] = None
    if verify:
        from assay.passport_sign import verify_passport_signature
        verification_result = verify_passport_signature(passport_path, keystore=keystore)

    # Run all checks
    findings: List[XRayFinding] = []
    findings.extend(_check_signature(passport, verification_result))
    findings.extend(_check_freshness(passport, state))
    findings.extend(_check_coverage(passport))
    findings.extend(_check_claims(passport))
    findings.extend(_check_evidence(passport))
    findings.extend(_check_scope(passport))

    # Compute grade
    grade, missing = _compute_grade(passport, findings, state, verification_result)

    return XRayResult(
        passport_path=str(passport_path),
        findings=findings,
        overall_grade=grade,
        state=state,
        missing_for_next_grade=missing,
    )
