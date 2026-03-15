"""Mint passport drafts from proof packs.

Pipeline: proof_pack → verify → extract claims + coverage + evidence
→ populate passport template → write unsigned JSON. User reviews,
then signs with `assay passport sign`.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class PassportMintError(ValueError):
    """Raised when minting fails due to missing inputs or verification failure."""


def _extract_claims_from_report(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract passport claims from a verify_report.json."""
    claims: List[Dict[str, Any]] = []
    attestation = report.get("attestation", {})
    pack_id = attestation.get("pack_id", "")
    integrity = attestation.get("receipt_integrity", "N/A")
    claim_check = attestation.get("claim_check", "N/A")

    # C-001: Offline verifiability (integrity)
    claims.append({
        "claim_id": "C-001",
        "topic": "Offline verifiability",
        "claim_type": "integrity",
        "applies_to": "proof_pack",
        "assertion": "The proof artifact can be verified offline without network access.",
        "result": "pass" if integrity == "PASS" else "fail",
        "evidence_type": "machine_verified",
        "proof_tier": "core",
        "evidence_refs": [f"proof_pack/{pack_id}/verify_report.json#integrity"],
        "qualification": None,
        "boundary": None,
    })

    # C-002: Receipt integrity
    claims.append({
        "claim_id": "C-002",
        "topic": "Receipt integrity",
        "claim_type": "integrity",
        "applies_to": "proof_pack",
        "assertion": "All receipts in the proof pack pass hash-chain integrity verification.",
        "result": "pass" if integrity == "PASS" else "fail",
        "evidence_type": "machine_verified",
        "proof_tier": "core",
        "evidence_refs": [f"proof_pack/{pack_id}/verify_report.json#hash_chain"],
        "qualification": None,
        "boundary": None,
    })

    # C-003: Claim verification
    if claim_check != "N/A":
        claims.append({
            "claim_id": "C-003",
            "topic": "Claim verification",
            "claim_type": "integrity",
            "applies_to": "proof_pack",
            "assertion": "All attestation claims in the proof pack were evaluated.",
            "result": "pass" if claim_check == "PASS" else "fail",
            "evidence_type": "machine_verified",
            "proof_tier": "core",
            "evidence_refs": [f"proof_pack/{pack_id}/verify_report.json#claims"],
            "qualification": None,
            "boundary": None,
        })

    return claims


def _extract_evidence_summary(
    report: Dict[str, Any],
    claims: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build evidence summary from verify report and extracted claims."""
    machine = sum(1 for c in claims if c.get("evidence_type") == "machine_verified")
    human = sum(1 for c in claims if c.get("evidence_type") == "human_attested")
    core_passed = sum(
        1 for c in claims
        if c.get("proof_tier") == "core" and c.get("result") == "pass"
    )
    core_total = sum(1 for c in claims if c.get("proof_tier") == "core")

    attestation = report.get("attestation", {})
    return {
        "total_claims": len(claims),
        "machine_verified": machine,
        "human_attested": human,
        "core_claims_passed": f"{core_passed}/{core_total}",
        "conditional_claims": "0/0",
        "coverage_gaps": 0,
        "proof_pack_hash": attestation.get("pack_root_sha256", ""),
    }


def _determine_reliance_class(
    claims: List[Dict[str, Any]],
    signed: bool,
) -> Dict[str, Any]:
    """Determine reliance class from claims and signature status."""
    all_pass = all(c.get("result") == "pass" for c in claims)
    has_coverage = any(c.get("claim_type") == "coverage" for c in claims)

    if signed and all_pass and has_coverage:
        return {
            "class": "R3",
            "label": "Signed, full coverage, all claims pass",
        }
    if signed and all_pass:
        return {
            "class": "R2",
            "label": "Signed, all core claims pass",
        }
    if signed:
        return {
            "class": "R1",
            "label": "Signed, partial verification",
        }
    return {
        "class": "R0",
        "label": "Unsigned or minimal evidence",
    }


def mint_passport_draft(
    *,
    proof_pack_dir: Optional[Path] = None,
    subject_name: str,
    subject_system_id: str,
    subject_owner: str,
    valid_days: int = 30,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Mint an unsigned passport draft from a proof pack.

    If proof_pack_dir is provided, reads verify_report.json and
    pack_manifest.json to extract claims, evidence, and coverage.
    If omitted, produces a minimal skeleton.

    Returns the passport dict (unsigned — no passport_id or signature).
    """
    now = now or datetime.now(timezone.utc)
    issued_at = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    valid_until = (now + timedelta(days=valid_days)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    claims: List[Dict[str, Any]] = []
    evidence_summary: Dict[str, Any] = {}
    proof_pack_ref: Optional[str] = None
    observation_window = {
        "start": issued_at,
        "end": issued_at,
        "note": "Draft passport — observation window matches issuance",
    }

    if proof_pack_dir:
        proof_pack_dir = Path(proof_pack_dir)

        # Load verify report
        report_path = proof_pack_dir / "verify_report.json"
        if not report_path.exists():
            raise PassportMintError(
                f"verify_report.json not found in {proof_pack_dir}. "
                "Run 'assay verify-pack' first."
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))

        # Load manifest for pack hash
        manifest_path = proof_pack_dir / "pack_manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            attestation = manifest.get("attestation", {})
            proof_pack_ref = f"sha256:{attestation.get('pack_root_sha256', '')}"
            ts_start = attestation.get("timestamp_start", issued_at)
            ts_end = attestation.get("timestamp_end", issued_at)
            observation_window = {
                "start": ts_start,
                "end": ts_end,
                "note": "Evidence collected during proof pack capture session",
            }

        claims = _extract_claims_from_report(report)
        evidence_summary = _extract_evidence_summary(report, claims)

    reliance = _determine_reliance_class(claims, signed=False)

    passport: Dict[str, Any] = {
        "passport_version": "0.1",
        "issued_at": issued_at,
        "valid_until": valid_until,
        "observation_window": observation_window,
        "status": {
            "state": "FRESH",
            "reason": "Draft passport — not yet signed.",
            "checked_at": issued_at,
        },
        "reliance": {
            "class": reliance["class"],
            "label": reliance["label"],
            "verdict": f"Draft passport for {subject_name}. Sign to finalize.",
            "limits": [],
            "freshness_note": f"Draft issued at {issued_at}. Valid for {valid_days} days.",
        },
        "trust_posture": {
            "freshness": "current",
            "signature": "unsigned",
            "coverage": "unknown",
            "evidence_mix": f"{evidence_summary.get('machine_verified', 0)} machine / "
                           f"{evidence_summary.get('human_attested', 0)} human",
            "challenges": "none",
            "scope_class": "unknown",
        },
        "subject": {
            "name": subject_name,
            "system_id": subject_system_id,
            "type": "ai_workflow",
            "description": "",
            "owner": subject_owner,
            "version": "1.0",
            "environment": "",
            "sample_boundary": "",
        },
        "scope": {
            "in_scope": [],
            "not_covered": [],
            "not_observed": [],
            "not_concluded": [],
            "boundary_notes": [],
        },
        "claims": claims,
        "evidence_summary": evidence_summary or {
            "total_claims": 0,
            "machine_verified": 0,
            "human_attested": 0,
            "core_claims_passed": "0/0",
            "conditional_claims": "0/0",
            "coverage_gaps": 0,
        },
        "relationships": {
            "proof_pack_ref": proof_pack_ref,
            "reviewer_packet_ref": None,
            "supersedes": None,
            "superseded_by": None,
            "challenge_refs": [],
            "revocation_ref": None,
        },
        "verification": {
            "how_to_verify": "assay passport verify ./passport.json",
            "what_is_checked": [
                "passport_id matches SHA-256 of passport body",
                "Ed25519 signature is valid (if signed)",
                "valid_until has not passed",
                "No active challenge, supersession, or revocation receipts",
            ],
        },
        "challenge": {
            "how_to_challenge": 'assay passport challenge ./passport.json --reason "<your reason>"',
            "what_happens": [
                "A timestamped challenge receipt is created in the passport directory.",
                "Passport status becomes CHALLENGED on next verification.",
                "The issuer can respond by superseding or revoking.",
            ],
        },
        "chain": {
            "issuer": "",
            "issuer_fingerprint": "",
        },
    }

    return passport
