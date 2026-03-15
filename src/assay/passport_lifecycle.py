"""Passport lifecycle state machine — demo/compatibility layer.

This module provides two categories of functionality:

1. **compute_passport_state()** — Computes passport state from receipt files
   on disk. Used by the verify command to produce a human-readable lifecycle
   state. Does NOT perform cryptographic verification of receipts.

2. **create_*_receipt()** — Creates unsigned demo receipt files. These are
   legacy helpers retained for ``--demo`` mode and backward compatibility.

   **For production use, prefer the signed equivalents in lifecycle_receipt.py:**
   - lifecycle_receipt.create_signed_challenge_receipt()
   - lifecycle_receipt.create_signed_supersession_receipt()
   - lifecycle_receipt.create_signed_revocation_receipt()

   See docs/specs/GOVERNANCE_RECEIPT_CONTRACT.md for the full contract.

Priority order: REVOKED > SUPERSEDED > CHALLENGED > STALE > FRESH.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class PassportState:
    """Computed passport lifecycle state."""

    state: str  # FRESH | STALE | CHALLENGED | SUPERSEDED | REVOKED
    reason: str
    checked_at: str
    challenges: List[Dict[str, Any]] = field(default_factory=list)
    superseded_by: Optional[str] = None
    revocation_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "checked_at": self.checked_at,
            "challenges": self.challenges,
            "superseded_by": self.superseded_by,
            "revocation_ref": self.revocation_ref,
        }


# ---------------------------------------------------------------------------
# Receipt loaders
# ---------------------------------------------------------------------------

def _load_json_files(directory: Path, prefix: str) -> List[Dict[str, Any]]:
    """Load all JSON files matching a prefix from a directory."""
    if not directory.is_dir():
        return []
    results = []
    for f in sorted(directory.glob(f"{prefix}*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            data["_source_file"] = f.name
            results.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return results


def _is_stale(passport: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    """Check if passport has passed its valid_until date."""
    valid_until = passport.get("valid_until")
    if not valid_until:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        expiry = datetime.fromisoformat(valid_until)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now > expiry
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_passport_state(
    passport: Dict[str, Any],
    *,
    passport_dir: Optional[Path] = None,
    now: Optional[datetime] = None,
) -> PassportState:
    """Compute lifecycle state from passport data and adjacent receipt files.

    Args:
        passport: Parsed passport dict.
        passport_dir: Directory containing the passport file. Receipt files
            (challenge_*, supersession_*, revocation_*) are looked up here.
            If None, only the passport body is examined.
        now: Override for current time (testing).

    Returns:
        PassportState with computed state, reason, and evidence references.
    """
    now = now or datetime.now(timezone.utc)
    checked_at = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    # Load receipt files from passport directory
    revocations: List[Dict[str, Any]] = []
    supersessions: List[Dict[str, Any]] = []
    challenges: List[Dict[str, Any]] = []

    if passport_dir and passport_dir.is_dir():
        revocations = _load_json_files(passport_dir, "revocation_")
        supersessions = _load_json_files(passport_dir, "supersession_")
        challenges = _load_json_files(passport_dir, "challenge_")

    # Priority 1: REVOKED
    if revocations:
        rev = revocations[-1]  # most recent
        return PassportState(
            state="REVOKED",
            reason=rev.get("reason", "Revoked by issuer"),
            checked_at=checked_at,
            challenges=challenges,
            revocation_ref=rev.get("_source_file"),
        )

    # Priority 2: SUPERSEDED
    # Check both receipt files and inline relationship
    superseded_by = passport.get("relationships", {}).get("superseded_by")
    if supersessions:
        sup = supersessions[-1]
        return PassportState(
            state="SUPERSEDED",
            reason=sup.get("reason", "Superseded by newer passport"),
            checked_at=checked_at,
            challenges=challenges,
            superseded_by=sup.get("new_passport_id", superseded_by),
        )
    if superseded_by:
        return PassportState(
            state="SUPERSEDED",
            reason="Superseded by newer passport",
            checked_at=checked_at,
            challenges=challenges,
            superseded_by=superseded_by,
        )

    # Priority 3: CHALLENGED
    if challenges:
        reasons = [c.get("reason", "No reason given") for c in challenges]
        return PassportState(
            state="CHALLENGED",
            reason=f"{len(challenges)} active challenge(s): {'; '.join(reasons)}",
            checked_at=checked_at,
            challenges=challenges,
        )

    # Priority 4: STALE
    if _is_stale(passport, now=now):
        return PassportState(
            state="STALE",
            reason=f"Passport expired (valid_until: {passport.get('valid_until', 'unknown')})",
            checked_at=checked_at,
        )

    # Priority 5: FRESH
    return PassportState(
        state="FRESH",
        reason="Valid, no active challenges, not superseded.",
        checked_at=checked_at,
    )


def create_demo_challenge_receipt(
    passport: Dict[str, Any],
    *,
    reason: str,
    challenger_id: str = "anonymous",
    evidence_ref: Optional[str] = None,
    output_dir: Path,
    now: Optional[datetime] = None,
) -> Path:
    """Create an unsigned challenge receipt file (demo mode only).

    For production use, prefer lifecycle_receipt.create_signed_challenge_receipt()
    which produces Ed25519-signed receipts with content-addressed identity.

    Returns the path to the created receipt file.
    """
    import hashlib

    now = now or datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%S")
    hash8 = hashlib.sha256(f"{reason}{ts}".encode()).hexdigest()[:8]
    filename = f"challenge_{ts}_{hash8}.json"

    receipt = {
        "type": "challenge",
        "passport_id": passport.get("passport_id", ""),
        "reason": reason,
        "challenger_id": challenger_id,
        "evidence_ref": evidence_ref,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return path


def create_demo_supersession_receipt(
    old_passport: Dict[str, Any],
    new_passport: Dict[str, Any],
    *,
    reason: str,
    output_dir: Path,
    now: Optional[datetime] = None,
) -> Path:
    """Create an unsigned supersession receipt (demo mode only).

    For production use, prefer lifecycle_receipt.create_signed_supersession_receipt()
    which produces Ed25519-signed receipts with content-addressed identity.

    Returns the path to the created receipt file.
    """
    now = now or datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%S")

    receipt = {
        "type": "supersession",
        "old_passport_id": old_passport.get("passport_id", ""),
        "new_passport_id": new_passport.get("passport_id", ""),
        "reason": reason,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"supersession_{ts}.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return path


def create_demo_revocation_receipt(
    passport: Dict[str, Any],
    *,
    reason: str,
    output_dir: Path,
    now: Optional[datetime] = None,
) -> Path:
    """Create an unsigned revocation receipt (demo mode only).

    For production use, prefer lifecycle_receipt.create_signed_revocation_receipt()
    which produces Ed25519-signed receipts with content-addressed identity.

    Returns the path to the created receipt file.
    """
    now = now or datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%S")

    receipt = {
        "type": "revocation",
        "passport_id": passport.get("passport_id", ""),
        "reason": reason,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"revocation_{ts}.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return path
