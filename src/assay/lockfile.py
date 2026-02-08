"""
Verifier Lockfile Contract for Assay.

Freezes verification semantics per repo so that local, CI, and external
verification produce identical results. The lockfile records:

- Which RunCards are active (with deterministic claim_set_hash)
- Exit code semantics (0/1/2 contract)
- Signer policy (allowlist of pubkey fingerprints)
- Minimum Assay version required to verify

Usage:
  assay lock write --cards receipt_completeness,guardian_enforcement
  assay verify-pack ./proof_pack_*/ --lock assay.lock --require-claim-pass
  assay lock check
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from packaging.version import Version

from assay._receipts.canonicalize import to_jcs_bytes

from assay import __version__ as _assay_version
from assay.run_cards import RunCard, collect_claims_from_cards, get_builtin_card

LOCK_VERSION = "1.0"
DEFAULT_LOCK_PATH = "assay.lock"

# Required top-level fields. If any are missing, the lockfile is invalid.
_REQUIRED_FIELDS = {
    "lock_version",
    "assay_version_min",
    "pack_format_version",
    "run_cards",
    "run_cards_composite_hash",
    "claim_set_hash",
    "exit_contract",
    "signer_policy",
}

_VALID_SIGNER_MODES = {"any", "allowlist"}


@dataclass
class LockfileError:
    """A single lock mismatch."""

    field: str
    expected: str
    actual: str

    def __str__(self) -> str:
        return f"lock mismatch: {self.field}: expected {self.expected}, got {self.actual}"


@dataclass
class LockValidation:
    """Result of validating a pack against a lockfile."""

    passed: bool
    errors: List[LockfileError] = field(default_factory=list)


def write_lockfile(
    card_ids: List[str],
    *,
    signer_fingerprints: Optional[List[str]] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write an assay.lock file from the specified RunCards.

    Args:
        card_ids: List of RunCard IDs to lock (builtin or custom).
        signer_fingerprints: Optional allowlist of ed25519 pubkey SHA-256 hashes.
        output_path: Where to write the lockfile. Defaults to ./assay.lock.

    Returns:
        The lockfile dict that was written.
    """
    cards: List[RunCard] = []
    for cid in card_ids:
        card = get_builtin_card(cid)
        if card is None:
            raise ValueError(f"Unknown RunCard: {cid}")
        cards.append(card)

    run_card_entries = []
    for card in cards:
        run_card_entries.append({
            "id": card.card_id,
            "name": card.name,
            "claim_set_hash": card.claim_set_hash(),
        })

    # Compute composite hash two ways:
    # 1. Per-card hash composite (for card-level drift detection)
    composite_material = to_jcs_bytes([e["claim_set_hash"] for e in run_card_entries])
    composite_hash = hashlib.sha256(composite_material).hexdigest()

    # 2. Flattened claim set hash (matches ProofPack.claim_set_hash exactly)
    all_claims = collect_claims_from_cards(cards)
    flat_specs = [c.to_dict() for c in all_claims]
    flat_hash = hashlib.sha256(to_jcs_bytes(flat_specs)).hexdigest()

    lockfile: Dict[str, Any] = {
        "lock_version": LOCK_VERSION,
        "assay_version_min": _assay_version,
        "pack_format_version": "0.1.0",
        "receipt_schema_version": "3.0",
        "run_cards": run_card_entries,
        "run_cards_composite_hash": composite_hash,
        "claim_set_hash": flat_hash,
        "exit_contract": {
            "0": "integrity_pass AND claims_pass",
            "1": "integrity_pass AND claims_fail",
            "2": "integrity_fail",
        },
        "signer_policy": {
            "mode": "allowlist" if signer_fingerprints else "any",
            "allowed_fingerprints": signer_fingerprints or [],
        },
        "locked_at": datetime.now(timezone.utc).isoformat(),
        "locked_by_assay_version": _assay_version,
    }

    if output_path is None:
        output_path = Path(DEFAULT_LOCK_PATH)

    output_path.write_text(json.dumps(lockfile, indent=2) + "\n")
    return lockfile


def load_lockfile(path: Path) -> Dict[str, Any]:
    """Load and structurally validate lockfile.

    Fails closed: missing required fields or bad lock_version raises ValueError.
    """
    data = json.loads(path.read_text())

    if data.get("lock_version") != LOCK_VERSION:
        raise ValueError(
            f"Unsupported lock_version: {data.get('lock_version')} "
            f"(expected {LOCK_VERSION})"
        )

    # Structural validation: all required fields must exist
    missing = _REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(
            f"Invalid lockfile: missing required fields: {', '.join(sorted(missing))}"
        )

    # Signer policy must have valid mode
    sp = data.get("signer_policy", {})
    mode = sp.get("mode")
    if mode not in _VALID_SIGNER_MODES:
        raise ValueError(
            f"Invalid signer_policy.mode: {mode!r} "
            f"(expected one of {_VALID_SIGNER_MODES})"
        )
    if mode == "allowlist" and not isinstance(sp.get("allowed_fingerprints"), list):
        raise ValueError(
            "signer_policy.mode is 'allowlist' but allowed_fingerprints is not a list"
        )

    # assay_version_min must be parseable
    try:
        Version(data["assay_version_min"])
    except Exception:
        raise ValueError(
            f"Invalid assay_version_min: {data['assay_version_min']!r} "
            f"(must be a valid PEP 440 version)"
        )

    return data


def validate_against_lock(
    manifest: Dict[str, Any],
    lockfile: Dict[str, Any],
) -> LockValidation:
    """Validate a pack manifest against a lockfile.

    Fail-closed: missing required lock fields are treated as mismatches.

    Checks:
    1. Pack format version matches
    2. claim_set_hash matches (flattened, ProofPack-compatible)
    3. Signer fingerprint is in allowlist (if mode=allowlist)
    4. Assay version meets minimum

    Returns LockValidation with pass/fail and detailed errors.
    """
    errors: List[LockfileError] = []

    # 1. Pack format version
    att = manifest.get("attestation", {})
    pack_fmt = att.get("pack_format_version", "")
    locked_fmt = lockfile.get("pack_format_version", "")
    if not locked_fmt:
        errors.append(LockfileError(
            field="pack_format_version",
            expected="(required in lockfile)",
            actual="(missing)",
        ))
    elif pack_fmt != locked_fmt:
        errors.append(LockfileError(
            field="pack_format_version",
            expected=locked_fmt,
            actual=pack_fmt,
        ))

    # 2. Claim set hash (flattened, matches ProofPack computation)
    manifest_claim_hash = manifest.get("claim_set_hash", "")
    locked_flat_hash = lockfile.get("claim_set_hash", "")

    if not locked_flat_hash:
        errors.append(LockfileError(
            field="claim_set_hash",
            expected="(required in lockfile)",
            actual="(missing)",
        ))
    elif not manifest_claim_hash:
        errors.append(LockfileError(
            field="claim_set_hash",
            expected=locked_flat_hash[:16] + "...",
            actual="(missing in manifest)",
        ))
    elif manifest_claim_hash != locked_flat_hash:
        errors.append(LockfileError(
            field="claim_set_hash",
            expected=locked_flat_hash[:16] + "...",
            actual=manifest_claim_hash[:16] + "...",
        ))

    # 3. Signer policy
    signer_policy = lockfile.get("signer_policy", {})
    if signer_policy.get("mode") == "allowlist":
        allowed = signer_policy.get("allowed_fingerprints", [])
        pack_signer_fp = manifest.get("signer_pubkey_sha256", "")
        if not allowed:
            errors.append(LockfileError(
                field="signer_policy",
                expected="non-empty allowlist",
                actual="empty allowlist",
            ))
        elif not pack_signer_fp:
            errors.append(LockfileError(
                field="signer_pubkey_sha256",
                expected=f"one of {len(allowed)} allowed fingerprints",
                actual="(missing in manifest)",
            ))
        elif pack_signer_fp not in allowed:
            errors.append(LockfileError(
                field="signer_pubkey_sha256",
                expected=f"one of {len(allowed)} allowed fingerprints",
                actual=pack_signer_fp[:16] + "...",
            ))

    # 4. Assay version minimum
    locked_min = lockfile.get("assay_version_min", "")
    if locked_min:
        try:
            if Version(_assay_version) < Version(locked_min):
                errors.append(LockfileError(
                    field="assay_version_min",
                    expected=f">= {locked_min}",
                    actual=_assay_version,
                ))
        except Exception:
            pass  # Version parsing already validated in load_lockfile

    return LockValidation(
        passed=len(errors) == 0,
        errors=errors,
    )


def check_lockfile(path: Path) -> List[str]:
    """Validate a lockfile itself (structure, card references, hashes).

    Full semantic validation:
    - Required fields present
    - lock_version correct
    - assay_version_min parseable and compatible
    - signer_policy schema valid
    - exit_contract has all 3 codes
    - Each RunCard exists and per-card hash matches current definition
    - claim_set_hash matches recomputed flattened claims
    - run_cards_composite_hash matches recomputed per-card composite

    Returns list of error strings (empty = valid).
    """
    issues: List[str] = []

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return [f"Cannot read lockfile: {e}"]

    # Required fields
    missing = _REQUIRED_FIELDS - set(data.keys())
    if missing:
        issues.append(f"Missing required fields: {', '.join(sorted(missing))}")

    # lock_version
    if data.get("lock_version") != LOCK_VERSION:
        issues.append(
            f"Unsupported lock_version: {data.get('lock_version')} "
            f"(expected {LOCK_VERSION})"
        )

    # assay_version_min
    ver_min = data.get("assay_version_min", "")
    if ver_min:
        try:
            min_v = Version(ver_min)
            current_v = Version(_assay_version)
            if current_v < min_v:
                issues.append(
                    f"Assay version {_assay_version} is below "
                    f"assay_version_min {ver_min}"
                )
        except Exception:
            issues.append(f"Invalid assay_version_min: {ver_min!r}")
    elif "assay_version_min" in _REQUIRED_FIELDS:
        issues.append("Missing assay_version_min")

    # signer_policy
    sp = data.get("signer_policy", {})
    sp_mode = sp.get("mode")
    if sp_mode not in _VALID_SIGNER_MODES:
        issues.append(f"Invalid signer_policy.mode: {sp_mode!r}")
    if sp_mode == "allowlist":
        fps = sp.get("allowed_fingerprints")
        if not isinstance(fps, list):
            issues.append("signer_policy.allowed_fingerprints must be a list")

    # exit_contract
    exit_contract = data.get("exit_contract", {})
    for code in ("0", "1", "2"):
        if code not in exit_contract:
            issues.append(f"Missing exit_contract for code {code}")

    # Per-card validation
    resolved_cards: list[RunCard] = []
    for card_entry in data.get("run_cards", []):
        cid = card_entry.get("id", "?")
        card = get_builtin_card(cid)
        if card is None:
            issues.append(f"RunCard '{cid}' not found in builtins")
            continue

        resolved_cards.append(card)
        actual_hash = card.claim_set_hash()
        locked_hash = card_entry.get("claim_set_hash", "")
        if actual_hash != locked_hash:
            issues.append(
                f"RunCard '{cid}' hash drift: "
                f"locked={locked_hash[:16]}... current={actual_hash[:16]}..."
            )

    # Recompute and verify run_cards_composite_hash
    if resolved_cards and "run_cards_composite_hash" in data:
        recomputed_hashes = [card.claim_set_hash() for card in resolved_cards]
        recomputed_composite = hashlib.sha256(
            to_jcs_bytes(recomputed_hashes)
        ).hexdigest()
        if data["run_cards_composite_hash"] != recomputed_composite:
            issues.append(
                f"run_cards_composite_hash drift: "
                f"locked={data['run_cards_composite_hash'][:16]}... "
                f"current={recomputed_composite[:16]}..."
            )

    # Recompute and verify claim_set_hash (flattened)
    if resolved_cards and "claim_set_hash" in data:
        all_claims = collect_claims_from_cards(resolved_cards)
        flat_specs = [c.to_dict() for c in all_claims]
        recomputed_flat = hashlib.sha256(to_jcs_bytes(flat_specs)).hexdigest()
        if data["claim_set_hash"] != recomputed_flat:
            issues.append(
                f"claim_set_hash drift: "
                f"locked={data['claim_set_hash'][:16]}... "
                f"current={recomputed_flat[:16]}..."
            )

    return issues


__all__ = [
    "LOCK_VERSION",
    "DEFAULT_LOCK_PATH",
    "LockfileError",
    "LockValidation",
    "write_lockfile",
    "load_lockfile",
    "validate_against_lock",
    "check_lockfile",
]
