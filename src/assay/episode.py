"""
Episode-native SDK for long-lived runtimes.

This module exposes the three-mode Assay model as a Python API:

  Mode 1 (Wrapper):  assay run -- python app.py  (unchanged CLI)
  Mode 2 (Runtime):  open_episode / emit / seal_checkpoint
  Mode 3 (Settlement): verify_checkpoint / verify_pack

The Episode facade wraps existing infrastructure:
  - AssayStore for receipt persistence
  - ProofPack for checkpoint sealing
  - verify_receipt_pack / verify_pack_manifest for verification

Design rules:
  - No new storage format; uses the same JSONL traces and 5-file packs.
  - No new receipt schema; emits the same schema_version="3.0" receipts.
  - No new signing model; uses the same Ed25519 keystore.
  - Thread-safe: delegates to AssayStore's RLock.
  - One Episode = one trace = one causal chain of receipts.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay.claim_verifier import ClaimSpec
from assay.integrity import VerifyResult
from assay.keystore import AssayKeyStore, get_default_keystore
from assay.proof_pack import ProofPack
from assay.store import AssayStore, get_default_store


# ---------------------------------------------------------------------------
# Checkpoint result
# ---------------------------------------------------------------------------

@dataclass
class Checkpoint:
    """A sealed proof pack at a point in the episode."""

    pack_dir: Path
    episode_id: str
    reason: str
    receipt_count: int
    sealed_at: str


# ---------------------------------------------------------------------------
# Verdict (thin wrapper over VerifyResult for ergonomics)
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    """Settlement posture for a checkpoint.

    .ok is True only when both integrity and claims pass.
    The underlying VerifyResult is available as .detail for inspection.
    """

    ok: bool
    integrity_pass: bool
    claims_pass: bool
    errors: List[str] = field(default_factory=list)
    detail: Optional[VerifyResult] = None

    @property
    def honest_fail(self) -> bool:
        """True when evidence is authentic but claims failed.

        This is exit-code 1 territory: real evidence of a real problem.
        """
        return self.integrity_pass and not self.claims_pass


# ---------------------------------------------------------------------------
# Episode
# ---------------------------------------------------------------------------

class Episode:
    """An episode-scoped evidence session.

    Wraps an AssayStore trace with episode-level metadata, receipt
    emission, checkpoint sealing, and settlement verification.

    Usage::

        episode = open_episode(policy_version="v2.1")

        episode.emit("model.invoked", {"model": "gpt-4", "tokens": 800})
        episode.emit("guardian.approved", {"action": "send_email"})

        checkpoint = episode.seal_checkpoint(reason="before_send_email")
        verdict = verify_checkpoint(checkpoint)

        if verdict.ok:
            send_email()
        elif verdict.honest_fail:
            escalate()

        episode.close()

    The episode emits bookend receipts (episode.opened / episode.closed)
    automatically so the proof pack always has a bounded narrative.
    """

    def __init__(
        self,
        *,
        episode_id: Optional[str] = None,
        policy_version: Optional[str] = None,
        guardian_profile: Optional[str] = None,
        risk_class: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        store: Optional[AssayStore] = None,
        claims: Optional[List[ClaimSpec]] = None,
    ):
        self._store = store or get_default_store()
        self._episode_id = episode_id or _generate_episode_id()
        self._policy_version = policy_version
        self._guardian_profile = guardian_profile
        self._risk_class = risk_class
        self._metadata = metadata or {}
        self._claims = claims
        self._closed = False
        self._checkpoint_count = 0
        self._receipt_ids: List[str] = []

        # Start a dedicated trace for this episode
        self._trace_id = self._store.start_trace()

        # Emit opening receipt
        self._emit_lifecycle("episode.opened", {
            "policy_version": self._policy_version,
            "guardian_profile": self._guardian_profile,
            "risk_class": self._risk_class,
            **({"metadata": self._metadata} if self._metadata else {}),
        })

    @property
    def episode_id(self) -> str:
        return self._episode_id

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def receipt_count(self) -> int:
        return len(self._receipt_ids)

    # ------------------------------------------------------------------
    # Receipt emission
    # ------------------------------------------------------------------

    def emit(
        self,
        receipt_type: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        parent_receipt_id: Optional[str] = None,
    ) -> str:
        """Emit a receipt into this episode's trace.

        Returns the receipt_id for causal linking.
        """
        if self._closed:
            raise EpisodeClosedError(
                f"Episode {self._episode_id} is closed; cannot emit receipts."
            )
        return self._emit_raw(receipt_type, data, parent_receipt_id=parent_receipt_id)

    def _emit_raw(
        self,
        receipt_type: str,
        data: Optional[Dict[str, Any]] = None,
        *,
        parent_receipt_id: Optional[str] = None,
    ) -> str:
        """Internal: emit and track a receipt, return its ID."""
        rid = f"r_{uuid.uuid4().hex[:12]}"

        # User data goes in first; structural fields override so they
        # cannot be accidentally (or maliciously) clobbered.
        entry: Dict[str, Any] = {}
        if data:
            entry.update(data)
        entry.update({
            "receipt_id": rid,
            "type": receipt_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "episode_id": self._episode_id,
        })
        if parent_receipt_id:
            entry["parent_receipt_id"] = parent_receipt_id

        self._store.append_dict(entry)
        self._receipt_ids.append(rid)
        return rid

    def _emit_lifecycle(self, receipt_type: str, data: Dict[str, Any]) -> str:
        """Emit a lifecycle receipt (opened/closed)."""
        return self._emit_raw(receipt_type, data)

    # ------------------------------------------------------------------
    # Checkpoint sealing
    # ------------------------------------------------------------------

    def seal_checkpoint(
        self,
        reason: str = "checkpoint",
        *,
        output_dir: Optional[Path] = None,
        keystore: Optional[AssayKeyStore] = None,
        mode: str = "shadow",
    ) -> Checkpoint:
        """Seal current receipts into a signed proof pack.

        This does not close the episode. More receipts can be emitted
        after a checkpoint (e.g. for multi-phase workflows).

        Args:
            reason: Why the checkpoint was sealed (human-readable).
            output_dir: Where to write the pack. Defaults to
                        ./proof_pack_{trace_id}_cp{N}/
            keystore: Optional key store. Defaults to ~/.assay/keys/.
            mode: shadow | enforced | breakglass.

        Returns:
            Checkpoint with the pack directory and metadata.
        """
        if self._closed:
            raise EpisodeClosedError(
                f"Episode {self._episode_id} is closed; cannot seal checkpoint."
            )

        self._checkpoint_count += 1

        # Emit checkpoint receipt before sealing
        self._emit_raw("checkpoint.sealed", {
            "reason": reason,
            "checkpoint_number": self._checkpoint_count,
            "receipt_count": len(self._receipt_ids),
        })

        # Read current trace
        entries = self._store.read_trace(self._trace_id)
        if not entries:
            raise ValueError(f"No receipts in trace {self._trace_id}")

        # Determine output path
        if output_dir is None:
            suffix = f"_cp{self._checkpoint_count}" if self._checkpoint_count > 1 else ""
            output_dir = Path(f"proof_pack_{self._trace_id}{suffix}")

        ks = keystore or get_default_keystore()

        pack = ProofPack(
            run_id=self._trace_id,
            entries=entries,
            mode=mode,
            claims=self._claims,
        )
        pack_dir = pack.build(output_dir, keystore=ks)

        sealed_at = datetime.now(timezone.utc).isoformat()

        return Checkpoint(
            pack_dir=pack_dir,
            episode_id=self._episode_id,
            reason=reason,
            receipt_count=len(entries),
            sealed_at=sealed_at,
        )

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close(
        self,
        status: str = "completed",
        summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Close the episode. No more receipts can be emitted after this."""
        if self._closed:
            return  # idempotent

        self._emit_lifecycle("episode.closed", {
            "status": status,
            "receipt_count": len(self._receipt_ids),
            **({"summary": summary} if summary else {}),
        })
        self._closed = True

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Episode":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._closed:
            status = "failed" if exc_type else "completed"
            self.close(status=status)
        return None  # do not suppress exceptions


# ---------------------------------------------------------------------------
# Verification (standalone, works on any checkpoint/pack)
# ---------------------------------------------------------------------------

def verify_checkpoint(
    checkpoint: Checkpoint,
    *,
    keystore: Optional[AssayKeyStore] = None,
    claims: Optional[List[ClaimSpec]] = None,
    check_expiry: bool = False,
) -> Verdict:
    """Verify a sealed checkpoint and return a settlement verdict.

    This is the settlement gate: call it before allowing a
    consequential action to proceed.

    Args:
        checkpoint: A Checkpoint from episode.seal_checkpoint().
        keystore: Optional key store for signature verification.
        claims: Additional claims to check beyond pack-embedded ones.
        check_expiry: If True, fail packs past their valid_until.

    Returns:
        Verdict with .ok, .integrity_pass, .claims_pass, .honest_fail.
    """
    return verify_pack(
        checkpoint.pack_dir,
        keystore=keystore,
        claims=claims,
        check_expiry=check_expiry,
    )


def verify_pack(
    pack_dir: Path,
    *,
    keystore: Optional[AssayKeyStore] = None,
    claims: Optional[List[ClaimSpec]] = None,
    check_expiry: bool = False,
) -> Verdict:
    """Verify any proof pack directory and return a Verdict.

    Works on packs from seal_checkpoint() or from assay run.
    """
    import json as _json

    from assay.claim_verifier import verify_claims
    from assay.integrity import verify_pack_manifest, verify_receipt_pack

    pack_dir = Path(pack_dir)
    errors: List[str] = []

    # Load receipts
    receipt_path = pack_dir / "receipt_pack.jsonl"
    if not receipt_path.exists():
        return Verdict(
            ok=False, integrity_pass=False, claims_pass=False,
            errors=["receipt_pack.jsonl not found"],
        )

    entries = []
    for line in receipt_path.read_text().splitlines():
        if line.strip():
            entries.append(_json.loads(line))

    # Integrity check on receipts
    receipt_result = verify_receipt_pack(entries)
    integrity_pass = receipt_result.passed

    if not integrity_pass:
        for e in receipt_result.errors:
            errors.append(f"{e.code}: {e.message}")

    # Manifest check (if manifest exists)
    manifest_path = pack_dir / "pack_manifest.json"
    if manifest_path.exists():
        ks = keystore or get_default_keystore()
        manifest = _json.loads(manifest_path.read_text())
        manifest_result = verify_pack_manifest(manifest, pack_dir, ks)
        if not manifest_result.passed:
            integrity_pass = False
            for e in manifest_result.errors:
                errors.append(f"{e.code}: {e.message}")

        # Check expiry
        if check_expiry:
            valid_until = manifest.get("attestation", {}).get("valid_until")
            if valid_until:
                try:
                    expiry = datetime.fromisoformat(valid_until)
                    if datetime.now(timezone.utc) > expiry:
                        errors.append("E_PACK_STALE: pack has expired")
                        integrity_pass = False
                except (ValueError, TypeError):
                    pass

    # Claims check
    claims_pass = True
    if claims:
        claim_result = verify_claims(entries, claims)
        claims_pass = claim_result.passed
        if not claims_pass:
            for r in claim_result.results:
                if not r.passed:
                    errors.append(f"claim:{r.claim_id}: expected {r.expected}, got {r.actual}")

    return Verdict(
        ok=integrity_pass and claims_pass,
        integrity_pass=integrity_pass,
        claims_pass=claims_pass,
        errors=errors,
        detail=receipt_result,
    )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def open_episode(
    *,
    episode_id: Optional[str] = None,
    policy_version: Optional[str] = None,
    guardian_profile: Optional[str] = None,
    risk_class: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    store: Optional[AssayStore] = None,
    claims: Optional[List[ClaimSpec]] = None,
) -> Episode:
    """Open a new evidence episode.

    This is the primary entry point for Mode 2 (Runtime mode).

    Usage::

        episode = assay.open_episode(policy_version="v2.1")
        episode.emit("model.invoked", {"model": "gpt-4"})
        checkpoint = episode.seal_checkpoint(reason="before_action")
        verdict = assay.verify_checkpoint(checkpoint)
        episode.close()

    Or as a context manager::

        with assay.open_episode() as ep:
            ep.emit("tool.invoked", {"tool": "search"})
            cp = ep.seal_checkpoint()
            v = assay.verify_checkpoint(cp)
    """
    return Episode(
        episode_id=episode_id,
        policy_version=policy_version,
        guardian_profile=guardian_profile,
        risk_class=risk_class,
        metadata=metadata,
        store=store,
        claims=claims,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_episode_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"ep_{ts}_{uuid.uuid4().hex[:8]}"


class EpisodeClosedError(RuntimeError):
    """Raised when trying to emit or seal on a closed episode."""
    pass


__all__ = [
    "Checkpoint",
    "Episode",
    "EpisodeClosedError",
    "Verdict",
    "open_episode",
    "verify_checkpoint",
    "verify_pack",
]
