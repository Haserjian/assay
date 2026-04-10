"""
Proof Pack v0 Builder.

Builds the 5-file execution kernel:
  - receipt_pack.jsonl     Canonical receipts in deterministic order
  - verify_report.json     Machine-readable verification results
  - verify_transcript.md   Human-readable summary with attestation block
  - pack_manifest.json     Signed root envelope
  - pack_signature.sig     Detached Ed25519 signature

Signing workflow (per spec):
  1. Build unsigned manifest, validate structure
  2. JCS-canonicalize unsigned manifest, sign with Ed25519
  3. Attach signature to manifest -> pack_manifest.json
  4. Write detached pack_signature.sig with same bytes
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from assay._receipts.canonicalize import prepare_receipt_for_hashing
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.claim_verifier import ClaimSetResult, ClaimSpec, verify_claims
from assay.integrity import (
    E_MANIFEST_TAMPER,
    E_SCHEMA_UNKNOWN,
    VerifyError,
    VerifyResult,
    verify_pack_manifest,
    verify_receipt_pack,
)
from assay.keystore import DEFAULT_SIGNER_ID, AssayKeyStore, get_default_keystore

try:
    from assay import __version__ as _assay_version
except Exception:
    _assay_version = "0.1.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_UNSIGNED_SIDECAR_DIR = "_unsigned"

# Proof packs intentionally accept a narrow receipt vocabulary. Namespaced
# dotted receipt types are allowed, along with a compatibility set of flat
# legacy types used by current Assay proof-pack producers.
PROOF_PACK_ALLOWED_RECEIPT_TYPES = frozenset(
    {
        "ai_workflow",
        "capability_use",
        "challenge",
        "decision_v1",
        "governance_posture_snapshot",
        "grace_check",
        "guardian_check",
        "guardian_verdict",
        "mcp_tool_call",
        "model_call",
        "refusal",
        "revocation",
        "session_metadata",
        "supersession",
    }
)
_PROOF_PACK_NAMESPACED_TYPE_RE = re.compile(
    r"^[a-z0-9_]+(?:\.[a-z0-9_]+)+(?:/[a-z0-9_]+)?$"
)
PROOF_PACK_CURRENT_LOOM_RECEIPT_TYPES: frozenset[str] = frozenset(
    # Mirror rows marked `current` in
    # docs/specs/LOOM_RECEIPT_MAPPING_REGISTRY_V1.md.
)


def _generate_pack_id(*, deterministic_seed: Optional[str] = None) -> str:
    """Generate a pack ID.

    When deterministic_seed is provided (e.g. corpus generation), the ID
    is content-addressed and reproducible.  Otherwise it uses a timestamp
    and random suffix for production packs.
    """
    if deterministic_seed is not None:
        tag = hashlib.sha256(deterministic_seed.encode()).hexdigest()[:8]
        return f"pack_deterministic_{tag}"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"pack_{ts}_{uuid.uuid4().hex[:8]}"


def _build_deterministic_pack_seed(
    *,
    run_id: str,
    receipt_pack_bytes: bytes,
    policy_hash: str,
    suite_hash: str,
    claim_set_id: str,
    claim_set_hash: str,
    mode: str,
    ci_binding: Optional[Dict[str, Any]],
    valid_until: Optional[str],
    superseded_by: Optional[str],
) -> str:
    """Build a stable seed from artifact-defining inputs."""
    seed_material = {
        "pack_format_version": "0.1.0",
        "run_id": run_id,
        "receipt_pack_sha256": _sha256_hex(receipt_pack_bytes),
        "policy_hash": policy_hash,
        "suite_hash": suite_hash,
        "claim_set_id": claim_set_id,
        "claim_set_hash": claim_set_hash,
        "mode": mode,
        "ci_binding": ci_binding,
        "valid_until": valid_until,
        "superseded_by": superseded_by,
    }
    return _sha256_hex(jcs_canonicalize(seed_material))


import re as _re

_FULL_SHA_RE = _re.compile(r"^[a-f0-9]{40}$")


def _is_full_sha(s: str) -> bool:
    """Return True if *s* is a full 40-character lowercase hex SHA."""
    return bool(_FULL_SHA_RE.match(s.lower()))


def detect_ci_binding() -> Optional[Dict[str, Any]]:
    """Detect CI environment and return a ci_binding dict, or None if local."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        sha = os.environ.get("GITHUB_SHA")
        if not sha:
            # Required by schema; treat incomplete env as non-bound local context.
            return None
        if not _is_full_sha(sha):
            warnings.warn(
                f"GITHUB_SHA is not a full 40-char hex SHA ({sha!r}). "
                f"CI binding requires a full commit SHA (e.g. git rev-parse HEAD). "
                f"Skipping CI binding.",
                stacklevel=2,
            )
            return None

        binding: Dict[str, Any] = {
            "provider": "github_actions",
            "commit_sha": str(sha),
        }
        repo = os.environ.get("GITHUB_REPOSITORY")
        if repo:
            binding["repo"] = repo
        ref = os.environ.get("GITHUB_REF")
        if ref:
            binding["ref"] = ref
        run_id = os.environ.get("GITHUB_RUN_ID")
        if run_id:
            binding["run_id"] = str(run_id)
        run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
        if run_attempt:
            binding["run_attempt"] = str(run_attempt)
        workflow = os.environ.get("GITHUB_WORKFLOW_REF")
        if workflow:
            binding["workflow_ref"] = workflow
        actor = os.environ.get("GITHUB_ACTOR")
        if actor:
            binding["actor"] = actor
        return binding
    # Future: add GITLAB_CI, CIRCLECI detection here
    return None


def _sort_receipts(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort receipts by (run_id, seq, receipt_id) for deterministic ordering."""

    def sort_key(r: Dict[str, Any]):
        return (
            r.get("_trace_id", r.get("run_id", "")),
            r.get("seq", 0),
            r.get("receipt_id", ""),
        )

    return sorted(entries, key=sort_key)


def _receipt_run_id(entry: Dict[str, Any]) -> Optional[str]:
    """Return the canonical run identifier for a receipt, if present."""
    trace_id = entry.get("_trace_id")
    run_id = entry.get("run_id")
    if trace_id and run_id and trace_id != run_id:
        receipt_id = entry.get("receipt_id", "<unknown>")
        raise ValueError(
            f"Receipt {receipt_id} has conflicting run ids: "
            f"_trace_id={trace_id!r}, run_id={run_id!r}"
        )
    if trace_id:
        return str(trace_id)
    if run_id:
        return str(run_id)
    return None


def _assert_receipt_run_ids(
    entries: List[Dict[str, Any]], expected_run_id: str
) -> None:
    """Fail closed if a pack mixes receipts from multiple runs."""
    for entry in entries:
        entry_run_id = _receipt_run_id(entry)
        if entry_run_id and entry_run_id != expected_run_id:
            receipt_id = entry.get("receipt_id", "<unknown>")
            raise ValueError(
                f"Receipt {receipt_id} belongs to run {entry_run_id!r}; "
                f"expected {expected_run_id!r}"
            )


def _find_disallowed_receipt_types(
    entries: List[Dict[str, Any]],
    allowed_types: frozenset[str],
) -> List[tuple[int, str, str]]:
    """Return proof-pack receipt types that are outside the local allowlist."""
    unknown: List[tuple[int, str, str]] = []
    for index, entry in enumerate(entries):
        receipt_type = str(entry.get("type") or entry.get("receipt_type") or "")
        if receipt_type and not _is_allowed_proof_pack_receipt_type(
            receipt_type, allowed_types
        ):
            receipt_id = str(entry.get("receipt_id", "<unknown>"))
            unknown.append((index, receipt_id, receipt_type))
    return unknown


def _find_non_current_loom_receipt_types(
    entries: List[Dict[str, Any]],
) -> List[tuple[int, str, str]]:
    """Return Loom-family namespaced tokens that lack a current registry row."""
    unknown: List[tuple[int, str, str]] = []
    for index, entry in enumerate(entries):
        receipt_type = str(entry.get("type") or entry.get("receipt_type") or "")
        if _is_loom_namespaced_receipt_type(
            receipt_type
        ) and not _is_current_loom_receipt_type(receipt_type):
            receipt_id = str(entry.get("receipt_id", "<unknown>"))
            unknown.append((index, receipt_id, receipt_type))
    return unknown


def _is_loom_namespaced_receipt_type(receipt_type: str) -> bool:
    return receipt_type.startswith("loom.") and bool(
        _PROOF_PACK_NAMESPACED_TYPE_RE.match(receipt_type)
    )


def _is_current_loom_receipt_type(receipt_type: str) -> bool:
    return receipt_type in PROOF_PACK_CURRENT_LOOM_RECEIPT_TYPES


def _unsupported_loom_receipt_type_message(receipt_type: str) -> str:
    current_tokens = ", ".join(sorted(PROOF_PACK_CURRENT_LOOM_RECEIPT_TYPES)) or "none"
    return (
        f"Loom receipt type {receipt_type!r} is not admitted into the proof-pack kernel. "
        "Only rows marked `current` in docs/specs/LOOM_RECEIPT_MAPPING_REGISTRY_V1.md "
        f"may enter proof packs (current Loom proof-pack tokens: {current_tokens})."
    )


def _unsupported_receipt_type_message(
    receipt_type: str,
    allowed_types: frozenset[str],
) -> str:
    if _is_loom_namespaced_receipt_type(receipt_type):
        return _unsupported_loom_receipt_type_message(receipt_type)
    allowed = ", ".join(sorted(allowed_types))
    return f"type {receipt_type!r} not in allowed types: {allowed}"


def _is_allowed_proof_pack_receipt_type(
    receipt_type: str,
    allowed_types: frozenset[str],
) -> bool:
    if receipt_type in allowed_types:
        return True
    if not _PROOF_PACK_NAMESPACED_TYPE_RE.match(receipt_type):
        return False
    if _is_loom_namespaced_receipt_type(receipt_type):
        return _is_current_loom_receipt_type(receipt_type)
    return True


def _assert_registered_loom_receipt_types(entries: List[Dict[str, Any]]) -> None:
    """Fail closed on Loom-family tokens without a current registry row."""
    unknown = _find_non_current_loom_receipt_types(entries)
    if unknown:
        raise ValueError(
            "Unsupported proof-pack Loom receipt type(s): "
            + ", ".join(
                f"{receipt_id}@{index}={_unsupported_loom_receipt_type_message(receipt_type)}"
                for index, receipt_id, receipt_type in unknown
            )
        )


def _assert_allowed_receipt_types(
    entries: List[Dict[str, Any]],
    allowed_types: frozenset[str],
) -> None:
    """Fail closed on proof-pack receipt types outside the local allowlist."""
    unknown = _find_disallowed_receipt_types(entries, allowed_types)
    if unknown:
        raise ValueError(
            "Unsupported proof-pack receipt type(s): "
            + ", ".join(
                f"{receipt_id}@{index}={_unsupported_receipt_type_message(receipt_type, allowed_types)}"
                for index, receipt_id, receipt_type in unknown
            )
        )


def get_unsigned_sidecar_dir(pack_dir: Path) -> Path:
    """Return the directory that stores unsigned narrative sidecars."""
    return Path(pack_dir) / _UNSIGNED_SIDECAR_DIR


def get_pack_summary_path(pack_dir: Path, *, legacy_fallback: bool = True) -> Path:
    """Return the preferred PACK_SUMMARY path, falling back to legacy root."""
    sidecar = get_unsigned_sidecar_dir(pack_dir) / "PACK_SUMMARY.md"
    if sidecar.exists() or not legacy_fallback:
        return sidecar
    return Path(pack_dir) / "PACK_SUMMARY.md"


def get_decision_credential_path(
    pack_dir: Path, *, legacy_fallback: bool = True
) -> Path:
    """Return the preferred decision credential path, falling back to legacy root."""
    sidecar = get_unsigned_sidecar_dir(pack_dir) / "decision_credential.json"
    if sidecar.exists() or not legacy_fallback:
        return sidecar
    return Path(pack_dir) / "decision_credential.json"


# ---------------------------------------------------------------------------
# Transcript generator
# ---------------------------------------------------------------------------


def _generate_transcript(
    pack_id: str,
    attestation: Dict[str, Any],
    verify_result: VerifyResult,
    version: str,
    claim_result: Optional[ClaimSetResult] = None,
    *,
    generated_at: Optional[str] = None,
) -> str:
    """Generate verify_transcript.md from attestation and verification results."""
    errors_section = "None"
    if verify_result.errors:
        lines = []
        for e in verify_result.errors:
            loc = f" (receipt {e.receipt_index})" if e.receipt_index is not None else ""
            lines.append(f"- **{e.code}**{loc}: {e.message}")
        errors_section = "\n".join(lines)

    warnings_section = "None"
    if verify_result.warnings:
        warnings_section = "\n".join(f"- {w}" for w in verify_result.warnings)

    ts_start = attestation.get("timestamp_start", "N/A")
    ts_end = attestation.get("timestamp_end", "N/A")

    claim_section = "No claim set provided."
    if claim_result is not None:
        claim_lines = [
            f"- Verdict: **{'PASS' if claim_result.passed else 'FAIL'}**",
            f"- Claims evaluated: {claim_result.n_claims}",
            f"- Passed: {claim_result.n_passed}",
            f"- Failed: {claim_result.n_failed}",
            f"- Discrepancy fingerprint: `{claim_result.discrepancy_fingerprint}`",
        ]
        failed_claims = [r for r in claim_result.results if not r.passed]
        if failed_claims:
            claim_lines.append("")
            claim_lines.append("### Failed Claims")
            for result in failed_claims:
                claim_lines.append(
                    f"- **{result.claim_id}** ({result.severity}): "
                    f"expected {result.expected}; actual {result.actual}"
                )
        else:
            claim_lines.append("")
            claim_lines.append("No failing claims.")
        claim_section = "\n".join(claim_lines)

    return f"""# Proof Pack Verification Transcript

## Attestation

| Field | Value |
|-------|-------|
| Pack ID | `{pack_id}` |
| Run ID | `{attestation.get("run_id", "N/A")}` |
| Receipt Integrity | **{attestation.get("receipt_integrity", "N/A")}** |
| Claim Check | {attestation.get("claim_check", "N/A")} |
| Assurance Level | {attestation.get("assurance_level", "N/A")} |
| Mode | {attestation.get("mode", "N/A")} |
| Receipts | {attestation.get("n_receipts", 0)} |
| Head Hash | `{attestation.get("head_hash", "N/A")}` |
| Policy Hash | `{attestation.get("policy_hash", "N/A")}` |
| Suite ID | `{attestation.get("suite_id", "N/A")}` |
| Time Range | {ts_start} to {ts_end} |

## Verification Errors

{errors_section}

## Verification Warnings

{warnings_section}

## Claim Verification

{claim_section}

---
Generated by [Assay](https://github.com/Haserjian/assay) {version} at {generated_at or datetime.now(timezone.utc).isoformat()}
Verify: `assay verify-pack <pack_dir>` | [Verify in browser](https://haserjian.github.io/assay-proof-gallery/verify.html)

**Received this proof pack?** [How to verify in 60 seconds](https://haserjian.github.io/assay-proof-gallery/verify.html) — no install, no account.
"""


# ---------------------------------------------------------------------------
# ProofPack builder
# ---------------------------------------------------------------------------


class ProofPack:
    """Builds the 5-file Proof Pack v0 kernel."""

    def __init__(
        self,
        trace_id: Optional[str] = None,
        entries: Optional[List[Dict[str, Any]]] = None,
        *,
        run_id: Optional[str] = None,
        signer_id: str = DEFAULT_SIGNER_ID,
        policy_hash: Optional[str] = None,
        suite_id: str = "manual",
        suite_hash: Optional[str] = None,
        claim_set_id: str = "none",
        claim_set_hash: Optional[str] = None,
        claims: Optional[List[ClaimSpec]] = None,
        mode: str = "shadow",
        ci_binding: Optional[Dict[str, Any]] = None,
        valid_until: Optional[str] = None,
        superseded_by: Optional[str] = None,
        emit_adc: bool = False,
        claim_namespace: Optional[str] = None,
        authority_snapshot: Optional[Dict[str, Any]] = None,
    ):
        # run_id is canonical; trace_id accepted as alias for backward compat
        resolved_run_id = run_id or trace_id
        if not resolved_run_id:
            raise ValueError("run_id (or trace_id) is required")
        self.run_id = resolved_run_id
        self.entries = entries or []
        self.signer_id = signer_id
        self.mode = mode
        self.claims = claims
        self.ci_binding = ci_binding
        self.valid_until = valid_until
        self.superseded_by = superseded_by
        self.emit_adc = emit_adc
        self.claim_namespace = claim_namespace
        self.authority_snapshot = authority_snapshot

        # Default hashes for fields not yet wired
        self.policy_hash = policy_hash or _sha256_hex(b"default-policy-v0")
        self.suite_id = suite_id
        self.suite_hash = suite_hash or _sha256_hex(suite_id.encode())
        self.claim_set_id = claim_set_id

        # When claims are provided, compute real claim_set_hash from specs
        if claims and not claim_set_hash:
            specs = [c.to_dict() for c in claims]
            self.claim_set_hash = _sha256_hex(jcs_canonicalize(specs))
        else:
            self.claim_set_hash = claim_set_hash or _sha256_hex(claim_set_id.encode())

    def build(
        self,
        output_dir: Path,
        keystore: Optional[AssayKeyStore] = None,
        *,
        pack_id: Optional[str] = None,
        deterministic_ts: Optional[str] = None,
        receipt_type_allowlist: Optional[frozenset[str]] = None,
    ) -> Path:
        """Build the 5-file Proof Pack to output_dir.

        Args:
            pack_id: Explicit pack ID.  When omitted, one is generated
                     (random in production, content-addressed if
                     deterministic_ts is also set).
            deterministic_ts: Fixed ISO-8601 timestamp for all
                              time-dependent fields.  Used by
                              conformance corpus generation to ensure
                              bit-identical rebuilds.
            receipt_type_allowlist: Optional fail-closed type policy for
                              proof-pack-aware callers. When provided,
                              all receipts must use an allowed type.

        Returns output_dir on success.
        """
        ks = keystore or get_default_keystore()
        output_dir = Path(output_dir)
        if output_dir.exists():
            raise FileExistsError(
                f"Pack output directory already exists: {output_dir}. "
                f"Remove it first or use a fresh path."
            )
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        # Stage in a temp directory; publish atomically via rename.
        staging_dir = Path(
            tempfile.mkdtemp(
                dir=output_dir.parent,
                prefix=".assay_pack_staging_",
            )
        )
        try:
            return self._build_into(
                staging_dir,
                output_dir,
                ks,
                pack_id=pack_id,
                deterministic_ts=deterministic_ts,
                receipt_type_allowlist=receipt_type_allowlist,
            )
        except BaseException:
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise

    def _build_into(
        self,
        staging_dir: Path,
        output_dir: Path,
        ks: AssayKeyStore,
        *,
        pack_id: Optional[str],
        deterministic_ts: Optional[str],
        receipt_type_allowlist: Optional[frozenset[str]],
    ) -> Path:
        """Build pack files into staging_dir, then publish to output_dir."""
        build_ts = deterministic_ts or datetime.now(timezone.utc).isoformat()
        resolved_ci_binding = (
            self.ci_binding if self.ci_binding is not None else detect_ci_binding()
        )

        sorted_entries = _sort_receipts(self.entries)
        _assert_receipt_run_ids(sorted_entries, self.run_id)
        _assert_registered_loom_receipt_types(sorted_entries)
        if receipt_type_allowlist is not None:
            _assert_allowed_receipt_types(sorted_entries, receipt_type_allowlist)

        # 1. Write receipt_pack.jsonl (canonical, deterministic order).
        # JSONL invariant: one JCS-canonical JSON object per line, no blank
        # lines.  Non-empty packs end with exactly one trailing newline.
        # Empty packs produce a 0-byte file (no newline).
        # Verifier counts non-empty lines (line.strip()).
        receipt_lines = []
        for entry in sorted_entries:
            canonical = jcs_canonicalize(prepare_receipt_for_hashing(entry)).decode(
                "utf-8"
            )
            receipt_lines.append(canonical)
        receipt_pack_content = "\n".join(receipt_lines) + "\n" if receipt_lines else ""
        receipt_pack_bytes = receipt_pack_content.encode("utf-8")
        if pack_id is None:
            seed = (
                _build_deterministic_pack_seed(
                    run_id=self.run_id,
                    receipt_pack_bytes=receipt_pack_bytes,
                    policy_hash=self.policy_hash,
                    suite_hash=self.suite_hash,
                    claim_set_id=self.claim_set_id,
                    claim_set_hash=self.claim_set_hash,
                    mode=self.mode,
                    ci_binding=resolved_ci_binding,
                    valid_until=self.valid_until,
                    superseded_by=self.superseded_by,
                )
                if deterministic_ts
                else None
            )
            pack_id = _generate_pack_id(deterministic_seed=seed)
        (staging_dir / "receipt_pack.jsonl").write_bytes(receipt_pack_bytes)

        # 2. Verify receipts (structural integrity)
        verify_result = verify_receipt_pack(sorted_entries)

        # 2b. Verify claims (semantic) if claims provided
        claim_result: Optional[ClaimSetResult] = None
        if self.claims:
            claim_result = verify_claims(
                sorted_entries,
                self.claims,
                policy_hash=self.policy_hash,
                suite_hash=self.suite_hash,
            )

        # 3. Build verify_report.json
        report: Dict[str, Any] = {
            "pack_id": pack_id,
            "run_id": self.run_id,
            **verify_result.to_dict(),
            "verified_at": build_ts,
            "verifier_version": _assay_version,
        }
        if claim_result is not None:
            report["claim_verification"] = claim_result.to_dict()
        report_bytes = json.dumps(report, indent=2).encode("utf-8")
        (staging_dir / "verify_report.json").write_bytes(report_bytes)

        # 4. Build attestation object
        timestamps: List[str] = []
        for entry in sorted_entries:
            ts = entry.get("timestamp") or entry.get("_stored_at")
            if ts:
                timestamps.append(str(ts))

        ts_start = min(timestamps) if timestamps else None
        ts_end = max(timestamps) if timestamps else None

        attestation = {
            "pack_format_version": "0.1.0",
            "fingerprint_version": 1,
            "pack_id": pack_id,
            "run_id": self.run_id,
            "suite_id": self.suite_id,
            "suite_hash": self.suite_hash,
            "verifier_version": _assay_version,
            "canon_version": "jcs-rfc8785",
            "canon_impl": "receipts.jcs",
            "canon_impl_version": _assay_version,
            "policy_hash": self.policy_hash,
            "claim_set_id": self.claim_set_id,
            "claim_set_hash": self.claim_set_hash,
            "receipt_integrity": "PASS" if verify_result.passed else "FAIL",
            "claim_check": ("PASS" if claim_result.passed else "FAIL")
            if claim_result is not None
            else "N/A",
            "discrepancy_fingerprint": (claim_result.discrepancy_fingerprint)
            if claim_result is not None
            else None,
            "assurance_level": "L0",
            "proof_tier": "signed-pack",
            "mode": self.mode,
            "head_hash": verify_result.head_hash or _sha256_hex(b"empty"),
            "head_hash_algorithm": "last-receipt-digest-v0",
            "time_authority": "local_clock",
            "n_receipts": verify_result.receipt_count,
            "timestamp_start": ts_start or build_ts,
            "timestamp_end": ts_end or build_ts,
            "ci_binding": resolved_ci_binding,
            "valid_until": self.valid_until,
            "superseded_by": self.superseded_by,
        }

        # 5. Build verify_transcript.md
        transcript = _generate_transcript(
            pack_id,
            attestation,
            verify_result,
            _assay_version,
            claim_result=claim_result,
            generated_at=build_ts,
        )
        transcript_bytes = transcript.encode("utf-8")
        (staging_dir / "verify_transcript.md").write_bytes(transcript_bytes)

        # 6. Build unsigned manifest
        attestation_bytes = jcs_canonicalize(attestation)
        attestation_sha256 = _sha256_hex(attestation_bytes)

        files_list = [
            {
                "path": "receipt_pack.jsonl",
                "sha256": _sha256_hex(receipt_pack_bytes),
                "bytes": len(receipt_pack_bytes),
            },
            {
                "path": "verify_report.json",
                "sha256": _sha256_hex(report_bytes),
                "bytes": len(report_bytes),
            },
            {
                "path": "verify_transcript.md",
                "sha256": _sha256_hex(transcript_bytes),
                "bytes": len(transcript_bytes),
            },
        ]

        # All 5 expected files in the pack directory.
        # pack_manifest.json and pack_signature.sig cannot be in the
        # hash-covered `files` array: the manifest can't contain its own
        # hash, and pack_signature.sig is produced AFTER the manifest is
        # signed (circular dependency).  Their integrity is instead
        # protected by the Ed25519 signature and the detached-sig parity
        # check in verify_pack_manifest.
        expected_files = [
            "receipt_pack.jsonl",
            "verify_report.json",
            "verify_transcript.md",
            "pack_manifest.json",
            "pack_signature.sig",
        ]

        # 6b. Embed signer's public key fingerprint for offline verification.
        # Ed25519 public keys are 32 bytes; no reason not to include the full
        # key so packs are self-contained evidence objects.
        # Ensure key exists before reading pubkey (sign_b64 would create it
        # via ensure_key, but get_verify_key reads directly and would crash).
        ks.ensure_key(self.signer_id)
        vk = ks.get_verify_key(self.signer_id)
        pubkey_bytes = vk.encode()

        unsigned_manifest = {
            "pack_id": pack_id,
            "pack_version": "0.1.0",
            "manifest_version": "1.0.0",
            "hash_alg": "sha256",
            "attestation": attestation,
            "attestation_sha256": attestation_sha256,
            "suite_hash": self.suite_hash,
            "claim_set_id": self.claim_set_id,
            "claim_set_hash": self.claim_set_hash,
            "receipt_count_expected": len(sorted_entries),
            "files": files_list,
            "expected_files": expected_files,
            "signer_id": self.signer_id,
            "signer_pubkey": base64.b64encode(pubkey_bytes).decode("ascii"),
            "signer_pubkey_sha256": _sha256_hex(pubkey_bytes),
            "signature_alg": "ed25519",
            "signature_scope": "JCS(pack_manifest_excluding_signature_and_pack_root_sha256)",
        }

        from assay.manifest_schema import validate_attestation, validate_manifest

        attestation_errors = validate_attestation(attestation)
        if attestation_errors:
            raise ValueError(
                f"Built attestation fails schema validation: {attestation_errors[0]}"
            )

        # 7. Sign: JCS(unsigned_manifest) -> Ed25519
        # NORMATIVE: The signing base is JCS(unsigned_manifest), where
        # unsigned_manifest does NOT contain "signature" or
        # "pack_root_sha256".  Those fields are added AFTER signing.
        # The "signature_scope" field in the manifest is descriptive
        # only — verifiers must use the contract-defined exclusion set
        # {"signature", "pack_root_sha256"}, not the field value.
        canonical_unsigned = jcs_canonicalize(unsigned_manifest)
        signature_b64 = ks.sign_b64(canonical_unsigned, self.signer_id)

        # 8. Create signed manifest.
        # D12: pack_root_sha256 = attestation_sha256, making the attestation
        # the single immutable identifier for the evidence unit.
        pack_root_sha256 = attestation_sha256
        signed_manifest = {
            **unsigned_manifest,
            "signature": signature_b64,
            "pack_root_sha256": pack_root_sha256,
        }

        # 8b. Schema validation (build-time enforcement)
        schema_errors = validate_manifest(signed_manifest)
        if schema_errors:
            raise ValueError(
                f"Built manifest fails schema validation: {schema_errors[0]}"
            )

        # pack_manifest.json is stored as readable JSON, but the signature
        # covers JCS(unsigned_manifest), not the raw file bytes.
        manifest_bytes = json.dumps(signed_manifest, indent=2).encode("utf-8")
        (staging_dir / "pack_manifest.json").write_bytes(manifest_bytes)

        # 9. Write detached signature
        sig_raw = base64.b64decode(signature_b64)
        (staging_dir / "pack_signature.sig").write_bytes(sig_raw)

        # 9b. Emit ADC (optional, presentation layer alongside PACK_SUMMARY)
        if self.emit_adc:
            from assay.adc_emitter import build_adc

            unsigned_dir = get_unsigned_sidecar_dir(staging_dir)
            unsigned_dir.mkdir(parents=True, exist_ok=True)
            ns = self.claim_namespace
            if ns is None:
                ns = (
                    f"assay:{self.suite_id}"
                    if self.suite_id != "manual"
                    else "assay:pack:v0.1"
                )

            cids = (
                [c.claim_id for c in self.claims] if self.claims else ["pack_integrity"]
            )

            adc = build_adc(
                issuer_id=self.signer_id,
                signer_pubkey=signed_manifest["signer_pubkey"],
                signer_pubkey_sha256=signed_manifest["signer_pubkey_sha256"],
                claim_namespace=ns,
                claim_ids=cids,
                evidence_manifest_sha256=pack_root_sha256,
                evidence_pack_id=pack_id,
                evidence_n_receipts=attestation["n_receipts"],
                evidence_head_hash=attestation["head_hash"],
                policy_id=self.claim_set_id,
                policy_hash=self.policy_hash,
                integrity_passed=verify_result.passed,
                claim_result=claim_result,
                issued_at=build_ts,
                evidence_observed_at=attestation.get("timestamp_start"),
                evaluated_at=report["verified_at"],
                valid_until=self.valid_until,
                authority_snapshot=self.authority_snapshot,
                sign_fn=lambda data: ks.sign_b64(data, self.signer_id),
            )
            adc_bytes = json.dumps(adc, indent=2).encode("utf-8")
            get_decision_credential_path(
                staging_dir, legacy_fallback=False
            ).write_bytes(adc_bytes)

        # 10. Write PACK_SUMMARY.md (presentation layer, not part of
        # the 5-file verification kernel). Safe to import here since
        # explain has no dependency on proof_pack.
        try:
            from assay.explain import explain_pack, render_md

            unsigned_dir = get_unsigned_sidecar_dir(staging_dir)
            unsigned_dir.mkdir(parents=True, exist_ok=True)
            info = explain_pack(staging_dir)
            summary = render_md(info)
            get_pack_summary_path(staging_dir, legacy_fallback=False).write_text(
                summary, encoding="utf-8"
            )
        except Exception as exc:
            warnings.warn(f"PACK_SUMMARY generation failed: {exc}", stacklevel=2)

        # 11. Atomic publication: rename staging dir to final output_dir.
        os.rename(str(staging_dir), str(output_dir))
        return output_dir


def build_proof_pack(
    trace_id: str,
    output_dir: Optional[Path] = None,
    *,
    keystore: Optional[AssayKeyStore] = None,
    mode: str = "shadow",
    claims: Optional[List[ClaimSpec]] = None,
    ci_binding: Optional[Dict[str, Any]] = None,
    authority_snapshot: Optional[Dict[str, Any]] = None,
) -> Path:
    """Convenience function: load trace from store and build a Proof Pack.

    Args:
        trace_id: The trace to package.
        output_dir: Where to write the 5 files (default: proof_pack_{trace_id}/).
        keystore: Optional key store (default: ~/.assay/keys/).
        mode: shadow | enforced | breakglass.
        claims: Optional list of ClaimSpecs for semantic verification.

    Returns:
        Path to the output directory.
    """
    from assay.store import get_default_store

    store = get_default_store()
    entries = store.read_trace(trace_id)
    if not entries:
        raise ValueError(f"Trace not found: {trace_id}")

    if output_dir is None:
        output_dir = Path(f"proof_pack_{trace_id}")

    if ci_binding is None:
        ci_binding = detect_ci_binding()

    pack = ProofPack(
        run_id=trace_id,
        entries=entries,
        mode=mode,
        claims=claims,
        ci_binding=ci_binding,
        authority_snapshot=authority_snapshot,
    )
    return pack.build(output_dir, keystore=keystore)


def verify_proof_pack(
    manifest: Dict[str, Any],
    pack_dir: Path,
    keystore: Optional[AssayKeyStore] = None,
    *,
    max_age_hours: Optional[float] = None,
    max_future_hours: float = 24.0,
    now: Optional[datetime] = None,
    require_ci_binding: bool = False,
    expected_commit_sha: Optional[str] = None,
) -> VerifyResult:
    """Verify a proof pack with the generic verifier plus proof-pack policy."""
    result = verify_pack_manifest(
        manifest,
        pack_dir,
        keystore,
        max_age_hours=max_age_hours,
        max_future_hours=max_future_hours,
        now=now,
        require_ci_binding=require_ci_binding,
        expected_commit_sha=expected_commit_sha,
    )
    if not result.passed:
        return result

    receipt_pack_path = Path(pack_dir) / "receipt_pack.jsonl"
    try:
        lines = receipt_pack_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return VerifyResult(
            passed=False,
            errors=[
                VerifyError(
                    code=E_MANIFEST_TAMPER,
                    message=f"Cannot read receipt_pack.jsonl for proof-pack policy check: {exc}",
                    field="receipt_pack.jsonl",
                ),
            ],
            warnings=result.warnings,
            receipt_count=result.receipt_count,
            head_hash=result.head_hash,
            stages=result.stages,
        )

    parsed: List[Dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError as exc:
            return VerifyResult(
                passed=False,
                errors=[
                    VerifyError(
                        code=E_MANIFEST_TAMPER,
                        message=f"Invalid JSON in receipt_pack.jsonl at line {line_no}: {exc.msg}",
                        field="receipt_pack.jsonl",
                    ),
                ],
                warnings=result.warnings,
                receipt_count=result.receipt_count,
                head_hash=result.head_hash,
                stages=result.stages,
            )

    disallowed = _find_disallowed_receipt_types(
        parsed, PROOF_PACK_ALLOWED_RECEIPT_TYPES
    )
    if not disallowed:
        return result

    policy_errors = [
        VerifyError(
            code=E_SCHEMA_UNKNOWN,
            message=(
                f"{receipt_id}: "
                + _unsupported_receipt_type_message(
                    receipt_type,
                    PROOF_PACK_ALLOWED_RECEIPT_TYPES,
                )
            ),
            receipt_index=index,
            field="type",
        )
        for index, receipt_id, receipt_type in disallowed
    ]
    return VerifyResult(
        passed=False,
        errors=[*result.errors, *policy_errors],
        warnings=result.warnings,
        receipt_count=result.receipt_count,
        head_hash=result.head_hash,
        stages=result.stages,
    )


__all__ = [
    "ProofPack",
    "build_proof_pack",
    "detect_ci_binding",
    "get_decision_credential_path",
    "get_pack_summary_path",
    "get_unsigned_sidecar_dir",
    "verify_proof_pack",
]
