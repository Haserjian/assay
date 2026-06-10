"""Public verification report contract for Assay proof packs."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from assay._receipts.jcs import canonicalize as jcs_canonicalize

VERIFY_REPORT_SCHEMA_VERSION = "assay.verify_report.v0.1"
DEFAULT_VERIFY_POLICY_ID = "assay.verify_policy.v0.1"
_PUBLIC_REPLAY_VERDICTS = {"MATCH", "DIVERGE", "NOT_RUN"}
_ALL_CHANNELS = ("integrity", "claim", "replay", "trust")

# ---------------------------------------------------------------------------
# Scope & Caveats vocabulary.
#
# Local to Assay's verifier output. This does NOT define estate-wide proof
# vocabulary; it only states what this verifier checked and what that check
# does not imply. A verdict must always carry its boundary: PASS must not
# imply output correctness, safety, legal compliance, policy fitness,
# instrumentation completeness, or signer authority beyond configured trust.
# ---------------------------------------------------------------------------
SCOPE_SCHEMA_VERSION = "assay.verify.scope.v1"

# What an intact-pack verification establishes (integrity channel PASS).
SCOPE_PROVES_INTEGRITY = (
    "pack_integrity",
    "receipt_sequence_integrity",
    "signature_validity",
)

# What no verification verdict establishes, ever.
SCOPE_DOES_NOT_PROVE = (
    "output_correctness",
    "output_safety",
    "business_policy_fitness",
    "legal_compliance",
    "instrumentation_completeness",
    "signer_authority_beyond_configured_trust",
)

_SCOPE_TAMPERED_NOTE = (
    "Integrity failed. Channel claims are unavailable because the evidence "
    "object is not intact."
)


def sha256_file(path: Path) -> str:
    """Return SHA-256 of a file's raw bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _legacy_claim_check(claim_check: Optional[str]) -> str:
    value = str(claim_check or "N/A").upper()
    if value == "PASS":
        return "PASS"
    if value == "FAIL":
        return "HONEST_FAIL"
    return "NOT_EVALUATED"


def _trust_verdict(trust_eval: Optional[Any]) -> str:
    if trust_eval is None:
        return "NOT_EVALUATED"
    authorization = getattr(trust_eval, "authorization", None)
    acceptance = getattr(trust_eval, "acceptance", None)
    auth_status = getattr(authorization, "status", None)
    decision = getattr(acceptance, "decision", None)
    if auth_status in {"unrecognized", "revoked"} or decision == "reject":
        return "UNTRUSTED"
    if decision == "accept" or auth_status == "authorized":
        return "PASS"
    return "NOT_EVALUATED"


def _replay_verdict(value: str) -> str:
    verdict = str(value or "NOT_RUN").upper()
    if verdict in _PUBLIC_REPLAY_VERDICTS:
        return verdict
    return "NOT_RUN"


def _unevaluated_channels(
    *,
    claim_verdict: str,
    replay_verdict: str,
    trust_verdict: str,
) -> tuple[str, ...]:
    channels = []
    if claim_verdict == "NOT_EVALUATED":
        channels.append("claim")
    if replay_verdict == "NOT_RUN":
        channels.append("replay")
    if trust_verdict == "NOT_EVALUATED":
        channels.append("trust")
    return tuple(channels)


def _required_channels(
    *,
    claim_verdict: str,
    replay_verdict: str,
    trust_verdict: str,
) -> tuple[str, ...]:
    channels = ["integrity"]
    if claim_verdict != "NOT_EVALUATED":
        channels.append("claim")
    if replay_verdict != "NOT_RUN":
        channels.append("replay")
    if trust_verdict != "NOT_EVALUATED":
        channels.append("trust")
    return tuple(channels)


def _optional_channels(required_channels: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        channel for channel in _ALL_CHANNELS if channel not in required_channels
    )


def _evaluation_profile(required_channels: tuple[str, ...]) -> str:
    return "_".join(required_channels) + "_required"


def _scope(
    *,
    integrity_verdict: str,
    claim_verdict: str,
    replay_verdict: str,
    trust_verdict: str,
) -> Dict[str, Any]:
    """Build the verifier boundary object from existing channel verdicts.

    Derives entirely from the channel truth computed elsewhere in this module;
    it is a restatement of what ran and what it implies, not a new verdict
    engine. On TAMPERED, `proves` collapses: a non-intact evidence object
    cannot support normal channel claims, only the tamper finding itself.
    """
    channels = {
        "integrity": "ran",
        "claim": "not_evaluated" if claim_verdict == "NOT_EVALUATED" else "ran",
        "replay": "ran" if replay_verdict in ("MATCH", "DIVERGE") else "not_run",
        "trust": "not_evaluated" if trust_verdict == "NOT_EVALUATED" else "ran",
    }

    scope: Dict[str, Any] = {
        "schema": SCOPE_SCHEMA_VERSION,
        "channels": channels,
        # Reserved for future, explicitly-versioned extensions. Empty and
        # non-normative: the core verifier ignores this field entirely.
        "extensions": {},
    }

    if integrity_verdict == "TAMPERED":
        scope["proves"] = ["tamper_evidence_detected"]
        scope["does_not_prove"] = [
            *SCOPE_PROVES_INTEGRITY,
            *SCOPE_DOES_NOT_PROVE,
        ]
        scope["note"] = _SCOPE_TAMPERED_NOTE
        return scope

    proves = list(SCOPE_PROVES_INTEGRITY)
    if claim_verdict != "NOT_EVALUATED":
        proves.append("claim_set_evaluated")
        if claim_verdict == "PASS":
            proves.append("claim_set_satisfied")
    if replay_verdict == "MATCH":
        proves.append("replay_match")
    if trust_verdict == "PASS":
        proves.append("signer_trust_policy_satisfied")

    scope["proves"] = proves
    scope["does_not_prove"] = list(SCOPE_DOES_NOT_PROVE)
    return scope


def _pass_reason(*, unevaluated_channels: tuple[str, ...]) -> str:
    if not unevaluated_channels:
        return "required_channels_passed"
    return (
        "required_channels_passed; optional_channels_not_evaluated="
        + ",".join(unevaluated_channels)
    )


def _overall_verdict(
    *,
    integrity_verdict: str,
    claim_verdict: str,
    replay_verdict: str,
    trust_verdict: str,
) -> tuple[str, Optional[str], str]:
    if integrity_verdict == "TAMPERED":
        return "TAMPERED", "integrity", "integrity_verdict=TAMPERED"
    if trust_verdict == "UNTRUSTED":
        return "UNTRUSTED", "trust", "trust_verdict=UNTRUSTED"
    if replay_verdict == "DIVERGE":
        return "REPLAY_DIVERGED", "replay", "replay_verdict=DIVERGE"
    if claim_verdict == "HONEST_FAIL":
        return "HONEST_FAIL", "claim", "claim_verdict=HONEST_FAIL"
    return "PASS", None, "all_required_channels_passed"


def _report_id(seed: Dict[str, Any]) -> str:
    return "vr_" + _sha256_hex(jcs_canonicalize(seed))[:20]


def _evidence_ref(kind: str, path: str, sha256: Optional[str]) -> Dict[str, Any]:
    return {"kind": kind, "path": path, "sha256": sha256}


def _check_row(name: str, verdict: str, *, detail: Optional[str] = None) -> Dict[str, Any]:
    row: Dict[str, Any] = {"name": name, "verdict": verdict}
    if detail:
        row["detail"] = detail
    return row


def _stage_verdict(stage_dict: Dict[str, Any]) -> str:
    if "passed" in stage_dict:
        return "PASS" if stage_dict.get("passed") else "TAMPERED"
    status = str(stage_dict.get("status") or "").lower()
    if status == "ok":
        return "PASS"
    if status == "skipped":
        return "NOT_EVALUATED"
    return "TAMPERED"


def build_verify_report(
    *,
    verify_result: Any,
    verified_at: str,
    verifier_name: str,
    verifier_version: str,
    manifest: Optional[Dict[str, Any]] = None,
    pack_dir: Optional[Path] = None,
    claim_result: Optional[Any] = None,
    claim_check: Optional[str] = None,
    pack_id: Optional[str] = None,
    run_id: Optional[str] = None,
    pack_root_sha256: Optional[str] = None,
    pack_manifest_sha256: Optional[str] = None,
    receipt_pack_sha256: Optional[str] = None,
    policy_id: str = DEFAULT_VERIFY_POLICY_ID,
    policy_sha256: Optional[str] = None,
    claim_set_id: Optional[str] = None,
    claim_set_hash: Optional[str] = None,
    replay_verdict: str = "NOT_RUN",
    trust_eval: Optional[Any] = None,
    verifier_config_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the public verify_report.json judgment envelope.

    The report preserves the legacy VerifyResult fields at top level for
    compatibility while adding separate verdict channels for consumers.
    """
    manifest = manifest or {}
    attestation = manifest.get("attestation", {}) if manifest else {}
    pack_dir = Path(pack_dir) if pack_dir is not None else None

    pack_id = pack_id or attestation.get("pack_id") or manifest.get("pack_id")
    run_id = run_id or attestation.get("run_id")
    pack_root_sha256 = pack_root_sha256 or manifest.get("pack_root_sha256")
    policy_sha256 = policy_sha256 or attestation.get("policy_hash")
    claim_set_id = claim_set_id or attestation.get("claim_set_id")
    claim_set_hash = claim_set_hash or attestation.get("claim_set_hash")

    if pack_manifest_sha256 is None and pack_dir is not None:
        manifest_path = pack_dir / "pack_manifest.json"
        if manifest_path.exists():
            pack_manifest_sha256 = sha256_file(manifest_path)

    if receipt_pack_sha256 is None and pack_dir is not None:
        receipt_path = pack_dir / "receipt_pack.jsonl"
        if receipt_path.exists():
            receipt_pack_sha256 = sha256_file(receipt_path)

    if claim_result is not None:
        claim_verdict = (
            "PASS" if getattr(claim_result, "passed", False) else "HONEST_FAIL"
        )
    else:
        claim_verdict = _legacy_claim_check(claim_check or attestation.get("claim_check"))

    replay_verdict = _replay_verdict(replay_verdict)
    integrity_verdict = "PASS" if verify_result.passed else "TAMPERED"
    trust_verdict = _trust_verdict(trust_eval)
    required_channels = _required_channels(
        claim_verdict=claim_verdict,
        replay_verdict=replay_verdict,
        trust_verdict=trust_verdict,
    )
    optional_channels = _optional_channels(required_channels)
    unevaluated_channels = _unevaluated_channels(
        claim_verdict=claim_verdict,
        replay_verdict=replay_verdict,
        trust_verdict=trust_verdict,
    )
    evaluation_profile = _evaluation_profile(required_channels)
    overall, blocking_channel, overall_reason = _overall_verdict(
        integrity_verdict=integrity_verdict,
        claim_verdict=claim_verdict,
        replay_verdict=replay_verdict,
        trust_verdict=trust_verdict,
    )
    if overall == "PASS":
        overall_reason = _pass_reason(unevaluated_channels=unevaluated_channels)

    evidence_refs = [
        _evidence_ref("pack_manifest", "pack_manifest.json", pack_manifest_sha256),
        _evidence_ref("receipt_pack", "receipt_pack.jsonl", receipt_pack_sha256),
    ]

    checks = []
    stages = list(getattr(verify_result, "stages", []) or [])
    if stages:
        for stage in stages:
            stage_dict = stage.to_dict() if hasattr(stage, "to_dict") else dict(stage)
            checks.append(
                _check_row(
                    str(stage_dict.get("stage") or stage_dict.get("name") or "unknown"),
                    _stage_verdict(stage_dict),
                    detail=stage_dict.get("reason"),
                )
            )
    else:
        checks.append(_check_row("receipt_pack_integrity", integrity_verdict))

    checks.append(_check_row("claim_check", claim_verdict))
    checks.append(_check_row("replay", replay_verdict))
    checks.append(_check_row("trust", trust_verdict))

    summary = {
        "integrity": (
            "Manifest, file hashes, and signatures verified."
            if integrity_verdict == "PASS"
            else "Evidence object integrity failed."
        ),
        "claim": {
            "PASS": "Evidence satisfied the evaluated claim set.",
            "HONEST_FAIL": "Evidence was intact but did not satisfy the claim set.",
            "NOT_EVALUATED": "No claim set was evaluated.",
        }[claim_verdict],
        "replay": {
            "MATCH": "Replay matched prior trace.",
            "DIVERGE": "Replay diverged from prior trace.",
            "NOT_RUN": "Replay was not run.",
            "N/A": "Replay was not requested.",
        }.get(replay_verdict, f"Replay verdict: {replay_verdict}."),
        "trust": {
            "PASS": "Signer and policy trust checks passed.",
            "UNTRUSTED": "Signer or workflow trust checks failed.",
            "NOT_EVALUATED": "Trust policy was not evaluated.",
        }[trust_verdict],
    }

    legacy = verify_result.to_dict()
    report: Dict[str, Any] = {
        "schema_version": VERIFY_REPORT_SCHEMA_VERSION,
        "report_id": _report_id(
            {
                "pack_root_sha256": pack_root_sha256,
                "verified_at": verified_at,
                "integrity_verdict": integrity_verdict,
                "claim_verdict": claim_verdict,
                "replay_verdict": replay_verdict,
                "trust_verdict": trust_verdict,
                "verifier_version": verifier_version,
            }
        ),
        "pack_id": pack_id,
        "run_id": run_id,
        "pack_root_sha256": pack_root_sha256,
        "pack_manifest_sha256": pack_manifest_sha256,
        "integrity_verdict": integrity_verdict,
        "claim_verdict": claim_verdict,
        "replay_verdict": replay_verdict,
        "trust_verdict": trust_verdict,
        "evaluation_profile": evaluation_profile,
        "required_channels": list(required_channels),
        "optional_channels": list(optional_channels),
        "unevaluated_channels": list(unevaluated_channels),
        "overall_verdict": overall,
        "overall_reason": overall_reason,
        "blocking_channel": blocking_channel,
        "verified_at": verified_at,
        "verifier": {
            "name": verifier_name,
            "version": verifier_version,
            "policy_id": policy_id,
        },
        "expectations": {
            "policy_id": policy_id,
            "policy_sha256": policy_sha256,
            "claim_set_id": claim_set_id,
            "claim_set_hash": claim_set_hash,
        },
        "verification_inputs_sha256": pack_root_sha256,
        "verifier_config_sha256": verifier_config_sha256,
        "provenance": attestation.get("ci_binding") or {},
        "evidence_refs": evidence_refs,
        "checks": checks,
        "summary": summary,
        "scope": _scope(
            integrity_verdict=integrity_verdict,
            claim_verdict=claim_verdict,
            replay_verdict=replay_verdict,
            trust_verdict=trust_verdict,
        ),
        "errors": [e.to_dict() for e in verify_result.errors],
        "warnings": list(verify_result.warnings),
        **legacy,
    }
    if claim_result is not None:
        report["claim_verification"] = claim_result.to_dict()
    return report
