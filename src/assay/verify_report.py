"""Public verification report contract for Assay proof packs."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from assay._receipts.jcs import canonicalize as jcs_canonicalize

VERIFY_REPORT_SCHEMA_VERSION = "assay.verify_report.v0.1"
DEFAULT_VERIFY_POLICY_ID = "assay.verify_policy.v0.1"
DEFAULT_EVALUATION_PROFILE = "assay.verify_profile.integrity_required.v0.1"
DEFAULT_REQUIRED_CHANNELS = ["integrity"]
DEFAULT_OPTIONAL_CHANNELS = ["claim", "replay", "trust"]
_PUBLIC_REPLAY_VERDICTS = {"MATCH", "DIVERGE", "NOT_RUN"}


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
) -> list[str]:
    channels = []
    if claim_verdict == "NOT_EVALUATED":
        channels.append("claim")
    if replay_verdict == "NOT_RUN":
        channels.append("replay")
    if trust_verdict == "NOT_EVALUATED":
        channels.append("trust")
    return channels


def _overall_verdict(
    *,
    integrity_verdict: str,
    claim_verdict: str,
    replay_verdict: str,
    trust_verdict: str,
    unevaluated_channels: list[str],
) -> tuple[str, Optional[str], str]:
    if integrity_verdict == "TAMPERED":
        return "TAMPERED", "integrity", "integrity_verdict=TAMPERED"
    if trust_verdict == "UNTRUSTED":
        return "UNTRUSTED", "trust", "trust_verdict=UNTRUSTED"
    if replay_verdict == "DIVERGE":
        return "REPLAY_DIVERGED", "replay", "replay_verdict=DIVERGE"
    if claim_verdict == "HONEST_FAIL":
        return "HONEST_FAIL", "claim", "claim_verdict=HONEST_FAIL"
    if unevaluated_channels:
        return "PASS", None, "integrity_passed_optional_channels_not_evaluated"
    return "PASS", None, "all_evaluated_channels_passed"


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
        claim_verdict = "PASS" if getattr(claim_result, "passed", False) else "HONEST_FAIL"
    else:
        claim_verdict = _legacy_claim_check(claim_check or attestation.get("claim_check"))

    replay_verdict = _replay_verdict(replay_verdict)
    integrity_verdict = "PASS" if verify_result.passed else "TAMPERED"
    trust_verdict = _trust_verdict(trust_eval)
    unevaluated_channels = _unevaluated_channels(
        claim_verdict=claim_verdict,
        replay_verdict=replay_verdict,
        trust_verdict=trust_verdict,
    )
    overall, blocking_channel, overall_reason = _overall_verdict(
        integrity_verdict=integrity_verdict,
        claim_verdict=claim_verdict,
        replay_verdict=replay_verdict,
        trust_verdict=trust_verdict,
        unevaluated_channels=unevaluated_channels,
    )

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
        "overall_verdict": overall,
        "overall_reason": overall_reason,
        "blocking_channel": blocking_channel,
        "evaluation_profile": DEFAULT_EVALUATION_PROFILE,
        "required_channels": list(DEFAULT_REQUIRED_CHANNELS),
        "optional_channels": list(DEFAULT_OPTIONAL_CHANNELS),
        "unevaluated_channels": unevaluated_channels,
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
        "errors": [e.to_dict() for e in verify_result.errors],
        "warnings": list(verify_result.warnings),
        **legacy,
    }
    if claim_result is not None:
        report["claim_verification"] = claim_result.to_dict()
    return report
