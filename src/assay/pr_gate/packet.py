"""PR Gate proof-pack and Verification Report generator."""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Mapping

from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.pr_gate.policy import (
    compute_policy_sha256,
    evaluate_policy,
    load_evidence,
    load_policy,
)

PACK_SCHEMA_VERSION = "assay.pr_gate.pack_manifest.v0.1"
VERIFY_REPORT_SCHEMA_VERSION = "assay.pr_gate.verify_report.v0.1"
SIGNATURE_PROOF_SCHEMA_VERSION = "assay.pr_gate.signature_proof.v0.1"
DEFAULT_EXPECTED_SIGNER_IDENTITY = (
    "https://github.com/Haserjian/assay/.github/workflows/"
    "assay-pr-gate.yml@refs/heads/main"
)
DEFAULT_CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

PACK_FILES = (
    "pr_gate_evidence.json",
    "pr_gate_decision.json",
    "changed_files.json",
    "observed_checks.json",
    "policy.yml",
    "verify_transcript.md",
)

DO_NOT_INFER = (
    "code is secure",
    "all possible tests passed",
    "AI made a good design decision",
    "replay was performed",
    "production approval was granted",
)


class PacketError(ValueError):
    """Raised when PR Gate packet generation cannot bind inputs safely."""


def build_pr_gate_packet(
    *,
    evidence: Mapping[str, Any],
    decision: Mapping[str, Any],
    policy_path: Path,
    out_dir: Path,
    expected_identity: str = DEFAULT_EXPECTED_SIGNER_IDENTITY,
    certificate_oidc_issuer: str = DEFAULT_CERTIFICATE_OIDC_ISSUER,
) -> Dict[str, Any]:
    """Write a PR Gate proof-pack plus Verification Report.

    ``out_dir`` is the PR Gate artifact root. The function creates
    ``proof-pack/`` and ``signed-report/`` below it.
    """
    _validate_evidence(evidence)
    _validate_decision(decision)
    expected_identity = _string(expected_identity, "expected_identity")
    certificate_oidc_issuer = _string(
        certificate_oidc_issuer, "certificate_oidc_issuer"
    )
    policy = load_policy(policy_path)
    policy_ref = _policy_ref(policy)
    _validate_policy_binding(evidence, policy)
    _validate_decision_binding(evidence=evidence, decision=decision, policy=policy)

    proof_pack_dir = out_dir / "proof-pack"
    signed_report_dir = out_dir / "signed-report"
    _prepare_output_dir(proof_pack_dir)
    _prepare_output_dir(signed_report_dir)

    _write_json(proof_pack_dir / "pr_gate_evidence.json", evidence)
    _write_json(proof_pack_dir / "pr_gate_decision.json", decision)
    _write_json(proof_pack_dir / "changed_files.json", evidence.get("changed_files", []))
    _write_json(
        proof_pack_dir / "observed_checks.json",
        evidence.get("observed_checks", []),
    )
    shutil.copyfile(policy_path, proof_pack_dir / "policy.yml")
    (proof_pack_dir / "verify_transcript.md").write_text(
        render_verify_transcript(evidence=evidence, decision=decision),
        encoding="utf-8",
    )

    files = [_file_entry(proof_pack_dir / path, path) for path in PACK_FILES]
    manifest_without_root = _build_manifest_without_root(
        evidence=evidence,
        decision=decision,
        files=files,
        policy_ref=policy_ref,
    )
    pack_root_sha256 = _sha256_prefixed(jcs_canonicalize(manifest_without_root))
    manifest = {**manifest_without_root, "pack_root_sha256": pack_root_sha256}
    _write_json(proof_pack_dir / "pack_manifest.json", manifest)

    pack_manifest_sha256 = _sha256_prefixed((proof_pack_dir / "pack_manifest.json").read_bytes())
    verify_report = _build_verify_report(
        evidence=evidence,
        decision=decision,
        manifest=manifest,
        pack_manifest_sha256=pack_manifest_sha256,
        policy_ref=policy_ref,
        expected_identity=expected_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )
    _write_json(signed_report_dir / "verify_report.json", verify_report)

    verify_report_sha256 = _sha256_prefixed(
        (signed_report_dir / "verify_report.json").read_bytes()
    )
    signature_proof = {
        "schema_version": SIGNATURE_PROOF_SCHEMA_VERSION,
        "signature_status": "NOT_SIGNED",
        "reason": "PR Gate signing is deferred to the stable signer milestone.",
        "signed_artifact": "verify_report.json",
        "expected_certificate_identity": expected_identity,
        "certificate_oidc_issuer": certificate_oidc_issuer,
        "verify_report_sha256": verify_report_sha256,
    }
    _write_json(signed_report_dir / "verify_report.sigstore.json", signature_proof)

    return {
        "proof_pack_dir": str(proof_pack_dir),
        "signed_report_dir": str(signed_report_dir),
        "pack_manifest": manifest,
        "verify_report": verify_report,
        "signature_proof": signature_proof,
    }


def build_pr_gate_packet_files(
    *,
    evidence_path: Path,
    decision_path: Path,
    policy_path: Path,
    out_dir: Path,
    expected_identity: str = DEFAULT_EXPECTED_SIGNER_IDENTITY,
    certificate_oidc_issuer: str = DEFAULT_CERTIFICATE_OIDC_ISSUER,
) -> Dict[str, Any]:
    """Load files and write a PR Gate packet/report artifact tree."""
    return build_pr_gate_packet(
        evidence=load_evidence(evidence_path),
        decision=_load_decision(decision_path),
        policy_path=policy_path,
        out_dir=out_dir,
        expected_identity=expected_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )


def render_verify_transcript(
    *, evidence: Mapping[str, Any], decision: Mapping[str, Any]
) -> str:
    """Render a compact human transcript for the PR Gate proof-pack."""
    subject = _mapping(evidence.get("subject"), "evidence.subject")
    channels = _mapping(decision.get("channels"), "decision.channels")
    reasons = decision.get("reasons") or []
    reason_lines = "\n".join(
        f"- {json.dumps(reason, sort_keys=True)}" for reason in reasons
    ) or "- none"
    return (
        "# Assay PR Gate Verification Transcript\n\n"
        f"Repository: {subject.get('repo')}\n"
        f"PR: #{subject.get('pr_number')}\n"
        f"Head commit: {subject.get('head_sha')}\n"
        f"Diff hash: {subject.get('diff_sha256')}\n\n"
        f"Decision: {decision.get('overall_decision')}\n"
        f"Recommended action: {decision.get('recommended_action')}\n\n"
        "Verdict channels:\n"
        f"- Integrity: {channels.get('integrity')}\n"
        f"- Claim: {channels.get('claim')}\n"
        f"- Replay: {channels.get('replay')}\n"
        f"- Trust policy: {channels.get('trust_policy')}\n\n"
        "Reasons:\n"
        f"{reason_lines}\n\n"
        "Do not infer:\n"
        + "".join(f"- {item}\n" for item in DO_NOT_INFER)
    )


def _build_manifest_without_root(
    *,
    evidence: Mapping[str, Any],
    decision: Mapping[str, Any],
    files: List[Dict[str, Any]],
    policy_ref: Mapping[str, str],
) -> Dict[str, Any]:
    subject = _mapping(evidence.get("subject"), "evidence.subject")
    pack_seed = {
        "schema_version": PACK_SCHEMA_VERSION,
        "subject": subject,
        "policy": policy_ref,
        "decision": {
            "overall_decision": decision.get("overall_decision"),
            "recommended_action": decision.get("recommended_action"),
            "channels": decision.get("channels"),
        },
        "files": files,
    }
    pack_id = "prgate_pack_" + _sha256_hex(jcs_canonicalize(pack_seed))[:16]
    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "pack_id": pack_id,
        "subject": subject,
        "policy": dict(policy_ref),
        "decision_ref": {
            "overall_decision": decision.get("overall_decision"),
            "recommended_action": decision.get("recommended_action"),
            "channels": decision.get("channels"),
        },
        "files": files,
        "expected_files": [*PACK_FILES, "pack_manifest.json"],
        "hash_alg": "sha256",
        "canonicalization": "jcs-rfc8785",
    }


def _build_verify_report(
    *,
    evidence: Mapping[str, Any],
    decision: Mapping[str, Any],
    manifest: Mapping[str, Any],
    pack_manifest_sha256: str,
    policy_ref: Mapping[str, str],
    expected_identity: str,
    certificate_oidc_issuer: str,
) -> Dict[str, Any]:
    channels = _mapping(decision.get("channels"), "decision.channels")
    pack_root_sha256 = _string(manifest.get("pack_root_sha256"), "pack_root_sha256")
    report_seed = {
        "schema_version": VERIFY_REPORT_SCHEMA_VERSION,
        "pack_root_sha256": pack_root_sha256,
        "decision": decision,
    }
    report_id = "vr_" + _sha256_hex(jcs_canonicalize(report_seed))[:20]
    return {
        "schema_version": VERIFY_REPORT_SCHEMA_VERSION,
        "report_id": report_id,
        "pack_id": manifest.get("pack_id"),
        "pack_root_sha256": pack_root_sha256,
        "pack_manifest_sha256": pack_manifest_sha256,
        "subject": evidence.get("subject"),
        "capture": evidence.get("capture"),
        "policy": dict(policy_ref),
        "overall_decision": decision.get("overall_decision"),
        "recommended_action": decision.get("recommended_action"),
        "reasons": decision.get("reasons", []),
        "channels": {
            "integrity": channels.get("integrity"),
            "claim": channels.get("claim"),
            "replay": channels.get("replay"),
            "trust_policy": channels.get("trust_policy"),
        },
        "evidence_refs": [
            {
                "kind": "Evidence Box",
                "path": "proof-pack/pack_manifest.json",
                "sha256": pack_manifest_sha256,
            },
            {
                "kind": "Verification Report",
                "path": "signed-report/verify_report.json",
                "sha256": None,
            },
            {
                "kind": "Signature Proof",
                "path": "signed-report/verify_report.sigstore.json",
                "sha256": None,
            },
        ],
        "do_not_infer": list(DO_NOT_INFER),
        "signature_policy": {
            "scheme": "sigstore_keyless",
            "required": True,
            "expected_certificate_identity": expected_identity,
            "certificate_oidc_issuer": certificate_oidc_issuer,
        },
        "generator": {
            "name": "assay pr-gate pack",
            "version": "v0.1",
        },
    }


def _load_decision(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise PacketError(f"Decision file not found: {path}")
    if not path.is_file():
        raise PacketError(f"Decision path is not a file: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PacketError(f"Failed to parse decision JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise PacketError(f"Decision file must be a JSON object, got {type(raw).__name__}")
    _validate_decision(raw)
    return raw


def _validate_evidence(evidence: Mapping[str, Any]) -> None:
    subject = _mapping(evidence.get("subject"), "evidence.subject")
    for key in ("repo", "pr_number", "base_sha", "head_sha", "diff_sha256"):
        if key not in subject:
            raise PacketError(f"evidence.subject missing {key}")
    if not isinstance(evidence.get("changed_files", []), list):
        raise PacketError("evidence.changed_files must be a list")
    if not isinstance(evidence.get("observed_checks", []), list):
        raise PacketError("evidence.observed_checks must be a list")


def _validate_decision(decision: Mapping[str, Any]) -> None:
    for key in ("overall_decision", "recommended_action", "channels"):
        if key not in decision:
            raise PacketError(f"decision missing {key}")
    channels = _mapping(decision.get("channels"), "decision.channels")
    for key in ("integrity", "claim", "replay", "trust_policy"):
        if key not in channels:
            raise PacketError(f"decision.channels missing {key}")
    if not isinstance(decision.get("reasons", []), list):
        raise PacketError("decision.reasons must be a list")


def _validate_policy_binding(
    evidence: Mapping[str, Any], policy: Mapping[str, Any]
) -> None:
    evidence_policy = evidence.get("policy")
    if not isinstance(evidence_policy, Mapping):
        return
    profile = evidence_policy.get("profile")
    if profile is not None and profile != policy.get("profile"):
        raise PacketError("evidence policy profile does not match policy.yml")
    expected_hash = evidence_policy.get("policy_sha256")
    actual_hash = compute_policy_sha256(policy)
    if expected_hash is not None and expected_hash != actual_hash:
        raise PacketError("evidence policy_sha256 does not match policy.yml")


def _validate_decision_binding(
    *,
    evidence: Mapping[str, Any],
    decision: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    expected_decision = evaluate_policy(evidence, policy)
    if jcs_canonicalize(decision) != jcs_canonicalize(expected_decision):
        raise PacketError("decision does not match evidence and policy.yml")


def _policy_ref(policy: Mapping[str, Any]) -> Dict[str, str]:
    profile = policy.get("profile")
    if not isinstance(profile, str) or not profile:
        raise PacketError("policy.yml missing profile")
    return {
        "profile": profile,
        "policy_sha256": compute_policy_sha256(policy),
    }


def _prepare_output_dir(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        if not path.is_dir():
            raise PacketError(f"Output path is not a directory: {path}")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=False)


def _file_entry(path: Path, relative_path: str) -> Dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": relative_path,
        "sha256": _sha256_prefixed(data),
        "bytes": len(data),
    }


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _mapping(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise PacketError(f"{label} must be a mapping")
    return raw


def _string(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise PacketError(f"{label} must be a non-empty string")
    return raw


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + _sha256_hex(data)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "DO_NOT_INFER",
    "DEFAULT_CERTIFICATE_OIDC_ISSUER",
    "DEFAULT_EXPECTED_SIGNER_IDENTITY",
    "PACK_FILES",
    "PACK_SCHEMA_VERSION",
    "PacketError",
    "SIGNATURE_PROOF_SCHEMA_VERSION",
    "VERIFY_REPORT_SCHEMA_VERSION",
    "build_pr_gate_packet",
    "build_pr_gate_packet_files",
    "render_verify_transcript",
]
