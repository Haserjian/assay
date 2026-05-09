"""PR Gate packet, report, and signature verifier."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay.pr_gate.packet import (
    DEFAULT_CERTIFICATE_OIDC_ISSUER,
    DEFAULT_EXPECTED_SIGNER_IDENTITY,
    PACK_SCHEMA_VERSION,
    VERIFY_REPORT_SCHEMA_VERSION,
)
from assay.pr_gate.policy import (
    PolicyEvaluationError,
    compute_policy_sha256,
    evaluate_policy,
    load_policy,
)

VERIFY_RESULT = "ASSAY PR GATE VERIFIED"
CosignRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class PRGateInputError(ValueError):
    """Raised when verifier inputs cannot be read or parsed."""


class PRGateVerificationError(ValueError):
    """Raised when a PR Gate packet fails verification."""


def verify_pr_gate_packet(
    *,
    pack_dir: Path,
    report_path: Path,
    sigstore_path: Path,
    expected_identity: str = DEFAULT_EXPECTED_SIGNER_IDENTITY,
    certificate_oidc_issuer: str = DEFAULT_CERTIFICATE_OIDC_ISSUER,
    cosign_bin: str = "cosign",
    cosign_runner: Optional[CosignRunner] = None,
) -> Dict[str, Any]:
    """Verify a PR Gate proof-pack, report binding, and Sigstore signature."""
    expected_identity = _non_empty_string(expected_identity, "expected_identity")
    certificate_oidc_issuer = _non_empty_string(
        certificate_oidc_issuer, "certificate_oidc_issuer"
    )
    if cosign_runner is None:
        cosign_runner = _run_cosign

    pack_dir = pack_dir.resolve()
    manifest_path = pack_dir / "pack_manifest.json"
    manifest = _load_json_object(manifest_path, "pack manifest")
    report = _load_json_object(report_path, "verification report")
    signature_proof = _load_json_object(sigstore_path, "signature proof")

    _verify_signature_proof_metadata(
        report_path=report_path,
        signature_proof=signature_proof,
        expected_identity=expected_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )
    _verify_manifest(pack_dir=pack_dir, manifest=manifest)
    _verify_report_binding(
        pack_dir=pack_dir,
        manifest_path=manifest_path,
        manifest=manifest,
        report=report,
        expected_identity=expected_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )
    _verify_recomputed_decision(pack_dir=pack_dir, manifest=manifest, report=report)
    _verify_sigstore_bundle(
        report_path=report_path,
        sigstore_path=sigstore_path,
        expected_identity=expected_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
        cosign_bin=cosign_bin,
        cosign_runner=cosign_runner,
    )

    channels = _mapping(report.get("channels"), "report.channels")
    return {
        "command": "assay pr-gate verify",
        "status": "ok",
        "result": VERIFY_RESULT,
        "pack_root_sha256": report["pack_root_sha256"],
        "report_id": report.get("report_id"),
        "decision": report.get("overall_decision"),
        "recommended_action": report.get("recommended_action"),
        "channels": {
            "integrity": channels.get("integrity"),
            "claim": channels.get("claim"),
            "replay": channels.get("replay"),
            "trust_policy": channels.get("trust_policy"),
        },
        "expected_identity": expected_identity,
        "certificate_oidc_issuer": certificate_oidc_issuer,
    }


def render_verification_text(result: Mapping[str, Any]) -> str:
    """Render the reviewer-facing PR Gate verification summary."""
    channels = _mapping(result.get("channels"), "result.channels")
    return (
        f"Result: {result.get('result')}\n"
        f"Decision: {result.get('decision')}\n"
        f"Recommended action: {result.get('recommended_action')}\n"
        f"Integrity: {channels.get('integrity')}\n"
        f"Claim: {channels.get('claim')}\n"
        f"Replay: {channels.get('replay')}\n"
        f"Trust policy: {channels.get('trust_policy')}\n"
        "Signed by expected workflow:\n"
        f"{result.get('expected_identity')}"
    )


def _verify_manifest(*, pack_dir: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema_version") != PACK_SCHEMA_VERSION:
        raise PRGateVerificationError("pack manifest schema_version is not PR Gate v0.1")
    expected_files = _string_list(manifest.get("expected_files"), "manifest.expected_files")
    file_entries = _file_entries(manifest.get("files"))
    entry_paths = [entry["path"] for entry in file_entries]
    if sorted(expected_files) != sorted([*entry_paths, "pack_manifest.json"]):
        raise PRGateVerificationError("pack manifest expected_files does not match files")

    for relative_path in expected_files:
        _safe_pack_path(pack_dir, relative_path)

    for entry in file_entries:
        path = _safe_pack_path(pack_dir, entry["path"])
        actual_bytes = path.read_bytes()
        actual_sha256 = _sha256_prefixed(actual_bytes)
        if entry["sha256"] != actual_sha256:
            raise PRGateVerificationError(f"proof-pack file hash mismatch: {entry['path']}")
        if "bytes" in entry and entry["bytes"] != len(actual_bytes):
            raise PRGateVerificationError(f"proof-pack file byte count mismatch: {entry['path']}")

    expected_root = _non_empty_string(
        manifest.get("pack_root_sha256"), "manifest.pack_root_sha256"
    )
    manifest_without_root = dict(manifest)
    manifest_without_root.pop("pack_root_sha256", None)
    actual_root = _sha256_prefixed(jcs_canonicalize(manifest_without_root))
    if actual_root != expected_root:
        raise PRGateVerificationError("pack manifest root hash mismatch")


def _verify_report_binding(
    *,
    pack_dir: Path,
    manifest_path: Path,
    manifest: Mapping[str, Any],
    report: Mapping[str, Any],
    expected_identity: str,
    certificate_oidc_issuer: str,
) -> None:
    if report.get("schema_version") != VERIFY_REPORT_SCHEMA_VERSION:
        raise PRGateVerificationError("verify report schema_version is not PR Gate v0.1")
    if report.get("pack_root_sha256") != manifest.get("pack_root_sha256"):
        raise PRGateVerificationError("report pack_root_sha256 does not match manifest")
    actual_manifest_sha256 = _sha256_prefixed(manifest_path.read_bytes())
    if report.get("pack_manifest_sha256") != actual_manifest_sha256:
        raise PRGateVerificationError("report pack_manifest_sha256 does not match manifest")
    if report.get("subject") != manifest.get("subject"):
        raise PRGateVerificationError("report subject does not match manifest")
    if report.get("policy") != manifest.get("policy"):
        raise PRGateVerificationError("report policy does not match manifest")

    try:
        policy = load_policy(pack_dir / "policy.yml")
    except PolicyEvaluationError as exc:
        raise PRGateVerificationError(f"policy.yml cannot be evaluated: {exc}") from exc
    policy_ref = {
        "profile": policy.get("profile"),
        "policy_sha256": compute_policy_sha256(policy),
    }
    if report.get("policy") != policy_ref:
        raise PRGateVerificationError("report policy hash does not match policy.yml")

    signature_policy = _mapping(
        report.get("signature_policy"), "report.signature_policy"
    )
    if signature_policy.get("scheme") != "sigstore_keyless":
        raise PRGateVerificationError("unsupported report signature policy scheme")
    if signature_policy.get("required") is not True:
        raise PRGateVerificationError("report signature policy must be required")
    if signature_policy.get("expected_certificate_identity") != expected_identity:
        raise PRGateVerificationError("expected signer identity does not match report")
    if signature_policy.get("certificate_oidc_issuer") != certificate_oidc_issuer:
        raise PRGateVerificationError("certificate OIDC issuer does not match report")


def _verify_recomputed_decision(
    *, pack_dir: Path, manifest: Mapping[str, Any], report: Mapping[str, Any]
) -> None:
    evidence = _load_json_object(pack_dir / "pr_gate_evidence.json", "PR Gate evidence")
    decision = _load_json_object(pack_dir / "pr_gate_decision.json", "PR Gate decision")
    try:
        policy = load_policy(pack_dir / "policy.yml")
        expected_decision = evaluate_policy(evidence, policy)
    except PolicyEvaluationError as exc:
        raise PRGateVerificationError(
            f"decision cannot be recomputed from evidence and policy.yml: {exc}"
        ) from exc
    if jcs_canonicalize(decision) != jcs_canonicalize(expected_decision):
        raise PRGateVerificationError("decision does not match evidence and policy.yml")

    decision_ref = _mapping(manifest.get("decision_ref"), "manifest.decision_ref")
    if decision_ref.get("overall_decision") != decision.get("overall_decision"):
        raise PRGateVerificationError("manifest decision_ref does not match decision")
    if decision_ref.get("recommended_action") != decision.get("recommended_action"):
        raise PRGateVerificationError("manifest decision_ref does not match decision")
    if decision_ref.get("channels") != decision.get("channels"):
        raise PRGateVerificationError("manifest decision_ref does not match decision")

    for field in ("overall_decision", "recommended_action", "reasons", "channels"):
        if report.get(field) != decision.get(field):
            raise PRGateVerificationError(f"report {field} does not match decision")


def _verify_signature_proof_metadata(
    *,
    report_path: Path,
    signature_proof: Mapping[str, Any],
    expected_identity: str,
    certificate_oidc_issuer: str,
) -> None:
    status = signature_proof.get("signature_status")
    if status == "NOT_SIGNED":
        raise PRGateVerificationError("signature proof is not signed")
    if status is not None and status != "SIGNED":
        raise PRGateVerificationError(f"unsupported signature_status: {status!r}")

    report_hash = signature_proof.get("verify_report_sha256")
    if report_hash is not None and report_hash != _sha256_prefixed(report_path.read_bytes()):
        raise PRGateVerificationError("signature proof does not match verify_report.json")

    for key in ("certificate_identity", "expected_certificate_identity"):
        identity = signature_proof.get(key)
        if identity is not None and identity != expected_identity:
            raise PRGateVerificationError(
                "signature identity does not match expected signer identity"
            )
    issuer = signature_proof.get("certificate_oidc_issuer")
    if issuer is not None and issuer != certificate_oidc_issuer:
        raise PRGateVerificationError("signature OIDC issuer does not match expected issuer")


def _verify_sigstore_bundle(
    *,
    report_path: Path,
    sigstore_path: Path,
    expected_identity: str,
    certificate_oidc_issuer: str,
    cosign_bin: str,
    cosign_runner: CosignRunner,
) -> None:
    args = [
        cosign_bin,
        "verify-blob",
        str(report_path),
        "--bundle",
        str(sigstore_path),
        "--certificate-identity",
        expected_identity,
        "--certificate-oidc-issuer",
        certificate_oidc_issuer,
    ]
    try:
        result = cosign_runner(args)
    except FileNotFoundError as exc:
        raise PRGateInputError(f"cosign not found: {cosign_bin}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "cosign verify-blob failed").strip()
        raise PRGateVerificationError(f"sigstore verification failed: {detail}")


def _run_cosign(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def _load_json_object(path: Path, label: str) -> Dict[str, Any]:
    if not path.exists():
        raise PRGateInputError(f"{label} not found: {path}")
    if not path.is_file():
        raise PRGateInputError(f"{label} path is not a file: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PRGateInputError(f"failed to parse {label} JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise PRGateInputError(f"{label} must be a JSON object")
    return raw


def _safe_pack_path(pack_dir: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise PRGateVerificationError("proof-pack file path must be a non-empty string")
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise PRGateVerificationError(f"unsafe proof-pack path: {relative_path}")
    resolved = (pack_dir / candidate).resolve()
    try:
        resolved.relative_to(pack_dir)
    except ValueError as exc:
        raise PRGateVerificationError(f"unsafe proof-pack path: {relative_path}") from exc
    if not resolved.exists():
        raise PRGateVerificationError(f"missing proof-pack file: {relative_path}")
    if not resolved.is_file():
        raise PRGateVerificationError(f"proof-pack path is not a file: {relative_path}")
    return resolved


def _file_entries(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        raise PRGateVerificationError("manifest.files must be a list")
    entries: List[Dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise PRGateVerificationError(f"manifest.files[{index}] must be a mapping")
        path = _non_empty_string(entry.get("path"), f"manifest.files[{index}].path")
        sha256 = _non_empty_string(entry.get("sha256"), f"manifest.files[{index}].sha256")
        if not sha256.startswith("sha256:"):
            raise PRGateVerificationError(f"manifest.files[{index}].sha256 must be prefixed")
        normalized = dict(entry)
        normalized["path"] = path
        normalized["sha256"] = sha256
        entries.append(normalized)
    return entries


def _string_list(raw: Any, label: str) -> List[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PRGateVerificationError(f"{label} must be a list of strings")
    return list(raw)


def _mapping(raw: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise PRGateVerificationError(f"{label} must be a mapping")
    return raw


def _non_empty_string(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise PRGateVerificationError(f"{label} must be a non-empty string")
    return raw


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


__all__ = [
    "DEFAULT_CERTIFICATE_OIDC_ISSUER",
    "DEFAULT_EXPECTED_SIGNER_IDENTITY",
    "PRGateInputError",
    "PRGateVerificationError",
    "VERIFY_RESULT",
    "render_verification_text",
    "verify_pr_gate_packet",
]
