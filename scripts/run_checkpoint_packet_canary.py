#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any, Dict, List, Sequence


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from assay import __version__ as ASSAY_VERSION
from assay import open_episode
from assay.checkpoint_reviewer_packet import CHECKPOINT_REVIEWER_PACKET_PROFILE
from assay.checkpoints import CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL, OutboundEmailCheckpointFlow
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.store import AssayStore


def _iso8601(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _git_value(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip() or "unknown"


def _assay_version() -> str:
    try:
        return package_version("assay-ai")
    except PackageNotFoundError:
        return ASSAY_VERSION


def _cli_env() -> Dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC) if not current else f"{SRC}{os.pathsep}{current}"
    return env


def _run_cli(args: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "assay.cli", *args],
        cwd=cwd,
        env=_cli_env(),
        capture_output=True,
        text=True,
    )


def _parse_cli_json(result: subprocess.CompletedProcess[str], *, label: str) -> Dict[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed with exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{label} returned non-JSON output\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        ) from exc


def _build_request(now: datetime) -> Dict[str, Any]:
    return {
        "subject": {
            "actor_id": "agent:customer_ops_assistant",
            "actor_type": "agent",
            "requester_id": "workflow:invoice_follow_up",
            "session_id": f"sess_{uuid.uuid4().hex[:8]}",
        },
        "attempt": {
            "intent_hash": _sha256_text(f"outbound-email-intent:{uuid.uuid4().hex}"),
            "intent": {
                "recipient": {
                    "value_ref": "secret://customer_email",
                    "domain": "example.com",
                    "contact_id": f"crm_contact_{uuid.uuid4().hex[:6]}",
                },
                "subject_ref": f"hash://{_sha256_text('invoice follow-up subject')}",
                "body_ref": f"hash://{_sha256_text('invoice follow-up body')}",
                "purpose": "follow_up_on_open_invoice",
            },
            "action_target": {
                "system": "gmail",
                "operation": "send_message",
            },
        },
        "relying_party": {
            "party_id": "team://ops_manager_17",
            "role": "approver",
            "consequence": "external customer communication",
            "disclosure_profile": "ops_manager_selective",
        },
        "requested_at": _iso8601(now),
    }


def _build_evaluation(now: datetime) -> Dict[str, Any]:
    recipient_observed_at = now - timedelta(minutes=5)
    auth_observed_at = now - timedelta(days=14)
    context_observed_at = now - timedelta(minutes=2)
    policy_observed_at = now + timedelta(seconds=1)
    evidence_valid_until = now + timedelta(hours=1)
    return {
        "shadow": {
            "required_evidence": [
                {
                    "kind": "recipient_verified",
                    "required": True,
                    "minimum_authority_level": "authoritative",
                    "max_age_seconds": 604800,
                },
                {
                    "kind": "contact_authorization",
                    "required": True,
                    "minimum_authority_level": "authoritative",
                    "max_age_seconds": None,
                },
                {
                    "kind": "fresh_context_snapshot",
                    "required": True,
                    "minimum_authority_level": "supportive",
                    "max_age_seconds": 86400,
                },
                {
                    "kind": "policy_match",
                    "required": True,
                    "minimum_authority_level": "authoritative",
                    "max_age_seconds": 3600,
                },
            ],
            "predicted_failure_modes": [
                {
                    "kind": "wrong_recipient",
                    "score": 0.17,
                    "rationale": "External send still depends on human approval despite strong CRM linkage.",
                },
                {
                    "kind": "thin_policy_margin",
                    "score": 0.24,
                    "rationale": "Collections follow-up is allowed, but only with explicit review.",
                },
            ],
            "predicted_uncertainty": {
                "support": 0.81,
                "freshness": 0.88,
                "consensus": 0.9,
                "policy_margin": 0.44,
            },
            "recommended_route": "review",
            "notes_ref": f"hash://{_sha256_text('checkpoint canary shadow notes')}",
        },
        "evidence_bundle": {
            "bundle_id": f"eb_{uuid.uuid4().hex[:12]}",
            "items": [
                {
                    "evidence_id": f"ev_{uuid.uuid4().hex[:8]}",
                    "kind": "recipient_verified",
                    "uri": "hash://crm_contact_record_v1",
                    "hash": _sha256_text("recipient_verified"),
                    "observed_at": _iso8601(recipient_observed_at),
                    "valid_until": _iso8601(now + timedelta(days=7)),
                    "sensitivity": "restricted",
                    "disclosure": "selective",
                    "authority_level": "authoritative",
                },
                {
                    "evidence_id": f"ev_{uuid.uuid4().hex[:8]}",
                    "kind": "contact_authorization",
                    "uri": "hash://consent_record_v3",
                    "hash": _sha256_text("contact_authorization"),
                    "observed_at": _iso8601(auth_observed_at),
                    "valid_until": None,
                    "sensitivity": "restricted",
                    "disclosure": "selective",
                    "authority_level": "authoritative",
                },
                {
                    "evidence_id": f"ev_{uuid.uuid4().hex[:8]}",
                    "kind": "fresh_context_snapshot",
                    "uri": "hash://ticket_context_snapshot_v2",
                    "hash": _sha256_text("fresh_context_snapshot"),
                    "observed_at": _iso8601(context_observed_at),
                    "valid_until": _iso8601(now + timedelta(days=1)),
                    "sensitivity": "internal",
                    "disclosure": "full",
                    "authority_level": "supportive",
                },
                {
                    "evidence_id": f"ev_{uuid.uuid4().hex[:8]}",
                    "kind": "policy_match",
                    "uri": "hash://policy_eval_input_v7",
                    "hash": _sha256_text("policy_match"),
                    "observed_at": _iso8601(policy_observed_at),
                    "valid_until": _iso8601(evidence_valid_until),
                    "sensitivity": "internal",
                    "disclosure": "full",
                    "authority_level": "authoritative",
                },
            ],
            "gaps": [],
            "contradictions": [],
        },
        "verifiers": [
            {
                "name": "guardian.recipient_verifier",
                "version": "0.1.0",
                "input_refs": ["recipient_verified"],
                "result": "pass",
                "reason_codes": ["recipient_matches_verified_contact"],
                "notes_ref": f"hash://{_sha256_text('recipient verifier notes')}",
            },
            {
                "name": "guardian.authorization_verifier",
                "version": "0.1.0",
                "input_refs": ["contact_authorization"],
                "result": "pass",
                "reason_codes": ["contact_authorization_current"],
                "notes_ref": f"hash://{_sha256_text('authorization verifier notes')}",
            },
            {
                "name": "guardian.freshness_verifier",
                "version": "0.1.0",
                "input_refs": ["fresh_context_snapshot"],
                "result": "pass",
                "reason_codes": ["context_within_freshness_window"],
                "notes_ref": f"hash://{_sha256_text('freshness verifier notes')}",
            },
            {
                "name": "guardian.policy_verifier",
                "version": "0.1.0",
                "input_refs": ["recipient_verified", "contact_authorization", "fresh_context_snapshot", "policy_match"],
                "result": "pass_with_warning",
                "reason_codes": ["sensitive_external_send", "collections_account_requires_review"],
                "notes_ref": f"hash://{_sha256_text('policy verifier notes')}",
            },
        ],
        "uncertainty": {
            "support": 0.89,
            "freshness": 0.93,
            "consensus": 0.82,
            "policy_margin": 0.41,
        },
        "policy": {
            "policy_id": "policy.outbound_email.default",
            "policy_version": "2026-03-19.1",
            "policy_hash": _sha256_text("policy.outbound_email.default@2026-03-19.1"),
            "decision_rule": (
                "allow if recipient_verified and contact_authorization and freshness_ok and policy_match; "
                "require review for sensitive external send"
            ),
            "thresholds": {
                "minimum_support": 0.75,
                "minimum_policy_margin": 0.25,
            },
        },
        "evaluation_outcome": {
            "route": "allow_if_approved",
            "reason_codes": ["sensitive_external_send", "policy_margin_near_threshold"],
            "human_review_required": True,
            "release_conditions": ["human_approval_required", "freshness_recheck_required_at_release"],
        },
        "validity": {
            "evaluated_at": _iso8601(now),
            "evidence_valid_until": _iso8601(evidence_valid_until),
            "release_revalidation_required": True,
            "invalidation_triggers": [
                "intent_hash_changed",
                "fresh_context_expired",
                "recipient_verification_revoked",
            ],
        },
        "audit": {
            "created_at": _iso8601(now),
            "retention_days": 30,
            "redaction_profile": "default_pii",
            "attestation_state": "policy_validated_bundle",
        },
    }


def _assert_canary_outputs(
    *,
    checkpoint_attempt_id: str,
    decision_receipt: Dict[str, Any],
    export_payload: Dict[str, Any],
    verify_payload: Dict[str, Any],
    run_context: Dict[str, Any],
    proof_pack_dir: Path,
    reviewer_packet_dir: Path,
    trace_id: str,
) -> None:
    settlement = _json(reviewer_packet_dir / "SETTLEMENT.json")
    scope_manifest = _json(reviewer_packet_dir / "SCOPE_MANIFEST.json")
    packet_inputs = _json(reviewer_packet_dir / "PACKET_INPUTS.json")
    receipt_rows = _jsonl(proof_pack_dir / "receipt_pack.jsonl")
    packaged_decisions = sorted((reviewer_packet_dir / "decision_receipts").glob("*.json"))
    if len(packaged_decisions) != 1:
        raise RuntimeError(f"expected exactly one packaged Decision Receipt, found {len(packaged_decisions)}")
    packaged_decision = _json(packaged_decisions[0])

    request_row = next(row for row in receipt_rows if row.get("type") == "checkpoint.requested")
    resolution_row = next(row for row in receipt_rows if row.get("type") == "checkpoint.resolved")
    evaluation_row = next(
        row for row in receipt_rows
        if row.get("type") == "checkpoint.evaluated"
        and row.get("evaluation_id") == resolution_row.get("final_evaluation_id", row.get("evaluation_id"))
    )

    proof_pack_manifest_path = proof_pack_dir / "pack_manifest.json"
    expected_pack_manifest_sha = hashlib.sha256(proof_pack_manifest_path.read_bytes()).hexdigest()
    decision_evaluation_refs = {
        ref.get("ref_id")
        for ref in packaged_decision.get("evidence_refs", [])
        if isinstance(ref, dict)
    }

    assert export_payload["settlement_state"] == "VERIFIED"
    assert export_payload["machine_coverage"]["numerator"] == 4
    assert export_payload["machine_coverage"]["denominator"] == 4
    assert not export_payload["limitations"]

    assert verify_payload["packet_verified"] is True
    assert verify_payload["settlement_state"] == "VERIFIED"
    assert verify_payload["coverage_summary"].get("EVIDENCED") == 4
    assert verify_payload["errors"] == []
    assert not any("authority" in warning.lower() for warning in verify_payload["warnings"])

    assert settlement["packet_profile"] == CHECKPOINT_REVIEWER_PACKET_PROFILE
    assert settlement["settlement_state"] == "VERIFIED"
    assert settlement["pack_manifest_sha256"] == expected_pack_manifest_sha
    assert scope_manifest["decision_layer_mode"] == "canonical_decision_receipts"
    assert not any("authority" in limitation for limitation in scope_manifest.get("boundary_notes", []))

    assert request_row["checkpoint_id"] == checkpoint_attempt_id
    assert evaluation_row["checkpoint_id"] == checkpoint_attempt_id
    assert resolution_row["checkpoint_id"] == checkpoint_attempt_id
    assert scope_manifest["checkpoint_attempt_id"] == checkpoint_attempt_id
    assert packet_inputs["checkpoint_profile_inputs"]["checkpoint_attempt_id"] == checkpoint_attempt_id

    assert resolution_row["decision_receipt_ids"] == [packaged_decision["receipt_id"]]
    assert packaged_decision["receipt_id"] == decision_receipt["receipt_id"]
    assert packaged_decision["receipt_id"] in resolution_row["decision_receipt_ids"]
    assert resolution_row["final_evaluation_id"] == evaluation_row["evaluation_id"]
    assert resolution_row["final_evaluation_id"] in decision_evaluation_refs
    assert packaged_decision["decision_subject"] == f"checkpoint_attempt:{checkpoint_attempt_id}"
    assert scope_manifest["trace_id"] == trace_id
    assert run_context["packet_profile"] == CHECKPOINT_REVIEWER_PACKET_PROFILE
    assert run_context["checkpoint_type"] == CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL


def build_canary(out_dir: Path, *, render_html: bool = False) -> Path:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    signer_suffix = uuid.uuid4().hex[:8]
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = out_dir / ".work"
    store = AssayStore(base_dir=work_dir / "store")
    keystore = AssayKeyStore(work_dir / "keys")
    proof_pack_dir = out_dir / "proof_pack"
    reviewer_packet_dir = out_dir / "reviewer_packet"
    decision_receipt_path = out_dir / "decision_receipt.json"
    trace_id_path = out_dir / "trace_id.txt"
    reviewer_verify_path = out_dir / "reviewer_verify.json"
    reviewer_export_path = out_dir / "checkpoint_export.json"
    run_context_path = out_dir / "RUN_CONTEXT.json"
    html_path = out_dir / "reviewer_packet.html"

    pack_signer_id = f"checkpoint-canary-pack-{signer_suffix}"
    packet_signer_id = f"checkpoint-canary-packet-{signer_suffix}"
    if not keystore.has_key(pack_signer_id):
        keystore.generate_key(pack_signer_id)
        keystore.set_active_signer(pack_signer_id)

    request_data = _build_request(now)
    evaluation_data = _build_evaluation(now + timedelta(seconds=2))
    decision_timestamp = now + timedelta(seconds=5)
    resolved_at = now + timedelta(seconds=6)

    with open_episode(
        store=store,
        metadata={
            "scenario": "checkpoint_packet_canary",
            "checkpoint_type": CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
        },
    ) as episode:
        request_data["subject"]["episode_id"] = episode.episode_id
        flow = OutboundEmailCheckpointFlow(episode)
        request = flow.create_request(
            subject=request_data["subject"],
            attempt=request_data["attempt"],
            relying_party=request_data["relying_party"],
            requested_at=request_data["requested_at"],
        )
        evaluation = flow.evaluate(
            shadow=evaluation_data["shadow"],
            evidence_bundle=evaluation_data["evidence_bundle"],
            verifiers=evaluation_data["verifiers"],
            uncertainty=evaluation_data["uncertainty"],
            policy=evaluation_data["policy"],
            evaluation_outcome=evaluation_data["evaluation_outcome"],
            validity=evaluation_data["validity"],
            audit=evaluation_data["audit"],
        )
        decision = flow.decide(
            authority_id="assay:checkpoint:human_review",
            authority_scope=CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
            timestamp=_iso8601(decision_timestamp),
            verdict="APPROVE",
            verdict_reason="Human reviewer approved the outbound send after verifying recipient, context, and disclosure.",
            verdict_reason_codes=["human_approval_granted", "recipient_verified", "policy_review_complete"],
            confidence="high",
        )
        resolution = flow.resolve(
            resolution_outcome="released",
            reason_codes=["human_approval_granted", "freshness_revalidated"],
            release_revalidation_performed=True,
            evaluation_valid_at_resolution=True,
            resolved_at=_iso8601(resolved_at),
            human_approval={
                "approver_id": "user://ops_manager_17",
                "decision": "approved",
                "decided_at": _iso8601(decision_timestamp),
            },
            dispatch_attempted_at=_iso8601(resolved_at),
        )
        trace_id = episode.trace_id

    entries = store.read_trace(trace_id)
    pack = ProofPack(
        run_id=trace_id,
        entries=entries,
        signer_id=pack_signer_id,
    )
    pack.build(proof_pack_dir, keystore=keystore)

    trace_id_path.write_text(f"{trace_id}\n", encoding="utf-8")
    decision_receipt_path.write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    cli_history: List[Dict[str, Any]] = []
    export_args = [
        "checkpoint",
        "export-reviewer",
        flow.checkpoint_id,
        "--proof-pack",
        str(proof_pack_dir),
        "--out",
        str(reviewer_packet_dir),
        "--decision-receipt",
        str(decision_receipt_path),
        "--sign-packet",
        "--packet-signer",
        packet_signer_id,
        "--keys-dir",
        str(work_dir / "keys"),
        "--json",
    ]
    export_result = _run_cli(export_args, cwd=ROOT)
    cli_history.append(
        {
            "argv": ["assay", *export_args],
            "exit_code": export_result.returncode,
            "stdout": export_result.stdout,
            "stderr": export_result.stderr,
        }
    )
    export_payload = _parse_cli_json(export_result, label="checkpoint export-reviewer")
    reviewer_export_path.write_text(json.dumps(export_payload, indent=2) + "\n", encoding="utf-8")

    verify_args = [
        "reviewer",
        "verify",
        str(reviewer_packet_dir),
        "--json",
    ]
    verify_result = _run_cli(verify_args, cwd=ROOT)
    cli_history.append(
        {
            "argv": ["assay", *verify_args],
            "exit_code": verify_result.returncode,
            "stdout": verify_result.stdout,
            "stderr": verify_result.stderr,
        }
    )
    verify_payload = _parse_cli_json(verify_result, label="reviewer verify")
    reviewer_verify_path.write_text(json.dumps(verify_payload, indent=2) + "\n", encoding="utf-8")

    if render_html:
        render_args = [
            "reviewer",
            "packet",
            "--input",
            str(reviewer_packet_dir),
            "--output",
            str(html_path),
        ]
        render_result = _run_cli(render_args, cwd=ROOT)
        cli_history.append(
            {
                "argv": ["assay", *render_args],
                "exit_code": render_result.returncode,
                "stdout": render_result.stdout,
                "stderr": render_result.stderr,
            }
        )
        if render_result.returncode != 0:
            raise RuntimeError(
                f"reviewer packet render failed with exit {render_result.returncode}\n"
                f"stdout:\n{render_result.stdout}\nstderr:\n{render_result.stderr}"
            )

    run_context = {
        "generated_at": _iso8601(datetime.now(timezone.utc)),
        "git_commit_sha": _git_value("rev-parse", "HEAD"),
        "git_ref": _git_value("symbolic-ref", "--quiet", "--short", "HEAD"),
        "python_version": sys.version.split()[0],
        "assay_version": _assay_version(),
        "command_args": sys.argv[1:],
        "packet_profile": CHECKPOINT_REVIEWER_PACKET_PROFILE,
        "checkpoint_type": CHECKPOINT_TYPE_OUTBOUND_SEND_EMAIL,
        "checkpoint_attempt_id": flow.checkpoint_id,
        "trace_id": trace_id,
        "signers": {
            "proof_pack_signer_id": pack_signer_id,
            "packet_signer_id": packet_signer_id,
        },
        "paths": {
            "proof_pack": str(proof_pack_dir),
            "reviewer_packet": str(reviewer_packet_dir),
            "decision_receipt": str(decision_receipt_path),
            "reviewer_verify": str(reviewer_verify_path),
            "trace_id": str(trace_id_path),
        },
        "script": "scripts/run_checkpoint_packet_canary.py",
        "cli_commands": cli_history,
        "acceptance_target": {
            "settlement_state": "VERIFIED",
            "authority_mode": "canonical_decision_receipts",
            "coverage_evidenced": 4,
        },
    }
    run_context_path.write_text(json.dumps(run_context, indent=2) + "\n", encoding="utf-8")

    _assert_canary_outputs(
        checkpoint_attempt_id=flow.checkpoint_id,
        decision_receipt=decision,
        export_payload=export_payload,
        verify_payload=verify_payload,
        run_context=run_context,
        proof_pack_dir=proof_pack_dir,
        reviewer_packet_dir=reviewer_packet_dir,
        trace_id=trace_id,
    )

    print(json.dumps(
        {
            "status": "ok",
            "checkpoint_attempt_id": flow.checkpoint_id,
            "trace_id": trace_id,
            "proof_pack": str(proof_pack_dir),
            "reviewer_packet": str(reviewer_packet_dir),
            "reviewer_verify": str(reviewer_verify_path),
            "reviewer_html": str(html_path) if render_html else None,
        },
        indent=2,
    ))
    return out_dir


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate and verify one local outbound checkpoint reviewer-packet canary.",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for the canary artifact chain.",
    )
    parser.add_argument(
        "--render-html",
        action="store_true",
        help="Also render reviewer_packet.html with `assay reviewer packet`.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    out_dir = Path(args.out).resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"Output directory must be empty or absent: {out_dir}", file=sys.stderr)
        return 2
    try:
        build_canary(out_dir, render_html=bool(args.render_html))
    except Exception as exc:
        print(f"checkpoint packet canary failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
