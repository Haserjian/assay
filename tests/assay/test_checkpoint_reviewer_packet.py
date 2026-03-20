from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay import open_episode
from assay.checkpoint_reviewer_packet import (
    CHECKPOINT_REVIEWER_PACKET_PROFILE,
    compile_checkpoint_reviewer_packet,
)
from assay.checkpoints import OutboundEmailCheckpointFlow
from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.reviewer_packet_verify import verify_reviewer_packet
from assay.store import AssayStore
from assay.vendorq_models import VendorQInputError


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = ROOT / "docs" / "examples" / "checkpoints"
runner = CliRunner()
PACK_TS = "2026-03-19T13:00:00+00:00"


@pytest.fixture
def tmp_store(tmp_path):
    return AssayStore(base_dir=tmp_path / "assay_store")


def _load_example(name: str) -> dict:
    return json.loads((EXAMPLES_DIR / name).read_text())


def _emit_request_and_evaluation(flow: OutboundEmailCheckpointFlow, template: dict) -> None:
    flow.create_request(
        subject=template["subject"],
        attempt=template["attempt"],
        relying_party=template["relying_party"],
        requested_at=template["requested_at"],
        request_id=template["request_id"],
    )
    flow.evaluate(
        shadow=template["shadow"],
        evidence_bundle=template["evidence_bundle"],
        verifiers=template["verifiers"],
        uncertainty=template["uncertainty"],
        policy=template["policy"],
        evaluation_outcome=template["evaluation_outcome"],
        validity=template["validity"],
        audit=template["audit"],
        evaluation_id=template["evaluation_id"],
    )


def _make_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(tmp_path / "keys")
    ks.generate_key("reviewer-signer")
    return ks


def _build_checkpoint_proof_pack(
    tmp_path: Path,
    *,
    trace_id: str,
    entries: list[dict],
) -> tuple[Path, AssayKeyStore]:
    ks = _make_keystore(tmp_path)
    pack = ProofPack(
        run_id=trace_id,
        entries=entries,
        signer_id="reviewer-signer",
    )
    pack_dir = tmp_path / "proof_pack"
    pack.build(pack_dir, keystore=ks, deterministic_ts=PACK_TS)
    return pack_dir, ks


def _trace_entry(entry_type: str, timestamp: str, payload: dict, *, trace_id: str) -> dict:
    return {
        **payload,
        "receipt_id": f"r_{entry_type.replace('.', '_')}_{timestamp[-3:-1]}_{payload.get('evaluation_id', '00')}",
        "type": entry_type,
        "timestamp": timestamp,
        "schema_version": "3.0",
        "episode_id": payload.get("subject", {}).get("episode_id", "ep_123"),
        "_trace_id": trace_id,
        "_stored_at": timestamp,
    }


def _build_released_attempt(tmp_store: AssayStore) -> tuple[dict, str, dict, list[dict]]:
    template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
    with open_episode(store=tmp_store) as episode:
        flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
        _emit_request_and_evaluation(flow, template)
        decision = flow.decide(
            authority_id="assay:checkpoint:human_review",
            authority_scope="outbound_action.send_email",
            timestamp="2026-03-19T12:05:00Z",
            verdict="APPROVE",
            verdict_reason="Human reviewer approved the outbound send after checking recipient and context.",
            verdict_reason_codes=["human_approval_granted"],
            confidence="high",
        )
        flow.resolve(
            resolution_outcome="released",
            reason_codes=["human_approval_granted"],
            release_revalidation_performed=True,
            evaluation_valid_at_resolution=True,
            resolved_at="2026-03-19T12:05:01Z",
            human_approval={
                "approver_id": "user://ops_manager_17",
                "decision": "approved",
                "decided_at": "2026-03-19T12:05:00Z",
            },
            dispatch_attempted_at="2026-03-19T12:05:01Z",
        )
    entries = tmp_store.read_trace(episode.trace_id)
    return template, episode.trace_id, decision, entries


def _build_blocked_attempt(tmp_store: AssayStore) -> tuple[dict, str, dict, list[dict]]:
    template = _load_example("outbound_action.send_email.blocked.v0.1.json")
    with open_episode(store=tmp_store) as episode:
        flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
        _emit_request_and_evaluation(flow, template)
        decision = flow.decide(
            authority_id="assay:checkpoint:outbound_email_policy",
            authority_scope="outbound_action.send_email",
            timestamp="2026-03-19T12:15:02Z",
            verdict="REFUSE",
            verdict_reason="Recipient verification and freshness requirements were not satisfied.",
            verdict_reason_codes=["missing_recipient_verification", "stale_context"],
            evidence_sufficient=False,
            evidence_gaps=["recipient_verified", "fresh_context_snapshot"],
            confidence="moderate",
        )
        flow.resolve(
            resolution_outcome="blocked",
            reason_codes=["missing_recipient_verification", "stale_context"],
            release_revalidation_performed=False,
            evaluation_valid_at_resolution=False,
            resolved_at="2026-03-19T12:15:03Z",
        )
    entries = tmp_store.read_trace(episode.trace_id)
    return template, episode.trace_id, decision, entries


def test_checkpoint_reviewer_packet_happy_path_verifies(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    packet_dir = tmp_path / "packet"

    result = compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_happy"},
    )

    assert result["packet_profile"] == CHECKPOINT_REVIEWER_PACKET_PROFILE
    assert result["settlement_state"] == "VERIFIED"
    assert result["machine_coverage"]["numerator"] == 4
    assert (packet_dir / "decision_receipts").is_dir()

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is True
    assert verify_result["settlement_state"] == "VERIFIED"
    assert verify_result["provided_settlement_state"] == "VERIFIED"
    assert verify_result["coverage_summary"]["EVIDENCED"] == 4


def test_checkpoint_reviewer_packet_degrades_without_canonical_decisions(tmp_path: Path, tmp_store) -> None:
    template, trace_id, _, entries = _build_blocked_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    packet_dir = tmp_path / "packet"

    result = compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_degraded"},
    )

    authority_row = next(row for row in result["coverage_rows"] if row["Claim / Question"].startswith("Is the authority"))
    assert result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert authority_row["Status"] == "PARTIAL"
    assert "authority_layer_only_proven_by_trace_wrappers" in result["limitations"]

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is True
    assert verify_result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert verify_result["coverage_summary"]["PARTIAL"] == 1
    scope_manifest = json.loads((packet_dir / "SCOPE_MANIFEST.json").read_text())
    assert "authority_layer_only_proven_by_trace_wrappers" in scope_manifest["boundary_notes"]


def test_checkpoint_reviewer_packet_legacy_resolution_compatibility(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    legacy_entries = copy.deepcopy(entries)
    for entry in legacy_entries:
        if entry.get("type") == "checkpoint.resolved":
            entry.pop("final_evaluation_id", None)
            break
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=legacy_entries)
    packet_dir = tmp_path / "packet"

    result = compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_legacy"},
    )

    posture_row = next(row for row in result["coverage_rows"] if row["Claim / Question"].startswith("Which evaluation"))
    assert result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert posture_row["Status"] == "PARTIAL"
    assert "final_evaluation_id_missing_used_evaluation_id_compatibility_fallback" in result["limitations"]

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is True
    assert verify_result["settlement_state"] == "VERIFIED_WITH_GAPS"


def test_checkpoint_packet_uses_carried_forward_evaluation_not_latest(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    later_evaluation = _load_example("outbound_action.send_email.blocked.v0.1.json")
    later_evaluation["checkpoint_id"] = template["checkpoint_id"]
    later_evaluation["request_id"] = template["request_id"]
    later_evaluation["subject"] = template["subject"]
    later_evaluation["attempt"] = template["attempt"]
    later_evaluation["relying_party"] = template["relying_party"]
    later_evaluation["evaluation_id"] = "cke_later"
    later_evaluation["validity"]["evaluated_at"] = "2026-03-19T12:10:02Z"
    later_evaluation["audit"]["trace_receipt_ids"] = ["r_checkpoint_evaluated_10_cke_later"]
    augmented_entries = copy.deepcopy(entries) + [
        _trace_entry(
            "checkpoint.evaluated",
            "2026-03-19T12:10:02Z",
            later_evaluation,
            trace_id=trace_id,
        )
    ]
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=augmented_entries)
    packet_dir = tmp_path / "packet"

    result = compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_multieval"},
    )

    assert result["settlement_state"] == "VERIFIED"
    scope_manifest = json.loads((packet_dir / "SCOPE_MANIFEST.json").read_text())
    assert scope_manifest["carried_forward_evaluation_id"] == template["evaluation_id"]

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is True
    assert verify_result["settlement_state"] == "VERIFIED"


def test_checkpoint_reviewer_packet_invalid_lifecycle_settles_incomplete(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_blocked_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    packet_dir = tmp_path / "packet"
    bad_decision = copy.deepcopy(decision)
    bad_decision["verdict"] = "APPROVE"
    bad_decision["disposition"] = "execute"

    result = compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[bad_decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_incomplete"},
    )

    assert result["settlement_state"] == "INCOMPLETE_EVIDENCE"

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is True
    assert verify_result["settlement_state"] == "INCOMPLETE_EVIDENCE"
    assert verify_result["provided_settlement_state"] == "INCOMPLETE_EVIDENCE"


def test_checkpoint_export_reviewer_rejects_unresolved_attempt(tmp_path: Path, tmp_store) -> None:
    template = _load_example("outbound_action.send_email.allow_if_approved.v0.1.json")
    with open_episode(store=tmp_store) as episode:
        flow = OutboundEmailCheckpointFlow(episode, checkpoint_id=template["checkpoint_id"])
        _emit_request_and_evaluation(flow, template)
    entries = tmp_store.read_trace(episode.trace_id)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=episode.trace_id, entries=entries)
    packet_dir = tmp_path / "packet"

    with pytest.raises(VendorQInputError, match="checkpoint_attempt_unresolved"):
        compile_checkpoint_reviewer_packet(
            proof_pack_dir=proof_pack_dir,
            checkpoint_attempt_id=template["checkpoint_id"],
            out_dir=packet_dir,
            packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_unresolved"},
        )

    assert not packet_dir.exists()


def test_checkpoint_reviewer_packet_detects_tampered_nested_proof_pack(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    packet_dir = tmp_path / "packet"
    compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_tamper_pack"},
    )

    receipt_path = packet_dir / "proof_pack" / "receipt_pack.jsonl"
    data = bytearray(receipt_path.read_bytes())
    data[10] = (data[10] + 1) % 256
    receipt_path.write_bytes(bytes(data))

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is False
    assert verify_result["settlement_state"] == "TAMPERED"
    assert verify_result["primary_failure_reason"] == "nested_proof_pack_failure"


def test_checkpoint_reviewer_packet_detects_tampered_packaged_decision_receipt(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    packet_dir = tmp_path / "packet"
    compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_tamper_decision"},
    )

    decision_file = next((packet_dir / "decision_receipts").glob("*.json"))
    payload = json.loads(decision_file.read_text())
    payload["verdict_reason"] = "tampered"
    decision_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is False
    assert verify_result["settlement_state"] == "TAMPERED"
    assert verify_result["primary_failure_reason"] == "packet_layer_tamper"
    assert any("PACKET_MANIFEST.json file hash mismatch" in error for error in verify_result["errors"])


def test_checkpoint_reviewer_packet_sanitizes_adversarial_decision_receipt_ids(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    old_receipt_id = decision["receipt_id"]
    malicious_receipt_id = "../../etc/passwd"
    malicious_decision = copy.deepcopy(decision)
    malicious_decision["receipt_id"] = malicious_receipt_id
    malicious_entries = copy.deepcopy(entries)
    for entry in malicious_entries:
        if entry.get("type") == "checkpoint.decision_recorded":
            if entry.get("decision_receipt_id") == old_receipt_id:
                entry["decision_receipt_id"] = malicious_receipt_id
        if entry.get("type") == "checkpoint.resolved":
            entry["decision_receipt_ids"] = [
                malicious_receipt_id if value == old_receipt_id else value
                for value in entry.get("decision_receipt_ids", [])
            ]
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=malicious_entries)
    packet_dir = tmp_path / "packet"

    result = compile_checkpoint_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        checkpoint_attempt_id=template["checkpoint_id"],
        out_dir=packet_dir,
        decision_receipts=[malicious_decision],
        packet_overrides={"generated_at": PACK_TS, "packet_id": "rp_checkpoint_sanitized"},
    )

    decision_dir = packet_dir / "decision_receipts"
    decision_files = sorted(decision_dir.glob("*.json"))
    assert len(decision_files) == 1
    assert decision_files[0].parent == decision_dir
    assert ".." not in decision_files[0].name
    assert "/" not in decision_files[0].name
    assert not (packet_dir / "etc").exists()
    assert result["settlement_state"] == "VERIFIED"

    packet_inputs = json.loads((packet_dir / "PACKET_INPUTS.json").read_text())
    rel_paths = packet_inputs["checkpoint_profile_inputs"]["decision_receipt_files"]
    assert rel_paths == [f"decision_receipts/{decision_files[0].name}"]

    verify_result = verify_reviewer_packet(packet_dir)
    assert verify_result["packet_verified"] is True
    assert verify_result["settlement_state"] == "VERIFIED"


def test_checkpoint_export_reviewer_cli_json_and_reviewer_verify(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    packet_dir = tmp_path / "packet"

    export = runner.invoke(
        assay_app,
        [
            "checkpoint",
            "export-reviewer",
            template["checkpoint_id"],
            "--proof-pack",
            str(proof_pack_dir),
            "--out",
            str(packet_dir),
            "--decision-receipt",
            str(decision_path),
            "--json",
        ],
    )

    assert export.exit_code == 0, export.output
    export_payload = json.loads(export.output)
    assert export_payload["command"] == "checkpoint export-reviewer"
    assert export_payload["packet_profile"] == CHECKPOINT_REVIEWER_PACKET_PROFILE
    assert export_payload["settlement_state"] == "VERIFIED"

    verify = runner.invoke(assay_app, ["reviewer", "verify", str(packet_dir), "--json"])
    assert verify.exit_code == 0, verify.output
    verify_payload = json.loads(verify.output)
    assert verify_payload["packet_verified"] is True
    assert verify_payload["settlement_state"] == "VERIFIED"


def test_checkpoint_export_reviewer_cli_human_output(tmp_path: Path, tmp_store) -> None:
    template, trace_id, decision, entries = _build_released_attempt(tmp_store)
    proof_pack_dir, _ = _build_checkpoint_proof_pack(tmp_path, trace_id=trace_id, entries=entries)
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    packet_dir = tmp_path / "packet"

    result = runner.invoke(
        assay_app,
        [
            "checkpoint",
            "export-reviewer",
            template["checkpoint_id"],
            "--proof-pack",
            str(proof_pack_dir),
            "--out",
            str(packet_dir),
            "--decision-receipt",
            str(decision_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Checkpoint Reviewer Packet Compiled" in result.output
    assert "Machine coverage:  4/4 (100.00%)" in result.output
