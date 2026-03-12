from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.claim_verifier import ClaimSpec
from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.reviewer_packet_compile import compile_reviewer_packet
from assay.reviewer_packet_verify import verify_reviewer_packet
from assay.vendorq_models import load_json

runner = CliRunner()

_TS = "2026-03-11T12:00:00+00:00"


def _fixture_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "reviewer_packet"


def _make_keystore(tmp_path: Path) -> AssayKeyStore:
    ks = AssayKeyStore(tmp_path / "keys")
    ks.generate_key("reviewer-signer")
    return ks


def _make_receipt(receipt_id: str) -> dict[str, object]:
    return {
        "receipt_id": receipt_id,
        "type": "model_call",
        "timestamp": _TS,
        "schema_version": "3.0",
        "seq": 0,
        "provider": "openai",
        "model_id": "gpt-4o",
    }


def _build_proof_pack(tmp_path: Path, *, claim_pass: bool = True) -> tuple[Path, AssayKeyStore]:
    ks = _make_keystore(tmp_path)
    claims = [
        ClaimSpec(
            claim_id="model_call_present" if claim_pass else "guardian_verdict_present",
            description="Reviewer packet sample claim",
            check="receipt_type_present",
            params={"receipt_type": "model_call" if claim_pass else "guardian_verdict"},
        )
    ]
    pack = ProofPack(
        run_id="reviewer-packet-run",
        entries=[_make_receipt("r_packet_001")],
        signer_id="reviewer-signer",
        claims=claims,
    )
    pack_dir = tmp_path / "proof_pack"
    pack.build(pack_dir, keystore=ks, deterministic_ts=_TS)
    return pack_dir, ks


def _base_boundary() -> dict[str, object]:
    return {
        "workflow_name": "Support workflow",
        "workflow_description": "Support workflow reviewer packet",
        "repo_or_system_in_scope": "support-service",
        "entrypoints_in_scope": ["support.handle_request"],
        "callsites_identified": 1,
        "callsites_instrumented": 1,
        "controls_declared": ["Signed proof pack"],
        "excluded_components": [],
        "boundary_notes": [],
        "freshness_policy": {"valid_for": "P30D"},
        "signed_by": "assay reviewer-packet compiler",
    }


def _base_mapping() -> dict[str, object]:
    return {
        "questions": [
            {
                "question_id": "offline_verify",
                "prompt": "Can the reviewer verify the proof artifact offline?",
                "scope": "Whole packet",
                "status_rule": "ALL_EVIDENCE_REQUIRED",
                "evidence": [{"type": "verify_report_field", "path": "claim_verification.passed"}],
            },
            {
                "question_id": "coverage_complete",
                "prompt": "Is all identified workflow coverage complete?",
                "scope": "Support workflow",
                "status_rule": "PARTIAL_IF_RATIO_LT_1",
                "numerator_field": "callsites_instrumented",
                "denominator_field": "callsites_identified",
            },
            {
                "question_id": "legal_conclusion",
                "prompt": "Does this packet establish legal or regulatory compliance?",
                "scope": "Out of scope for this packet",
                "status_rule": "OUT_OF_SCOPE",
                "in_scope": False,
                "out_of_scope_note": "Packet provides evidence, not legal conclusions.",
            },
        ]
    }


def _compile_packet(
    tmp_path: Path,
    *,
    claim_pass: bool = True,
    complete_coverage: bool = True,
    baseline_state: str | None = None,
    all_out_of_scope: bool = False,
) -> tuple[Path, AssayKeyStore]:
    proof_pack_dir, ks = _build_proof_pack(tmp_path / "proof_inputs", claim_pass=claim_pass)
    boundary = _base_boundary()
    mapping = _base_mapping()

    if not complete_coverage:
        boundary["callsites_identified"] = 2
        boundary["callsites_instrumented"] = 1

    if all_out_of_scope:
        mapping["questions"] = [
            {
                "question_id": "legal_conclusion",
                "prompt": "Does this packet establish legal or regulatory compliance?",
                "scope": "Out of scope for this packet",
                "status_rule": "OUT_OF_SCOPE",
                "in_scope": False,
                "out_of_scope_note": "Packet provides evidence, not legal conclusions.",
            }
        ]

    baseline_dir = None
    if baseline_state is not None:
        baseline_dir = tmp_path / "baseline_packet"
        baseline_dir.mkdir(parents=True, exist_ok=True)
        (baseline_dir / "SETTLEMENT.json").write_text(
            json.dumps({"settlement_state": baseline_state}, indent=2) + "\n",
            encoding="utf-8",
        )

    out_dir = tmp_path / "reviewer_packet"
    compile_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        boundary_payload=boundary,
        mapping_payload=mapping,
        out_dir=out_dir,
        baseline_packet_dir=baseline_dir,
        packet_overrides={
            "generated_at": _TS,
            "packet_id": f"rp_{tmp_path.name}",
        },
        keystore=ks,
    )
    return out_dir, ks


def test_verify_reviewer_packet_matches_compiled_sample(tmp_path: Path) -> None:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"

    compile_reviewer_packet(
        proof_pack_dir=fixtures / "sample_proof_pack",
        boundary_payload=load_json(fixtures / "sample_boundary.json"),
        mapping_payload=load_json(fixtures / "sample_mapping.json"),
        out_dir=out_dir,
    )

    result = verify_reviewer_packet(out_dir)
    assert result["packet_verified"] is True
    assert result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert result["provided_settlement_state"] == "VERIFIED_WITH_GAPS"
    assert result["primary_failure_reason"] is None
    assert result["failure_reasons"] == []
    assert result["settlement_verification"]["recomputed"] is True
    assert result["settlement_verification"]["matches_provided"] is True
    assert result["settlement_verification"]["provided_metadata_matches"] is True
    assert result["proof_pack"]["verified"] is True


def test_reviewer_verify_cli_json(tmp_path: Path) -> None:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"
    compile_reviewer_packet(
        proof_pack_dir=fixtures / "sample_proof_pack",
        boundary_payload=load_json(fixtures / "sample_boundary.json"),
        mapping_payload=load_json(fixtures / "sample_mapping.json"),
        out_dir=out_dir,
    )

    result = runner.invoke(assay_app, ["reviewer", "verify", str(out_dir), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["command"] == "reviewer verify"
    assert payload["packet_verified"] is True
    assert payload["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert payload["packet_manifest"]["signed"] is False
    assert payload["packet_manifest"]["verified"] is True
    assert payload["packet_manifest"]["signer_identity"] is None
    assert payload["packet_manifest"]["signer_fingerprint"] is None
    assert payload["settlement_verification"]["recomputed"] is True
    assert payload["settlement_verification"]["matches_provided"] is True
    assert payload["settlement_verification"]["provided_metadata_matches"] is True
    assert payload["failure_reasons"] == []
    assert payload["primary_failure_reason"] is None


def test_verify_reviewer_packet_detects_tampered_nested_proof_pack(tmp_path: Path) -> None:
    packet_dir, ks = _compile_packet(tmp_path, claim_pass=True, complete_coverage=True)
    receipt_path = packet_dir / "proof_pack" / "receipt_pack.jsonl"
    data = bytearray(receipt_path.read_bytes())
    data[10] = (data[10] + 1) % 256
    receipt_path.write_bytes(bytes(data))

    result = verify_reviewer_packet(packet_dir, keystore=ks)
    assert result["packet_verified"] is False
    assert result["settlement_state"] == "TAMPERED"
    assert result["proof_pack"]["verified"] is False
    assert result["primary_failure_reason"] == "nested_proof_pack_failure"
    assert any(reason["code"] == "nested_proof_pack_failure" for reason in result["failure_reasons"])
    assert any("Nested proof pack verification failed" in error for error in result["errors"])


def test_verify_reviewer_packet_detects_settlement_mismatch(tmp_path: Path) -> None:
    packet_dir, ks = _compile_packet(tmp_path, claim_pass=True, complete_coverage=False)
    settlement_path = packet_dir / "SETTLEMENT.json"
    settlement = json.loads(settlement_path.read_text())
    settlement["settlement_state"] = "VERIFIED"
    settlement_path.write_text(json.dumps(settlement, indent=2) + "\n", encoding="utf-8")

    result = verify_reviewer_packet(packet_dir, keystore=ks)
    assert result["packet_verified"] is False
    assert result["settlement_state"] == "TAMPERED"
    assert any("PACKET_MANIFEST.json file hash mismatch: SETTLEMENT.json" in error for error in result["errors"])


def test_verify_reviewer_packet_detects_packet_layer_status_tamper(tmp_path: Path) -> None:
    packet_dir, ks = _compile_packet(tmp_path, claim_pass=True, complete_coverage=False)
    coverage_path = packet_dir / "COVERAGE_MATRIX.md"
    coverage = coverage_path.read_text(encoding="utf-8")
    coverage_path.write_text(
        coverage.replace("| Is all identified workflow coverage complete? | PARTIAL |", "| Is all identified workflow coverage complete? | EVIDENCED |"),
        encoding="utf-8",
    )

    result = verify_reviewer_packet(packet_dir, keystore=ks)
    assert result["packet_verified"] is False
    assert result["settlement_state"] == "TAMPERED"
    assert result["packet_manifest"]["signed"] is True
    assert result["packet_manifest"]["verified"] is False
    assert result["packet_manifest"]["signer_identity"] == "reviewer-signer"
    assert result["packet_manifest"]["signer_fingerprint"]
    assert result["primary_failure_reason"] == "packet_layer_tamper"
    assert any(reason["code"] == "packet_layer_tamper" for reason in result["failure_reasons"])
    assert any("PACKET_MANIFEST.json file hash mismatch: COVERAGE_MATRIX.md" in error for error in result["errors"])


def test_verify_reviewer_packet_recomputes_expiry_and_freshness(tmp_path: Path) -> None:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"
    boundary = load_json(fixtures / "sample_boundary.json")
    boundary["freshness_policy"] = {"valid_for": "P1D", "stale_after": "P90D"}
    compile_reviewer_packet(
        proof_pack_dir=fixtures / "sample_proof_pack",
        boundary_payload=boundary,
        mapping_payload=load_json(fixtures / "sample_mapping.json"),
        out_dir=out_dir,
        packet_overrides={"generated_at": "2026-03-04T23:00:00+00:00", "packet_id": "rp_expired_fixture"},
    )

    result = verify_reviewer_packet(out_dir)
    assert result["packet_verified"] is False
    assert result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert result["freshness_state"] == "STALE"
    assert result["primary_failure_reason"] == "stale_packet"
    assert any(reason["code"] == "stale_packet" for reason in result["failure_reasons"])
    assert result["settlement_verification"]["matches_provided"] is True
    assert result["settlement_verification"]["provided_metadata_matches"] is False
    assert "freshness_state" in result["settlement_verification"]["metadata_mismatches"]
    assert any("does not match derived freshness_state=STALE" in error for error in result["errors"])


def test_verify_reviewer_packet_handles_malformed_generated_at(tmp_path: Path) -> None:
    fixtures = _fixture_dir()
    out_dir = tmp_path / "reviewer_packet"
    compile_reviewer_packet(
        proof_pack_dir=fixtures / "sample_proof_pack",
        boundary_payload=load_json(fixtures / "sample_boundary.json"),
        mapping_payload=load_json(fixtures / "sample_mapping.json"),
        out_dir=out_dir,
    )

    settlement_path = out_dir / "SETTLEMENT.json"
    settlement = json.loads(settlement_path.read_text())
    settlement["generated_at"] = "not-a-time"
    settlement_path.write_text(json.dumps(settlement, indent=2) + "\n", encoding="utf-8")

    result = verify_reviewer_packet(out_dir)
    assert result["packet_verified"] is False
    assert result["freshness_state"] == "STALE"
    assert any("SETTLEMENT.json generated_at must be ISO-8601" in error for error in result["errors"])


def test_verify_reviewer_packet_accepts_human_attested_text_labels(tmp_path: Path) -> None:
    proof_pack_dir, ks = _build_proof_pack(tmp_path / "proof_inputs", claim_pass=True)
    boundary = _base_boundary()
    mapping = {
        "questions": [
            {
                "question_id": "offline_verify",
                "prompt": "Can the reviewer verify the proof artifact offline?",
                "scope": "Whole packet",
                "status_rule": "ALL_EVIDENCE_REQUIRED",
                "evidence": [{"type": "verify_report_field", "path": "claim_verification.passed"}],
            },
            {
                "question_id": "governance_docs",
                "prompt": "Is organizational governance documentation available?",
                "scope": "Support workflow",
                "status_rule": "HUMAN_ATTESTED",
                "evidence_label": "Organizational governance documentation (human-attested)",
            },
        ]
    }
    packet_dir = tmp_path / "reviewer_packet"
    compile_reviewer_packet(
        proof_pack_dir=proof_pack_dir,
        boundary_payload=boundary,
        mapping_payload=mapping,
        out_dir=packet_dir,
        packet_overrides={
            "generated_at": _TS,
            "packet_id": f"rp_{tmp_path.name}",
        },
        keystore=ks,
    )

    result = verify_reviewer_packet(packet_dir, keystore=ks)
    assert result["packet_verified"] is True
    assert result["settlement_state"] == "VERIFIED_WITH_GAPS"
    assert result["provided_settlement_state"] == "VERIFIED_WITH_GAPS"
    assert result["errors"] == []


@pytest.mark.parametrize(
    ("state", "claim_pass", "complete_coverage", "baseline_state", "all_out_of_scope", "should_verify"),
    [
        ("VERIFIED", True, True, None, False, True),
        ("VERIFIED_WITH_GAPS", True, False, None, False, True),
        ("INCOMPLETE_EVIDENCE", False, True, None, False, True),
        ("EVIDENCE_REGRESSION", True, False, "VERIFIED", False, True),
        ("OUT_OF_SCOPE", True, True, None, True, True),
        ("TAMPERED", True, True, None, False, False),
    ],
)
def test_reviewer_packet_state_corpus(
    tmp_path: Path,
    state: str,
    claim_pass: bool,
    complete_coverage: bool,
    baseline_state: str | None,
    all_out_of_scope: bool,
    should_verify: bool,
) -> None:
    packet_dir, ks = _compile_packet(
        tmp_path / state.lower(),
        claim_pass=claim_pass,
        complete_coverage=complete_coverage,
        baseline_state=baseline_state,
        all_out_of_scope=all_out_of_scope,
    )

    if state == "TAMPERED":
        receipt_path = packet_dir / "proof_pack" / "receipt_pack.jsonl"
        data = bytearray(receipt_path.read_bytes())
        data[15] = (data[15] + 1) % 256
        receipt_path.write_bytes(bytes(data))

    result = verify_reviewer_packet(packet_dir, keystore=ks)
    assert result["settlement_state"] == state
    assert result["packet_verified"] is should_verify
    if should_verify:
        assert result["provided_settlement_state"] == state
