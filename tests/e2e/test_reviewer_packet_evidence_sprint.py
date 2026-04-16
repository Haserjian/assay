"""Buyer simulation: reviewer-ready evidence packet (synthetic, CI-stable).

Realistic synthetic buyer-review simulation. Receipt shapes mirror real
OpenAI integration output but no live API call is made. This is a
buyer-facing projection layer test, not the production reviewer-packet
compile/verify path (see reviewer_packet_compile.py for that).

Scenario: Mid-market SaaS uses LLM in customer-support. Reviewer asks
6 governance questions. One is honestly unresolved (prompt-injection
resilience). The rest are answered with machine evidence and one human
attestation.

Pass bar (from BUYER_SIMULATION_TEST_CONTRACT.md):
  - realistic synthetic receipts emitted (mirror OpenAI integration shape)
  - multiple receipts exist (5 types)
  - signed pack verifies (Ed25519)
  - reviewer packet generated (4 artifact files)
  - all 6 questions present
  - at least 1 question unresolved (Q6)
  - authority classes visible (machine_evidenced, mixed, insufficient)
  - proof tamper fails (tamper A: receipt mutation)
  - answer inflation tamper fails (tamper B: Q6 status inflation)
"""
from __future__ import annotations

import copy
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay.claim_verifier import ClaimSpec
from assay.integrity import verify_pack_manifest
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack
from assay.reviewer_packet import (
    ANSWER_STATUSES,
    AUTHORITY_CLASSES,
    EvidenceRef,
    QuestionAnswer,
    ReviewerPacket,
)
from assay.reviewer_packet_validator import (
    E_ARTIFACT_PATH_ESCAPE,
    E_ARTIFACT_PATH_MISSING,
    E_AUTHORITY_INFLATED,
    E_MACHINE_CLAIM_NO_RECEIPT,
    E_MISSING_EVIDENCE,
    E_UNRESOLVED_RELABELED,
    E_VERIFICATION_MISMATCH,
    validate_packet,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "evidence_sprint_minirepo"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_receipts(run_id: str) -> list[dict]:
    """Build realistic receipts matching what the OpenAI integration emits."""
    ts_base = _now_iso()
    return [
        {
            "receipt_id": f"r_{run_id}_001",
            "type": "model_call",
            "timestamp": ts_base,
            "schema_version": "3.0",
            "seq": 0,
            "provider": "openai",
            "model_id": "gpt-4o",
            "input_tokens": 1850,
            "output_tokens": 620,
            "total_tokens": 2470,
            "latency_ms": 1120,
            "finish_reason": "stop",
            "input_hash": "a1b2c3d4e5f6a7b8",
            "output_hash": "f8e7d6c5b4a39281",
            "message_count": 3,
            "integration_source": "assay.integrations.openai",
        },
        {
            "receipt_id": f"r_{run_id}_002",
            "type": "guardian_verdict",
            "timestamp": ts_base,
            "schema_version": "3.0",
            "seq": 1,
            "parent_receipt_id": f"r_{run_id}_001",
            "verdict": "allow",
            "action": "customer_support_response",
            "reason": "Content within policy bounds; no PII detected",
            "guardian_id": "content-policy-v2",
        },
        {
            "receipt_id": f"r_{run_id}_003",
            "type": "guardian_decision",
            "timestamp": ts_base,
            "schema_version": "3.0",
            "seq": 2,
            "parent_receipt_id": f"r_{run_id}_002",
            "decision": "approved",
            "authority_class": "BINDING",
            "policy_version": "content-policy-v2.1",
            "controls_evaluated": ["pii_filter", "content_safety", "output_length"],
        },
        {
            "receipt_id": f"r_{run_id}_004",
            "type": "verification_result",
            "timestamp": ts_base,
            "schema_version": "3.0",
            "seq": 3,
            "verified": True,
            "receipt_count": 3,
            "integrity": "PASS",
            "method": "jcs-ed25519",
        },
        {
            "receipt_id": f"r_{run_id}_005",
            "type": "packet_compiled",
            "timestamp": ts_base,
            "schema_version": "3.0",
            "seq": 4,
            "packet_type": "reviewer_packet",
            "questions_total": 6,
            "questions_answered": 5,
            "questions_unresolved": 1,
            "authority_classes_present": [
                "machine_evidenced",
                "mixed",
                "insufficient",
            ],
        },
    ]


def _build_claims() -> list[ClaimSpec]:
    """Claims that the proof pack should satisfy."""
    return [
        ClaimSpec(
            claim_id="model_called",
            description="At least one model_call receipt",
            check="receipt_type_present",
            params={"receipt_type": "model_call"},
        ),
        ClaimSpec(
            claim_id="guardian_ran",
            description="Guardian verdict was issued",
            check="receipt_type_present",
            params={"receipt_type": "guardian_verdict"},
        ),
        ClaimSpec(
            claim_id="guardian_decision_issued",
            description="Guardian decision receipt exists",
            check="receipt_type_present",
            params={"receipt_type": "guardian_decision"},
        ),
        ClaimSpec(
            claim_id="verification_completed",
            description="Verification result receipt exists",
            check="receipt_type_present",
            params={"receipt_type": "verification_result"},
        ),
    ]


def _build_reviewer_packet(
    run_id: str,
    receipts: list[dict],
    proof_pack_id: str,
    proof_pack_verified: bool,
    signer_id: str,
    signer_fingerprint: str,
) -> ReviewerPacket:
    """Compile the 6-question reviewer packet from receipts."""
    human_attestation = json.loads(
        (FIXTURES_DIR / "human_attestation.json").read_text()
    )

    # Q1: Which model/provider? → machine_evidenced from model_call
    q1 = QuestionAnswer(
        question_id="Q1",
        question_text="Which model/provider executed the workflow?",
        status="ANSWERED",
        authority_class="machine_evidenced",
        answer_text="gpt-4o via OpenAI (2,470 tokens, 1,120ms latency)",
        evidence_refs=[
            EvidenceRef(
                receipt_id=receipts[0]["receipt_id"],
                receipt_type="model_call",
                authority_class="machine_evidenced",
                description="OpenAI model_call receipt with provider, model_id, token counts",
                artifact_path="proof_pack/receipt_pack.jsonl",
            ),
        ],
    )

    # Q2: Was it actually executed? → machine_evidenced from model_call
    q2 = QuestionAnswer(
        question_id="Q2",
        question_text="Is there evidence the workflow was actually executed?",
        status="ANSWERED",
        authority_class="machine_evidenced",
        answer_text="Yes. Model call receipt shows finish_reason=stop with measurable latency.",
        evidence_refs=[
            EvidenceRef(
                receipt_id=receipts[0]["receipt_id"],
                receipt_type="model_call",
                authority_class="machine_evidenced",
                description="Execution evidence: latency_ms=1120, finish_reason=stop",
                artifact_path="proof_pack/receipt_pack.jsonl",
            ),
        ],
    )

    # Q3: Safety gate? → mixed (machine guardian_verdict + human attestation)
    q3 = QuestionAnswer(
        question_id="Q3",
        question_text="Was a policy/safety gate evaluated before model execution?",
        status="ANSWERED",
        authority_class="mixed",
        answer_text="Yes. Guardian verdict=allow (content-policy-v2). Human review confirms gate configuration.",
        evidence_refs=[
            EvidenceRef(
                receipt_id=receipts[1]["receipt_id"],
                receipt_type="guardian_verdict",
                authority_class="machine_evidenced",
                description="Guardian verdict: allow, action=customer_support_response",
                artifact_path="proof_pack/receipt_pack.jsonl",
            ),
            EvidenceRef(
                receipt_id=human_attestation["attestation_id"],
                receipt_type="human_attestation",
                authority_class="human_attested",
                description=human_attestation["statement"],
            ),
        ],
    )

    # Q4: Independently verifiable? → machine_evidenced from verification_result
    q4 = QuestionAnswer(
        question_id="Q4",
        question_text="Can the result be independently verified and tamper-checked?",
        status="ANSWERED",
        authority_class="machine_evidenced",
        answer_text="Yes. Signed proof pack passes Ed25519 verification. Run `assay verify-pack` to confirm.",
        evidence_refs=[
            EvidenceRef(
                receipt_id=receipts[3]["receipt_id"],
                receipt_type="verification_result",
                authority_class="machine_evidenced",
                description="Verification result: PASS, method=jcs-ed25519",
                artifact_path="proof_pack/receipt_pack.jsonl",
            ),
        ],
    )

    # Q5: Machine vs human separation? → mixed from packet_compiled + human attestation
    q5 = QuestionAnswer(
        question_id="Q5",
        question_text="Which claims rely on machine evidence vs human attestation?",
        status="ANSWERED",
        authority_class="mixed",
        answer_text="Q1,Q2,Q4 are machine_evidenced. Q3,Q5 are mixed. Q6 is honestly unresolved.",
        evidence_refs=[
            EvidenceRef(
                receipt_id=receipts[4]["receipt_id"],
                receipt_type="packet_compiled",
                authority_class="machine_evidenced",
                description="Packet compilation receipt showing authority class breakdown",
                artifact_path="proof_pack/receipt_pack.jsonl",
            ),
            EvidenceRef(
                receipt_id=human_attestation["attestation_id"],
                receipt_type="human_attestation",
                authority_class="human_attested",
                description="Human attestation confirming policy review scope",
            ),
        ],
    )

    # Q6: Prompt injection resilience? → INSUFFICIENT_EVIDENCE (honest gap)
    q6 = QuestionAnswer(
        question_id="Q6",
        question_text="Is prompt-injection resilience proven?",
        status="INSUFFICIENT_EVIDENCE",
        authority_class="insufficient",
        answer_text=None,
        notes="Honest gap: no adversarial testing evidence exists for this workflow. "
              "This is a known limitation, not a hidden one.",
    )

    return ReviewerPacket(
        packet_id=f"rp_{run_id}",
        workflow_name="Customer Support LLM Workflow",
        workflow_description="Mid-market SaaS customer-support workflow using GPT-4o "
                            "with content-policy guardian gate.",
        questions=[q1, q2, q3, q4, q5, q6],
        proof_pack_path="./proof_pack",
        proof_pack_id=proof_pack_id,
        proof_pack_verified=proof_pack_verified,
        signer_id=signer_id,
        signer_fingerprint=signer_fingerprint,
        generated_at=_now_iso(),
    )


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def run_dir(tmp_path: Path):
    """Create the full run directory with proof pack and reviewer packet."""
    run_id = f"esprint_{uuid.uuid4().hex[:8]}"
    run_root = tmp_path / run_id

    # --- 1. Build and sign proof pack ---
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("evidence-sprint")
    signer_fingerprint = ks.signer_fingerprint("evidence-sprint")

    receipts = _build_receipts(run_id)
    claims = _build_claims()

    pack = ProofPack(
        run_id=run_id,
        entries=receipts,
        signer_id="evidence-sprint",
        claims=claims,
        mode="shadow",
    )
    pack_dir = pack.build(run_root / "proof_pack", keystore=ks)

    # --- 2. Verify proof pack ---
    manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
    verify_result = verify_pack_manifest(manifest, pack_dir, ks)
    pack_id = manifest.get("pack_id", run_id)

    # --- 3. Build reviewer packet ---
    reviewer_packet = _build_reviewer_packet(
        run_id=run_id,
        receipts=receipts,
        proof_pack_id=pack_id,
        proof_pack_verified=verify_result.passed,
        signer_id="evidence-sprint",
        signer_fingerprint=signer_fingerprint,
    )
    packet_dir = reviewer_packet.write(run_root / "reviewer_packet")

    return {
        "run_id": run_id,
        "run_root": run_root,
        "pack_dir": pack_dir,
        "packet_dir": packet_dir,
        "receipts": receipts,
        "claims": claims,
        "keystore": ks,
        "manifest": manifest,
        "verify_result": verify_result,
        "reviewer_packet": reviewer_packet,
        "signer_fingerprint": signer_fingerprint,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestProofPackIntegrity:
    """Proof pack is built, signed, and verifiable."""

    def test_pack_files_exist(self, run_dir):
        pack_dir = run_dir["pack_dir"]
        for name in [
            "receipt_pack.jsonl",
            "pack_manifest.json",
            "pack_signature.sig",
            "verify_report.json",
            "verify_transcript.md",
        ]:
            assert (pack_dir / name).exists(), f"Missing: {name}"

    def test_multiple_receipts(self, run_dir):
        pack_dir = run_dir["pack_dir"]
        lines = [
            ln for ln in (pack_dir / "receipt_pack.jsonl").read_text().splitlines()
            if ln.strip()
        ]
        assert len(lines) >= 4, f"Expected >= 4 receipts, got {len(lines)}"

    def test_signed_pack_verifies(self, run_dir):
        assert run_dir["verify_result"].passed, (
            f"Proof pack verification failed: "
            f"{[e.message for e in run_dir['verify_result'].errors]}"
        )

    def test_claims_pass(self, run_dir):
        report = json.loads(
            (run_dir["pack_dir"] / "verify_report.json").read_text()
        )
        claim_v = report.get("claim_verification", {})
        assert claim_v.get("passed", False), f"Claims failed: {claim_v}"


class TestReviewerPacket:
    """Reviewer packet is generated with correct structure."""

    def test_packet_files_exist(self, run_dir):
        packet_dir = run_dir["packet_dir"]
        for name in [
            "packet.json",
            "questionnaire_answers.json",
            "evidence_index.json",
            "reviewer_summary.md",
        ]:
            assert (packet_dir / name).exists(), f"Missing: {name}"

    def test_six_questions_present(self, run_dir):
        packet = run_dir["reviewer_packet"]
        assert len(packet.questions) == 6

    def test_at_least_one_unresolved(self, run_dir):
        packet = run_dir["reviewer_packet"]
        assert packet.unresolved_count >= 1, "No honestly unresolved questions"

    def test_q6_is_unresolved(self, run_dir):
        packet = run_dir["reviewer_packet"]
        q6 = next(q for q in packet.questions if q.question_id == "Q6")
        assert q6.status == "INSUFFICIENT_EVIDENCE"
        assert q6.authority_class == "insufficient"

    def test_authority_classes_visible(self, run_dir):
        packet = run_dir["reviewer_packet"]
        classes = {q.authority_class for q in packet.questions}
        assert "machine_evidenced" in classes
        assert "mixed" in classes
        assert "insufficient" in classes

    def test_answered_questions_have_evidence(self, run_dir):
        packet = run_dir["reviewer_packet"]
        for q in packet.questions:
            if q.status == "ANSWERED":
                assert len(q.evidence_refs) > 0, (
                    f"{q.question_id} is ANSWERED but has no evidence refs"
                )

    def test_packet_json_roundtrip(self, run_dir):
        packet_dir = run_dir["packet_dir"]
        packet_dict = json.loads((packet_dir / "packet.json").read_text())
        assert packet_dict["schema_version"] == "0.1.0"
        assert packet_dict["proof_pack_verified"] is True
        assert len(packet_dict["questions"]) == 6
        assert packet_dict["summary"]["answered"] == 5
        assert packet_dict["summary"]["unresolved"] == 1

    def test_evidence_index_has_all_refs(self, run_dir):
        packet_dir = run_dir["packet_dir"]
        index = json.loads((packet_dir / "evidence_index.json").read_text())
        packet = run_dir["reviewer_packet"]
        for q in packet.questions:
            for ref in q.evidence_refs:
                assert ref.receipt_id in index, (
                    f"Evidence ref {ref.receipt_id} missing from evidence_index.json"
                )

    def test_reviewer_summary_mentions_gap(self, run_dir):
        packet_dir = run_dir["packet_dir"]
        summary = (packet_dir / "reviewer_summary.md").read_text()
        assert "GAP" in summary or "INSUFFICIENT_EVIDENCE" in summary or "unresolved" in summary.lower()


class TestPacketValidation:
    """Packet validator catches real issues and passes clean packets."""

    def test_clean_packet_passes(self, run_dir):
        packet = run_dir["reviewer_packet"]
        receipts = run_dir["receipts"]
        human_att = json.loads(
            (FIXTURES_DIR / "human_attestation.json").read_text()
        )
        receipt_ids = {r["receipt_id"] for r in receipts}
        receipt_ids.add(human_att["attestation_id"])

        result = validate_packet(
            packet,
            receipt_ids_on_disk=receipt_ids,
            require_unresolved=True,
        )
        assert result.passed, (
            f"Clean packet should pass: {[e.to_dict() for e in result.errors]}"
        )

    def test_validator_with_proof_pack_reverification(self, run_dir):
        packet = run_dir["reviewer_packet"]
        result = validate_packet(
            packet,
            proof_pack_dir=run_dir["pack_dir"],
        )
        assert result.passed


class TestTamperA:
    """Tamper A: mutate proof pack → verification fails."""

    def test_proof_pack_tamper_detected(self, run_dir):
        pack_dir = run_dir["pack_dir"]
        ks = run_dir["keystore"]

        # Copy the pack and tamper the receipt file
        tampered_dir = run_dir["run_root"] / "tampered_pack"
        shutil.copytree(pack_dir, tampered_dir)

        receipt_file = tampered_dir / "receipt_pack.jsonl"
        data = bytearray(receipt_file.read_bytes())
        # Change model name: gpt-4o → gpt-5x
        target = b'"gpt-4o"'
        idx = data.find(target)
        assert idx >= 0, "Could not find gpt-4o in receipt pack"
        data[idx + 1 : idx + 6] = b"gpt-5x"
        receipt_file.write_bytes(bytes(data))

        # Re-verify: must fail
        manifest = json.loads(
            (tampered_dir / "pack_manifest.json").read_text()
        )
        result = verify_pack_manifest(manifest, tampered_dir, ks)
        assert not result.passed, "Tampered pack should fail verification"
        assert any(
            "mismatch" in e.message.lower() or "tamper" in e.message.lower()
            for e in result.errors
        ), f"Expected tamper/mismatch error, got: {[e.message for e in result.errors]}"

    def test_tampered_pack_fails_packet_validation(self, run_dir):
        """Packet validation with tampered proof pack fails E_VERIFICATION_MISMATCH."""
        pack_dir = run_dir["pack_dir"]
        packet = run_dir["reviewer_packet"]

        tampered_dir = run_dir["run_root"] / "tampered_pack_for_validator"
        shutil.copytree(pack_dir, tampered_dir)

        receipt_file = tampered_dir / "receipt_pack.jsonl"
        data = bytearray(receipt_file.read_bytes())
        target = b'"gpt-4o"'
        idx = data.find(target)
        assert idx >= 0
        data[idx + 1 : idx + 6] = b"gpt-5x"
        receipt_file.write_bytes(bytes(data))

        result = validate_packet(
            packet,
            proof_pack_dir=tampered_dir,
        )
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_VERIFICATION_MISMATCH in error_codes, (
            f"Expected E_VERIFICATION_MISMATCH, got: {error_codes}"
        )


class TestTamperB:
    """Tamper B: inflate Q6 from INSUFFICIENT_EVIDENCE to ANSWERED → validator fails."""

    def test_answer_inflation_detected(self, run_dir):
        """Mutate Q6 to claim ANSWERED + machine_evidenced with no evidence."""
        packet = run_dir["reviewer_packet"]

        # Deep copy and inflate Q6
        inflated = copy.deepcopy(packet)
        q6 = next(q for q in inflated.questions if q.question_id == "Q6")
        q6.status = "ANSWERED"
        q6.authority_class = "machine_evidenced"
        # Crucially: no evidence_refs added

        result = validate_packet(inflated, require_unresolved=True)
        assert not result.passed, "Inflated packet should fail validation"

        error_codes = {e.code for e in result.errors}
        # Must catch at least one of these inflation signals
        inflation_codes = {
            E_MISSING_EVIDENCE,
            E_UNRESOLVED_RELABELED,
            E_MACHINE_CLAIM_NO_RECEIPT,
        }
        assert error_codes & inflation_codes, (
            f"Expected inflation error codes {inflation_codes}, got: {error_codes}"
        )

    def test_answer_inflation_with_authority_inflated(self, run_dir):
        """Mutate Q6 to ANSWERED + insufficient → E_AUTHORITY_INFLATED."""
        packet = run_dir["reviewer_packet"]

        inflated = copy.deepcopy(packet)
        q6 = next(q for q in inflated.questions if q.question_id == "Q6")
        q6.status = "ANSWERED"
        # Leave authority_class as 'insufficient' — contradicts ANSWERED
        q6.authority_class = "insufficient"

        result = validate_packet(inflated)
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_AUTHORITY_INFLATED in error_codes, (
            f"Expected E_AUTHORITY_INFLATED, got: {error_codes}"
        )

    def test_inflation_from_disk_roundtrip(self, run_dir):
        """Write packet to disk, tamper the JSON, re-validate — must fail."""
        packet = run_dir["reviewer_packet"]
        packet_dir = run_dir["packet_dir"]

        # Load from disk
        packet_dict = json.loads((packet_dir / "packet.json").read_text())

        # Find Q6 and inflate it
        for q in packet_dict["questions"]:
            if q["question_id"] == "Q6":
                q["status"] = "ANSWERED"
                q["authority_class"] = "machine_evidenced"
                # No evidence_refs added
                break

        # Write tampered packet back
        tampered_path = run_dir["run_root"] / "tampered_packet.json"
        tampered_path.write_text(json.dumps(packet_dict, indent=2))

        # Validate from dict
        from assay.reviewer_packet_validator import validate_packet_dict
        result = validate_packet_dict(packet_dict)
        assert not result.passed, "Tampered packet.json should fail validation"


class TestArtifactPathIntegrity:
    """Validator checks that artifact_path refs resolve to real files."""

    def test_valid_artifact_paths_pass(self, run_dir):
        """All artifact_path refs in the clean packet point to existing files."""
        packet = run_dir["reviewer_packet"]
        result = validate_packet(packet, proof_pack_dir=run_dir["pack_dir"])
        assert result.passed
        # No artifact-path errors
        path_errors = {e.code for e in result.errors} & {
            E_ARTIFACT_PATH_MISSING, E_ARTIFACT_PATH_ESCAPE
        }
        assert not path_errors

    def test_missing_artifact_path_caught(self, run_dir):
        """Fabricated artifact_path that doesn't exist is caught."""
        packet = copy.deepcopy(run_dir["reviewer_packet"])
        packet.questions[0].evidence_refs[0].artifact_path = "proof_pack/nonexistent.jsonl"
        result = validate_packet(packet, proof_pack_dir=run_dir["pack_dir"])
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_ARTIFACT_PATH_MISSING in error_codes

    def test_path_escape_caught(self, run_dir):
        """artifact_path that escapes the packet root is caught."""
        packet = copy.deepcopy(run_dir["reviewer_packet"])
        packet.questions[0].evidence_refs[0].artifact_path = "../../etc/passwd"
        result = validate_packet(packet, proof_pack_dir=run_dir["pack_dir"])
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_ARTIFACT_PATH_ESCAPE in error_codes

    def test_sibling_prefix_escape_caught(self, run_dir):
        """Sibling directory with shared prefix stem is caught.

        e.g. root=/tmp/proof_pack, target=/tmp/proof_pack_evil/file.json
        String prefix check would pass this; semantic relative_to does not.
        """
        packet = copy.deepcopy(run_dir["reviewer_packet"])
        # proof_pack_dir.parent is the run_root. A sibling with the same
        # prefix stem but different suffix escapes the real root.
        run_root = run_dir["run_root"]
        evil_dir = run_root.parent / (run_root.name + "_evil")
        evil_dir.mkdir(exist_ok=True)
        (evil_dir / "fake.jsonl").write_text("{}")
        # Build a relative path that resolves to the evil sibling
        # from the packet root (run_root):  ../<run_root_name>_evil/fake.jsonl
        relative_escape = f"../{run_root.name}_evil/fake.jsonl"
        packet.questions[0].evidence_refs[0].artifact_path = relative_escape
        result = validate_packet(packet, proof_pack_dir=run_dir["pack_dir"])
        assert not result.passed
        error_codes = {e.code for e in result.errors}
        assert E_ARTIFACT_PATH_ESCAPE in error_codes


class TestFixtureConsistency:
    """Questionnaire fixture stays consistent with the hardcoded scenario."""

    def test_fixture_question_count_matches(self):
        """questionnaire.json has exactly 6 questions."""
        q = json.loads((FIXTURES_DIR / "questionnaire.json").read_text())
        assert len(q["questions"]) == 6

    def test_fixture_question_ids_match_scenario(self, run_dir):
        """Fixture question_ids match the test scenario Q1-Q6."""
        q = json.loads((FIXTURES_DIR / "questionnaire.json").read_text())
        fixture_ids = {qn["question_id"] for qn in q["questions"]}
        scenario_ids = {qa.question_id for qa in run_dir["reviewer_packet"].questions}
        assert fixture_ids == scenario_ids

    def test_fixture_q6_expects_insufficient(self):
        """Fixture declares Q6 as INSUFFICIENT_EVIDENCE."""
        q = json.loads((FIXTURES_DIR / "questionnaire.json").read_text())
        q6 = next(qn for qn in q["questions"] if qn["question_id"] == "Q6")
        assert q6["expected_status"] == "INSUFFICIENT_EVIDENCE"
        assert q6["expected_authority"] == "insufficient"

    def test_human_attestation_fixture_loads(self):
        """human_attestation.json is valid and has required fields."""
        ha = json.loads((FIXTURES_DIR / "human_attestation.json").read_text())
        assert "attestation_id" in ha
        assert "type" in ha
        assert ha["type"] == "human_attestation"


class TestOutputStructure:
    """The test produces the exact output folder structure from the pass bar."""

    def test_full_output_tree(self, run_dir):
        run_root = run_dir["run_root"]

        # Proof pack kernel
        assert (run_root / "proof_pack" / "receipt_pack.jsonl").exists()
        assert (run_root / "proof_pack" / "pack_manifest.json").exists()
        assert (run_root / "proof_pack" / "pack_signature.sig").exists()

        # Reviewer packet
        assert (run_root / "reviewer_packet" / "packet.json").exists()
        assert (run_root / "reviewer_packet" / "reviewer_summary.md").exists()
        assert (run_root / "reviewer_packet" / "questionnaire_answers.json").exists()
        assert (run_root / "reviewer_packet" / "evidence_index.json").exists()
