# Buyer Simulation Test Contract

**Status:** IMPLEMENTED. 29 tests passing (0.4s). All pass bar items covered.

**Goal:** Prove Assay can produce a reviewer-ready evidence packet for a
realistic synthetic buyer-review simulation: one scenario, one
questionnaire, one signed proof pack, one reviewer packet, one explicit
evidence gap, one successful verification, one failed tamper attempt.

**What this is:** CI-stable buyer-packet simulation using realistic
synthetic receipts that mirror the shape of real OpenAI integration output.
**What this is not:** A live integration test, or a substitute for the
production reviewer-packet compile/verify path in `reviewer_packet_compile.py`.

**Test name:** `tests/e2e/test_reviewer_packet_evidence_sprint.py`

**Scenario:** Mid-market SaaS company uses an LLM in a customer-support
workflow. A prospect reviewer asks 6 governance/security questions.

## Questionnaire

Q1: Which model/provider executed the workflow? → ANSWERED (machine_evidenced)
Q2: Is there evidence the workflow was actually executed? → ANSWERED (machine_evidenced)
Q3: Was a policy/safety gate evaluated before model execution? → ANSWERED (mixed)
Q4: Can the result be independently verified and tamper-checked? → ANSWERED (machine_evidenced)
Q5: Which claims rely on machine evidence vs human attestation? → ANSWERED (mixed)
Q6: Is prompt-injection resilience proven? → INSUFFICIENT_EVIDENCE (honest gap)

## Required artifacts
- Multiple receipts (model_call, guardian_verdict, guardian_decision, verification_result, packet_compiled)
- Signed proof pack
- Reviewer packet with authority classes and evidence index
- Tamper test A: proof-pack mutation → verify fails
- Tamper test B: answer inflation (Q6 → ANSWERED) → packet consistency fails

## Pass criteria
- At least one question is honestly unresolved
- No unsupported question marked ANSWERED with machine_evidenced
- All cited evidence receipt_ids exist in proof pack; artifact_path refs resolve to existing files
- Packet visibly separates authority classes

## Implementation (2026-03-17)

**New modules:**
- `src/assay/reviewer_packet.py` — `EvidenceRef`, `QuestionAnswer`, `ReviewerPacket` dataclasses
- `src/assay/reviewer_packet_validator.py` — 11 error codes, 5 anti-inflation checks + 2 artifact-path checks

**Fixtures:**
- `tests/fixtures/evidence_sprint_minirepo/questionnaire.json` — 6 questions
- `tests/fixtures/evidence_sprint_minirepo/human_attestation.json` — human attestation

**Test:** `tests/e2e/test_reviewer_packet_evidence_sprint.py` — 29 tests across 8 test classes:
- `TestProofPackIntegrity` (4) — files, receipts, signing, claims
- `TestReviewerPacket` (9) — structure, questions, authority, roundtrip, evidence index
- `TestPacketValidation` (2) — clean pass, proof pack re-verification
- `TestTamperA` (2) — proof-pack mutation, validator catch
- `TestTamperB` (3) — answer inflation (in-memory, authority, disk roundtrip)
- `TestArtifactPathIntegrity` (4) — valid paths pass, missing caught, escape caught, sibling-prefix caught
- `TestFixtureConsistency` (4) — fixture/scenario alignment, Q6 status, human attestation
- `TestOutputStructure` (1) — full output tree

**Test ladder:** live_receipt_smoke → constitutional_episode_runtime → reviewer_packet_evidence_sprint.
