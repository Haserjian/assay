#!/usr/bin/env python3
"""
Settlement Gate Example

Demonstrates the episode SDK with a real consequence boundary:
an insurance claim agent that must prove its evidence posture
before sending a decision to a policyholder.

Two acts:
  Act 1: Agent drafts approval, guardian approves, evidence passes → sends.
  Act 2: Agent drafts denial, guardian blocks (missing rationale) → escalates.

No API key. No account. Runs in seconds.

    python examples/settlement_gate.py

This is the "Mode 2 + Mode 3" pattern:
  - Mode 2 (Runtime): open_episode / emit / seal_checkpoint
  - Mode 3 (Settlement): verify_checkpoint before consequence
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import assay
from assay.claim_verifier import ClaimSpec

# -----------------------------------------------------------------------
# Simulated agent components
# -----------------------------------------------------------------------

def draft_decision(claim_id: str, recommendation: str) -> dict:
    """Agent drafts a claim decision."""
    return {
        "claim_id": claim_id,
        "recommendation": recommendation,
        "rationale": f"Based on policy review, recommend {recommendation}.",
        "model": "gpt-4",
        "confidence": 0.92,
    }


def guardian_check(decision: dict, *, require_rationale: bool = True) -> dict:
    """Policy guardian evaluates the decision before send."""
    approved = True
    reasons = []

    if require_rationale and not decision.get("rationale"):
        approved = False
        reasons.append("missing_rationale")

    if decision.get("confidence", 0) < 0.7:
        approved = False
        reasons.append("low_confidence")

    return {
        "approved": approved,
        "reasons": reasons or ["policy_compliant"],
        "policy": "outbound_decision_v2",
    }


def send_decision(claim_id: str, recommendation: str) -> None:
    """Send decision to policyholder. This is the irreversible action."""
    print(f"    [SENT] Decision for {claim_id}: {recommendation}")


def escalate(claim_id: str, reasons: list) -> None:
    """Escalate to human reviewer. Safe fallback."""
    print(f"    [ESCALATED] {claim_id} to human review: {', '.join(reasons)}")


# -----------------------------------------------------------------------
# Claims: what we require before sending
# -----------------------------------------------------------------------

SEND_CLAIMS = [
    ClaimSpec(
        claim_id="guardian_present",
        description="Guardian must evaluate before send",
        check="receipt_type_present",
        params={"receipt_type": "guardian.approved"},
        severity="critical",
    ),
]


# -----------------------------------------------------------------------
# Act 1: Clean path — guardian approves, evidence passes, action settles
# -----------------------------------------------------------------------

def act_1(work_dir: Path) -> None:
    print("=" * 62)
    print("  ACT 1: Clean approval path")
    print("=" * 62)
    print()

    with assay.open_episode(
        policy_version="outbound_decision_v2",
        guardian_profile="standard",
        risk_class="medium",
        claims=SEND_CLAIMS,
    ) as episode:

        # Step 1: Agent drafts decision
        decision = draft_decision("CLM-2024-0847", "approve")
        r1 = episode.emit("model.invoked", {
            "model": decision["model"],
            "claim_id": decision["claim_id"],
            "recommendation": decision["recommendation"],
            "confidence": decision["confidence"],
        })
        print(f"  1. Agent drafted: approve CLM-2024-0847 (conf={decision['confidence']})")

        # Step 2: Guardian evaluates
        guardian = guardian_check(decision)
        if guardian["approved"]:
            r2 = episode.emit("guardian.approved", {
                "action": "send_decision",
                "policy": guardian["policy"],
                "reasons": guardian["reasons"],
            }, parent_receipt_id=r1)
            print(f"  2. Guardian: APPROVED ({guardian['policy']})")
        else:
            r2 = episode.emit("guardian.blocked", {
                "action": "send_decision",
                "policy": guardian["policy"],
                "reasons": guardian["reasons"],
            }, parent_receipt_id=r1)
            print(f"  2. Guardian: BLOCKED ({guardian['reasons']})")

        # Step 3: Seal checkpoint before irreversible send
        checkpoint = episode.seal_checkpoint(
            reason="before_send_decision",
            output_dir=work_dir / "act1_pack",
        )
        print(f"  3. Checkpoint sealed: {checkpoint.receipt_count} receipts")

        # Step 4: Verify — this is the settlement gate
        verdict = assay.verify_checkpoint(checkpoint, claims=SEND_CLAIMS)
        print(f"  4. Verdict: integrity={'PASS' if verdict.integrity_pass else 'FAIL'}"
              f"  claims={'PASS' if verdict.claims_pass else 'FAIL'}")

        # Step 5: Settle or escalate
        if verdict.ok:
            send_decision("CLM-2024-0847", "approve")
            episode.emit("action.settled", {
                "action": "send_decision",
                "claim_id": "CLM-2024-0847",
            })
        elif verdict.honest_fail:
            escalate("CLM-2024-0847", verdict.errors)
            episode.emit("action.denied", {
                "reason": "honest_fail",
                "errors": verdict.errors,
            })
        else:
            escalate("CLM-2024-0847", ["evidence_tampered"])
            episode.emit("action.denied", {"reason": "tampered"})

    print(f"\n  Pack: {checkpoint.pack_dir}")
    print(f"  Verify: assay verify-pack {checkpoint.pack_dir}")
    print()


# -----------------------------------------------------------------------
# Act 2: Guardian blocks — honest failure, action denied
# -----------------------------------------------------------------------

def act_2(work_dir: Path) -> None:
    print("=" * 62)
    print("  ACT 2: Guardian blocks — honest failure")
    print("=" * 62)
    print()

    with assay.open_episode(
        policy_version="outbound_decision_v2",
        guardian_profile="strict",
        risk_class="high",
        claims=SEND_CLAIMS,
    ) as episode:

        # Step 1: Agent drafts decision (denial, high stakes)
        decision = draft_decision("CLM-2024-1193", "deny")
        r1 = episode.emit("model.invoked", {
            "model": decision["model"],
            "claim_id": decision["claim_id"],
            "recommendation": decision["recommendation"],
            "confidence": decision["confidence"],
        })
        print(f"  1. Agent drafted: deny CLM-2024-1193 (conf={decision['confidence']})")

        # Step 2: Guardian blocks (simulating policy requiring
        # human review for all denials under strict profile)
        episode.emit("guardian.blocked", {
            "action": "send_decision",
            "policy": "outbound_decision_v2",
            "reasons": ["denial_requires_human_review"],
        }, parent_receipt_id=r1)
        print(f"  2. Guardian: BLOCKED (denial_requires_human_review)")

        # Note: no "guardian.approved" receipt was emitted.
        # The claim check will catch this.

        # Step 3: Seal checkpoint
        checkpoint = episode.seal_checkpoint(
            reason="before_send_decision",
            output_dir=work_dir / "act2_pack",
        )
        print(f"  3. Checkpoint sealed: {checkpoint.receipt_count} receipts")

        # Step 4: Verify — this SHOULD fail on claims
        verdict = assay.verify_checkpoint(checkpoint, claims=SEND_CLAIMS)
        print(f"  4. Verdict: integrity={'PASS' if verdict.integrity_pass else 'FAIL'}"
              f"  claims={'PASS' if verdict.claims_pass else 'FAIL'}")

        # Step 5: Settlement gate prevents send
        if verdict.ok:
            send_decision("CLM-2024-1193", "deny")
            episode.emit("action.settled", {
                "action": "send_decision",
                "claim_id": "CLM-2024-1193",
            })
        elif verdict.honest_fail:
            escalate("CLM-2024-1193", verdict.errors)
            episode.emit("action.denied", {
                "reason": "honest_fail",
                "errors": verdict.errors,
            })
        else:
            escalate("CLM-2024-1193", ["evidence_tampered"])
            episode.emit("action.denied", {"reason": "tampered"})

    print(f"\n  Pack: {checkpoint.pack_dir}")
    print(f"  Verify: assay verify-pack {checkpoint.pack_dir}")
    print()


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main() -> None:
    print()
    print("  ASSAY SETTLEMENT GATE DEMO")
    print("  Insurance claim agent with evidence-gated send")
    print()

    with tempfile.TemporaryDirectory() as tmp:
        work_dir = Path(tmp)
        act_1(work_dir)
        act_2(work_dir)

    print("=" * 62)
    print("  SUMMARY")
    print("=" * 62)
    print()
    print("  Act 1: Guardian approved → evidence passed → decision SENT")
    print("  Act 2: Guardian blocked  → honest failure  → ESCALATED")
    print()
    print("  Both acts produced signed proof packs.")
    print("  The settlement gate prevented Act 2 from sending")
    print("  because the required guardian.approved receipt was absent.")
    print()
    print("  A signed failure is stronger evidence than a vague pass.")
    print()


if __name__ == "__main__":
    main()
