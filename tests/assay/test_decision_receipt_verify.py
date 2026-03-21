"""Tests for Decision Receipt signature verification in Assay.

Proves: CCIO-signed receipts verify correctly through Assay's standalone
verifier. This is the cross-repo verification boundary.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

from assay.decision_receipt_verify import (
    VerificationKeyRequired,
    make_verifier_with_key,
    verify_decision_receipt,
)
from assay.decision_receipt_trust import (
    DecisionReceiptTrustState,
    classify_trust,
)

needs_nacl = pytest.mark.skipif(not HAS_NACL, reason="PyNaCl not installed")


def _make_receipt() -> Dict[str, Any]:
    """Minimal valid unsigned Decision Receipt for testing."""
    return {
        "receipt_id": "verify-test-001",
        "receipt_type": "decision_v1",
        "receipt_version": "0.1.0",
        "ceid": None,
        "timestamp": "2026-03-21T12:00:00.000Z",
        "parent_receipt_id": None,
        "supersedes": None,
        "decision_type": "guardian_constitutional_refusal",
        "decision_subject": "test:verify",
        "verdict": "REFUSE",
        "verdict_reason": "Test verification",
        "verdict_reason_codes": ["clarity_check_failed", "domain:epistemic"],
        "authority_id": "ccio:settlement:guardian_seat",
        "authority_class": "BINDING",
        "authority_scope": "constitutional_baseline",
        "delegated_from": None,
        "policy_id": "ccio.settlement.constitutional_baseline.v1",
        "policy_hash": "a" * 64,
        "episode_id": "ep-verify-001",
        "source_organ": "ccio",
        "disposition": "block",
        "disposition_target": None,
        "obligations_created": [],
        "evidence_refs": [],
        "evidence_sufficient": True,
        "evidence_gaps": [],
        "confidence": "high",
        "conflict_refs": [],
        "dissent": None,
        "abstention_reason": None,
        "unresolved_contradictions": [],
        "proof_tier_at_decision": None,
        "proof_tier_achieved": None,
        "proof_tier_minimum_required": None,
        "provenance_complete": True,
        "known_provenance_gaps": [],
        "content_hash": None,
        "signature": None,
        "signer_pubkey_sha256": None,
    }


def _sign_receipt_standalone(receipt: Dict[str, Any], sk: "SigningKey") -> Dict[str, Any]:
    """Sign a receipt using the same canonical algorithm as CCIO.

    This reimplements the signing inline so the test doesn't import CCIO.
    """
    import hashlib

    # Same canonical byte extraction as CCIO's sign.py and Assay's verify.py
    excluded = {"content_hash", "signature", "signer_pubkey_sha256"}
    hashable = {k: v for k, v in receipt.items() if k not in excluded and v is not None}
    if "verdict_reason_codes" in hashable and isinstance(hashable["verdict_reason_codes"], list):
        hashable["verdict_reason_codes"] = sorted(set(hashable["verdict_reason_codes"]))
    if "evidence_refs" in hashable and isinstance(hashable["evidence_refs"], list):
        hashable["evidence_refs"] = sorted(
            hashable["evidence_refs"],
            key=lambda r: json.dumps(r, sort_keys=True, separators=(",", ":")),
        )
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    # content_hash
    receipt["content_hash"] = hashlib.sha256(canonical).hexdigest()

    # signer identity
    vk = sk.verify_key
    receipt["signer_pubkey_sha256"] = hashlib.sha256(bytes(vk)).hexdigest()

    # Ed25519 signature
    signed = sk.sign(canonical)
    receipt["signature"] = base64.b64encode(signed.signature).decode("ascii")

    return receipt


# ---------------------------------------------------------------------------
# Cross-repo verification
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# P2 fix: verify_decision_receipt raises instead of lying
# ---------------------------------------------------------------------------

class TestVerifierApiContract:

    def test_verify_decision_receipt_raises_without_key(self):
        """The top-level verifier must not silently return False."""
        receipt = _make_receipt()
        with pytest.raises(VerificationKeyRequired):
            verify_decision_receipt(receipt)

    def test_error_message_mentions_make_verifier(self):
        receipt = _make_receipt()
        with pytest.raises(VerificationKeyRequired, match="make_verifier_with_key"):
            verify_decision_receipt(receipt)


# ---------------------------------------------------------------------------
# Cross-repo verification
# ---------------------------------------------------------------------------

@needs_nacl
class TestCrossRepoVerification:
    """Prove Assay can verify receipts signed by CCIO's algorithm."""

    def test_signed_receipt_verifies_in_assay(self):
        sk = SigningKey(b"\xcc" * 32)
        receipt = _sign_receipt_standalone(_make_receipt(), sk)

        verifier = make_verifier_with_key(bytes(sk.verify_key))
        assert verifier(receipt) is True

    def test_tampered_receipt_fails_in_assay(self):
        sk = SigningKey(b"\xcc" * 32)
        receipt = _sign_receipt_standalone(_make_receipt(), sk)

        receipt["verdict"] = "APPROVE"  # tamper

        verifier = make_verifier_with_key(bytes(sk.verify_key))
        assert verifier(receipt) is False

    def test_wrong_key_fails_in_assay(self):
        sk = SigningKey(b"\xcc" * 32)
        receipt = _sign_receipt_standalone(_make_receipt(), sk)

        other_key = SigningKey(b"\xdd" * 32)
        verifier = make_verifier_with_key(bytes(other_key.verify_key))
        assert verifier(receipt) is False


# ---------------------------------------------------------------------------
# Trust evaluator integration
# ---------------------------------------------------------------------------

@needs_nacl
class TestTrustEvaluatorIntegration:
    """End-to-end: signed receipt → classify_trust → VERIFIED."""

    def test_signed_receipt_classified_as_verified(self):
        sk = SigningKey(b"\xee" * 32)
        receipt = _sign_receipt_standalone(_make_receipt(), sk)

        verifier = make_verifier_with_key(bytes(sk.verify_key))
        trust = classify_trust(receipt, verify_signature=verifier)
        assert trust.state == DecisionReceiptTrustState.VERIFIED
        assert trust.is_trustworthy

    def test_tampered_receipt_classified_as_invalid(self):
        sk = SigningKey(b"\xee" * 32)
        receipt = _sign_receipt_standalone(_make_receipt(), sk)
        receipt["verdict"] = "APPROVE"  # tamper

        verifier = make_verifier_with_key(bytes(sk.verify_key))
        trust = classify_trust(receipt, verify_signature=verifier)
        assert trust.state == DecisionReceiptTrustState.INVALID

    def test_unsigned_receipt_classified_as_unsigned(self):
        receipt = _make_receipt()
        receipt["content_hash"] = "f" * 64

        trust = classify_trust(receipt)
        assert trust.state == DecisionReceiptTrustState.UNSIGNED

    def test_signed_no_key_classified_as_unverifiable(self):
        sk = SigningKey(b"\xee" * 32)
        receipt = _sign_receipt_standalone(_make_receipt(), sk)

        # No verifier provided
        trust = classify_trust(receipt)
        assert trust.state == DecisionReceiptTrustState.UNVERIFIABLE


# ---------------------------------------------------------------------------
# Cross-repo golden vector
# ---------------------------------------------------------------------------

@needs_nacl
class TestGoldenVector:
    """Shared golden vector — same fixture as CCIO. Proves contract fidelity."""

    def test_golden_vector_verifies_in_assay(self):
        """CCIO-produced golden signature verifies through Assay's standalone verifier."""
        import copy
        from pathlib import Path

        vector_path = Path(__file__).parent / "golden_vector.json"
        vector = json.loads(vector_path.read_text())

        # Reconstruct the signed receipt from the vector
        receipt = copy.deepcopy(vector["receipt"])
        receipt["content_hash"] = vector["expected"]["content_hash"]
        receipt["signature"] = vector["expected"]["signature"]
        receipt["signer_pubkey_sha256"] = vector["expected"]["signer_pubkey_sha256"]

        # Verify using Assay's standalone verifier with the known public key
        import base64 as b64
        pubkey_bytes = b64.b64decode(vector["expected"]["pubkey_b64"])
        verifier = make_verifier_with_key(pubkey_bytes)
        assert verifier(receipt) is True

    def test_golden_vector_trust_state_is_verified(self):
        """Golden vector receipt classifies as VERIFIED through trust evaluator."""
        import copy
        from pathlib import Path

        vector_path = Path(__file__).parent / "golden_vector.json"
        vector = json.loads(vector_path.read_text())

        receipt = copy.deepcopy(vector["receipt"])
        receipt["content_hash"] = vector["expected"]["content_hash"]
        receipt["signature"] = vector["expected"]["signature"]
        receipt["signer_pubkey_sha256"] = vector["expected"]["signer_pubkey_sha256"]

        import base64 as b64
        pubkey_bytes = b64.b64decode(vector["expected"]["pubkey_b64"])
        verifier = make_verifier_with_key(pubkey_bytes)

        trust = classify_trust(receipt, verify_signature=verifier)
        assert trust.state == DecisionReceiptTrustState.VERIFIED
        assert trust.is_trustworthy
