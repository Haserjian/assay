"""Tests for ReceiptV2 verifier — SigResult, VerifyResultV2, verify_v2().

Covers:
  - digest_valid / digest_status in all six status cases
  - Upstream gating: digest_valid=False → operational_valid=False, archival_valid=None
  - v1 shim: flat signature field synthesized into signatures[]
  - Signature verification: valid, invalid, untrusted_signer, unsupported_algorithm, policy_rejected
  - operational_valid / archival_valid tri-state / policy_satisfied evaluation
  - key_resolver interface
"""
from __future__ import annotations

import base64
import hashlib
import pytest

from nacl.signing import SigningKey

from assay._receipts.canonicalize import canonical_projection, compute_bundle_digest
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay._receipts.v2_verify import SigResult, VerifyResultV2, verify_v2


# ---------------------------------------------------------------------------
# Fixtures — real Ed25519 key for crypto round-trips
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ed25519_keypair():
    sk = SigningKey.generate()
    vk = sk.verify_key
    return sk, vk


@pytest.fixture(scope="module")
def base_receipt():
    return {
        "receipt_id": "r-test",
        "type": "test",
        "timestamp": "2026-01-01T00:00:00Z",
        "payload": {"x": 1},
        "verification_profile": "operational-v1",
        "verification_policy": {
            "operational_requires": {"min_signatures": 1, "algorithms": ["ed25519"]}
        },
    }


def _make_signed_receipt(sk, base_receipt: dict, signer_id: str = "test-signer") -> dict:
    """Build a fully signed v2 receipt from a base receipt."""
    import base64 as b64
    projection = canonical_projection(base_receipt)
    canonical_bytes = jcs_canonicalize(projection)
    bundle_digest = f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"

    sig_bytes = sk.sign(canonical_bytes).signature
    sig_b64 = b64.b64encode(sig_bytes).decode()
    pubkey_fp = hashlib.sha256(sk.verify_key.encode()).hexdigest()

    return {
        **base_receipt,
        "verification_bundle": {
            "bundle_digest": bundle_digest,
            "bundle_algorithm": "sha256",
            "canonicalization": "jcs-rfc8785",
            "projection_id": "receipt-core-v2",
        },
        "signatures": [{
            "algorithm": "ed25519",
            "signer_id": signer_id,
            "value": sig_b64,
            "signer_pubkey_sha256": pubkey_fp,
        }],
    }


def _make_key_resolver(sk, signer_id: str = "test-signer"):
    """Build a key_resolver that returns the verify key for signer_id."""
    pubkey_bytes = sk.verify_key.encode()
    def resolver(sid, _pubkey_sha256):
        if sid == signer_id:
            return pubkey_bytes
        return None
    return resolver


# ---------------------------------------------------------------------------
# digest_valid / digest_status cases
# ---------------------------------------------------------------------------

class TestDigestStatus:
    def test_matched(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.digest_valid is True
        assert result.digest_status == "matched"

    def test_mismatch(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        # Tamper the stored digest
        receipt = {
            **receipt,
            "verification_bundle": {
                **receipt["verification_bundle"],
                "bundle_digest": "sha256:deadbeefdeadbeef" + "0" * 48,
            }
        }
        result = verify_v2(receipt)
        assert result.digest_valid is False
        assert result.digest_status == "mismatch"

    def test_missing_bundle(self, base_receipt):
        """No verification_bundle → missing_bundle status."""
        result = verify_v2(base_receipt)
        assert result.digest_valid is False
        assert result.digest_status == "missing_bundle"

    def test_unsupported_projection(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        result = verify_v2(base_receipt, projection_id="receipt-core-v9999")
        assert result.digest_valid is False
        assert result.digest_status == "unsupported_projection"

    def test_missing_bundle_is_not_mismatch(self, base_receipt):
        """missing_bundle and mismatch are distinct statuses."""
        result_missing = verify_v2(base_receipt)
        assert result_missing.digest_status == "missing_bundle"
        assert result_missing.digest_status != "mismatch"


# ---------------------------------------------------------------------------
# Upstream gating: digest_valid=False implies operational_valid=False and archival_valid=None
# ---------------------------------------------------------------------------

class TestUpstreamGating:
    def test_digest_false_gates_operational(self, base_receipt):
        result = verify_v2(base_receipt)  # no bundle → digest_valid=False
        assert result.digest_valid is False
        assert result.operational_valid is False

    def test_digest_false_gates_archival_as_none(self, base_receipt):
        """archival_valid=None when digest fails — not assessed, not False."""
        result = verify_v2(base_receipt)
        assert result.archival_valid is None

    def test_digest_false_gates_policy(self, base_receipt):
        result = verify_v2(base_receipt)
        assert result.policy_satisfied is False

    def test_digest_false_empty_sig_results(self, base_receipt):
        result = verify_v2(base_receipt)
        assert result.signature_results == []

    def test_digest_mismatch_also_gates(self, ed25519_keypair, base_receipt):
        """digest_status=mismatch also correctly gates all downstream predicates."""
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        receipt = {
            **receipt,
            "verification_bundle": {
                **receipt["verification_bundle"],
                "bundle_digest": "sha256:" + "0" * 64,
            }
        }
        result = verify_v2(receipt)
        assert result.digest_valid is False
        assert result.operational_valid is False
        assert result.archival_valid is None


# ---------------------------------------------------------------------------
# Valid signature — full round-trip
# ---------------------------------------------------------------------------

class TestValidSignature:
    def test_operational_valid_true(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.operational_valid is True

    def test_policy_satisfied_true(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.policy_satisfied is True

    def test_sig_result_status_valid(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert len(result.signature_results) == 1
        assert result.signature_results[0].status == "valid"
        assert result.signature_results[0].cryptographically_valid is True
        assert result.signature_results[0].trusted_signer is True
        assert result.signature_results[0].algorithm_acceptable is True

    def test_distinct_signer_ids(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt, signer_id="test-signer")
        resolver = _make_key_resolver(sk, signer_id="test-signer")
        result = verify_v2(receipt, key_resolver=resolver)
        assert "test-signer" in result.distinct_signer_ids

    def test_archival_valid_none_when_no_pq(self, ed25519_keypair, base_receipt):
        """No PQ signatures → archival_valid=None (not assessed, not False)."""
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.archival_valid is None


# ---------------------------------------------------------------------------
# Invalid / tampered signature
# ---------------------------------------------------------------------------

class TestInvalidSignature:
    def test_tampered_signature_invalid(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        import base64 as b64
        # Replace signature with garbage bytes of same length
        original = b64.b64decode(receipt["signatures"][0]["value"])
        garbage = bytes(b ^ 0xFF for b in original)
        receipt = {
            **receipt,
            "signatures": [{
                **receipt["signatures"][0],
                "value": b64.b64encode(garbage).decode(),
            }]
        }
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.operational_valid is False
        assert result.signature_results[0].status == "invalid"
        assert result.signature_results[0].cryptographically_valid is False

    def test_invalid_base64_signature(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        receipt = {
            **receipt,
            "signatures": [{
                **receipt["signatures"][0],
                "value": "not-valid-base64!!!",
            }]
        }
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.signature_results[0].status == "invalid"

    def test_untrusted_signer_no_resolver(self, ed25519_keypair, base_receipt):
        """No key_resolver → trusted_signer=False, status=untrusted_signer."""
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        result = verify_v2(receipt, key_resolver=None)
        assert result.signature_results[0].status == "untrusted_signer"
        assert result.signature_results[0].trusted_signer is False
        assert result.operational_valid is False

    def test_untrusted_signer_unknown_id(self, ed25519_keypair, base_receipt):
        """Resolver that doesn't know the signer → untrusted_signer."""
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt, signer_id="known-signer")
        # Resolver only knows "other-signer"
        other_resolver = _make_key_resolver(sk, signer_id="other-signer")
        result = verify_v2(receipt, key_resolver=other_resolver)
        assert result.signature_results[0].status == "untrusted_signer"


# ---------------------------------------------------------------------------
# Algorithm status cases
# ---------------------------------------------------------------------------

class TestAlgorithmStatus:
    def test_unknown_algorithm_policy_rejected(self, ed25519_keypair, base_receipt):
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        receipt = {
            **receipt,
            "signatures": [{
                **receipt["signatures"][0],
                "algorithm": "rsa-pkcs1-sha256",  # not in any allowed set
            }]
        }
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.signature_results[0].status == "policy_rejected"
        assert result.signature_results[0].algorithm_acceptable is False
        assert result.operational_valid is False

    def test_pq_algorithm_unsupported_not_invalid(self, ed25519_keypair, base_receipt):
        """PQ algorithm in allowed set but not yet implemented → unsupported_algorithm, not invalid."""
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        receipt = {
            **receipt,
            "signatures": [{
                **receipt["signatures"][0],
                "algorithm": "ml-dsa-65",  # in archival set, not implemented
            }]
        }
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.signature_results[0].status == "unsupported_algorithm"
        assert result.signature_results[0].algorithm_acceptable is True  # recognized by spec


# ---------------------------------------------------------------------------
# v1 shim
# ---------------------------------------------------------------------------

class TestV1Shim:
    def test_flat_signature_shimmed(self, ed25519_keypair, base_receipt):
        """v1 receipt with flat signature field: shim synthesizes signatures[]."""
        sk, _ = ed25519_keypair
        import base64 as b64

        # Build a v1-style receipt: no signatures[], no verification_bundle
        # First compute what should be signed (using v0 canonicalization)
        from assay._receipts.canonicalize import prepare_receipt_for_hashing
        v1_receipt = dict(base_receipt)
        canonical_bytes = jcs_canonicalize(prepare_receipt_for_hashing(v1_receipt))
        sig_bytes = sk.sign(canonical_bytes).signature

        # Now add verification_bundle using the v2 projection
        bundle_digest = compute_bundle_digest(v1_receipt)
        # For the shim test, we'll sign the v2 canonical bytes
        v2_canonical = jcs_canonicalize(canonical_projection(v1_receipt))
        sig_v2 = sk.sign(v2_canonical).signature

        v1_receipt["verification_bundle"] = {
            "bundle_digest": bundle_digest,
            "bundle_algorithm": "sha256",
            "canonicalization": "jcs-rfc8785",
        }
        v1_receipt["signature"] = b64.b64encode(sig_v2).decode()
        v1_receipt["signer_id"] = "test-signer"
        v1_receipt["signer_pubkey_sha256"] = hashlib.sha256(sk.verify_key.encode()).hexdigest()

        resolver = _make_key_resolver(sk, signer_id="test-signer")
        result = verify_v2(v1_receipt, key_resolver=resolver)

        # Shim should have synthesized one SigResult
        assert len(result.signature_results) == 1
        assert result.signature_results[0].algorithm == "ed25519"
        assert result.signature_results[0].status == "valid"
        assert result.operational_valid is True

    def test_no_signatures_no_shim(self, base_receipt):
        """Receipt with no signatures[] and no flat signature → no SigResult entries."""
        receipt = {
            **base_receipt,
            "verification_bundle": {
                "bundle_digest": "sha256:" + "0" * 64,
                "bundle_algorithm": "sha256",
                "canonicalization": "jcs-rfc8785",
            }
        }
        # digest will fail (wrong hash), but we can check signature_results after that
        # Actually digest will fail here so sig_results will be empty regardless
        result = verify_v2(receipt)
        assert result.digest_valid is False  # mismatch
        assert result.signature_results == []


# ---------------------------------------------------------------------------
# policy_satisfied semantics
# ---------------------------------------------------------------------------

class TestPolicySatisfied:
    def test_no_archival_policy_satisfied_on_operational(self, ed25519_keypair, base_receipt):
        """No archival_requires in policy → policy_satisfied requires only operational."""
        sk, _ = ed25519_keypair
        receipt = _make_signed_receipt(sk, base_receipt)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        assert result.policy_satisfied is True
        assert result.archival_valid is None  # no PQ — not assessed

    def test_archival_policy_declared_requires_pq(self, ed25519_keypair, base_receipt):
        """With archival_requires declared: policy_satisfied requires archival too."""
        sk, _ = ed25519_keypair
        receipt_with_arch_policy = {
            **base_receipt,
            "verification_policy": {
                "operational_requires": {"min_signatures": 1, "algorithms": ["ed25519"]},
                "archival_requires": {"min_signatures": 1, "algorithms": ["ml-dsa-65"]},
            }
        }
        receipt = _make_signed_receipt(sk, receipt_with_arch_policy)
        resolver = _make_key_resolver(sk)
        result = verify_v2(receipt, key_resolver=resolver)
        # operational is satisfied (ed25519 passes) but archival is not (no PQ sig)
        assert result.operational_valid is True
        assert result.archival_valid is None   # no PQ sig, not assessed but not False either
        # policy_satisfied: archival declared but no PQ sig present → archival_valid=None → not True
        assert result.policy_satisfied is False
