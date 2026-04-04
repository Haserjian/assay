"""
Security invariant tests — enforce security/invariants.yaml in CI.

Adjudicated 2026-04-03. Tests reflect the settled invariant set, not the
full pre-adjudication audit findings.
See: docs/security/SECURITY_AUDIT_ADJUDICATION_2026-04-03.md

Active invariants covered here:
  INV-04: PQ algorithms must not be in OPERATIONAL_ALGORITHMS while unimplemented
      (tests confirm ambiguous dual-membership is the bug)
  INV-07: ASCII-only field-name validation before projection/canonicalization

Active invariants tracked elsewhere:
  INV-02: Gate vs verify split — CI topology, not unit-testable here
  INV-06: JCS normalization boundary — ENFORCED, no test needed

Hardening candidates beyond the current implementation:
    broader TR39-style confusable screening above the ASCII-only key policy
"""

from __future__ import annotations

import base64
import hashlib
import warnings

import pytest
from nacl.signing import SigningKey

from assay._receipts.canonicalize import (
    canonical_projection,
    prepare_receipt_for_hashing,
)
from assay._receipts.jcs import canonicalize as jcs_canonicalize
from assay._receipts.v2_types import OPERATIONAL_ALGORITHMS, UNSUPPORTED_ALGORITHMS
from assay._receipts.v2_verify import verify_v2

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

DETERMINISTIC_SEED = b"\x00" * 32  # never use in production


@pytest.fixture(scope="module")
def test_keypair():
    sk = SigningKey(DETERMINISTIC_SEED)
    return sk, sk.verify_key


def _sign_receipt(base: dict, sk: SigningKey, signer_id: str = "test-signer") -> dict:
    projection = canonical_projection(base)
    canonical_bytes = jcs_canonicalize(projection)
    bundle_digest = f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"
    sig_b64 = base64.b64encode(sk.sign(canonical_bytes).signature).decode()
    pubkey_fp = hashlib.sha256(sk.verify_key.encode()).hexdigest()
    return {
        **base,
        "verification_bundle": {
            "bundle_digest": bundle_digest,
            "bundle_algorithm": "sha256",
            "canonicalization": "jcs-rfc8785",
            "projection_id": "receipt-core-v2",
        },
        "signatures": [
            {
                "algorithm": "ed25519",
                "signer_id": signer_id,
                "value": sig_b64,
                "signer_pubkey_sha256": pubkey_fp,
            }
        ],
    }


def _resolver_for(sk: SigningKey, signer_id: str = "test-signer"):
    pubkey_bytes = sk.verify_key.encode()

    def resolver(sid, _fp):
        return pubkey_bytes if sid == signer_id else None

    return resolver


# ---------------------------------------------------------------------------
# INV-07: ASCII-only field-name validation before projection
# ---------------------------------------------------------------------------


class TestInv07AsciiFieldNameValidation:
    """
    INV-07: ASCII-only field-name validation before projection and canonicalization.

    Adjudicated 2026-04-03: RFC 8785 JCS preserves strings as-is (INV-06, ENFORCED).
    The implemented control is narrow and explicit: non-ASCII object member names
    are rejected before attestation input is formed. This is a higher-layer
    identifier policy above JCS, not a change to JCS behavior.
    """

    CYRILLIC_I = "\u0456"  # looks like Latin 'i' but different codepoint
    HOMOGLYPH_FIELD = f"s{CYRILLIC_I}gnatures"

    def _receipt_with_homoglyph(self) -> dict:
        return {
            "receipt_id": "inv07-homoglyph",
            "type": "test",
            "ts": "2026-04-03T00:00:00Z",
            "payload": {"action": "test"},
            self.HOMOGLYPH_FIELD: [{"injected": "data"}],
        }

    def test_homoglyph_field_rejected_by_canonical_projection(self):
        """
        INV-07: A Cyrillic homoglyph of 'signatures' must be rejected before
        canonical projection is formed.
        """
        receipt = self._receipt_with_homoglyph()
        with pytest.raises(ValueError, match="ASCII-only"):
            canonical_projection(receipt)

    def test_homoglyph_field_rejected_by_prepare_receipt_for_hashing(self):
        """
        INV-07: The same field-name policy applies to the historical hashing
        projection path, not just the v2 canonical projection path.
        """
        receipt = self._receipt_with_homoglyph()
        with pytest.raises(ValueError, match="ASCII-only"):
            prepare_receipt_for_hashing(receipt)

    def test_nested_non_ascii_field_rejected(self):
        """
        INV-07: Nested object member names are part of the same attestation input
        and must also satisfy the ASCII-only field-name policy.
        """
        receipt = {
            "receipt_id": "inv07-nested-homoglyph",
            "type": "test",
            "ts": "2026-04-04T00:00:00Z",
            "payload": {
                self.HOMOGLYPH_FIELD: {"detail": "nested"},
            },
        }
        with pytest.raises(ValueError, match="ASCII-only"):
            canonical_projection(receipt)

    def test_non_string_field_name_rejected(self):
        """
        INV-07: Object member names must remain string keys for canonicalization;
        non-string keys must be rejected before projection.
        """
        receipt = {
            "receipt_id": "inv07-non-string-key",
            "type": "test",
            "ts": "2026-04-04T00:00:00Z",
            "payload": {
                7: "not allowed",
            },
        }
        with pytest.raises(TypeError, match="must be strings"):
            canonical_projection(receipt)

    def test_ascii_field_names_are_accepted(self):
        """
        Positive control: ASCII field names must still work after any fix.
        """
        receipt = {
            "receipt_id": "inv07-positive",
            "type": "test",
            "ts": "2026-04-03T00:00:00Z",
            "payload": {"action": "test"},
            "custom_ascii_field": "valid",
        }
        projection = canonical_projection(receipt)
        assert "custom_ascii_field" in projection


# ---------------------------------------------------------------------------
# INV-04: PQ algorithms not in operational set until implemented
# ---------------------------------------------------------------------------


class TestInv04PQAlgorithmPosture:
    """
    INV-04 STATUS: BROKEN
    UNSUPPORTED_ALGORITHMS is an empty frozenset. PQ algorithms (ml-dsa-*) are in
    OPERATIONAL_ALGORITHMS. A receipt signed only with a PQ algorithm returns
    trusted_signer=True with status='unsupported_algorithm'. Callers checking
    trusted_signer instead of policy_satisfied will misread this as a passing receipt.

    These tests FAIL until PQ algorithms are moved to UNSUPPORTED_ALGORITHMS
    or have working cryptographic verification.
    Fix: v2_types.py — move ml-dsa-*/slh-dsa-* out of OPERATIONAL_ALGORITHMS.
    """

    PQ_ALGORITHMS = [
        "ml-dsa-44",
        "ml-dsa-65",
        "ml-dsa-87",
    ]

    def _receipt_with_pq_sig(self, sk: SigningKey, pq_alg: str) -> tuple[dict, bytes]:
        """Build a receipt claiming a PQ signature (using ed25519 bytes for the value)."""
        base = {
            "receipt_id": f"inv05-pq-{pq_alg}",
            "type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {"pq_test": pq_alg},
            "verification_policy": {
                "operational_requires": {"min_signatures": 1, "algorithms": [pq_alg]}
            },
        }
        projection = canonical_projection(base)
        canonical_bytes = jcs_canonicalize(projection)
        bundle_digest = f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"
        # Use ed25519 bytes as the "PQ signature" — it will fail crypto, which is fine.
        # The test is about the trusted_signer and policy_satisfied fields.
        sig_b64 = base64.b64encode(sk.sign(canonical_bytes).signature).decode()
        pubkey_fp = hashlib.sha256(sk.verify_key.encode()).hexdigest()
        receipt = {
            **base,
            "verification_bundle": {
                "bundle_digest": bundle_digest,
                "bundle_algorithm": "sha256",
                "canonicalization": "jcs-rfc8785",
                "projection_id": "receipt-core-v2",
            },
            "signatures": [
                {
                    "algorithm": pq_alg,
                    "signer_id": "pq-signer",
                    "value": sig_b64,
                    "signer_pubkey_sha256": pubkey_fp,
                }
            ],
        }
        return receipt, sk.verify_key.encode()

    @pytest.mark.parametrize("pq_alg", PQ_ALGORITHMS)
    def test_pq_only_receipt_policy_satisfied_false(self, test_keypair, pq_alg):
        """
        A receipt signed only with an unimplemented PQ algorithm must return
        policy_satisfied=False. This is currently true but fragile.
        """
        sk, _ = test_keypair
        receipt, pubkey_bytes = self._receipt_with_pq_sig(sk, pq_alg)

        def resolver(sid, _fp):
            return pubkey_bytes if sid == "pq-signer" else None

        result = verify_v2(receipt, key_resolver=resolver)
        assert not result.policy_satisfied, (
            f"INV-04: receipt with only {pq_alg} signature must not satisfy policy."
        )

    @pytest.mark.parametrize("pq_alg", PQ_ALGORITHMS)
    def test_pq_sig_trusted_signer_must_be_false_for_unimplemented(
        self, test_keypair, pq_alg
    ):
        """
        INV-04 BROKEN: For an unimplemented algorithm, trusted_signer must be False.
        A SigResult with status='unsupported_algorithm' should not report trusted_signer=True
        because it conveys false confidence to callers inspecting individual sig entries.

        CURRENT BEHAVIOR: trusted_signer=True even for unsupported_algorithm.
        EXPECTED BEHAVIOR: trusted_signer=False when algorithm is not cryptographically verified.
        Fix: v2_verify.py _verify_single_sig — set trusted_signer=False when algorithm
        is in UNSUPPORTED_ALGORITHMS or has no cryptographic implementation.
        """
        sk, _ = test_keypair
        receipt, pubkey_bytes = self._receipt_with_pq_sig(sk, pq_alg)

        def resolver(sid, _fp):
            return pubkey_bytes if sid == "pq-signer" else None

        result = verify_v2(receipt, key_resolver=resolver)
        assert len(result.signature_results) == 1
        sig_result = result.signature_results[0]

        assert not sig_result.trusted_signer, (
            f"INV-04 BROKEN: {pq_alg} signature returned trusted_signer=True "
            f"with status='{sig_result.status}'. Callers checking trusted_signer "
            f"instead of policy_satisfied will misread this as a trusted result. "
            f"Fix: return trusted_signer=False for any unimplemented algorithm."
        )

    def test_pq_algorithms_not_in_operational_set(self):
        """
        INV-04 BROKEN: PQ algorithms must NOT appear in OPERATIONAL_ALGORITHMS
        until cryptographic verification is implemented.

        CURRENT BEHAVIOR: ml-dsa-* are in OPERATIONAL_ALGORITHMS, UNSUPPORTED_ALGORITHMS is empty.
        EXPECTED BEHAVIOR: ml-dsa-* in UNSUPPORTED_ALGORITHMS.
        Fix: v2_types.py — move PQ algorithms to UNSUPPORTED_ALGORITHMS.
        """
        pq_in_operational = OPERATIONAL_ALGORITHMS - {"ed25519"}
        assert len(pq_in_operational) == 0, (
            f"INV-04 BROKEN: PQ algorithms in OPERATIONAL_ALGORITHMS before implementation: "
            f"{pq_in_operational}. Move to UNSUPPORTED_ALGORITHMS."
        )

    def test_unsupported_algorithms_covers_pq(self):
        """
        INV-04: After fix, UNSUPPORTED_ALGORITHMS must contain PQ algorithms.
        CURRENT BEHAVIOR: UNSUPPORTED_ALGORITHMS = frozenset() — empty.
        """
        expected_in_unsupported = {"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"}
        missing = expected_in_unsupported - UNSUPPORTED_ALGORITHMS
        assert not missing, (
            f"INV-04 BROKEN: PQ algorithms not in UNSUPPORTED_ALGORITHMS: {missing}. "
            f"Fix: v2_types.py."
        )


# ---------------------------------------------------------------------------
# INV-08: V1 shim must not silently discard valid flat signature
# ---------------------------------------------------------------------------


class TestInv08ShimNonSilentDiscard:
    """
    INV-08 STATUS: BROKEN
    When a receipt has BOTH a flat 'signature' field (v1) AND a 'signatures[]' array (v2),
    the shim at v2_verify.py:130-132 returns signatures[] immediately and silently discards
    the flat field. No warning is emitted. The legitimate flat signature is never evaluated.

    Fix: _shim_v1_signatures() must emit a warning when both fields are present,
    or the receipt must be rejected as ambiguous.
    See: assay/src/assay/_receipts/v2_verify.py:130-132
    """

    def _receipt_with_both_sig_fields(self, sk: SigningKey) -> dict:
        """Receipt with both flat 'signature' and 'signatures[]' populated."""
        base = {
            "receipt_id": "inv08-dual-sig",
            "type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": {"test": "dual-signature"},
            "verification_policy": {
                "operational_requires": {"min_signatures": 1, "algorithms": ["ed25519"]}
            },
        }
        signed_v2 = _sign_receipt(base, sk)
        # Also inject a flat v1-style signature field
        signed_v2["signature"] = base64.b64encode(b"\xff" * 64).decode()
        signed_v2["signer_id"] = "legacy-signer"
        return signed_v2

    def test_dual_signature_emits_warning(self, test_keypair):
        """
        INV-08 BROKEN: verifier must emit a warning when both signature fields are present.

        CURRENT BEHAVIOR: flat 'signature' silently discarded, no warning.
        EXPECTED BEHAVIOR: warnings.warn() or logging at WARNING level.
        Fix: _shim_v1_signatures() — add warning when 'signatures' key present AND
        'signature' flat key is also present.
        """
        sk, _ = test_keypair
        receipt = self._receipt_with_both_sig_fields(sk)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            verify_v2(receipt, key_resolver=_resolver_for(sk))

        ambiguity_warnings = [
            w
            for w in caught
            if "signature" in str(w.message).lower()
            or "ambiguous" in str(w.message).lower()
        ]
        assert ambiguity_warnings, (
            "INV-08 BROKEN: No warning emitted when receipt has both 'signature' "
            "(flat v1) and 'signatures' (v2 array). The flat field was silently "
            "discarded. Fix: emit warnings.warn() in _shim_v1_signatures() when "
            "both fields are present."
        )

    def test_dual_signature_flat_field_is_not_silently_lost(self, test_keypair):
        """
        INV-08: The flat 'signature' field must not vanish without trace.
        Acceptable outcomes: evaluated (2+ results), rejected (error), or warned.
        Silent discard is the only unacceptable outcome.

        This test accepts "warned discard" as the fix — a UserWarning is evidence
        the discard was not silent.
        """
        sk, _ = test_keypair
        receipt = self._receipt_with_both_sig_fields(sk)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = verify_v2(receipt, key_resolver=_resolver_for(sk))

        has_warning = any(
            "signature" in str(w.message).lower()
            or "ambiguous" in str(w.message).lower()
            for w in caught
        )
        evaluates_both = len(result.signature_results) >= 2

        assert has_warning or evaluates_both, (
            "INV-08: The flat 'signature' field was silently discarded — no warning emitted "
            "and only one signature result returned. Silent discard is not acceptable."
        )
