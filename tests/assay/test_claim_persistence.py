"""Tests for claim persistence into proof pack manifests.

Contract: when a pack is built with run cards, the claim specs
are persisted into pack_manifest.json so downstream consumers
(posture, replay) can re-evaluate without the original run card.

Backward compatibility: packs built without claims must still
produce valid manifests and posture must degrade honestly.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.claim_verifier import ClaimSpec
from assay.proof_pack import ProofPack
from assay.proof_posture import posture_from_pack
from assay.run_cards import BUILTIN_CARDS, collect_claims_from_cards


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_pack_with_claims(
    tmp_path: Path,
    claims: list[ClaimSpec],
    receipts: list[dict] | None = None,
) -> Path:
    """Build a proof pack with given claims and receipts."""
    if receipts is None:
        receipts = [
            {"type": "model_call", "receipt_id": "r_001", "seq": 0,
             "timestamp": "2026-03-21T00:00:00Z", "schema_version": "3.0",
             "provider": "anthropic", "model_id": "claude-sonnet-4-20250514",
             "input_tokens": 100, "output_tokens": 50, "total_tokens": 150,
             "latency_ms": 500, "task": "test"},
            {"type": "guardian_verdict", "receipt_id": "r_002", "seq": 1,
             "timestamp": "2026-03-21T00:00:01Z", "schema_version": "3.0",
             "verdict": "allow", "dignity_gate": "pass",
             "tool": "test_tool", "risk_score": 0.1,
             "parent_receipt_id": "r_001", "rationale": "test"},
        ]

    builder = ProofPack(
        run_id="trace_test_001",
        entries=receipts,
        claims=claims,
        mode="shadow",
    )
    output_dir = tmp_path / "proof_pack_test"
    builder.build(output_dir=output_dir)
    return output_dir


def _build_pack_without_claims(tmp_path: Path) -> Path:
    """Build a proof pack with no claims (old-style)."""
    receipts = [
        {"type": "model_call", "receipt_id": "r_001", "seq": 0,
         "timestamp": "2026-03-21T00:00:00Z", "schema_version": "3.0",
         "provider": "anthropic", "model_id": "claude-sonnet-4-20250514",
         "input_tokens": 100, "output_tokens": 50, "total_tokens": 150,
         "latency_ms": 500, "task": "test"},
    ]
    builder = ProofPack(
        run_id="trace_test_002",
        entries=receipts,
        mode="shadow",
    )
    output_dir = tmp_path / "proof_pack_no_claims"
    builder.build(output_dir=output_dir)
    return output_dir


# ---------------------------------------------------------------------------
# Test: claims are persisted into manifest
# ---------------------------------------------------------------------------


class TestClaimPersistence:
    def test_claims_present_in_manifest(self, tmp_path: Path) -> None:
        claims = [
            ClaimSpec(
                claim_id="model_call_present",
                description="At least one model_call receipt",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert "claims" in manifest
        assert len(manifest["claims"]) == 1
        assert manifest["claims"][0]["claim_id"] == "model_call_present"
        assert manifest["claims"][0]["check"] == "receipt_type_present"
        assert manifest["claims"][0]["severity"] == "critical"

    def test_claims_absent_when_none_provided(self, tmp_path: Path) -> None:
        pack_dir = _build_pack_without_claims(tmp_path)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert "claims" not in manifest

    def test_multiple_claims_persisted(self, tmp_path: Path) -> None:
        claims = [
            ClaimSpec(claim_id="c1", description="d1", check="receipt_type_present",
                      params={"receipt_type": "model_call"}),
            ClaimSpec(claim_id="c2", description="d2", check="receipt_type_present",
                      params={"receipt_type": "guardian_verdict"}),
            ClaimSpec(claim_id="c3", description="d3", check="receipt_count_ge",
                      params={"min_count": 1}, severity="warning"),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert len(manifest["claims"]) == 3
        ids = [c["claim_id"] for c in manifest["claims"]]
        assert ids == ["c1", "c2", "c3"]

    def test_claim_params_preserved(self, tmp_path: Path) -> None:
        claims = [
            ClaimSpec(claim_id="c1", description="d1", check="receipt_count_ge",
                      params={"receipt_type": "model_call", "min_count": 3}),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert manifest["claims"][0]["params"]["min_count"] == 3
        assert manifest["claims"][0]["params"]["receipt_type"] == "model_call"


# ---------------------------------------------------------------------------
# Test: claim_set_hash consistency
# ---------------------------------------------------------------------------


class TestClaimSetHashConsistency:
    def test_hash_matches_persisted_claims(self, tmp_path: Path) -> None:
        """claim_set_hash in manifest must match hash of persisted claim specs."""
        from assay._receipts.canonicalize import to_jcs_bytes
        import hashlib

        claims = [
            ClaimSpec(claim_id="c1", description="d1", check="receipt_type_present",
                      params={"receipt_type": "model_call"}),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        # Recompute hash from persisted claims
        persisted_specs = manifest["claims"]
        canonical = to_jcs_bytes(persisted_specs)
        expected_hash = hashlib.sha256(canonical).hexdigest()

        assert manifest["claim_set_hash"] == expected_hash

    def test_builtin_card_hash_matches(self, tmp_path: Path) -> None:
        """Built-in run card claim_set_hash should match persisted claims hash."""
        from assay._receipts.canonicalize import to_jcs_bytes
        import hashlib

        card = BUILTIN_CARDS["receipt_completeness"]
        claims = card.claims
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())

        persisted_specs = manifest["claims"]
        canonical = to_jcs_bytes(persisted_specs)
        expected_hash = hashlib.sha256(canonical).hexdigest()

        assert manifest["claim_set_hash"] == expected_hash
        assert manifest["claim_set_hash"] == card.claim_set_hash()


# ---------------------------------------------------------------------------
# Test: posture on normally-produced claim-bearing pack
# ---------------------------------------------------------------------------


class TestPostureOnProducedPack:
    def test_posture_sees_claims_from_manifest(self, tmp_path: Path) -> None:
        claims = [
            ClaimSpec(claim_id="model_present", description="model_call exists",
                      check="receipt_type_present", params={"receipt_type": "model_call"}),
            ClaimSpec(claim_id="guardian_present", description="guardian_verdict exists",
                      check="receipt_type_present", params={"receipt_type": "guardian_verdict"}),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        result = posture_from_pack(str(pack_dir))
        assert result.claims_loaded == 2
        assert result.posture.n_claims == 2
        assert result.posture.n_passed == 2
        assert result.posture.disposition == "verified"

    def test_posture_detects_failure_from_persisted_claims(self, tmp_path: Path) -> None:
        """Claim for a receipt type not in the pack should fail."""
        claims = [
            ClaimSpec(claim_id="model_present", description="model_call exists",
                      check="receipt_type_present", params={"receipt_type": "model_call"}),
            ClaimSpec(claim_id="breakglass_present", description="breakglass exists",
                      check="receipt_type_present", params={"receipt_type": "breakglass"}),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        result = posture_from_pack(str(pack_dir))
        assert result.claims_loaded == 2
        assert result.posture.n_passed == 1
        assert result.posture.n_failed == 1
        assert result.posture.disposition == "incomplete"

    def test_posture_with_builtin_card(self, tmp_path: Path) -> None:
        """Full end-to-end: builtin run card → pack → posture."""
        card = BUILTIN_CARDS["receipt_completeness"]
        pack_dir = _build_pack_with_claims(tmp_path, card.claims)
        result = posture_from_pack(str(pack_dir))
        assert result.claims_loaded == len(card.claims)
        assert result.posture.n_claims == len(card.claims)
        # receipt_completeness requires model_call + min 1 receipt — both present
        assert result.posture.n_passed == len(card.claims)
        assert result.posture.disposition == "verified"


# ---------------------------------------------------------------------------
# Test: backward compatibility — old packs without claims
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_old_pack_no_claims_field(self, tmp_path: Path) -> None:
        pack_dir = _build_pack_without_claims(tmp_path)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        assert "claims" not in manifest
        # Manifest still valid
        assert manifest["claim_set_id"] == "none"

    def test_posture_on_old_pack_degrades_honestly(self, tmp_path: Path) -> None:
        pack_dir = _build_pack_without_claims(tmp_path)
        result = posture_from_pack(str(pack_dir))
        assert result.claims_loaded == 0
        # No claims → verified (nothing to fail), but with warning
        assert result.posture.disposition == "verified"
        assert any("no claims" in w.lower() for w in result.warnings)

    def test_old_pack_manifest_still_validates(self, tmp_path: Path) -> None:
        """Manifest schema must accept packs both with and without claims."""
        from assay.manifest_schema import validate_manifest

        pack_dir = _build_pack_without_claims(tmp_path)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        errors = validate_manifest(manifest)
        assert errors == [], f"Old pack manifest should still validate: {errors}"

    def test_new_pack_manifest_validates(self, tmp_path: Path) -> None:
        from assay.manifest_schema import validate_manifest

        claims = [
            ClaimSpec(claim_id="c1", description="d1", check="receipt_type_present",
                      params={"receipt_type": "model_call"}),
        ]
        pack_dir = _build_pack_with_claims(tmp_path, claims)
        manifest = json.loads((pack_dir / "pack_manifest.json").read_text())
        errors = validate_manifest(manifest)
        assert errors == [], f"New pack manifest should validate: {errors}"
