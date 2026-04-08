"""Contract tests for the top-level assay import surface."""

from __future__ import annotations

import assay

REQUIRED_EXPORTS = {
    "__version__",
    "ArtifactVerificationResult",
    "AssayStore",
    "BeliefUpdateArtifact",
    "CheckpointAttemptView",
    "CheckpointEvaluationArtifact",
    "CheckpointRequestArtifact",
    "CheckpointResolutionArtifact",
    "ClaimAssertionArtifact",
    "ClaimSupportChangeArtifact",
    "Episode",
    "GuardianVerdict",
    "ProofBudgetSnapshotArtifact",
    "ProofPackArtifact",
    "RCEVerifyResult",
    "emit_receipt",
    "emit_proof_pack",
    "no_coherence_by_dignity_debt",
    "validate_rce_replay_result",
    "verify_pack",
    "verify_rce_pack",
}


class TestTopLevelPublicApiContract:
    """Top-level exports must remain intentionally versioned."""

    def test_required_exports_remain_available(self) -> None:
        """Core top-level exports should not disappear silently."""
        exported_names = set(assay.__all__)
        missing = sorted(REQUIRED_EXPORTS - exported_names)

        assert not missing, (
            f"Top-level assay export surface changed; missing exports: {missing}"
        )

        for name in REQUIRED_EXPORTS:
            getattr(assay, name)

    def test_public_exports_are_unique_strings(self) -> None:
        """__all__ should stay deterministic and free of duplicate names."""
        assert isinstance(assay.__all__, list)
        assert all(isinstance(name, str) for name in assay.__all__)
        assert len(assay.__all__) == len(set(assay.__all__))
