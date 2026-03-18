"""Tests for the four-stage trust evaluation model.

Covers: registry loading, acceptance matrix, authorization decisions,
composed trust evaluation, and serialization.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.trust.types import (
    AcceptanceDecision,
    ArtifactClassification,
    AuthorizationDecision,
    TrustEvaluation,
    VerificationFacts,
)
from assay.trust.registry import (
    SignerEntry,
    SignerGrant,
    SignerRegistry,
    load_registry,
)
from assay.trust.acceptance import AcceptanceMatrix, load_acceptance
from assay.trust.evaluator import (
    authorize_signer,
    classify_pack_manifest,
    evaluate_acceptance,
    evaluate_trust,
    extract_verification_facts,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_manifest(**overrides):
    base = {
        "pack_id": "pack_test",
        "pack_version": "0.1.0",
        "manifest_version": "1.0.0",
        "signer_id": "test-signer",
        "signer_pubkey": "AAAA",
        "signer_pubkey_sha256": "ab" * 32,
        "signature": "sig_b64",
        "attestation": {
            "mode": "shadow",
            "verifier_version": "1.17.0",
        },
    }
    base.update(overrides)
    return base


class _FakeVerifyResult:
    def __init__(self, passed=True, errors=None, warnings=None):
        self.passed = passed
        self.errors = errors or []
        self.warnings = warnings or []


class _FakeError:
    def __init__(self, code):
        self.code = code


REGISTRY_YAML = """\
signers:
  - signer_id: prod-signer
    fingerprint: "ab" * 32
    lifecycle: active
    grants:
      - artifact_class: proof_pack
        scope: "*"
        purpose: ci_attestation
  - signer_id: revoked-signer
    fingerprint: "cd" * 32
    lifecycle: revoked
    grants:
      - artifact_class: proof_pack
        scope: "*"
        purpose: "*"
  - signer_id: recognized-only
    fingerprint: "ef" * 32
    lifecycle: active
    grants: []
"""

ACCEPTANCE_YAML = """\
rules:
  - artifact_class: proof_pack
    verification_level: signature_verified
    authorization_status: authorized
    target: ci_gate
    decision: accept
    reason: "Signed by authorized signer"
  - artifact_class: proof_pack
    verification_level: signature_verified
    authorization_status: unrecognized
    target: ci_gate
    decision: warn
    reason: "UNKNOWN_SIGNER"
  - artifact_class: proof_pack
    verification_level: "*"
    authorization_status: revoked
    target: ci_gate
    decision: reject
    reason: "SIGNER_REVOKED"
  - artifact_class: proof_pack
    verification_level: unverified
    authorization_status: "*"
    target: publication
    decision: reject
    reason: "INTEGRITY_FAIL"
"""


@pytest.fixture
def registry_path(tmp_path):
    p = tmp_path / "signers.yaml"
    # Fix the fingerprint strings (YAML doesn't evaluate Python expressions)
    content = REGISTRY_YAML.replace('"ab" * 32', "a" * 64).replace('"cd" * 32', "c" * 64).replace('"ef" * 32', "e" * 64)
    p.write_text(content)
    return p


@pytest.fixture
def acceptance_path(tmp_path):
    p = tmp_path / "acceptance.yaml"
    p.write_text(ACCEPTANCE_YAML)
    return p


# ---------------------------------------------------------------------------
# Stage 1: Classification
# ---------------------------------------------------------------------------

class TestClassification:
    def test_classify_shadow_pack(self):
        m = _make_manifest()
        c = classify_pack_manifest(m)
        assert c.artifact_class == "proof_pack"
        assert c.schema_version == "0.1.0"
        assert c.declared_purpose == "internal_evidence"

    def test_classify_ci_bound_pack(self):
        m = _make_manifest(attestation={
            "mode": "enforced",
            "ci_binding": {"provider": "github_actions", "repo": "Haserjian/assay"},
        })
        c = classify_pack_manifest(m)
        assert c.declared_purpose == "ci_attestation"
        assert c.provenance.get("provider") == "github_actions"

    def test_classify_unknown_purpose(self):
        m = _make_manifest(attestation={"mode": "enforced"})
        c = classify_pack_manifest(m)
        assert c.declared_purpose == "unknown"


# ---------------------------------------------------------------------------
# Stage 2: Verification facts
# ---------------------------------------------------------------------------

class TestVerificationFacts:
    def test_passing_verification(self):
        vr = _FakeVerifyResult(passed=True)
        m = _make_manifest()
        facts = extract_verification_facts(vr, m)
        assert facts.integrity_passed is True
        assert facts.signature_valid is True
        assert facts.signer_id == "test-signer"
        assert facts.embedded_pubkey is True
        assert facts.schema_recognized is True

    def test_failed_signature(self):
        vr = _FakeVerifyResult(passed=False, errors=[_FakeError("E_PACK_SIG_INVALID")])
        m = _make_manifest()
        facts = extract_verification_facts(vr, m)
        assert facts.signature_valid is False

    def test_no_signature(self):
        vr = _FakeVerifyResult(passed=True)
        m = _make_manifest(signature=None)
        facts = extract_verification_facts(vr, m)
        assert facts.signature_valid is None

    def test_facts_are_serializable(self):
        vr = _FakeVerifyResult(passed=True)
        facts = extract_verification_facts(vr, _make_manifest())
        d = facts.to_dict()
        json.dumps(d)  # must not raise


# ---------------------------------------------------------------------------
# Stage 3: Authorization
# ---------------------------------------------------------------------------

class TestAuthorization:
    def test_no_registry_returns_not_evaluated(self):
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="x", signer_fingerprint="y",
            embedded_pubkey=True, schema_recognized=True,
        )
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        auth = authorize_signer(facts, cls, registry=None)
        assert auth.status == "not_evaluated"
        assert "NO_REGISTRY" in auth.reason_codes

    def test_unknown_signer(self, registry_path):
        reg = load_registry(registry_path)
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="nobody", signer_fingerprint="f" * 64,
            embedded_pubkey=True, schema_recognized=True,
        )
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        auth = authorize_signer(facts, cls, registry=reg)
        assert auth.status == "unrecognized"

    def test_revoked_signer_never_authorized(self, registry_path):
        reg = load_registry(registry_path)
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="revoked-signer", signer_fingerprint="c" * 64,
            embedded_pubkey=True, schema_recognized=True,
        )
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        auth = authorize_signer(facts, cls, registry=reg)
        assert auth.status == "revoked"
        assert "SIGNER_REVOKED" in auth.reason_codes

    def test_authorized_signer_with_matching_grant(self, registry_path):
        reg = load_registry(registry_path)
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="prod-signer", signer_fingerprint="a" * 64,
            embedded_pubkey=True, schema_recognized=True,
        )
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        auth = authorize_signer(facts, cls, registry=reg)
        assert auth.status == "authorized"
        assert len(auth.matched_grants) >= 1

    def test_recognized_but_no_grant(self, registry_path):
        reg = load_registry(registry_path)
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="recognized-only", signer_fingerprint="e" * 64,
            embedded_pubkey=True, schema_recognized=True,
        )
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        auth = authorize_signer(facts, cls, registry=reg)
        assert auth.status == "recognized"
        assert "NO_MATCHING_GRANT" in auth.reason_codes


# ---------------------------------------------------------------------------
# Stage 4: Acceptance
# ---------------------------------------------------------------------------

class TestAcceptance:
    def test_accept_authorized_for_ci_gate(self, acceptance_path):
        matrix = load_acceptance(acceptance_path)
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="x", signer_fingerprint="y",
            embedded_pubkey=True, schema_recognized=True,
        )
        auth = AuthorizationDecision(
            subject_signer_id="x", subject_fingerprint="y",
            status="authorized", lifecycle_state="active",
        )
        decision = evaluate_acceptance(cls, facts, auth, matrix, "ci_gate")
        assert decision.decision == "accept"

    def test_warn_unknown_signer_for_ci_gate(self, acceptance_path):
        matrix = load_acceptance(acceptance_path)
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="x", signer_fingerprint="y",
            embedded_pubkey=True, schema_recognized=True,
        )
        auth = AuthorizationDecision(
            subject_signer_id="x", subject_fingerprint="y",
            status="unrecognized", lifecycle_state=None,
        )
        decision = evaluate_acceptance(cls, facts, auth, matrix, "ci_gate")
        assert decision.decision == "warn"

    def test_reject_revoked_for_ci_gate(self, acceptance_path):
        matrix = load_acceptance(acceptance_path)
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="x", signer_fingerprint="y",
            embedded_pubkey=True, schema_recognized=True,
        )
        auth = AuthorizationDecision(
            subject_signer_id="x", subject_fingerprint="y",
            status="revoked", lifecycle_state="revoked",
        )
        decision = evaluate_acceptance(cls, facts, auth, matrix, "ci_gate")
        assert decision.decision == "reject"

    def test_reject_unverified_for_publication(self, acceptance_path):
        matrix = load_acceptance(acceptance_path)
        cls = ArtifactClassification("proof_pack", "0.1.0", "publication")
        facts = VerificationFacts(
            integrity_passed=False, signature_valid=False,
            signer_id="x", signer_fingerprint="y",
            embedded_pubkey=True, schema_recognized=True,
        )
        auth = AuthorizationDecision(
            subject_signer_id="x", subject_fingerprint="y",
            status="authorized", lifecycle_state="active",
        )
        decision = evaluate_acceptance(cls, facts, auth, matrix, "publication")
        assert decision.decision == "reject"

    def test_no_policy_returns_not_evaluated(self):
        cls = ArtifactClassification("proof_pack", "0.1.0", "ci_attestation")
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=True,
            signer_id="x", signer_fingerprint="y",
            embedded_pubkey=True, schema_recognized=True,
        )
        auth = AuthorizationDecision(
            subject_signer_id="x", subject_fingerprint="y",
            status="authorized", lifecycle_state="active",
        )
        decision = evaluate_acceptance(cls, facts, auth, None, "ci_gate")
        assert decision.decision == "not_evaluated"


# ---------------------------------------------------------------------------
# Composed trust evaluation
# ---------------------------------------------------------------------------

class TestTrustEvaluation:
    def test_full_evaluation_is_serializable(self, registry_path, acceptance_path):
        reg = load_registry(registry_path)
        matrix = load_acceptance(acceptance_path)
        vr = _FakeVerifyResult(passed=True)
        m = _make_manifest(
            signer_id="prod-signer",
            signer_pubkey_sha256="a" * 64,
            attestation={"mode": "enforced", "ci_binding": {"provider": "github_actions"}},
        )
        te = evaluate_trust(
            vr, m, registry=reg, acceptance_policy=matrix, target="ci_gate",
        )
        d = te.to_dict()
        s = json.dumps(d, indent=2)
        assert "authorized" in s
        assert "accept" in s

    def test_evaluation_without_registry_or_policy(self):
        vr = _FakeVerifyResult(passed=True)
        m = _make_manifest()
        te = evaluate_trust(vr, m)
        assert te.authorization.status == "not_evaluated"
        assert te.acceptance.decision == "not_evaluated"

    def test_evaluation_with_failed_verification(self, registry_path, acceptance_path):
        reg = load_registry(registry_path)
        matrix = load_acceptance(acceptance_path)
        vr = _FakeVerifyResult(passed=False, errors=[_FakeError("E_MANIFEST_TAMPER")])
        m = _make_manifest(
            signer_id="prod-signer",
            signer_pubkey_sha256="a" * 64,
        )
        te = evaluate_trust(
            vr, m, registry=reg, acceptance_policy=matrix, target="publication",
        )
        assert te.facts.integrity_passed is False
        assert te.acceptance.decision == "reject"
