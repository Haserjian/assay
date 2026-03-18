"""Tests for trust visibility in assay verify-pack CLI.

Invariants:
- trust block appears in JSON when --trust-target is provided
- no-policy path emits not_evaluated, not omission
- target changes acceptance result
- exit code unchanged even when trust says reject/warn
- signer-ID-only fallback emits AUTHZ.LEGACY_ID_FALLBACK_USED
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    import assay.store as store_mod
    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


def _build_pack(tmp_path: Path, ks: AssayKeyStore, signer_id: str = "test-signer") -> Path:
    from datetime import datetime, timezone
    receipt = {
        "receipt_id": "r1",
        "type": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    pack = ProofPack(run_id="trust-cli-test", entries=[receipt], signer_id=signer_id)
    return pack.build(tmp_path / "pack", keystore=ks)


def _make_policy_dir(tmp_path: Path, ks: AssayKeyStore, signer_id: str = "test-signer") -> Path:
    """Create trust policy directory with registry and acceptance matrix."""
    policy_dir = tmp_path / "trust"
    policy_dir.mkdir()

    ks.ensure_key(signer_id)
    fingerprint = ks.signer_fingerprint(signer_id)

    signers = {
        "signers": [{
            "signer_id": signer_id,
            "fingerprint": fingerprint,
            "lifecycle": "active",
            "grants": [{"artifact_class": "proof_pack", "purpose": "*"}],
        }]
    }

    acceptance = {
        "rules": [
            {"artifact_class": "proof_pack", "verification_level": "signature_verified",
             "authorization_status": "authorized", "target": "local_verify", "decision": "accept",
             "reason": "Authorized signer"},
            {"artifact_class": "proof_pack", "verification_level": "signature_verified",
             "authorization_status": "unrecognized", "target": "ci_gate", "decision": "reject",
             "reason": "UNKNOWN_SIGNER"},
            {"artifact_class": "*", "verification_level": "*",
             "authorization_status": "*", "target": "*", "decision": "warn",
             "reason": "DEFAULT_WARN"},
        ]
    }

    import yaml
    (policy_dir / "signers.yaml").write_text(yaml.dump(signers))
    (policy_dir / "acceptance.yaml").write_text(yaml.dump(acceptance))
    return policy_dir


class TestTrustJsonOutput:
    def test_trust_block_present_when_requested(self, assay_home_tmp, tmp_path):
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "local_verify",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "trust" in data
        assert data["trust"]["acceptance"]["target"] == "local_verify"

    def test_no_trust_block_without_flag(self, assay_home_tmp, tmp_path):
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "trust" not in data

    def test_not_evaluated_when_no_policy(self, assay_home_tmp, tmp_path):
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        trust = data["trust"]
        assert trust["authorization"]["status"] == "not_evaluated"
        assert trust["acceptance"]["decision"] == "not_evaluated"

    def test_authorized_with_policy(self, assay_home_tmp, tmp_path):
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)
        policy_dir = _make_policy_dir(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "local_verify",
            "--trust-policy-dir", str(policy_dir),
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        trust = data["trust"]
        assert trust["authorization"]["status"] == "authorized"
        assert trust["acceptance"]["decision"] == "accept"

    def test_target_changes_acceptance(self, assay_home_tmp, tmp_path):
        """Different targets produce different acceptance decisions."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="unknown-signer")

        # Policy only recognizes test-signer, not unknown-signer
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        trust = data["trust"]
        assert trust["authorization"]["status"] == "unrecognized"
        assert trust["acceptance"]["decision"] == "reject"


class TestTrustExitCodeUnchanged:
    def test_exit_zero_even_when_trust_rejects(self, assay_home_tmp, tmp_path):
        """Trust rejection must NOT change exit code — advisory only."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="unknown-signer")
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
        ])
        # Verification passes (integrity is fine), so exit 0
        # even though trust says reject
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["trust"]["acceptance"]["decision"] == "reject"


class TestTrustGateEnforcement:
    """Invariants for --enforce-trust-gate opt-in enforcement.

    Enforcement fires ONLY when ALL conditions hold:
      - --enforce-trust-gate flag set
      - --trust-target is "ci_gate" (not local_verify, publication)
      - trust policy loaded cleanly (no load errors)
      - acceptance decision is explicitly "reject"

    Any other combination must remain advisory (exit 0).
    """

    def test_enforce_exits_1_on_ci_gate_reject(self, assay_home_tmp, tmp_path):
        """Core invariant: clean reject + ci_gate + flag → exit 1."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="unknown-signer")
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
            "--enforce-trust-gate",
        ])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "trust_gate_rejected"
        assert data["trust"]["acceptance"]["decision"] == "reject"
        assert data["trust_gate"] == "rejected_by_trust_policy"

    def test_no_enforce_flag_remains_advisory(self, assay_home_tmp, tmp_path):
        """Without flag, even a clean reject stays advisory (exit 0)."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="unknown-signer")
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert "trust_gate" not in data

    def test_enforce_with_non_ci_gate_target_remains_advisory(self, assay_home_tmp, tmp_path):
        """Flag has no effect for local_verify even if policy rejects."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="unknown-signer")
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "local_verify",
            "--trust-policy-dir", str(policy_dir),
            "--enforce-trust-gate",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "trust_gate" not in data

    def test_enforce_with_load_errors_remains_advisory(self, assay_home_tmp, tmp_path):
        """Policy load error → enforcement bypassed (advisory only)."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        policy_dir = tmp_path / "broken_trust"
        policy_dir.mkdir()
        (policy_dir / "signers.yaml").write_text("not: [valid: yaml: {{{")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
            "--enforce-trust-gate",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "trust_gate" not in data

    def test_enforce_accept_remains_exit_0(self, assay_home_tmp, tmp_path):
        """When trust accepts, --enforce-trust-gate has no effect."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="test-signer")
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        # Overwrite acceptance to accept everything for ci_gate
        import yaml
        acceptance = {
            "rules": [
                {"artifact_class": "*", "verification_level": "*",
                 "authorization_status": "*", "target": "ci_gate", "decision": "accept",
                 "reason": "ALL_OK"},
            ]
        }
        (policy_dir / "acceptance.yaml").write_text(yaml.dump(acceptance))

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
            "--enforce-trust-gate",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "trust_gate" not in data

    def test_enforce_human_output_shows_rejection_panel(self, assay_home_tmp, tmp_path):
        """Terminal output must show TRUST GATE REJECTED panel when enforced."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks, signer_id="unknown-signer")
        policy_dir = _make_policy_dir(tmp_path, ks, signer_id="test-signer")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir),
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(policy_dir),
            "--enforce-trust-gate",
        ])
        assert result.exit_code == 1
        assert "TRUST GATE REJECTED" in result.output

    def test_enforce_not_evaluated_remains_advisory(self, assay_home_tmp, tmp_path):
        """not_evaluated (no policy dir) → enforcement bypassed even with flag."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--enforce-trust-gate",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["trust"]["acceptance"]["decision"] == "not_evaluated"
        assert "trust_gate" not in data


class TestTrustHumanOutput:
    def test_human_output_includes_trust_section(self, assay_home_tmp, tmp_path):
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir),
            "--trust-target", "local_verify",
        ])
        assert result.exit_code == 0
        assert "Trust evaluation" in result.output
        assert "authorization:" in result.output
        assert "acceptance:" in result.output


class TestLegacyFallbackTelemetry:
    def test_id_only_fallback_emits_reason_code(self, assay_home_tmp, tmp_path):
        """When fingerprint is absent and signer_id matches, emit fallback code."""
        from assay.trust.evaluator import authorize_signer
        from assay.trust.types import ArtifactClassification, VerificationFacts
        from assay.trust.registry import SignerEntry, SignerGrant, SignerRegistry

        entry = SignerEntry(
            signer_id="legacy-signer",
            fingerprint="a" * 64,
            lifecycle="active",
            grants=[SignerGrant(artifact_class="proof_pack", purpose="*")],
        )
        reg = SignerRegistry([entry])

        # Facts with NO fingerprint, only signer_id
        facts = VerificationFacts(
            integrity_passed=True, signature_valid=None,
            signer_id="legacy-signer", signer_fingerprint=None,
            embedded_pubkey=False, schema_recognized=True,
        )
        cls = ArtifactClassification("proof_pack", "0.1.0", "internal_evidence")
        auth = authorize_signer(facts, cls, registry=reg)
        assert auth.status == "authorized"
        assert "AUTHZ.LEGACY_ID_FALLBACK_USED" in auth.reason_codes


class TestTrustPolicyLoadErrors:
    def test_malformed_signers_yaml_surfaces_error(self, assay_home_tmp, tmp_path):
        """Malformed policy file must surface error, not silently not_evaluated."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        policy_dir = tmp_path / "bad_trust"
        policy_dir.mkdir()
        (policy_dir / "signers.yaml").write_text("not: [valid: yaml: {{{")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "local_verify",
            "--trust-policy-dir", str(policy_dir),
        ])
        assert result.exit_code == 0  # advisory — no exit code change
        data = json.loads(result.output)
        assert "trust" in data
        assert "load_errors" in data["trust"]
        assert any("signers.yaml" in e for e in data["trust"]["load_errors"])

    def test_missing_policy_dir_gives_not_evaluated(self, assay_home_tmp, tmp_path):
        """Missing policy dir = not_evaluated (no load_errors)."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "ci_gate",
            "--trust-policy-dir", str(tmp_path / "nonexistent"),
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        trust = data["trust"]
        assert trust["authorization"]["status"] == "not_evaluated"
        assert "load_errors" not in trust

    def test_malformed_policy_human_output_warns(self, assay_home_tmp, tmp_path):
        """Human output must show trust load error."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)

        policy_dir = tmp_path / "bad_trust2"
        policy_dir.mkdir()
        (policy_dir / "acceptance.yaml").write_text("rules: not_a_list")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir),
            "--trust-target", "local_verify",
            "--trust-policy-dir", str(policy_dir),
        ])
        assert result.exit_code == 0
        assert "Trust policy load error" in result.output


    def test_partial_config_valid_registry_malformed_acceptance(self, assay_home_tmp, tmp_path):
        """Valid signers + malformed acceptance: auth computed, acceptance not_evaluated."""
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)
        policy_dir = _make_policy_dir(tmp_path, ks)

        # Break the acceptance file
        (policy_dir / "acceptance.yaml").write_text("rules: not_a_list")

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "local_verify",
            "--trust-policy-dir", str(policy_dir),
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        trust = data["trust"]
        # Registry loaded fine → authorization should be computed
        assert trust["authorization"]["status"] == "authorized"
        # Acceptance failed to load → not_evaluated
        assert trust["acceptance"]["decision"] == "not_evaluated"
        # Load error surfaced
        assert "load_errors" in trust
        assert any("acceptance.yaml" in e for e in trust["load_errors"])


class TestTrustSerialization:
    def test_trust_evaluation_roundtrips_json(self, assay_home_tmp, tmp_path):
        ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
        pack_dir = _build_pack(tmp_path, ks)
        policy_dir = _make_policy_dir(tmp_path, ks)

        result = runner.invoke(assay_app, [
            "verify-pack", str(pack_dir), "--json",
            "--trust-target", "local_verify",
            "--trust-policy-dir", str(policy_dir),
        ])
        data = json.loads(result.output)
        trust = data["trust"]
        # Must be fully serializable (no objects, no None surprises)
        reparsed = json.loads(json.dumps(trust))
        assert reparsed == trust
