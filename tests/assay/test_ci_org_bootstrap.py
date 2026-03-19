"""Tests for ci-org bootstrap helpers used by the first real CI rollout."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.trust.ci_org_bootstrap import (
    bootstrap_ci_org_signer,
    build_ci_smoke_pack,
)

runner = CliRunner()

FAKE_SHA = "a" * 40


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    import assay.store as store_mod

    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


def _make_policy_dir(tmp_path: Path) -> Path:
    import yaml

    policy_dir = tmp_path / "trust"
    policy_dir.mkdir()
    signers = {
        "version": 1,
        "signer_classes": {
            "ci-org": {
                "description": "Organization-controlled signer for CI and publication contexts.",
                "allowed_targets": ["ci_gate", "publication"],
            },
        },
        "verification_profiles": {
            "ci_gate": {"accepts_authorization_statuses": ["authorized"]},
            "publication": {"accepts_authorization_statuses": ["authorized"]},
        },
        "signers": [],
    }
    acceptance = {
        "rules": [
            {
                "artifact_class": "proof_pack",
                "verification_level": "signature_verified",
                "authorization_status": "authorized",
                "target": "ci_gate",
                "decision": "accept",
                "reason": "Signed by authorized signer",
            },
            {
                "artifact_class": "proof_pack",
                "verification_level": "signature_verified",
                "authorization_status": "authorized",
                "target": "publication",
                "decision": "accept",
                "reason": "Signed by authorized signer for publication",
            },
            {
                "artifact_class": "*",
                "verification_level": "*",
                "authorization_status": "*",
                "target": "*",
                "decision": "reject",
                "reason": "INSUFFICIENT_VERIFICATION",
            },
        ]
    }
    (policy_dir / "signers.yaml").write_text(yaml.safe_dump(signers, sort_keys=False), encoding="utf-8")
    (policy_dir / "acceptance.yaml").write_text(yaml.safe_dump(acceptance, sort_keys=False), encoding="utf-8")
    return policy_dir


def _export_key_material(signer_id: str, *, source_dir: Path) -> tuple[str, str, str]:
    ks = AssayKeyStore(keys_dir=source_dir / "keys")
    ks.generate_key(signer_id)
    pub_b64 = base64.b64encode(ks.get_verify_key(signer_id).encode()).decode("ascii")
    key_b64 = base64.b64encode(ks.get_signing_key(signer_id).encode()).decode("ascii")
    fingerprint = ks.signer_fingerprint(signer_id)
    return pub_b64, key_b64, fingerprint


def test_bootstrap_imports_signer_and_writes_overlay(assay_home_tmp: Path, tmp_path: Path) -> None:
    policy_dir = _make_policy_dir(tmp_path)
    pub_b64, key_b64, fingerprint = _export_key_material("ci-org-main", source_dir=tmp_path / "source")

    result = bootstrap_ci_org_signer(
        policy_dir=policy_dir,
        output_dir=tmp_path / "overlay",
        signer_id="ci-org-main",
        pub_b64=pub_b64,
        key_b64=key_b64,
        expected_fingerprint=fingerprint,
    )

    ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
    assert ks.has_key("ci-org-main")
    assert ks.get_active_signer() == "ci-org-main"
    assert ks.signer_fingerprint("ci-org-main") == fingerprint
    assert result.fingerprint == fingerprint

    signers_yaml = (result.policy_dir / "signers.yaml").read_text(encoding="utf-8")
    assert "ci-org-main" in signers_yaml
    assert fingerprint in signers_yaml
    assert "signer_class: ci-org" in signers_yaml


def test_bootstrap_rejects_fingerprint_mismatch(assay_home_tmp: Path, tmp_path: Path) -> None:
    policy_dir = _make_policy_dir(tmp_path)
    pub_b64, key_b64, _ = _export_key_material("ci-org-main", source_dir=tmp_path / "source")

    with pytest.raises(ValueError, match="fingerprint mismatch"):
        bootstrap_ci_org_signer(
            policy_dir=policy_dir,
            output_dir=tmp_path / "overlay",
            signer_id="ci-org-main",
            pub_b64=pub_b64,
            key_b64=key_b64,
            expected_fingerprint="0" * 64,
        )


def test_build_smoke_pack_and_verify_under_ci_gate(
    assay_home_tmp: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    policy_dir = _make_policy_dir(tmp_path)
    pub_b64, key_b64, fingerprint = _export_key_material("ci-org-main", source_dir=tmp_path / "source")

    overlay_dir = bootstrap_ci_org_signer(
        policy_dir=policy_dir,
        output_dir=tmp_path / "overlay",
        signer_id="ci-org-main",
        pub_b64=pub_b64,
        key_b64=key_b64,
        expected_fingerprint=fingerprint,
    ).policy_dir

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", FAKE_SHA)
    monkeypatch.setenv("GITHUB_REPOSITORY", "Haserjian/assay")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

    pack_dir = build_ci_smoke_pack(output_dir=tmp_path / "ci_org_smoke_pack")
    manifest = json.loads((pack_dir / "pack_manifest.json").read_text(encoding="utf-8"))
    assert manifest["signer_id"] == "ci-org-main"
    assert manifest["attestation"]["ci_binding"]["commit_sha"] == FAKE_SHA

    result = runner.invoke(
        assay_app,
        [
            "verify-pack",
            str(pack_dir),
            "--json",
            "--require-claim-pass",
            "--require-ci-binding",
            "--expected-commit-sha",
            FAKE_SHA,
            "--trust-target",
            "ci_gate",
            "--trust-policy-dir",
            str(overlay_dir),
            "--enforce-trust-gate",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert (data["trust"].get("load_errors") or []) == []
    assert data["trust"]["acceptance"]["decision"] == "accept"
