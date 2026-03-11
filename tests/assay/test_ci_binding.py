"""Tests for CI binding in proof packs.

Covers:
  - detect_ci_binding() env var detection
  - ci_binding embedded in attestation
  - verify_pack_manifest with --require-ci-binding
  - verify_pack_manifest with --expected-commit-sha
  - match/mismatch/missing scenarios
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from assay.integrity import (
    E_CI_BINDING_MISSING,
    E_CI_BINDING_MISMATCH,
    verify_pack_manifest,
)
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack, build_proof_pack, detect_ci_binding
import assay.store as store_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keystore(tmp_path):
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test")
    return ks


def _build_pack(keystore, ci_binding=None, tmp_path=None):
    """Helper: build a minimal pack and return (manifest, pack_dir)."""
    td = tmp_path or Path(tempfile.mkdtemp())
    pack_dir = td / "pack"
    pp = ProofPack(
        run_id="ci-binding-test",
        entries=[],
        signer_id="test",
        ci_binding=ci_binding,
    )
    result_dir = pp.build(pack_dir, keystore=keystore)
    manifest = json.loads((result_dir / "pack_manifest.json").read_text())
    return manifest, result_dir


FAKE_SHA = "a" * 40
OTHER_SHA = "b" * 40

FULL_BINDING = {
    "provider": "github_actions",
    "repo": "Haserjian/assay",
    "ref": "refs/heads/main",
    "commit_sha": FAKE_SHA,
    "run_id": "12345",
    "run_attempt": "1",
    "workflow_ref": ".github/workflows/ci.yml",
    "actor": "test-user",
}


def _clear_github_env(monkeypatch):
    for key in (
        "GITHUB_ACTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_ACTOR",
    ):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# detect_ci_binding tests
# ---------------------------------------------------------------------------

class TestDetectCiBinding:
    def test_returns_none_locally(self):
        # Ensure GITHUB_ACTIONS is not set
        old = os.environ.pop("GITHUB_ACTIONS", None)
        try:
            assert detect_ci_binding() is None
        finally:
            if old is not None:
                os.environ["GITHUB_ACTIONS"] = old

    def test_detects_github_actions(self):
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "Haserjian/assay",
            "GITHUB_REF": "refs/pull/42/merge",
            "GITHUB_SHA": FAKE_SHA,
            "GITHUB_RUN_ID": "98765",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_WORKFLOW_REF": "Haserjian/assay/.github/workflows/ci.yml@refs/heads/main",
            "GITHUB_ACTOR": "dependabot[bot]",
        }
        old_vals = {}
        for k, v in env.items():
            old_vals[k] = os.environ.get(k)
            os.environ[k] = v
        try:
            binding = detect_ci_binding()
            assert binding is not None
            assert binding["provider"] == "github_actions"
            assert binding["commit_sha"] == FAKE_SHA
            assert binding["repo"] == "Haserjian/assay"
            assert binding["run_id"] == "98765"
            assert binding["run_attempt"] == "2"
            assert binding["actor"] == "dependabot[bot]"
        finally:
            for k, old in old_vals.items():
                if old is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = old

    def test_partial_env_still_works(self):
        """Only GITHUB_ACTIONS and GITHUB_SHA set — other fields omitted."""
        env = {"GITHUB_ACTIONS": "true", "GITHUB_SHA": FAKE_SHA}
        old_vals = {}
        # Clear all GH env vars first
        gh_keys = [
            "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF",
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            "GITHUB_WORKFLOW_REF", "GITHUB_ACTOR",
        ]
        for k in gh_keys:
            old_vals[k] = os.environ.pop(k, None)
        for k, v in env.items():
            os.environ[k] = v
        try:
            binding = detect_ci_binding()
            assert binding is not None
            assert binding["provider"] == "github_actions"
            assert binding["commit_sha"] == FAKE_SHA
            assert "repo" not in binding
            assert "run_id" not in binding
        finally:
            for k in gh_keys:
                os.environ.pop(k, None)
            for k, old in old_vals.items():
                if old is not None:
                    os.environ[k] = old

    def test_github_actions_without_sha_returns_none(self):
        env = {"GITHUB_ACTIONS": "true"}
        old_vals = {}
        gh_keys = [
            "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF",
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            "GITHUB_WORKFLOW_REF", "GITHUB_ACTOR",
        ]
        for k in gh_keys:
            old_vals[k] = os.environ.pop(k, None)
        for k, v in env.items():
            os.environ[k] = v
        try:
            assert detect_ci_binding() is None
        finally:
            for k in gh_keys:
                os.environ.pop(k, None)
            for k, old in old_vals.items():
                if old is not None:
                    os.environ[k] = old


# ---------------------------------------------------------------------------
# Pack attestation embedding tests
# ---------------------------------------------------------------------------

class TestCiBindingInAttestation:
    def test_no_binding_local(self, keystore, tmp_path, monkeypatch):
        _clear_github_env(monkeypatch)
        manifest, _ = _build_pack(keystore, ci_binding=None, tmp_path=tmp_path)
        att = manifest["attestation"]
        assert att["ci_binding"] is None

    def test_binding_embedded(self, keystore, tmp_path):
        manifest, _ = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)
        att = manifest["attestation"]
        cb = att["ci_binding"]
        assert cb["provider"] == "github_actions"
        assert cb["commit_sha"] == FAKE_SHA
        assert cb["repo"] == "Haserjian/assay"
        assert cb["run_id"] == "12345"

    def test_direct_build_auto_detects_ci_binding(self, keystore, tmp_path, monkeypatch):
        _clear_github_env(monkeypatch)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_SHA", FAKE_SHA)
        monkeypatch.setenv("GITHUB_REPOSITORY", "Haserjian/assay")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

        manifest, _ = _build_pack(keystore, ci_binding=None, tmp_path=tmp_path)
        cb = manifest["attestation"]["ci_binding"]
        assert cb is not None
        assert cb["provider"] == "github_actions"
        assert cb["commit_sha"] == FAKE_SHA
        assert cb["repo"] == "Haserjian/assay"
        assert cb["ref"] == "refs/heads/main"

    def test_binding_covered_by_signature(self, keystore, tmp_path):
        """CI binding is part of the signed attestation — tampering fails verification."""
        manifest, pack_dir = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)

        # Tamper with ci_binding in the manifest file
        manifest["attestation"]["ci_binding"]["commit_sha"] = OTHER_SHA
        (pack_dir / "pack_manifest.json").write_text(json.dumps(manifest, indent=2))

        result = verify_pack_manifest(manifest, pack_dir, keystore)
        assert not result.passed
        error_codes = [e.code for e in result.errors]
        # Should detect attestation hash mismatch (tamper)
        assert any("TAMPER" in c or "SIG" in c for c in error_codes)


# ---------------------------------------------------------------------------
# Verification: require_ci_binding flag
# ---------------------------------------------------------------------------

class TestRequireCiBinding:
    def test_not_required_no_binding_passes(self, keystore, tmp_path, monkeypatch):
        _clear_github_env(monkeypatch)
        manifest, pack_dir = _build_pack(keystore, ci_binding=None, tmp_path=tmp_path)
        result = verify_pack_manifest(manifest, pack_dir, keystore, require_ci_binding=False)
        assert result.passed

    def test_required_no_binding_fails(self, keystore, tmp_path, monkeypatch):
        _clear_github_env(monkeypatch)
        manifest, pack_dir = _build_pack(keystore, ci_binding=None, tmp_path=tmp_path)
        result = verify_pack_manifest(manifest, pack_dir, keystore, require_ci_binding=True)
        assert not result.passed
        error_codes = [e.code for e in result.errors]
        assert E_CI_BINDING_MISSING in error_codes

    def test_required_with_binding_passes(self, keystore, tmp_path):
        manifest, pack_dir = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)
        result = verify_pack_manifest(manifest, pack_dir, keystore, require_ci_binding=True)
        assert result.passed


# ---------------------------------------------------------------------------
# Verification: expected_commit_sha flag
# ---------------------------------------------------------------------------

class TestExpectedCommitSha:
    def test_matching_sha_passes(self, keystore, tmp_path):
        manifest, pack_dir = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)
        result = verify_pack_manifest(
            manifest, pack_dir, keystore, expected_commit_sha=FAKE_SHA,
        )
        assert result.passed

    def test_mismatching_sha_fails(self, keystore, tmp_path):
        manifest, pack_dir = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)
        result = verify_pack_manifest(
            manifest, pack_dir, keystore, expected_commit_sha=OTHER_SHA,
        )
        assert not result.passed
        error_codes = [e.code for e in result.errors]
        assert E_CI_BINDING_MISMATCH in error_codes

    def test_expected_sha_no_binding_fails(self, keystore, tmp_path, monkeypatch):
        """Expecting a commit SHA but pack has no CI binding → fail."""
        _clear_github_env(monkeypatch)
        manifest, pack_dir = _build_pack(keystore, ci_binding=None, tmp_path=tmp_path)
        result = verify_pack_manifest(
            manifest, pack_dir, keystore, expected_commit_sha=FAKE_SHA,
        )
        assert not result.passed
        error_codes = [e.code for e in result.errors]
        assert E_CI_BINDING_MISSING in error_codes

    def test_both_flags_together(self, keystore, tmp_path):
        """require_ci_binding + expected_commit_sha both pass when binding matches."""
        manifest, pack_dir = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)
        result = verify_pack_manifest(
            manifest, pack_dir, keystore,
            require_ci_binding=True,
            expected_commit_sha=FAKE_SHA,
        )
        assert result.passed

    def test_both_flags_mismatch(self, keystore, tmp_path):
        """require_ci_binding + wrong expected_commit_sha → mismatch error."""
        manifest, pack_dir = _build_pack(keystore, ci_binding=FULL_BINDING, tmp_path=tmp_path)
        result = verify_pack_manifest(
            manifest, pack_dir, keystore,
            require_ci_binding=True,
            expected_commit_sha=OTHER_SHA,
        )
        assert not result.passed
        error_codes = [e.code for e in result.errors]
        assert E_CI_BINDING_MISMATCH in error_codes


# ---------------------------------------------------------------------------
# Minimal binding (only required fields)
# ---------------------------------------------------------------------------

class TestMinimalBinding:
    def test_minimal_binding_passes_schema(self, keystore, tmp_path):
        """Only provider + commit_sha (the required fields) should work."""
        minimal = {"provider": "github_actions", "commit_sha": FAKE_SHA}
        manifest, pack_dir = _build_pack(keystore, ci_binding=minimal, tmp_path=tmp_path)
        result = verify_pack_manifest(
            manifest, pack_dir, keystore,
            require_ci_binding=True,
            expected_commit_sha=FAKE_SHA,
        )
        assert result.passed
        cb = manifest["attestation"]["ci_binding"]
        assert cb["provider"] == "github_actions"
        assert cb["commit_sha"] == FAKE_SHA
        assert "repo" not in cb


class TestBuildProofPackCiAutoDetection:
    def test_build_proof_pack_auto_detects_ci_binding(self, tmp_path, monkeypatch):
        # Isolate store/keys under tmp home
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(store_mod, "_default_store", None)

        store = store_mod.get_default_store()
        trace_id = store.start_trace("trace_ci_binding_auto")
        store.append_dict(
            {
                "receipt_id": "r_ci_1",
                "type": "model_call",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "schema_version": "3.0",
                "seq": 0,
            }
        )

        # Simulate GitHub Actions environment
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_SHA", FAKE_SHA)
        monkeypatch.setenv("GITHUB_REPOSITORY", "Haserjian/assay")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

        ks = AssayKeyStore(keys_dir=tmp_path / ".assay" / "keys")
        ks.generate_key("assay-local")

        out_dir = tmp_path / "proof_pack_auto_ci"
        result_dir = build_proof_pack(trace_id, output_dir=out_dir, keystore=ks)
        manifest = json.loads((result_dir / "pack_manifest.json").read_text())

        cb = manifest["attestation"]["ci_binding"]
        assert cb is not None
        assert cb["provider"] == "github_actions"
        assert cb["commit_sha"] == FAKE_SHA
        assert cb["repo"] == "Haserjian/assay"
        assert cb["ref"] == "refs/heads/main"
