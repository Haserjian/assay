"""Tests for assay trust bootstrap command."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


def _run_bootstrap(tmp_path: Path, profile: str, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable, "-m", "assay", "trust", "bootstrap",
        "--profile", profile,
        "--output-dir", str(tmp_path),
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


class TestGeneratedSignersYaml:
    """P1: signers.yaml must be valid YAML with signers as a list."""

    @pytest.mark.parametrize("profile", ["minimal", "reviewer", "strict"])
    def test_signers_parses_as_list(self, tmp_path: Path, profile: str) -> None:
        result = _run_bootstrap(tmp_path, profile)
        assert result.returncode == 0, result.stderr

        signers_path = tmp_path / "trust" / "signers.yaml"
        assert signers_path.exists()

        data = yaml.safe_load(signers_path.read_text())
        assert isinstance(data["signers"], list), (
            f"signers should be a list, got {type(data['signers']).__name__}: {data['signers']}"
        )

    @pytest.mark.parametrize("profile", ["minimal", "reviewer", "strict"])
    def test_acceptance_parses_with_rules_list(self, tmp_path: Path, profile: str) -> None:
        result = _run_bootstrap(tmp_path, profile)
        assert result.returncode == 0, result.stderr

        acceptance_path = tmp_path / "trust" / "acceptance.yaml"
        data = yaml.safe_load(acceptance_path.read_text())
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) >= 3


class TestTrustLoaderAcceptsGeneratedPolicy:
    """P1: verify-pack must load generated trust policy without errors."""

    @pytest.mark.parametrize("profile", ["minimal", "reviewer", "strict"])
    def test_no_load_errors(self, tmp_path: Path, profile: str) -> None:
        result = _run_bootstrap(tmp_path, profile)
        assert result.returncode == 0, result.stderr

        from assay.trust.registry import load_registry
        from assay.trust.acceptance import load_acceptance

        trust_dir = tmp_path / "trust"
        registry = load_registry(trust_dir / "signers.yaml")
        assert registry is not None

        matrix = load_acceptance(trust_dir / "acceptance.yaml")
        assert matrix is not None


class TestOverwriteGuard:
    """P2: bootstrap must refuse to overwrite any target without --force."""

    def test_refuses_when_trust_dir_exists(self, tmp_path: Path) -> None:
        # First run succeeds
        result = _run_bootstrap(tmp_path, "minimal")
        assert result.returncode == 0

        # Second run without --force fails
        result = _run_bootstrap(tmp_path, "minimal")
        assert result.returncode == 1
        assert "Existing files" in result.stderr or "already exists" in result.stderr or "overwritten" in result.stdout

    def test_refuses_when_only_workflow_exists(self, tmp_path: Path) -> None:
        # Create only the workflow file, no trust/ dir
        workflow = tmp_path / ".github" / "workflows" / "assay-verify.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("existing workflow")

        result = _run_bootstrap(tmp_path, "minimal")
        assert result.returncode == 1

    def test_force_overwrites(self, tmp_path: Path) -> None:
        # First run
        result = _run_bootstrap(tmp_path, "minimal")
        assert result.returncode == 0

        # Second run with --force succeeds
        result = _run_bootstrap(tmp_path, "reviewer", ["--force"])
        assert result.returncode == 0

        # Verify it's now reviewer profile
        acceptance = yaml.safe_load((tmp_path / "trust" / "acceptance.yaml").read_text())
        unrecognized_rule = [r for r in acceptance["rules"] if r["authorization_status"] == "unrecognized"][0]
        assert unrecognized_rule["decision"] == "warn"  # reviewer warns, minimal accepts

    def test_dry_run_does_not_write(self, tmp_path: Path) -> None:
        result = _run_bootstrap(tmp_path, "minimal", ["--dry-run"])
        assert result.returncode == 0
        assert not (tmp_path / "trust").exists()
        assert not (tmp_path / ".github").exists()


class TestProfileDifferences:
    """Verify profiles produce distinct acceptance behavior."""

    def test_minimal_accepts_unrecognized(self, tmp_path: Path) -> None:
        _run_bootstrap(tmp_path, "minimal")
        data = yaml.safe_load((tmp_path / "trust" / "acceptance.yaml").read_text())
        rule = [r for r in data["rules"] if r["authorization_status"] == "unrecognized"][0]
        assert rule["decision"] == "accept"

    def test_reviewer_warns_unrecognized(self, tmp_path: Path) -> None:
        _run_bootstrap(tmp_path, "reviewer")
        data = yaml.safe_load((tmp_path / "trust" / "acceptance.yaml").read_text())
        rule = [r for r in data["rules"] if r["authorization_status"] == "unrecognized"][0]
        assert rule["decision"] == "warn"

    def test_strict_rejects_unrecognized(self, tmp_path: Path) -> None:
        _run_bootstrap(tmp_path, "strict")
        data = yaml.safe_load((tmp_path / "trust" / "acceptance.yaml").read_text())
        rule = [r for r in data["rules"] if r["authorization_status"] == "unrecognized"][0]
        assert rule["decision"] == "reject"

    def test_strict_workflow_has_enforce_trust(self, tmp_path: Path) -> None:
        _run_bootstrap(tmp_path, "strict")
        workflow = (tmp_path / ".github" / "workflows" / "assay-verify.yml").read_text()
        assert "enforce-trust: true" in workflow

    def test_minimal_workflow_has_no_enforce_trust(self, tmp_path: Path) -> None:
        _run_bootstrap(tmp_path, "minimal")
        workflow = (tmp_path / ".github" / "workflows" / "assay-verify.yml").read_text()
        assert "enforce-trust" not in workflow

    def test_workflow_pins_action_to_sha(self, tmp_path: Path) -> None:
        _run_bootstrap(tmp_path, "reviewer")
        workflow = (tmp_path / ".github" / "workflows" / "assay-verify.yml").read_text()
        assert "assay-verify-action@40af9bd" in workflow
        assert "@v1" not in workflow
        assert "@main" not in workflow

    def test_invalid_profile_rejected(self, tmp_path: Path) -> None:
        result = _run_bootstrap(tmp_path, "bogus")
        assert result.returncode == 1
