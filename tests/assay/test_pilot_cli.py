"""Tests for assay pilot run/verify/closeout CLI commands."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.pilot import (
    BUNDLE_SCHEMA_VERSION,
    C_LOCALITY_UNKNOWN,
    C_TIME_AUTHORITY_WEAK,
    C_TRUNCATED_OUTPUT,
    PilotConfig,
    PilotError,
    _run_self_test,
    _run_assay,
    load_pilot_config,
    run_pilot_closeout,
    verify_pilot_bundle,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_pilot_yaml(
    path: Path,
    *,
    test_cmd: str = "echo ok",
    version: str = "1",
    **overrides: object,
) -> Path:
    """Write a minimal pilot.yaml config file."""
    import yaml

    data: dict = {"version": version, "test_cmd": test_cmd}
    data.update(overrides)
    yaml_path = path / "pilot.yaml"
    yaml_path.write_text(yaml.dump(data), encoding="utf-8")
    return yaml_path


def _write_pilot_bundle(
    tmp_path: Path,
    *,
    with_proof: bool = True,
    with_score: bool = True,
    with_receipts: int = 0,
    verify_exit: int = 0,
    receipt_finish_reason: str | None = None,
    receipt_locality: str | None = None,
    receipt_time_authority: str | None = None,
) -> Path:
    """Write a minimal pilot bundle directory for testing."""
    bundle = tmp_path / "pilot_bundle"
    bundle.mkdir(parents=True, exist_ok=True)

    # proof/
    if with_proof:
        proof = bundle / "proof"
        proof.mkdir(parents=True, exist_ok=True)
        (proof / "pack_manifest.json").write_text('{"pack_id": "test"}', encoding="utf-8")
        (proof / "pack_signature.sig").write_text("sig", encoding="utf-8")
        receipt_lines = []
        for i in range(with_receipts):
            receipt: dict[str, object] = {"receipt_id": f"r_{i}", "type": "model_call"}
            if receipt_finish_reason is not None:
                receipt["finish_reason"] = receipt_finish_reason
            if receipt_locality is not None:
                receipt["locality"] = receipt_locality
            if receipt_time_authority is not None:
                receipt["time_authority"] = receipt_time_authority
            receipt_lines.append(json.dumps(receipt))
        (proof / "receipt_pack.jsonl").write_text(
            "\n".join(receipt_lines) + ("\n" if receipt_lines else ""),
            encoding="utf-8",
        )
        (proof / "verify_report.json").write_text('{"status":"pass"}', encoding="utf-8")
        (proof / "verify_transcript.md").write_text("# Verify\nPASS", encoding="utf-8")

    # score/
    if with_score:
        score = bundle / "score"
        score.mkdir(parents=True, exist_ok=True)
        (score / "before.json").write_text(
            json.dumps({"score": {"raw_score": 10.0, "breakdown": {}}}),
            encoding="utf-8",
        )
        (score / "after.json").write_text(
            json.dumps({"score": {"raw_score": 45.0, "breakdown": {}}}),
            encoding="utf-8",
        )
        (score / "delta.json").write_text(
            json.dumps({"before": 10.0, "after": 45.0, "delta": 35.0}),
            encoding="utf-8",
        )

    # verification/
    verify = bundle / "verification"
    verify.mkdir(parents=True, exist_ok=True)
    (verify / "summary.json").write_text(
        json.dumps({"pack_verify_exit": verify_exit, "status": "PASS" if verify_exit == 0 else "FAIL"}),
        encoding="utf-8",
    )

    # replay/
    replay = bundle / "replay"
    replay.mkdir(parents=True, exist_ok=True)
    (replay / "replay.sh").write_text("#!/bin/bash\necho replay\n", encoding="utf-8")

    # Collect artifacts and build manifest
    artifacts = []
    for path in sorted(bundle.rglob("*")):
        if path.is_dir():
            continue
        rel = str(path.relative_to(bundle))
        if rel.startswith(".") or rel == "manifest.json":
            continue
        artifacts.append({
            "name": rel,
            "sha256": _sha256(path.read_bytes()),
            "bytes": path.stat().st_size,
        })

    manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_id": "test_bundle_001",
        "created_at_utc": "2026-03-02T00:00:00+00:00",
        "repo": str(tmp_path),
        "commit": "abc1234",
        "branch": "main",
        "mode": "high-only",
        "assay_version": "1.11.1",
        "dirty_tree": False,
        "allow_empty": False,
        "steps_completed": ["preflight", "scan", "score_before", "run", "verify_pack", "write_bundle"],
        "artifacts": artifacts,
        "pack_root_sha256": "",
        "score_delta": {"before": 10.0, "after": 45.0, "delta": 35.0} if with_score else {},
    }

    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return bundle


# ---------------------------------------------------------------------------
# Config loading tests
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_load_config_valid(self, tmp_path: Path) -> None:
        _write_pilot_yaml(tmp_path, test_cmd="pytest -q", mode="high+medium")
        config = load_pilot_config(
            str(tmp_path / "pilot.yaml"),
            tmp_path,
        )
        assert isinstance(config, PilotConfig)
        assert config.test_cmd == "pytest -q"
        assert config.mode == "high+medium"
        assert config.allow_empty is False

    def test_load_config_missing_version(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "pilot.yaml"
        yaml_path.write_text("test_cmd: echo ok\n", encoding="utf-8")
        with pytest.raises(PilotError, match="Unsupported config version"):
            load_pilot_config(str(yaml_path), tmp_path)

    def test_load_config_unknown_keys(self, tmp_path: Path) -> None:
        _write_pilot_yaml(tmp_path, test_cmd="echo ok", bogus_key="bad")
        with pytest.raises(PilotError, match="Unknown config keys"):
            load_pilot_config(str(tmp_path / "pilot.yaml"), tmp_path)

    def test_load_config_type_mismatch(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "pilot.yaml"
        yaml_path.write_text(
            "version: '1'\ntest_cmd: echo ok\nallow_empty: not_a_bool\n",
            encoding="utf-8",
        )
        with pytest.raises(PilotError, match="must be boolean"):
            load_pilot_config(str(yaml_path), tmp_path)

    def test_load_config_cli_overrides(self, tmp_path: Path) -> None:
        _write_pilot_yaml(tmp_path, test_cmd="echo yaml", mode="high-only")
        config = load_pilot_config(
            str(tmp_path / "pilot.yaml"),
            tmp_path,
            cli_overrides={"test_cmd": "echo cli", "mode": "high+medium"},
        )
        assert config.test_cmd == "echo cli"
        assert config.mode == "high+medium"


# ---------------------------------------------------------------------------
# CLI help tests
# ---------------------------------------------------------------------------


class TestPilotHelp:
    def test_pilot_no_args_shows_help(self) -> None:
        result = runner.invoke(assay_app, ["pilot"])
        # Typer's no_args_is_help exits with code 0 or 2 depending on version
        assert result.exit_code in (0, 2)
        assert "run" in result.output
        assert "verify" in result.output
        assert "closeout" in result.output

    def test_pilot_run_help(self) -> None:
        result = runner.invoke(assay_app, ["pilot", "run", "--help"])
        assert result.exit_code == 0
        assert "--test-cmd" in result.output
        assert "--dry-run" in result.output

    def test_pilot_verify_help(self) -> None:
        result = runner.invoke(assay_app, ["pilot", "verify", "--help"])
        assert result.exit_code == 0
        assert "--profile" in result.output
        assert "--self-test" in result.output

    def test_pilot_closeout_help(self) -> None:
        result = runner.invoke(assay_app, ["pilot", "closeout", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output
        assert "--json-output" in result.output


# ---------------------------------------------------------------------------
# CLI run tests
# ---------------------------------------------------------------------------


class TestPilotRunCLI:
    def test_pilot_run_missing_repo(self) -> None:
        result = runner.invoke(
            assay_app,
            ["pilot", "run", "/nonexistent/path", "--test-cmd", "echo ok", "--json"],
        )
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert data["status"] == "error"

    def test_pilot_run_no_config_no_testcmd(self, tmp_path: Path) -> None:
        result = runner.invoke(
            assay_app,
            ["pilot", "run", str(tmp_path), "--json"],
        )
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert data["status"] == "error"

    def test_run_assay_uses_assay_cli_module(self, tmp_path: Path) -> None:
        result = _run_assay(["--help"], cwd=tmp_path, dry_run=True)
        assert result.command[:3] == [sys.executable, "-m", "assay.cli"]


# ---------------------------------------------------------------------------
# Verify tests (unit)
# ---------------------------------------------------------------------------


class TestVerifyPilotBundle:
    def test_verify_pass(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path, with_score=True, verify_exit=0)
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert errors == []

    def test_verify_claims_fail_missing_score(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path, with_score=False, verify_exit=0)
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 1
        assert "C_SCORE_BEFORE_MISSING" in errors
        assert "C_SCORE_AFTER_MISSING" in errors

    def test_verify_integrity_fail(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        # Corrupt a file to trigger integrity failure
        receipt_path = bundle / "proof" / "receipt_pack.jsonl"
        receipt_path.write_text('{"tampered": true}\n', encoding="utf-8")
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 2
        assert any("E_MANIFEST_TAMPER" in e for e in errors)
        assert warnings == []

    def test_verify_malformed_no_manifest(self, tmp_path: Path) -> None:
        bundle = tmp_path / "empty_bundle"
        bundle.mkdir()
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 3
        assert "E_MANIFEST_MISSING" in errors
        assert warnings == []

    def test_verify_otel_bridge_profile(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path,
            with_score=False,
            with_receipts=3,
            verify_exit=0,
        )
        # otel-bridge profile: requires receipts, not scores
        exit_code, errors, warnings = verify_pilot_bundle(bundle, profile="otel-bridge")
        assert exit_code == 0
        assert errors == []

    def test_verify_otel_bridge_no_receipts(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path,
            with_score=False,
            with_receipts=0,
            verify_exit=0,
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle, profile="otel-bridge")
        assert exit_code == 1
        assert "C_NO_RECEIPTS" in errors


# ---------------------------------------------------------------------------
# Verify CLI tests
# ---------------------------------------------------------------------------


class TestPilotVerifyCLI:
    def test_verify_pass_json(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        result = runner.invoke(
            assay_app,
            ["pilot", "verify", str(bundle), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["exit_code"] == 0

    def test_verify_claims_fail_json(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path, with_score=False)
        result = runner.invoke(
            assay_app,
            ["pilot", "verify", str(bundle), "--json"],
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "claims_fail"

    def test_verify_malformed_json(self, tmp_path: Path) -> None:
        bundle = tmp_path / "empty_bundle"
        bundle.mkdir()
        result = runner.invoke(
            assay_app,
            ["pilot", "verify", str(bundle), "--json"],
        )
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["status"] == "malformed"


# ---------------------------------------------------------------------------
# Self-test tests
# ---------------------------------------------------------------------------


class TestSelfTest:
    def test_self_test_detects_tamper(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        st_code, st_errors = _run_self_test(bundle)
        assert st_code == 0
        assert st_errors == []


# ---------------------------------------------------------------------------
# Closeout tests
# ---------------------------------------------------------------------------


class TestCloseout:
    def test_closeout_dry_run(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        row = run_pilot_closeout(bundle, dry_run=True)
        assert isinstance(row, dict)
        assert row["bundle_id"] == "test_bundle_001"
        assert row["pilot_type"] == "score-delta"
        assert row["verify_exit"] == 0

    def test_closeout_json_output(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        json_out = tmp_path / "closeout.json"
        row = run_pilot_closeout(bundle, json_output=json_out)
        assert json_out.exists()
        written = json.loads(json_out.read_text(encoding="utf-8"))
        assert written["bundle_id"] == row["bundle_id"]

    def test_closeout_jsonl_log(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        log_path = tmp_path / "replication.jsonl"
        row = run_pilot_closeout(bundle, log_path=log_path)
        assert log_path.exists()
        lines = [
            json.loads(l)
            for l in log_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        assert lines[0]["bundle_id"] == row["bundle_id"]

    def test_closeout_cli_dry_run(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path)
        result = runner.invoke(
            assay_app,
            ["pilot", "closeout", str(bundle), "--dry-run", "--json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["bundle_id"] == "test_bundle_001"

    def test_closeout_otel_bridge_type(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path,
            with_score=False,
            with_receipts=3,
        )
        row = run_pilot_closeout(bundle, dry_run=True)
        assert row["pilot_type"] == "otel-bridge"
        assert row["receipt_count"] == 3


# ---------------------------------------------------------------------------
# Receipt quality warning tests
# ---------------------------------------------------------------------------


class TestWarnCodes:
    def test_warn_truncated_output(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_finish_reason="length",
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_TRUNCATED_OUTPUT in warnings

    def test_no_warn_truncated_when_stop(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_finish_reason="stop",
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_TRUNCATED_OUTPUT not in warnings

    def test_warn_locality_unknown_absent(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path, with_receipts=3)
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_LOCALITY_UNKNOWN in warnings

    def test_warn_locality_unknown_explicit(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_locality="unknown",
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_LOCALITY_UNKNOWN in warnings

    def test_no_warn_locality_set(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_locality="cloud",
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_LOCALITY_UNKNOWN not in warnings

    def test_warn_time_authority_weak_absent(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path, with_receipts=3)
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_TIME_AUTHORITY_WEAK in warnings

    def test_warn_time_authority_local_clock(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_time_authority="local_clock",
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_TIME_AUTHORITY_WEAK in warnings

    def test_no_warn_time_authority_strong(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_time_authority="ntp_verified",
        )
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert exit_code == 0
        assert C_TIME_AUTHORITY_WEAK not in warnings

    def test_no_warns_zero_receipts(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(tmp_path, with_receipts=0)
        exit_code, errors, warnings = verify_pilot_bundle(bundle)
        assert warnings == []

    def test_closeout_warn_fields(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_finish_reason="length",
        )
        row = run_pilot_closeout(bundle, dry_run=True)
        assert row["verify_warn_codes"] is not None
        assert C_TRUNCATED_OUTPUT in row["verify_warn_codes"]
        assert row["verify_warn_count"] >= 1

    def test_closeout_no_warns_clean(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path,
            with_receipts=3,
            receipt_finish_reason="stop",
            receipt_locality="cloud",
            receipt_time_authority="ntp_verified",
        )
        row = run_pilot_closeout(bundle, dry_run=True)
        assert row["verify_warn_codes"] is None
        assert row["verify_warn_count"] == 0

    def test_verify_json_includes_warnings(self, tmp_path: Path) -> None:
        bundle = _write_pilot_bundle(
            tmp_path, with_receipts=3, receipt_finish_reason="length",
        )
        result = runner.invoke(
            assay_app,
            ["pilot", "verify", str(bundle), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "warnings" in data
        assert C_TRUNCATED_OUTPUT in data["warnings"]
        assert data["warning_count"] >= 1
