"""Tests for assay doctor."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.doctor import (
    CheckStatus,
    DoctorCheckResult,
    DoctorReport,
    Profile,
    Severity,
    run_doctor,
    _check_core_001,
    _check_fs_001,
    _check_key_001,
    _check_card_001,
    _check_lock_001,
    _check_lock_002,
    _check_lock_003,
    _check_pack_001,
    _check_pack_002,
    _check_exit_001,
    _check_ci_001,
    _check_ledger_001,
    _check_witness_001,
)


# ---------------------------------------------------------------------------
# DoctorCheckResult model
# ---------------------------------------------------------------------------

class TestDoctorCheckResult:
    def test_to_dict_minimal(self):
        r = DoctorCheckResult(
            id="TEST_001", status=CheckStatus.PASS,
            severity=Severity.INFO, message="ok",
        )
        d = r.to_dict()
        assert d["id"] == "TEST_001"
        assert d["status"] == "pass"
        assert d["severity"] == "info"
        assert "evidence" not in d
        assert "fix" not in d

    def test_to_dict_with_evidence_and_fix(self):
        r = DoctorCheckResult(
            id="TEST_002", status=CheckStatus.FAIL,
            severity=Severity.HIGH, message="broken",
            evidence={"key": "val"}, fix="do something",
        )
        d = r.to_dict()
        assert d["evidence"] == {"key": "val"}
        assert d["fix"] == "do something"


# ---------------------------------------------------------------------------
# DoctorReport model
# ---------------------------------------------------------------------------

class TestDoctorReport:
    def test_summary_counts(self):
        report = DoctorReport(profile=Profile.LOCAL, version="1.0.0")
        report.checks = [
            DoctorCheckResult("A", CheckStatus.PASS, Severity.INFO, "ok"),
            DoctorCheckResult("B", CheckStatus.PASS, Severity.INFO, "ok"),
            DoctorCheckResult("C", CheckStatus.WARN, Severity.MEDIUM, "warn"),
            DoctorCheckResult("D", CheckStatus.FAIL, Severity.HIGH, "fail"),
            DoctorCheckResult("E", CheckStatus.SKIP, Severity.INFO, "skip"),
        ]
        assert report.summary == {"pass": 2, "warn": 1, "fail": 1, "skip": 1}

    def test_overall_status_fail(self):
        report = DoctorReport(profile=Profile.LOCAL, version="1.0.0")
        report.checks = [
            DoctorCheckResult("A", CheckStatus.PASS, Severity.INFO, "ok"),
            DoctorCheckResult("B", CheckStatus.FAIL, Severity.HIGH, "fail"),
        ]
        assert report.overall_status == "fail"
        assert report.exit_code == 2

    def test_overall_status_warn(self):
        report = DoctorReport(profile=Profile.LOCAL, version="1.0.0")
        report.checks = [
            DoctorCheckResult("A", CheckStatus.PASS, Severity.INFO, "ok"),
            DoctorCheckResult("B", CheckStatus.WARN, Severity.MEDIUM, "warn"),
        ]
        assert report.overall_status == "warn"
        assert report.exit_code == 1

    def test_overall_status_pass(self):
        report = DoctorReport(profile=Profile.LOCAL, version="1.0.0")
        report.checks = [
            DoctorCheckResult("A", CheckStatus.PASS, Severity.INFO, "ok"),
        ]
        assert report.overall_status == "pass"
        assert report.exit_code == 0

    def test_strict_escalates_warn(self):
        report = DoctorReport(profile=Profile.LOCAL, version="1.0.0")
        report.checks = [
            DoctorCheckResult("A", CheckStatus.WARN, Severity.MEDIUM, "warn"),
        ]
        assert report.exit_code == 1
        assert report.exit_code_strict() == 2

    def test_to_dict_json_schema(self):
        report = DoctorReport(profile=Profile.CI, version="1.0.1")
        report.checks = [
            DoctorCheckResult("A", CheckStatus.PASS, Severity.INFO, "ok"),
        ]
        report.next_command = "assay run -- python test.py"
        d = report.to_dict()
        assert d["tool"] == "assay-doctor"
        assert d["version"] == "1.0.1"
        assert d["profile"] == "ci"
        assert d["status"] == "pass"
        assert d["summary"]["pass"] == 1
        assert d["next_command"] == "assay run -- python test.py"
        # Must be valid JSON
        json.dumps(d)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

class TestCheckCore001:
    def test_assay_available(self):
        r = _check_core_001()
        assert r.status == CheckStatus.PASS
        assert r.id == "DOCTOR_CORE_001"
        assert "version" in r.evidence


class TestCheckFS001:
    def test_home_writable(self):
        r = _check_fs_001()
        assert r.status == CheckStatus.PASS
        assert r.id == "DOCTOR_FS_001"


class TestCheckKey001:
    def test_key_check(self):
        r = _check_key_001()
        assert r.id == "DOCTOR_KEY_001"
        # Either PASS (key exists) or WARN (no key yet)
        assert r.status in (CheckStatus.PASS, CheckStatus.WARN)


class TestCheckCard001:
    def test_cards_available(self):
        r = _check_card_001()
        assert r.status == CheckStatus.PASS
        assert r.id == "DOCTOR_CARD_001"
        assert len(r.evidence["cards"]) >= 2


class TestCheckLock001:
    def test_missing_lockfile(self, tmp_path):
        r = _check_lock_001(tmp_path / "nonexistent.lock")
        assert r.status == CheckStatus.WARN
        assert r.fix is not None

    def test_valid_lockfile(self, tmp_path):
        from assay.lockfile import write_lockfile
        lock_path = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness"], output_path=lock_path)
        r = _check_lock_001(lock_path)
        assert r.status == CheckStatus.PASS

    def test_corrupt_lockfile(self, tmp_path):
        lock_path = tmp_path / "assay.lock"
        lock_path.write_text("{bad json")
        r = _check_lock_001(lock_path)
        assert r.status == CheckStatus.FAIL


class TestCheckLock002:
    def test_no_lockfile_skips(self, tmp_path):
        r = _check_lock_002(tmp_path / "nonexistent.lock")
        assert r.status == CheckStatus.SKIP

    def test_valid_lockfile_passes(self, tmp_path):
        from assay.lockfile import write_lockfile
        lock_path = tmp_path / "assay.lock"
        write_lockfile(["receipt_completeness", "guardian_enforcement"], output_path=lock_path)
        r = _check_lock_002(lock_path)
        assert r.status == CheckStatus.PASS


class TestCheckLock003:
    def test_no_lockfile_skips(self, tmp_path):
        r = _check_lock_003(tmp_path / "nonexistent.lock")
        assert r.status == CheckStatus.SKIP

    def test_clean_lockfile_passes(self, tmp_path):
        lock_path = tmp_path / "assay.lock"
        lock_path.write_text(json.dumps({
            "signer_policy": {"mode": "any", "allowed_fingerprints": []},
        }))
        r = _check_lock_003(lock_path)
        assert r.status == CheckStatus.PASS

    def test_corpus_signer_in_allowlist_fails(self, tmp_path):
        lock_path = tmp_path / "assay.lock"
        lock_path.write_text(json.dumps({
            "signer_policy": {
                "mode": "allowlist",
                "allowed_fingerprints": [],
                "allowed_signer_ids": ["my-prod-key", "corpus-signer"],
            },
        }))
        r = _check_lock_003(lock_path)
        assert r.status == CheckStatus.FAIL
        assert "corpus-signer" in r.message

    def test_corpus_signer_underscore_variant(self, tmp_path):
        lock_path = tmp_path / "assay.lock"
        lock_path.write_text(json.dumps({
            "signer_policy": {
                "mode": "allowlist",
                "allowed_signer_ids": ["corpus_signer"],
            },
        }))
        r = _check_lock_003(lock_path)
        assert r.status == CheckStatus.FAIL

    def test_prod_signer_only_passes(self, tmp_path):
        lock_path = tmp_path / "assay.lock"
        lock_path.write_text(json.dumps({
            "signer_policy": {
                "mode": "allowlist",
                "allowed_signer_ids": ["prod-signer-001"],
            },
        }))
        r = _check_lock_003(lock_path)
        assert r.status == CheckStatus.PASS


class TestCheckPack001:
    def test_no_pack_skips(self):
        r = _check_pack_001(Path("/nonexistent"))
        assert r.status == CheckStatus.FAIL  # dir doesn't exist, files missing

    def test_valid_pack(self):
        pack_dir = Path(__file__).parent.parent.parent / "conformance" / "corpus_v1" / "packs" / "good_01"
        if not pack_dir.exists():
            pytest.skip("corpus not generated")
        r = _check_pack_001(pack_dir)
        assert r.status == CheckStatus.PASS

    def test_missing_files(self, tmp_path):
        (tmp_path / "pack_manifest.json").write_text("{}")
        r = _check_pack_001(tmp_path)
        assert r.status == CheckStatus.FAIL
        assert "missing" in r.message.lower()


class TestCheckPack002:
    def test_valid_corpus_pack(self):
        pack_dir = Path(__file__).parent.parent.parent / "conformance" / "corpus_v1" / "packs" / "good_01"
        if not pack_dir.exists():
            pytest.skip("corpus not generated")
        r = _check_pack_002(pack_dir)
        assert r.status == CheckStatus.PASS

    def test_tampered_pack(self):
        pack_dir = Path(__file__).parent.parent.parent / "conformance" / "corpus_v1" / "packs" / "tampered_01"
        if not pack_dir.exists():
            pytest.skip("corpus not generated")
        r = _check_pack_002(pack_dir)
        assert r.status == CheckStatus.FAIL


class TestCheckExit001:
    def test_exit_contract(self):
        r = _check_exit_001()
        assert r.status == CheckStatus.PASS
        assert "exit_codes" in r.evidence


class TestCheckCI001:
    def test_no_workflows_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = _check_ci_001()
        assert r.status == CheckStatus.WARN

    def test_with_workflows(self, tmp_path, monkeypatch):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("steps:\n  - run: assay verify-pack ./pack/\n")
        monkeypatch.chdir(tmp_path)
        r = _check_ci_001()
        assert r.status == CheckStatus.PASS

    def test_workflow_without_assay(self, tmp_path, monkeypatch):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("steps:\n  - run: pytest\n")
        monkeypatch.chdir(tmp_path)
        r = _check_ci_001()
        assert r.status == CheckStatus.WARN


class TestCheckWitness001:
    def test_dev_mode(self):
        r = _check_witness_001(strict=False)
        assert r.status == CheckStatus.PASS

    def test_strict_mode(self):
        r = _check_witness_001(strict=True)
        assert r.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# Runner integration
# ---------------------------------------------------------------------------

class TestRunDoctor:
    def test_local_profile_runs(self):
        report = run_doctor(Profile.LOCAL)
        assert report.profile == Profile.LOCAL
        assert len(report.checks) >= 5
        assert report.next_command is not None

    def test_ci_profile_runs(self):
        report = run_doctor(Profile.CI)
        assert report.profile == Profile.CI
        assert any(c.id == "DOCTOR_CI_001" for c in report.checks)
        assert any(c.id == "DOCTOR_LOCK_003" for c in report.checks)

    def test_ledger_profile_runs(self):
        report = run_doctor(Profile.LEDGER)
        assert report.profile == Profile.LEDGER
        assert any(c.id == "DOCTOR_LEDGER_001" for c in report.checks)
        assert any(c.id == "DOCTOR_WITNESS_001" for c in report.checks)

    def test_release_profile_runs(self):
        report = run_doctor(Profile.RELEASE)
        assert report.profile == Profile.RELEASE
        assert any(c.id == "DOCTOR_LOCK_001" for c in report.checks)

    def test_with_corpus_pack(self):
        pack_dir = Path(__file__).parent.parent.parent / "conformance" / "corpus_v1" / "packs" / "good_01"
        if not pack_dir.exists():
            pytest.skip("corpus not generated")
        report = run_doctor(Profile.LOCAL, pack_dir=pack_dir)
        pack_checks = [c for c in report.checks if c.id.startswith("DOCTOR_PACK")]
        assert all(c.status == CheckStatus.PASS for c in pack_checks)

    def test_strict_mode_escalates(self):
        report = run_doctor(Profile.LEDGER, strict=True)
        # In strict mode on ledger, DOCTOR_WITNESS_001 warns
        witness = [c for c in report.checks if c.id == "DOCTOR_WITNESS_001"]
        assert len(witness) == 1
        assert witness[0].status == CheckStatus.WARN
        assert report.exit_code_strict() == 2

    def test_json_roundtrip(self):
        report = run_doctor(Profile.LOCAL)
        d = report.to_dict()
        serialized = json.dumps(d)
        parsed = json.loads(serialized)
        assert parsed["tool"] == "assay-doctor"
        assert isinstance(parsed["checks"], list)
        assert isinstance(parsed["summary"], dict)
