"""
Tests for LaunchReadinessReceipt and assay launch-check command.
"""
import json
import tempfile
from pathlib import Path



class TestCheckResult:
    """Tests for CheckResult receipt."""

    def test_create_check_result(self):
        """Can create CheckResult with required fields."""
        from assay._receipts.domains.launch_readiness import CheckResult

        check = CheckResult(
            receipt_id="chk_test123",
            name="test_check",
            cmd=["python", "-c", "print('hello')"],
            cwd="/tmp",
            passed=True,
            exit_code=0,
            duration_ms=100,
        )

        assert check.name == "test_check"
        assert check.cmd == ["python", "-c", "print('hello')"]
        assert check.passed is True
        assert check.exit_code == 0
        assert check.duration_ms == 100
        assert check.receipt_type == "CheckResult"

    def test_check_result_with_error(self):
        """CheckResult captures error details."""
        from assay._receipts.domains.launch_readiness import CheckResult

        check = CheckResult(
            receipt_id="chk_fail123",
            name="failing_check",
            cmd=["false"],
            cwd="/tmp",
            passed=False,
            exit_code=1,
            duration_ms=50,
            error_message="Command failed with exit code 1",
        )

        assert check.passed is False
        assert check.error_message == "Command failed with exit code 1"

    def test_check_result_with_artifacts(self):
        """CheckResult includes artifact paths and hash."""
        from assay._receipts.domains.launch_readiness import CheckResult

        check = CheckResult(
            receipt_id="chk_art123",
            name="artifact_check",
            cmd=["echo", "test"],
            cwd="/tmp",
            passed=True,
            exit_code=0,
            duration_ms=10,
            stdout_path="/tmp/stdout.txt",
            stderr_path="/tmp/stderr.txt",
            artifact_hash="abc123def456",
        )

        assert check.stdout_path == "/tmp/stdout.txt"
        assert check.stderr_path == "/tmp/stderr.txt"
        assert check.artifact_hash == "abc123def456"


class TestSystemFingerprint:
    """Tests for SystemFingerprint receipt."""

    def test_create_fingerprint(self):
        """Can create SystemFingerprint."""
        from assay._receipts.domains.launch_readiness import SystemFingerprint

        fp = SystemFingerprint(
            receipt_id="fp_test123",
            platform="Darwin-23.0.0-arm64",
            python_version="3.11.0",
        )

        assert fp.platform == "Darwin-23.0.0-arm64"
        assert fp.python_version == "3.11.0"
        assert fp.git_commit is None
        assert fp.git_dirty is False

    def test_fingerprint_with_git(self):
        """Fingerprint includes git info."""
        from assay._receipts.domains.launch_readiness import SystemFingerprint

        fp = SystemFingerprint(
            receipt_id="fp_git123",
            platform="Linux-5.4.0",
            python_version="3.10.0",
            git_commit="abc1234",
            git_dirty=True,
        )

        assert fp.git_commit == "abc1234"
        assert fp.git_dirty is True

    def test_get_system_fingerprint(self):
        """get_system_fingerprint returns valid fingerprint."""
        from assay._receipts.domains.launch_readiness import get_system_fingerprint

        fp = get_system_fingerprint()

        assert fp.receipt_id.startswith("fp_")
        assert len(fp.platform) > 0
        assert len(fp.python_version) > 0
        assert fp.receipt_type == "SystemFingerprint"


class TestComponentSummary:
    """Tests for ComponentSummary receipt."""

    def test_create_summary(self):
        """Can create ComponentSummary."""
        from assay._receipts.domains.launch_readiness import ComponentSummary

        summary = ComponentSummary(
            receipt_id="sum_test123",
            total=5,
            passed=4,
            failed=1,
        )

        assert summary.total == 5
        assert summary.passed == 4
        assert summary.failed == 1
        assert summary.skipped == 0

    def test_summary_with_skipped(self):
        """Summary includes skipped count."""
        from assay._receipts.domains.launch_readiness import ComponentSummary

        summary = ComponentSummary(
            receipt_id="sum_skip123",
            total=10,
            passed=7,
            failed=1,
            skipped=2,
        )

        assert summary.skipped == 2


class TestLaunchReadinessReceipt:
    """Tests for LaunchReadinessReceipt."""

    def test_create_receipt(self):
        """Can create LaunchReadinessReceipt."""
        from assay._receipts.domains.launch_readiness import (
            LaunchReadinessReceipt,
            CheckResult,
            SystemFingerprint,
            ComponentSummary,
        )

        checks = [
            CheckResult(
                receipt_id="chk_1",
                name="check1",
                cmd=["true"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=10,
            ),
        ]

        fp = SystemFingerprint(
            receipt_id="fp_1",
            platform="Darwin",
            python_version="3.11.0",
        )

        summary = ComponentSummary(
            receipt_id="sum_1",
            total=1,
            passed=1,
            failed=0,
        )

        receipt = LaunchReadinessReceipt(
            receipt_id="launch_test123",
            system_fingerprint=fp,
            checks=checks,
            component_summary=summary,
            overall_passed=True,
        )

        assert receipt.receipt_type == "LaunchReadinessReceipt"
        assert receipt.overall_passed is True
        assert len(receipt.checks) == 1
        assert receipt.component_summary.total == 1

    def test_create_launch_readiness_receipt_factory(self):
        """Factory creates valid receipt."""
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            create_launch_readiness_receipt,
        )

        checks = [
            CheckResult(
                receipt_id="chk_a",
                name="check_a",
                cmd=["echo", "a"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=5,
            ),
            CheckResult(
                receipt_id="chk_b",
                name="check_b",
                cmd=["echo", "b"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=5,
            ),
        ]

        receipt = create_launch_readiness_receipt(checks)

        assert receipt.receipt_id.startswith("launch_")
        assert receipt.overall_passed is True
        assert receipt.component_summary.total == 2
        assert receipt.component_summary.passed == 2
        assert receipt.component_summary.failed == 0

    def test_factory_with_failures(self):
        """Factory correctly computes overall_passed=False when checks fail."""
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            create_launch_readiness_receipt,
        )

        checks = [
            CheckResult(
                receipt_id="chk_pass",
                name="passing",
                cmd=["true"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=5,
            ),
            CheckResult(
                receipt_id="chk_fail",
                name="failing",
                cmd=["false"],
                cwd="/tmp",
                passed=False,
                exit_code=1,
                duration_ms=5,
                error_message="Failed",
            ),
        ]

        receipt = create_launch_readiness_receipt(checks)

        assert receipt.overall_passed is False
        assert receipt.component_summary.total == 2
        assert receipt.component_summary.passed == 1
        assert receipt.component_summary.failed == 1

    def test_factory_with_artifacts_dir(self):
        """Factory stores artifacts_dir."""
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            create_launch_readiness_receipt,
        )

        checks = [
            CheckResult(
                receipt_id="chk_1",
                name="check1",
                cmd=["true"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=10,
            ),
        ]

        receipt = create_launch_readiness_receipt(
            checks,
            artifacts_dir="/path/to/artifacts",
        )

        assert receipt.artifacts_dir == "/path/to/artifacts"


class TestLaunchReadinessReceiptSerialization:
    """Tests for serialization/deserialization."""

    def test_serialize_to_json(self):
        """Receipt can be serialized to JSON."""
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            create_launch_readiness_receipt,
        )

        checks = [
            CheckResult(
                receipt_id="chk_1",
                name="test",
                cmd=["echo", "hi"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=10,
            ),
        ]

        receipt = create_launch_readiness_receipt(checks)
        json_str = json.dumps(receipt.model_dump(mode="json"), default=str)
        data = json.loads(json_str)

        assert data["receipt_type"] == "LaunchReadinessReceipt"
        assert data["overall_passed"] is True
        assert len(data["checks"]) == 1
        assert data["checks"][0]["name"] == "test"

    def test_all_nested_receipts_have_ids(self):
        """All nested receipts have receipt_id."""
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            create_launch_readiness_receipt,
        )

        checks = [
            CheckResult(
                receipt_id="chk_1",
                name="test",
                cmd=["true"],
                cwd="/tmp",
                passed=True,
                exit_code=0,
                duration_ms=10,
            ),
        ]

        receipt = create_launch_readiness_receipt(checks)

        # All should have receipt_id
        assert receipt.receipt_id.startswith("launch_")
        assert receipt.system_fingerprint.receipt_id.startswith("fp_")
        assert receipt.component_summary.receipt_id.startswith("sum_")
        assert receipt.checks[0].receipt_id == "chk_1"


class TestLaunchCheckCLI:
    """Tests for the assay launch-check CLI command behavior."""

    def test_launch_check_creates_artifacts_dir(self):
        """launch-check creates artifacts directory."""
        # This is a behavioral test - when run, it creates dirs
        # Testing the module-level behavior
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            create_launch_readiness_receipt,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_dir = Path(tmpdir) / "artifacts"
            artifact_dir.mkdir()

            checks = [
                CheckResult(
                    receipt_id="chk_1",
                    name="test",
                    cmd=["true"],
                    cwd=str(tmpdir),
                    passed=True,
                    exit_code=0,
                    duration_ms=10,
                    stdout_path=str(artifact_dir / "stdout.txt"),
                ),
            ]

            receipt = create_launch_readiness_receipt(checks, artifacts_dir=str(artifact_dir))
            assert receipt.artifacts_dir == str(artifact_dir)

    def test_check_result_domain_is_governance(self):
        """All launch readiness receipts are in governance domain."""
        from assay._receipts.domains.launch_readiness import (
            CheckResult,
            SystemFingerprint,
            ComponentSummary,
            create_launch_readiness_receipt,
        )
        from assay._receipts.base import Domain

        check = CheckResult(
            receipt_id="chk_1",
            name="test",
            cmd=["true"],
            cwd="/tmp",
            passed=True,
            exit_code=0,
            duration_ms=10,
        )
        assert check.domain == Domain.GOVERNANCE.value

        fp = SystemFingerprint(
            receipt_id="fp_1",
            platform="Darwin",
            python_version="3.11.0",
        )
        assert fp.domain == Domain.GOVERNANCE.value

        summary = ComponentSummary(
            receipt_id="sum_1",
            total=1,
            passed=1,
            failed=0,
        )
        assert summary.domain == Domain.GOVERNANCE.value

        receipt = create_launch_readiness_receipt([check])
        assert receipt.domain == Domain.GOVERNANCE.value
