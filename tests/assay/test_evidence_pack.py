"""
Tests for Evidence Pack generator.
"""
import json
import hashlib
import tempfile
import zipfile
from pathlib import Path

import pytest


class TestMerkleRoot:
    """Tests for Merkle root generation."""

    def test_get_merkle_root_empty(self):
        """Empty entries return null root."""
        from assay.evidence_pack import get_merkle_root

        result = get_merkle_root([])
        assert result["root"] is None
        assert result["leaf_count"] == 0
        assert result["hash_algorithm"] == "sha256"
        assert result["canonicalization"] == "jcs-rfc8785"

    def test_get_merkle_root_with_entries(self):
        """Entries produce valid merkle root."""
        from assay.evidence_pack import get_merkle_root
        from assay._receipts.canonicalize import to_jcs_bytes
        from assay._receipts.merkle import compute_merkle_root

        entries = [
            {"type": "test", "value": 1},
            {"type": "test", "value": 2},
        ]
        result = get_merkle_root(entries)

        leaf_hashes = [
            hashlib.sha256(to_jcs_bytes(entry)).hexdigest()
            for entry in entries
        ]
        expected_root = compute_merkle_root(leaf_hashes)

        assert result["root"] == expected_root
        assert result["leaf_count"] == 2
        assert len(result["leaf_hashes"]) == 2
        assert result["hash_algorithm"] == "sha256"
        assert result["canonicalization"] == "jcs-rfc8785"
        assert "computed_at" in result


class TestClaimMap:
    """Tests for patent claim mapping."""

    def test_claim_map_structure(self):
        """CLAIM_MAP has expected structure."""
        from assay.evidence_pack import CLAIM_MAP

        assert "claim_1" in CLAIM_MAP
        assert "claim_14" in CLAIM_MAP
        assert "claim_15" in CLAIM_MAP
        assert "claim_17" in CLAIM_MAP

        # Each claim should have required fields
        for claim_id, claim in CLAIM_MAP.items():
            assert "title" in claim
            assert "description" in claim
            assert "implementation" in claim
            assert "tests" in claim
            assert "invariants" in claim

    def test_claim_1_model_call(self):
        """Claim 1 maps to ModelCallReceipt."""
        from assay.evidence_pack import CLAIM_MAP

        claim = CLAIM_MAP["claim_1"]
        assert "Audit trail" in claim["title"]
        impl = claim["implementation"][0]
        assert "model_call.py" in impl["file"]
        assert impl["class"] == "ModelCallReceipt"

    def test_claim_14_dignity_floor(self):
        """Claim 14 maps to dignity floor enforcement."""
        from assay.evidence_pack import CLAIM_MAP

        claim = CLAIM_MAP["claim_14"]
        assert "Dignity floor" in claim["title"]
        impl = claim["implementation"][0]
        assert "dignity_budget.py" in impl["file"]


class TestBuildMetadata:
    """Tests for build metadata generation."""

    def test_get_build_metadata(self):
        """Build metadata includes required fields."""
        from assay.evidence_pack import get_build_metadata

        meta = get_build_metadata()

        assert "assay_version" in meta
        assert "python_version" in meta
        assert "platform" in meta
        assert "generated_at" in meta
        assert "generator" in meta
        assert meta["generator"] == "assay evidence-pack"
        assert meta["canonicalization"] == "jcs-rfc8785"
        assert meta["hash_algorithm"] == "sha256"


class TestGenerateReadme:
    """Tests for README generation."""

    def test_generate_readme_passed(self):
        """README for passed verification."""
        from assay.evidence_pack import generate_readme

        readme = generate_readme(
            trace_id="trace_test123",
            entry_count=5,
            merkle_root="abc123",
            verify_passed=True,
            build_meta={"generated_at": "2025-02-05T12:00:00Z", "assay_version": "0.1.0"},
        )

        assert "trace_test123" in readme
        assert "5 entries" in readme
        assert "abc123" in readme
        assert "**PASSED**" in readme
        assert "patent defense" in readme.lower()

    def test_generate_readme_failed(self):
        """README for failed verification."""
        from assay.evidence_pack import generate_readme

        readme = generate_readme(
            trace_id="trace_test",
            entry_count=3,
            merkle_root="xyz789",
            verify_passed=False,
            build_meta={"generated_at": "2025-02-05T12:00:00Z", "assay_version": "0.1.0"},
        )

        assert "**FAILED**" in readme


class TestEvidencePack:
    """Tests for EvidencePack class."""

    def test_create_evidence_pack_class(self):
        """Can create EvidencePack instance."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        assert pack.trace_id == "trace_test"
        assert pack.entries == []
        assert pack.verify_errors == []

    def test_verify_empty_trace(self):
        """Empty trace fails verification."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        passed = pack.verify()

        assert passed is False
        assert "empty" in pack.verify_errors[0].lower()

    def test_verify_valid_entries(self):
        """Valid entries pass verification."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test", "receipt_id": "r1", "_stored_at": "2025-02-05T12:00:00Z"},
            {"type": "test", "receipt_id": "r2", "_stored_at": "2025-02-05T12:00:01Z"},
        ]

        passed = pack.verify()
        assert passed is True
        assert len(pack.verify_errors) == 0

    def test_verify_detects_missing_type(self):
        """Missing type is detected."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"receipt_id": "r1"},  # Missing type
        ]

        passed = pack.verify()
        assert passed is False
        assert any("missing type" in e for e in pack.verify_errors)

    def test_verify_detects_duplicate_ids(self):
        """Duplicate receipt IDs are detected."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test", "receipt_id": "r1"},
            {"type": "test", "receipt_id": "r1"},  # Duplicate
        ]

        passed = pack.verify()
        assert passed is False
        assert any("duplicate" in e for e in pack.verify_errors)

    def test_verify_detects_temporal_violation(self):
        """Temporal ordering violation is detected."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test", "receipt_id": "r1", "_stored_at": "2025-02-05T12:00:01Z"},
            {"type": "test", "receipt_id": "r2", "_stored_at": "2025-02-05T12:00:00Z"},  # Goes backwards
        ]

        passed = pack.verify()
        assert passed is False
        assert any("temporal" in e for e in pack.verify_errors)

    def test_verify_handles_timezone_offsets(self):
        """Timestamps with different timezone offsets are compared correctly."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        # These are the same instant, just different representations
        pack.entries = [
            {"type": "test", "receipt_id": "r1", "_stored_at": "2025-02-05T12:00:00+00:00"},
            {"type": "test", "receipt_id": "r2", "_stored_at": "2025-02-05T13:00:00+01:00"},  # Same instant as above
            {"type": "test", "receipt_id": "r3", "_stored_at": "2025-02-05T14:00:00+00:00"},  # Later
        ]

        passed = pack.verify()
        assert passed is True  # No violation, correctly ordered

    def test_verify_warns_on_missing_receipt_id(self):
        """Missing receipt_id generates warning by default."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test"},  # Missing receipt_id
        ]

        passed = pack.verify()
        assert passed is True  # Still passes
        assert any("missing receipt_id" in w for w in pack.verify_warnings)

    def test_verify_errors_on_missing_receipt_id_when_required(self):
        """Missing receipt_id is error when require_receipt_id=True."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test"},  # Missing receipt_id
        ]

        passed = pack.verify(require_receipt_id=True)
        assert passed is False
        assert any("missing receipt_id" in e for e in pack.verify_errors)

    def test_get_verify_report(self):
        """Verify report includes all fields."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [{"type": "test", "receipt_id": "r1"}]

        report = pack.get_verify_report()

        assert report["trace_id"] == "trace_test"
        assert report["passed"] is True
        assert report["entry_count"] == 1
        assert "errors" in report
        assert "warnings" in report
        assert "verified_at" in report

    def test_get_merkle(self):
        """Merkle root is computed."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [{"type": "test", "value": 1}]

        merkle = pack.get_merkle()

        assert merkle["root"] is not None
        assert merkle["leaf_count"] == 1

    def test_export_zip(self):
        """Can export evidence pack as zip."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test", "receipt_id": "r1", "value": 1},
            {"type": "test", "receipt_id": "r2", "value": 2},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_pack.zip"
            result = pack.export_zip(output_path)

            assert result.exists()
            assert result == output_path

            # Verify zip contents
            with zipfile.ZipFile(result, "r") as zf:
                names = zf.namelist()
                assert "trace.jsonl" in names
                assert "verify_report.json" in names
                assert "merkle_root.json" in names
                assert "claim_map.json" in names
                assert "build_metadata.json" in names
                assert "README.md" in names

                # Verify trace.jsonl content
                trace_content = zf.read("trace.jsonl").decode("utf-8")
                lines = [line for line in trace_content.split("\n") if line.strip()]
                assert len(lines) == 2

                # Verify verify_report.json content
                verify_content = json.loads(zf.read("verify_report.json"))
                assert verify_content["trace_id"] == "trace_test"
                assert verify_content["passed"] is True

                # Verify merkle_root.json content
                merkle_content = json.loads(zf.read("merkle_root.json"))
                assert merkle_content["leaf_count"] == 2

    def test_export_zip_with_source(self):
        """Export with source files flag works."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [{"type": "test", "receipt_id": "r1"}]

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_pack_with_source.zip"
            result = pack.export_zip(output_path, include_source=True)

            assert result.exists()

            # Source files are only included if they exist
            with zipfile.ZipFile(result, "r") as zf:
                names = zf.namelist()
                # Core files should always be there
                assert "trace.jsonl" in names
                assert "README.md" in names

    def test_export_zip_forensic_mode(self):
        """Forensic mode preserves raw trace bytes."""
        from assay.evidence_pack import EvidencePack

        # Simulate raw bytes with specific formatting
        raw_bytes = b'{"type":"test","receipt_id":"r1","value":1}\n{"type":"test","receipt_id":"r2","value":2}\n'

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test", "receipt_id": "r1", "value": 1},
            {"type": "test", "receipt_id": "r2", "value": 2},
        ]
        pack.raw_trace_bytes = raw_bytes

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_forensic.zip"
            result = pack.export_zip(output_path)

            with zipfile.ZipFile(result, "r") as zf:
                # Trace should be exactly the raw bytes
                trace_content = zf.read("trace.jsonl")
                assert trace_content == raw_bytes

                # Metadata should indicate forensic mode
                build_meta = json.loads(zf.read("build_metadata.json"))
                assert build_meta["forensic_mode"] is True

    def test_export_zip_canonicalized_mode(self):
        """Default mode re-serializes (canonicalizes) entries."""
        from assay.evidence_pack import EvidencePack

        pack = EvidencePack(trace_id="trace_test")
        pack.entries = [
            {"type": "test", "receipt_id": "r1", "value": 1},
        ]
        # No raw_trace_bytes set

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_canonical.zip"
            result = pack.export_zip(output_path)

            with zipfile.ZipFile(result, "r") as zf:
                # Metadata should indicate non-forensic mode
                build_meta = json.loads(zf.read("build_metadata.json"))
                assert build_meta["forensic_mode"] is False


class TestCreateEvidencePack:
    """Tests for the create_evidence_pack factory function."""

    def test_create_evidence_pack_not_found(self):
        """Raises error when trace not found."""
        from assay.evidence_pack import create_evidence_pack

        with pytest.raises(ValueError, match="not found"):
            create_evidence_pack("nonexistent_trace_id")
