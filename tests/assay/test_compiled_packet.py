"""Tests for compiled packet: verdict derivation truth table + end-to-end verification."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from assay.compiled_packet import (
    PacketVerifyResult,
    compile_packet,
    derive_top_level_verdict,
    init_packet,
    questionnaire_from_csv,
    verify_packet,
)


# ---------------------------------------------------------------------------
# Truth table: derive_top_level_verdict
# Per PACKET_SEMANTICS_V1.md §3.4
# ---------------------------------------------------------------------------

class TestDeriveTopLevelVerdict:
    """Exhaustive truth table for verdict derivation.

    Every cell in the integrity x completeness cross-product is tested.
    """

    @pytest.mark.parametrize(
        "integrity,completeness,expected",
        [
            # INVALID dominates everything
            ("INVALID", "COMPLETE", "INVALID"),
            ("INVALID", "PARTIAL", "INVALID"),
            ("INVALID", "INCOMPLETE", "INVALID"),
            # TAMPERED dominates completeness
            ("TAMPERED", "COMPLETE", "TAMPERED"),
            ("TAMPERED", "PARTIAL", "TAMPERED"),
            ("TAMPERED", "INCOMPLETE", "TAMPERED"),
            # DEGRADED dominates completeness
            ("DEGRADED", "COMPLETE", "DEGRADED"),
            ("DEGRADED", "PARTIAL", "DEGRADED"),
            ("DEGRADED", "INCOMPLETE", "DEGRADED"),
            # INTACT: completeness determines top-level
            ("INTACT", "COMPLETE", "PASS"),
            ("INTACT", "PARTIAL", "PARTIAL"),
            ("INTACT", "INCOMPLETE", "PARTIAL"),
        ],
    )
    def test_truth_table(self, integrity, completeness, expected):
        assert derive_top_level_verdict(integrity, completeness) == expected

    def test_result_verdict_property_delegates(self):
        """PacketVerifyResult.verdict should use derive_top_level_verdict."""
        r = PacketVerifyResult(integrity_verdict="DEGRADED", completeness_verdict="COMPLETE")
        assert r.verdict == "DEGRADED"

    def test_result_to_dict_includes_both_axes(self):
        """Machine-readable output includes both axis verdicts."""
        r = PacketVerifyResult(
            integrity_verdict="INTACT",
            completeness_verdict="PARTIAL",
            packet_id="test",
        )
        d = r.to_dict()
        assert d["integrity_verdict"] == "INTACT"
        assert d["completeness_verdict"] == "PARTIAL"
        assert d["verdict"] == "PARTIAL"


# ---------------------------------------------------------------------------
# End-to-end: init → compile → verify
# ---------------------------------------------------------------------------

SAMPLE_CSV = Path(__file__).resolve().parents[2] / "examples" / "vendorq" / "sample_questionnaire.csv"
DEMO_PACK = Path(__file__).resolve().parents[2] / "examples" / "vendorq" / "demo_pack"


@pytest.fixture
def tmp_workdir(tmp_path):
    return tmp_path


@pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="Demo questionnaire not found")
@pytest.mark.skipif(not DEMO_PACK.exists(), reason="Demo pack not found")
class TestEndToEnd:

    def test_init_creates_stubs(self, tmp_workdir):
        result = init_packet(
            questionnaire_path=SAMPLE_CSV,
            pack_dirs=[DEMO_PACK],
            output_dir=tmp_workdir / "draft",
            from_csv=True,
        )
        assert result["questionnaire_items"] == 6
        assert result["stub_bindings"] == 6
        assert (tmp_workdir / "draft" / "claim_bindings.jsonl").exists()
        assert (tmp_workdir / "draft" / "questionnaire_import.json").exists()

    def test_compile_and_verify_round_trip(self, tmp_workdir):
        """Init with stubs → compile → verify. All UNSUPPORTED = INTACT + PARTIAL."""
        draft = tmp_workdir / "draft"
        init_packet(
            questionnaire_path=SAMPLE_CSV,
            pack_dirs=[DEMO_PACK],
            output_dir=draft,
            from_csv=True,
        )

        output = tmp_workdir / "packet"
        compile_packet(
            draft_dir=draft,
            pack_dirs=[DEMO_PACK],
            output_dir=output,
            bundle=True,
        )

        result = verify_packet(output)
        assert result.integrity_verdict == "INTACT"
        assert result.completeness_verdict == "PARTIAL"  # all stubs are UNSUPPORTED
        assert result.verdict == "PARTIAL"
        assert not result.errors

    def test_tamper_binding_yields_tampered(self, tmp_workdir):
        draft = tmp_workdir / "draft"
        init_packet(
            questionnaire_path=SAMPLE_CSV,
            pack_dirs=[DEMO_PACK],
            output_dir=draft,
            from_csv=True,
        )
        output = tmp_workdir / "packet"
        compile_packet(
            draft_dir=draft,
            pack_dirs=[DEMO_PACK],
            output_dir=output,
            bundle=True,
        )

        # Tamper: modify bindings after signing
        bindings_path = output / "claim_bindings.jsonl"
        bindings_path.write_text("tampered content\n")

        result = verify_packet(output)
        assert result.integrity_verdict == "TAMPERED"
        assert result.verdict == "TAMPERED"

    def test_missing_pack_yields_degraded(self, tmp_workdir):
        draft = tmp_workdir / "draft"
        init_packet(
            questionnaire_path=SAMPLE_CSV,
            pack_dirs=[DEMO_PACK],
            output_dir=draft,
            from_csv=True,
        )
        output = tmp_workdir / "packet"
        compile_packet(
            draft_dir=draft,
            pack_dirs=[DEMO_PACK],
            output_dir=output,
            bundle=True,
        )

        # Remove bundled pack
        packs_dir = output / "packs"
        shutil.rmtree(packs_dir)

        result = verify_packet(output)
        assert result.integrity_verdict == "DEGRADED"
        assert result.verdict == "DEGRADED"

    def test_broken_signature_yields_tampered(self, tmp_workdir):
        draft = tmp_workdir / "draft"
        init_packet(
            questionnaire_path=SAMPLE_CSV,
            pack_dirs=[DEMO_PACK],
            output_dir=draft,
            from_csv=True,
        )
        output = tmp_workdir / "packet"
        compile_packet(
            draft_dir=draft,
            pack_dirs=[DEMO_PACK],
            output_dir=output,
            bundle=True,
        )

        # Break detached signature
        (output / "packet_signature.sig").write_bytes(b"broken")

        result = verify_packet(output)
        assert result.integrity_verdict == "TAMPERED"
        assert result.verdict == "TAMPERED"

    def test_corrupted_nested_receipt_yields_degraded(self, tmp_workdir):
        draft = tmp_workdir / "draft"
        init_packet(
            questionnaire_path=SAMPLE_CSV,
            pack_dirs=[DEMO_PACK],
            output_dir=draft,
            from_csv=True,
        )
        output = tmp_workdir / "packet"
        compile_packet(
            draft_dir=draft,
            pack_dirs=[DEMO_PACK],
            output_dir=output,
            bundle=True,
        )

        # Find and corrupt the nested receipt
        pack_dirs = list((output / "packs").iterdir())
        assert pack_dirs, "Expected at least one bundled pack"
        receipt_path = pack_dirs[0] / "receipt_pack.jsonl"
        receipt_path.write_text('{"tampered": true}\n')

        result = verify_packet(output)
        assert result.integrity_verdict == "DEGRADED"
        assert result.verdict == "DEGRADED"

    def test_missing_manifest_yields_invalid(self, tmp_workdir):
        result = verify_packet(tmp_workdir)
        assert result.integrity_verdict == "INVALID"
        assert result.verdict == "INVALID"


# ---------------------------------------------------------------------------
# Questionnaire CSV conversion
# ---------------------------------------------------------------------------

class TestQuestionnaireCSV:

    def test_csv_to_json(self):
        if not SAMPLE_CSV.exists():
            pytest.skip("Demo CSV not found")
        q = questionnaire_from_csv(SAMPLE_CSV)
        assert q["schema_version"] == "vendorq.question.v1"
        assert len(q["questions"]) == 6
        assert q["questions"][0]["question_id"] == "Q1"
