"""Shell-level integration tests for scripts/assay-gate.sh.

These tests invoke the gate script via subprocess against real compiled
packets, verifying the shell enforcement membrane independently of the
Python verifier tests.

Requires: assay-gate.sh in scripts/, assay CLI installed in the environment.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from assay.compiled_packet import compile_packet, init_packet, verify_packet

SAMPLE_CSV = Path(__file__).resolve().parents[2] / "examples" / "compiled_packet" / "questionnaire.csv"
DEMO_PACK = Path(__file__).resolve().parents[2] / "examples" / "vendorq" / "demo_pack"
GATE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "assay-gate.sh"

TEST_SUBJECT = {
    "subject_type": "artifact",
    "subject_id": "test:gate-shell@v1",
    "subject_digest": "sha256:" + "ab" * 32,
}
TEST_SOURCE_COMMIT = "d1f001ccabc926d7f671c80399b5db1efca25034"


def _run_gate(packet_dir: Path) -> subprocess.CompletedProcess:
    """Run assay-gate.sh against packet_dir. Returns completed process."""
    return subprocess.run(
        ["bash", str(GATE_SCRIPT), str(packet_dir)],
        capture_output=True,
        text=True,
    )


def _make_packet(tmp_path: Path, *, bundle: bool = True, subject: dict | None = None) -> Path:
    """Init + compile a packet into tmp_path. Returns packet dir."""
    draft = tmp_path / "draft"
    init_packet(
        questionnaire_path=SAMPLE_CSV,
        pack_dirs=[DEMO_PACK],
        output_dir=draft,
        from_csv=True,
    )
    output = tmp_path / "packet"
    compile_packet(
        draft_dir=draft,
        pack_dirs=[DEMO_PACK],
        output_dir=output,
        bundle=bundle,
        subject=subject or TEST_SUBJECT,
        source_commit=TEST_SOURCE_COMMIT,
    )
    return output


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not GATE_SCRIPT.exists(), reason="assay-gate.sh not found")
@pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="Demo questionnaire not found")
@pytest.mark.skipif(not DEMO_PACK.exists(), reason="Demo pack not found")
class TestGateShell:

    def test_gate_passes_intact_bundled_packet(self, tmp_path):
        """Gate exits 0 for an INTACT, admissible, bundled packet."""
        packet = _make_packet(tmp_path)
        result = _run_gate(packet)
        assert result.returncode == 0, f"Expected PASS, got exit {result.returncode}:\n{result.stderr}"
        assert "GATE: PASS" in result.stdout

    def test_gate_blocks_non_bundled_packet(self, tmp_path):
        """Gate exits 1 for a non-bundled packet (NOT_SELF_CONTAINED → not admissible)."""
        packet = _make_packet(tmp_path, bundle=False)
        result = _run_gate(packet)
        assert result.returncode == 1, f"Expected BLOCKED, got exit {result.returncode}"
        assert "GATE: BLOCKED" in result.stderr or "GATE: BLOCKED" in result.stdout

    def test_gate_blocks_tampered_manifest(self, tmp_path):
        """Gate exits 1 when subject_digest is mutated in the manifest after signing."""
        packet = _make_packet(tmp_path)
        manifest_path = packet / "packet_manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["subject"]["subject_digest"] = "sha256:" + "cafebabe" * 8
        manifest_path.write_text(json.dumps(manifest, indent=2))

        result = _run_gate(packet)
        assert result.returncode == 1, f"Expected BLOCKED, got exit {result.returncode}"
        assert "GATE: BLOCKED" in result.stderr or "GATE: BLOCKED" in result.stdout

    def test_gate_blocks_tampered_bindings(self, tmp_path):
        """Gate exits 1 when claim_bindings.jsonl is overwritten."""
        packet = _make_packet(tmp_path)
        (packet / "claim_bindings.jsonl").write_text('{"tampered": true}\n')

        result = _run_gate(packet)
        assert result.returncode == 1

    def test_gate_blocks_missing_directory(self, tmp_path):
        """Gate exits 1 when the packet directory does not exist."""
        result = _run_gate(tmp_path / "does_not_exist")
        assert result.returncode == 1
        assert "does not exist" in result.stderr

    def test_gate_blocks_empty_directory(self, tmp_path):
        """Gate exits 1 when the directory exists but contains no manifest."""
        empty = tmp_path / "empty"
        empty.mkdir()
        result = _run_gate(empty)
        assert result.returncode == 1

    def test_gate_blocks_no_argument(self):
        """Gate exits 1 when no packet directory is specified."""
        result = subprocess.run(
            ["bash", str(GATE_SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "no packet directory specified" in result.stderr

    def test_gate_stdout_shows_subject(self, tmp_path):
        """Gate stdout includes the subject identifier on PASS."""
        packet = _make_packet(tmp_path)
        result = _run_gate(packet)
        assert result.returncode == 0
        assert "artifact:test:gate-shell@v1" in result.stdout

    def test_gate_stdout_shows_integrity(self, tmp_path):
        """Gate stdout includes integrity verdict."""
        packet = _make_packet(tmp_path)
        result = _run_gate(packet)
        assert "INTACT" in result.stdout

    def test_gate_stderr_contains_reason_on_block(self, tmp_path):
        """Gate stderr contains a reason line when blocked.

        An empty directory causes the verifier to return INVALID (no manifest).
        The gate should block and print a reason to stderr.
        """
        empty = tmp_path / "empty"
        empty.mkdir()
        result = _run_gate(empty)
        assert result.returncode == 1
        assert "GATE: BLOCKED" in result.stderr
