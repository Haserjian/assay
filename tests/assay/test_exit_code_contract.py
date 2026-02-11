"""Exit-code truth table: assert the advertised contract.

The exit codes are a public API:
  0 = integrity PASS (+ claim gate PASS if --require-claim-pass)
  1 = claim gate failed (integrity PASS but claims not PASS)
  2 = integrity FAIL (tampered evidence)

These are the exact exit codes documented in every post, the HTML report,
and the README. If they break, the launch messaging is a lie.
"""
from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.claim_verifier import ClaimSpec
from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_receipt(**overrides):
    base = {
        "receipt_id": f"r_{uuid.uuid4().hex[:8]}",
        "type": "model_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": "3.0",
    }
    base.update(overrides)
    return base


def _build_pack(
    tmp_path: Path,
    receipts: list | None = None,
    claims: list | None = None,
    signer_id: str = "exit-code-signer",
) -> tuple[Path, AssayKeyStore]:
    """Build a valid proof pack and return (pack_dir, keystore)."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key(signer_id)

    if receipts is None:
        receipts = [_make_receipt(seq=i) for i in range(3)]

    pack = ProofPack(
        run_id="exit-code-test",
        entries=receipts,
        signer_id=signer_id,
        claims=claims or [],
        mode="shadow",
    )
    out = pack.build(tmp_path / "pack", keystore=ks)
    return out, ks


def _tamper_receipts(pack_dir: Path):
    """Modify a receipt value in receipt_pack.jsonl (preserves JSON validity)."""
    receipt_file = pack_dir / "receipt_pack.jsonl"
    lines = receipt_file.read_text().strip().split("\n")
    if lines:
        obj = json.loads(lines[0])
        obj["receipt_id"] = "r_tampered_999"  # change a value
        lines[0] = json.dumps(obj)
    receipt_file.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Exit code 0: everything passes
# ---------------------------------------------------------------------------

class TestExitCode0:
    """Exit 0 = integrity PASS, claims PASS (or no claim gate)."""

    def test_valid_pack_exits_0(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 0, f"Expected 0, got {result.exit_code}\n{result.output}"

    def test_valid_pack_json_exits_0(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["status"] == "ok"

    def test_valid_pack_with_passing_claims_and_require_claim_pass_exits_0(self, tmp_path):
        """Claims PASS + --require-claim-pass => exit 0."""
        claims = [
            ClaimSpec(
                claim_id="has_model_calls",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        pack_dir, ks = _build_pack(tmp_path, claims=claims)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--require-claim-pass"],
        )
        assert result.exit_code == 0, f"Expected 0, got {result.exit_code}\n{result.output}"


# ---------------------------------------------------------------------------
# Exit code 2: integrity failure
# ---------------------------------------------------------------------------

class TestExitCode2:
    """Exit 2 = tampered evidence (integrity FAIL)."""

    def test_tampered_receipts_exits_2(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        _tamper_receipts(pack_dir)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 2, f"Expected 2, got {result.exit_code}\n{result.output}"

    def test_tampered_receipts_json_exits_2(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        _tamper_receipts(pack_dir)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir), "--json"])
        assert result.exit_code == 2
        payload = json.loads(result.output)
        assert payload["status"] == "failed"

    def test_deleted_signature_exits_2(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        (pack_dir / "pack_signature.sig").unlink()
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 2, f"Expected 2, got {result.exit_code}\n{result.output}"

    def test_corrupt_manifest_exits_2(self, tmp_path):
        pack_dir, ks = _build_pack(tmp_path)
        manifest_path = pack_dir / "pack_manifest.json"
        data = json.loads(manifest_path.read_text())
        data["receipt_count_expected"] = 999
        manifest_path.write_text(json.dumps(data))
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 2, f"Expected 2, got {result.exit_code}\n{result.output}"


# ---------------------------------------------------------------------------
# Exit code 1: claim gate failure
# ---------------------------------------------------------------------------

class TestExitCode1:
    """Exit 1 = integrity PASS but claim gate failed."""

    def test_no_manifest_exits_1(self, tmp_path):
        """Missing pack_manifest.json -> exit 1 (error, not tampering)."""
        empty_dir = tmp_path / "empty_pack"
        empty_dir.mkdir()
        result = runner.invoke(assay_app, ["verify-pack", str(empty_dir)])
        assert result.exit_code == 1

    def test_failing_claims_with_require_claim_pass_exits_1(self, tmp_path):
        """Claims FAIL + --require-claim-pass => exit 1."""
        # Create a claim that will fail: require guardian_verdict but only
        # provide model_call receipts
        claims = [
            ClaimSpec(
                claim_id="needs_guardian",
                description="Guardian verdict must be present",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]
        receipts = [_make_receipt(seq=0)]  # model_call only, no guardian_verdict
        pack_dir, ks = _build_pack(tmp_path, receipts=receipts, claims=claims)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--require-claim-pass"],
        )
        assert result.exit_code == 1, f"Expected 1, got {result.exit_code}\n{result.output}"

    def test_failing_claims_without_flag_exits_0(self, tmp_path):
        """Claims FAIL but no --require-claim-pass => exit 0 (integrity passed)."""
        claims = [
            ClaimSpec(
                claim_id="needs_guardian",
                description="Guardian verdict must be present",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]
        receipts = [_make_receipt(seq=0)]
        pack_dir, ks = _build_pack(tmp_path, receipts=receipts, claims=claims)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 0, (
            f"Without --require-claim-pass, failing claims should not affect "
            f"exit code. Got {result.exit_code}\n{result.output}"
        )


# ---------------------------------------------------------------------------
# Truth table: all combinations
# ---------------------------------------------------------------------------

class TestTruthTable:
    """Exhaustive truth table matching the README and post messaging."""

    def test_integrity_pass_no_claim_gate(self, tmp_path):
        """PASS/N/A -> 0"""
        pack_dir, ks = _build_pack(tmp_path)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 0

    def test_integrity_pass_claims_pass(self, tmp_path):
        """PASS/PASS -> 0"""
        claims = [
            ClaimSpec(
                claim_id="has_model_calls",
                description="model_call present",
                check="receipt_type_present",
                params={"receipt_type": "model_call"},
            ),
        ]
        pack_dir, ks = _build_pack(tmp_path, claims=claims)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--require-claim-pass"],
        )
        assert result.exit_code == 0

    def test_integrity_pass_claims_fail(self, tmp_path):
        """PASS/FAIL + --require-claim-pass -> 1"""
        claims = [
            ClaimSpec(
                claim_id="needs_guardian",
                description="Guardian verdict must be present",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]
        pack_dir, ks = _build_pack(tmp_path, receipts=[_make_receipt()], claims=claims)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--require-claim-pass"],
        )
        assert result.exit_code == 1

    def test_integrity_fail(self, tmp_path):
        """FAIL/-- -> 2"""
        pack_dir, ks = _build_pack(tmp_path)
        _tamper_receipts(pack_dir)
        result = runner.invoke(assay_app, ["verify-pack", str(pack_dir)])
        assert result.exit_code == 2

    def test_integrity_fail_trumps_claim_gate(self, tmp_path):
        """FAIL takes precedence over claim gate -> 2, not 1."""
        claims = [
            ClaimSpec(
                claim_id="needs_guardian",
                description="Guardian verdict must be present",
                check="receipt_type_present",
                params={"receipt_type": "guardian_verdict"},
            ),
        ]
        pack_dir, ks = _build_pack(tmp_path, receipts=[_make_receipt()], claims=claims)
        _tamper_receipts(pack_dir)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--require-claim-pass"],
        )
        assert result.exit_code == 2, (
            f"Integrity failure should always be exit 2, even with "
            f"--require-claim-pass. Got {result.exit_code}"
        )

    def test_json_output_contains_status_field(self, tmp_path):
        """JSON output must include status for all exit codes."""
        pack_dir, ks = _build_pack(tmp_path)

        # Exit 0
        r0 = runner.invoke(assay_app, ["verify-pack", str(pack_dir), "--json"])
        assert "status" in json.loads(r0.output)

        # Exit 2
        _tamper_receipts(pack_dir)
        r2 = runner.invoke(assay_app, ["verify-pack", str(pack_dir), "--json"])
        assert "status" in json.loads(r2.output)
