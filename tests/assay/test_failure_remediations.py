"""Tests for high-friction failure remediation messages (Stage 1 PR3)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack


runner = CliRunner()


def _build_valid_pack(tmp_path: Path) -> Path:
    """Build a minimal valid pack for verify-pack command tests."""
    ks = AssayKeyStore(keys_dir=tmp_path / "keys")
    ks.generate_key("test-signer")

    entries = [
        {
            "receipt_id": "r_1",
            "type": "model_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": "3.0",
            "seq": 0,
        }
    ]

    pack = ProofPack(
        run_id="remediation-test",
        entries=entries,
        signer_id="test-signer",
        claims=[],
        mode="shadow",
    )
    return pack.build(tmp_path / "pack", keystore=ks)


class TestRunRemediations:
    def test_no_command_shows_copy_paste_fixes(self) -> None:
        result = runner.invoke(assay_app, ["run"])
        assert result.exit_code == 1
        assert "No command provided" in result.output
        assert "assay run -- python app.py" in result.output
        assert "assay doctor" in result.output

    def test_no_command_json_has_fixes(self) -> None:
        result = runner.invoke(assay_app, ["run", "--json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["error"] == "no_command_provided"
        assert "assay run -- python app.py" in data["fixes"]

    def test_no_receipts_includes_rerun_hint(self) -> None:
        result = runner.invoke(assay_app, ["run", "--", "python", "-c", "print('ok')"])
        assert result.exit_code == 1
        assert "No receipts emitted during run" in result.output
        assert "assay scan . --report" in result.output
        assert "Then re-run" in result.output


class TestVerifyPackLockRemediations:
    def test_missing_lock_shows_fix_commands(self, tmp_path: Path) -> None:
        pack_dir = _build_valid_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--lock", "missing.lock"],
        )
        assert result.exit_code == 2
        assert "Lock file not found" in result.output
        assert "assay lock init" in result.output

    def test_missing_lock_json_uses_exit_2_and_fixes(self, tmp_path: Path) -> None:
        pack_dir = _build_valid_pack(tmp_path)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--lock", "missing.lock", "--json"],
        )
        assert result.exit_code == 2
        data = json.loads(result.output)
        assert data["error"] == "lock_file_not_found"
        assert "assay lock init" in data["fixes"][0]


class TestDiffAndMcpRemediations:
    def test_against_previous_no_baseline_shows_next_steps(self, tmp_path: Path) -> None:
        only = tmp_path / "proof_pack_only"
        only.mkdir()
        (only / "pack_manifest.json").write_text("{}")
        result = runner.invoke(assay_app, ["diff", str(only), "--against-previous"])
        assert result.exit_code == 3
        assert "No baseline found" in result.output
        assert "baseline set" in result.output

    def test_mcp_proxy_no_upstream_shows_fixes(self) -> None:
        result = runner.invoke(assay_app, ["mcp-proxy"])
        assert result.exit_code == 3
        assert "No server command provided" in result.output
        assert "assay mcp-proxy -- python my_server.py" in result.output

    def test_mcp_proxy_no_upstream_json_has_fixes(self) -> None:
        result = runner.invoke(assay_app, ["mcp-proxy", "--json"])
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["error"] == "no_server_command_provided"
        assert "assay mcp-proxy -- python my_server.py" in data["fixes"][0]
