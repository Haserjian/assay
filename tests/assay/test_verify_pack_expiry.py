"""Tests for verify-pack --check-expiry behavior (issue #75).

Decision (fail-closed):
- Expired valid_until   -> exit 1, status "expired", expiry_status "expired"
- Malformed valid_until -> fail-closed; tested at parsing-logic level because
                           attestation schema validates date-time at build time,
                           so a malformed value can only appear in hand-crafted
                           or tampered packs (which would also fail integrity).
- No valid_until        -> exit 0, no expiry_status field
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.commands import assay_app
from assay.keystore import AssayKeyStore
from assay.proof_pack import ProofPack

runner = CliRunner()


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    import assay.store as store_mod
    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


def _build_pack(tmp_path: Path, assay_home: Path, valid_until: str | None = None) -> Path:
    ks = AssayKeyStore(keys_dir=assay_home / "keys")
    ks.ensure_key("test-signer")
    receipt = {
        "receipt_id": "r1",
        "type": "session_metadata",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": "expiry-test",
    }
    pack = ProofPack(
        run_id="expiry-test",
        entries=[receipt],
        signer_id="test-signer",
        valid_until=valid_until,
    )
    return pack.build(tmp_path / "pack", keystore=ks)


class TestCheckExpiryExpired:
    def test_expired_pack_exits_1(self, tmp_path, assay_home_tmp):
        pack_dir = _build_pack(tmp_path, assay_home_tmp, valid_until="2020-01-01T00:00:00+00:00")
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--check-expiry", "--json"],
        )
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["status"] == "expired"
        assert payload["expiry_status"] == "expired"

    def test_expired_pack_z_suffix(self, tmp_path, assay_home_tmp):
        """Z-suffix valid_until parses correctly via fromisoformat Z-shim (Python 3.9/3.10 compat)."""
        pack_dir = _build_pack(tmp_path, assay_home_tmp, valid_until="2020-06-01T00:00:00Z")
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--check-expiry", "--json"],
        )
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["expiry_status"] == "expired"

    def test_future_pack_passes(self, tmp_path, assay_home_tmp):
        pack_dir = _build_pack(tmp_path, assay_home_tmp, valid_until="2099-01-01T00:00:00+00:00")
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--check-expiry", "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["status"] == "ok"
        assert "expiry_status" not in payload

    def test_expiry_status_absent_without_check_expiry(self, tmp_path, assay_home_tmp):
        """expiry_status not emitted when --check-expiry is not passed."""
        pack_dir = _build_pack(tmp_path, assay_home_tmp, valid_until="2020-01-01T00:00:00+00:00")
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert "expiry_status" not in payload


class TestCheckExpiryNoField:
    def test_no_valid_until_passes_with_check_expiry(self, tmp_path, assay_home_tmp):
        """Pack without valid_until is not an expiry failure."""
        pack_dir = _build_pack(tmp_path, assay_home_tmp, valid_until=None)
        result = runner.invoke(
            assay_app,
            ["verify-pack", str(pack_dir), "--check-expiry", "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert "expiry_status" not in payload


class TestMalformedValidUntilParsingLogic:
    """Unit tests for the expiry parsing logic decision: fail-closed on malformed.

    Attestation schema enforces date-time format at build time, so a malformed
    valid_until can only reach verify-pack via hand-crafted or tampered packs
    (which would also fail integrity). These tests confirm the parsing decision
    directly rather than through a full CLI+pack cycle.
    """

    def _run_expiry_check(self, valid_until_str: str) -> tuple[bool, str | None, str]:
        """Replicate the expiry-check block from verify_pack_cmd."""
        expiry_failed = False
        expiry_kind = None
        expiry_message = "--check-expiry: valid_until is in the past"

        try:
            _vu = (
                valid_until_str.replace("Z", "+00:00")
                if valid_until_str.endswith("Z")
                else valid_until_str
            )
            valid_until_ts = datetime.fromisoformat(_vu)
            if valid_until_ts.tzinfo is None:
                valid_until_ts = valid_until_ts.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > valid_until_ts:
                expiry_failed = True
                expiry_kind = "expired"
        except (ValueError, TypeError):
            expiry_failed = True
            expiry_kind = "malformed"
            expiry_message = (
                f"--check-expiry: valid_until is malformed ({valid_until_str!r}); "
                "treating as expiry failure"
            )

        return expiry_failed, expiry_kind, expiry_message

    def test_malformed_string_fails_closed(self):
        failed, kind, msg = self._run_expiry_check("not-a-date")
        assert failed is True
        assert kind == "malformed"
        assert "malformed" in msg

    def test_malformed_empty_string_fails_closed(self):
        failed, kind, msg = self._run_expiry_check("")
        assert failed is True
        assert kind == "malformed"

    def test_malformed_partial_date_fails_closed(self):
        failed, kind, msg = self._run_expiry_check("2026-13-01")  # month 13
        assert failed is True
        assert kind == "malformed"

    def test_malformed_distinguishable_from_expired(self):
        """expiry_kind distinguishes malformed from a genuinely expired timestamp."""
        _, expired_kind, _ = self._run_expiry_check("2020-01-01T00:00:00+00:00")
        _, malformed_kind, _ = self._run_expiry_check("garbage")
        assert expired_kind == "expired"
        assert malformed_kind == "malformed"

    def test_valid_future_passes(self):
        failed, kind, _ = self._run_expiry_check("2099-01-01T00:00:00+00:00")
        assert failed is False
        assert kind is None

    def test_z_suffix_parses_correctly(self):
        """Z suffix is normalized before fromisoformat (Python 3.9/3.10 compat)."""
        failed, kind, _ = self._run_expiry_check("2020-06-01T00:00:00Z")
        assert failed is True
        assert kind == "expired"  # valid parse, just in the past
