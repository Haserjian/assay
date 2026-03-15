"""Tests for passport challenge/supersede/revoke lifecycle."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assay.keystore import AssayKeyStore
from assay.passport_lifecycle import (
    compute_passport_state,
    create_demo_challenge_receipt,
    create_demo_revocation_receipt,
    create_demo_supersession_receipt,
)
from assay.passport_mint import mint_passport_draft


@pytest.fixture
def assay_home_tmp(tmp_path: Path, monkeypatch) -> Path:
    import assay.store as store_mod

    home = tmp_path / ".assay"
    monkeypatch.setattr(store_mod, "assay_home", lambda: home)
    monkeypatch.setattr(store_mod, "_default_store", None)
    monkeypatch.setattr(store_mod, "_seq_counter", 0)
    monkeypatch.setattr(store_mod, "_seq_trace_id", None)
    return home


@pytest.fixture
def keystore(assay_home_tmp: Path) -> AssayKeyStore:
    ks = AssayKeyStore(keys_dir=assay_home_tmp / "keys")
    ks.generate_key("assay-local")
    return ks


def _mint_and_sign(tmp_path: Path, ks: AssayKeyStore, name: str = "passport.json") -> Path:
    passport = mint_passport_draft(
        subject_name="TestApp",
        subject_system_id="test.v1",
        subject_owner="Test Inc.",
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / name
    path.write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")

    from assay.passport_sign import sign_passport
    sign_passport(path, keystore=ks)
    return path


class TestFullLifecycle:
    def test_mint_sign_challenge_supersede(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """Full lifecycle: mint → sign → challenge → mint v2 → supersede → verify."""
        # Step 1: Mint and sign v1
        v1_path = _mint_and_sign(tmp_path, keystore, "v1.json")
        v1_data = json.loads(v1_path.read_text(encoding="utf-8"))

        # Step 2: Verify fresh
        state = compute_passport_state(v1_data, passport_dir=tmp_path)
        assert state.state == "FRESH"

        # Step 3: Challenge
        challenge_path = create_demo_challenge_receipt(
            v1_data,
            reason="Missing admin coverage",
            challenger_id="auditor",
            output_dir=tmp_path,
        )
        assert challenge_path.exists()

        # Step 4: Verify challenged
        state = compute_passport_state(v1_data, passport_dir=tmp_path)
        assert state.state == "CHALLENGED"
        assert len(state.challenges) == 1

        # Step 5: Mint v2
        v2_path = _mint_and_sign(tmp_path / "v2_dir", keystore, "v2.json")
        v2_data = json.loads(v2_path.read_text(encoding="utf-8"))

        # Step 6: Supersede v1 → v2
        sup_path = create_demo_supersession_receipt(
            v1_data, v2_data,
            reason="Addressed coverage gap",
            output_dir=tmp_path,
        )
        assert sup_path.exists()

        # Step 7: Verify v1 is superseded (supersession > challenge)
        state = compute_passport_state(v1_data, passport_dir=tmp_path)
        assert state.state == "SUPERSEDED"

        # Step 8: v2 should be fresh
        v2_dir = v2_path.parent
        state_v2 = compute_passport_state(v2_data, passport_dir=v2_dir)
        assert state_v2.state == "FRESH"

    def test_revoke_overrides_everything(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        """Revocation takes priority over challenge and supersession."""
        v1_path = _mint_and_sign(tmp_path, keystore, "v1.json")
        v1_data = json.loads(v1_path.read_text(encoding="utf-8"))

        # Challenge
        create_demo_challenge_receipt(
            v1_data, reason="test", output_dir=tmp_path,
        )

        # Revoke
        create_demo_revocation_receipt(
            v1_data, reason="Key compromised", output_dir=tmp_path,
        )

        state = compute_passport_state(v1_data, passport_dir=tmp_path)
        assert state.state == "REVOKED"

    def test_multiple_challenges(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        v1_path = _mint_and_sign(tmp_path, keystore, "v1.json")
        v1_data = json.loads(v1_path.read_text(encoding="utf-8"))

        from datetime import datetime, timedelta, timezone

        t1 = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)
        t2 = t1 + timedelta(hours=1)

        create_demo_challenge_receipt(
            v1_data, reason="Missing coverage", output_dir=tmp_path, now=t1,
        )
        create_demo_challenge_receipt(
            v1_data, reason="Stale evidence", output_dir=tmp_path, now=t2,
        )

        state = compute_passport_state(v1_data, passport_dir=tmp_path)
        assert state.state == "CHALLENGED"
        assert len(state.challenges) == 2
        assert "2 active challenge" in state.reason


class TestDiffAfterLifecycle:
    def test_diff_after_supersession(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        from assay.passport_diff import diff_passports

        v1_path = _mint_and_sign(tmp_path, keystore, "v1.json")
        v2_dir = tmp_path / "v2"
        v2_dir.mkdir()
        v2_path = _mint_and_sign(v2_dir, keystore, "v2.json")

        # Set up supersession relationship
        v1_data = json.loads(v1_path.read_text(encoding="utf-8"))
        v2_data = json.loads(v2_path.read_text(encoding="utf-8"))
        v2_data["relationships"]["supersedes"] = v1_data.get("passport_id", "")
        v2_path.write_text(json.dumps(v2_data, indent=2), encoding="utf-8")

        result = diff_passports(v1_path, v2_path)
        assert result.is_supersession

    def test_xray_after_challenge(
        self, tmp_path: Path, keystore: AssayKeyStore
    ) -> None:
        from assay.xray import xray_passport

        v1_path = _mint_and_sign(tmp_path, keystore, "v1.json")
        v1_data = json.loads(v1_path.read_text(encoding="utf-8"))

        create_demo_challenge_receipt(
            v1_data, reason="test", output_dir=tmp_path,
        )

        result = xray_passport(v1_path, keystore=keystore, verify=True)
        # Challenged passport gets warn finding
        freshness_findings = [f for f in result.findings if f.category == "freshness"]
        assert any("challenged" in f.title.lower() for f in freshness_findings)
