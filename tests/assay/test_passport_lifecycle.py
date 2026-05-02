"""Tests for passport lifecycle state machine."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from assay.passport_lifecycle import (
    PassportState,
    compute_passport_state,
    create_demo_challenge_receipt,
    create_demo_revocation_receipt,
    create_demo_supersession_receipt,
)


def _make_passport(**overrides) -> dict:
    base = {
        "passport_version": "0.1",
        "issued_at": "2026-03-14T00:00:00+00:00",
        "valid_until": "2036-04-13T00:00:00+00:00",
        "status": {"state": "FRESH", "reason": "ok", "checked_at": "2026-03-14T00:00:00+00:00"},
        "relationships": {
            "supersedes": None,
            "superseded_by": None,
            "challenge_refs": [],
            "revocation_ref": None,
        },
    }
    base.update(overrides)
    return base


class TestComputePassportState:
    def test_fresh_passport(self) -> None:
        passport = _make_passport()
        now = datetime(2026, 3, 15, tzinfo=timezone.utc)
        state = compute_passport_state(passport, now=now)
        assert state.state == "FRESH"

    def test_stale_passport(self) -> None:
        passport = _make_passport(valid_until="2026-03-10T00:00:00+00:00")
        now = datetime(2026, 3, 15, tzinfo=timezone.utc)
        state = compute_passport_state(passport, now=now)
        assert state.state == "STALE"
        assert "expired" in state.reason.lower()

    def test_challenged_passport(self, tmp_path: Path) -> None:
        passport = _make_passport()
        challenge = {
            "type": "challenge",
            "passport_id": "",
            "reason": "Missing coverage",
            "timestamp": "2026-03-14T12:00:00+00:00",
        }
        (tmp_path / "challenge_20260314T120000_abcd1234.json").write_text(
            json.dumps(challenge), encoding="utf-8"
        )
        state = compute_passport_state(passport, passport_dir=tmp_path)
        assert state.state == "CHALLENGED"
        assert len(state.challenges) == 1
        assert "Missing coverage" in state.reason

    def test_superseded_by_receipt(self, tmp_path: Path) -> None:
        passport = _make_passport()
        supersession = {
            "type": "supersession",
            "old_passport_id": "old",
            "new_passport_id": "new_id_123",
            "reason": "Upgraded",
            "timestamp": "2026-03-14T12:00:00+00:00",
        }
        (tmp_path / "supersession_20260314T120000.json").write_text(
            json.dumps(supersession), encoding="utf-8"
        )
        state = compute_passport_state(passport, passport_dir=tmp_path)
        assert state.state == "SUPERSEDED"
        assert state.superseded_by == "new_id_123"

    def test_superseded_by_relationship(self) -> None:
        passport = _make_passport()
        passport["relationships"]["superseded_by"] = "sha256:abc123"
        state = compute_passport_state(passport)
        assert state.state == "SUPERSEDED"

    def test_revoked_passport(self, tmp_path: Path) -> None:
        passport = _make_passport()
        revocation = {
            "type": "revocation",
            "passport_id": "",
            "reason": "Key compromised",
            "timestamp": "2026-03-14T12:00:00+00:00",
        }
        (tmp_path / "revocation_20260314T120000.json").write_text(
            json.dumps(revocation), encoding="utf-8"
        )
        state = compute_passport_state(passport, passport_dir=tmp_path)
        assert state.state == "REVOKED"
        assert "Key compromised" in state.reason

    def test_priority_revoked_over_challenged(self, tmp_path: Path) -> None:
        passport = _make_passport()
        # Both challenge and revocation exist — revocation wins
        (tmp_path / "challenge_20260314T100000_aaaa0000.json").write_text(
            json.dumps({"type": "challenge", "reason": "test"}), encoding="utf-8"
        )
        (tmp_path / "revocation_20260314T120000.json").write_text(
            json.dumps({"type": "revocation", "reason": "compromised"}), encoding="utf-8"
        )
        state = compute_passport_state(passport, passport_dir=tmp_path)
        assert state.state == "REVOKED"

    def test_priority_superseded_over_challenged(self, tmp_path: Path) -> None:
        passport = _make_passport()
        (tmp_path / "challenge_20260314T100000_bbbb0000.json").write_text(
            json.dumps({"type": "challenge", "reason": "test"}), encoding="utf-8"
        )
        (tmp_path / "supersession_20260314T120000.json").write_text(
            json.dumps({"type": "supersession", "reason": "upgraded", "new_passport_id": "new"}),
            encoding="utf-8",
        )
        state = compute_passport_state(passport, passport_dir=tmp_path)
        assert state.state == "SUPERSEDED"

    def test_priority_challenged_over_stale(self, tmp_path: Path) -> None:
        passport = _make_passport(valid_until="2026-03-10T00:00:00+00:00")
        now = datetime(2026, 3, 15, tzinfo=timezone.utc)
        (tmp_path / "challenge_20260314T100000_cccc0000.json").write_text(
            json.dumps({"type": "challenge", "reason": "needs review"}), encoding="utf-8"
        )
        state = compute_passport_state(passport, passport_dir=tmp_path, now=now)
        assert state.state == "CHALLENGED"

    def test_to_dict(self) -> None:
        state = PassportState(
            state="FRESH",
            reason="ok",
            checked_at="2026-03-14T00:00:00+00:00",
        )
        d = state.to_dict()
        assert d["state"] == "FRESH"
        assert "reason" in d

    def test_no_passport_dir(self) -> None:
        passport = _make_passport()
        state = compute_passport_state(passport, passport_dir=None)
        assert state.state == "FRESH"

    def test_no_valid_until(self) -> None:
        passport = _make_passport()
        del passport["valid_until"]
        state = compute_passport_state(passport)
        assert state.state == "FRESH"


class TestCreateReceipts:
    def test_create_challenge(self, tmp_path: Path) -> None:
        passport = _make_passport()
        passport["passport_id"] = "sha256:abcd"
        path = create_demo_challenge_receipt(
            passport,
            reason="Test challenge",
            challenger_id="tester",
            output_dir=tmp_path,
        )
        assert path.exists()
        assert path.name.startswith("challenge_")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["type"] == "challenge"
        assert data["reason"] == "Test challenge"
        assert data["passport_id"] == "sha256:abcd"

    def test_create_supersession(self, tmp_path: Path) -> None:
        old = _make_passport()
        old["passport_id"] = "sha256:old"
        new = _make_passport()
        new["passport_id"] = "sha256:new"
        path = create_demo_supersession_receipt(
            old, new,
            reason="Upgraded coverage",
            output_dir=tmp_path,
        )
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["old_passport_id"] == "sha256:old"
        assert data["new_passport_id"] == "sha256:new"

    def test_create_revocation(self, tmp_path: Path) -> None:
        passport = _make_passport()
        passport["passport_id"] = "sha256:revoked"
        path = create_demo_revocation_receipt(
            passport,
            reason="Key compromised",
            output_dir=tmp_path,
        )
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["type"] == "revocation"
        assert data["reason"] == "Key compromised"

    def test_challenge_receipt_triggers_challenged_state(self, tmp_path: Path) -> None:
        passport = _make_passport()
        create_demo_challenge_receipt(
            passport,
            reason="Test",
            output_dir=tmp_path,
        )
        state = compute_passport_state(passport, passport_dir=tmp_path)
        assert state.state == "CHALLENGED"
